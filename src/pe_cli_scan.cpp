#include "pe_cli_scan.h"

#include "language_manager.h"
#include "pe_findings.h"
#include "pe_parser_new.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

namespace {

QString severitySlug(PEFindingSeverity severity)
{
    switch (severity) {
    case PEFindingSeverity::Info:
        return QStringLiteral("info");
    case PEFindingSeverity::Low:
        return QStringLiteral("low");
    case PEFindingSeverity::High:
        return QStringLiteral("high");
    default:
        return QStringLiteral("medium");
    }
}

int severityRank(PEFindingSeverity severity)
{
    switch (severity) {
    case PEFindingSeverity::Info:
        return 0;
    case PEFindingSeverity::Low:
        return 1;
    case PEFindingSeverity::Medium:
        return 2;
    case PEFindingSeverity::High:
        return 3;
    }
    return 0;
}

bool severityAtLeast(PEFindingSeverity value, PEFindingSeverity minimum)
{
    return severityRank(value) >= severityRank(minimum);
}

void printCliHelp()
{
    QTextStream out(stdout);
    out << "PEHint — headless PE triage scan\n\n"
        << "Usage:\n"
        << "  PEHint --scan [options] <pe-file>\n\n"
        << "Options:\n"
        << "  --format <text|json>   Output format (default: text)\n"
        << "  --min-severity <level> Minimum severity to report: info, low, medium, high (default: low)\n"
        << "  --include-passes       Include hardening pass rows (ASLR/DEP/CFG enabled)\n"
        << "  --lang <en|pt>         UI language for finding text (default: en)\n"
        << "  -h, --help             Show this help\n\n"
        << "Exit codes:\n"
        << "  0  Scan OK, no medium/high findings\n"
        << "  1  File open or parse error\n"
        << "  2  One or more medium/high findings\n";
}

PEFindingSeverity parseMinSeverity(const QString &value)
{
    const QString v = value.trimmed().toLower();
    if (v == QStringLiteral("info")) {
        return PEFindingSeverity::Info;
    }
    if (v == QStringLiteral("low")) {
        return PEFindingSeverity::Low;
    }
    if (v == QStringLiteral("high")) {
        return PEFindingSeverity::High;
    }
    return PEFindingSeverity::Medium;
}

QVector<PEFindingInstance> filterFindings(const QVector<PEFindingInstance> &findings,
                                          PEFindingSeverity minSeverity,
                                          bool includePasses)
{
    QVector<PEFindingInstance> filtered;
    for (const PEFindingInstance &finding : findings) {
        if (finding.isPass && !includePasses) {
            continue;
        }
        if (!severityAtLeast(finding.severity, minSeverity)) {
            continue;
        }
        filtered.append(finding);
    }
    return filtered;
}

bool hasActionableFindings(const QVector<PEFindingInstance> &findings)
{
    for (const PEFindingInstance &finding : findings) {
        if (finding.isPass) {
            continue;
        }
        if (severityAtLeast(finding.severity, PEFindingSeverity::Medium)) {
            return true;
        }
    }
    return false;
}

void printTextReport(QTextStream &out,
                     const QString &filePath,
                     const PEDataModel &model,
                     const QVector<PEFindingInstance> &findings)
{
    out << "PEHint scan: " << filePath << '\n';
    const PEFileMetrics metrics = model.getFileMetrics();
    if (metrics.hashesValid) {
        out << "MD5:    " << metrics.md5Hex << '\n';
        out << "SHA256: " << metrics.sha256Hex << '\n';
        if (!metrics.imphashHex.isEmpty()) {
            out << "ImpHash: " << metrics.imphashHex << '\n';
        }
    }
    out << "Findings (" << findings.size() << "):\n";
    for (const PEFindingInstance &finding : findings) {
        out << '[' << severitySlug(finding.severity).toUpper() << "] "
            << finding.title;
        if (!finding.detail.isEmpty()) {
            out << " — " << finding.detail;
        }
        out << '\n';
    }
}

void printJsonReport(QTextStream &out,
                     const QString &filePath,
                     bool parseOk,
                     const PEDataModel &model,
                     const QVector<PEFindingInstance> &findings,
                     int exitCode)
{
    QJsonObject root;
    root.insert(QStringLiteral("file"), filePath);
    root.insert(QStringLiteral("valid"), parseOk && model.isValid());
    root.insert(QStringLiteral("exitCode"), exitCode);

    const PEFileMetrics metrics = model.getFileMetrics();
    if (metrics.hashesValid) {
        QJsonObject metricsObj;
        metricsObj.insert(QStringLiteral("md5"), metrics.md5Hex);
        metricsObj.insert(QStringLiteral("sha256"), metrics.sha256Hex);
        if (!metrics.imphashHex.isEmpty()) {
            metricsObj.insert(QStringLiteral("imphash"), metrics.imphashHex);
        }
        if (metrics.fileRatioValid) {
            metricsObj.insert(QStringLiteral("fileRatio"), metrics.fileRatio);
        }
        root.insert(QStringLiteral("metrics"), metricsObj);
    }

    QJsonArray findingsArr;
    for (const PEFindingInstance &finding : findings) {
        QJsonObject obj;
        obj.insert(QStringLiteral("id"), finding.ruleId);
        obj.insert(QStringLiteral("severity"), severitySlug(finding.severity));
        obj.insert(QStringLiteral("title"), finding.title);
        obj.insert(QStringLiteral("detail"), finding.detail);
        obj.insert(QStringLiteral("category"), finding.category);
        obj.insert(QStringLiteral("isPass"), finding.isPass);
        if (finding.hasHexNav) {
            obj.insert(QStringLiteral("hexOffset"), static_cast<qint64>(finding.hexOffset));
            obj.insert(QStringLiteral("hexSize"), static_cast<qint64>(finding.hexSize));
        }
        findingsArr.append(obj);
    }
    root.insert(QStringLiteral("findings"), findingsArr);

    out << QJsonDocument(root).toJson(QJsonDocument::Compact) << '\n';
}

} // namespace

bool peCliScanRequested(int argc, char *argv[])
{
    for (int i = 1; i < argc; ++i) {
        if (QString::fromLocal8Bit(argv[i]) == QStringLiteral("--scan")) {
            return true;
        }
    }
    return false;
}

int runPeCliScan(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("PEHint"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Headless PE findings scan"));
    parser.addHelpOption();
    QCommandLineOption scanOption(QStringLiteral("scan"),
                                  QStringLiteral("Scan a PE file and print findings (no GUI)."));
    parser.addOption(scanOption);
    QCommandLineOption formatOption(QStringLiteral("format"),
                                    QStringLiteral("Output format: text or json."),
                                    QStringLiteral("format"),
                                    QStringLiteral("text"));
    parser.addOption(formatOption);
    QCommandLineOption minSeverityOption(QStringLiteral("min-severity"),
                                           QStringLiteral("Minimum severity: info, low, medium, high."),
                                           QStringLiteral("level"),
                                           QStringLiteral("low"));
    parser.addOption(minSeverityOption);
    QCommandLineOption includePassesOption(QStringLiteral("include-passes"),
                                             QStringLiteral("Include hardening pass findings."));
    parser.addOption(includePassesOption);
    QCommandLineOption langOption(QStringLiteral("lang"),
                                  QStringLiteral("Language for finding strings: en or pt."),
                                  QStringLiteral("code"),
                                  QStringLiteral("en"));
    parser.addOption(langOption);
    parser.addPositionalArgument(QStringLiteral("file"), QStringLiteral("PE file to scan"));
    parser.process(app);

    if (!parser.isSet(scanOption)) {
        printCliHelp();
        return 1;
    }

    const QStringList positional = parser.positionalArguments();
    if (positional.isEmpty()) {
        QTextStream err(stderr);
        err << "Error: missing PE file path.\n";
        printCliHelp();
        return 1;
    }

    const QString filePath = QFileInfo(positional.first()).absoluteFilePath();
    const QString format = parser.value(formatOption).trimmed().toLower();
    const PEFindingSeverity minSeverity = parseMinSeverity(parser.value(minSeverityOption));
    const bool includePasses = parser.isSet(includePassesOption);
    const QString lang = parser.value(langOption).trimmed().toLower();

    LanguageManager &langMgr = LanguageManager::getInstance();
    langMgr.initialize();
    if (lang == QStringLiteral("pt")) {
        langMgr.setLanguage(QStringLiteral("pt"));
    } else {
        langMgr.setLanguage(QStringLiteral("en"));
    }

    PEFindingsEngine::loadRules();

    PEParserNew parserEngine;
    if (!parserEngine.loadFile(filePath)) {
        QTextStream err(stderr);
        err << "Error: failed to parse " << filePath << '\n';
        return 1;
    }

    const PEDataModel &model = parserEngine.getDataModel();
    const auto rvaToFo = [&parserEngine](quint32 rva) -> quint32 {
        return parserEngine.rvaToFileOffset(rva);
    };

    QVector<PEFindingInstance> findings = PEFindingsEngine::evaluate(model, rvaToFo);
    if (includePasses) {
        findings += PEFindingsEngine::evaluateHardeningPasses(model);
    }
    findings = filterFindings(findings, minSeverity, includePasses);

    const int exitCode = hasActionableFindings(findings) ? 2 : 0;
    QTextStream out(stdout);

    if (format == QStringLiteral("json")) {
        printJsonReport(out, filePath, true, model, findings, exitCode);
    } else {
        printTextReport(out, filePath, model, findings);
    }

    return exitCode;
}
