#include "pe_cli_scan.h"

#include "language_manager.h"
#include "pe_findings.h"
#include "pe_parser_new.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDateTime>
#include <QDirIterator>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QTextStream>
#include <QTimer>
#include <algorithm>
#include <memory>

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

bool isSupportedPeFilePath(const QString &path)
{
    const QString suffix = QFileInfo(path).suffix().toLower();
    return suffix == QStringLiteral("exe") || suffix == QStringLiteral("dll")
           || suffix == QStringLiteral("sys");
}

QStringList listSupportedFilesInDirectory(const QString &dirPath, bool recursive)
{
    QDir dir(dirPath);
    QDirIterator::IteratorFlags flags = QDirIterator::NoIteratorFlags;
    if (recursive) {
        flags = QDirIterator::Subdirectories;
    }
    QStringList files;
    QDirIterator it(dirPath,
                      QStringList() << QStringLiteral("*.exe") << QStringLiteral("*.dll") << QStringLiteral("*.sys"),
                      QDir::Files | QDir::Readable | QDir::NoSymLinks, flags);
    while (it.hasNext()) {
        files.append(it.next());
    }
    std::sort(files.begin(), files.end(), [](const QString &a, const QString &b) {
        return a.compare(b, Qt::CaseInsensitive) < 0;
    });
    return files;
}

QStringList uniqueSortedPaths(const QStringList &paths)
{
    QSet<QString> seen;
    QStringList out;
    out.reserve(paths.size());
    for (const QString &path : paths) {
        const QString absolute = QFileInfo(path).absoluteFilePath();
        if (!seen.contains(absolute)) {
            seen.insert(absolute);
            out.append(absolute);
        }
    }
    std::sort(out.begin(), out.end(), [](const QString &a, const QString &b) {
        return a.compare(b, Qt::CaseInsensitive) < 0;
    });
    return out;
}

void printCliHelp()
{
    QTextStream out(stdout);
    out << "PEHint — headless PE triage scan\n\n"
        << "Usage:\n"
        << "  PEHint --scan [options] <pe-file> [more-pe-files...]\n"
        << "  PEHint --scan --dir <directory> [options]\n"
        << "  PEHint --scan --watch <directory> [options]\n\n"
        << "Options:\n"
        << "  --format <text|json>   Output format (default: text)\n"
        << "  --min-severity <level> Minimum severity to report: info, low, medium, high (default: low)\n"
        << "  --include-passes       Include hardening pass rows (ASLR/DEP/CFG enabled)\n"
        << "  --dir <directory>      Scan all .exe/.dll/.sys files in a directory\n"
        << "  --recursive            With --dir or --watch, include subdirectories\n"
        << "  --watch <directory>    Watch directory and rescan changed .exe/.dll/.sys files\n"
        << "  --debounce-ms <n>      Debounce watch rescans (default: 500)\n"
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

void printFileHeader(QTextStream &out, const QString &filePath)
{
    out << "=== " << filePath << " ===\n";
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

int scanOneFile(const QString &filePath,
                const QString &format,
                PEFindingSeverity minSeverity,
                bool includePasses,
                bool printHeader)
{
    QTextStream out(stdout);
    QTextStream err(stderr);
    PEParserNew parserEngine;
    if (!parserEngine.loadFile(filePath)) {
        err << "Error: failed to parse " << filePath << '\n';
        return 1;
    }

    const PEDataModel &model = parserEngine.getDataModel();
    const auto rvaToFo = [&parserEngine](quint32 rva) -> quint32 { return parserEngine.rvaToFileOffset(rva); };

    QVector<PEFindingInstance> findings = PEFindingsEngine::evaluate(model, rvaToFo);
    if (includePasses) {
        findings += PEFindingsEngine::evaluateHardeningPasses(model);
    }
    findings = filterFindings(findings, minSeverity, includePasses);

    const int exitCode = hasActionableFindings(findings) ? 2 : 0;
    if (printHeader && format != QStringLiteral("json")) {
        printFileHeader(out, filePath);
    }
    if (format == QStringLiteral("json")) {
        printJsonReport(out, filePath, true, model, findings, exitCode);
    } else {
        printTextReport(out, filePath, model, findings);
    }
    return exitCode;
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
    std::unique_ptr<QCoreApplication> ownedApp;
    if (!QCoreApplication::instance()) {
        ownedApp = std::make_unique<QCoreApplication>(argc, argv);
    }
    QCoreApplication *app = QCoreApplication::instance();
    QCoreApplication::setApplicationName(QStringLiteral("PEHint"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Headless PE findings scan"));
    parser.addHelpOption();
    QCommandLineOption scanOption(QStringLiteral("scan"),
                                  QStringLiteral("Scan PE files and print findings (no GUI)."));
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
    QCommandLineOption dirOption(QStringLiteral("dir"),
                                 QStringLiteral("Scan all .exe/.dll/.sys files in a directory (non-recursive)."),
                                 QStringLiteral("directory"));
    parser.addOption(dirOption);
    QCommandLineOption watchOption(QStringLiteral("watch"),
                                   QStringLiteral("Watch directory and rescan changed .exe/.dll/.sys files."),
                                   QStringLiteral("directory"));
    parser.addOption(watchOption);
    QCommandLineOption recursiveOption(QStringLiteral("recursive"),
                                       QStringLiteral("Include subdirectories for --dir and --watch."));
    parser.addOption(recursiveOption);
    QCommandLineOption debounceOption(QStringLiteral("debounce-ms"),
                                      QStringLiteral("Watch debounce interval in milliseconds."),
                                      QStringLiteral("ms"),
                                      QStringLiteral("500"));
    parser.addOption(debounceOption);
    QCommandLineOption langOption(QStringLiteral("lang"),
                                  QStringLiteral("Language for finding strings: en or pt."),
                                  QStringLiteral("code"),
                                  QStringLiteral("en"));
    parser.addOption(langOption);
    parser.addPositionalArgument(QStringLiteral("files"), QStringLiteral("PE file(s) to scan"));

    QStringList argList;
    argList.reserve(argc);
    for (int i = 0; i < argc; ++i) {
        argList << QString::fromLocal8Bit(argv[i]);
    }
    if (!parser.parse(argList)) {
        return 0;
    }

    if (!parser.isSet(scanOption)) {
        printCliHelp();
        return 1;
    }

    const QString format = parser.value(formatOption).trimmed().toLower();
    const PEFindingSeverity minSeverity = parseMinSeverity(parser.value(minSeverityOption));
    const bool includePasses = parser.isSet(includePassesOption);
    const bool recursive = parser.isSet(recursiveOption);
    const int debounceMs = qMax(50, parser.value(debounceOption).toInt());
    const QString lang = parser.value(langOption).trimmed().toLower();
    const QString dirPath = parser.value(dirOption).trimmed();
    const QString watchPath = parser.value(watchOption).trimmed();

    if (!watchPath.isEmpty() && !QFileInfo(watchPath).isDir()) {
        QTextStream err(stderr);
        err << "Error: --watch requires a valid directory.\n";
        return 1;
    }
    if (!dirPath.isEmpty() && !QFileInfo(dirPath).isDir()) {
        QTextStream err(stderr);
        err << "Error: --dir requires a valid directory.\n";
        return 1;
    }

    QStringList filesToScan;
    const QStringList positional = parser.positionalArguments();
    for (const QString &pathArg : positional) {
        filesToScan.append(QFileInfo(pathArg).absoluteFilePath());
    }
    if (!dirPath.isEmpty()) {
        filesToScan += listSupportedFilesInDirectory(QFileInfo(dirPath).absoluteFilePath(), recursive);
    }
    filesToScan = uniqueSortedPaths(filesToScan);

    if (watchPath.isEmpty() && filesToScan.isEmpty()) {
        QTextStream err(stderr);
        err << "Error: provide one or more PE files, --dir, or --watch.\n";
        printCliHelp();
        return 1;
    }

    LanguageManager &langMgr = LanguageManager::getInstance();
    langMgr.initialize();
    if (lang == QStringLiteral("pt")) {
        langMgr.setLanguage(QStringLiteral("pt"));
    } else {
        langMgr.setLanguage(QStringLiteral("en"));
    }

    PEFindingsEngine::loadRules();

    int aggregateExitCode = 0;
    if (!filesToScan.isEmpty()) {
        const bool showHeader = filesToScan.size() > 1;
        for (const QString &filePath : filesToScan) {
            if (!isSupportedPeFilePath(filePath)) {
                continue;
            }
            const int oneExit = scanOneFile(filePath, format, minSeverity, includePasses, showHeader);
            if (oneExit == 1) {
                aggregateExitCode = 1;
            } else if (oneExit == 2 && aggregateExitCode == 0) {
                aggregateExitCode = 2;
            }
        }
    }

    if (watchPath.isEmpty()) {
        return aggregateExitCode;
    }

    const QString watchDir = QFileInfo(watchPath).absoluteFilePath();
    QTextStream out(stdout);
    out << "Watching: " << watchDir << '\n';

    QFileSystemWatcher watcher;
    watcher.addPath(watchDir);
    QTimer debounceTimer;
    debounceTimer.setSingleShot(true);
    debounceTimer.setInterval(debounceMs);

    QHash<QString, QDateTime> knownMtime;
    QHash<QString, QDateTime> lastScannedMtime;
    QSet<QString> pendingChanges;

    const auto updateWatchedFiles = [&watcher, watchDir, recursive]() {
        const QStringList currentlyWatched = watcher.files();
        for (const QString &watchedPath : currentlyWatched) {
            watcher.removePath(watchedPath);
        }
        for (const QString &filePath : listSupportedFilesInDirectory(watchDir, recursive)) {
            watcher.addPath(filePath);
        }
    };

    const auto detectChangedFiles = [&knownMtime, &pendingChanges, watchDir, recursive]() {
        QHash<QString, QDateTime> current;
        const QStringList files = listSupportedFilesInDirectory(watchDir, recursive);
        for (const QString &path : files) {
            const QDateTime mtime = QFileInfo(path).lastModified();
            current.insert(path, mtime);
            if (!knownMtime.contains(path) || knownMtime.value(path) != mtime) {
                pendingChanges.insert(path);
            }
        }
        for (auto it = knownMtime.constBegin(); it != knownMtime.constEnd(); ++it) {
            if (!current.contains(it.key())) {
                pendingChanges.insert(it.key());
            }
        }
        knownMtime = current;
    };

    detectChangedFiles();
    updateWatchedFiles();

    QObject::connect(&watcher, &QFileSystemWatcher::directoryChanged, app, [&](const QString &) {
        detectChangedFiles();
        updateWatchedFiles();
        debounceTimer.start();
    });
    QObject::connect(&watcher, &QFileSystemWatcher::fileChanged, app, [&](const QString &path) {
        pendingChanges.insert(path);
        detectChangedFiles();
        updateWatchedFiles();
        debounceTimer.start();
    });
    QObject::connect(&debounceTimer, &QTimer::timeout, app, [&]() {
        QStringList changed = uniqueSortedPaths(pendingChanges.values());
        pendingChanges.clear();
        for (const QString &filePath : changed) {
            if (!QFileInfo::exists(filePath) || !isSupportedPeFilePath(filePath)) {
                continue;
            }
            const QDateTime mtime = QFileInfo(filePath).lastModified();
            if (lastScannedMtime.value(filePath) == mtime) {
                continue;
            }
            const int oneExit = scanOneFile(filePath, format, minSeverity, includePasses, true);
            if (oneExit != 1) {
                lastScannedMtime.insert(filePath, mtime);
            }
            if (oneExit == 1) {
                aggregateExitCode = 1;
            } else if (oneExit == 2 && aggregateExitCode == 0) {
                aggregateExitCode = 2;
            }
        }
    });

    app->exec();
    return aggregateExitCode;
}
