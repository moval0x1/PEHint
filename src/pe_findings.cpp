#include "pe_findings.h"
#include "language_manager.h"
#include "pe_utils.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace {

constexpr quint32 kSectionExecute = 0x20000000u;
constexpr quint32 kSectionRead = 0x40000000u;
constexpr quint32 kSectionWrite = 0x08000000u;
constexpr quint32 kEpochYear2000 = 946684800u;

QVector<PEFindingRule> g_rules;
bool g_rulesLoaded = false;

QString findConfigFile(const QString &fileName)
{
    QStringList paths;
    const QString appDir = QCoreApplication::applicationDirPath();
    paths << QDir(appDir).absoluteFilePath(QStringLiteral("config/") + fileName);
    paths << QDir::currentPath() + QStringLiteral("/config/") + fileName;
    QDir up(appDir);
    if (up.cdUp() && up.cdUp() && up.cdUp()) {
        paths << up.absoluteFilePath(QStringLiteral("config/") + fileName);
    }
    paths << QDir(appDir).absoluteFilePath(QStringLiteral("../../../config/") + fileName);
    for (const QString &path : paths) {
        if (QFile::exists(path)) {
            return path;
        }
    }
    return QString();
}

PEFindingSeverity severityFromString(const QString &value)
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

QString sectionNameFromHeader(const IMAGE_SECTION_HEADER *section)
{
    if (!section) {
        return QString();
    }
    const char *namePtr = reinterpret_cast<const char *>(section->Name);
    int nameLength = 0;
    while (nameLength < 8 && namePtr[nameLength] != '\0'
           && static_cast<unsigned char>(namePtr[nameLength]) >= 32) {
        ++nameLength;
    }
    if (nameLength > 0) {
        return QString::fromLatin1(namePtr, nameLength);
    }
    return QStringLiteral("0x") + QString(QByteArray(namePtr, 8).toHex()).toUpper();
}

QString sectionTreeKey(int index, const QString &name)
{
    return QStringLiteral("Section %1: %2").arg(index + 1).arg(name);
}

int sectionIndexForRva(const QList<const IMAGE_SECTION_HEADER *> &sections, quint32 rva)
{
    for (int i = 0; i < sections.size(); ++i) {
        const IMAGE_SECTION_HEADER *section = sections.at(i);
        if (!section) {
            continue;
        }
        const quint32 start = section->VirtualAddress;
        const quint32 size = qMax(section->getVirtualSize(), section->SizeOfRawData);
        if (rva >= start && rva < start + size) {
            return i;
        }
    }
    return -1;
}

void appendInstance(QVector<PEFindingInstance> &out, const PEFindingRule &rule, const QString &detail,
                    const QString &treeFieldOverride = QString(), quint32 hexOffset = 0, quint32 hexSize = 0)
{
    PEFindingInstance inst;
    inst.ruleId = rule.id;
    inst.severity = rule.severity;
    inst.title = LANG(rule.titleKey);
    inst.detail = detail.isEmpty() ? LANG(rule.detailKey) : detail;
    inst.treeField = treeFieldOverride.isEmpty() ? rule.treeField : treeFieldOverride;
    if (hexSize > 0) {
        inst.hexOffset = hexOffset;
        inst.hexSize = hexSize;
        inst.hasHexNav = true;
    }
    out.append(inst);
}

QVector<PEFindingRule> defaultRules()
{
    QVector<PEFindingRule> rules;
    auto add = [&](const char *id, const char *check, PEFindingSeverity sev, const char *title,
                   const char *detail, const char *tree = nullptr) {
        PEFindingRule r;
        r.id = QString::fromLatin1(id);
        r.check = QString::fromLatin1(check);
        r.severity = sev;
        r.titleKey = QString::fromLatin1(title);
        r.detailKey = QString::fromLatin1(detail);
        if (tree) {
            r.treeField = QString::fromLatin1(tree);
        }
        rules.append(r);
    };
    add("missing_aslr", "missing_aslr", PEFindingSeverity::Medium, "findings/missing_aslr_title",
        "findings/missing_aslr_detail", "DllCharacteristics");
    add("missing_dep", "missing_dep", PEFindingSeverity::Medium, "findings/missing_dep_title",
        "findings/missing_dep_detail", "DllCharacteristics");
    add("overlay_present", "overlay_present", PEFindingSeverity::Medium, "findings/overlay_present_title",
        "findings/overlay_present_detail", "Overlay");
    return rules;
}

} // namespace

bool PEFindingsEngine::loadRules(QString *errorOut)
{
    g_rules.clear();
    g_rulesLoaded = false;

    const QString path = findConfigFile(QStringLiteral("findings.json"));
    if (path.isEmpty()) {
        g_rules = defaultRules();
        g_rulesLoaded = true;
        if (errorOut) {
            *errorOut = QStringLiteral("findings.json not found; using built-in rules");
        }
        return true;
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (errorOut) {
            *errorOut = QStringLiteral("Cannot open %1").arg(path);
        }
        g_rules = defaultRules();
        g_rulesLoaded = true;
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        if (errorOut) {
            *errorOut = parseError.errorString();
        }
        g_rules = defaultRules();
        g_rulesLoaded = true;
        return false;
    }

    const QJsonArray rulesArr = doc.object().value(QStringLiteral("rules")).toArray();
    for (const QJsonValue &val : rulesArr) {
        if (!val.isObject()) {
            continue;
        }
        const QJsonObject obj = val.toObject();
        if (!obj.value(QStringLiteral("enabled")).toBool(true)) {
            continue;
        }
        PEFindingRule rule;
        rule.id = obj.value(QStringLiteral("id")).toString();
        rule.check = obj.value(QStringLiteral("check")).toString();
        if (rule.id.isEmpty() || rule.check.isEmpty()) {
            continue;
        }
        rule.severity = severityFromString(obj.value(QStringLiteral("severity")).toString());
        rule.titleKey = obj.value(QStringLiteral("titleKey")).toString();
        rule.detailKey = obj.value(QStringLiteral("detailKey")).toString();
        rule.treeField = obj.value(QStringLiteral("treeField")).toString();
        rule.threshold = obj.value(QStringLiteral("threshold")).toDouble(7.0);
        rule.maxImports = obj.value(QStringLiteral("maxImports")).toInt(3);
        if (rule.titleKey.isEmpty()) {
            rule.titleKey = QStringLiteral("findings/") + rule.id + QStringLiteral("_title");
        }
        if (rule.detailKey.isEmpty()) {
            rule.detailKey = QStringLiteral("findings/") + rule.id + QStringLiteral("_detail");
        }
        g_rules.append(rule);
    }

    if (g_rules.isEmpty()) {
        g_rules = defaultRules();
    }
    g_rulesLoaded = true;
    return true;
}

const QVector<PEFindingRule> &PEFindingsEngine::rules()
{
    if (!g_rulesLoaded) {
        loadRules();
    }
    return g_rules;
}

QString PEFindingsEngine::severityDisplayName(PEFindingSeverity severity)
{
    switch (severity) {
    case PEFindingSeverity::Info:
        return LANG(QStringLiteral("findings/severity_info"));
    case PEFindingSeverity::Low:
        return LANG(QStringLiteral("findings/severity_low"));
    case PEFindingSeverity::High:
        return LANG(QStringLiteral("findings/severity_high"));
    default:
        return LANG(QStringLiteral("findings/severity_medium"));
    }
}

QVector<PEFindingInstance> PEFindingsEngine::evaluate(
    const PEDataModel &model,
    const std::function<quint32(quint32)> &rvaToFileOffset)
{
    QVector<PEFindingInstance> results;
    if (!model.isValid()) {
        return results;
    }

    const IMAGE_OPTIONAL_HEADER *opt = model.getOptionalHeader();
    const IMAGE_FILE_HEADER *fileHdr = model.getFileHeader();
    const QList<const IMAGE_SECTION_HEADER *> sections = model.getSections();
    const PEOverlayInfo overlay = model.getOverlayInfo();
    const PEEntropySummary entropy = model.getEntropySummary();
    const QStringList imports = model.getImports();

    for (const PEFindingRule &rule : rules()) {
        if (!rule.enabled) {
            continue;
        }

        const QString check = rule.check;

        if (check == QStringLiteral("missing_aslr")) {
            if (opt && !PEUtils::hasASLR(opt->DllCharacteristics)) {
                appendInstance(results, rule, QString());
            }
            continue;
        }

        if (check == QStringLiteral("missing_dep")) {
            if (opt && !PEUtils::hasDEP(opt->DllCharacteristics)) {
                appendInstance(results, rule, QString());
            }
            continue;
        }

        if (check == QStringLiteral("missing_cfg")) {
            if (opt && !PEUtils::hasControlFlowGuard(opt->DllCharacteristics)) {
                appendInstance(results, rule, QString());
            }
            continue;
        }

        if (check == QStringLiteral("overlay_present")) {
            if (overlay.present && overlay.fileOffset > 0) {
                quint32 size = static_cast<quint32>(qMin(overlay.size, static_cast<quint64>(UINT32_MAX)));
                if (size == 0 && model.getFileSize() > static_cast<qint64>(overlay.fileOffset)) {
                    size = static_cast<quint32>(
                        qMin(static_cast<quint64>(model.getFileSize() - overlay.fileOffset),
                             static_cast<quint64>(UINT32_MAX)));
                }
                QMap<QString, QString> params;
                params[QStringLiteral("offset")] = PEUtils::formatHexWidth(overlay.fileOffset, 8);
                params[QStringLiteral("size")] = QString::number(size);
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params), rule.treeField,
                               overlay.fileOffset, qMax(size, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("high_file_entropy")) {
            if (entropy.fileEntropyValid && entropy.fileEntropy >= rule.threshold) {
                QMap<QString, QString> params;
                params[QStringLiteral("value")] = QString::number(entropy.fileEntropy, 'f', 2);
                params[QStringLiteral("threshold")] = QString::number(rule.threshold, 'f', 1);
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params));
            }
            continue;
        }

        if (check == QStringLiteral("high_section_entropy")) {
            for (const PESectionEntropy &se : entropy.sections) {
                if (!se.computed || se.entropy < rule.threshold) {
                    continue;
                }
                QMap<QString, QString> params;
                params[QStringLiteral("section")] = se.sectionName;
                params[QStringLiteral("value")] = QString::number(se.entropy, 'f', 2);
                params[QStringLiteral("threshold")] = QString::number(rule.threshold, 'f', 1);
                QString treeKey = rule.treeField;
                for (int i = 0; i < sections.size(); ++i) {
                    if (sectionNameFromHeader(sections.at(i)) == se.sectionName) {
                        treeKey = sectionTreeKey(i, se.sectionName);
                        break;
                    }
                }
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params), treeKey, se.rawOffset,
                               qMax(se.rawSize, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("few_imports")) {
            if (!imports.isEmpty() && imports.size() <= rule.maxImports) {
                QMap<QString, QString> params;
                params[QStringLiteral("count")] = QString::number(imports.size());
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params));
            }
            continue;
        }

        if (check == QStringLiteral("no_imports")) {
            if (imports.isEmpty() && fileHdr && !(fileHdr->Characteristics & 0x2000)) {
                appendInstance(results, rule, QString());
            }
            continue;
        }

        if (check == QStringLiteral("rwx_section")) {
            for (int i = 0; i < sections.size(); ++i) {
                const IMAGE_SECTION_HEADER *sec = sections.at(i);
                if (!sec) {
                    continue;
                }
                const quint32 chars = sec->Characteristics;
                if ((chars & kSectionExecute) && (chars & kSectionRead) && (chars & kSectionWrite)) {
                    const QString name = sectionNameFromHeader(sec);
                    QMap<QString, QString> params;
                    params[QStringLiteral("section")] = name;
                    appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                                   sectionTreeKey(i, name), sec->PointerToRawData,
                                   qMax(sec->SizeOfRawData, 1u));
                }
            }
            continue;
        }

        if (check == QStringLiteral("suspicious_ep")) {
            if (!opt || opt->AddressOfEntryPoint == 0) {
                continue;
            }
            const quint32 epRva = opt->AddressOfEntryPoint;
            const int secIdx = sectionIndexForRva(sections, epRva);
            bool suspicious = false;
            QString reason;
            if (secIdx < 0) {
                suspicious = true;
                reason = LANG(QStringLiteral("findings/suspicious_ep_outside_sections"));
            } else {
                const IMAGE_SECTION_HEADER *sec = sections.at(secIdx);
                const QString name = sectionNameFromHeader(sec);
                const quint32 chars = sec->Characteristics;
                const bool writable = (chars & kSectionWrite) != 0;
                const bool executable = (chars & kSectionExecute) != 0;
                const bool typicalName =
                    name.contains(QStringLiteral("text"), Qt::CaseInsensitive)
                    || name.contains(QStringLiteral("code"), Qt::CaseInsensitive);
                if (writable && executable) {
                    suspicious = true;
                    QMap<QString, QString> wp;
                    wp[QStringLiteral("section")] = name;
                    reason = LANG_PARAMS(QStringLiteral("findings/suspicious_ep_writable"), wp);
                } else if (executable && !typicalName) {
                    suspicious = true;
                    QMap<QString, QString> up;
                    up[QStringLiteral("section")] = name;
                    reason = LANG_PARAMS(QStringLiteral("findings/suspicious_ep_unusual_section"), up);
                }
            }
            if (suspicious) {
                quint32 fo = 0;
                if (rvaToFileOffset) {
                    fo = rvaToFileOffset(epRva);
                }
                appendInstance(results, rule, reason, rule.treeField, fo, fo > 0 ? 16u : 0u);
            }
            continue;
        }

        if (check == QStringLiteral("zero_timestamp")) {
            if (fileHdr && fileHdr->TimeDateStamp == 0) {
                appendInstance(results, rule, QString());
            }
            continue;
        }

        if (check == QStringLiteral("old_timestamp")) {
            if (fileHdr && fileHdr->TimeDateStamp != 0
                && fileHdr->TimeDateStamp < kEpochYear2000) {
                QMap<QString, QString> params;
                params[QStringLiteral("date")] = PEUtils::formatTimestamp(fileHdr->TimeDateStamp);
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params));
            }
            continue;
        }
    }

    return results;
}
