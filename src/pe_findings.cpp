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
#include <QRegularExpression>
#include <QSet>
#include <functional>

namespace {

constexpr quint32 kSectionExecute = 0x20000000u;
constexpr quint32 kSectionRead = 0x40000000u;
constexpr quint32 kSectionWrite = 0x08000000u;
constexpr quint32 kEpochYear2000 = 946684800u;
constexpr quint32 kImageFileDll = 0x2000u;
constexpr quint32 kImageFileRelocsStripped = 0x0001u;
constexpr quint32 kImageFileDebugStripped = 0x0200u;

struct OptionalHeaderView {
    quint32 checksum = 0;
    quint16 subsystem = 0;
    quint16 dllCharacteristics = 0;
    bool pe32Plus = false;
};

OptionalHeaderView viewOptionalHeader(const IMAGE_OPTIONAL_HEADER *opt)
{
    OptionalHeaderView view;
    if (!opt) {
        return view;
    }
    if (opt->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const auto *oh64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(opt);
        view.pe32Plus = true;
        view.checksum = oh64->CheckSum;
        view.subsystem = oh64->Subsystem;
        view.dllCharacteristics = oh64->DllCharacteristics;
    } else {
        view.checksum = opt->CheckSum;
        view.subsystem = opt->Subsystem;
        view.dllCharacteristics = opt->DllCharacteristics;
    }
    return view;
}

const IMAGE_DATA_DIRECTORY *optionalDataDirectory(const IMAGE_OPTIONAL_HEADER *opt, int index)
{
    if (!opt || index < 0 || index >= 16) {
        return nullptr;
    }
    if (opt->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const auto *oh64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(opt);
        if (static_cast<quint32>(index) >= oh64->NumberOfRvaAndSizes) {
            return nullptr;
        }
        return &oh64->DataDirectory[index];
    }
    const auto *oh32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32 *>(opt);
    if (static_cast<quint32>(index) >= oh32->NumberOfRvaAndSizes) {
        return nullptr;
    }
    return &oh32->DataDirectory[index];
}

bool isDllImage(const IMAGE_FILE_HEADER *fileHdr)
{
    return fileHdr && (fileHdr->Characteristics & kImageFileDll) != 0;
}

bool sectionNameLooksLikeCode(const QString &name)
{
    return name.contains(QStringLiteral("text"), Qt::CaseInsensitive)
           || name.contains(QStringLiteral("code"), Qt::CaseInsensitive);
}

bool sectionNameLooksLikeData(const QString &name)
{
    return name.contains(QStringLiteral("data"), Qt::CaseInsensitive)
           || name.contains(QStringLiteral("bss"), Qt::CaseInsensitive);
}

bool isKnownPackerSectionName(const QString &name)
{
    const QString lower = name.toLower();
    static const char *const kPatterns[] = {
        ".upx", "upx!", ".themida", ".vmp", ".enigma", ".aspack", ".pec", ".packed", ".nsp", ".petite"
    };
    for (const char *pattern : kPatterns) {
        if (lower.contains(QString::fromLatin1(pattern))) {
            return true;
        }
    }
    return false;
}

bool hasAuthenticodeDirectory(const IMAGE_OPTIONAL_HEADER *opt)
{
    const IMAGE_DATA_DIRECTORY *certDir = optionalDataDirectory(opt, 4);
    return certDir && certDir->VirtualAddress != 0 && certDir->Size != 0;
}

QVector<PEFindingRule> g_rules;
bool g_rulesLoaded = false;

struct ImportFlagRule {
    QString id;
    QString dll;
    QString function;
    PEFindingSeverity severity = PEFindingSeverity::Medium;
    QString note;
};

QVector<ImportFlagRule> g_importFlags;
bool g_importFlagsLoaded = false;

struct ImportComboRequirement {
    QString function;
    QString dll;
};

struct ImportComboRule {
    QString id;
    QString name;
    PEFindingSeverity severity = PEFindingSeverity::High;
    QString note;
    QVector<ImportComboRequirement> requires;
};

QVector<ImportComboRule> g_importCombos;
bool g_importCombosLoaded = false;

QString normalizeDllToken(const QString &dll)
{
    QString d = dll.trimmed().toLower();
    if (d.endsWith(QStringLiteral(".dll"))) {
        d.chop(4);
    }
    return d;
}

bool importFlagMatches(const ImportFlagRule &rule, const QString &moduleName, const QString &functionName)
{
    if (rule.function.compare(functionName, Qt::CaseInsensitive) != 0) {
        return false;
    }
    if (rule.dll.isEmpty()) {
        return true;
    }
    return normalizeDllToken(rule.dll) == normalizeDllToken(moduleName);
}

QString formatMatchSample(const QVector<PEHardcodedMatch> &matches, int maxShow = 3)
{
    QStringList parts;
    const int limit = qMin(maxShow, matches.size());
    for (int i = 0; i < limit; ++i) {
        parts.append(matches.at(i).value);
    }
    if (matches.size() > maxShow) {
        parts.append(QStringLiteral("…"));
    }
    return parts.join(QStringLiteral(", "));
}

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

void loadImportFlags()
{
    g_importFlags.clear();
    g_importFlagsLoaded = true;

    const QString path = findConfigFile(QStringLiteral("import_flags.json"));
    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        return;
    }

    const QJsonArray entries = doc.object().value(QStringLiteral("entries")).toArray();
    for (const QJsonValue &val : entries) {
        if (!val.isObject()) {
            continue;
        }
        const QJsonObject obj = val.toObject();
        if (!obj.value(QStringLiteral("enabled")).toBool(true)) {
            continue;
        }
        ImportFlagRule rule;
        rule.id = obj.value(QStringLiteral("id")).toString();
        rule.function = obj.value(QStringLiteral("function")).toString();
        rule.dll = obj.value(QStringLiteral("dll")).toString();
        rule.severity = severityFromString(obj.value(QStringLiteral("severity")).toString());
        rule.note = obj.value(QStringLiteral("note")).toString();
        if (rule.function.isEmpty()) {
            continue;
        }
        if (rule.id.isEmpty()) {
            rule.id = rule.function.toLower();
        }
        g_importFlags.append(rule);
    }
}

const QVector<ImportFlagRule> &importFlags()
{
    if (!g_importFlagsLoaded) {
        loadImportFlags();
    }
    return g_importFlags;
}

const ImportFlagRule *importFlagById(const QString &id)
{
    for (const ImportFlagRule &rule : importFlags()) {
        if (rule.id == id) {
            return &rule;
        }
    }
    return nullptr;
}

bool parseImportComboRequirement(const QJsonValue &val, ImportComboRequirement *out)
{
    if (!out) {
        return false;
    }
    if (val.isString()) {
        const ImportFlagRule *flag = importFlagById(val.toString());
        if (!flag) {
            return false;
        }
        out->function = flag->function;
        out->dll = flag->dll;
        return !out->function.isEmpty();
    }
    if (!val.isObject()) {
        return false;
    }
    const QJsonObject obj = val.toObject();
    out->function = obj.value(QStringLiteral("function")).toString();
    out->dll = obj.value(QStringLiteral("dll")).toString();
    return !out->function.isEmpty();
}

void loadImportCombos()
{
    g_importCombos.clear();
    g_importCombosLoaded = true;

    const QString path = findConfigFile(QStringLiteral("import_combos.json"));
    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        return;
    }

    const QJsonArray combos = doc.object().value(QStringLiteral("combos")).toArray();
    for (const QJsonValue &val : combos) {
        if (!val.isObject()) {
            continue;
        }
        const QJsonObject obj = val.toObject();
        if (!obj.value(QStringLiteral("enabled")).toBool(true)) {
            continue;
        }
        ImportComboRule combo;
        combo.id = obj.value(QStringLiteral("id")).toString();
        combo.name = obj.value(QStringLiteral("name")).toString();
        combo.severity = severityFromString(obj.value(QStringLiteral("severity")).toString());
        combo.note = obj.value(QStringLiteral("note")).toString();
        if (combo.id.isEmpty()) {
            continue;
        }
        if (combo.name.isEmpty()) {
            combo.name = combo.id;
        }
        const QJsonArray requires = obj.value(QStringLiteral("requires")).toArray();
        for (const QJsonValue &reqVal : requires) {
            ImportComboRequirement req;
            if (parseImportComboRequirement(reqVal, &req)) {
                combo.requires.append(req);
            }
        }
        if (combo.requires.size() < 2) {
            continue;
        }
        g_importCombos.append(combo);
    }
}

const QVector<ImportComboRule> &importCombos()
{
    if (!g_importCombosLoaded) {
        loadImportCombos();
    }
    return g_importCombos;
}

QString importLookupKey(const QString &moduleName, const QString &functionName)
{
    return normalizeDllToken(moduleName) + QChar('|') + functionName.trimmed().toLower();
}

QSet<QString> collectImportedFunctionKeys(const PEDataModel &model)
{
    QSet<QString> keys;
    const auto scanModules = [&](const QMap<QString, QList<PEDataModel::ImportFunctionEntry>> &details) {
        for (auto modIt = details.constBegin(); modIt != details.constEnd(); ++modIt) {
            for (const PEDataModel::ImportFunctionEntry &entry : modIt.value()) {
                if (entry.name.isEmpty() || entry.importedByOrdinal) {
                    continue;
                }
                keys.insert(importLookupKey(modIt.key(), entry.name));
            }
        }
    };
    scanModules(model.getImportFunctions());
    scanModules(model.getDelayImportFunctions());
    return keys;
}

bool importComboRequirementMet(const ImportComboRequirement &req, const QSet<QString> &importKeys)
{
    return importKeys.contains(importLookupKey(req.dll, req.function));
}

void appendImportCombos(const PEDataModel &model, const PEFindingRule &metaRule, QVector<PEFindingInstance> &results)
{
    const QSet<QString> importKeys = collectImportedFunctionKeys(model);
    for (const ImportComboRule &combo : importCombos()) {
        QStringList matchedLabels;
        bool allMet = true;
        for (const ImportComboRequirement &req : combo.requires) {
            if (!importComboRequirementMet(req, importKeys)) {
                allMet = false;
                break;
            }
            if (req.dll.isEmpty()) {
                matchedLabels.append(req.function);
            } else {
                matchedLabels.append(req.dll + QChar('!') + req.function);
            }
        }
        if (!allMet) {
            continue;
        }
        QMap<QString, QString> params;
        params[QStringLiteral("name")] = combo.name;
        params[QStringLiteral("apis")] = matchedLabels.join(QStringLiteral(", "));
        params[QStringLiteral("note")] = combo.note.isEmpty() ? QStringLiteral("-") : combo.note;
        PEFindingInstance inst;
        inst.ruleId = metaRule.id + QChar(':') + combo.id;
        inst.severity = combo.severity;
        inst.title = LANG_PARAMS(QStringLiteral("findings/import_combo_title"), params);
        inst.detail = LANG_PARAMS(QStringLiteral("findings/import_combo_detail"), params);
        inst.treeField = QStringLiteral("Data Directories");
        inst.category = metaRule.category.isEmpty() ? QStringLiteral("imports") : metaRule.category;
        results.append(inst);
    }
}

void appendFlaggedImports(const PEDataModel &model, const PEFindingRule &metaRule, QVector<PEFindingInstance> &results)
{
    const auto scanModules = [&](const QMap<QString, QList<PEDataModel::ImportFunctionEntry>> &details) {
        for (auto modIt = details.constBegin(); modIt != details.constEnd(); ++modIt) {
            for (const PEDataModel::ImportFunctionEntry &entry : modIt.value()) {
                if (entry.name.isEmpty() || entry.importedByOrdinal) {
                    continue;
                }
                for (const ImportFlagRule &flag : importFlags()) {
                    if (!importFlagMatches(flag, modIt.key(), entry.name)) {
                        continue;
                    }
                    QMap<QString, QString> params;
                    params[QStringLiteral("dll")] = modIt.key();
                    params[QStringLiteral("function")] = entry.name;
                    params[QStringLiteral("note")] = flag.note.isEmpty() ? QStringLiteral("-")
                                                                       : flag.note;
                    PEFindingInstance inst;
                    inst.ruleId = metaRule.id + QChar(':') + flag.id;
                    inst.severity = flag.severity;
                    inst.title = LANG_PARAMS(QStringLiteral("findings/flagged_import_title"), params);
                    inst.detail = LANG_PARAMS(QStringLiteral("findings/flagged_import_detail"), params);
                    inst.category = metaRule.category.isEmpty() ? QStringLiteral("imports") : metaRule.category;
                    if (entry.thunkOffset > 0) {
                        inst.hexOffset = entry.thunkOffset;
                        inst.hexSize = 4;
                        inst.hasHexNav = true;
                    }
                    results.append(inst);
                }
            }
        }
    };

    scanModules(model.getImportFunctions());
    scanModules(model.getDelayImportFunctions());
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
    if (!rule.category.isEmpty()) {
        inst.category = rule.category;
    }
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
        rule.category = obj.value(QStringLiteral("category")).toString();
        rule.threshold = obj.value(QStringLiteral("threshold")).toDouble(7.0);
        rule.maxImports = obj.value(QStringLiteral("maxImports")).toInt(3);
        rule.minCount = obj.value(QStringLiteral("minCount")).toInt(5);
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
    const IMAGE_DOS_HEADER *dos = model.getDOSHeader();
    const QList<const IMAGE_SECTION_HEADER *> sections = model.getSections();
    const PEOverlayInfo overlay = model.getOverlayInfo();
    const PEEntropySummary entropy = model.getEntropySummary();
    const QStringList imports = model.getImports();
    const PEPdbInfo pdb = model.getPdbInfo();
    const PEVersionInfo version = model.getVersionInfo();
    const PEAnalysisMetadata metadata = model.getAnalysisMetadata();
    const PEContentScan contentScan = model.getContentScan();
    const OptionalHeaderView optView = viewOptionalHeader(opt);

    for (const PEFindingRule &rule : rules()) {
        if (!rule.enabled) {
            continue;
        }

        const QString check = rule.check;

        if (check == QStringLiteral("missing_aslr")) {
            if (opt && !PEUtils::hasASLR(optView.dllCharacteristics)) {
                appendInstance(results, rule, QString());
            }
            continue;
        }

        if (check == QStringLiteral("missing_dep")) {
            if (opt && !PEUtils::hasDEP(optView.dllCharacteristics)) {
                appendInstance(results, rule, QString());
            }
            continue;
        }

        if (check == QStringLiteral("missing_cfg")) {
            if (opt && !PEUtils::hasControlFlowGuard(optView.dllCharacteristics)) {
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

        if (check == QStringLiteral("delay_import_present")) {
            const QStringList delayImports = model.getDelayImports();
            if (!delayImports.isEmpty()) {
                QMap<QString, QString> params;
                params[QStringLiteral("count")] = QString::number(delayImports.size());
                quint32 fo = 0;
                quint32 highlightSize = 0;
                const IMAGE_DATA_DIRECTORY *delayDir = optionalDataDirectory(opt, 13);
                if (delayDir && delayDir->VirtualAddress != 0 && rvaToFileOffset) {
                    fo = rvaToFileOffset(delayDir->VirtualAddress);
                    highlightSize = qMax(delayDir->Size, 1u);
                }
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params), rule.treeField, fo,
                               highlightSize);
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

        if (check == QStringLiteral("checksum_zero")) {
            if (opt && optView.checksum == 0) {
                appendInstance(results, rule, QString(), QStringLiteral("CheckSum"));
            }
            continue;
        }

        if (check == QStringLiteral("checksum_mismatch")) {
            if (opt && metadata.imageChecksumComputed && optView.checksum != 0
                && optView.checksum != metadata.computedImageChecksum) {
                QMap<QString, QString> params;
                params[QStringLiteral("stored")] = PEUtils::formatHexWidth(optView.checksum, 8);
                params[QStringLiteral("computed")] =
                    PEUtils::formatHexWidth(metadata.computedImageChecksum, 8);
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                               QStringLiteral("CheckSum"));
            }
            continue;
        }

        if (check == QStringLiteral("dll_no_exports")) {
            if (isDllImage(fileHdr) && model.getExportFunctions().isEmpty()) {
                appendInstance(results, rule, QString(), QStringLiteral("Data Directories"));
            }
            continue;
        }

        if (check == QStringLiteral("no_rich_header")) {
            if (dos && metadata.imageChecksumComputed && !metadata.richHeaderPresent) {
                appendInstance(results, rule, QString(), QStringLiteral("Rich Header"));
            }
            continue;
        }

        if (check == QStringLiteral("pdb_present")) {
            if (pdb.present) {
                QMap<QString, QString> params;
                params[QStringLiteral("path")] = pdb.path.isEmpty() ? pdb.format : pdb.path;
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                               QStringLiteral("PDB Path"));
            }
            continue;
        }

        if (check == QStringLiteral("debug_info_stripped")) {
            if (fileHdr && (fileHdr->Characteristics & kImageFileDebugStripped) != 0) {
                appendInstance(results, rule, QString(), QStringLiteral("Characteristics"));
            }
            continue;
        }

        if (check == QStringLiteral("writable_code_section")) {
            for (int i = 0; i < sections.size(); ++i) {
                const IMAGE_SECTION_HEADER *sec = sections.at(i);
                if (!sec) {
                    continue;
                }
                const QString name = sectionNameFromHeader(sec);
                const quint32 chars = sec->Characteristics;
                if ((chars & kSectionWrite) && (chars & kSectionExecute)
                    && sectionNameLooksLikeCode(name)) {
                    QMap<QString, QString> params;
                    params[QStringLiteral("section")] = name;
                    appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                                   sectionTreeKey(i, name), sec->PointerToRawData,
                                   qMax(sec->SizeOfRawData, 1u));
                }
            }
            continue;
        }

        if (check == QStringLiteral("executable_data_section")) {
            for (int i = 0; i < sections.size(); ++i) {
                const IMAGE_SECTION_HEADER *sec = sections.at(i);
                if (!sec) {
                    continue;
                }
                const QString name = sectionNameFromHeader(sec);
                const quint32 chars = sec->Characteristics;
                if ((chars & kSectionExecute) && sectionNameLooksLikeData(name)) {
                    QMap<QString, QString> params;
                    params[QStringLiteral("section")] = name;
                    appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                                   sectionTreeKey(i, name), sec->PointerToRawData,
                                   qMax(sec->SizeOfRawData, 1u));
                }
            }
            continue;
        }

        if (check == QStringLiteral("section_raw_gt_virtual")) {
            for (int i = 0; i < sections.size(); ++i) {
                const IMAGE_SECTION_HEADER *sec = sections.at(i);
                if (!sec) {
                    continue;
                }
                const quint32 virtualSize = sec->getVirtualSize();
                const quint32 rawSize = sec->SizeOfRawData;
                if (virtualSize == 0 || rawSize <= virtualSize) {
                    continue;
                }
                const double ratio = static_cast<double>(rawSize) / static_cast<double>(virtualSize);
                if (ratio < rule.threshold) {
                    continue;
                }
                const QString name = sectionNameFromHeader(sec);
                QMap<QString, QString> params;
                params[QStringLiteral("section")] = name;
                params[QStringLiteral("raw")] = QString::number(rawSize);
                params[QStringLiteral("virtual")] = QString::number(virtualSize);
                params[QStringLiteral("ratio")] = QString::number(ratio, 'f', 2);
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                               sectionTreeKey(i, name), sec->PointerToRawData,
                               qMax(rawSize, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("future_timestamp")) {
            if (fileHdr && fileHdr->TimeDateStamp != 0) {
                const quint32 now =
                    static_cast<quint32>(QDateTime::currentDateTimeUtc().toSecsSinceEpoch());
                if (fileHdr->TimeDateStamp > now) {
                    QMap<QString, QString> params;
                    params[QStringLiteral("date")] = PEUtils::formatTimestamp(fileHdr->TimeDateStamp);
                    appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                                   QStringLiteral("TimeDateStamp"));
                }
            }
            continue;
        }

        if (check == QStringLiteral("gui_few_imports")) {
            if (!isDllImage(fileHdr) && optView.subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI
                && !imports.isEmpty() && imports.size() <= rule.maxImports) {
                QMap<QString, QString> params;
                params[QStringLiteral("count")] = QString::number(imports.size());
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                               QStringLiteral("Subsystem"));
            }
            continue;
        }

        if (check == QStringLiteral("tls_callbacks_present")) {
            if (metadata.tlsCallbacksPresent) {
                appendInstance(results, rule, QString(), QStringLiteral("TLS Directory"));
            }
            continue;
        }

        if (check == QStringLiteral("unsigned_executable")) {
            if (!isDllImage(fileHdr) && opt && !hasAuthenticodeDirectory(opt)) {
                appendInstance(results, rule, QString(), QStringLiteral("Certificate Directory"));
            }
            continue;
        }

        if (check == QStringLiteral("relocations_stripped_aslr")) {
            if (fileHdr && (fileHdr->Characteristics & kImageFileRelocsStripped) != 0
                && PEUtils::hasASLR(optView.dllCharacteristics)) {
                appendInstance(results, rule, QString(), QStringLiteral("Characteristics"));
            }
            continue;
        }

        if (check == QStringLiteral("version_info_missing")) {
            if (!isDllImage(fileHdr) && !version.present) {
                appendInstance(results, rule, QString(), QStringLiteral("File Version"));
            }
            continue;
        }

        if (check == QStringLiteral("manifest_require_admin")) {
            if (version.manifestPresent
                && version.manifestExecutionLevel.contains(QStringLiteral("requireAdministrator"),
                                                           Qt::CaseInsensitive)) {
                appendInstance(results, rule, QString(), QStringLiteral("Manifest UAC"));
            }
            continue;
        }

        if (check == QStringLiteral("high_ordinal_imports")) {
            int total = 0;
            int ordinals = 0;
            const auto &details = model.getImportFunctions();
            for (auto it = details.constBegin(); it != details.constEnd(); ++it) {
                for (const PEDataModel::ImportFunctionEntry &entry : it.value()) {
                    ++total;
                    if (entry.importedByOrdinal) {
                        ++ordinals;
                    }
                }
            }
            if (total >= rule.minCount) {
                const double ratio = static_cast<double>(ordinals) / static_cast<double>(total);
                if (ratio >= rule.threshold) {
                    QMap<QString, QString> params;
                    params[QStringLiteral("ordinal")] = QString::number(ordinals);
                    params[QStringLiteral("total")] = QString::number(total);
                    params[QStringLiteral("percent")] =
                        QString::number(ratio * 100.0, 'f', 0);
                    appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params));
                }
            }
            continue;
        }

        if (check == QStringLiteral("packer_section_name")) {
            for (int i = 0; i < sections.size(); ++i) {
                const IMAGE_SECTION_HEADER *sec = sections.at(i);
                if (!sec) {
                    continue;
                }
                const QString name = sectionNameFromHeader(sec);
                if (!isKnownPackerSectionName(name)) {
                    continue;
                }
                QMap<QString, QString> params;
                params[QStringLiteral("section")] = name;
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                               sectionTreeKey(i, name), sec->PointerToRawData,
                               qMax(sec->SizeOfRawData, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("flagged_import")) {
            appendFlaggedImports(model, rule, results);
            continue;
        }

        if (check == QStringLiteral("import_combo")) {
            appendImportCombos(model, rule, results);
            continue;
        }

        if (check == QStringLiteral("hardcoded_url")) {
            if (!contentScan.urls.isEmpty()) {
                QMap<QString, QString> params;
                params[QStringLiteral("count")] = QString::number(contentScan.urls.size());
                const PEHardcodedMatch &first = contentScan.urls.first();
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params), rule.treeField,
                               first.fileOffset, qMax(first.length, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("hardcoded_ip")) {
            if (!contentScan.ips.isEmpty()) {
                QMap<QString, QString> params;
                params[QStringLiteral("count")] = QString::number(contentScan.ips.size());
                const PEHardcodedMatch &first = contentScan.ips.first();
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params), QString(),
                               first.fileOffset, qMax(first.length, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("hardcoded_registry")) {
            if (!contentScan.registryPaths.isEmpty()) {
                QMap<QString, QString> params;
                params[QStringLiteral("count")] = QString::number(contentScan.registryPaths.size());
                const PEHardcodedMatch &first = contentScan.registryPaths.first();
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params), QString(),
                               first.fileOffset, qMax(first.length, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("suspicious_command")) {
            if (!contentScan.suspiciousCommands.isEmpty()) {
                QMap<QString, QString> params;
                params[QStringLiteral("count")] = QString::number(contentScan.suspiciousCommands.size());
                const PEHardcodedMatch &first = contentScan.suspiciousCommands.first();
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params), QString(),
                               first.fileOffset, qMax(first.length, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("nonstandard_dos_stub")) {
            if (contentScan.dosStubNonStandard) {
                QMap<QString, QString> params;
                params[QStringLiteral("message")] = contentScan.dosStubMessage;
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                               QStringLiteral("DOS_STUB"), contentScan.dosStubOffset,
                               qMax(contentScan.dosStubSize, 1u));
            }
            continue;
        }

        if (check == QStringLiteral("duplicate_exports")) {
            QHash<QString, int> nameCounts;
            QHash<QString, QString> displayNames;
            for (const PEDataModel::ExportFunctionEntry &entry : model.getExportFunctions()) {
                if (entry.name.isEmpty() || entry.name == QStringLiteral("[ - ]")) {
                    continue;
                }
                const QString key = entry.name.toLower();
                nameCounts[key] += 1;
                if (!displayNames.contains(key)) {
                    displayNames.insert(key, entry.name);
                }
            }
            for (auto it = nameCounts.constBegin(); it != nameCounts.constEnd(); ++it) {
                if (it.value() < 2) {
                    continue;
                }
                QMap<QString, QString> params;
                params[QStringLiteral("name")] = displayNames.value(it.key(), it.key());
                params[QStringLiteral("count")] = QString::number(it.value());
                appendInstance(results, rule, LANG_PARAMS(rule.detailKey, params),
                               QStringLiteral("Data Directories"));
            }
            continue;
        }
    }

    return results;
}

QString PEFindingsEngine::categoryKeyForRule(const PEFindingRule &rule)
{
    if (!rule.category.isEmpty()) {
        return rule.category;
    }
    const QString check = rule.check;
    if (check == QStringLiteral("missing_aslr") || check == QStringLiteral("missing_dep")
        || check == QStringLiteral("missing_cfg")
        || check == QStringLiteral("relocations_stripped_aslr")) {
        return QStringLiteral("hardening");
    }
    if (check.contains(QStringLiteral("import")) || check == QStringLiteral("no_imports")
        || check == QStringLiteral("few_imports") || check == QStringLiteral("gui_few_imports")
        || check == QStringLiteral("high_ordinal_imports") || check == QStringLiteral("dll_no_exports")
        || check == QStringLiteral("flagged_import") || check == QStringLiteral("import_combo")) {
        return QStringLiteral("imports");
    }
    if (check.contains(QStringLiteral("url")) || check.contains(QStringLiteral("ip"))
        || check.contains(QStringLiteral("registry")) || check.contains(QStringLiteral("command"))
        || check.contains(QStringLiteral("dos_stub")) || check.contains(QStringLiteral("duplicate_export"))) {
        return QStringLiteral("content");
    }
    if (check.contains(QStringLiteral("timestamp")) || check.contains(QStringLiteral("checksum"))
        || check.contains(QStringLiteral("rich")) || check.contains(QStringLiteral("pdb"))
        || check.contains(QStringLiteral("debug")) || check.contains(QStringLiteral("version"))
        || check.contains(QStringLiteral("manifest")) || check.contains(QStringLiteral("unsigned"))
        || check == QStringLiteral("certificate_present")) {
        return QStringLiteral("metadata");
    }
  return QStringLiteral("content");
}

QString PEFindingsEngine::categoryDisplayName(const QString &categoryKey)
{
    if (categoryKey == QStringLiteral("hardening")) {
        return LANG(QStringLiteral("findings/category_hardening"));
    }
    if (categoryKey == QStringLiteral("imports")) {
        return LANG(QStringLiteral("findings/category_imports"));
    }
    if (categoryKey == QStringLiteral("metadata")) {
        return LANG(QStringLiteral("findings/category_metadata"));
    }
    if (categoryKey == QStringLiteral("content")) {
        return LANG(QStringLiteral("findings/category_content"));
    }
    return LANG(QStringLiteral("findings/category_other"));
}

QVector<PEFindingInstance> PEFindingsEngine::evaluateHardeningPasses(const PEDataModel &model)
{
    QVector<PEFindingInstance> passes;
    if (!model.isValid()) {
        return passes;
    }
    const IMAGE_OPTIONAL_HEADER *opt = model.getOptionalHeader();
    if (!opt) {
        return passes;
    }
    const OptionalHeaderView optView = viewOptionalHeader(opt);

    auto addPass = [&](const char *id, const char *titleKey, const char *detailKey, const char *treeField) {
        PEFindingInstance inst;
        inst.ruleId = QString::fromLatin1(id);
        inst.severity = PEFindingSeverity::Info;
        inst.title = LANG(QString::fromLatin1(titleKey));
        inst.detail = LANG(QString::fromLatin1(detailKey));
        inst.treeField = QString::fromLatin1(treeField);
        inst.category = QStringLiteral("hardening");
        inst.isPass = true;
        passes.append(inst);
    };

    if (PEUtils::hasASLR(optView.dllCharacteristics)) {
        addPass("aslr_enabled", "findings/aslr_pass_title", "findings/aslr_pass_detail", "DllCharacteristics");
    }
    if (PEUtils::hasDEP(optView.dllCharacteristics)) {
        addPass("dep_enabled", "findings/dep_pass_title", "findings/dep_pass_detail", "DllCharacteristics");
    }
    if (PEUtils::hasControlFlowGuard(optView.dllCharacteristics)) {
        addPass("cfg_enabled", "findings/cfg_pass_title", "findings/cfg_pass_detail", "DllCharacteristics");
    }
    return passes;
}

bool PEFindingsEngine::isFlaggedImport(const QString &moduleName, const QString &functionName,
                                       PEFindingSeverity *severityOut, QString *noteOut)
{
    if (functionName.isEmpty()) {
        return false;
    }
    for (const ImportFlagRule &flag : importFlags()) {
        if (!importFlagMatches(flag, moduleName, functionName)) {
            continue;
        }
        if (severityOut) {
            *severityOut = flag.severity;
        }
        if (noteOut) {
            *noteOut = flag.note;
        }
        return true;
    }
    return false;
}
