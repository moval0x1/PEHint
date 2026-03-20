/**
 * @file pe_dependency_analyzer.cpp
 * @brief Implementation of PE Dependency Analyzer
 */

#include "pe_dependency_analyzer.h"
#include "pe_structures.h"
#include <QDir>
#include <QFileInfo>
#include <QFile>
#include <QHash>
#include <QSet>
#include <QXmlStreamReader>
#include <QRegularExpression>

namespace {

constexpr quint32 kRtManifest = 24; // RT_MANIFEST
constexpr quint32 kMaxManifestBytes = 512 * 1024;

bool peLayoutForResources(const QByteArray &data,
                          quint32 &resourceRva,
                          quint32 &resourceSize,
                          quint32 &sizeOfHeaders,
                          QList<IMAGE_SECTION_HEADER> &sections)
{
    resourceRva = 0;
    resourceSize = 0;
    sizeOfHeaders = 0;
    sections.clear();
    if (data.size() < static_cast<int>(sizeof(IMAGE_DOS_HEADER))) return false;
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(data.constData());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew <= 0) return false;
    const quint32 ntOffset = static_cast<quint32>(dos->e_lfanew);
    if (ntOffset + 4 + sizeof(IMAGE_FILE_HEADER) >= static_cast<quint32>(data.size())) return false;
    const quint32 ntSig = *reinterpret_cast<const quint32 *>(data.constData() + ntOffset);
    if (ntSig != IMAGE_NT_SIGNATURE) return false;
    const auto *fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER *>(data.constData() + ntOffset + 4);
    const quint32 optionalOffset = ntOffset + 4 + sizeof(IMAGE_FILE_HEADER);
    if (optionalOffset + fileHdr->SizeOfOptionalHeader > static_cast<quint32>(data.size())) return false;
    const quint16 magic = *reinterpret_cast<const quint16 *>(data.constData() + optionalOffset);
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER32) > static_cast<quint32>(data.size())) return false;
        const auto *opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32 *>(data.constData() + optionalOffset);
        resourceRva = opt->DataDirectory[2].VirtualAddress;
        resourceSize = opt->DataDirectory[2].Size;
        sizeOfHeaders = opt->SizeOfHeaders;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER64) > static_cast<quint32>(data.size())) return false;
        const auto *opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(data.constData() + optionalOffset);
        resourceRva = opt->DataDirectory[2].VirtualAddress;
        resourceSize = opt->DataDirectory[2].Size;
        sizeOfHeaders = opt->SizeOfHeaders;
    } else {
        return false;
    }
    const quint32 sectionOffset = optionalOffset + fileHdr->SizeOfOptionalHeader;
    if (sectionOffset + fileHdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > static_cast<quint32>(data.size()))
        return false;
    sections.reserve(fileHdr->NumberOfSections);
    for (quint16 i = 0; i < fileHdr->NumberOfSections; ++i) {
        const quint32 off = sectionOffset + i * sizeof(IMAGE_SECTION_HEADER);
        const auto *sec = reinterpret_cast<const IMAGE_SECTION_HEADER *>(data.constData() + off);
        sections.append(*sec);
    }
    return true;
}

quint32 rvaToFileOffset(quint32 rva,
                        quint32 sizeOfHeaders,
                        const QList<IMAGE_SECTION_HEADER> &sections,
                        quint32 fileSize)
{
    if (rva < sizeOfHeaders && rva < fileSize) {
        return rva;
    }
    for (const IMAGE_SECTION_HEADER &s : sections) {
        const quint32 sectionStart = s.VirtualAddress;
        const quint32 sectionSpan = qMax(s.SizeOfRawData, s.Misc.VirtualSize);
        if (sectionSpan == 0) continue;
        if (rva >= sectionStart && rva < sectionStart + sectionSpan) {
            const quint32 delta = rva - sectionStart;
            if (delta >= s.SizeOfRawData) return 0;
            const quint32 offset = s.PointerToRawData + delta;
            if (offset < fileSize) return offset;
            return 0;
        }
    }
    return 0;
}

QString readAsciiZ(const QByteArray &data, quint32 offset, int maxLen = 260)
{
    if (offset >= static_cast<quint32>(data.size())) return QString();
    QByteArray bytes;
    bytes.reserve(maxLen);
    for (quint32 i = offset; i < static_cast<quint32>(data.size()) && bytes.size() < maxLen; ++i) {
        const char c = data.at(static_cast<int>(i));
        if (c == '\0') break;
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E) return QString();
        bytes.append(c);
    }
    return QString::fromLatin1(bytes);
}

bool walkResourceFindManifest(const QByteArray &data,
                              quint32 resRootFileOff,
                              quint32 dirFileOff,
                              int depth,
                              quint32 sizeOfHeaders,
                              const QList<IMAGE_SECTION_HEADER> &sections,
                              quint32 fileSize,
                              QByteArray &outManifest)
{
    if (depth > 8) return false;
    if (dirFileOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) return false;
    const auto *dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY *>(data.constData() + dirFileOff);
    const quint32 total = static_cast<quint32>(dir->NumberOfNamedEntries) + static_cast<quint32>(dir->NumberOfIdEntries);
    quint32 entryOff = dirFileOff + sizeof(IMAGE_RESOURCE_DIRECTORY);
    for (quint32 i = 0; i < total; ++i) {
        if (entryOff + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileSize) break;
        const auto *e = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY *>(data.constData() + entryOff);
        entryOff += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

        if (depth == 0) {
            if (e->isNameString()) continue;
            if (e->getName() != kRtManifest) continue;
        }

        if (e->isDataDirectory()) {
            const quint32 nextOff = resRootFileOff + (e->getOffsetToData() & 0x7FFFFFFF);
            if (walkResourceFindManifest(data, resRootFileOff, nextOff, depth + 1, sizeOfHeaders, sections,
                                         fileSize, outManifest)) {
                return true;
            }
        } else {
            const quint32 dataEntryOff = resRootFileOff + e->getOffsetToData();
            if (dataEntryOff + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > fileSize) continue;
            const auto *de = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY *>(data.constData() + dataEntryOff);
            const quint32 rva = de->OffsetToData;
            const quint32 sz = de->Size;
            if (sz == 0 || sz > kMaxManifestBytes) continue;
            const quint32 raw = rvaToFileOffset(rva, sizeOfHeaders, sections, fileSize);
            if (raw == 0 || raw + sz > fileSize) continue;
            outManifest = data.mid(static_cast<int>(raw), static_cast<int>(sz));
            return !outManifest.isEmpty();
        }
    }
    return false;
}

bool extractEmbeddedManifest(const QByteArray &peData, QByteArray &outManifest)
{
    outManifest.clear();
    quint32 resourceRva = 0;
    quint32 resourceSize = 0;
    quint32 sizeOfHeaders = 0;
    QList<IMAGE_SECTION_HEADER> sections;
    if (!peLayoutForResources(peData, resourceRva, resourceSize, sizeOfHeaders, sections)) return false;
    if (resourceRva == 0) return false;
    const quint32 fileSize = static_cast<quint32>(peData.size());
    const quint32 resRootOff = rvaToFileOffset(resourceRva, sizeOfHeaders, sections, fileSize);
    if (resRootOff == 0) return false;
    return walkResourceFindManifest(peData, resRootOff, resRootOff, 0, sizeOfHeaders, sections,
                                    fileSize, outManifest);
}

QString manifestBytesToUtf8Xml(const QByteArray &raw)
{
    if (raw.isEmpty()) return QString();
    if (raw.size() >= 3
        && static_cast<unsigned char>(raw[0]) == 0xEF && static_cast<unsigned char>(raw[1]) == 0xBB
        && static_cast<unsigned char>(raw[2]) == 0xBF) {
        return QString::fromUtf8(raw.constData() + 3, raw.size() - 3);
    }
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF && static_cast<unsigned char>(raw[1]) == 0xFE) {
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(raw.constData() + 2),
                                  (raw.size() - 2) / 2);
    }
    return QString::fromUtf8(raw);
}

QStringList privatePathsFromManifestText(const QString &xml, const QString &exeDir)
{
    QStringList out;
    if (exeDir.isEmpty()) return out;
    static const QRegularExpression re(QStringLiteral("privatePath\\s*=\\s*\"([^\"]*)\""));
    QRegularExpressionMatchIterator it = re.globalMatch(xml);
    while (it.hasNext()) {
        const QString cap = it.next().captured(1);
        const QStringList parts = cap.split(QLatin1Char(';'), Qt::SkipEmptyParts);
        for (const QString &p : parts) {
            const QString trimmed = p.trimmed();
            if (trimmed.isEmpty()) continue;
            const QDir base(exeDir);
            if (!base.exists()) continue;
            const QString abs = base.absoluteFilePath(trimmed);
            const QDir sub(abs);
            if (sub.exists()) out << sub.absolutePath();
        }
    }
    return out;
}

bool winSxSFolderMatchesAssembly(const QString &folderName,
                                 const QString &assemblyNameLower,
                                 const QString &publicKeyTokenLower,
                                 const QString &version,
                                 const QString &archPrefix)
{
    if (assemblyNameLower.isEmpty() || publicKeyTokenLower.isEmpty()) return false;
    if (!folderName.contains(assemblyNameLower, Qt::CaseInsensitive)) return false;
    if (!folderName.contains(publicKeyTokenLower, Qt::CaseInsensitive)) return false;
    if (!version.isEmpty() && !folderName.contains(version)) return false;
    if (!archPrefix.isEmpty() && !folderName.startsWith(archPrefix + QLatin1Char('_'), Qt::CaseInsensitive))
        return false;
    return true;
}

QStringList winSxSPathsForAssembly(const QString &assemblyName,
                                   const QString &version,
                                   const QString &publicKeyToken,
                                   const QString &processorArchitecture,
                                   const QString &windowsRoot)
{
    QStringList out;
#ifdef Q_OS_WIN
    if (windowsRoot.isEmpty()) return out;
    const QString nameLower = assemblyName.toLower();
    const QString tokenLower = publicKeyToken.toLower();
    QString archPrefix;
    const QString arch = processorArchitecture.toLower();
    if (arch == QLatin1String("amd64") || arch == QLatin1String("ia64")) archPrefix = QStringLiteral("amd64");
    else if (arch == QLatin1String("x86")) archPrefix = QStringLiteral("x86");
    else if (arch == QLatin1String("wow64")) archPrefix = QStringLiteral("wow64");

    const QDir sx(QDir(windowsRoot).absoluteFilePath(QStringLiteral("WinSxS")));
    if (!sx.exists()) return out;
    const QStringList dirs = sx.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    const QStringList archVariants = archPrefix.isEmpty()
        ? QStringList{QString(), QStringLiteral("amd64"), QStringLiteral("x86"), QStringLiteral("wow64")}
        : QStringList{archPrefix};
    QSet<QString> added;
    for (const QString &d : dirs) {
        for (const QString &ap : archVariants) {
            if (winSxSFolderMatchesAssembly(d, nameLower, tokenLower, version, ap)) {
                const QString abs = sx.absoluteFilePath(d);
                if (!added.contains(abs)) {
                    added.insert(abs);
                    out << abs;
                }
                break;
            }
        }
    }
#else
    Q_UNUSED(assemblyName);
    Q_UNUSED(version);
    Q_UNUSED(publicKeyToken);
    Q_UNUSED(processorArchitecture);
    Q_UNUSED(windowsRoot);
#endif
    return out;
}

QStringList collectDependentAssemblyPaths(const QString &xml, const QString &exeDir, const QString &windowsRoot)
{
    QStringList out = privatePathsFromManifestText(xml, exeDir);
    QXmlStreamReader reader(xml);
    int dependentAssemblyDepth = 0;
    while (!reader.atEnd()) {
        reader.readNext();
        if (reader.isStartElement()) {
            if (reader.name() == QLatin1String("dependentAssembly")) {
                ++dependentAssemblyDepth;
            } else if (dependentAssemblyDepth > 0 && reader.name() == QLatin1String("assemblyIdentity")) {
                const QXmlStreamAttributes a = reader.attributes();
                const QString type = a.value(QLatin1String("type")).toString();
                if (!type.isEmpty() && type.compare(QLatin1String("win32"), Qt::CaseInsensitive) != 0
                    && type.compare(QLatin1String("*"), Qt::CaseInsensitive) != 0) {
                    continue;
                }
                const QString name = a.value(QLatin1String("name")).toString();
                const QString ver = a.value(QLatin1String("version")).toString();
                const QString token = a.value(QLatin1String("publicKeyToken")).toString();
                const QString proc = a.value(QLatin1String("processorArchitecture")).toString();
                if (!name.isEmpty()) {
                    out << winSxSPathsForAssembly(name, ver, token, proc, windowsRoot);
                }
            }
        } else if (reader.isEndElement()) {
            if (reader.name() == QLatin1String("dependentAssembly") && dependentAssemblyDepth > 0) {
                --dependentAssemblyDepth;
            }
        }
    }
    out.removeDuplicates();
    out.removeAll(QString());
    return out;
}

QStringList buildSearchPaths(const QString &peFilePath, bool *manifestParsedOut)
{
    bool manifestParsed = false;
    QStringList searchPaths;
    QString exeDir;
    QString systemRoot = QStringLiteral("C:\\Windows");
#ifdef Q_OS_WIN
    systemRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
#endif
    if (!peFilePath.isEmpty()) {
        const QFileInfo fi(peFilePath);
        if (fi.exists()) {
            exeDir = fi.absolutePath();
            searchPaths << exeDir;
        }
    }

    QString manifestXml;
    if (!peFilePath.isEmpty()) {
        QFile pe(peFilePath);
        if (pe.open(QIODevice::ReadOnly)) {
            const QByteArray peData = pe.readAll();
            pe.close();
            QByteArray rawManifest;
            if (extractEmbeddedManifest(peData, rawManifest) && !rawManifest.isEmpty()) {
                manifestXml = manifestBytesToUtf8Xml(rawManifest);
                manifestParsed = true;
            }
        }
        if (manifestXml.isEmpty()) {
            const QFileInfo fi(peFilePath);
            QFile mf(fi.absolutePath() + QLatin1Char('/') + fi.completeBaseName() + QStringLiteral(".manifest"));
            if (mf.open(QIODevice::ReadOnly)) {
                manifestXml = QString::fromUtf8(mf.readAll());
                mf.close();
                if (!manifestXml.isEmpty()) manifestParsed = true;
            }
        }
    }

    if (!manifestXml.isEmpty()) {
        const QStringList extra = collectDependentAssemblyPaths(manifestXml, exeDir, systemRoot);
        for (const QString &p : extra) {
            if (!p.isEmpty() && !searchPaths.contains(p)) searchPaths << p;
        }
    }

#ifdef Q_OS_WIN
    searchPaths << systemRoot + QStringLiteral("\\System32") << systemRoot + QStringLiteral("\\System32\\drivers")
                << systemRoot + QStringLiteral("\\SysWOW64");
    const QString pathEnv = qEnvironmentVariable("PATH");
    if (!pathEnv.isEmpty()) {
        for (const QString &p : pathEnv.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
            const QString trimmed = p.trimmed();
            if (!trimmed.isEmpty() && !searchPaths.contains(trimmed)) searchPaths << trimmed;
        }
    }
#endif
    if (manifestParsedOut) *manifestParsedOut = manifestParsed;
    return searchPaths;
}

QString normalizeModuleName(const QString &moduleName)
{
    QString normalized = QFileInfo(moduleName.trimmed()).fileName();
    return normalized.toLower();
}

QStringList parseImportModulesFromFile(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return {};
    const QByteArray data = file.readAll();
    file.close();
    if (data.size() < static_cast<int>(sizeof(IMAGE_DOS_HEADER))) return {};

    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.constData());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return {};
    if (dos->e_lfanew <= 0) return {};
    const quint32 ntOffset = static_cast<quint32>(dos->e_lfanew);
    if (ntOffset + 4 + sizeof(IMAGE_FILE_HEADER) >= static_cast<quint32>(data.size())) return {};

    const quint32 ntSig = *reinterpret_cast<const quint32*>(data.constData() + ntOffset);
    if (ntSig != IMAGE_NT_SIGNATURE) return {};

    const auto *fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(data.constData() + ntOffset + 4);
    const quint32 optionalOffset = ntOffset + 4 + sizeof(IMAGE_FILE_HEADER);
    if (optionalOffset + fileHdr->SizeOfOptionalHeader > static_cast<quint32>(data.size())) return {};

    const quint16 magic = *reinterpret_cast<const quint16*>(data.constData() + optionalOffset);
    quint32 importRva = 0;
    quint32 sizeOfHeaders = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER32) > static_cast<quint32>(data.size())) return {};
        const auto *opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data.constData() + optionalOffset);
        importRva = opt->DataDirectory[1].VirtualAddress; // Import Directory
        sizeOfHeaders = opt->SizeOfHeaders;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER64) > static_cast<quint32>(data.size())) return {};
        const auto *opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data.constData() + optionalOffset);
        importRva = opt->DataDirectory[1].VirtualAddress; // Import Directory
        sizeOfHeaders = opt->SizeOfHeaders;
    } else {
        return {};
    }
    if (importRva == 0) return {};

    const quint32 sectionOffset = optionalOffset + fileHdr->SizeOfOptionalHeader;
    if (sectionOffset + fileHdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > static_cast<quint32>(data.size())) return {};
    QList<IMAGE_SECTION_HEADER> sections;
    sections.reserve(fileHdr->NumberOfSections);
    for (quint16 i = 0; i < fileHdr->NumberOfSections; ++i) {
        const quint32 off = sectionOffset + i * sizeof(IMAGE_SECTION_HEADER);
        const auto *sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(data.constData() + off);
        sections.append(*sec);
    }

    const quint32 importsOffset = rvaToFileOffset(importRva, sizeOfHeaders, sections, static_cast<quint32>(data.size()));
    if (importsOffset == 0 || importsOffset >= static_cast<quint32>(data.size())) return {};

    QStringList modules;
    QSet<QString> seen;
    constexpr int kMaxDescriptors = 4096;
    for (int idx = 0; idx < kMaxDescriptors; ++idx) {
        const quint32 descOff = importsOffset + static_cast<quint32>(idx) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (descOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > static_cast<quint32>(data.size())) break;
        const auto *desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(data.constData() + descOff);
        if (desc->Name == 0 && desc->FirstThunk == 0 && desc->OriginalFirstThunk == 0) break;
        if (desc->Name == 0) continue;
        const quint32 nameOff = rvaToFileOffset(desc->Name, sizeOfHeaders, sections, static_cast<quint32>(data.size()));
        if (nameOff == 0) continue;
        const QString module = readAsciiZ(data, nameOff).trimmed();
        if (module.isEmpty()) continue;
        const QString key = module.toLower();
        if (seen.contains(key)) continue;
        seen.insert(key);
        modules.append(module);
    }
    return modules;
}

DependencyNode buildNodeRecursive(const QString &moduleName,
                                  int depth,
                                  int maxDepth,
                                  const QStringList &searchPaths,
                                  QSet<QString> &ancestorModules,
                                  QHash<QString, QStringList> &importsByResolvedPath)
{
    DependencyNode node;
    node.moduleName = moduleName;
    node.depth = depth;
    node.resolvedPath = PEDependencyAnalyzer::resolveDependencyPath(moduleName, searchPaths);
    node.foundOnSystem = !node.resolvedPath.isEmpty();

    const QString moduleKey = normalizeModuleName(moduleName);
    if (moduleKey.isEmpty()) return node;
    if (ancestorModules.contains(moduleKey)) {
        node.cycleDetected = true;
        return node;
    }
    if (depth >= maxDepth) {
        node.truncatedByDepth = node.foundOnSystem;
        return node;
    }
    if (!node.foundOnSystem) return node;

    ancestorModules.insert(moduleKey);
    QStringList childImports = importsByResolvedPath.value(node.resolvedPath);
    if (childImports.isEmpty() && !importsByResolvedPath.contains(node.resolvedPath)) {
        childImports = parseImportModulesFromFile(node.resolvedPath);
        importsByResolvedPath.insert(node.resolvedPath, childImports);
    }

    for (const QString &child : childImports) {
        node.children.append(buildNodeRecursive(child, depth + 1, maxDepth, searchPaths, ancestorModules, importsByResolvedPath));
    }
    ancestorModules.remove(moduleKey);
    return node;
}
} // namespace

DependencyAnalysisResult PEDependencyAnalyzer::analyze(const QStringList &importModules,
                                                       const QString &peFilePath)
{
    DependencyAnalysisResult result;
    result.dependencies.reserve(importModules.size());
    const QStringList searchPaths = buildSearchPaths(peFilePath, &result.manifestParsed);
    result.searchPaths = searchPaths;

    for (const QString &name : importModules) {
        DependencyEntry entry;
        entry.moduleName = name;
        entry.resolvedPath = resolveDependencyPath(name, searchPaths);
        entry.foundOnSystem = !entry.resolvedPath.isEmpty();
        result.dependencies.append(entry);
    }

    return result;
}

DependencyAnalysisResult PEDependencyAnalyzer::analyzeTransitive(const QStringList &importModules,
                                                                 const QString &peFilePath,
                                                                 int maxDepth)
{
    DependencyAnalysisResult result = analyze(importModules, peFilePath);
    if (maxDepth < 0) maxDepth = 0;
    QHash<QString, QStringList> importsByResolvedPath;
    for (const QString &module : importModules) {
        QSet<QString> ancestors;
        result.dependencyTree.append(
            buildNodeRecursive(module, 0, maxDepth, result.searchPaths, ancestors, importsByResolvedPath));
    }
    return result;
}

QString PEDependencyAnalyzer::resolveDependencyPath(const QString &moduleName,
                                                    const QStringList &searchPaths)
{
    if (moduleName.isEmpty()) return QString();

    QString normalizedModule = moduleName.trimmed();
    // Imports can occasionally contain prefixed paths; keep only file name.
    normalizedModule = QFileInfo(normalizedModule).fileName();
    if (normalizedModule.isEmpty()) return QString();

    QStringList paths = searchPaths;
    if (paths.isEmpty()) {
#ifdef Q_OS_WIN
        QString systemRoot = qEnvironmentVariable("SystemRoot", "C:\\Windows");
        paths << systemRoot + "\\System32"
              << systemRoot + "\\System32\\drivers"
              << systemRoot + "\\SysWOW64";
#endif
    }

    for (const QString &dir : paths) {
        QDir d(dir);
        if (!d.exists()) continue;
        QString full = d.absoluteFilePath(normalizedModule);
        QFileInfo fi(full);
        if (fi.exists() && fi.isFile()) {
            return fi.absoluteFilePath();
        }
    }
    return QString();
}

QStringList PEDependencyAnalyzer::extraSearchPathsFromManifestXml(const QString &manifestXmlUtf8,
                                                                  const QString &exeDirectory,
                                                                  const QString &windowsRoot)
{
    if (manifestXmlUtf8.isEmpty()) return {};
    return collectDependentAssemblyPaths(manifestXmlUtf8, exeDirectory, windowsRoot);
}
