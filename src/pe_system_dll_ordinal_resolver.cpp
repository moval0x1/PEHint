#include "pe_system_dll_ordinal_resolver.h"
#include "pe_structures.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QMutex>
#include <QProcessEnvironment>
#include <QStringList>

namespace {

QMutex g_cacheMutex;
QHash<QString, QHash<quint16, QString>> g_ordinalNameCache;

QString pickSystemDllPathForPe(const QString &dllName, bool analyzedPeIs64Bit)
{
    const QString clean = dllName.trimmed();
    if (clean.isEmpty()) {
        return QString();
    }
    const QString root = QProcessEnvironment::systemEnvironment().value(
        QStringLiteral("SystemRoot"), QStringLiteral("C:\\Windows"));
    const QString sys32 = QDir(root).absoluteFilePath(QStringLiteral("System32/") + clean);
    const QString wow64 = QDir(root).absoluteFilePath(QStringLiteral("SysWOW64/") + clean);

    if (analyzedPeIs64Bit) {
        if (QFile::exists(sys32)) {
            return sys32;
        }
        if (QFile::exists(wow64)) {
            return wow64;
        }
        return QString();
    }
    // 32-bit PE: prefer 32-bit copy on WOW64
    if (QFile::exists(wow64)) {
        return wow64;
    }
    if (QFile::exists(sys32)) {
        return sys32;
    }
    return QString();
}

quint32 rvaToFileOffset(quint32 rva, const QByteArray &data, const QList<const IMAGE_SECTION_HEADER *> &sections)
{
    for (const IMAGE_SECTION_HEADER *sec : sections) {
        const quint32 va = sec->VirtualAddress;
        const quint32 vsize = qMax(sec->getVirtualSize(), sec->SizeOfRawData);
        if (rva >= va && rva < va + vsize) {
            return sec->PointerToRawData + (rva - va);
        }
    }
    return 0;
}

QString readAsciizAt(quint32 fileOffset, const QByteArray &data)
{
    if (fileOffset >= static_cast<quint32>(data.size())) {
        return QString();
    }
    qsizetype end = data.indexOf('\0', static_cast<qsizetype>(fileOffset));
    if (end < 0) {
        end = data.size();
    }
    return QString::fromLatin1(data.constData() + fileOffset, end - static_cast<int>(fileOffset));
}

QHash<quint16, QString> buildOrdinalToNameMap(const QByteArray &data, QString *errorOut)
{
    QHash<quint16, QString> out;
    if (data.size() < 512) {
        if (errorOut) {
            *errorOut = QStringLiteral("too small");
        }
        return out;
    }
    const IMAGE_DOS_HEADER *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(data.constData());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0
        || dos->e_lfanew > data.size() - 256) {
        if (errorOut) {
            *errorOut = QStringLiteral("bad DOS");
        }
        return out;
    }
    const quint32 peOff = static_cast<quint32>(dos->e_lfanew);
    if (data.size() < peOff + 4 + static_cast<int>(sizeof(IMAGE_FILE_HEADER))) {
        if (errorOut) {
            *errorOut = QStringLiteral("truncated PE");
        }
        return out;
    }
    const quint32 peSig = *reinterpret_cast<const quint32 *>(data.constData() + peOff);
    if (peSig != IMAGE_NT_SIGNATURE) {
        if (errorOut) {
            *errorOut = QStringLiteral("bad PE sig");
        }
        return out;
    }
    const IMAGE_FILE_HEADER *fh = reinterpret_cast<const IMAGE_FILE_HEADER *>(data.constData() + peOff + 4);
    const quint32 optOff = peOff + 4 + static_cast<quint32>(sizeof(IMAGE_FILE_HEADER));
    if (data.size() < static_cast<int>(optOff + 2)) {
        return out;
    }
    const quint16 magic = *reinterpret_cast<const quint16 *>(data.constData() + optOff);

    quint32 exportRva = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (fh->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)
            || data.size() < static_cast<int>(optOff + sizeof(IMAGE_OPTIONAL_HEADER32))) {
            return out;
        }
        const IMAGE_OPTIONAL_HEADER32 *opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32 *>(data.constData() + optOff);
        exportRva = opt->DataDirectory[0].VirtualAddress;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (fh->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)
            || data.size() < static_cast<int>(optOff + sizeof(IMAGE_OPTIONAL_HEADER64))) {
            return out;
        }
        const IMAGE_OPTIONAL_HEADER64 *opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(data.constData() + optOff);
        exportRva = opt->DataDirectory[0].VirtualAddress;
    } else {
        if (errorOut) {
            *errorOut = QStringLiteral("optional header magic");
        }
        return out;
    }
    if (exportRva == 0) {
        return out;
    }

    QList<const IMAGE_SECTION_HEADER *> sections;
    const quint32 secTableOff = optOff + fh->SizeOfOptionalHeader;
    if (data.size() < static_cast<int>(secTableOff)
        || fh->NumberOfSections > 96
        || data.size() < secTableOff + fh->NumberOfSections * static_cast<int>(sizeof(IMAGE_SECTION_HEADER))) {
        return out;
    }
    for (quint16 si = 0; si < fh->NumberOfSections; ++si) {
        const IMAGE_SECTION_HEADER *sec = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
            data.constData() + secTableOff + si * sizeof(IMAGE_SECTION_HEADER));
        sections.append(sec);
    }

    const quint32 exportOff = rvaToFileOffset(exportRva, data, sections);
    if (exportOff == 0 || exportOff + sizeof(IMAGE_EXPORT_DIRECTORY) > static_cast<quint32>(data.size())) {
        return out;
    }
    const IMAGE_EXPORT_DIRECTORY *exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(data.constData() + exportOff);

    if (exportDir->NumberOfNames == 0 || exportDir->AddressOfNames == 0 || exportDir->AddressOfNameOrdinals == 0) {
        return out;
    }

    const quint32 namesOff = rvaToFileOffset(exportDir->AddressOfNames, data, sections);
    const quint32 ordinalsOff = rvaToFileOffset(exportDir->AddressOfNameOrdinals, data, sections);
    if (namesOff == 0 || ordinalsOff == 0) {
        return out;
    }

    const quint32 maxNames = qMin(exportDir->NumberOfNames, static_cast<quint32>(16384));
    const quint32 *nameRVAs = reinterpret_cast<const quint32 *>(data.constData() + namesOff);
    const quint16 *nameOrdinals = reinterpret_cast<const quint16 *>(data.constData() + ordinalsOff);

    for (quint32 i = 0; i < maxNames; ++i) {
        const quint32 nameRva = nameRVAs[i];
        const quint16 funcIndex = nameOrdinals[i];
        if (funcIndex >= exportDir->NumberOfFunctions) {
            continue;
        }
        const quint16 ord = static_cast<quint16>(exportDir->OrdinalBase + funcIndex);
        const quint32 nameFo = rvaToFileOffset(nameRva, data, sections);
        const QString nm = readAsciizAt(nameFo, data);
        if (!nm.isEmpty() && !out.contains(ord)) {
            out.insert(ord, nm);
        }
    }
    return out;
}

} // namespace

QString resolveImportOrdinalToName(const QString &dllName, quint16 ordinal, bool analyzedPeIs64Bit)
{
    const QString path = pickSystemDllPathForPe(dllName, analyzedPeIs64Bit);
    if (path.isEmpty()) {
        return QString();
    }

    const QString cacheKey = QFileInfo(path).canonicalFilePath().isEmpty()
        ? path
        : QFileInfo(path).canonicalFilePath();

    {
        QMutexLocker lock(&g_cacheMutex);
        const auto it = g_ordinalNameCache.constFind(cacheKey);
        if (it != g_ordinalNameCache.constEnd()) {
            return it->value(ordinal);
        }
    }

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        return QString();
    }
    QByteArray data = f.readAll();
    if (data.size() > 40 * 1024 * 1024) {
        return QString();
    }

    QString err;
    QHash<quint16, QString> map = buildOrdinalToNameMap(data, &err);

    {
        QMutexLocker lock(&g_cacheMutex);
        g_ordinalNameCache.insert(cacheKey, map);
    }

    return map.value(ordinal);
}
