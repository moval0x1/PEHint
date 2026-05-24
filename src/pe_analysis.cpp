#include "pe_analysis.h"
#include "pe_data_model.h"

#include <QCryptographicHash>
#include <QHash>
#include <cmath>
#include <cstddef>
#include <string>

#include "pe_utils.h"

namespace {

constexpr quint32 kCvSignatureRsds = 0x53445352u; // 'RSDS'
constexpr quint32 kCvSignatureNb10 = 0x3031424Eu; // 'NB10'
constexpr quint32 kRsdsFixedSize = 24;  // CvSignature + Signature[16] + Age
constexpr quint32 kNb10FixedSize = 12;  // signature + offset + age
constexpr quint64 kMinOverlayBytes = 1;
constexpr int kImageDirectoryEntrySecurity = 4;

QString formatGuidRsds(const quint8 *sig16)
{
    if (!sig16) {
        return QString();
    }
    return QStringLiteral("%1%2%3-%4%5-%6%7-%8%9-%10%11%12%13%14%15%16")
        .arg(sig16[3], 2, 16, QChar('0'))
        .arg(sig16[2], 2, 16, QChar('0'))
        .arg(sig16[1], 2, 16, QChar('0'))
        .arg(sig16[0], 2, 16, QChar('0'))
        .arg(sig16[5], 2, 16, QChar('0'))
        .arg(sig16[4], 2, 16, QChar('0'))
        .arg(sig16[7], 2, 16, QChar('0'))
        .arg(sig16[6], 2, 16, QChar('0'))
        .arg(sig16[8], 2, 16, QChar('0'))
        .arg(sig16[9], 2, 16, QChar('0'))
        .arg(sig16[10], 2, 16, QChar('0'))
        .arg(sig16[11], 2, 16, QChar('0'))
        .arg(sig16[12], 2, 16, QChar('0'))
        .arg(sig16[13], 2, 16, QChar('0'))
        .arg(sig16[14], 2, 16, QChar('0'))
        .arg(sig16[15], 2, 16, QChar('0'))
        .toUpper();
}

QString sectionNameFromHeader(const IMAGE_SECTION_HEADER *section)
{
    if (!section) {
        return QString();
    }
    const char *namePtr = reinterpret_cast<const char *>(section->Name);
    int nameLength = 0;
    while (nameLength < 8 && namePtr[nameLength] != '\0' && static_cast<unsigned char>(namePtr[nameLength]) >= 32) {
        ++nameLength;
    }
    if (nameLength > 0) {
        return QString::fromLatin1(namePtr, nameLength);
    }
    return QStringLiteral("0x") + QString(QByteArray(namePtr, 8).toHex()).toUpper();
}

} // namespace

double PEAnalysis::shannonEntropy(const QByteArray &data)
{
    if (data.isEmpty()) {
        return 0.0;
    }
    QHash<unsigned char, quint64> counts;
    counts.reserve(256);
    for (const char c : data) {
        counts[static_cast<unsigned char>(c)]++;
    }
    const double len = static_cast<double>(data.size());
    double entropy = 0.0;
    for (auto it = counts.constBegin(); it != counts.constEnd(); ++it) {
        const double p = static_cast<double>(it.value()) / len;
        if (p > 0.0) {
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

PEOverlayInfo PEAnalysis::detectOverlay(const QByteArray &fileData,
                                        const QList<const IMAGE_SECTION_HEADER *> &sections,
                                        qint64 fileSize,
                                        const IMAGE_OPTIONAL_HEADER *optionalHeader)
{
    PEOverlayInfo info;
    const qint64 effectiveSize =
        fileSize > 0 ? fileSize : static_cast<qint64>(fileData.size());
    if (effectiveSize <= 0 || fileData.isEmpty()) {
        return info;
    }

    quint64 physicalEnd = 0;
    for (const IMAGE_SECTION_HEADER *section : sections) {
        if (!section || section->PointerToRawData == 0) {
            continue;
        }
        quint32 span = section->SizeOfRawData;
        if (span == 0 && section->Misc.VirtualSize > 0) {
            span = section->Misc.VirtualSize;
        }
        if (span == 0) {
            continue;
        }
        const quint64 end = static_cast<quint64>(section->PointerToRawData) + span;
        if (end > physicalEnd) {
            physicalEnd = end;
        }
    }

    if (optionalHeader) {
        if (optionalHeader->SizeOfHeaders > 0) {
            physicalEnd = qMax(physicalEnd, static_cast<quint64>(optionalHeader->SizeOfHeaders));
        }
        const IMAGE_DATA_DIRECTORY &certDir =
            optionalHeader->DataDirectory[kImageDirectoryEntrySecurity];
        if (certDir.Size > 0 && certDir.VirtualAddress > 0) {
            const quint64 certEnd = static_cast<quint64>(certDir.VirtualAddress) + certDir.Size;
            physicalEnd = qMax(physicalEnd, certEnd);
        }
    }

    const quint64 fileEnd = static_cast<quint64>(effectiveSize);
    if (fileEnd > physicalEnd && (fileEnd - physicalEnd) >= kMinOverlayBytes) {
        info.present = true;
        info.fileOffset = static_cast<quint32>(qMin(physicalEnd, static_cast<quint64>(UINT32_MAX)));
        info.size = fileEnd - physicalEnd;
    }
    return info;
}

quint32 PEAnalysis::codeViewRecordByteSize(const QByteArray &fileData, quint32 fileOffset, quint32 maxSize)
{
    if (maxSize < 4 || fileOffset >= static_cast<quint32>(fileData.size())) {
        return 0;
    }
    const quint32 avail = static_cast<quint32>(fileData.size()) - fileOffset;
    maxSize = qMin(maxSize, avail);

    const char *base = fileData.constData() + fileOffset;
    quint32 sig = 0;
    std::memcpy(&sig, base, sizeof(sig));

    if (sig == kCvSignatureRsds) {
        if (maxSize < kRsdsFixedSize) {
            return maxSize;
        }
        const char *nameStart = base + kRsdsFixedSize;
        const quint32 nameMax = maxSize - kRsdsFixedSize;
        int nameLen = 0;
        while (nameLen < static_cast<int>(nameMax) && nameStart[nameLen] != '\0') {
            ++nameLen;
        }
        return kRsdsFixedSize + static_cast<quint32>(nameLen) + 1u;
    }

    if (sig == kCvSignatureNb10) {
        if (maxSize < kNb10FixedSize) {
            return maxSize;
        }
        const char *nameStart = base + kNb10FixedSize;
        const quint32 nameMax = maxSize - kNb10FixedSize;
        int nameLen = 0;
        while (nameLen < static_cast<int>(nameMax) && nameStart[nameLen] != '\0') {
            ++nameLen;
        }
        return kNb10FixedSize + static_cast<quint32>(nameLen) + 1u;
    }

    return qMin(maxSize, 256u);
}

PEPdbInfo PEAnalysis::parseCodeViewDebugData(const QByteArray &fileData, quint32 pointerToRawData, quint32 sizeOfData)
{
    PEPdbInfo pdb;
    if (sizeOfData < 4
        || static_cast<quint64>(pointerToRawData) + sizeOfData > static_cast<quint64>(fileData.size())) {
        return pdb;
    }

    const char *base = fileData.constData() + pointerToRawData;
    quint32 sig = 0;
    std::memcpy(&sig, base, sizeof(sig));

    if (sig == kCvSignatureRsds) {
        if (sizeOfData < kRsdsFixedSize + 1) {
            return pdb;
        }
        const auto *cv = reinterpret_cast<const CV_INFO_PDB70 *>(base);
        pdb.present = true;
        pdb.format = QStringLiteral("RSDS");
        pdb.age = cv->Age;
        pdb.guid = formatGuidRsds(cv->Signature);
        const char *nameStart = base + offsetof(CV_INFO_PDB70, PdbFileName);
        const quint32 nameMax = sizeOfData - static_cast<quint32>(offsetof(CV_INFO_PDB70, PdbFileName));
        int nameLen = 0;
        while (nameLen < static_cast<int>(nameMax) && nameStart[nameLen] != '\0') {
            ++nameLen;
        }
        pdb.path = QString::fromLocal8Bit(nameStart, nameLen).trimmed();
        pdb.pathFileOffset = pointerToRawData + kRsdsFixedSize;
        pdb.pathByteSize = nameLen > 0 ? static_cast<quint32>(nameLen) + 1u : 0u;
        return pdb;
    }

    if (sig == kCvSignatureNb10) {
        // NB10: signature(4) + offset(4) + age(4) + pdb path (null-terminated)
        if (sizeOfData < 12) {
            return pdb;
        }
        const quint32 age = *reinterpret_cast<const quint32 *>(base + 8);
        pdb.present = true;
        pdb.format = QStringLiteral("NB10");
        pdb.age = age;
        const char *nameStart = base + 12;
        const quint32 nameMax = sizeOfData - 12;
        int nameLen = 0;
        while (nameLen < static_cast<int>(nameMax) && nameStart[nameLen] != '\0') {
            ++nameLen;
        }
        pdb.path = QString::fromLocal8Bit(nameStart, nameLen).trimmed();
        pdb.pathFileOffset = pointerToRawData + kNb10FixedSize;
        pdb.pathByteSize = nameLen > 0 ? static_cast<quint32>(nameLen) + 1u : 0u;
        return pdb;
    }

    return pdb;
}

PEEntropySummary PEAnalysis::computeEntropy(const QByteArray &fileData,
                                            const QList<const IMAGE_SECTION_HEADER *> &sections)
{
    PEEntropySummary summary;
    if (!fileData.isEmpty()) {
        summary.fileEntropy = shannonEntropy(fileData);
        summary.fileEntropyValid = true;
    }

    for (const IMAGE_SECTION_HEADER *section : sections) {
        if (!section) {
            continue;
        }
        PESectionEntropy se;
        se.sectionName = sectionNameFromHeader(section);
        se.rawOffset = section->PointerToRawData;
        se.rawSize = section->SizeOfRawData;
        if (se.rawSize > 0 && se.rawOffset < static_cast<quint32>(fileData.size())) {
            const quint32 avail = static_cast<quint32>(fileData.size()) - se.rawOffset;
            const quint32 take = qMin(se.rawSize, avail);
            if (take > 0) {
                se.entropy = shannonEntropy(fileData.mid(static_cast<int>(se.rawOffset), static_cast<int>(take)));
                se.computed = true;
            }
        }
        summary.sections.append(se);
    }
    return summary;
}

QString PEAnalysis::computeImphash(const PEDataModel &dataModel)
{
    QStringList pairs;
    const QStringList &importModules = dataModel.getImports();
    const QMap<QString, QList<PEDataModel::ImportFunctionEntry>> &importDetails =
        dataModel.getImportFunctions();

    for (const QString &dllRaw : importModules) {
        QString dll = dllRaw;
        const int slash = qMax(dll.lastIndexOf(QLatin1Char('\\')), dll.lastIndexOf(QLatin1Char('/')));
        if (slash >= 0) {
            dll = dll.mid(slash + 1);
        }
        dll = dll.toLower();

        const QList<PEDataModel::ImportFunctionEntry> functions = importDetails.value(dllRaw);
        for (const PEDataModel::ImportFunctionEntry &entry : functions) {
            QString func;
            if (entry.importedByOrdinal) {
                func = QStringLiteral("ord%1").arg(entry.ordinal);
            } else {
                func = entry.name;
                const int paren = func.indexOf(QLatin1Char('('));
                if (paren >= 0) {
                    func = func.left(paren);
                }
                func = func.toLower();
            }
            pairs.append(dll + QLatin1Char(',') + func);
        }
    }

    if (pairs.isEmpty()) {
        return QString();
    }

    const QByteArray canonical = pairs.join(QLatin1Char(',')).toUtf8();
    return QString::fromLatin1(QCryptographicHash::hash(canonical, QCryptographicHash::Md5).toHex());
}

quint64 PEAnalysis::computePeLogicalSize(const PEDataModel &dataModel, qint64 fileSize)
{
    quint64 logicalEnd = 0;
    const IMAGE_OPTIONAL_HEADER *optionalHeader = dataModel.getOptionalHeader();
    if (optionalHeader) {
        logicalEnd = qMax(logicalEnd, static_cast<quint64>(optionalHeader->SizeOfHeaders));
    }

    for (const IMAGE_SECTION_HEADER *section : dataModel.getSections()) {
        if (!section) {
            continue;
        }
        const quint64 sectionEnd =
            static_cast<quint64>(section->PointerToRawData) + static_cast<quint64>(section->SizeOfRawData);
        logicalEnd = qMax(logicalEnd, sectionEnd);
    }

    if (fileSize > 0) {
        logicalEnd = qMin(logicalEnd, static_cast<quint64>(fileSize));
    }
    return logicalEnd;
}

PEFileMetrics PEAnalysis::computeFileMetrics(const QByteArray &fileData, const PEDataModel &dataModel)
{
    PEFileMetrics metrics;
    if (fileData.isEmpty()) {
        return metrics;
    }

    metrics.md5Hex =
        QString::fromLatin1(QCryptographicHash::hash(fileData, QCryptographicHash::Md5).toHex());
    metrics.sha256Hex =
        QString::fromLatin1(QCryptographicHash::hash(fileData, QCryptographicHash::Sha256).toHex());
    metrics.imphashHex = computeImphash(dataModel);
    metrics.hashesValid = true;

    const qint64 fileSize = qMax(dataModel.getFileSize(), static_cast<qint64>(fileData.size()));
    if (fileSize > 0) {
        metrics.peLogicalSize = computePeLogicalSize(dataModel, fileSize);
        if (metrics.peLogicalSize > 0) {
            metrics.fileRatio = static_cast<double>(metrics.peLogicalSize) / static_cast<double>(fileSize);
            metrics.fileRatioValid = true;
        }
    }

    const IMAGE_DOS_HEADER *dos = dataModel.getDOSHeader();
    if (dos) {
        const QString toolchain = PEUtils::summarizeRichToolchain(fileData, *dos);
        if (!toolchain.isEmpty()) {
            metrics.toolchainSummary = toolchain;
            metrics.toolchainValid = true;
        }
    }

    return metrics;
}

void PEAnalysis::analyzeIntoModel(const QByteArray &fileData, PEDataModel &dataModel)
{
    const QList<const IMAGE_SECTION_HEADER *> &sections = dataModel.getSections();
    const qint64 effectiveSize = qMax(dataModel.getFileSize(), static_cast<qint64>(fileData.size()));
    dataModel.setOverlayInfo(
        detectOverlay(fileData, sections, effectiveSize, dataModel.getOptionalHeader()));
    dataModel.setEntropySummary(computeEntropy(fileData, sections));
    dataModel.setVersionInfo(parseVersionResource(fileData, dataModel));

    PEAnalysisMetadata metadata;
    const IMAGE_DOS_HEADER *dos = dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHdr = dataModel.getFileHeader();
    if (dos && fileHdr && !fileData.isEmpty()) {
        const quint32 checksumOffset = PEUtils::optionalHeaderChecksumFileOffset(*dos, *fileHdr);
        if (checksumOffset + sizeof(quint32) <= static_cast<quint32>(fileData.size())) {
            metadata.computedImageChecksum =
                PEUtils::computePeImageChecksum(fileData, checksumOffset);
            metadata.imageChecksumComputed = true;
        }
        metadata.richHeaderPresent = PEUtils::hasRichHeader(fileData, *dos);
    }
    dataModel.setAnalysisMetadata(metadata);
    dataModel.setFileMetrics(computeFileMetrics(fileData, dataModel));
}

namespace {

constexpr quint32 kRtVersion = 16;
constexpr quint32 kRtManifest = 24;
constexpr quint32 kMaxResourceBytes = 512 * 1024;

quint32 rvaToFileOffsetResource(quint32 rva,
                                quint32 sizeOfHeaders,
                                const QList<const IMAGE_SECTION_HEADER *> &sections,
                                quint32 fileSize)
{
    if (rva < sizeOfHeaders && rva < fileSize) {
        return rva;
    }
    for (const IMAGE_SECTION_HEADER *section : sections) {
        if (!section) {
            continue;
        }
        const quint32 start = section->VirtualAddress;
        const quint32 span = qMax(section->SizeOfRawData, section->getVirtualSize());
        if (rva >= start && rva < start + span) {
            return section->PointerToRawData + (rva - start);
        }
    }
    return 0;
}

bool resourceLayout(const QByteArray &fileData,
                    const PEDataModel &dataModel,
                    quint32 &resourceRva,
                    quint32 &sizeOfHeaders)
{
    resourceRva = 0;
    sizeOfHeaders = 0;
    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    if (!opt || opt->NumberOfRvaAndSizes <= 2) {
        return false;
    }
    resourceRva = opt->DataDirectory[2].VirtualAddress;
    sizeOfHeaders = opt->SizeOfHeaders;
    return resourceRva != 0;
}

bool walkResourceByType(const QByteArray &data,
                        quint32 resRootFileOff,
                        quint32 dirFileOff,
                        int depth,
                        quint32 sizeOfHeaders,
                        const QList<const IMAGE_SECTION_HEADER *> &sections,
                        quint32 fileSize,
                        quint32 targetTypeId,
                        QByteArray &outPayload,
                        quint32 &outFileOffset,
                        quint32 &outSize)
{
    if (depth > 8 || dirFileOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) {
        return false;
    }
    const auto *dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY *>(data.constData() + dirFileOff);
    const quint32 total =
        static_cast<quint32>(dir->NumberOfNamedEntries) + static_cast<quint32>(dir->NumberOfIdEntries);
    quint32 entryOff = dirFileOff + sizeof(IMAGE_RESOURCE_DIRECTORY);
    for (quint32 i = 0; i < total; ++i) {
        if (entryOff + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileSize) {
            break;
        }
        const auto *entry =
            reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY *>(data.constData() + entryOff);
        entryOff += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

        if (depth == 0) {
            if (entry->isNameString()) {
                continue;
            }
            if (entry->getName() != targetTypeId) {
                continue;
            }
        }

        if (entry->isDataDirectory()) {
            const quint32 nextOff = resRootFileOff + (entry->getOffsetToData() & 0x7FFFFFFF);
            if (walkResourceByType(data, resRootFileOff, nextOff, depth + 1, sizeOfHeaders, sections,
                                   fileSize, targetTypeId, outPayload, outFileOffset, outSize)) {
                return true;
            }
        } else {
            const quint32 dataEntryOff = resRootFileOff + entry->getOffsetToData();
            if (dataEntryOff + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > fileSize) {
                continue;
            }
            const auto *dataEntry =
                reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY *>(data.constData() + dataEntryOff);
            const quint32 payloadRva = dataEntry->OffsetToData;
            const quint32 payloadSize = dataEntry->Size;
            if (payloadSize == 0 || payloadSize > kMaxResourceBytes) {
                continue;
            }
            const quint32 raw =
                rvaToFileOffsetResource(payloadRva, sizeOfHeaders, sections, fileSize);
            if (raw == 0 || raw + payloadSize > fileSize) {
                continue;
            }
            outPayload = data.mid(static_cast<int>(raw), static_cast<int>(payloadSize));
            outFileOffset = raw;
            outSize = payloadSize;
            return !outPayload.isEmpty();
        }
    }
    return false;
}

QString manifestXmlFromBytes(const QByteArray &raw)
{
    if (raw.isEmpty()) {
        return QString();
    }
    if (raw.size() >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF
        && static_cast<unsigned char>(raw[1]) == 0xBB && static_cast<unsigned char>(raw[2]) == 0xBF) {
        return QString::fromUtf8(raw.constData() + 3, raw.size() - 3);
    }
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF
        && static_cast<unsigned char>(raw[1]) == 0xFE) {
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(raw.constData() + 2),
                                 (raw.size() - 2) / 2);
    }
    return QString::fromUtf8(raw);
}

QString manifestExecutionLevel(const QString &xml)
{
    if (xml.contains(QStringLiteral("requireAdministrator"), Qt::CaseInsensitive)) {
        return QStringLiteral("requireAdministrator");
    }
    if (xml.contains(QStringLiteral("highestAvailable"), Qt::CaseInsensitive)) {
        return QStringLiteral("highestAvailable");
    }
    if (xml.contains(QStringLiteral("asInvoker"), Qt::CaseInsensitive)) {
        return QStringLiteral("asInvoker");
    }
    return QString();
}

QString readUtf16CString(const QByteArray &data, int offset)
{
    QString out;
    for (int i = offset; i + 1 < data.size(); i += 2) {
        const char16_t ch = *reinterpret_cast<const char16_t *>(data.constData() + i);
        if (ch == 0) {
            break;
        }
        out.append(QChar(ch));
    }
    return out.trimmed();
}

QString versionStringForKey(const QByteArray &blob, const QString &key)
{
    const std::u16string u16 = key.toStdU16String();
    const QByteArray keyUtf16(reinterpret_cast<const char *>(u16.data()),
                              static_cast<int>(u16.size() * sizeof(char16_t)));
    const int idx = blob.indexOf(keyUtf16);
    if (idx < 0) {
        return QString();
    }
    int pos = idx + keyUtf16.size();
    while (pos + 1 < blob.size() && blob.at(pos) == '\0' && blob.at(pos + 1) == '\0') {
        pos += 2;
    }
    pos = (pos + 3) & ~3;
    if (pos + 6 < blob.size()) {
        pos += 6;
    }
    return readUtf16CString(blob, pos);
}

QString formatFixedVersion(quint32 ms, quint32 ls)
{
    return QStringLiteral("%1.%2.%3.%4")
        .arg((ms >> 16) & 0xFFFF)
        .arg(ms & 0xFFFF)
        .arg((ls >> 16) & 0xFFFF)
        .arg(ls & 0xFFFF);
}

} // namespace

PEVersionInfo PEAnalysis::parseVersionResource(const QByteArray &fileData, const PEDataModel &dataModel)
{
    PEVersionInfo info;
    if (fileData.isEmpty() || !dataModel.isValid()) {
        return info;
    }

    quint32 resourceRva = 0;
    quint32 sizeOfHeaders = 0;
    if (!resourceLayout(fileData, dataModel, resourceRva, sizeOfHeaders)) {
        return info;
    }

    const quint32 fileSize = static_cast<quint32>(fileData.size());
    const QList<const IMAGE_SECTION_HEADER *> &sections = dataModel.getSections();
    const quint32 resRootOff =
        rvaToFileOffsetResource(resourceRva, sizeOfHeaders, sections, fileSize);
    if (resRootOff == 0) {
        return info;
    }

    QByteArray versionBlob;
    quint32 versionOff = 0;
    quint32 versionSize = 0;
    if (walkResourceByType(fileData, resRootOff, resRootOff, 0, sizeOfHeaders, sections, fileSize,
                           kRtVersion, versionBlob, versionOff, versionSize)) {
        info.present = true;
        info.versionResourceOffset = versionOff;
        info.versionResourceSize = versionSize;
        info.fileVersion = versionStringForKey(versionBlob, QStringLiteral("FileVersion"));
        info.productVersion = versionStringForKey(versionBlob, QStringLiteral("ProductVersion"));
        info.companyName = versionStringForKey(versionBlob, QStringLiteral("CompanyName"));
        info.productName = versionStringForKey(versionBlob, QStringLiteral("ProductName"));
        info.fileDescription = versionStringForKey(versionBlob, QStringLiteral("FileDescription"));
        info.originalFilename = versionStringForKey(versionBlob, QStringLiteral("OriginalFilename"));
        info.legalCopyright = versionStringForKey(versionBlob, QStringLiteral("LegalCopyright"));

        if (versionBlob.size() >= 92) {
            const auto *fixed = reinterpret_cast<const quint32 *>(versionBlob.constData() + 36);
            if (info.fileVersion.isEmpty()) {
                info.fileVersion = formatFixedVersion(fixed[2], fixed[3]);
            }
            if (info.productVersion.isEmpty()) {
                info.productVersion = formatFixedVersion(fixed[0], fixed[1]);
            }
        }
    }

    QByteArray manifestBlob;
    quint32 manifestOff = 0;
    quint32 manifestSize = 0;
    if (walkResourceByType(fileData, resRootOff, resRootOff, 0, sizeOfHeaders, sections, fileSize,
                           kRtManifest, manifestBlob, manifestOff, manifestSize)) {
        info.manifestPresent = true;
        const QString xml = manifestXmlFromBytes(manifestBlob);
        info.manifestExecutionLevel = manifestExecutionLevel(xml);
    }

    return info;
}
