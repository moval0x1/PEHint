#include "pe_analysis.h"
#include "pe_data_model.h"

#include <QHash>
#include <cmath>
#include <cstddef>

namespace {

constexpr quint32 kCvSignatureRsds = 0x53445352u; // 'RSDS'
constexpr quint32 kCvSignatureNb10 = 0x3031424Eu; // 'NB10'
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
        constexpr quint32 kRsdsFixedSize = 24;
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
        constexpr quint32 kNb10FixedSize = 12;
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
        constexpr quint32 kRsdsFixedSize = 24; // CvSignature + Signature[16] + Age
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

void PEAnalysis::analyzeIntoModel(const QByteArray &fileData, PEDataModel &dataModel)
{
    const QList<const IMAGE_SECTION_HEADER *> &sections = dataModel.getSections();
    const qint64 effectiveSize = qMax(dataModel.getFileSize(), static_cast<qint64>(fileData.size()));
    dataModel.setOverlayInfo(
        detectOverlay(fileData, sections, effectiveSize, dataModel.getOptionalHeader()));
    dataModel.setEntropySummary(computeEntropy(fileData, sections));
}
