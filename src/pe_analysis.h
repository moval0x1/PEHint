#ifndef PE_ANALYSIS_H
#define PE_ANALYSIS_H

#include "pe_structures.h"

class PEDataModel;
#include <QByteArray>
#include <QString>
#include <QVector>

struct PEOverlayInfo {
    bool present = false;
    quint32 fileOffset = 0;
    quint64 size = 0;
};

struct PESectionEntropy {
    QString sectionName;
    quint32 rawOffset = 0;
    quint32 rawSize = 0;
    double entropy = 0.0; ///< Shannon entropy in bits per byte (0–8)
    bool computed = false;
};

struct PEEntropySummary {
    double fileEntropy = 0.0;
    bool fileEntropyValid = false;
    QVector<PESectionEntropy> sections;
};

struct PEPdbInfo {
    bool present = false;
    QString format;       ///< RSDS, NB10, or empty
    QString path;
    QString guid;         ///< uppercase hex with dashes when RSDS
    quint32 age = 0;
    quint32 codeViewFileOffset = 0; ///< PointerToRawData of CodeView debug data
    quint32 codeViewSize = 0;
    quint32 pathFileOffset = 0;     ///< File offset of embedded PDB path string
    quint32 pathByteSize = 0;       ///< Length of path in file (includes null terminator)
};

struct PEAnalysisMetadata {
    quint32 computedImageChecksum = 0;
    bool imageChecksumComputed = false;
    bool richHeaderPresent = false;
    bool tlsCallbacksPresent = false;
};

struct PEFileMetrics {
    QString md5Hex;
    QString sha256Hex;
    QString imphashHex;
    bool hashesValid = false;
    double fileRatio = 0.0; ///< PE logical size / file size (0–1)
    quint64 peLogicalSize = 0;
    bool fileRatioValid = false;
    QString toolchainSummary;
    bool toolchainValid = false;
    bool authenticodePresent = false;
    QString authenticodePublisher;
    quint32 certTableSize = 0;
    int importFunctionCount = 0;
    int exportFunctionCount = 0;
    quint32 entryPointRva = 0;
    QString entryPointSection;
    QString entryPointBytesHex;
    quint32 entryPointFileOffset = 0;
    bool triageSummaryValid = false;
};

struct PEHardcodedMatch {
    QString value;
    quint32 fileOffset = 0;
    quint32 length = 0;
};

/** URLs/IPs in section raw data and DOS stub triage — filled in analyzeIntoModel(). */
struct PEContentScan {
    QString dosStubMessage;
    bool dosStubNonStandard = false;
    quint32 dosStubOffset = 0;
    quint32 dosStubSize = 0;
    QVector<PEHardcodedMatch> urls;
    QVector<PEHardcodedMatch> ips;
    QVector<PEHardcodedMatch> registryPaths;
    QVector<PEHardcodedMatch> suspiciousCommands;
};

struct PEResourceItem {
    QString typeName;
    quint32 typeId = 0;
    QString resourceName;
    quint32 nameId = 0;
    quint32 languageId = 0;
    quint32 rva = 0;
    quint32 size = 0;
    quint32 fileOffset = 0;
};

struct PEVersionInfo {
    bool present = false;
    QString fileVersion;
    QString productVersion;
    QString companyName;
    QString productName;
    QString fileDescription;
    QString originalFilename;
    QString legalCopyright;
    bool manifestPresent = false;
    QString manifestExecutionLevel;
    quint32 versionResourceOffset = 0;
    quint32 versionResourceSize = 0;
};

/**
 * @brief Static PE file analysis helpers (overlay, entropy, PDB) used after parsing.
 */
class PEAnalysis
{
public:
    static double shannonEntropy(const QByteArray &data);

    static PEOverlayInfo detectOverlay(const QByteArray &fileData,
                                       const QList<const IMAGE_SECTION_HEADER *> &sections,
                                       qint64 fileSize,
                                       const IMAGE_OPTIONAL_HEADER *optionalHeader = nullptr);

    static PEPdbInfo parseCodeViewDebugData(const QByteArray &fileData, quint32 pointerToRawData, quint32 sizeOfData);

    /** Bytes occupied by one RSDS/NB10 record (not the whole debug directory SizeOfData). */
    static quint32 codeViewRecordByteSize(const QByteArray &fileData, quint32 fileOffset, quint32 maxSize);

    static PEEntropySummary computeEntropy(const QByteArray &fileData,
                                           const QList<const IMAGE_SECTION_HEADER *> &sections);

    /** Fills overlay, entropy, version resource, manifest, hashes, ratio, and toolchain on @p dataModel. */
    static void analyzeIntoModel(const QByteArray &fileData, PEDataModel &dataModel);

    static QString computeImphash(const PEDataModel &dataModel);
    static quint64 computePeLogicalSize(const PEDataModel &dataModel, qint64 fileSize);
    static PEFileMetrics computeFileMetrics(const QByteArray &fileData, const PEDataModel &dataModel);

    static PEContentScan computeContentScan(const QByteArray &fileData, const PEDataModel &dataModel);

    /** True when @p value matches a pattern in config/suspicious_strings.json (Strings tab filter). */
    static bool matchesSuspiciousCommand(const QString &value);

    /** Parses VS_VERSION_INFO strings from the PE resource directory (RT_VERSION). */
    static PEVersionInfo parseVersionResource(const QByteArray &fileData, const PEDataModel &dataModel);

    /** Recursively walks the PE resource tree and returns one row per data leaf. */
    static QVector<PEResourceItem> enumerateResourceEntries(const QByteArray &fileData,
                                                            const PEDataModel &dataModel);
};

#endif // PE_ANALYSIS_H
