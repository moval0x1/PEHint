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

    /** Fills overlay, entropy, and PDB (from debug dir) on @p dataModel. */
    static void analyzeIntoModel(const QByteArray &fileData, PEDataModel &dataModel);
};

#endif // PE_ANALYSIS_H
