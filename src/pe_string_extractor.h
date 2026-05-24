/**
 * @file pe_string_extractor.h
 * @brief PE String Extractor - Extracts ASCII and Unicode strings from PE files
 */

#ifndef PE_STRING_EXTRACTOR_H
#define PE_STRING_EXTRACTOR_H

#include <QString>
#include <QList>
#include <QByteArray>
#include <functional>

/**
 * @brief Single extracted string with offset and encoding
 */
struct ExtractedString {
    quint32 fileOffset = 0;   ///< Offset in file where string starts
    QString value;            ///< Decoded string content
    bool isUnicode = false;   ///< True if UTF-16LE, false if ASCII
};

/**
 * @brief Result of string extraction
 */
struct StringExtractionResult {
    QList<ExtractedString> strings;
    int minLength = 4;        ///< Minimum length used for extraction
};

/**
 * @brief Extracts readable strings from binary data (e.g. PE file)
 */
class PEStringExtractor
{
public:
    PEStringExtractor() = default;

    /**
     * @brief Extract strings from raw file data
     * @param data Raw bytes (e.g. entire PE file or section)
     * @param minLength Minimum string length (default 4)
     * @param reportProgress Optional 0–100 progress (ASCII pass ~0–50, UTF-16LE ~50–100); may be called from a worker thread
     * @return List of extracted strings with offset and encoding
     */
    static StringExtractionResult extractFromData(const QByteArray &data, int minLength = 4,
                                                  const std::function<void(int)> &reportProgress = {});

    /**
     * @brief Extract strings from a file
     * @param filePath Path to the file
     * @param minLength Minimum string length (default 4)
     * @return List of extracted strings; empty list on read error
     */
    static StringExtractionResult extractFromFile(const QString &filePath, int minLength = 4);

    /** Content triage filters for the Strings tab (url / ip / registry / command). */
    static bool matchesContentFilter(const QString &value, const QString &filterKey);
};

#endif // PE_STRING_EXTRACTOR_H
