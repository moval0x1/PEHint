/**
 * @file pe_string_extractor.cpp
 * @brief Implementation of PE String Extractor
 */

#include "pe_string_extractor.h"
#include "pe_structures.h"
#include <QFile>

static bool isPrintableAscii(quint8 c) {
    return c >= 0x20 && c < 0x7F;
}

static bool isPrintableUtf16Lead(const QByteArray &data, int i) {
    if (i + 1 >= data.size()) return false;
    quint8 lo = static_cast<quint8>(data[i]);
    quint8 hi = static_cast<quint8>(data[i + 1]);
    if (hi != 0) return false;  // ASCII range in UTF-16LE
    return isPrintableAscii(lo);
}

StringExtractionResult PEStringExtractor::extractFromData(const QByteArray &data, int minLength)
{
    StringExtractionResult result;
    result.minLength = minLength;
    if (data.isEmpty() || minLength < 1) return result;

    const int n = data.size();

    // ASCII strings
    int start = -1;
    for (int i = 0; i < n; ++i) {
        if (isPrintableAscii(static_cast<quint8>(data[i]))) {
            if (start < 0) start = i;
        } else {
            if (start >= 0 && (i - start) >= minLength) {
                ExtractedString e;
                e.fileOffset = static_cast<quint32>(start);
                e.value = QString::fromLatin1(data.mid(start, i - start));
                e.isUnicode = false;
                result.strings.append(e);
            }
            start = -1;
        }
    }
    if (start >= 0 && (n - start) >= minLength) {
        ExtractedString e;
        e.fileOffset = static_cast<quint32>(start);
        e.value = QString::fromLatin1(data.mid(start, n - start));
        e.isUnicode = false;
        result.strings.append(e);
    }

    // UTF-16LE strings (2-byte aligned)
    start = -1;
    for (int i = 0; i + 1 < n; i += 2) {
        if (isPrintableUtf16Lead(data, i)) {
            if (start < 0) start = i;
        } else {
            if (start >= 0 && (i - start) >= minLength * 2) {
                QByteArray u16 = data.mid(start, i - start);
                ExtractedString e;
                e.fileOffset = static_cast<quint32>(start);
                e.value = QString::fromUtf16(reinterpret_cast<const char16_t*>(u16.constData()), u16.size() / 2);
                e.isUnicode = true;
                result.strings.append(e);
            }
            start = -1;
        }
    }
    if (start >= 0 && (n - start) >= minLength * 2) {
        QByteArray u16 = data.mid(start, n - start);
        if (u16.size() % 2 == 0) {
            ExtractedString e;
            e.fileOffset = static_cast<quint32>(start);
            e.value = QString::fromUtf16(reinterpret_cast<const char16_t*>(u16.constData()), u16.size() / 2);
            e.isUnicode = true;
            result.strings.append(e);
        }
    }

    return result;
}

StringExtractionResult PEStringExtractor::extractFromFile(const QString &filePath, int minLength)
{
    StringExtractionResult result;
    result.minLength = minLength;
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
        return result;
    QByteArray data = file.readAll();
    file.close();
    return extractFromData(data, minLength);
}
