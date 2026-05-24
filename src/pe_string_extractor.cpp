/**
 * @file pe_string_extractor.cpp
 * @brief Implementation of PE String Extractor
 */

#include "pe_string_extractor.h"
#include "pe_analysis.h"
#include "pe_utils.h"
#include "pe_structures.h"
#include <QFile>
#include <QRegularExpression>

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

StringExtractionResult PEStringExtractor::extractFromData(const QByteArray &data, int minLength,
                                                          const std::function<void(int)> &reportProgress)
{
    StringExtractionResult result;
    result.minLength = minLength;
    if (data.isEmpty() || minLength < 1) {
        if (reportProgress) {
            reportProgress(100);
        }
        return result;
    }

    int lastReported = -1;
    auto report = [&](int pct) {
        if (!reportProgress) {
            return;
        }
        pct = qBound(0, pct, 100);
        if (pct > lastReported) {
            lastReported = pct;
            reportProgress(pct);
        }
    };

    report(0);

    const int n = data.size();
    const int asciiStep = qMax(4096, n / 128);

    // ASCII strings
    int start = -1;
    for (int i = 0; i < n; ++i) {
        if ((i % asciiStep) == 0) {
            report((i * 50) / qMax(1, n));
        }
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

    report(50);

    // UTF-16LE strings (2-byte aligned)
    const int unicodeSpan = qMax(1, n - 1);
    const int uStep = qMax(4096, unicodeSpan / 128);
    start = -1;
    for (int i = 0; i + 1 < n; i += 2) {
        if ((i % uStep) == 0) {
            report(50 + (i * 50) / unicodeSpan);
        }
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

    report(100);
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

namespace {

bool stringContainsUrl(const QString &value)
{
    const QString lower = value.toLower();
    if (lower.contains(QStringLiteral("http://")) || lower.contains(QStringLiteral("https://"))) {
        return true;
    }
    static const QRegularExpression wwwRe(
        QStringLiteral(R"(\bwww\.[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})"),
        QRegularExpression::CaseInsensitiveOption);
    return wwwRe.match(value).hasMatch();
}

bool stringContainsRegistryPath(const QString &value)
{
    const QString upper = value.toUpper();
    if (upper.contains(QStringLiteral("HKEY_"))) {
        return true;
    }
    if (upper.startsWith(QStringLiteral("HKLM")) || upper.startsWith(QStringLiteral("HKCU"))
        || upper.startsWith(QStringLiteral("HKCR")) || upper.startsWith(QStringLiteral("HKU"))
        || upper.startsWith(QStringLiteral("HKCC"))) {
        return true;
    }
    if (value.contains(QStringLiteral("\\Software\\"), Qt::CaseInsensitive)
        || value.contains(QStringLiteral("\\CurrentVersion\\"), Qt::CaseInsensitive)
        || value.contains(QStringLiteral("\\Registry\\"), Qt::CaseInsensitive)
        || value.contains(QStringLiteral("\\System\\CurrentControlSet\\"), Qt::CaseInsensitive)) {
        return true;
    }
    return false;
}

} // namespace

bool PEStringExtractor::matchesContentFilter(const QString &value, const QString &filterKey)
{
    if (filterKey == QStringLiteral("url")) {
        return stringContainsUrl(value);
    }
    if (filterKey == QStringLiteral("ip")) {
        return PEUtils::stringContainsPlausibleHardcodedIpv4(value);
    }
    if (filterKey == QStringLiteral("registry")) {
        return stringContainsRegistryPath(value);
    }
    if (filterKey == QStringLiteral("command")) {
        return PEAnalysis::matchesSuspiciousCommand(value);
    }
    return true;
}
