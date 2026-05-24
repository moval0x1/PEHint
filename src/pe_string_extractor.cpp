/**
 * @file pe_string_extractor.cpp
 * @brief Implementation of PE String Extractor
 */

#include "pe_string_extractor.h"
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

bool ipv4OctetsFromString(const QString &ip, int out[4])
{
    const QStringList parts = ip.split(QLatin1Char('.'));
    if (parts.size() != 4) {
        return false;
    }
    bool ok = false;
    for (int i = 0; i < 4; ++i) {
        out[i] = parts.at(i).toInt(&ok);
        if (!ok || out[i] < 0 || out[i] > 255) {
            return false;
        }
    }
    return true;
}

bool looksLikeVersionQuadruple(int o1, int o2, int o3, int o4)
{
    if (o2 == 0 && o3 == 0 && o4 == 0) {
        return true;
    }
    if (o3 == 0 && o4 == 0) {
        return true;
    }
    if (o1 <= 30 && o2 <= 30 && o3 <= 30 && o4 <= 30) {
        return true;
    }
    return false;
}

bool isLikelyNetworkIpv4(int o1, int o2, int o3, int o4)
{
    if (o1 >= 100 || o2 >= 100 || o3 >= 100 || o4 >= 100) {
        return true;
    }
    if (o1 == o2 && o2 == o3 && o3 == o4 && o1 > 0) {
        return true;
    }
    if (o1 == 10 && (o2 > 0 || o3 > 0 || o4 > 0)) {
        return true;
    }
    if (o1 == 127 && o4 > 0) {
        return true;
    }
    if (o1 == 172 && o2 >= 16 && o2 <= 31) {
        return true;
    }
    if (o1 == 192 && o2 == 168) {
        return true;
    }
    return false;
}

bool isPlausibleIpv4Token(const QString &ip)
{
    int octets[4] = {0, 0, 0, 0};
    if (!ipv4OctetsFromString(ip, octets)) {
        return false;
    }
    if (ip == QStringLiteral("0.0.0.0") || ip == QStringLiteral("255.255.255.255")) {
        return false;
    }
    if (looksLikeVersionQuadruple(octets[0], octets[1], octets[2], octets[3])
        && !isLikelyNetworkIpv4(octets[0], octets[1], octets[2], octets[3])) {
        return false;
    }
    return isLikelyNetworkIpv4(octets[0], octets[1], octets[2], octets[3]);
}

bool stringContainsPlausibleIpv4(const QString &value)
{
    static const QRegularExpression ipRe(
        QStringLiteral(R"(\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b)"));
    QRegularExpressionMatchIterator it = ipRe.globalMatch(value);
    while (it.hasNext()) {
        if (isPlausibleIpv4Token(it.next().captured(0))) {
            return true;
        }
    }
    return false;
}

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
        return stringContainsPlausibleIpv4(value);
    }
    if (filterKey == QStringLiteral("registry")) {
        return stringContainsRegistryPath(value);
    }
    return true;
}
