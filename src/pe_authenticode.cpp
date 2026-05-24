#include "pe_authenticode.h"

#include <QChar>

namespace {

constexpr int kMaxPublisherChars = 120;

quint32 readLe32(const QByteArray &bytes, int offset)
{
    const auto *d = reinterpret_cast<const unsigned char *>(bytes.constData() + offset);
    return static_cast<quint32>(d[0]) | (static_cast<quint32>(d[1]) << 8)
           | (static_cast<quint32>(d[2]) << 16) | (static_cast<quint32>(d[3]) << 24);
}

QString sanitizePublisher(QString value)
{
    value = value.trimmed();
    while (!value.isEmpty() && (value.front() == QLatin1Char('"') || value.front() == QLatin1Char('\''))) {
        value.remove(0, 1);
    }
    while (!value.isEmpty() && (value.back() == QLatin1Char('"') || value.back() == QLatin1Char('\''))) {
        value.chop(1);
    }
    value = value.trimmed();
    if (value.size() > kMaxPublisherChars) {
        value = value.left(kMaxPublisherChars);
    }
    bool hasLetterOrDigit = false;
    for (const QChar ch : value) {
        if (ch.isLetterOrNumber()) {
            hasLetterOrDigit = true;
            break;
        }
    }
    if (!hasLetterOrDigit || value.size() < 2) {
        return QString();
    }
    return value;
}

QString readUntilDelimiterUtf8(const QByteArray &payload, int start)
{
    int end = start;
    while (end < payload.size()) {
        const char ch = payload.at(end);
        if (ch == '\0' || ch == '\r' || ch == '\n' || ch == ',' || ch == '/' || ch == ';') {
            break;
        }
        ++end;
    }
    return sanitizePublisher(QString::fromUtf8(payload.constData() + start, end - start));
}

QString readUntilDelimiterUtf16(const QByteArray &payload, int start)
{
    QString out;
    for (int i = start; i + 1 < payload.size(); i += 2) {
        const char16_t ch = static_cast<char16_t>(
            static_cast<unsigned char>(payload.at(i))
            | (static_cast<unsigned char>(payload.at(i + 1)) << 8));
        if (ch == 0 || ch == u'\r' || ch == u'\n' || ch == u',' || ch == u'/' || ch == u';') {
            break;
        }
        out.append(QChar(ch));
    }
    return sanitizePublisher(out);
}

QString findCnUtf8(const QByteArray &payload)
{
    int idx = payload.indexOf("CN=");
    while (idx >= 0) {
        const QString candidate = readUntilDelimiterUtf8(payload, idx + 3);
        if (!candidate.isEmpty()) {
            return candidate;
        }
        idx = payload.indexOf("CN=", idx + 3);
    }
    return QString();
}

QString findCnUtf16(const QByteArray &payload)
{
    static const QByteArray kCnUtf16("C\0N\0=\0", 6);
    int idx = payload.indexOf(kCnUtf16);
    while (idx >= 0) {
        const QString candidate = readUntilDelimiterUtf16(payload, idx + kCnUtf16.size());
        if (!candidate.isEmpty()) {
            return candidate;
        }
        idx = payload.indexOf(kCnUtf16, idx + 2);
    }
    return QString();
}

QString findCommonNameUtf16(const QByteArray &payload)
{
    static const QByteArray kCommonNameUtf16(
        "c\0o\0m\0m\0o\0n\0N\0a\0m\0e\0", 20);
    int idx = payload.indexOf(kCommonNameUtf16);
    while (idx >= 0) {
        int cursor = idx + kCommonNameUtf16.size();
        while (cursor + 1 < payload.size()) {
            const char16_t ch = static_cast<char16_t>(
                static_cast<unsigned char>(payload.at(cursor))
                | (static_cast<unsigned char>(payload.at(cursor + 1)) << 8));
            if (ch == u'=' || ch == u':') {
                cursor += 2;
                break;
            }
            if (ch == 0 || ch == u'\r' || ch == u'\n') {
                break;
            }
            cursor += 2;
        }
        if (cursor + 1 < payload.size()) {
            const QString candidate = readUntilDelimiterUtf16(payload, cursor);
            if (!candidate.isEmpty()) {
                return candidate;
            }
        }
        idx = payload.indexOf(kCommonNameUtf16, idx + 2);
    }
    return QString();
}

QString extractPublisherFromPkcs7Payload(const QByteArray &payload)
{
    if (payload.isEmpty()) {
        return QString();
    }
    QString publisher = findCnUtf8(payload);
    if (!publisher.isEmpty()) {
        return publisher;
    }
    publisher = findCnUtf16(payload);
    if (!publisher.isEmpty()) {
        return publisher;
    }
    return findCommonNameUtf16(payload);
}

} // namespace

QString extractAuthenticodePublisher(const QByteArray &fileData, quint32 certTableOffset, quint32 certTableSize)
{
    if (fileData.isEmpty() || certTableOffset == 0 || certTableSize < 8) {
        return QString();
    }
    const quint64 start = certTableOffset;
    const quint64 fileSize = static_cast<quint64>(fileData.size());
    if (start >= fileSize) {
        return QString();
    }
    const quint64 end = qMin(start + static_cast<quint64>(certTableSize), fileSize);
    quint64 cursor = start;
    while (cursor + 8 <= end) {
        const int certStart = static_cast<int>(cursor);
        const quint32 certLength = readLe32(fileData, certStart);
        if (certLength < 8) {
            break;
        }
        const quint64 certEnd = qMin(cursor + static_cast<quint64>(certLength), end);
        const quint64 payloadStart = cursor + 8;
        if (payloadStart < certEnd) {
            const int payloadOffset = static_cast<int>(payloadStart);
            const int payloadLength = static_cast<int>(certEnd - payloadStart);
            const QByteArray payload = fileData.mid(payloadOffset, payloadLength);
            const QString publisher = extractPublisherFromPkcs7Payload(payload);
            if (!publisher.isEmpty()) {
                return publisher;
            }
        }
        const quint64 advance = (static_cast<quint64>(certLength) + 7u) & ~7ull;
        if (advance == 0) {
            break;
        }
        cursor += advance;
    }
    return QString();
}
