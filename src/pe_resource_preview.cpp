#include "pe_resource_preview.h"

#include "pe_structures.h"

#include <QImage>
#include <QtGlobal>
#include <cstring>

namespace {

quint32 readLe32(const QByteArray &data, int offset)
{
    if (offset + 4 > data.size()) {
        return 0;
    }
    const auto *p = reinterpret_cast<const unsigned char *>(data.constData() + offset);
    return quint32(p[0]) | (quint32(p[1]) << 8) | (quint32(p[2]) << 16) | (quint32(p[3]) << 24);
}

QString decodeResourceText(const QByteArray &data)
{
    if (data.isEmpty()) {
        return QString();
    }
    if (data.size() >= 4 && data.at(1) == '\0' && data.at(0) != '\0' && data.at(2) == '\0') {
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(data.constData()), data.size() / 2);
    }
    return QString::fromUtf8(data);
}

QString formatHexPreview(const QByteArray &data, int maxBytes = 512)
{
    if (data.isEmpty()) {
        return QString();
    }
    const int cap = qMin(data.size(), maxBytes);
    QString s;
    s.reserve(cap * 3);
    for (int i = 0; i < cap; ++i) {
        if (i > 0) {
            s += QLatin1Char(' ');
        }
        s += QStringLiteral("%1").arg(static_cast<quint8>(data.at(i)), 2, 16, QLatin1Char('0')).toUpper();
    }
    if (data.size() > maxBytes) {
        s += QStringLiteral(" …");
    }
    return s;
}

quint16 readLe16(const QByteArray &data, int offset)
{
    if (offset + 2 > data.size()) {
        return 0;
    }
    const auto *p = reinterpret_cast<const unsigned char *>(data.constData() + offset);
    return quint16(p[0]) | (quint16(p[1]) << 8);
}

quint32 dibColorTableBytes(const QByteArray &data, quint32 headerSize)
{
    if (data.size() < 16 || headerSize < 16) {
        return 0;
    }
    const quint16 bitCount = readLe16(data, 14);
    if (bitCount > 8) {
        return 0;
    }
    return (1u << bitCount) * 4u;
}

QByteArray wrapDibAsBmpFile(const QByteArray &dib)
{
    if (dib.size() < 40) {
        return QByteArray();
    }
    const quint32 headerSize = readLe32(dib, 0);
    if (headerSize < 40 || dib.size() < static_cast<int>(headerSize)) {
        return QByteArray();
    }
    const quint32 paletteBytes = dibColorTableBytes(dib, headerSize);
    const quint32 pixelOffset = 14u + headerSize + paletteBytes;
    const quint32 fileSize = 14u + static_cast<quint32>(dib.size());

    QByteArray bmp;
    bmp.resize(14 + dib.size());
    bmp[0] = 'B';
    bmp[1] = 'M';
    bmp[2] = char(fileSize & 0xff);
    bmp[3] = char((fileSize >> 8) & 0xff);
    bmp[4] = char((fileSize >> 16) & 0xff);
    bmp[5] = char((fileSize >> 24) & 0xff);
    bmp[6] = bmp[7] = bmp[8] = bmp[9] = 0;
    bmp[10] = char(pixelOffset & 0xff);
    bmp[11] = char((pixelOffset >> 8) & 0xff);
    bmp[12] = char((pixelOffset >> 16) & 0xff);
    bmp[13] = char((pixelOffset >> 24) & 0xff);
    std::memcpy(bmp.data() + 14, dib.constData(), static_cast<size_t>(dib.size()));
    return bmp;
}

QImage decodeBitmapResource(const QByteArray &data)
{
    QImage img;
    if (img.loadFromData(data, "BMP")) {
        return img;
    }
    const QByteArray wrapped = wrapDibAsBmpFile(data);
    if (!wrapped.isEmpty() && img.loadFromData(wrapped, "BMP")) {
        return img;
    }
    return QImage();
}

QImage decodeImagePayload(const QByteArray &data, const QString &formatHint)
{
    QImage img;
    if (img.loadFromData(data, formatHint.toLatin1().constData())) {
        return img;
    }
    if (formatHint == QStringLiteral("ICO")) {
        return decodeBitmapResource(data);
    }
    return QImage();
}

bool isMostlyPrintableText(const QString &text)
{
    if (text.size() < 4) {
        return false;
    }
    int printable = 0;
    for (const QChar ch : text) {
        if (ch.isPrint() || ch == QLatin1Char('\n') || ch == QLatin1Char('\r') || ch == QLatin1Char('\t')) {
            ++printable;
        }
    }
    return printable * 100 / text.size() >= 85;
}

} // namespace

ResourcePreview buildResourcePreview(const QByteArray &fileData, const PEResourceItem &item)
{
    ResourcePreview preview;
    preview.title = item.typeName;
    if (!item.resourceName.isEmpty()) {
        preview.title += QStringLiteral(" / ") + item.resourceName;
    }

    if (item.fileOffset == 0 || item.size == 0
        || static_cast<quint64>(item.fileOffset) + item.size > static_cast<quint64>(fileData.size())) {
        preview.kind = ResourcePreview::Kind::Empty;
        return preview;
    }

    const QByteArray payload = fileData.mid(static_cast<int>(item.fileOffset), static_cast<int>(item.size));
    const QString typeUpper = item.typeName.toUpper();

    if (typeUpper.contains(QStringLiteral("MANIFEST")) || item.typeId == 24) {
        const QString text = decodeResourceText(payload).trimmed();
        preview.kind = ResourcePreview::Kind::Html;
        preview.htmlContent =
            QStringLiteral("<pre style='font-family:Consolas,monospace;font-size:11px;white-space:pre-wrap;'>%1</pre>")
                .arg(text.toHtmlEscaped());
        return preview;
    }

    if (typeUpper.contains(QStringLiteral("VERSION")) || item.typeId == 16) {
        preview.kind = ResourcePreview::Kind::Hex;
        preview.hexPreview = formatHexPreview(payload, 256);
        preview.textContent = QStringLiteral("VS_VERSION_INFO block (%1 bytes)").arg(item.size);
        return preview;
    }

    if (typeUpper.contains(QStringLiteral("ICON")) || item.typeId == 3 || item.typeId == 14) {
        preview.image = decodeImagePayload(payload, QStringLiteral("ICO"));
        if (!preview.image.isNull()) {
            preview.kind = ResourcePreview::Kind::Image;
            return preview;
        }
    }

    if (typeUpper.contains(QStringLiteral("BITMAP")) || item.typeId == 2) {
        preview.image = decodeBitmapResource(payload);
        if (!preview.image.isNull()) {
            preview.kind = ResourcePreview::Kind::Image;
            return preview;
        }
    }

    const QString text = decodeResourceText(payload);
    if (isMostlyPrintableText(text)) {
        preview.kind = ResourcePreview::Kind::Text;
        preview.textContent = text.left(8192);
        if (text.size() > 8192) {
            preview.textContent += QStringLiteral("\n…");
        }
        return preview;
    }

    preview.kind = ResourcePreview::Kind::Hex;
    preview.hexPreview = formatHexPreview(payload);
    return preview;
}
