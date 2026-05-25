#include "pe_resource_preview.h"

#include "language_manager.h"
#include "pe_analysis.h"
#include "pe_structures.h"

#include <QBuffer>
#include <QImage>
#include <QMap>
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

quint16 readLe16(const QByteArray &data, int offset)
{
    if (offset + 2 > data.size()) {
        return 0;
    }
    const auto *p = reinterpret_cast<const unsigned char *>(data.constData() + offset);
    return quint16(p[0]) | (quint16(p[1]) << 8);
}

void writeLe16At(QByteArray &data, int offset, quint16 value)
{
    if (offset + 2 > data.size()) {
        return;
    }
    data[offset] = char(value & 0xff);
    data[offset + 1] = char((value >> 8) & 0xff);
}

void writeLe32At(QByteArray &data, int offset, quint32 value)
{
    if (offset + 4 > data.size()) {
        return;
    }
    data[offset] = char(value & 0xff);
    data[offset + 1] = char((value >> 8) & 0xff);
    data[offset + 2] = char((value >> 16) & 0xff);
    data[offset + 3] = char((value >> 24) & 0xff);
}

bool looksLikeUtf16LeText(const QByteArray &data)
{
    if (data.size() < 4) {
        return false;
    }
    int pairs = 0;
    int asciiPairs = 0;
    for (int i = 0; i + 1 < data.size(); i += 2) {
        const quint8 lo = static_cast<quint8>(data.at(i));
        const quint8 hi = static_cast<quint8>(data.at(i + 1));
        if (lo == 0 && hi == 0) {
            break;
        }
        ++pairs;
        if (hi == 0 && lo >= 32 && lo <= 126) {
            ++asciiPairs;
        }
    }
    return pairs >= 2 && asciiPairs * 100 / pairs >= 70;
}

QString decodeResourceText(const QByteArray &data)
{
    if (data.isEmpty()) {
        return QString();
    }
    if (looksLikeUtf16LeText(data)) {
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(data.constData()), data.size() / 2);
    }
    if (data.size() >= 4 && data.at(1) == '\0' && data.at(0) != '\0' && data.at(2) == '\0') {
        return QString::fromUtf16(reinterpret_cast<const char16_t *>(data.constData()), data.size() / 2);
    }
    return QString::fromUtf8(data);
}

QString decodeRtStringResource(const QByteArray &data)
{
    QStringList lines;
    int off = 0;
    while (off + 2 <= data.size()) {
        const quint16 len = readLe16(data, off);
        off += 2;
        if (len == 0) {
            continue;
        }
        if (off + static_cast<int>(len) * 2 > data.size()) {
            break;
        }
        const QString s = QString::fromUtf16(reinterpret_cast<const char16_t *>(data.constData() + off), len);
        off += static_cast<int>(len) * 2;
        const QString trimmed = s.trimmed();
        if (!trimmed.isEmpty()) {
            lines.append(trimmed);
        }
    }
    return lines.join(QStringLiteral("\n"));
}

QString extractUtf16LeRuns(const QByteArray &data, int maxChars = 4096)
{
    QString out;
    int i = 0;
    while (i + 1 < data.size() && out.size() < maxChars) {
        const quint8 lo = static_cast<quint8>(data.at(i));
        const quint8 hi = static_cast<quint8>(data.at(i + 1));
        if (hi != 0 || lo < 32 || lo > 126) {
            ++i;
            continue;
        }
        QString run;
        while (i + 1 < data.size() && static_cast<quint8>(data.at(i + 1)) == 0) {
            const quint8 b = static_cast<quint8>(data.at(i));
            if (b < 32 || b > 126) {
                break;
            }
            run.append(QLatin1Char(static_cast<char>(b)));
            i += 2;
        }
        if (run.size() >= 4) {
            if (!out.isEmpty()) {
                out += QLatin1Char('\n');
            }
            out += run;
        }
        if (i < data.size() && run.isEmpty()) {
            ++i;
        }
    }
    return out.left(maxChars);
}

QString extractAsciiRuns(const QByteArray &data, int maxChars = 4096)
{
    QString out;
    QString run;
    auto flush = [&]() {
        if (run.size() >= 4) {
            if (!out.isEmpty()) {
                out += QLatin1Char('\n');
            }
            out += run;
            run.clear();
        } else {
            run.clear();
        }
    };
    for (int i = 0; i < data.size() && out.size() < maxChars; ++i) {
        const quint8 b = static_cast<quint8>(data.at(i));
        if (b >= 32 && b <= 126) {
            run.append(QLatin1Char(static_cast<char>(b)));
        } else {
            flush();
        }
    }
    flush();
    return out.left(maxChars);
}

QString extractEmbeddedTextPreview(const QByteArray &data)
{
    const QString utf16 = extractUtf16LeRuns(data);
    const QString ascii = extractAsciiRuns(data);
    if (!utf16.isEmpty() && !ascii.isEmpty()) {
        return utf16 + QStringLiteral("\n") + ascii;
    }
    return !utf16.isEmpty() ? utf16 : ascii;
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

QString formatHexAndTextPreview(const QByteArray &data, int maxBytes = 512)
{
    QString out = formatHexPreview(data, maxBytes);
    const int cap = qMin(data.size(), maxBytes);
    const QString decoded = extractEmbeddedTextPreview(data.mid(0, cap));
    if (!decoded.isEmpty()) {
        out += QStringLiteral("\n\n");
        out += decoded;
    }
    return out;
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

QImage decodePeIconOrCursorPayload(const QByteArray &data)
{
    if (data.size() >= 8 && static_cast<quint8>(data.at(0)) == 0x89 && data.mid(1, 3) == "PNG") {
        QImage img;
        if (img.loadFromData(data, "PNG")) {
            return img;
        }
    }
    if (data.size() >= 6 && readLe16(data, 0) == 0 && readLe16(data, 2) == 1) {
        QImage img;
        if (img.loadFromData(data, "ICO")) {
            return img;
        }
    }
    return decodeBitmapResource(data);
}

QImage decodeImagePayload(const QByteArray &data, const QString &formatHint)
{
    QImage img;
    if (img.loadFromData(data, formatHint.toLatin1().constData())) {
        return img;
    }
    if (formatHint == QStringLiteral("ICO")) {
        return decodePeIconOrCursorPayload(data);
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

QString escHtml(const QString &s)
{
    return s.toHtmlEscaped();
}

QString formatVersionFieldRow(const QString &label, const QString &value)
{
    if (value.isEmpty()) {
        return QString();
    }
    return QStringLiteral("<tr><td style='padding:4px 8px;font-weight:600;white-space:nowrap;'>%1</td>"
                          "<td style='padding:4px 8px;'>%2</td></tr>")
        .arg(escHtml(label), escHtml(value));
}

QString formatVersionInfoHtml(const PEVersionInfo &info)
{
    QString html = QStringLiteral(
        "<table style='border-collapse:collapse;font-family:Segoe UI,sans-serif;font-size:11px;'>");
    html += formatVersionFieldRow(LANG("UI/resource_ver_file_version"), info.fileVersion);
    html += formatVersionFieldRow(LANG("UI/resource_ver_product_version"), info.productVersion);
    html += formatVersionFieldRow(LANG("UI/resource_ver_company_name"), info.companyName);
    html += formatVersionFieldRow(LANG("UI/resource_ver_product_name"), info.productName);
    html += formatVersionFieldRow(LANG("UI/resource_ver_file_description"), info.fileDescription);
    html += formatVersionFieldRow(LANG("UI/resource_ver_original_filename"), info.originalFilename);
    html += formatVersionFieldRow(LANG("UI/resource_ver_internal_name"), info.internalName);
    html += formatVersionFieldRow(LANG("UI/resource_ver_legal_copyright"), info.legalCopyright);
    html += formatVersionFieldRow(LANG("UI/resource_ver_legal_trademarks"), info.legalTrademarks);
    html += formatVersionFieldRow(LANG("UI/resource_ver_comments"), info.comments);
    html += QStringLiteral("</table>");
    if (!html.contains(QStringLiteral("<tr>"))) {
        return QString();
    }
    return html;
}

struct GrpIconEntry {
    quint8 width = 0;
    quint8 height = 0;
    quint16 bitCount = 0;
    quint32 bytesInRes = 0;
    quint16 resourceId = 0;
};

bool parseGroupIconDirectory(const QByteArray &data, QVector<GrpIconEntry> &entries)
{
    entries.clear();
    if (data.size() < 6) {
        return false;
    }
    const quint16 reserved = readLe16(data, 0);
    const quint16 type = readLe16(data, 2);
    const quint16 count = readLe16(data, 4);
    if (reserved != 0 || (type != 1 && type != 2) || count == 0) {
        return false;
    }
    const int needed = 6 + static_cast<int>(count) * 14;
    if (data.size() < needed) {
        return false;
    }
    entries.reserve(count);
    for (int i = 0; i < count; ++i) {
        const int off = 6 + i * 14;
        GrpIconEntry entry;
        entry.width = static_cast<quint8>(data.at(off));
        entry.height = static_cast<quint8>(data.at(off + 1));
        entry.bitCount = readLe16(data, off + 6);
        entry.bytesInRes = readLe32(data, off + 8);
        entry.resourceId = readLe16(data, off + 12);
        entries.append(entry);
    }
    return !entries.isEmpty();
}

QString iconSizeLabel(const GrpIconEntry &entry)
{
    const int w = entry.width == 0 ? 256 : entry.width;
    const int h = entry.height == 0 ? 256 : entry.height;
    QMap<QString, QString> sizeParams;
    sizeParams[QStringLiteral("width")] = QString::number(w);
    sizeParams[QStringLiteral("height")] = QString::number(h);
    sizeParams[QStringLiteral("bpp")] = QString::number(entry.bitCount);
    const QString fromIni = LanguageManager::getInstance().getIniString(QStringLiteral("UI/resource_size_bpp"));
    if (!fromIni.isEmpty()) {
        return LanguageManager::getInstance().getString(QStringLiteral("UI/resource_size_bpp"), sizeParams, fromIni);
    }
    return QStringLiteral("%1x%2, %3 bpp").arg(w).arg(h).arg(entry.bitCount);
}

const PEResourceItem *findLinkedIconResource(const QVector<PEResourceItem> &allItems,
                                             quint32 iconTypeId,
                                             quint16 resourceId,
                                             quint32 languageId)
{
    const PEResourceItem *fallback = nullptr;
    for (const PEResourceItem &candidate : allItems) {
        if (candidate.typeId != iconTypeId || candidate.nameId != resourceId) {
            continue;
        }
        if (languageId != 0 && candidate.languageId == languageId) {
            return &candidate;
        }
        if (!fallback) {
            fallback = &candidate;
        }
    }
    return fallback;
}

QByteArray buildIcoFileFromImages(const QVector<QPair<QByteArray, GrpIconEntry>> &images)
{
    if (images.isEmpty()) {
        return QByteArray();
    }
    quint32 offset = 6 + static_cast<quint32>(images.size()) * 16u;
    QByteArray ico;
    ico.resize(static_cast<int>(offset));
    writeLe16At(ico, 0, 0);
    writeLe16At(ico, 2, 1);
    writeLe16At(ico, 4, static_cast<quint16>(images.size()));

    int dirOff = 6;
    for (int i = 0; i < images.size(); ++i) {
        const GrpIconEntry &entry = images.at(i).second;
        const QByteArray &payload = images.at(i).first;
        ico[dirOff] = entry.width;
        ico[dirOff + 1] = entry.height;
        ico[dirOff + 2] = 0;
        ico[dirOff + 3] = 0;
        writeLe16At(ico, dirOff + 4, 1);
        writeLe16At(ico, dirOff + 6, entry.bitCount != 0 ? entry.bitCount : 32);
        writeLe32At(ico, dirOff + 8, static_cast<quint32>(payload.size()));
        writeLe32At(ico, dirOff + 12, offset);
        offset += static_cast<quint32>(payload.size());
        dirOff += 16;
    }
    for (const auto &pair : images) {
        ico.append(pair.first);
    }
    return ico;
}

QString imageGalleryHtml(const QVector<ResourcePreviewImageEntry> &images)
{
    QString html = QStringLiteral(
        "<div style='display:flex;flex-wrap:wrap;gap:12px;font-family:Segoe UI,sans-serif;font-size:10px;'>");
    for (const ResourcePreviewImageEntry &entry : images) {
        if (entry.image.isNull()) {
            continue;
        }
        QByteArray bytes;
        QBuffer buffer(&bytes);
        buffer.open(QIODevice::WriteOnly);
        entry.image.save(&buffer, "PNG");
        html += QStringLiteral("<div style='text-align:center;'>"
                               "<img src='data:image/png;base64,%1' style='max-width:96px;max-height:96px;"
                               "border:1px solid #e5e7eb;background:#fafafa;padding:4px;'/>"
                               "<div style='margin-top:4px;color:#555;'>%2</div></div>")
                    .arg(QString::fromLatin1(bytes.toBase64()), escHtml(entry.label));
    }
    html += QStringLiteral("</div>");
    return html;
}

ResourcePreview buildGroupIconPreview(const QByteArray &fileData,
                                      const PEResourceItem &item,
                                      const QVector<PEResourceItem> &allItems,
                                      quint32 iconTypeId,
                                      const QString &kindLabel)
{
    ResourcePreview preview;
    preview.title = item.typeName;
    if (!item.resourceName.isEmpty()) {
        preview.title += QStringLiteral(" / ") + item.resourceName;
    }

    QVector<GrpIconEntry> entries;
    const QByteArray payload = fileData.mid(static_cast<int>(item.fileOffset), static_cast<int>(item.size));
    if (!parseGroupIconDirectory(payload, entries)) {
        preview.kind = ResourcePreview::Kind::Hex;
        preview.hexPreview = formatHexPreview(payload, 256);
        QMap<QString, QString> dirParams;
        dirParams[QStringLiteral("kind")] = kindLabel;
        dirParams[QStringLiteral("size")] = QString::number(item.size);
        preview.textContent = LANG_PARAMS("UI/resource_directory_bytes", dirParams);
        return preview;
    }

    QVector<QPair<QByteArray, GrpIconEntry>> resolvedImages;
    for (const GrpIconEntry &entry : entries) {
        const PEResourceItem *linked =
            findLinkedIconResource(allItems, iconTypeId, entry.resourceId, item.languageId);
        if (!linked || linked->fileOffset == 0 || linked->size == 0) {
            continue;
        }
        const QByteArray iconPayload =
            fileData.mid(static_cast<int>(linked->fileOffset), static_cast<int>(linked->size));
        if (!iconPayload.isEmpty()) {
            resolvedImages.append({iconPayload, entry});
        }
    }

    for (const auto &pair : resolvedImages) {
        QImage img = decodePeIconOrCursorPayload(pair.first);
        if (img.isNull()) {
            continue;
        }
        ResourcePreviewImageEntry entry;
        entry.image = img;
        QMap<QString, QString> idParams;
        idParams[QStringLiteral("size")] = iconSizeLabel(pair.second);
        idParams[QStringLiteral("id")] = QString::number(pair.second.resourceId);
        const QString iconIdFmt = LanguageManager::getInstance().getIniString(QStringLiteral("UI/resource_icon_size_id"));
        entry.label = iconIdFmt.isEmpty()
                          ? QStringLiteral("%1 (id %2)").arg(idParams.value(QStringLiteral("size")),
                                                           idParams.value(QStringLiteral("id")))
                          : LanguageManager::getInstance().getString(QStringLiteral("UI/resource_icon_size_id"),
                                                                     idParams, iconIdFmt);
        preview.images.append(entry);
    }

    if (!preview.images.isEmpty()) {
        preview.kind = ResourcePreview::Kind::ImageGallery;
        preview.htmlContent = imageGalleryHtml(preview.images);
        preview.image = preview.images.first().image;
        return preview;
    }

    const QByteArray icoFile = buildIcoFileFromImages(resolvedImages);
    if (!icoFile.isEmpty()) {
        QImage img;
        if (img.loadFromData(icoFile, "ICO")) {
            preview.kind = ResourcePreview::Kind::Image;
            preview.image = img;
            QMap<QString, QString> groupParams;
            groupParams[QStringLiteral("kind")] = kindLabel;
            groupParams[QStringLiteral("count")] = QString::number(resolvedImages.size());
            preview.textContent = LANG_PARAMS("UI/resource_group_embedded", groupParams);
            return preview;
        }
    }

    preview.kind = ResourcePreview::Kind::Text;
    QMap<QString, QString> listHeaderParams;
    listHeaderParams[QStringLiteral("kind")] = kindLabel;
    listHeaderParams[QStringLiteral("count")] = QString::number(entries.size());
    preview.textContent = LANG_PARAMS("UI/resource_group_list_header", listHeaderParams);
    for (const GrpIconEntry &entry : entries) {
        QMap<QString, QString> entryParams;
        entryParams[QStringLiteral("id")] = QString::number(entry.resourceId);
        entryParams[QStringLiteral("label")] = iconSizeLabel(entry);
        entryParams[QStringLiteral("size")] = QString::number(entry.bytesInRes);
        preview.textContent += LANG_PARAMS("UI/resource_group_entry", entryParams);
    }
    return preview;
}

} // namespace

ResourcePreview buildResourcePreview(const QByteArray &fileData,
                                     const PEResourceItem &item,
                                     const QVector<PEResourceItem> &allItems)
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
        const PEVersionInfo versionInfo = PEAnalysis::parseVersionResourceBlob(payload);
        const QString table = formatVersionInfoHtml(versionInfo);
        preview.kind = ResourcePreview::Kind::Html;
        if (!table.isEmpty()) {
            preview.htmlContent = table;
        } else {
            preview.htmlContent =
                QStringLiteral("<p style='font-family:Segoe UI,sans-serif;font-size:11px;'>%1</p>")
                    .arg(LANG_PARAM("UI/resource_ver_no_stringfileinfo", "size", QString::number(item.size)));
            preview.hexPreview = formatHexPreview(payload, 256);
        }
        return preview;
    }

    if (typeUpper.contains(QStringLiteral("GROUP_ICON")) || item.typeId == 14) {
        return buildGroupIconPreview(fileData, item, allItems, 3, LANG("UI/resource_kind_icon"));
    }

    if (typeUpper.contains(QStringLiteral("GROUP_CURSOR")) || item.typeId == 12) {
        return buildGroupIconPreview(fileData, item, allItems, 1, LANG("UI/resource_kind_cursor"));
    }

    if (typeUpper.contains(QStringLiteral("ICON")) || item.typeId == 3) {
        preview.image = decodeImagePayload(payload, QStringLiteral("ICO"));
        if (!preview.image.isNull()) {
            preview.kind = ResourcePreview::Kind::Image;
            return preview;
        }
    }

    if (typeUpper.contains(QStringLiteral("CURSOR")) || item.typeId == 1) {
        preview.image = decodePeIconOrCursorPayload(payload);
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

    if (item.typeId == 6 || typeUpper.contains(QStringLiteral("RT_STRING"))) {
        const QString strings = decodeRtStringResource(payload);
        if (!strings.isEmpty()) {
            preview.kind = ResourcePreview::Kind::Text;
            preview.textContent = strings.left(8192);
            if (strings.size() > 8192) {
                preview.textContent += QStringLiteral("\n…");
            }
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

    const QString embedded = extractEmbeddedTextPreview(payload);
    if (!embedded.isEmpty() && isMostlyPrintableText(embedded)) {
        preview.kind = ResourcePreview::Kind::Text;
        preview.textContent = embedded.left(8192);
        if (embedded.size() > 8192) {
            preview.textContent += QStringLiteral("\n…");
        }
        return preview;
    }

    preview.kind = ResourcePreview::Kind::Hex;
    preview.hexPreview = formatHexAndTextPreview(payload);
    return preview;
}
