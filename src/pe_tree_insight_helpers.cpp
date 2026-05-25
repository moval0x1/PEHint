#include "pe_tree_insight_helpers.h"

#include "language_manager.h"
#include "pe_utils.h"

#include <QHash>
#include <QRegularExpression>
#include <QSet>
#include <QVector>

namespace PeTreeInsight {

QString uiStringWithFallback(const QString &key, const QString &fallback)
{
    const QString fromIni = LanguageManager::getInstance().getIniString(key);
    if (!fromIni.isEmpty()) {
        return fromIni;
    }
    return LanguageManager::getInstance().getString(key, fallback);
}

QString formatHexPreview(const QByteArray &data, int maxBytes)
{
    if (data.isEmpty()) {
        return QString();
    }
    const int cap = qMin(data.size(), maxBytes);
    QString s;
    s.reserve(static_cast<int>(static_cast<size_t>(cap) * 3u));
    for (int i = 0; i < cap; ++i) {
        if (i > 0) {
            s += QLatin1Char(' ');
        }
        s += QStringLiteral("%1").arg(static_cast<quint8>(data[i]), 2, 16, QLatin1Char('0')).toUpper();
    }
    if (data.size() > maxBytes) {
        s += QStringLiteral(" â€¦");
    }
    return s;
}

/** PE structure tree uses English only (field names / units), regardless of UI language. */
QString peTreeSizeBytesText(const QString &sizeHexToken)
{
    return QStringLiteral("%1 bytes").arg(sizeHexToken);
}

QString peTreeEntriesText(const QString &countToken)
{
    return QStringLiteral("%1 entries").arg(countToken);
}

bool isFileInsightJsonKey(const QString &jsonFieldKey)
{
    static const QSet<QString> kKeys = {
        QStringLiteral("File Insights"),
        QStringLiteral("Overlay"),
        QStringLiteral("File Entropy"),
        QStringLiteral("MD5"),
        QStringLiteral("SHA256"),
        QStringLiteral("ImpHash"),
        QStringLiteral("File Ratio"),
        QStringLiteral("Toolchain"),
        QStringLiteral("Signed"),
        QStringLiteral("Entry Point"),
        QStringLiteral("PDB Path"),
        QStringLiteral("PDB Raw"),
        QStringLiteral("PDB GUID"),
        QStringLiteral("PDB Age"),
        QStringLiteral("File Version"),
        QStringLiteral("Product Version"),
        QStringLiteral("Company Name"),
        QStringLiteral("Product Name"),
        QStringLiteral("Manifest UAC"),
    };
    return kKeys.contains(jsonFieldKey);
}

QString insightMeaningText(const QString &jsonFieldKey)
{
    struct Row {
        const char *fieldKey;
        const char *iniKey;
        const char *enFallback;
    };
    static const Row kRows[] = {
        { "Overlay", "UI/overlay_meaning",
          "Data appended after the last section on disk; common in installers, self-extractors, and some packers." },
        { "File Entropy", "UI/entropy_meaning_normal",
          "Shannon entropy of the whole file (0-8 bits per byte); high values often indicate packing or encryption." },
        { "MD5", "UI/md5_meaning",
          "MD5 digest of the entire file on disk (useful for quick identification and IOC sharing)." },
        { "SHA256", "UI/sha256_meaning",
          "SHA-256 digest of the entire file on disk (common for malware feeds and Authenticode-adjacent workflows)." },
        { "ImpHash", "UI/imphash_meaning",
          "Mandiant import hash â€” MD5 of ordered import DLL/function pairs; stable across packers that preserve the IAT." },
        { "File Ratio", "UI/file_ratio_meaning",
          "Ratio of PE logical size (headers + section raw data) to total file size; lower values suggest overlay or appended data." },
        { "Toolchain", "UI/toolchain_meaning",
          "Compiler/linker fingerprint inferred from the Rich Header (when present)." },
        { "Signed", "UI/signed_meaning",
          "Whether the file carries a digital signature (Authenticode). Signed files include a certificate table; unsigned files do not." },
        { "Entry Point", "UI/entry_point_meaning",
          "Where Windows starts running this program â€” the memory address (RVA) and the section that contains the first instructions." },
        { "PDB Path", "UI/pdb_path_meaning",
          "Program database path from the CodeView debug directory (RSDS or NB10)." },
        { "PDB Raw", "UI/pdb_raw_meaning",
          "Raw RSDS/NB10 record at the CodeView offset; use the hex view for byte-level detail." },
        { "PDB GUID", "UI/pdb_guid_meaning",
          "Unique PDB identifier used with age to locate symbols on a symbol server." },
        { "PDB Age", "UI/pdb_age_meaning",
          "Incremental build counter paired with the GUID to match the correct PDB file." },
        { "File Version", "UI/version_file_meaning",
          "FileVersion string from the VS_VERSION_INFO resource block." },
        { "Product Version", "UI/version_product_meaning",
          "ProductVersion string from the VS_VERSION_INFO resource block." },
        { "Company Name", "UI/version_company_meaning",
          "CompanyName string from the VS_VERSION_INFO resource block." },
        { "Product Name", "UI/version_product_name_meaning",
          "ProductName string from the VS_VERSION_INFO resource block." },
        { "Manifest UAC", "UI/version_manifest_uac_meaning",
          "requestedExecutionLevel from the embedded application manifest (RT_MANIFEST)." },
        { "File Insights", "UI/tree_file_insights_hint",
          "Quick triage: appended overlay, Shannon entropy, and PDB path from CodeView." },
    };
    for (const Row &row : kRows) {
        if (jsonFieldKey != QLatin1String(row.fieldKey)) {
            continue;
        }
        const QString fromIni = LanguageManager::getInstance().getIniString(QString::fromLatin1(row.iniKey));
        if (!fromIni.isEmpty()) {
            return fromIni;
        }
        return QString::fromUtf8(row.enFallback);
    }
    return QString();
}
QString formatCodeViewRawTreeValue(const PEPdbInfo &pdb)
{
    return pdb.format.isEmpty() ? QStringLiteral("CodeView") : pdb.format;
}
QString formatEntryPointSummary(const PEFileMetrics &metrics)
{
    if (metrics.entryPointRva == 0) {
        return LANG(QStringLiteral("UI/entry_point_none"));
    }
    QMap<QString, QString> params;
    params.insert(QStringLiteral("rva"), PEUtils::formatHexWidth(metrics.entryPointRva, 8));
    params.insert(QStringLiteral("section"),
                  metrics.entryPointSection.isEmpty() ? QStringLiteral("?") : metrics.entryPointSection);
    return LANG_PARAMS(QStringLiteral("UI/entry_point_summary"), params);
}

const QStringList &dataDirectoryFieldKeys()
{
    static const QStringList keys = {
        QStringLiteral("Export Directory"),
        QStringLiteral("Import Directory"),
        QStringLiteral("Resource Directory"),
        QStringLiteral("Exception Directory"),
        QStringLiteral("Certificate Directory"),
        QStringLiteral("Base Relocation Directory"),
        QStringLiteral("Debug Directory"),
        QStringLiteral("Architecture Directory"),
        QStringLiteral("Global Pointer Directory"),
        QStringLiteral("TLS Directory"),
        QStringLiteral("Load Configuration Directory"),
        QStringLiteral("Bound Import Directory"),
        QStringLiteral("Import Address Table Directory"),
        QStringLiteral("Delay Import Directory"),
        QStringLiteral("COM+ Runtime Header Directory"),
        QStringLiteral("Reserved")
    };
    return keys;
}

quint32 readLe32(const uchar *p)
{
    return quint32(p[0]) | (quint32(p[1]) << 8) | (quint32(p[2]) << 16) | (quint32(p[3]) << 24);
}

quint16 readLe16(const uchar *p)
{
    return quint16(p[0]) | (quint16(p[1]) << 8);
}

quint64 readLe64(const uchar *p)
{
    quint64 lo = readLe32(p);
    quint64 hi = readLe32(p + 4);
    return lo | (hi << 32);
}
QString resourceTypeIdLabel(quint32 id)
{
    switch (id) {
    case 1: return QStringLiteral("RT_CURSOR");
    case 2: return QStringLiteral("RT_BITMAP");
    case 3: return QStringLiteral("RT_ICON");
    case 4: return QStringLiteral("RT_MENU");
    case 5: return QStringLiteral("RT_DIALOG");
    case 6: return QStringLiteral("RT_STRING");
    case 7: return QStringLiteral("RT_FONTDIR");
    case 8: return QStringLiteral("RT_FONT");
    case 9: return QStringLiteral("RT_ACCELERATOR");
    case 10: return QStringLiteral("RT_RCDATA");
    case 11: return QStringLiteral("RT_MESSAGETABLE");
    case 12: return QStringLiteral("RT_GROUP_CURSOR");
    case 14: return QStringLiteral("RT_GROUP_ICON");
    case 16: return QStringLiteral("RT_VERSION");
    case 24: return QStringLiteral("RT_MANIFEST");
    default: return QString();
    }
}

bool findEmbeddedManifestRva(const QByteArray &data, quint32 rootFo, quint32 absEnd, quint32 *outRva, quint32 *outSize)
{
    *outRva = 0;
    *outSize = 0;

    struct Frame {
        quint32 dirFo;
        int depth;
        bool inManifestBranch;
    };

    const quint32 fileSize = static_cast<quint32>(data.size());
    const quint32 regionEnd = qMin(absEnd, fileSize);
    QVector<Frame> stack;
    stack.append({rootFo, 0, false});
    QSet<quint32> visited;

    while (!stack.isEmpty()) {
        const Frame frame = stack.takeLast();
        if (frame.depth > 8 || visited.contains(frame.dirFo)) {
            continue;
        }
        visited.insert(frame.dirFo);

        const quint32 dirFo = frame.dirFo;
        if (dirFo + 16 > regionEnd) {
            continue;
        }

        const uchar *b = reinterpret_cast<const uchar *>(data.constData() + dirFo);
        const quint16 nNamed = readLe16(b + 12);
        const quint16 nId = readLe16(b + 14);
        const quint32 maxEntriesInDir =
            (dirFo + 16 < regionEnd) ? (regionEnd - dirFo - 16) / 8 : 0;
        const quint32 nEntries = qMin(static_cast<quint32>(nNamed) + static_cast<quint32>(nId),
                                      maxEntriesInDir);

        quint32 entryOff = 16;
        for (quint32 i = 0; i < nEntries; ++i) {
            if (dirFo + entryOff + 8 > regionEnd) {
                break;
            }
            const quint32 name = readLe32(b + entryOff);
            const quint32 otd = readLe32(b + entryOff + 4);
            entryOff += 8;
            const bool isNamed = (name & 0x80000000u) != 0;
            const quint32 id = isNamed ? 0u : name;

            if (otd & 0x80000000u) {
                const quint32 subFo = rootFo + (otd & 0x7FFFFFFFu);
                bool branch = frame.inManifestBranch;
                if (frame.depth == 0) {
                    if (isNamed || id != 24u) {
                        continue;
                    }
                    branch = true;
                }
                stack.append({subFo, frame.depth + 1, branch});
            } else {
                if (!frame.inManifestBranch || frame.depth < 2) {
                    continue;
                }
                const quint32 dataFo = rootFo + otd;
                if (dataFo + 16 > fileSize) {
                    continue;
                }
                const uchar *de = reinterpret_cast<const uchar *>(data.constData() + dataFo);
                *outRva = readLe32(de);
                *outSize = readLe32(de + 4);
                return true;
            }
        }
    }
    return false;
}
QString insightExplanationHtml(const QString &jsonFieldKey)
{
    const QString text = insightMeaningText(jsonFieldKey);
    if (text.isEmpty()) {
        return QString();
    }
    return QStringLiteral("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>")
        .arg(text.toHtmlEscaped());
}

QString fileInsightFieldLabel(const QString &fieldKey)
{
    static const QHash<QString, const char *> kLabels = {
        { QStringLiteral("Overlay"), "UI/field_overlay" },
        { QStringLiteral("File Entropy"), "UI/field_file_entropy" },
        { QStringLiteral("MD5"), "UI/field_md5" },
        { QStringLiteral("SHA256"), "UI/field_sha256" },
        { QStringLiteral("ImpHash"), "UI/field_imphash" },
        { QStringLiteral("File Ratio"), "UI/field_file_ratio" },
        { QStringLiteral("Toolchain"), "UI/field_toolchain" },
        { QStringLiteral("Signed"), "UI/field_signed" },
        { QStringLiteral("Entry Point"), "UI/field_entry_point" },
        { QStringLiteral("PDB Path"), "UI/field_pdb_path" },
        { QStringLiteral("PDB Raw"), "UI/field_pdb_raw" },
        { QStringLiteral("PDB GUID"), "UI/field_pdb_guid" },
        { QStringLiteral("PDB Age"), "UI/field_pdb_age" },
        { QStringLiteral("File Version"), "UI/field_file_version" },
        { QStringLiteral("Product Version"), "UI/field_product_version" },
        { QStringLiteral("Company Name"), "UI/field_company_name" },
        { QStringLiteral("Product Name"), "UI/field_product_name" },
        { QStringLiteral("Manifest UAC"), "UI/field_manifest_uac" },
    };
    const char *iniKey = kLabels.value(fieldKey);
    return iniKey ? LANG(iniKey) : fieldKey;
}

} // namespace PeTreeInsight

