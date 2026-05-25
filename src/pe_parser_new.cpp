#include "pe_parser_new.h"
#include "pe_authenticode.h"
#include "pe_ui_presenter.h"
#include "pe_ep_disasm.h"
#include "pe_utils.h"
#include "pe_analysis.h"
#include "language_manager.h"
#include <QDebug>
#include <QFileInfo>
#include <QTreeWidgetItem>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QCoreApplication>
#include <QDir>
#include <QDateTime>
#include <QSet>
#include <QVector>
#include <QMap>
#include <QtGlobal>
#include <QRegularExpression>
#include <functional>
#include <cstddef>
#include <cstring>

namespace {
constexpr int kFieldOffsetRole = Qt::UserRole + 20;
constexpr int kFieldSizeRole = Qt::UserRole + 21;

QString uiStringWithFallback(const QString &key, const QString &fallback)
{
    const QString fromIni = LanguageManager::getInstance().getIniString(key);
    if (!fromIni.isEmpty()) {
        return fromIni;
    }
    return LanguageManager::getInstance().getString(key, fallback);
}

QString formatHexPreview(const QByteArray &data, int maxBytes = 72)
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
        s += QStringLiteral(" …");
    }
    return s;
}

/** PE structure tree uses English only (field names / units), regardless of UI language. */
QString peTreeSizeBytesText(const QString &sizeHexToken)
{
    return QStringLiteral("%1 bytes").arg(sizeHexToken);
}

QString formatCodeViewRawTreeValue(const PEPdbInfo &pdb)
{
    return pdb.format.isEmpty() ? QStringLiteral("CodeView") : pdb.format;
}

QString peTreeEntriesText(const QString &countToken)
{
    return QStringLiteral("%1 entries").arg(countToken);
}

struct FieldExplanationCaches {
    QHash<QString, QString> explanationHtmlCache;
    QHash<QString, QJsonObject> languageJsonCache;
    QHash<QString, QDateTime> languageJsonMtime;
    /// Resolved absolute path per UI language (explanations.json / explanations_pt.json); avoids hundreds of disk probes while building the tree.
    QHash<QString, QString> explanationsPathByLanguage;
};

FieldExplanationCaches &fieldExplanationCaches()
{
    static FieldExplanationCaches s;
    return s;
}

void clearFieldExplanationCachesInternal()
{
    FieldExplanationCaches &c = fieldExplanationCaches();
    c.explanationHtmlCache.clear();
    c.languageJsonCache.clear();
    c.languageJsonMtime.clear();
    c.explanationsPathByLanguage.clear();
}

QString resolveExplanationsLanguageKey(const QJsonObject &root, const QString &currentLanguage)
{
    if (root.contains(currentLanguage) && root.value(currentLanguage).isObject()) {
        return currentLanguage;
    }
    if (root.contains(QStringLiteral("en")) && root.value(QStringLiteral("en")).isObject()) {
        return QStringLiteral("en");
    }
    if (root.contains(QStringLiteral("pt")) && root.value(QStringLiteral("pt")).isObject()) {
        return QStringLiteral("pt");
    }
    for (auto it = root.begin(); it != root.end(); ++it) {
        if (it.value().isObject()) {
            return it.key();
        }
    }
    return QString();
}

bool isFieldExplanationPlaceholder(const QString &fieldName, const QString &html)
{
    if (html.isEmpty()) {
        return true;
    }
    QString plain = html;
    plain.replace(QRegularExpression(QStringLiteral("<[^>]*>")), QStringLiteral(" "));
    plain = plain.simplified();
    const QString placeholder =
        LANG_PARAM(QStringLiteral("UI/field_explanation_placeholder"), QStringLiteral("fieldname"), fieldName)
            .simplified();
    if (!placeholder.isEmpty() && plain == placeholder) {
        return true;
    }
    if (plain.contains(QStringLiteral("Field explanation for"), Qt::CaseInsensitive)
        || plain.contains(QStringLiteral("Explicação do campo"), Qt::CaseInsensitive)
        || plain.contains(QStringLiteral("No detailed explanation"), Qt::CaseInsensitive)
        || plain.contains(QStringLiteral("Nenhuma explicação detalhada"), Qt::CaseInsensitive)) {
        return true;
    }
    return plain.contains(QStringLiteral("Coming soon"), Qt::CaseInsensitive)
           || plain.contains(QStringLiteral("Em breve"), Qt::CaseInsensitive);
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
          "Mandiant import hash — MD5 of ordered import DLL/function pairs; stable across packers that preserve the IAT." },
        { "File Ratio", "UI/file_ratio_meaning",
          "Ratio of PE logical size (headers + section raw data) to total file size; lower values suggest overlay or appended data." },
        { "Toolchain", "UI/toolchain_meaning",
          "Compiler/linker fingerprint inferred from the Rich Header (when present)." },
        { "Signed", "UI/signed_meaning",
          "Whether the file carries a digital signature (Authenticode). Signed files include a certificate table; unsigned files do not." },
        { "Entry Point", "UI/entry_point_meaning",
          "Where Windows starts running this program — the memory address (RVA) and the section that contains the first instructions." },
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

} // namespace

QString PEParserNew::relatedStructureFieldForInsight(const QString &fieldKey)
{
    if (fieldKey == QLatin1String("File Version") || fieldKey == QLatin1String("Product Version")
        || fieldKey == QLatin1String("Company Name") || fieldKey == QLatin1String("Product Name")
        || fieldKey == QLatin1String("Manifest UAC")) {
        return QStringLiteral("Resource Directory");
    }
    if (fieldKey == QLatin1String("PDB Path") || fieldKey == QLatin1String("PDB Raw")
        || fieldKey == QLatin1String("PDB GUID") || fieldKey == QLatin1String("PDB Age")) {
        return QStringLiteral("Debug Directory");
    }
    if (fieldKey == QLatin1String("Toolchain")) {
        return QStringLiteral("Rich Header");
    }
    return QString();
}

bool PEParserNew::fileInsightHasHexTarget(const QString &fieldKey) const
{
    const PEOverlayInfo overlay = m_dataModel.getOverlayInfo();
    const PEPdbInfo pdb = m_dataModel.getPdbInfo();
    const PEVersionInfo version = m_dataModel.getVersionInfo();

    if (fieldKey == QLatin1String("Overlay")) {
        return overlay.present && overlay.fileOffset > 0;
    }
    if (fieldKey == QLatin1String("File Entropy")) {
        return false;
    }
    if (fieldKey == QLatin1String("PDB Path")) {
        return pdb.present && pdb.pathByteSize > 0;
    }
    if (fieldKey == QLatin1String("PDB Raw")) {
        return pdb.present && pdb.codeViewSize > 0;
    }
    if (fieldKey == QLatin1String("PDB GUID")) {
        return pdb.present && !pdb.guid.isEmpty();
    }
    if (fieldKey == QLatin1String("PDB Age")) {
        return pdb.present && pdb.age > 0;
    }
    if (fieldKey == QLatin1String("File Version") || fieldKey == QLatin1String("Product Version")
        || fieldKey == QLatin1String("Company Name") || fieldKey == QLatin1String("Product Name")) {
        return version.present && version.versionResourceSize > 0;
    }
    if (fieldKey == QLatin1String("Manifest UAC")) {
        return version.manifestPresent;
    }
    return false;
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

QString PEParserNew::getFileInsightExplanation(const QString &fieldKey) const
{
    if (!isFileInsightJsonKey(fieldKey) || fieldKey == QLatin1String("File Insights")) {
        return QString();
    }

    const PEOverlayInfo overlay = m_dataModel.getOverlayInfo();
    const PEEntropySummary entropy = m_dataModel.getEntropySummary();
    const PEPdbInfo pdb = m_dataModel.getPdbInfo();
    const PEVersionInfo version = m_dataModel.getVersionInfo();
    const PEFileMetrics metrics = m_dataModel.getFileMetrics();

    QString currentValue;
    bool absent = false;
    QString tipKey;

    if (fieldKey == QLatin1String("Overlay")) {
        tipKey = QStringLiteral("UI/insight_tip_overlay");
        if (overlay.present && overlay.fileOffset > 0) {
            quint64 overlayBytes = overlay.size;
            if (overlayBytes == 0) {
                const qint64 tail = qMax(m_dataModel.getFileSize(), static_cast<qint64>(m_file.size()))
                                    - static_cast<qint64>(overlay.fileOffset);
                if (tail > 0) {
                    overlayBytes = static_cast<quint64>(tail);
                }
            }
            const quint32 overlaySize =
                static_cast<quint32>(qMin(overlayBytes, static_cast<quint64>(UINT32_MAX)));
            currentValue = QStringLiteral("%1 (%2)")
                               .arg(PEUtils::formatHexWidth(overlay.fileOffset, 8),
                                    PEUtils::formatHexWidth(overlaySize, 0));
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/overlay_none"));
        }
    } else if (fieldKey == QLatin1String("File Entropy")) {
        tipKey = QStringLiteral("UI/insight_tip_entropy");
        if (entropy.fileEntropyValid) {
            currentValue =
                QStringLiteral("%1 %2").arg(QString::number(entropy.fileEntropy, 'f', 2), LANG(QStringLiteral("UI/entropy_unit")));
        }
    } else if (fieldKey == QLatin1String("MD5")) {
        if (metrics.hashesValid) {
            currentValue = metrics.md5Hex;
        }
    } else if (fieldKey == QLatin1String("SHA256")) {
        if (metrics.hashesValid) {
            currentValue = metrics.sha256Hex;
        }
    } else if (fieldKey == QLatin1String("ImpHash")) {
        if (metrics.hashesValid && !metrics.imphashHex.isEmpty()) {
            currentValue = metrics.imphashHex;
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/imphash_none"));
        }
    } else if (fieldKey == QLatin1String("File Ratio")) {
        if (metrics.fileRatioValid) {
            QMap<QString, QString> ratioParams;
            ratioParams.insert(QStringLiteral("ratio"), QString::number(metrics.fileRatio * 100.0, 'f', 1));
            ratioParams.insert(QStringLiteral("pe_size"),
                               PEUtils::formatFileSize(static_cast<quint64>(metrics.peLogicalSize)));
            ratioParams.insert(QStringLiteral("file_size"),
                               PEUtils::formatFileSize(static_cast<quint64>(
                                   qMax(m_dataModel.getFileSize(), static_cast<qint64>(m_fileData.size())))));
            currentValue = LANG_PARAMS(QStringLiteral("UI/file_ratio_value"), ratioParams);
        }
    } else if (fieldKey == QLatin1String("Toolchain")) {
        tipKey = QStringLiteral("UI/insight_tip_toolchain");
        if (metrics.toolchainValid) {
            currentValue = metrics.toolchainSummary;
        } else if (m_dataModel.getAnalysisMetadata().richHeaderPresent) {
            currentValue = LANG(QStringLiteral("UI/toolchain_rich_unknown"));
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/toolchain_none"));
        }
    } else if (fieldKey == QLatin1String("Signed")) {
        if (metrics.authenticodePresent) {
            QMap<QString, QString> params;
            params.insert(QStringLiteral("size"), PEUtils::formatFileSize(metrics.certTableSize));
            if (metrics.authenticodeInfo.trustStatus == AuthenticodeTrustStatus::Valid) {
                currentValue = LANG_PARAMS(QStringLiteral("UI/signed_yes"), params);
                if (!metrics.authenticodePublisher.isEmpty()) {
                    QMap<QString, QString> publisherParams;
                    publisherParams.insert(QStringLiteral("publisher"), metrics.authenticodePublisher);
                    currentValue = LanguageManager::getInstance().getString(
                        QStringLiteral("UI/signed_publisher_format"),
                        publisherParams,
                        currentValue);
                }
            } else {
                currentValue = LANG_PARAMS(QStringLiteral("UI/signed_cert_data"), params);
            }
        } else {
            currentValue = LANG(QStringLiteral("UI/signed_no"));
        }
    } else if (fieldKey == QLatin1String("Entry Point")) {
        if (metrics.entryPointRva != 0) {
            currentValue = formatEntryPointSummary(metrics);
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/entry_point_none"));
        }
    } else if (fieldKey == QLatin1String("PDB Path")) {
        tipKey = QStringLiteral("UI/insight_tip_debug_dir");
        if (pdb.present && !pdb.path.isEmpty()) {
            currentValue = pdb.path;
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/pdb_none"));
        }
    } else if (fieldKey == QLatin1String("PDB Raw")) {
        tipKey = QStringLiteral("UI/insight_tip_debug_dir");
        if (pdb.present && pdb.codeViewSize > 0) {
            currentValue = formatCodeViewRawTreeValue(pdb);
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/pdb_none"));
        }
    } else if (fieldKey == QLatin1String("PDB GUID")) {
        tipKey = QStringLiteral("UI/insight_tip_debug_dir");
        if (pdb.present && !pdb.guid.isEmpty()) {
            currentValue = pdb.guid;
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/pdb_none"));
        }
    } else if (fieldKey == QLatin1String("PDB Age")) {
        tipKey = QStringLiteral("UI/insight_tip_debug_dir");
        if (pdb.present && pdb.age > 0) {
            currentValue = QString::number(pdb.age);
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/pdb_none"));
        }
    } else if (fieldKey == QLatin1String("File Version")) {
        tipKey = QStringLiteral("UI/insight_tip_resource_dir");
        if (version.present && !version.fileVersion.isEmpty()) {
            currentValue = version.fileVersion;
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/version_none"));
        }
    } else if (fieldKey == QLatin1String("Product Version")) {
        tipKey = QStringLiteral("UI/insight_tip_resource_dir");
        if (version.present && !version.productVersion.isEmpty()) {
            currentValue = version.productVersion;
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/version_none"));
        }
    } else if (fieldKey == QLatin1String("Company Name")) {
        tipKey = QStringLiteral("UI/insight_tip_resource_dir");
        if (version.present && !version.companyName.isEmpty()) {
            currentValue = version.companyName;
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/version_none"));
        }
    } else if (fieldKey == QLatin1String("Product Name")) {
        tipKey = QStringLiteral("UI/insight_tip_resource_dir");
        if (version.present && !version.productName.isEmpty()) {
            currentValue = version.productName;
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/version_none"));
        }
    } else if (fieldKey == QLatin1String("Manifest UAC")) {
        tipKey = QStringLiteral("UI/insight_tip_resource_dir");
        if (version.manifestPresent) {
            currentValue = version.manifestExecutionLevel.isEmpty()
                               ? LANG(QStringLiteral("UI/version_manifest_present"))
                               : version.manifestExecutionLevel;
        } else {
            absent = true;
            currentValue = LANG(QStringLiteral("UI/version_none"));
        }
    }

    QString html;
    html += QStringLiteral("<div style='font-family:\"Segoe UI\",Arial,sans-serif;font-size:11px;color:#222;line-height:1.55;'>");
    html += QStringLiteral("<div style='font-weight:600;font-size:12px;margin-bottom:10px;color:#111;'>%1</div>")
                .arg(fileInsightFieldLabel(fieldKey).toHtmlEscaped());

    if (absent) {
        html += QStringLiteral(
                    "<div style='margin:0 0 12px 0;padding:8px 10px;background:#fff8e6;border-left:3px solid "
                    "#f59e0b;border-radius:4px;color:#92400e;'>%1<br/><span style='color:#78716c;'>%2</span></div>")
                    .arg(currentValue.toHtmlEscaped(), LANG(QStringLiteral("UI/insight_absent_note")).toHtmlEscaped());
    } else if (!currentValue.isEmpty()) {
        if (fieldKey == QLatin1String("Signed")) {
            const PEAuthenticodeInfo &auth = metrics.authenticodeInfo;
            const bool trustValid = auth.trustStatus == AuthenticodeTrustStatus::Valid;
            const QString bg = trustValid ? QStringLiteral("#ecfdf5")
                                          : (metrics.authenticodePresent ? QStringLiteral("#fff1f2")
                                                                         : QStringLiteral("#fff8e6"));
            const QString border = trustValid ? QStringLiteral("#22c55e")
                                              : (metrics.authenticodePresent ? QStringLiteral("#ef4444")
                                                                             : QStringLiteral("#f59e0b"));
            const QString fg = trustValid ? QStringLiteral("#166534")
                                          : (metrics.authenticodePresent ? QStringLiteral("#991b1b")
                                                                         : QStringLiteral("#92400e"));
            html += QStringLiteral(
                        "<div style='margin:0 0 12px 0;padding:8px 10px;background:%1;border-left:3px solid "
                        "%2;border-radius:4px;color:%3;font-weight:600;'>%4</div>")
                        .arg(bg, border, fg, currentValue.toHtmlEscaped());
            html += QStringLiteral("<div style='margin:0 0 8px 0;color:#374151;'><b>%1:</b> %2</div>")
                        .arg(LANG(QStringLiteral("UI/signed_trust_label")).toHtmlEscaped(),
                             authenticodeTrustStatusLabel(auth.trustStatus).toHtmlEscaped());
            if (!auth.statusMessage.isEmpty()) {
                html += QStringLiteral("<div style='margin:0 0 8px 0;color:#555;'>%1</div>")
                            .arg(auth.statusMessage.toHtmlEscaped());
            }
            if (!auth.thumbprintSha256.isEmpty()) {
                html += QStringLiteral(
                            "<div style='margin:0 0 8px 0;font-family:Consolas,monospace;font-size:10px;"
                            "color:#374151;'><b>SHA256:</b> %1</div>")
                            .arg(auth.thumbprintSha256.toHtmlEscaped());
            }
            if (auth.notBefore.isValid() || auth.notAfter.isValid()) {
                html += QStringLiteral("<div style='margin:0 0 8px 0;color:#555;'>%1 — %2</div>")
                            .arg(auth.notBefore.isValid() ? auth.notBefore.toString(Qt::ISODate) : QStringLiteral("?"),
                                 auth.notAfter.isValid() ? auth.notAfter.toString(Qt::ISODate) : QStringLiteral("?"));
            }
            if (!auth.certificateSubjects.isEmpty()) {
                html += QStringLiteral("<div style='margin:8px 0 4px 0;font-weight:600;'>%1</div>")
                            .arg(LANG(QStringLiteral("UI/signed_chain_label")).toHtmlEscaped());
                html += QStringLiteral("<ul style='margin:0 0 12px 18px;padding:0;color:#444;'>");
                for (const QString &subject : auth.certificateSubjects) {
                    html += QStringLiteral("<li style='margin-bottom:3px;'>%1</li>")
                                .arg(subject.toHtmlEscaped());
                }
                html += QStringLiteral("</ul>");
            }
        } else if (fieldKey == QLatin1String("Entry Point") && !metrics.entryPointBytesHex.isEmpty()) {
            html += QStringLiteral("<div style='margin:0 0 8px 0;'><span style='color:#666;'>%1:</span> <b>%2</b></div>")
                        .arg(LANG(QStringLiteral("UI/insight_current_value")).toHtmlEscaped(),
                             currentValue.toHtmlEscaped());
            QMap<QString, QString> byteParams;
            byteParams.insert(QStringLiteral("bytes"), metrics.entryPointBytesHex);
            html += QStringLiteral(
                        "<div style='margin:0 0 12px 0;font-family:Consolas,monospace;font-size:10px;"
                        "color:#374151;'>%1</div>")
                        .arg(LANG_PARAMS(QStringLiteral("UI/entry_point_bytes_line"), byteParams).toHtmlEscaped());
            QByteArray epBytes;
            for (const QString &part : metrics.entryPointBytesHex.split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
                bool ok = false;
                const uint byte = part.toUInt(&ok, 16);
                if (ok) {
                    epBytes.append(static_cast<char>(byte));
                }
            }
            bool is64 = false;
            if (const IMAGE_OPTIONAL_HEADER *opt = m_dataModel.getOptionalHeader()) {
                is64 = opt->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            }
            const QStringList asmLines =
                PEEpDisasm::disassembleEntryPoint(is64, epBytes, PEEpDisasm::kDefaultMaxInstructions,
                                                  metrics.entryPointRva);
            if (!asmLines.isEmpty()) {
                QStringList escapedAsm;
                escapedAsm.reserve(asmLines.size());
                for (const QString &line : asmLines) {
                    escapedAsm.append(line.toHtmlEscaped());
                }
                html += QStringLiteral(
                            "<div style='margin:0 0 12px 0;font-family:Consolas,monospace;font-size:10px;"
                            "color:#1e40af;'>%1<br/>%2</div>"
                            "<div style='font-size:10px;color:#64748b;margin-top:4px;'>%3</div>")
                            .arg(uiStringWithFallback(QStringLiteral("UI/entry_point_disasm_title"),
                                                      QStringLiteral("Likely disassembly (best effort, not a full decoder):"))
                                    .toHtmlEscaped(),
                                 escapedAsm.join(QStringLiteral("<br/>")),
                                 uiStringWithFallback(QStringLiteral("UI/entry_point_disasm_note"),
                                                      QStringLiteral("These are hints for the first bytes only — use a "
                                                                     "disassembler for complete code."))
                                     .toHtmlEscaped());
            }
        } else {
            html += QStringLiteral("<div style='margin:0 0 12px 0;'><span style='color:#666;'>%1:</span> <b>%2</b></div>")
                        .arg(LANG(QStringLiteral("UI/insight_current_value")).toHtmlEscaped(),
                             currentValue.toHtmlEscaped());
        }
    }

    const QString body = insightMeaningText(fieldKey);
    if (!body.isEmpty()) {
        html += QStringLiteral("<div style='margin-bottom:12px;color:#333;'>%1</div>").arg(body.toHtmlEscaped());
    }

    if (!tipKey.isEmpty()) {
        const QString tip = LANG(tipKey);
        if (!tip.isEmpty()) {
            html += QStringLiteral(
                        "<div style='margin-top:8px;padding-top:8px;border-top:1px solid #eee;color:#555;"
                        "font-size:10px;'>%1</div>")
                        .arg(tip);
        }
    }

    html += QStringLiteral("</div>");
    return html;
}

namespace {

/** Last-resort English when INI has no entry (must match config/language_config.ini). */
QString defaultEnglishSectionTypeInfo(const QString &sectionTypeKey)
{
    static const QHash<QString, QString> kEn = {
        {QStringLiteral("section_info_text"), QStringLiteral("This section contains the executable code of the program.")},
        {QStringLiteral("section_info_data"), QStringLiteral("This section contains initialized data that can be read and written.")},
        {QStringLiteral("section_info_rdata"), QStringLiteral("This section contains read-only initialized data, typically constants and string literals.")},
        {QStringLiteral("section_info_rsrc"), QStringLiteral("This section contains resources such as icons, bitmaps, dialogs, and version information.")},
        {QStringLiteral("section_info_reloc"), QStringLiteral("This section contains relocation information for when the executable cannot be loaded at its preferred base address.")},
        {QStringLiteral("section_info_idata"), QStringLiteral("This section contains import information, listing DLLs and functions that the executable depends on.")},
        {QStringLiteral("section_info_edata"), QStringLiteral("This section contains export information, listing functions and data that this module exports.")},
        {QStringLiteral("section_info_tls"), QStringLiteral("This section stores Thread Local Storage (TLS) templates and callbacks used during per-thread initialization.")},
        {QStringLiteral("section_info_gfids"), QStringLiteral("This section stores Control Flow Guard (CFG) function IDs used by the loader/runtime for indirect-call validation.")},
        {QStringLiteral("section_info_pdata"), QStringLiteral("This section contains runtime function table entries used for exception unwinding (especially on x64/ARM).")},
        {QStringLiteral("section_info_xdata"), QStringLiteral("This section stores unwind metadata referenced by .pdata entries.")},
        {QStringLiteral("section_info_didat"), QStringLiteral("This section contains delay-load import tables used when DLLs are resolved on first use.")},
        {QStringLiteral("section_info_crt"), QStringLiteral("This section stores C/C++ runtime initializer and terminator arrays (global constructors/destructors).")},
        {QStringLiteral("section_info_cfg"), QStringLiteral("This section stores Control Flow Guard metadata and helper tables.")},
        {QStringLiteral("section_info_sxdata"), QStringLiteral("This section contains Safe Exception Handler / structured exception metadata for some toolchains.")},
        {QStringLiteral("section_info_debug"), QStringLiteral("This section stores debug directory and symbol-related metadata.")},
        {QStringLiteral("section_info_cormeta"), QStringLiteral("This section contains CLR/.NET metadata streams in managed images.")},
        {QStringLiteral("section_info_managed"), QStringLiteral("This section contains IL/managed runtime data used by .NET executables.")},
    };
    return kEn.value(sectionTypeKey);
}

/** English labels for data-directory rows (display == explanations.json keys). */
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

QString decodeClrImageFlags(quint32 flags)
{
    struct Bit {
        quint32 mask;
        const char *name;
    };
    static const Bit kBits[] = {
        {0x00000001u, "ILONLY"},
        {0x00000002u, "32BITREQUIRED"},
        {0x00000004u, "IL_LIBRARY"},
        {0x00000008u, "STRONGNAMESIGNED"},
        {0x00020000u, "TRACKDEBUGDATA"},
    };
    QStringList parts;
    for (const Bit &b : kBits) {
        if ((flags & b.mask) != 0) {
            parts << QString::fromLatin1(b.name);
        }
    }
    if (parts.isEmpty()) {
        return QString();
    }
    return parts.join(QStringLiteral(", "));
}

QString decodeGuardCfFlags(quint32 flags)
{
    if (flags == 0) {
        return QString();
    }
    struct Bit { quint32 mask; const char *name; };
    static const Bit kTable[] = {
        {0x00000100u, "CF_INSTRUMENTED"},
        {0x00000200u, "CFW_INSTRUMENTED"},
        {0x00000400u, "CF_FUNCTION_TABLE_PRESENT"},
        {0x00000800u, "SECURITY_COOKIE_UNUSED"},
        {0x00001000u, "PROTECT_DELAYLOAD_IAT"},
        {0x00002000u, "DELAYLOAD_IAT_IN_OWN_SECTION"},
        {0x00004000u, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"},
        {0x00008000u, "CF_ENABLE_EXPORT_SUPPRESSION"},
        {0x00010000u, "CF_LONGJUMP_TABLE_PRESENT"},
        {0x00020000u, "RF_INSTRUMENTED"},
        {0x00040000u, "RF_ENABLE"},
        {0x00080000u, "RF_STRICT"},
        {0x00100000u, "RETPOLINE_PRESENT"},
        {0x00400000u, "EH_CONTINUATION_TABLE_PRESENT"},
    };
    QStringList parts;
    quint32 known = 0;
    for (const Bit &b : kTable) {
        if (flags & b.mask) {
            parts << QString::fromLatin1(b.name);
            known |= b.mask;
        }
    }
    const quint32 rest = flags & ~known;
    if (rest != 0) {
        parts << QStringLiteral("0x%1").arg(rest, 0, 16);
    }
    return parts.join(QLatin1String(", "));
}

/** Green callout appended to JSON explanation: raw value + decoded flags for the opened PE. */
QString appendDllCharacteristicsThisImageHtml(const QString &baseHtml, quint16 dllChars)
{
    QString decoded = PEUtils::getDLLCharacteristics(dllChars);
    if (decoded.startsWith(QLatin1String("UI/"))) {
        decoded.clear();
    }
    constexpr quint16 kKnownMask = static_cast<quint16>(
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        | IMAGE_DLLCHARACTERISTICS_NO_ISOLATION | IMAGE_DLLCHARACTERISTICS_NO_SEH
        | IMAGE_DLLCHARACTERISTICS_NO_BIND | IMAGE_DLLCHARACTERISTICS_APPCONTAINER
        | IMAGE_DLLCHARACTERISTICS_WDM_DRIVER | IMAGE_DLLCHARACTERISTICS_GUARD_CF
        | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);
    const quint16 unknownBits = dllChars & static_cast<quint16>(~kKnownMask);

    LanguageManager &lm = LanguageManager::getInstance();
    auto ui = [&lm](const QString &key, const QString &fallback) -> QString {
        const QString s = lm.getString(key, fallback);
        return (s == key) ? fallback : s;
    };
    const QString title = ui(QStringLiteral("UI/explain_dll_this_image"), QStringLiteral("This image"));
    QString html = baseHtml;
    html += QStringLiteral("<div style=\"margin-top: 10px; margin-bottom: 8px; padding: 12px; background: #f0fdf4; border-left: 4px solid #16a34a; border-radius: 6px;\">");
    html += QStringLiteral("<div style=\"font-weight: 600; color: #065f46; margin-bottom: 6px;\">%1</div>").arg(title.toHtmlEscaped());
    html += QStringLiteral("<div style=\"font-family: monospace; color: #1f2937; margin-bottom: 6px;\">0x%1</div>").arg(dllChars, 4, 16, QChar('0'));
    if (!decoded.isEmpty()) {
        html += QStringLiteral("<div style=\"color: #334155; line-height: 1.5;\">%1</div>").arg(decoded.toHtmlEscaped());
    }
    if (unknownBits != 0u) {
        const QString unkLabel = ui(QStringLiteral("UI/explain_dll_unknown_bits"), QStringLiteral("Unknown or reserved bits:"));
        html += QStringLiteral("<div style=\"margin-top: 8px; color: #b45309;\"><span style=\"font-weight: 600;\">%1</span> <span style=\"font-family: monospace;\">0x%2</span></div>")
                     .arg(unkLabel.toHtmlEscaped(), QString::number(unknownBits, 16));
    }
    html += QStringLiteral("</div>");
    return html;
}

} // namespace

static_assert(sizeof(IMAGE_COR20_HEADER) == 72, "IMAGE_COR20_HEADER size mismatch");

PEParserNew::PEParserNew(QObject *parent)
    : QObject(parent)
    , m_isValid(false)
    , m_isParsing(false)
    , m_dataDirectoryParser(m_fileData)
{
}

PEParserNew::~PEParserNew()
{
    clear();
}

bool PEParserNew::loadFile(const QString &filePath)
{
    clear();
    
    m_file.setFileName(filePath);
    if (!m_file.open(QIODevice::ReadOnly)) {
        emit errorOccurred(LANG_PARAM("UI/error_file_open_generic", "filepath", filePath));
        return false;
    }
    
    m_dataModel.setFilePath(filePath);
    m_dataModel.setFileSize(m_file.size());
    
    if (m_file.size() > LARGE_FILE_THRESHOLD) {
        emit parsingProgress(5, LANG("UI/progress_large_file_detected"));
    } else {
        emit parsingProgress(5, LANG("UI/progress_file_loaded"));
    }

    // Always load the full image into memory so structure parsing and the hex view see every byte.
    m_fileData = m_file.readAll();
    m_file.close();
    
    // Parse DOS header
    if (!parseDOSHeader()) {
        return false;
    }
    
    emit parsingProgress(15, LANG("UI/progress_dos_header"));
    
    // Parse PE headers
    if (!parsePEHeaders()) {
        return false;
    }
    
    emit parsingProgress(25, LANG("UI/progress_pe_headers"));
    
    // Parse sections
    if (!parseSections()) {
        return false;
    }
    
    emit parsingProgress(35, LANG("UI/progress_sections"));
    
    // Parse data directories (NEW: Microsoft PE Format compliant)
    if (!parseDataDirectories()) {
        return false;
    }
    
    emit parsingProgress(50, LANG("UI/progress_data_directories"));

    PEAnalysis::analyzeIntoModel(m_fileData, m_dataModel, QFileInfo(m_file.fileName()).absoluteFilePath());
    emit parsingProgress(60, LANG("UI/progress_file_analysis"));
    clearFieldExplanationCaches();
    
    m_dataModel.setValid(true);
    m_isValid = true;
    
    // Parsing complete, but MainWindow still needs to update heavy UI widgets (tree/hex/tabs).
    // Leave headroom so 100% is only shown when the UI is actually ready.
    emit parsingProgress(85, LANG("UI/progress_complete"));
    emit parsingComplete(true);
    return true;
}

void PEParserNew::loadFileAsync(const QString &filePath)
{
    if (m_isParsing) {
        m_parsingFuture.waitForFinished();
    }
    
    m_isParsing = true;
    emit parsingProgress(0, LANG("UI/progress_async_start"));
    
    m_parsingFuture = QtConcurrent::run([this, filePath]() {
        QMutexLocker locker(&m_parsingMutex);
        
        emit parsingProgress(1, LANG("UI/progress_async_loading"));
        
        bool success = loadFile(filePath);
        m_isParsing = false;
        
        QMetaObject::invokeMethod(this, [this, success]() {
            if (success) {
                // Keep < 100 until MainWindow finishes post-parse UI updates.
                emit parsingProgress(90, LANG("UI/progress_async_complete"));
            } else {
                emit parsingProgress(100, LANG("UI/progress_async_failed"));
                // loadFile() does not emit parsingComplete(false) on early returns.
                emit parsingComplete(false);
            }
        }, Qt::QueuedConnection);
    });
}

void PEParserNew::clear()
{
    m_file.close();
    m_fileData.clear();
    m_dataModel.clear();
    m_optionalHeaderBuffer.clear();
    m_cachedSections.clear();
    m_cachedDosHeader = IMAGE_DOS_HEADER{};
    m_cachedFileHeader = IMAGE_FILE_HEADER{};
    m_isValid = false;
    m_isParsing = false;
    invalidateFieldOffsetLookup();
}

void PEParserNew::invalidateFieldOffsetLookup()
{
    m_fieldOffsetLookup.clear();
    m_fieldOffsetLookupValid = false;
}

void PEParserNew::ensureFieldOffsetLookup()
{
    if (m_fieldOffsetLookupValid) {
        return;
    }

    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    if (!dosHeader || !fileHeader || !optionalHeader) {
        m_fieldOffsetLookupValid = true;
        return;
    }

    QHash<QString, QPair<quint32, quint32>> &fieldOffsets = m_fieldOffsetLookup;

    fieldOffsets[QStringLiteral("e_magic")] = QPair<quint32, quint32>(0, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_cblp")] = QPair<quint32, quint32>(2, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_cp")] = QPair<quint32, quint32>(4, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_crlc")] = QPair<quint32, quint32>(6, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_cparhdr")] = QPair<quint32, quint32>(8, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_minalloc")] = QPair<quint32, quint32>(10, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_maxalloc")] = QPair<quint32, quint32>(12, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_ss")] = QPair<quint32, quint32>(14, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_sp")] = QPair<quint32, quint32>(16, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_csum")] = QPair<quint32, quint32>(18, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_ip")] = QPair<quint32, quint32>(20, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_cs")] = QPair<quint32, quint32>(22, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_lfarlc")] = QPair<quint32, quint32>(24, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_ovno")] = QPair<quint32, quint32>(26, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_res")] = QPair<quint32, quint32>(28, static_cast<quint32>(sizeof(quint16) * 4));
    fieldOffsets[QStringLiteral("e_oemid")] = QPair<quint32, quint32>(36, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_oeminfo")] = QPair<quint32, quint32>(38, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_res2")] = QPair<quint32, quint32>(40, static_cast<quint32>(sizeof(quint16) * 10));
    fieldOffsets[QStringLiteral("e_lfanew")] = QPair<quint32, quint32>(60, static_cast<quint32>(sizeof(quint32)));

    quint32 peHeaderOffset = dosHeader->e_lfanew;
    fieldOffsets[QStringLiteral("Signature")] = QPair<quint32, quint32>(peHeaderOffset, static_cast<quint32>(sizeof(quint32)));

    quint32 fileHeaderOffset = peHeaderOffset + sizeof(quint32);
    fieldOffsets[QStringLiteral("Machine")] = QPair<quint32, quint32>(fileHeaderOffset, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("NumberOfSections")] = QPair<quint32, quint32>(fileHeaderOffset + 2, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("TimeDateStamp")] = QPair<quint32, quint32>(fileHeaderOffset + 4, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("PointerToSymbolTable")] = QPair<quint32, quint32>(fileHeaderOffset + 8, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("NumberOfSymbols")] = QPair<quint32, quint32>(fileHeaderOffset + 12, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfOptionalHeader")] = QPair<quint32, quint32>(fileHeaderOffset + 16, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("Characteristics")] = QPair<quint32, quint32>(fileHeaderOffset + 18, static_cast<quint32>(sizeof(quint16)));

    quint32 optionalHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    fieldOffsets[QStringLiteral("Magic")] = QPair<quint32, quint32>(optionalHeaderOffset, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MajorLinkerVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 2, static_cast<quint32>(sizeof(quint8)));
    fieldOffsets[QStringLiteral("MinorLinkerVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 3, static_cast<quint32>(sizeof(quint8)));
    fieldOffsets[QStringLiteral("SizeOfCode")] = QPair<quint32, quint32>(optionalHeaderOffset + 4, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfInitializedData")] = QPair<quint32, quint32>(optionalHeaderOffset + 8, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfUninitializedData")] = QPair<quint32, quint32>(optionalHeaderOffset + 12, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("AddressOfEntryPoint")] = QPair<quint32, quint32>(optionalHeaderOffset + 16, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("BaseOfCode")] = QPair<quint32, quint32>(optionalHeaderOffset + 20, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("BaseOfData")] = QPair<quint32, quint32>(optionalHeaderOffset + 24, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("ImageBase")] = QPair<quint32, quint32>(optionalHeaderOffset + 28, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SectionAlignment")] = QPair<quint32, quint32>(optionalHeaderOffset + 32, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("FileAlignment")] = QPair<quint32, quint32>(optionalHeaderOffset + 36, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("MajorOperatingSystemVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 40, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MinorOperatingSystemVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 42, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MajorImageVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 44, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MinorImageVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 46, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MajorSubsystemVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 48, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MinorSubsystemVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 50, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("Win32VersionValue")] = QPair<quint32, quint32>(optionalHeaderOffset + 52, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfImage")] = QPair<quint32, quint32>(optionalHeaderOffset + 56, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfHeaders")] = QPair<quint32, quint32>(optionalHeaderOffset + 60, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("CheckSum")] = QPair<quint32, quint32>(optionalHeaderOffset + 64, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("Subsystem")] = QPair<quint32, quint32>(optionalHeaderOffset + 68, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("DllCharacteristics")] = QPair<quint32, quint32>(optionalHeaderOffset + 70, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("SizeOfStackReserve")] = QPair<quint32, quint32>(optionalHeaderOffset + 72, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfStackCommit")] = QPair<quint32, quint32>(optionalHeaderOffset + 76, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfHeapReserve")] = QPair<quint32, quint32>(optionalHeaderOffset + 80, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfHeapCommit")] = QPair<quint32, quint32>(optionalHeaderOffset + 84, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("LoaderFlags")] = QPair<quint32, quint32>(optionalHeaderOffset + 88, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("NumberOfRvaAndSizes")] = QPair<quint32, quint32>(optionalHeaderOffset + 92, static_cast<quint32>(sizeof(quint32)));

    fieldOffsets[QStringLiteral("DOS Header")] = QPair<quint32, quint32>(0, static_cast<quint32>(sizeof(IMAGE_DOS_HEADER)));
    fieldOffsets[QStringLiteral("PE Header")] = QPair<quint32, quint32>(peHeaderOffset, static_cast<quint32>(sizeof(quint32) + sizeof(IMAGE_FILE_HEADER)));
    fieldOffsets[QStringLiteral("File Header")] = QPair<quint32, quint32>(fileHeaderOffset, static_cast<quint32>(sizeof(IMAGE_FILE_HEADER)));
    fieldOffsets[QStringLiteral("Optional Header")] = QPair<quint32, quint32>(optionalHeaderOffset, static_cast<quint32>(fileHeader->SizeOfOptionalHeader));

    quint32 sectionsOffset = optionalHeaderOffset + fileHeader->SizeOfOptionalHeader;
    quint32 sectionsSize = fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    fieldOffsets[QStringLiteral("Sections")] = QPair<quint32, quint32>(sectionsOffset, sectionsSize);

    quint16 magic = optionalHeader->Magic;
    quint32 dataDirectoriesOffset;
    if (magic == 0x10b) {
        dataDirectoriesOffset = optionalHeaderOffset + 96;
    } else {
        dataDirectoriesOffset = optionalHeaderOffset + 112;
    }
    quint32 dataDirectoriesSize = 16 * sizeof(IMAGE_DATA_DIRECTORY);
    fieldOffsets[QStringLiteral("Data Directories")] = QPair<quint32, quint32>(dataDirectoriesOffset, dataDirectoriesSize);

    const PEOverlayInfo overlay = m_dataModel.getOverlayInfo();
    if (overlay.present && overlay.fileOffset > 0) {
        quint64 overlayBytes = overlay.size;
        if (overlayBytes == 0) {
            const qint64 tail = qMax(m_dataModel.getFileSize(), static_cast<qint64>(m_file.size()))
                                - static_cast<qint64>(overlay.fileOffset);
            if (tail > 0) {
                overlayBytes = static_cast<quint64>(tail);
            }
        }
        const quint32 overlaySize =
            static_cast<quint32>(qMin(overlayBytes, static_cast<quint64>(UINT32_MAX)));
        if (overlaySize > 0) {
            fieldOffsets[QStringLiteral("Overlay")] = QPair<quint32, quint32>(overlay.fileOffset, overlaySize);
            fieldOffsets[QStringLiteral("FILE_OVERLAY")] = fieldOffsets[QStringLiteral("Overlay")];
        }
    }

    const PEPdbInfo pdb = m_dataModel.getPdbInfo();
    if (pdb.present && pdb.codeViewFileOffset > 0 && pdb.codeViewSize > 0) {
        fieldOffsets[QStringLiteral("PDB Raw")] =
            QPair<quint32, quint32>(pdb.codeViewFileOffset, pdb.codeViewSize);
        if (pdb.pathByteSize > 0
            && static_cast<quint64>(pdb.pathFileOffset) + pdb.pathByteSize
                   <= static_cast<quint64>(m_fileData.size())) {
            fieldOffsets[QStringLiteral("PDB Path")] =
                QPair<quint32, quint32>(pdb.pathFileOffset, pdb.pathByteSize);
        }
        const bool isRsds = pdb.format.compare(QStringLiteral("RSDS"), Qt::CaseInsensitive) == 0;
        if (!pdb.guid.isEmpty() && isRsds) {
            fieldOffsets[QStringLiteral("PDB GUID")] = QPair<quint32, quint32>(pdb.codeViewFileOffset + 4, 16);
        }
        const quint32 ageOff = isRsds ? pdb.codeViewFileOffset + 20 : pdb.codeViewFileOffset + 8;
        fieldOffsets[QStringLiteral("PDB Age")] = QPair<quint32, quint32>(ageOff, 4);
    }

    const PEVersionInfo version = m_dataModel.getVersionInfo();
    if (version.present && version.versionResourceSize > 0
        && static_cast<quint64>(version.versionResourceOffset) + version.versionResourceSize
               <= static_cast<quint64>(m_fileData.size())) {
        const QPair<quint32, quint32> versionRange(version.versionResourceOffset, version.versionResourceSize);
        fieldOffsets[QStringLiteral("File Version")] = versionRange;
        fieldOffsets[QStringLiteral("Product Version")] = versionRange;
        fieldOffsets[QStringLiteral("Company Name")] = versionRange;
        fieldOffsets[QStringLiteral("Product Name")] = versionRange;
    }

    const QStringList &dirKeys = dataDirectoryFieldKeys();
    for (int i = 0; i < 16 && i < dirKeys.size(); ++i) {
        quint32 addressOffset = dataDirectoriesOffset + (i * 8);
        quint32 sizeOffset = dataDirectoriesOffset + (i * 8) + 4;
        const QString &k = dirKeys.at(i);
        fieldOffsets[k] = QPair<quint32, quint32>(addressOffset, 8);
        fieldOffsets[k + QStringLiteral(" Address")] = QPair<quint32, quint32>(addressOffset, 4);
        fieldOffsets[k + QStringLiteral(" Size")] = QPair<quint32, quint32>(sizeOffset, 4);
    }

    m_fieldOffsetLookupValid = true;
}

bool PEParserNew::isValid() const
{
    return m_isValid;
}

bool PEParserNew::isParsing() const
{
    return m_isParsing;
}

QString PEParserNew::getFilePath() const
{
    return m_dataModel.getFilePath();
}



const PEDataModel& PEParserNew::getDataModel() const
{
    return m_dataModel;
}

const QByteArray& PEParserNew::getFileData() const
{
    return m_fileData;
}

void PEParserNew::cancelParsing()
{
    if (m_isParsing) {
        m_parsingFuture.waitForFinished();
        m_isParsing = false;
    }
}

void PEParserNew::onAsyncParsingComplete()
{
    // This slot is called when async parsing completes
}

// Core parsing methods (Microsoft PE Format compliant)
bool PEParserNew::parseDOSHeader()
{
    if (m_fileData.size() < sizeof(IMAGE_DOS_HEADER)) {
        emit errorOccurred(LANG("UI/error_file_too_small"));
        return false;
    }
    
    const IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_fileData.constData());
    
    // Validate DOS magic number
    if (!PEUtils::isValidDOSMagic(dosHeader->e_magic)) {
        emit errorOccurred(LANG("UI/error_invalid_dos"));
        return false;
    }
    
    // Check if PE header exists
    if (dosHeader->e_lfanew >= m_fileData.size() || 
        dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER)) {
        emit errorOccurred(LANG("UI/error_invalid_pe_offset"));
        return false;
    }
    
    m_cachedDosHeader = *dosHeader;
    m_dataModel.setDOSHeader(&m_cachedDosHeader);
    return true;
}

bool PEParserNew::parsePEHeaders()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    if (!dosHeader) return false;
    
    quint32 peOffset = dosHeader->e_lfanew;
    
    // Parse PE signature
    if (peOffset + sizeof(quint32) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_pe_signature_beyond"));
        return false;
    }
    
    quint32 peSignature = *reinterpret_cast<const quint32*>(m_fileData.constData() + peOffset);
    if (!PEUtils::isValidPESignature(peSignature)) {
        emit errorOccurred(LANG("UI/error_invalid_pe_signature"));
        return false;
    }
    
    // Parse file header (immediately after the PE signature)
    quint32 fileHeaderOffset = peOffset + sizeof(quint32);
    if (fileHeaderOffset + sizeof(IMAGE_FILE_HEADER) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_pe_header_beyond"));
        return false;
    }
    
    const IMAGE_FILE_HEADER *fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_fileData.constData() + fileHeaderOffset
    );
    m_cachedFileHeader = *fileHeader;
    m_dataModel.setFileHeader(&m_cachedFileHeader);
    
    // Parse optional header
    quint32 optionalHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeaderOffset + fileHeader->SizeOfOptionalHeader > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_optional_header_beyond"));
        return false;
    }
    
    m_optionalHeaderBuffer.resize(static_cast<int>(fileHeader->SizeOfOptionalHeader));
    memcpy(m_optionalHeaderBuffer.data(),
           m_fileData.constData() + optionalHeaderOffset,
           static_cast<size_t>(fileHeader->SizeOfOptionalHeader));

    const IMAGE_OPTIONAL_HEADER *optionalHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER*>(
        m_optionalHeaderBuffer.constData()
    );

    if (!PEUtils::isValidOptionalHeaderMagic(optionalHeader->Magic)) {
        qWarning() << "Unexpected optional header magic" << QString::number(optionalHeader->Magic, 16)
                   << "at offset" << QString("0x%1").arg(optionalHeaderOffset, 0, 16);
        emit errorOccurred(LANG("UI/error_invalid_optional_magic"));
        return false;
    }

    m_dataModel.setOptionalHeader(optionalHeader);
    return true;
}

bool PEParserNew::parseSections()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return false;
    }
    
    // Calculate section table offset (PE signature + file header + optional header)
    quint32 sectionTableOffset = dosHeader->e_lfanew
                               + sizeof(quint32) // PE signature
                               + sizeof(IMAGE_FILE_HEADER)
                               + fileHeader->SizeOfOptionalHeader;
    
    if (sectionTableOffset + (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_section_table_beyond"));
        return false;
    }
    
    // Copy section headers: QList stores pointers — must not point into m_fileData (QByteArray may detach
    // when shared, e.g. with HexViewer), which would invalidate those pointers.
    m_cachedSections.clear();
    const quint16 sectionCount = fileHeader->NumberOfSections;
    m_cachedSections.reserve(sectionCount);
    for (quint16 i = 0; i < sectionCount; ++i) {
        const IMAGE_SECTION_HEADER *section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            m_fileData.constData() + sectionTableOffset + (i * sizeof(IMAGE_SECTION_HEADER))
        );
        m_cachedSections.push_back(*section);
        m_dataModel.addSection(&m_cachedSections.last());
    }
    
    return true;
}

bool PEParserNew::parseDataDirectories()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return false;
    }
    
    // Calculate the start of the data directories inside the optional header
    quint32 optionalHeaderOffset = dosHeader->e_lfanew
                                + sizeof(quint32) // PE signature
                                + sizeof(IMAGE_FILE_HEADER);
    
    quint16 magic = optionalHeader->Magic;
    quint32 numberOfRvaAndSizesOffset = (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 92 : 108; // 0x5C / 0x6C
    quint32 dataDirectoryOffset = optionalHeaderOffset + numberOfRvaAndSizesOffset + sizeof(quint32);
    
    // Use the specialized data directory parser
    return m_dataDirectoryParser.parseDataDirectories(optionalHeader, dataDirectoryOffset, m_dataModel);
}

quint32 PEParserNew::rvaToFileOffset(quint32 rva)
{
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_dataModel.getSections();
    
    // Find the section that contains this RVA
    for (const IMAGE_SECTION_HEADER *section : sections) {
        quint32 sectionStart = section->VirtualAddress;
        quint32 sectionSize = qMax(section->getVirtualSize(), section->SizeOfRawData);
        quint32 sectionEnd = sectionStart + sectionSize;
        
        if (rva >= sectionStart && rva < sectionEnd) {
            // Calculate file offset
            quint32 offsetInSection = rva - sectionStart;
            return section->PointerToRawData + offsetInSection;
        }
    }
    
    return 0;
}

bool PEParserNew::isLargeFile() const
{
    return m_dataModel.getFileSize() > LARGE_FILE_THRESHOLD;
}

bool PEParserNew::isVeryLargeFile() const
{
    return m_dataModel.getFileSize() > VERY_LARGE_FILE_THRESHOLD;
}

// Field explanation and offset methods (for UI compatibility)
QString PEParserNew::getFieldExplanation(const QString &fieldName)
{
    // Get current language from language manager
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();

    FieldExplanationCaches &fec = fieldExplanationCaches();

    // Load explanations from the language-specific JSON file (resolve path once per language per cache generation)
    QString explanationsPath;
    if (!fec.explanationsPathByLanguage.contains(currentLanguage)) {
        const QString fileName = (currentLanguage == QStringLiteral("pt")) ? QStringLiteral("explanations_pt.json")
                                                                           : QStringLiteral("explanations.json");
        fec.explanationsPathByLanguage.insert(currentLanguage, findConfigFile(fileName));
    }
    explanationsPath = fec.explanationsPathByLanguage.value(currentLanguage);
    QHash<QString, QString> &explanationHtmlCache = fec.explanationHtmlCache;
    QHash<QString, QJsonObject> &languageJsonCache = fec.languageJsonCache;
    QHash<QString, QDateTime> &languageJsonMtime = fec.languageJsonMtime;

    // Include optional-header value in cache key for fields whose explanation depends on the loaded image
    QString cacheFieldKey = fieldName;
    if (fieldName == QStringLiteral("DllCharacteristics")) {
        const IMAGE_OPTIONAL_HEADER *optHdr = m_dataModel.getOptionalHeader();
        if (optHdr) {
            cacheFieldKey += QStringLiteral("|0x") + QString::number(optHdr->DllCharacteristics, 16);
        }
    }
    const QString htmlCacheKey = explanationsPath + QStringLiteral("|") + currentLanguage + QStringLiteral("|") + cacheFieldKey;
    if (explanationHtmlCache.contains(htmlCacheKey)) {
        return explanationHtmlCache.value(htmlCacheKey);
    }

    auto cacheAndReturn = [&](const QString &value) -> QString {
        if (!isFieldExplanationPlaceholder(fieldName, value)) {
            explanationHtmlCache.insert(htmlCacheKey, value);
        }
        return value;
    };

    const QString langCacheKey = explanationsPath + QStringLiteral("|") + currentLanguage;
    QFileInfo explainInfo(explanationsPath);
    const QDateTime currentMtime = explainInfo.exists() ? explainInfo.lastModified() : QDateTime();
    if (!languageJsonCache.contains(langCacheKey) ||
        languageJsonMtime.value(langCacheKey) != currentMtime) {
        QFile explanationsFile(explanationsPath);
        if (explanationsFile.open(QIODevice::ReadOnly)) {
            QJsonDocument doc = QJsonDocument::fromJson(explanationsFile.readAll());
            QJsonObject root = doc.object();
            const QString langKey = resolveExplanationsLanguageKey(root, currentLanguage);
            if (!langKey.isEmpty()) {
                languageJsonCache.insert(langCacheKey, root[langKey].toObject());
                languageJsonMtime.insert(langCacheKey, currentMtime);
            } else {
                languageJsonCache.remove(langCacheKey);
                languageJsonMtime.remove(langCacheKey);
            }
        }
    }

    if (languageJsonCache.contains(langCacheKey)) {
        QJsonObject languageObj = languageJsonCache.value(langCacheKey);
            
            // Handle section names dynamically (e.g., "Section 1: .text", "Section 2: .data")
            if (fieldName.startsWith("Section ")) {
                // Extract section name if possible
                QString sectionInfo = fieldName;
                QString sectionName;
                if (fieldName.contains(QStringLiteral(": "))) {
                    sectionName = fieldName.split(QStringLiteral(": ")).last();
                }
                sectionName.remove(QChar(0));
                sectionName = sectionName.trimmed();

                // Try to get generic "Section" explanation
                if (languageObj.contains("Section")) {
                    QJsonObject sectionObj = languageObj["Section"].toObject();
                    QString description = sectionObj["description"].toString();
                    QString purpose = sectionObj["purpose"].toString();
                    QString note = sectionObj["note"].toString();
                    QString securityNotes = sectionObj["security_notes"].toString();
                    
                    // Format the explanation with section-specific information
                    QString explanation;
                    explanation += QString("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>").arg(description);
                    
                    if (!sectionName.isEmpty() && sectionName != "0x") {
                        // Add section-specific information
                        QString sectionTypeInfo = "";
                        QString sectionTypeKey = "";
                        const QString sectionNameNorm = sectionName.trimmed().toLower();
                        if (sectionNameNorm == ".text" || sectionNameNorm == "_text") {
                            sectionTypeKey = "section_info_text";
                        } else if (sectionNameNorm == ".data" || sectionNameNorm == "_data") {
                            sectionTypeKey = "section_info_data";
                        } else if (sectionNameNorm == ".rdata" || sectionNameNorm == "_rdata" ||
                                   sectionNameNorm == "rdata" || sectionNameNorm == "._rdata") {
                            sectionTypeKey = "section_info_rdata";
                        } else if (sectionNameNorm == ".rsrc" || sectionNameNorm == "_rsrc") {
                            sectionTypeKey = "section_info_rsrc";
                        } else if (sectionNameNorm == ".reloc" || sectionNameNorm == "_reloc") {
                            sectionTypeKey = "section_info_reloc";
                        } else if (sectionNameNorm == ".idata" || sectionNameNorm == "_idata") {
                            sectionTypeKey = "section_info_idata";
                        } else if (sectionNameNorm == ".edata" || sectionNameNorm == "_edata") {
                            sectionTypeKey = "section_info_edata";
                        } else if (sectionNameNorm == ".tls" || sectionNameNorm == "_tls" ||
                                   sectionNameNorm.startsWith(".tls$") || sectionNameNorm.startsWith("_tls$")) {
                            sectionTypeKey = "section_info_tls";
                        } else if (sectionNameNorm == ".gfids" || sectionNameNorm == "_gfids") {
                            sectionTypeKey = "section_info_gfids";
                        } else if (sectionNameNorm == ".pdata" || sectionNameNorm == "_pdata") {
                            sectionTypeKey = "section_info_pdata";
                        } else if (sectionNameNorm == ".xdata" || sectionNameNorm == "_xdata") {
                            sectionTypeKey = "section_info_xdata";
                        } else if (sectionNameNorm == ".didat" || sectionNameNorm == "_didat") {
                            sectionTypeKey = "section_info_didat";
                        } else if (sectionNameNorm == ".crt" || sectionNameNorm == "_crt" ||
                                   sectionNameNorm.startsWith(".crt$") || sectionNameNorm.startsWith("_crt$")) {
                            sectionTypeKey = "section_info_crt";
                        } else if (sectionNameNorm == ".00cfg" || sectionNameNorm == ".cfg" ||
                                   sectionNameNorm == "_cfg") {
                            sectionTypeKey = "section_info_cfg";
                        } else if (sectionNameNorm == ".sxdata" || sectionNameNorm == "_sxdata") {
                            sectionTypeKey = "section_info_sxdata";
                        } else if (sectionNameNorm == ".debug" || sectionNameNorm == "_debug") {
                            sectionTypeKey = "section_info_debug";
                        } else if (sectionNameNorm == ".cormeta" || sectionNameNorm == "_cormeta") {
                            sectionTypeKey = "section_info_cormeta";
                        } else if (sectionNameNorm == ".managed" || sectionNameNorm == "_managed") {
                            sectionTypeKey = "section_info_managed";
                        }
                        
                        if (!sectionTypeKey.isEmpty()) {
                            LanguageManager &lm = LanguageManager::getInstance();
                            // getString(key, "") returns the key when missing — never use that for body text.
                            sectionTypeInfo = lm.getIniString(sectionTypeKey);
                            if (sectionTypeInfo.isEmpty()) {
                                sectionTypeInfo = lm.getIniString(QStringLiteral("UI/") + sectionTypeKey);
                            }
                            if (sectionTypeInfo.isEmpty()) {
                                sectionTypeInfo = defaultEnglishSectionTypeInfo(sectionTypeKey);
                            }
                        }
                        
                        if (!sectionTypeInfo.isEmpty()) {
                            explanation += QString("<div style='margin-bottom: 8px; padding: 8px; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 4px;'><b style='color: #1e40af;'>Section: %1</b><br>%2</div>").arg(sectionName, sectionTypeInfo);
                        }
                    }
                    
                    if (!purpose.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #1d4ed8;'>Purpose:</b> %1</div>").arg(purpose);
                    }
                    
                    if (!note.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7c3aed;'>Note:</b> %1</div>").arg(note);
                    }
                    
                    if (!securityNotes.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7f1d1d;'>Security Notes:</b> %1</div>").arg(securityNotes);
                    }
                    
                    return cacheAndReturn(explanation);
                }
            }
            
            // Check for exact field name match
            if (languageObj.contains(fieldName)) {
                QJsonObject fieldObj = languageObj[fieldName].toObject();
                QString description = fieldObj["description"].toString();
                QString purpose = fieldObj["purpose"].toString();
                QString securityNotes = fieldObj["security_notes"].toString();
                QString value = fieldObj["value"].toString();
                QString note = fieldObj["note"].toString();
                QString commonNames = fieldObj["common_names"].toString();
                
                // Format the explanation with HTML for better presentation
                QString explanation;
                
                // Main description
                explanation += QString("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>").arg(description);
                
                // Value field (if exists)
                if (!value.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #059669;'>Value:</b> <span style='font-family: monospace; background: #f3f4f6; padding: 2px 6px; border-radius: 4px;'>%1</span></div>").arg(value);
                }
                
                // Purpose field
                if (!purpose.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #1d4ed8;'>Purpose:</b> %1</div>").arg(purpose);
                }
                
                // Note field (if exists)
                if (!note.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7c3aed;'>Note:</b> %1</div>").arg(note);
                }
                
                // Common names field (if exists)
                if (!commonNames.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #dc2626;'>Common Names:</b> <span style='font-family: monospace; background: #fef2f2; padding: 2px 6px; border-radius: 4px; color: #991b1b;'>%1</span></div>").arg(commonNames);
                }
                
                // Security notes - bold and dark red
                if (!securityNotes.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7f1d1d;'>Security Notes:</b> %1</div>").arg(securityNotes);
                }

                if (fieldName == QStringLiteral("DllCharacteristics")) {
                    const IMAGE_OPTIONAL_HEADER *optExplain = m_dataModel.getOptionalHeader();
                    if (optExplain) {
                        explanation = appendDllCharacteristicsThisImageHtml(explanation, optExplain->DllCharacteristics);
                    }
                }

                return cacheAndReturn(explanation);
            }

            // Alias common tree container names to explanation keys.
            // This avoids fallback placeholder text when UI labels differ slightly
            // from JSON keys (e.g., "File Header" vs "PE Header").
            const QMap<QString, QString> explanationAliases = {
                {QStringLiteral("File Header"), QStringLiteral("PE Header")},
                {QStringLiteral("Section Headers"), QStringLiteral("Sections")},
                // Legacy JSON key used lowercase "numbers"; tree field is NumberOfLineNumbers (COFF)
                {QStringLiteral("NumberOfLineNumbers"), QStringLiteral("NumberOfLinenumbers")}
            };
            const QString aliasKey = explanationAliases.value(fieldName);
            if (!aliasKey.isEmpty() && languageObj.contains(aliasKey)) {
                QJsonObject fieldObj = languageObj[aliasKey].toObject();
                QString description = fieldObj["description"].toString();
                QString purpose = fieldObj["purpose"].toString();
                QString securityNotes = fieldObj["security_notes"].toString();
                QString note = fieldObj["note"].toString();

                QString explanation;
                explanation += QString("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>").arg(description);
                if (!purpose.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #1d4ed8;'>Purpose:</b> %1</div>").arg(purpose);
                }
                if (!note.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7c3aed;'>Note:</b> %1</div>").arg(note);
                }
                if (!securityNotes.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7f1d1d;'>Security Notes:</b> %1</div>").arg(securityNotes);
                }
                return cacheAndReturn(explanation);
            }
    }
    
    if (isFileInsightJsonKey(fieldName)) {
        const QString insightHtml = insightExplanationHtml(fieldName);
        if (!insightHtml.isEmpty()) {
            return insightHtml;
        }
    }

    // Do not cache misses — a later config deploy or language switch should recover without reload.
    QString explanation =
        QStringLiteral("<div style='margin-bottom: 8px; line-height: 1.6; color: #4b5563;'>%1</div>")
            .arg(LANG_PARAM(QStringLiteral("UI/field_explanation_unavailable"),
                            QStringLiteral("fieldname"), fieldName));
    const QString staticMeaning = getFieldMeaning(fieldName, QStringLiteral("-"));
    if (!staticMeaning.isEmpty()) {
        explanation += QStringLiteral("<div style='margin-bottom: 8px;'><b>%1:</b> %2</div>")
                           .arg(LANG(QStringLiteral("UI/field_explanation_value_hint")), staticMeaning);
    }
    return explanation;
}

void PEParserNew::clearFieldExplanationCaches()
{
    clearFieldExplanationCachesInternal();
}

QPair<quint32, quint32> PEParserNew::getFieldOffset(const QString &fieldName)
{
    if (fieldName == QLatin1String("e_magic")) {
        return QPair<quint32, quint32>(0, static_cast<quint32>(sizeof(quint16)));
    }
    if (fieldName == QLatin1String("DOS_STUB")) {
        return QPair<quint32, quint32>(0x40, 0x40);
    }

    if (fieldName == QLatin1String("VirtualAddress") || fieldName == QLatin1String("SizeOfRawData")
        || fieldName == QLatin1String("PointerToRawData") || fieldName == QLatin1String("PointerToRelocations")
        || fieldName == QLatin1String("PointerToLineNumbers") || fieldName == QLatin1String("NumberOfRelocations")
        || fieldName == QLatin1String("NumberOfLineNumbers") || fieldName == QLatin1String("Characteristics")) {
        return QPair<quint32, quint32>(0, 0);
    }

    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return QPair<quint32, quint32>(0, 0);
    }

    ensureFieldOffsetLookup();
    const auto it = m_fieldOffsetLookup.constFind(fieldName);
    if (it != m_fieldOffsetLookup.constEnd()) {
        return it.value();
    }
    return QPair<quint32, quint32>(0, 0);
}

void PEParserNew::setLanguage(const QString &language)
{
    // Set the language for the language manager
    LanguageManager::getInstance().setLanguage(language);
    
    // Emit signal to notify UI of language change
    emit languageChanged(language);
}


QList<QTreeWidgetItem*> PEParserNew::getPEStructureTree()
{
    return PEUIPresenter(this).buildStructureTree();
}

QTreeWidgetItem *PEParserNew::buildFileInsightsItem()
{
    return PEUIPresenter(this).buildFileInsightsOverview();
}




QString PEParserNew::getFieldMeaning(const QString &fieldName, const QString &value)
{
    if (isFileInsightJsonKey(fieldName)) {
        const QString insight = insightMeaningText(fieldName);
        if (!insight.isEmpty()) {
            return insight;
        }
    }

    // Blob / non-scalar regions: meaning does not depend on the Value column text
    if (fieldName == QStringLiteral("DOS_STUB")) {
        return QStringLiteral("MS-DOS 16-bit stub program (8086 real-mode machine code)");
    }

    // Handle empty values
    if (value.isEmpty()) {
        return "";
    }

    // Machine field - convert to architecture name
    if (fieldName == "Machine") {
        bool ok;
        quint16 machine = value.toUShort(&ok, 16);
        if (ok) {
            return PEUtils::getMachineType(machine);
        }
    }
    
    // TimeDateStamp - convert to date/time (optional header and load-config share this name pattern)
    if (fieldName == QStringLiteral("TimeDateStamp") || fieldName.endsWith(QStringLiteral("TimeDateStamp"))) {
        bool ok;
        quint32 timestamp = value.toULong(&ok, 16);
        if (ok && timestamp != 0) {
            QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
            return dateTime.toString("dddd, dd.MM.yyyy HH:mm:ss UTC");
        }
    }

    if (fieldName == QStringLiteral("LoadCfg GuardFlags")) {
        bool ok;
        quint32 gf = value.toULong(&ok, 16);
        if (ok) {
            QString decoded = decodeGuardCfFlags(gf);
            if (!decoded.isEmpty()) {
                return decoded;
            }
        }
    }

    if (fieldName == QStringLiteral("CLR Flags")) {
        bool ok;
        quint32 cf = value.toULong(&ok, 16);
        if (ok) {
            QString decoded = decodeClrImageFlags(cf);
            if (!decoded.isEmpty()) {
                return decoded;
            }
        }
    }

    if (fieldName == QStringLiteral("Exc RuntimeFunctionCount")) {
        bool ok;
        quint32 n = value.toULong(&ok, 10);
        if (ok && n > 0) {
            return QStringLiteral("%1 × RUNTIME_FUNCTION (12 bytes each on x64)").arg(n);
        }
    }
    
    // Characteristics - decode flags (can be File Header or Section Header)
    if (fieldName == "Characteristics") {
        bool ok;
        // Try parsing as 16-bit first (File Header Characteristics)
        quint16 chars16 = value.toUShort(&ok, 16);
        if (ok) {
            // File characteristics are typically small values (0x0001-0xFFFF)
            // Section characteristics are typically larger (0x00000020-0xE0000000)
            // If value fits in 16-bit and is reasonable for file chars, use file characteristics
            if (chars16 <= 0xFFFF && chars16 != 0) {
                QString fileChars = PEUtils::getFileCharacteristics(chars16);
                // Check if we got meaningful flags (not just "None")
                if (!fileChars.isEmpty() && fileChars != LANG("UI/section_char_none")) {
                    return fileChars;
                }
            }
        }
        
        // Otherwise try section characteristics (32-bit)
        quint32 chars32 = value.toULong(&ok, 16);
        if (ok) {
            QString sectionChars = PEUtils::getSectionCharacteristics(chars32);
            if (!sectionChars.isEmpty()) {
                return sectionChars;
            }
        }
    }
    
    // DllCharacteristics - decode flags
    if (fieldName == "DllCharacteristics") {
        bool ok;
        quint16 chars = value.toUShort(&ok, 16);
        if (ok) {
            QString dllChars = PEUtils::getDLLCharacteristics(chars);
            // If translation failed and we got raw keys, return empty to avoid showing broken text
            if (dllChars.startsWith("UI/")) {
                return ""; // Translation keys not found, return empty
            }
            return dllChars;
        }
    }
    
    // Subsystem - convert to subsystem name
    if (fieldName == "Subsystem") {
        bool ok;
        quint16 subsystem = value.toUShort(&ok, 10);
        if (ok) {
            return PEUtils::getSubsystem(subsystem);
        }
    }
    
    // Magic - PE32 or PE32+
    if (fieldName == "Magic") {
        bool ok;
        quint16 magic = value.toUShort(&ok, 16);
        if (ok) {
            if (magic == 0x10b) return "PE32 (32-bit)";
            if (magic == 0x20b) return "PE32+ (64-bit)";
            return QString("Unknown (0x%1)").arg(magic, 4, 16, QChar('0'));
        }
    }
    
    // e_magic - DOS signature
    if (fieldName == "e_magic") {
        bool ok;
        quint16 magic = value.toUShort(&ok, 16);
        if (ok && magic == 0x5a4d) {
            return "MZ (DOS signature)";
        }
    }
    
    // Signature - PE signature
    if (fieldName == "Signature") {
        bool ok;
        quint32 signature = value.toULong(&ok, 16);
        if (ok && signature == 0x00004550) {
            return "PE\\0\\0 (PE signature)";
        }
    }
    
    // NumberOfSections - just show count
    if (fieldName == "NumberOfSections") {
        return QString("%1 section(s)").arg(value);
    }
    
    // SizeOfOptionalHeader - show decimal value
    if (fieldName == "SizeOfOptionalHeader") {
        bool ok;
        quint16 size = value.toUShort(&ok, 10);
        if (ok) {
            return QString("%1 bytes (0x%2)").arg(size).arg(size, 0, 16);
        }
    }
    
    // PointerToSymbolTable - show if zero or not
    if (fieldName == "PointerToSymbolTable") {
        bool ok;
        quint32 ptr = value.toULong(&ok, 16);
        if (ok) {
            if (ptr == 0) {
                return "No symbol table";
            }
            return QString("RVA: 0x%1").arg(ptr, 8, 16, QChar('0'));
        }
    }
    
    // NumberOfSymbols - show count
    if (fieldName == "NumberOfSymbols") {
        bool ok;
        quint32 count = value.toULong(&ok, 10);
        if (ok) {
            if (count == 0) {
                return "No symbols";
            }
            return QString("%1 symbol(s)").arg(count);
        }
    }
    
    // Rich Header fields
    if (fieldName == "RichSignature") {
        bool ok;
        quint32 sig = value.toULong(&ok, 16);
        if (ok) {
            // Check if it's "DanS" when XORed (we'd need the XOR key, but for display we show it's the signature)
            return "DanS signature (XORed)";
        }
    }
    
    if (fieldName == "RichCount") {
        bool ok;
        quint32 count = value.toULong(&ok, 10);
        if (ok) {
            return QString("%1 entry/entries").arg(count);
        }
    }
    
    if (isFileInsightJsonKey(fieldName)) {
        return QString();
    }

    return QString();
}


QString PEParserNew::findConfigFile(const QString &fileName) const
{
    QStringList possibleConfigPaths;
    
    // 1. Try relative to executable (for deployed builds) - PRIORITY 1
    QString appDir = QCoreApplication::applicationDirPath();
    possibleConfigPaths << QDir(appDir).absoluteFilePath("config/" + fileName);
    
    // 2. Try current working directory - PRIORITY 2
    possibleConfigPaths << QDir::currentPath() + "/config/" + fileName;
    
    // 3. Try relative to executable but go up to project root (for development builds) - PRIORITY 3
    QDir appDirObj(appDir);
    if (appDirObj.cdUp() && appDirObj.cdUp() && appDirObj.cdUp()) {
        possibleConfigPaths << appDirObj.absoluteFilePath("config/" + fileName);
    }
    
    // 4. Try source directory (for development builds) - PRIORITY 4
    possibleConfigPaths << QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../../../config/" + fileName);
    
    qDebug() << "Searching for config file:" << fileName;
    qDebug() << "Possible paths (in priority order):" << possibleConfigPaths;
    
    // Find the first valid config file
    for (const QString &path : possibleConfigPaths) {
        if (QFile::exists(path)) {
            qDebug() << "Found config file at:" << path;
            return path;
        }
    }
    
    qWarning() << "Config file not found in any of these locations:" << possibleConfigPaths;
    return QString();
}
