#include "pe_file_insights.h"
#include "pe_authenticode.h"
#include "pe_ep_disasm.h"
#include "pe_structures.h"
#include "pe_tree_insight_helpers.h"
#include "pe_utils.h"
#include "language_manager.h"
#include <QtGlobal>

namespace PEFileInsights {

using namespace PeTreeInsight;

QString relatedStructureFieldForInsight(const QString &fieldKey)
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

bool fileInsightHasHexTarget(const QString &fieldKey, const PEDataModel &model)
{
    const PEOverlayInfo overlay = model.getOverlayInfo();
    const PEPdbInfo pdb = model.getPdbInfo();
    const PEVersionInfo version = model.getVersionInfo();

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

QString buildInsightExplanationHtml(const QString &fieldKey, const PEDataModel &model, const QByteArray &fileData, qint64 fileSizeOnDisk)
{
    if (!isFileInsightJsonKey(fieldKey) || fieldKey == QLatin1String("File Insights")) {
        return QString();
    }

    const PEOverlayInfo overlay = model.getOverlayInfo();
    const PEEntropySummary entropy = model.getEntropySummary();
    const PEPdbInfo pdb = model.getPdbInfo();
    const PEVersionInfo version = model.getVersionInfo();
    const PEFileMetrics metrics = model.getFileMetrics();

    QString currentValue;
    bool absent = false;
    QString tipKey;

    if (fieldKey == QLatin1String("Overlay")) {
        tipKey = QStringLiteral("UI/insight_tip_overlay");
        if (overlay.present && overlay.fileOffset > 0) {
            quint64 overlayBytes = overlay.size;
            if (overlayBytes == 0) {
                const qint64 tail = qMax(model.getFileSize(), static_cast<qint64>(fileSizeOnDisk))
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
                                   qMax(model.getFileSize(), static_cast<qint64>(fileData.size())))));
            currentValue = LANG_PARAMS(QStringLiteral("UI/file_ratio_value"), ratioParams);
        }
    } else if (fieldKey == QLatin1String("Toolchain")) {
        tipKey = QStringLiteral("UI/insight_tip_toolchain");
        if (metrics.toolchainValid) {
            currentValue = metrics.toolchainSummary;
        } else if (model.getAnalysisMetadata().richHeaderPresent) {
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
                html += QStringLiteral("<div style='margin:0 0 8px 0;color:#555;'>%1 â€” %2</div>")
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
            if (const IMAGE_OPTIONAL_HEADER *opt = model.getOptionalHeader()) {
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
                                                      QStringLiteral("These are hints for the first bytes only â€” use a "
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
} // namespace PEFileInsights

