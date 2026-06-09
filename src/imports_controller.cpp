#include "imports_controller.h"

#include "pe_data_model.h"
#include "pe_findings.h"
#include "pe_parser_new.h"
#include "pe_ui_manager.h"
#include "pe_utils.h"
#include "language_manager.h"
#include "sdk_api_markdown_reader.h"

#include <QColor>
#include <QMap>
#include <QTextEdit>
#include <QTreeWidget>
#include <QUrl>

namespace {

constexpr int kImportByOrdinalRole = Qt::UserRole + 31;

QColor flaggedImportRowColor(PEFindingSeverity severity)
{
    switch (severity) {
    case PEFindingSeverity::High:
        return QColor(255, 230, 230);
    case PEFindingSeverity::Medium:
        return QColor(255, 248, 220);
    case PEFindingSeverity::Low:
        return QColor(240, 248, 255);
    default:
        return QColor(245, 245, 245);
    }
}

void applyFlaggedImportRowStyle(QTreeWidgetItem *item, const QString &moduleName,
                                const PEDataModel::ImportFunctionEntry &entry)
{
    if (!item || entry.name.isEmpty() || entry.importedByOrdinal) {
        return;
    }
    PEFindingSeverity severity = PEFindingSeverity::Medium;
    QString note;
    if (!PEFindingsEngine::isFlaggedImport(moduleName, entry.name, &severity, &note)) {
        return;
    }
    const QColor bg = flaggedImportRowColor(severity);
    for (int col = 0; col < item->columnCount(); ++col) {
        item->setBackground(col, bg);
    }
    if (!note.isEmpty()) {
        QMap<QString, QString> params;
        params[QStringLiteral("note")] = note;
        item->setToolTip(0, LANG_PARAMS(QStringLiteral("UI/imports_flagged_tooltip"), params));
    } else {
        item->setToolTip(0, LANG(QStringLiteral("UI/imports_flagged_tooltip_short")));
    }
}

QString importHintPlaceholderText()
{
    return LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_placeholder"),
        QStringLiteral("Select an imported function. PEHint shows curated summaries; richer entries may include signature, parameters, and return value (informative only—not live Microsoft data)."));
}

QString importHintTitleText()
{
    return LanguageManager::getInstance().getString(QStringLiteral("UI/imports_hint_title"),
                                                    QStringLiteral("API summary"));
}

QString importHintFooterText()
{
    return LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_footer"),
        QStringLiteral("Tip: On Microsoft Learn, search for the function name (for example CreateFileW) to open the full topic."));
}

QString importHintOrdinalText()
{
    return LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_ordinal"),
        QStringLiteral("This import is bound by ordinal only and PEHint could not resolve a name from the system copy of the exporting DLL (missing file or unnamed export). Check the DLL’s exports or Microsoft Learn for that ordinal."));
}

QString importHintNoneForFunction(const QString &funcName)
{
    QMap<QString, QString> p;
    p.insert(QStringLiteral("name"), funcName);
    QString hint = LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_none"),
        p,
        QStringLiteral("No built-in summary for {name}. Search Microsoft Learn for the full reference and parameters."));
    const QString encoded = QString::fromLatin1(QUrl::toPercentEncoding(funcName));
    hint += QStringLiteral("\nhttps://learn.microsoft.com/en-us/search/?terms=%1").arg(encoded);
    return hint;
}

QString formatImportHintDisplay(const ImportApiHint &h, const QString &optionalBannerHtml = QString())
{
    auto escTitle = [](const QString &s) -> QString { return QString(s).toHtmlEscaped(); };

    QStringList html;
    html << QStringLiteral("<html><head><meta charset=\"utf-8\"/><style>");
    html << QStringLiteral(
        "body{font-family:'Segoe UI',Arial,sans-serif;font-size:11px;color:#222;margin:0;padding:0;line-height:1.5;}");
    html << QStringLiteral(
        "a{color:#0066cc;text-decoration:none;} a:hover{text-decoration:underline;}");
    html << QStringLiteral(".sec{font-weight:600;margin:14px 0 6px 0;color:#111;font-size:12px;}");
    html << QStringLiteral(
        ".learn-doc{font-size:11px;color:#222;}"
        ".learn-doc table{border-collapse:collapse;width:100%;margin:8px 0;font-size:11px;}"
        ".learn-doc th,.learn-doc td{border:1px solid #e0e0e0;padding:5px 8px;text-align:left;vertical-align:top;}"
        ".learn-doc th{background:#f3f3f3;font-weight:600;}"
        ".learn-doc pre,.learn-doc code{font-family:Consolas,'Cascadia Mono','Segoe UI Mono',monospace;}"
        ".learn-doc pre{background:#f6f6f6;border:1px solid #e8e8e8;border-radius:4px;padding:8px;font-size:10px;"
        "margin:8px 0;white-space:pre-wrap;word-wrap:break-word;}"
        ".learn-doc p{margin:6px 0;}"
        ".learn-doc ul,.learn-doc ol{margin:6px 0 6px 22px;padding:0;}"
        ".learn-doc li{margin:2px 0;}"
        ".learn-doc blockquote{margin:8px 0 8px 6px;padding:4px 0 4px 10px;border-left:3px solid #ccc;color:#333;}"
        ".param-item{margin:10px 0;padding:0;border-bottom:1px solid #eee;}"
        ".param-item:last-child{border-bottom:none;}"
        ".hint-foot{margin-top:12px;padding-top:8px;border-top:1px solid #e8e8e8;color:#666;font-size:10px;}");
    html << QStringLiteral("</style></head><body>");
    if (!optionalBannerHtml.isEmpty()) {
        html << optionalBannerHtml;
    }

    if (!h.summary.isEmpty()) {
        html << h.summary;
    }
    if (!h.signature.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Signature"))
             + QStringLiteral("</p>") + h.signature;
    }
    if (!h.parameters.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Parameters"))
             + QStringLiteral("</p>");
        for (const QString &paramLine : h.parameters) {
            html << paramLine;
        }
    }
    if (!h.returns.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Return value"))
             + QStringLiteral("</p>") + h.returns;
    }
    if (!h.remarks.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Remarks"))
             + QStringLiteral("</p>") + h.remarks;
    }
    if (!h.learnUrl.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Documentation"))
             + QStringLiteral("</p>");
        html << QStringLiteral("<p><a href=\"")
             + h.learnUrl.toHtmlEscaped() + QStringLiteral("\">") + h.learnUrl.toHtmlEscaped()
             + QStringLiteral("</a></p>");
    }
    if (!h.malapiUrl.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("MalAPI.io"))
             + QStringLiteral("</p>");
        html << QStringLiteral("<p><a href=\"")
             + h.malapiUrl.toHtmlEscaped() + QStringLiteral("\">") + h.malapiUrl.toHtmlEscaped()
             + QStringLiteral("</a></p>");
    }
    if (h.learnUrl.isEmpty() && h.malapiUrl.isEmpty()) {
        const QString foot = QStringLiteral(
                                   "Tip: On Microsoft Learn, search for the function name (for example CreateFileW) to open the full topic.")
                                   .toHtmlEscaped()
                                   .replace(QLatin1Char('\n'), QStringLiteral("<br/>"));
        html << QStringLiteral("<p class=\"hint-foot\">") + foot + QStringLiteral("</p>");
    }
    html << QStringLiteral("</body></html>");
    return html.join(QString());
}

} // namespace

ImportsController::ImportsController(UIManager *ui, QObject *parent)
    : QObject(parent), m_ui(ui)
{
}

void ImportsController::setParser(PEParserNew *parser)
{
    m_parser = parser;
}

void ImportsController::setFileLoaded(bool loaded)
{
    m_fileLoaded = loaded;
}

void ImportsController::refreshImports()
{
    if (m_importsPopulated) {
        return;
    }
    if (!m_ui || !m_ui->m_importModulesTree || !m_parser) {
        return;
    }

    m_ui->m_importModulesTree->blockSignals(true);
    m_ui->m_importModulesTree->clear();
    if (m_ui->m_importFunctionsTree) {
        m_ui->m_importFunctionsTree->blockSignals(true);
        m_ui->m_importFunctionsTree->clear();
        m_ui->m_importFunctionsTree->blockSignals(false);
    }
    m_ui->m_importModulesTree->blockSignals(false);

    const QStringList imports = m_parser->getImportModules();
    const auto &importDetails = m_parser->getImportFunctionDetails();

    for (const QString &moduleName : imports) {
        const QList<PEDataModel::ImportFunctionEntry> functions = importDetails.value(moduleName);
        QTreeWidgetItem *moduleItem = new QTreeWidgetItem(m_ui->m_importModulesTree);
        moduleItem->setText(0, moduleName);
        moduleItem->setText(1, QString::number(functions.size()));
        int flaggedCount = 0;
        for (const PEDataModel::ImportFunctionEntry &entry : functions) {
            if (!entry.importedByOrdinal && PEFindingsEngine::isFlaggedImport(moduleName, entry.name)) {
                ++flaggedCount;
            }
        }
        if (flaggedCount > 0) {
            const QColor bg = QColor(255, 248, 220);
            moduleItem->setBackground(0, bg);
            moduleItem->setBackground(1, bg);
            QMap<QString, QString> params;
            params[QStringLiteral("count")] = QString::number(flaggedCount);
            moduleItem->setToolTip(0, LANG_PARAMS(QStringLiteral("UI/imports_module_flagged_tooltip"), params));
        }
    }

    if (m_ui->m_importModulesTree->topLevelItemCount() > 0) {
        m_ui->m_importModulesTree->setCurrentItem(m_ui->m_importModulesTree->topLevelItem(0));
    } else if (m_ui->m_importFunctionsTree) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_ui->m_importModulesTree);
        placeholder->setText(0, LANG("UI/imports_none"));
        placeholder->setText(1, QString());
        populateImportFunctions(QString());
    }

    m_importsPopulated = true;
}

void ImportsController::refreshDelayImports()
{
    if (m_delayImportsPopulated) {
        return;
    }
    if (!m_ui || !m_ui->m_delayImportModulesTree || !m_parser) {
        return;
    }

    m_ui->m_delayImportModulesTree->blockSignals(true);
    m_ui->m_delayImportModulesTree->clear();
    if (m_ui->m_delayImportFunctionsTree) {
        m_ui->m_delayImportFunctionsTree->blockSignals(true);
        m_ui->m_delayImportFunctionsTree->clear();
        m_ui->m_delayImportFunctionsTree->blockSignals(false);
    }
    m_ui->m_delayImportModulesTree->blockSignals(false);

    const QStringList delayImports = m_parser->getDelayImportModules();
    const auto &delayImportDetails = m_parser->getDelayImportFunctionDetails();

    for (const QString &moduleName : delayImports) {
        const QList<PEDataModel::ImportFunctionEntry> functions = delayImportDetails.value(moduleName);
        QTreeWidgetItem *moduleItem = new QTreeWidgetItem(m_ui->m_delayImportModulesTree);
        moduleItem->setText(0, moduleName);
        moduleItem->setText(1, QString::number(functions.size()));
        int flaggedCount = 0;
        for (const PEDataModel::ImportFunctionEntry &entry : functions) {
            if (!entry.importedByOrdinal && PEFindingsEngine::isFlaggedImport(moduleName, entry.name)) {
                ++flaggedCount;
            }
        }
        if (flaggedCount > 0) {
            const QColor bg = QColor(255, 248, 220);
            moduleItem->setBackground(0, bg);
            moduleItem->setBackground(1, bg);
            QMap<QString, QString> params;
            params[QStringLiteral("count")] = QString::number(flaggedCount);
            moduleItem->setToolTip(0, LANG_PARAMS(QStringLiteral("UI/imports_module_flagged_tooltip"), params));
        }
    }

    if (m_ui->m_delayImportModulesTree->topLevelItemCount() > 0) {
        m_ui->m_delayImportModulesTree->setCurrentItem(
            m_ui->m_delayImportModulesTree->topLevelItem(0));
    } else {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_ui->m_delayImportModulesTree);
        placeholder->setText(0, LANG("UI/delay_imports_none"));
        placeholder->setText(1, QString());
        populateDelayImportFunctions(QString());
    }

    m_delayImportsPopulated = true;
}

void ImportsController::clear()
{
    if (m_ui && m_ui->m_importModulesTree) {
        m_ui->m_importModulesTree->clear();
    }
    if (m_ui && m_ui->m_importFunctionsTree) {
        m_ui->m_importFunctionsTree->clear();
    }
    if (m_ui && m_ui->m_importHintText) {
        m_ui->m_importHintText->setPlainText(importHintPlaceholderText());
    }
    if (m_ui && m_ui->m_delayImportModulesTree) {
        m_ui->m_delayImportModulesTree->clear();
    }
    if (m_ui && m_ui->m_delayImportFunctionsTree) {
        m_ui->m_delayImportFunctionsTree->clear();
    }
    m_importsPopulated = false;
    m_delayImportsPopulated = false;
}

void ImportsController::invalidate()
{
    m_importsPopulated = false;
    m_delayImportsPopulated = false;
}

void ImportsController::updateLanguageStrings()
{
    if (!m_ui) {
        return;
    }

    if (m_ui->m_importModulesTree) {
        m_ui->m_importModulesTree->setHeaderLabels(
            {LANG("UI/imports_header_module"), LANG("UI/imports_header_count")});
    }
    if (m_ui->m_importFunctionsTree) {
        m_ui->m_importFunctionsTree->setHeaderLabels({
            LANG("UI/imports_functions_header_name"),
            LANG("UI/imports_functions_header_offset"),
            LANG("UI/imports_functions_header_ordinal")
        });
    }
    if (m_ui->m_delayImportModulesTree) {
        m_ui->m_delayImportModulesTree->setHeaderLabels(
            {LANG("UI/imports_header_module"), LANG("UI/imports_header_count")});
    }
    if (m_ui->m_delayImportFunctionsTree) {
        m_ui->m_delayImportFunctionsTree->setHeaderLabels({
            LANG("UI/imports_functions_header_name"),
            LANG("UI/imports_functions_header_offset"),
            LANG("UI/imports_functions_header_ordinal")
        });
    }
    if (m_ui->m_importHintTitleLabel) {
        m_ui->m_importHintTitleLabel->setText(importHintTitleText());
    }
    if (m_ui->m_importHintText && !m_fileLoaded) {
        m_ui->m_importHintText->setPlainText(importHintPlaceholderText());
    }
}

void ImportsController::handleImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);

    if (!m_fileLoaded || !m_parser) {
        return;
    }

    if (!current) {
        populateImportFunctions(QString());
        return;
    }

    populateImportFunctions(current->text(0));
}

void ImportsController::handleImportFunctionSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);
    if (!m_ui || !m_ui->m_importHintText) {
        return;
    }
    if (!current || current->flags() == Qt::NoItemFlags) {
        m_ui->m_importHintText->setPlainText(importHintPlaceholderText());
        return;
    }
    QTreeWidgetItem *modItem =
        m_ui->m_importModulesTree ? m_ui->m_importModulesTree->currentItem() : nullptr;
    if (!modItem) {
        m_ui->m_importHintText->setPlainText(importHintPlaceholderText());
        return;
    }
    const QString moduleName = modItem->text(0);
    if (moduleName
        == LanguageManager::getInstance().getString(QStringLiteral("UI/imports_none"),
                                                    QStringLiteral("No imported modules"))) {
        m_ui->m_importHintText->setPlainText(importHintPlaceholderText());
        return;
    }
    const QString funcName = current->text(0);
    if (funcName
        == LanguageManager::getInstance().getString(QStringLiteral("UI/imports_no_functions"),
                                                    QStringLiteral("No imported functions"))) {
        m_ui->m_importHintText->setPlainText(importHintPlaceholderText());
        return;
    }
    const bool importByOrdinal = current->data(0, kImportByOrdinalRole).toBool();
    if (importByOrdinal) {
        if (funcName == QStringLiteral("[ - ]")) {
            QString t = importHintOrdinalText();
            t += QStringLiteral("\n\n");
            t += importHintFooterText();
            m_ui->m_importHintText->setPlainText(t);
            return;
        }
        const ImportApiHint hintOrd =
            SdkApiMarkdownReader::instance().hintForImport(moduleName, funcName);
        if (hintOrd.hasContent()) {
            const QString banner =
                QStringLiteral("<p style=\"color:#444;font-size:10px;margin:0 0 10px 0;padding:6px 8px;background:#fafafa;"
                               "border-left:3px solid #bbb;\">")
                + QStringLiteral("Imported by <strong>ordinal</strong> in this PE; the name in the list was resolved from the export table of the system copy of ")
                + moduleName.toHtmlEscaped()
                + QStringLiteral(" (not stored in the PE).</p>");
            m_ui->m_importHintText->setHtml(formatImportHintDisplay(hintOrd, banner));
            return;
        }
        QString t = importHintOrdinalText();
        t += QStringLiteral("\n\n");
        t += importHintFooterText();
        m_ui->m_importHintText->setPlainText(t);
        return;
    }
    const ImportApiHint hint = SdkApiMarkdownReader::instance().hintForImport(moduleName, funcName);
    if (!hint.hasContent()) {
        QString t = importHintNoneForFunction(funcName);
        t += QStringLiteral("\n\n");
        t += importHintFooterText();
        m_ui->m_importHintText->setPlainText(t);
        return;
    }
    m_ui->m_importHintText->setHtml(formatImportHintDisplay(hint));
}

void ImportsController::handleDelayImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);

    if (!m_fileLoaded || !m_parser) {
        return;
    }

    if (!current) {
        populateDelayImportFunctions(QString());
        return;
    }

    const QString noneLabel = LanguageManager::getInstance().getString(
        QStringLiteral("UI/delay_imports_none"), QStringLiteral("No delay-import modules"));
    if (current->text(0) == noneLabel) {
        populateDelayImportFunctions(QString());
        return;
    }

    populateDelayImportFunctions(current->text(0));
}

void ImportsController::populateImportFunctions(const QString &moduleName)
{
    if (!m_ui || !m_ui->m_importFunctionsTree) {
        return;
    }

    m_ui->m_importFunctionsTree->blockSignals(true);
    m_ui->m_importFunctionsTree->clear();
    m_ui->m_importFunctionsTree->blockSignals(false);

    if (!m_fileLoaded || !m_parser) {
        if (m_ui->m_importHintText) {
            m_ui->m_importHintText->setPlainText(importHintPlaceholderText());
        }
        return;
    }

    const auto &importDetails = m_parser->getImportFunctionDetails();
    const QList<PEDataModel::ImportFunctionEntry> functions =
        moduleName.isEmpty() ? QList<PEDataModel::ImportFunctionEntry>() : importDetails.value(moduleName);

    if (functions.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_ui->m_importFunctionsTree);
        placeholder->setText(0, LANG("UI/imports_no_functions"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
        if (m_ui->m_importHintText) {
            m_ui->m_importHintText->setPlainText(importHintPlaceholderText());
        }
        return;
    }

    for (const PEDataModel::ImportFunctionEntry &entry : functions) {
        QTreeWidgetItem *item = new QTreeWidgetItem(m_ui->m_importFunctionsTree);
        item->setText(0, entry.name);
        item->setData(0, kImportByOrdinalRole, entry.importedByOrdinal);
        if (entry.thunkRVA != 0) {
            item->setText(1, PEUtils::formatHexWidth(entry.thunkRVA, 8));
        } else {
            item->setText(1, QString());
        }
        if (entry.importedByOrdinal) {
            item->setText(2, QString::number(entry.ordinal));
        } else {
            item->setText(2, QString());
        }
        applyFlaggedImportRowStyle(item, moduleName, entry);
    }

    if (m_ui->m_importFunctionsTree->topLevelItemCount() > 0) {
        QTreeWidgetItem *first = m_ui->m_importFunctionsTree->topLevelItem(0);
        if (first->flags() != Qt::NoItemFlags) {
            m_ui->m_importFunctionsTree->setCurrentItem(first);
        }
    }
}

void ImportsController::populateDelayImportFunctions(const QString &moduleName)
{
    if (!m_ui || !m_ui->m_delayImportFunctionsTree) {
        return;
    }

    m_ui->m_delayImportFunctionsTree->blockSignals(true);
    m_ui->m_delayImportFunctionsTree->clear();
    m_ui->m_delayImportFunctionsTree->blockSignals(false);

    if (!m_fileLoaded || !m_parser) {
        return;
    }

    const auto &delayImportDetails = m_parser->getDelayImportFunctionDetails();
    const QList<PEDataModel::ImportFunctionEntry> functions =
        moduleName.isEmpty() ? QList<PEDataModel::ImportFunctionEntry>()
                             : delayImportDetails.value(moduleName);

    if (functions.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_ui->m_delayImportFunctionsTree);
        placeholder->setText(0, LANG("UI/delay_imports_no_functions"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
        return;
    }

    for (const PEDataModel::ImportFunctionEntry &entry : functions) {
        QTreeWidgetItem *item = new QTreeWidgetItem(m_ui->m_delayImportFunctionsTree);
        item->setText(0, entry.name);
        if (entry.thunkRVA != 0) {
            item->setText(1, PEUtils::formatHexWidth(entry.thunkRVA, 8));
        } else {
            item->setText(1, QString());
        }
        if (entry.importedByOrdinal) {
            item->setText(2, QString::number(entry.ordinal));
        } else {
            item->setText(2, QString());
        }
        applyFlaggedImportRowStyle(item, moduleName, entry);
    }
}
