#include "exports_controller.h"

#include "language_manager.h"
#include "pe_data_model.h"
#include "pe_parser_new.h"
#include "pe_ui_manager.h"
#include "pe_utils.h"

#include <QTreeWidget>

ExportsController::ExportsController(UIManager *ui, QObject *parent)
    : QObject(parent)
    , m_ui(ui)
{
}

void ExportsController::setParser(PEParserNew *parser)
{
    m_parser = parser;
}

void ExportsController::refresh()
{
    if (m_populated || !m_ui || !m_ui->m_exportsTree || !m_parser) {
        return;
    }

    m_ui->m_exportsTree->clear();
    const auto &exports = m_parser->getExportFunctions();
    if (exports.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_ui->m_exportsTree);
        placeholder->setText(0, LANG("UI/exports_none"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
    } else {
        for (const PEDataModel::ExportFunctionEntry &entry : exports) {
            QTreeWidgetItem *item = new QTreeWidgetItem(m_ui->m_exportsTree);
            item->setText(0, entry.name);
            item->setText(1, entry.rva != 0 ? PEUtils::formatHexWidth(entry.rva, 8) : QString());
            item->setText(2, QString::number(entry.ordinal));
        }
    }

    m_populated = true;
}

void ExportsController::clear()
{
    if (m_ui && m_ui->m_exportsTree) {
        m_ui->m_exportsTree->clear();
    }
    m_populated = false;
}

void ExportsController::invalidate()
{
    m_populated = false;
}

void ExportsController::updateLanguageStrings()
{
    if (!m_populated) {
        return;
    }
    invalidate();
    refresh();
}
