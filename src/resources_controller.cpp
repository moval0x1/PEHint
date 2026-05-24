#include "resources_controller.h"

#include "pe_parser_new.h"
#include "pe_ui_manager.h"
#include "pe_resource_preview.h"
#include "pe_utils.h"
#include "language_manager.h"

#include <QPixmap>
#include <QTreeWidget>
#include <QLabel>
#include <QPixmap>
#include <QTextEdit>

namespace {

constexpr int kResourceOffsetRole = Qt::UserRole;
constexpr int kResourceSizeRole = Qt::UserRole + 1;
constexpr int kResourceIndexRole = Qt::UserRole + 2;

} // namespace

ResourcesController::ResourcesController(UIManager *ui, QObject *parent)
    : QObject(parent), m_ui(ui)
{
}

void ResourcesController::setParser(PEParserNew *parser)
{
    m_parser = parser;
}

void ResourcesController::refresh()
{
    populate();
}

void ResourcesController::clear()
{
    if (m_ui && m_ui->m_resourcesTree) {
        m_ui->m_resourcesTree->clear();
    }
    if (m_ui && m_ui->m_resourcesPreviewImage) {
        m_ui->m_resourcesPreviewImage->clear();
        m_ui->m_resourcesPreviewImage->setVisible(false);
    }
    if (m_ui && m_ui->m_resourcesPreviewText) {
        m_ui->m_resourcesPreviewText->clear();
        m_ui->m_resourcesPreviewText->setVisible(true);
    }
    m_populated = false;
}

void ResourcesController::updateLanguageStrings()
{
    if (!m_ui || !m_ui->m_resourcesTree) {
        return;
    }

    m_ui->m_resourcesTree->setHeaderLabels({
        LANG("UI/resources_header_type"),
        LANG("UI/resources_header_name"),
        LANG("UI/resources_header_language"),
        LANG("UI/resources_header_size"),
        LANG("UI/resources_header_offset")
    });

    if (m_ui->m_resourcesPreviewText) {
        m_ui->m_resourcesPreviewText->setPlaceholderText(
            LanguageManager::getInstance().getString(
                QStringLiteral("UI/resources_preview_placeholder"),
                QStringLiteral("Select a resource row to preview manifest text, icons, or readable strings.")));
    }
}

void ResourcesController::handleItemClicked(QTreeWidgetItem *item)
{
    if (!item || !m_ui || !m_parser) {
        return;
    }

    const QVariant offsetVar = item->data(0, kResourceOffsetRole);
    if (offsetVar.isValid()) {
        const quint32 offset = offsetVar.toUInt();
        const quint32 size = item->data(0, kResourceSizeRole).toUInt();
        emit requestHexHighlight(offset, size);
    }

    const QVariant indexVar = item->data(0, kResourceIndexRole);
    if (!indexVar.isValid() || !m_ui->m_resourcesPreviewText) {
        return;
    }
    const int resourceIndex = indexVar.toInt();
    const QVector<PEResourceItem> &resources = m_parser->getResourceEntries();
    if (resourceIndex < 0 || resourceIndex >= resources.size()) {
        return;
    }
    const ResourcePreview preview =
        buildResourcePreview(m_parser->getFileData(), resources.at(resourceIndex), resources);
    m_ui->m_resourcesPreviewImage->clear();
    m_ui->m_resourcesPreviewImage->setVisible(false);
    m_ui->m_resourcesPreviewText->setVisible(true);
    if (preview.kind == ResourcePreview::Kind::Image && !preview.image.isNull()) {
        m_ui->m_resourcesPreviewImage->setPixmap(
            QPixmap::fromImage(preview.image).scaled(128, 128, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        m_ui->m_resourcesPreviewImage->setVisible(true);
        m_ui->m_resourcesPreviewText->setVisible(false);
        m_ui->m_resourcesPreviewText->clear();
        return;
    }
    if (preview.kind == ResourcePreview::Kind::ImageGallery) {
        m_ui->m_resourcesPreviewText->setHtml(preview.htmlContent);
        return;
    }
    if (preview.kind == ResourcePreview::Kind::Html) {
        m_ui->m_resourcesPreviewText->setHtml(preview.htmlContent);
        return;
    }
    if (preview.kind == ResourcePreview::Kind::Text) {
        m_ui->m_resourcesPreviewText->setPlainText(preview.textContent);
        return;
    }
    if (preview.kind == ResourcePreview::Kind::Hex) {
        m_ui->m_resourcesPreviewText->setPlainText(preview.hexPreview);
        return;
    }
    m_ui->m_resourcesPreviewText->clear();
}

void ResourcesController::populate()
{
    if (m_populated) {
        return;
    }
    if (!m_ui || !m_ui->m_resourcesTree || !m_parser) {
        return;
    }

    m_ui->m_resourcesTree->clear();
    const QVector<PEResourceItem> &resources = m_parser->getResourceEntries();
    if (resources.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_ui->m_resourcesTree);
        placeholder->setText(0, LANG("UI/resources_none"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
    } else {
        m_ui->m_resourcesTree->setUpdatesEnabled(false);
        for (int i = 0; i < resources.size(); ++i) {
            const PEResourceItem &entry = resources.at(i);
            QTreeWidgetItem *item = new QTreeWidgetItem(m_ui->m_resourcesTree);
            item->setText(0, entry.typeName);
            item->setText(1, entry.resourceName);
            item->setText(2, entry.languageId != 0 ? QString::number(entry.languageId) : QString());
            item->setText(3, QString::number(entry.size));
            item->setText(4, entry.fileOffset != 0 ? PEUtils::formatHexWidth(entry.fileOffset, 8) : QString());
            if (entry.fileOffset != 0) {
                item->setData(0, kResourceOffsetRole, QVariant::fromValue(entry.fileOffset));
                item->setData(0, kResourceSizeRole, QVariant::fromValue(entry.size));
            }
            item->setData(0, kResourceIndexRole, i);
            if (entry.rva != 0) {
                const QString tip = QStringLiteral("RVA %1, %2 bytes")
                                        .arg(PEUtils::formatHexWidth(entry.rva, 8))
                                        .arg(entry.size);
                item->setToolTip(0, tip);
                item->setToolTip(1, tip);
                item->setToolTip(2, tip);
                item->setToolTip(3, tip);
                item->setToolTip(4, tip);
            }
        }
        m_ui->m_resourcesTree->setUpdatesEnabled(true);
    }

    m_populated = true;
}
