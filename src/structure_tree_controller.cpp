#include "structure_tree_controller.h"

#include "crash_handler.h"
#include "hexviewer.h"
#include "language_manager.h"
#include "pe_parser_new.h"
#include "pe_ui_manager.h"
#include "pe_utils.h"

#include <QColor>
#include <QMap>
#include <QRegularExpression>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>

namespace {

constexpr int kFieldOffsetRole = Qt::UserRole + 20;
constexpr int kFieldSizeRole = Qt::UserRole + 21;

bool fileInsightUsesHexRoles(const QString &fieldName)
{
    return fieldName == QLatin1String("Overlay") || fieldName == QLatin1String("PDB Path")
           || fieldName == QLatin1String("PDB Raw") || fieldName == QLatin1String("PDB Age")
           || fieldName == QLatin1String("PDB GUID") || fieldName == QLatin1String("Entry Point");
}

bool parseInsightByteSizeFromValue(const QString &valueText, quint32 &outSize)
{
    static const QRegularExpression sizeInParens(
        QStringLiteral("\\(0x([0-9A-Fa-f]+) bytes\\)"), QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = sizeInParens.match(valueText);
    if (!match.hasMatch()) {
        return false;
    }
    bool ok = false;
    const quint32 parsed = match.captured(1).toUInt(&ok, 16);
    if (!ok || parsed == 0) {
        return false;
    }
    outSize = parsed;
    return true;
}

QColor colorForTreeSelection(const QTreeWidgetItem *item)
{
    if (!item) {
        return QColor(255, 235, 120, 180);
    }

    const QTreeWidgetItem *root = item;
    while (root->parent()) {
        root = root->parent();
    }

    const QString rootName = root->text(0).toLower();
    if (rootName.contains(QStringLiteral("dos"))) {
        return QColor(230, 80, 80, 185);
    }
    if (rootName.contains(QStringLiteral("rich"))) {
        return QColor(235, 170, 65, 185);
    }
    if (rootName.contains(QStringLiteral("nt"))) {
        return QColor(175, 195, 95, 185);
    }
    if (rootName.contains(QStringLiteral("section"))) {
        return QColor(100, 185, 205, 185);
    }
    if (rootName.contains(QStringLiteral("data"))) {
        return QColor(165, 145, 220, 185);
    }

    return QColor(255, 235, 120, 180);
}

} // namespace

StructureTreeController::StructureTreeController(PEParserNew *parser, UIManager *ui, QObject *parent)
    : QObject(parent)
    , m_parser(parser)
    , m_ui(ui)
{
}

void StructureTreeController::setParser(PEParserNew *parser)
{
    m_parser = parser;
}

void StructureTreeController::setUi(UIManager *ui)
{
    m_ui = ui;
}

void StructureTreeController::resetSessionState()
{
    m_lastExplainedFieldName.clear();
    m_lastHexHighlightOffset = -1;
    m_lastHexHighlightSize = 0;
    m_lastHexHighlightRgba = 0;
}

PeFieldHexRange StructureTreeController::resolveFieldHexRange(QTreeWidgetItem *item,
                                                               const QString &fieldName) const
{
    PeFieldHexRange out;
    if (!item || !m_parser || !m_parser->isValid()) {
        return out;
    }

    quint32 offsetValue = 0;
    quint32 sizeValue = 0;
    bool offsetOk = false;
    bool sizeOk = false;

    const QVariant roleOffset = item->data(0, kFieldOffsetRole);
    const QVariant roleSize = item->data(0, kFieldSizeRole);
    const bool hasRoleSize = roleSize.isValid();
    const bool insightHexRoles =
        fileInsightUsesHexRoles(fieldName) && roleOffset.isValid() && hasRoleSize;

    if (insightHexRoles) {
        offsetValue = roleOffset.toUInt(&offsetOk);
        sizeValue = roleSize.toUInt(&sizeOk);
    } else {
        if (roleOffset.isValid()) {
            offsetValue = roleOffset.toUInt(&offsetOk);
        }
        if (hasRoleSize) {
            sizeValue = roleSize.toUInt(&sizeOk);
        }

        if (!offsetOk) {
            const QString offsetText = item->text(2).trimmed();
            if (offsetText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
                offsetValue = offsetText.mid(2).toUInt(&offsetOk, 16);
            }
        }

        if (!hasRoleSize) {
            const QString sizeText = item->text(3);
            const QRegularExpression sizeHexRe(QStringLiteral("0x([0-9A-Fa-f]+)"));
            const QRegularExpressionMatch sizeMatch = sizeHexRe.match(sizeText);
            if (sizeMatch.hasMatch()) {
                sizeValue = sizeMatch.captured(1).toUInt(&sizeOk, 16);
            }
        }

        if (offsetOk && sizeValue == 0) {
            quint32 parsedSize = 0;
            if (parseInsightByteSizeFromValue(item->text(1), parsedSize)) {
                sizeValue = parsedSize;
                sizeOk = true;
            }
        }

        if (!offsetOk || (!hasRoleSize && !sizeOk)) {
            const QPair<quint32, quint32> fieldOffset = m_parser->getFieldOffset(fieldName);
            if (!offsetOk && fieldOffset.second > 0) {
                offsetValue = fieldOffset.first;
                offsetOk = true;
            }
            if (!hasRoleSize && !sizeOk && fieldOffset.second > 0) {
                sizeValue = fieldOffset.second;
                sizeOk = true;
            }
        }
    }

    if (offsetOk && sizeOk && sizeValue > 0) {
        out.offset = offsetValue;
        out.size = sizeValue;
        out.canHighlight = true;
    } else if (offsetOk) {
        out.offset = offsetValue;
        out.canGoTo = true;
    }
    return out;
}

void StructureTreeController::applyFieldHexNavigation(QTreeWidgetItem *item, const PeFieldHexRange &range)
{
    if (!m_ui || !m_ui->m_hexViewer) {
        return;
    }
    HexViewer *hex = m_ui->m_hexViewer;
    if (range.canHighlight) {
        const qint64 hexCap = hex->getDataSize();
        if (hexCap > 0 && static_cast<qint64>(range.offset) >= hexCap) {
            return;
        }
        const QColor highlightColor = colorForTreeSelection(item);
        const quint32 rgba = highlightColor.rgba();
        const bool sameHexAsLast = (static_cast<qint64>(range.offset) == m_lastHexHighlightOffset
                                    && range.size == m_lastHexHighlightSize && rgba == m_lastHexHighlightRgba);
        if (!sameHexAsLast) {
            hex->highlightRange(range.offset, range.size, highlightColor);
            m_lastHexHighlightOffset = static_cast<qint64>(range.offset);
            m_lastHexHighlightSize = range.size;
            m_lastHexHighlightRgba = rgba;
        }
    } else if (range.canGoTo) {
        hex->goToOffset(static_cast<qint64>(range.offset));
    }
}

void StructureTreeController::applyTabHexHighlight(quint32 offset, quint32 size, const QColor &color)
{
    if (!m_ui || !m_ui->m_hexViewer) {
        return;
    }
    HexViewer *hex = m_ui->m_hexViewer;
    if (size > 0) {
        const qint64 dataSize = hex->getDataSize();
        if (dataSize <= 0 || static_cast<qint64>(offset) >= dataSize) {
            return;
        }
        const quint32 cappedSize =
            static_cast<quint32>(qMin<qint64>(size, dataSize - static_cast<qint64>(offset)));
        hex->highlightRange(offset, cappedSize, color);
        m_lastHexHighlightOffset = static_cast<qint64>(offset);
        m_lastHexHighlightSize = cappedSize;
        m_lastHexHighlightRgba = color.rgba();
    } else {
        hex->goToOffset(static_cast<qint64>(offset));
    }
}

QTreeWidgetItem *StructureTreeController::findPeTreeItemByFieldKey(const QString &fieldKey) const
{
    if (fieldKey.isEmpty() || !m_ui || !m_ui->m_peTree) {
        return nullptr;
    }
    QTreeWidgetItemIterator it(m_ui->m_peTree);
    while (*it) {
        const QString key = (*it)->data(0, PEParserNew::kTreeFieldKeyRole).toString();
        if (key == fieldKey) {
            return *it;
        }
        ++it;
    }
    return nullptr;
}

void StructureTreeController::selectPeTreeItemForContext(QTreeWidgetItem *item)
{
    if (!item || !m_ui || !m_ui->m_peTree) {
        return;
    }
    QTreeWidgetItem *parent = item->parent();
    while (parent) {
        parent->setExpanded(true);
        parent = parent->parent();
    }
    m_ui->m_peTree->setCurrentItem(item);
    m_ui->m_peTree->scrollToItem(item);
}

void StructureTreeController::activatePeTreeItem(QTreeWidgetItem *item)
{
    if (!item || !m_ui) {
        return;
    }
    if (m_ui->m_analysisTabWidget) {
        m_ui->m_analysisTabWidget->setCurrentIndex(0);
    }
    selectPeTreeItemForContext(item);
    handleTreeItemClicked(item, 0);
}

void StructureTreeController::clearTreeHighlights() const
{
    if (!m_ui || !m_ui->m_peTree) {
        return;
    }

    QTreeWidgetItemIterator it(m_ui->m_peTree);
    while (*it) {
        QTreeWidgetItem *item = *it;

        const QVariant originalColor = item->data(0, Qt::UserRole + 1);
        if (originalColor.isValid()) {
            const QColor color = originalColor.value<QColor>();
            if (color.isValid()) {
                item->setBackground(0, color);
                item->setBackground(1, color);
                item->setBackground(2, color);
                item->setBackground(3, color);
            }
        } else {
            item->setBackground(0, QColor());
            item->setBackground(1, QColor());
            item->setBackground(2, QColor());
            item->setBackground(3, QColor());
        }

        item->setToolTip(0, QString());
        item->setToolTip(1, QString());
        item->setToolTip(2, QString());
        item->setToolTip(3, QString());

        ++it;
    }
}

void StructureTreeController::handleTreeItemClicked(QTreeWidgetItem *item, int column)
{
    try {
        if (!item || !m_ui) {
            return;
        }

        const QString displayFieldName = item->text(0);
        QString fieldName = displayFieldName;
        const QVariant treeKeyVar = item->data(0, PEParserNew::kTreeFieldKeyRole);
        if (treeKeyVar.isValid() && !treeKeyVar.toString().isEmpty()) {
            fieldName = treeKeyVar.toString();
        }
        Q_UNUSED(column);

        const bool sameFieldAsLast = (fieldName == m_lastExplainedFieldName);

        if (m_parser && m_parser->isValid()) {
            const PeFieldHexRange range = resolveFieldHexRange(item, fieldName);
            if (range.canHighlight) {
                HexViewer *hex = m_ui->m_hexViewer;
                const qint64 hexCap = hex ? hex->getDataSize() : 0;
                if (hex && hexCap > 0 && static_cast<qint64>(range.offset) >= hexCap) {
                    QMap<QString, QString> hp;
                    hp[QStringLiteral("offset")] = PEUtils::formatHexWidth(range.offset, 8);
                    hp[QStringLiteral("size")] = QString::number(hexCap);
                    emit statusMessageRequested(
                        LANG_PARAMS(QStringLiteral("UI/hex_offset_beyond_buffer"), hp), 5000);
                } else {
                    applyFieldHexNavigation(item, range);
                }
            } else if (range.canGoTo) {
                applyFieldHexNavigation(item, range);
            } else {
                emit statusMessageRequested(
                    LANG_PARAM("UI/field_no_offset", "field_name", displayFieldName), 3000);
            }
        }

        if (!sameFieldAsLast && m_parser && m_parser->isValid()) {
            const QString explanation = m_parser->getFieldExplanation(fieldName);
            m_ui->m_fieldExplanationText->setHtml(explanation);
            m_lastExplainedFieldName = fieldName;
        }
    } catch (const std::exception &e) {
        CrashHandler::getInstance().logError("StructureTreeController",
                                             "Exception during tree item click",
                                             QString("Exception: %1").arg(e.what()));
        emit errorOccurred(QStringLiteral("Error"), QString("Exception occurred: %1").arg(e.what()));
    } catch (...) {
        CrashHandler::getInstance().logError("StructureTreeController",
                                             "Unknown exception during tree item click",
                                             QStringLiteral("Unknown exception type"));
        emit errorOccurred(QStringLiteral("Error"), QStringLiteral("Unknown exception occurred"));
    }
}
