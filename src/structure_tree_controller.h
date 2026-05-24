#ifndef STRUCTURE_TREE_CONTROLLER_H
#define STRUCTURE_TREE_CONTROLLER_H

#include "pe_field_hex.h"

#include <QColor>
#include <QObject>

class PEParserNew;
class QTreeWidgetItem;
class UIManager;

class StructureTreeController : public QObject
{
    Q_OBJECT

public:
    explicit StructureTreeController(PEParserNew *parser, UIManager *ui, QObject *parent = nullptr);

    void setParser(PEParserNew *parser);
    void setUi(UIManager *ui);

    void resetSessionState();

    PeFieldHexRange resolveFieldHexRange(QTreeWidgetItem *item, const QString &fieldName) const;
    void applyFieldHexNavigation(QTreeWidgetItem *item, const PeFieldHexRange &range);
    void applyTabHexHighlight(quint32 offset, quint32 size, const QColor &color);

    QTreeWidgetItem *findPeTreeItemByFieldKey(const QString &fieldKey) const;
    void selectPeTreeItemForContext(QTreeWidgetItem *item);
    void activatePeTreeItem(QTreeWidgetItem *item);
    void clearTreeHighlights() const;

    void handleTreeItemClicked(QTreeWidgetItem *item, int column);

signals:
    void statusMessageRequested(const QString &message, int timeoutMs);
    void errorOccurred(const QString &title, const QString &message);

private:
    PEParserNew *m_parser = nullptr;
    UIManager *m_ui = nullptr;
    QString m_lastExplainedFieldName;
    qint64 m_lastHexHighlightOffset = -1;
    quint32 m_lastHexHighlightSize = 0;
    quint32 m_lastHexHighlightRgba = 0;
};

#endif // STRUCTURE_TREE_CONTROLLER_H
