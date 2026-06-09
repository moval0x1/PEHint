#ifndef RESOURCES_CONTROLLER_H
#define RESOURCES_CONTROLLER_H

#include <QObject>

class PEParserNew;
class QTreeWidgetItem;
class UIManager;

class ResourcesController : public QObject
{
    Q_OBJECT

public:
    explicit ResourcesController(UIManager *ui, QObject *parent = nullptr);

    void setParser(PEParserNew *parser);
    void refresh();
    void clear();
    void updateLanguageStrings();

    void handleItemClicked(QTreeWidgetItem *item);

signals:
    void requestHexHighlight(quint32 offset, quint32 size);

private:
    void populate();

    UIManager *m_ui = nullptr;
    PEParserNew *m_parser = nullptr;
    bool m_populated = false;
};

#endif // RESOURCES_CONTROLLER_H
