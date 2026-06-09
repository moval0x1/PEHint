#ifndef DEPENDENCIES_CONTROLLER_H
#define DEPENDENCIES_CONTROLLER_H

#include <QObject>
#include <QString>

class PEParserNew;
class UIManager;

class DependenciesController : public QObject
{
    Q_OBJECT

public:
    explicit DependenciesController(UIManager *ui, QObject *parent = nullptr);

    void setParser(PEParserNew *parser);
    void setFilePath(const QString &path);
    void setFileLoaded(bool loaded);

    void setupDepthSpin();
    void refresh();
    void clear();
    void invalidate();
    void updateLanguageStrings();
    void updateExpandCollapseButtonState();

    void handleCustomContextMenu(const QPoint &pos);
    void expandAll();
    void collapseAll();

signals:
    void statusMessageRequested(const QString &message, int timeoutMs);

private:
    void populate();

    UIManager *m_ui = nullptr;
    PEParserNew *m_parser = nullptr;
    QString m_filePath;
    bool m_fileLoaded = false;
    bool m_populated = false;
};

#endif // DEPENDENCIES_CONTROLLER_H
