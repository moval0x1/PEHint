#ifndef IMPORTS_CONTROLLER_H
#define IMPORTS_CONTROLLER_H

#include <QObject>

class PEParserNew;
class QTreeWidgetItem;
class UIManager;

class ImportsController : public QObject
{
    Q_OBJECT

public:
    explicit ImportsController(UIManager *ui, QObject *parent = nullptr);

    void setParser(PEParserNew *parser);
    void setFileLoaded(bool loaded);

    void refreshImports();
    void refreshDelayImports();
    void clear();
    void invalidate();
    void updateLanguageStrings();

    void handleImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void handleImportFunctionSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void handleDelayImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous);

private:
    void populateImportFunctions(const QString &moduleName);
    void populateDelayImportFunctions(const QString &moduleName);

    UIManager *m_ui = nullptr;
    PEParserNew *m_parser = nullptr;
    bool m_fileLoaded = false;
    bool m_importsPopulated = false;
    bool m_delayImportsPopulated = false;
};

#endif // IMPORTS_CONTROLLER_H
