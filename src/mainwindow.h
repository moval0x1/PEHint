#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidget>
#include <QTextEdit>
#include <QLabel>
#include <QProgressBar>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QPushButton>
#include <QFileDialog>
#include <QMessageBox>
#include <QStatusBar>
#include <QMenuBar>
#include <QAction>
#include <QIcon>
#include <QPixmap>
#include <QFileInfo>
#include <QApplication>
#include <QClipboard>
#include <QMenu>
#include <QSettings>
#include <QContextMenuEvent>
#include <QTimer>
#include <QColor>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <functional>

#include "pe_parser_new.h"
#include "pe_findings.h"
#include "hexviewer.h"
#include "pe_ui_manager.h"

class FindingsController;
class ResourcesController;
class DependenciesController;
class ImportsController;
class StringsController;
class ExportsController;
class StructureTreeController;
class AnalysisDisplayController;
class MainWindowChrome;
class PEDataModel;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void openPeFile(const QString &filePath);

protected:
    void contextMenuEvent(QContextMenuEvent *event) override;
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

public slots:
    void on_action_PEHint_triggered();
    void on_action_Open_triggered();
    void on_action_Exit_triggered();
    void on_action_Save_Report_triggered();
    void on_action_Copy_Report_triggered();
    void on_action_Refresh_triggered();

    void onParsingComplete(bool success);
    void onParsingProgress(int percentage, const QString &message);
    void onErrorOccurred(const QString &error);

    void onTreeItemClicked(QTreeWidgetItem *item, int column);
    void onHexViewerByteClicked(qint64 offset, int length);
    void onCopyToClipboard();
    void onExpandAll();
    void onCollapseAll();
    void onExpandAllDependencies();
    void onCollapseAllDependencies();
    void onHexViewerOptions();
    void onImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void onImportFunctionSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void onDelayImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void onStringsFilterChanged();
    void onCancelStringsExtraction();
    void onExportStrings();
    void onStringsTreeItemDoubleClicked(QTreeWidgetItem *item, int column);
    void onAnalysisTabChanged(int index);
    void onFindingsItemClicked(QTreeWidgetItem *item, int column);
    void onOverviewItemClicked(QTreeWidgetItem *item, int column);
    void onResourcesItemClicked(QTreeWidgetItem *item, int column);
    void onFindingsFilterChanged();

    void updateUILanguage();
    void updateHexViewerLanguage();

private:
    PEParserNew *m_peParser;
    UIManager *m_uiManager;
    MainWindowChrome *m_chrome = nullptr;

    QString m_currentFilePath;
    bool m_fileLoaded;

    FindingsController *m_findingsController = nullptr;
    ResourcesController *m_resourcesController = nullptr;
    DependenciesController *m_dependenciesController = nullptr;
    ImportsController *m_importsController = nullptr;
    StringsController *m_stringsController = nullptr;
    ExportsController *m_exportsController = nullptr;
    StructureTreeController *m_structureTreeController = nullptr;
    AnalysisDisplayController *m_analysisDisplay = nullptr;

    quint64 m_languageRefreshEpoch = 0;

    void setupUI();
    void setupConnections();

    void loadPEFile(const QString &filePath);
    void clearDisplay();
    void updateFileInfo();
    void showFindingsInsightHtml(const QString &html);

    void showError(const QString &title, const QString &message);
    QString getFileSizeString(qint64 size) const;

    void onApplicationLanguageChanged(const QString &languageCode);
    void refreshOpenFileAfterLanguageChange(quint64 languageRefreshEpoch);

    void onDependenciesCustomContextMenu(const QPoint &pos);
};

#endif // MAINWINDOW_H
