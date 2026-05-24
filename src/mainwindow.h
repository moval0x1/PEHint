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
#include <QActionGroup>
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
#include <QFutureWatcher>
#include <functional>

#include "pe_parser_new.h"
#include "pe_findings.h"
#include "hexviewer.h"
#include "pe_ui_manager.h"
#include "pe_string_extractor.h"

class PEDataModel;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

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
    
    // PE Parser slots
    void onParsingComplete(bool success);
    void onParsingProgress(int percentage, const QString &message);
    void onErrorOccurred(const QString &error);
    
    // UI interaction slots
    void onTreeItemClicked(QTreeWidgetItem *item, int column);
    void onHexViewerByteClicked(qint64 offset, int length);
    void onLanguageChanged(const QString &language);
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
    void onStringsExtractionFinished();
    void onCancelStringsExtraction();
    void onExportStrings();
    void onStringsTreeItemDoubleClicked(QTreeWidgetItem *item, int column);
    void onAnalysisTabChanged(int index);
    void onFindingsItemClicked(QTreeWidgetItem *item, int column);
    void onOverviewItemClicked(QTreeWidgetItem *item, int column);
    void onFindingsFilterChanged();

    // Language management
    void setupLanguageMenu();
    void onLanguageMenuTriggered(QAction *action);
    void updateUILanguage();
    void updateMenuLanguage();
    void updateLanguageMenu();
    void updateHexViewerLanguage();
    void updateWindowTitle();

private:
    
    // PE Parser
    PEParserNew *m_peParser;
    
    // UI Manager
    UIManager *m_uiManager;
    
    // UI Components (now managed by UIManager)
    // HexViewer is now managed by UIManager
    // Access it via m_uiManager->m_hexViewer
    // m_peTree is managed by UIManager
    
    // Current file info
    QString m_currentFilePath;
    bool m_fileLoaded;
    QList<ExtractedString> m_extractedStrings;  ///< Last extracted strings for filter
    QFutureWatcher<StringExtractionResult> m_stringsExtractionWatcher;
    bool m_stringsExtractionRunning;

    QVector<PEFindingInstance> m_cachedFindings;
    QVector<PEFindingInstance> m_cachedPassFindings;

    // Lazy UI population flags (to keep initial open/drag fast)
    bool m_importsPopulated;
    bool m_delayImportsPopulated;
    bool m_exportsPopulated;
    bool m_dependenciesPopulated;
    bool m_stringsPopulated;
    QString m_lastExplainedFieldName; ///< Avoid redundant explanation/hex work on repeated selection
    qint64 m_lastHexHighlightOffset = -1; ///< Last structure highlight start in hex (-1 = none)
    quint32 m_lastHexHighlightSize = 0;
    quint32 m_lastHexHighlightRgba = 0; ///< QColor::rgba() of last structure highlight

    /// Bumped on each in-flight language refresh so superseded staged UI work exits before mutating widgets.
    quint64 m_languageRefreshEpoch = 0;

    // UI Setup
    void setupUI();
    void setupConnections();
    void setupMenus();
    void setupToolbar();
    void setupStatusBar();
    void setupHexViewer();
    

    

    
    // File operations
    void loadPEFile(const QString &filePath);
    void clearDisplay();
    void updateFileInfo();
    void updateAnalysisDisplay();

    /// Split heavy post-parse UI into event-loop slices to avoid Windows "(Not Responding)".
    void analysisDisplayPhaseTree();
    void populateFindingsTab();
    void populateFindingsOverview();
    void applyFindingsFilter();
    QTreeWidgetItem *findPeTreeItemByFieldKey(const QString &fieldKey) const;
    void selectPeTreeItemForContext(QTreeWidgetItem *item);

    struct FieldHexRange {
        quint32 offset = 0;
        quint32 size = 0;
        bool canHighlight = false;
        bool canGoTo = false;
    };
    FieldHexRange resolveFieldHexRange(QTreeWidgetItem *item, const QString &fieldName) const;
    void applyFieldHexNavigation(QTreeWidgetItem *item, const FieldHexRange &range);
    void showFindingsInsightHtml(const QString &html);
    void analysisDisplayPhaseWelcomeOnly();
    void analysisDisplayPhaseHexSetData();
    void analysisDisplayPhaseStringsTab();
    void scheduleStagedAnalysisDisplay(const QString &pathGuard,
                                       std::function<void()> onComplete = nullptr,
                                       quint64 languageRefreshEpoch = 0);
    void populateImportFunctions(const QString &moduleName);
    void populateDelayImportFunctions(const QString &moduleName);
    void applyStringsFilter();  ///< Refill strings tree from m_extractedStrings using current filter
    
    // Utility functions
    void showError(const QString &title, const QString &message);
    void showInfo(const QString &title, const QString &message);
    QString getFileSizeString(qint64 size) const;

    // Full report generation (format choice: Text, HTML, JSON, XML)
    QString buildFullTextReport(const PEDataModel &dataModel) const;
    QString buildFullHTMLReport(const PEDataModel &dataModel) const;
    QString buildFullJSONReport(const PEDataModel &dataModel) const;
    QString buildFullXMLReport(const PEDataModel &dataModel) const;
    static QString escapeXml(const QString &str);
    
    void clearTreeHighlights();

    // Lazy tab population helpers
    void populateImportsTab();
    void populateDelayImportsTab();
    void populateExportsTab();
    void populateDependenciesTab();
    void populateStringsTab();

    /** Enable dependencies expand/collapse when the tree has top-level items */
    void updateDependenciesExpandCollapseButtonState();

    /// Full static + data refresh after LanguageManager loads a new INI
    void onApplicationLanguageChanged(const QString &languageCode);
    void refreshOpenFileAfterLanguageChange(quint64 languageRefreshEpoch);

    /** Cancel strings worker and wait so a stale finished() cannot race with setFuture(). */
    void stopStringsExtractionSynchronously();

    /// Dependencies tab: QTreeWidget gets the context menu event, not MainWindow.
    void onDependenciesCustomContextMenu(const QPoint &pos);
    
    // Context menu
    QMenu *m_contextMenu;
    void setupContextMenu();

    /// Exclusive checkmarks for Tools → Language items (Qt does not auto-uncheck siblings)
    QActionGroup *m_languageActionGroup;

    // Open recent menu
    QMenu *m_openRecentMenu;
    QStringList m_recentFiles;
    void loadRecentFiles();
    void saveRecentFiles() const;
    void updateOpenRecentMenu();
    void addToRecentFiles(const QString &filePath);
};

#endif // MAINWINDOW_H
