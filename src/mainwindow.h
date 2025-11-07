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
#include <QContextMenuEvent>
#include <QTimer>
#include <QColor>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>



#include "pe_parser_new.h"
#include "hexviewer.h"
#include "pe_ui_manager.h"
#include "pe_security_analyzer.h"

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
    void onHexViewerOptions();
    void onSecurityAnalysis();
    
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
    
    // Security Analyzer
    PESecurityAnalyzer *m_securityAnalyzer;
    
    // UI Manager
    UIManager *m_uiManager;
    
    // UI Components (now managed by UIManager)
    // HexViewer is now managed by UIManager
    // Access it via m_uiManager->m_hexViewer
    // m_peTree is managed by UIManager
    
    // Current file info
    QString m_currentFilePath;
    bool m_fileLoaded;
    

    
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
    
    // Utility functions
    void showError(const QString &title, const QString &message);
    void showInfo(const QString &title, const QString &message);
    QString getFileSizeString(qint64 size);
    
    // Security analysis
    void highlightSuspiciousSections(const SecurityAnalysisResult &result);
    void highlightSuspiciousFieldsInTree(const SecurityAnalysisResult &result);
    void clearTreeHighlights();
    
    // Context menu
    QMenu *m_contextMenu;
    void setupContextMenu();
};

#endif // MAINWINDOW_H
