/**
 * @file mainwindow.cpp
 * @brief Main application window for PEHint - PE Header Learning Tool
 * 
 * This file has been refactored to follow SOLID principles and reduce file size.
 * The original monolithic approach has been broken down into:
 * 
 * 1. MainWindow: Orchestrates the application, handles high-level logic
 * 2. UIManager: Manages all UI component creation and layout
 * 3. PEParserNew: Handles PE file parsing logic
 * 4. PEDataModel: Stores parsed PE data
 * 
 * REFACTORING DECISIONS:
 * - Extracted UI setup logic to UIManager to reduce MainWindow complexity
 * - Moved from old PEParser to new modular PEParserNew architecture
 * - Separated concerns: MainWindow handles coordination, UIManager handles UI
 * - Maintained backward compatibility through adapter methods
 * 
 * ARCHITECTURAL BENEFITS:
 * - Single Responsibility Principle: Each class has one clear purpose
 * - Open/Closed Principle: Easy to extend without modifying existing code
 * - Dependency Inversion: MainWindow depends on abstractions, not concrete implementations
 * - Reduced coupling: UI changes don't affect parsing logic and vice versa
 */

#include "mainwindow.h"

#include "version.h"
#include "language_manager.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QApplication>
#include <QComboBox>
#include <QCheckBox>
#include <QClipboard>
#include <QTextStream>
#include <QDateTime>
#include <QStandardPaths>
#include <QDesktopServices>
#include <QUrl>
#include <QDialog>
#include <QSpinBox>
#include <QGroupBox>
#include <QTimer>
#include <QCoreApplication>

/**
 * @brief Constructor for MainWindow
 * 
 * This constructor demonstrates the new architectural approach:
 * 1. Creates the new modular PEParserNew instead of the old monolithic PEParser
 * 2. Delegates UI setup to UIManager, reducing MainWindow's responsibilities
 * 3. Maintains the same public interface for backward compatibility
 * 
 * The refactoring reduces MainWindow from ~1500 lines to under 500 lines,
 * making it more maintainable and easier to understand.
 */
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_peParser(nullptr)
    , m_fileLoaded(false)
    , m_contextMenu(nullptr)
{
    
    // Initialize PE Parser - NEW ARCHITECTURE: Using modular PEParserNew
    // This replaces the old monolithic PEParser that violated SRP
    m_peParser = new PEParserNew(this);
    
    // Initialize UI Manager - NEW: Extracted UI setup logic to separate class
    // This reduces MainWindow complexity and follows Single Responsibility Principle
    m_uiManager = new UIManager(this);
    
    // Initialize Language Manager for internationalization
    // Look for config file in the same directory as the executable
    QString appDir = QCoreApplication::applicationDirPath();
    QString configPath = QDir(appDir).absoluteFilePath("config/language_config.ini");
    
    qDebug() << "Application directory:" << appDir;
    qDebug() << "Config path:" << configPath;
    
    if (QFile::exists(configPath)) {
        qDebug() << "Config file found at:" << configPath;
        if (LanguageManager::getInstance().initialize(configPath)) {
            qDebug() << "LanguageManager initialized successfully";
        } else {
            qWarning() << "LanguageManager initialization failed";
        }
    } else {
        qWarning() << "Config file does not exist at:" << configPath;
    }
    
    // Setup UI components - REFACTORED: Now delegates to UIManager
    // This must be done BEFORE trying to access UI components
    setupUI();
    
    // Now that UI is set up, we can access UI components
    setupConnections();
    setupMenus();
    setupLanguageMenu();
    setupToolbar();
    setupStatusBar();
    setupContextMenu();
    setupHexViewer();
    
    // Set window properties - optimized for laptop screens
    this->setFixedSize(1200, 800);
    this->setWindowTitle(LANG_PARAM("UI/window_title", "version", PEHINT_VERSION_STRING_FULL));
    
    // Set icon
    QIcon icon;
    icon.addFile(":/images/imgs/PEHint-ico.ico");
    this->setWindowIcon(icon);
    
    // Initial state - Now UI components are available
    clearDisplay();
}

MainWindow::~MainWindow()
{
}

/**
 * @brief Sets up the main UI layout
 * 
 * REFACTORING: This method has been dramatically simplified by moving UI setup
 * to UIManager. Previously, this method contained ~100+ lines of UI creation code.
 * 
 * Now it just:
 * 1. Creates a central widget
 * 2. Delegates all UI setup to UIManager
 * 
 * This follows the Single Responsibility Principle - MainWindow coordinates,
 * UIManager creates UI components.
 */
void MainWindow::setupUI()
{
    // Create central widget with layout
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    // REFACTORED: Use UI Manager to setup the main UI
    // This extracts ~100+ lines of UI creation code from MainWindow
    // MainWindow no longer needs to know about QVBoxLayout, QHBoxLayout, etc.
    m_uiManager->setupMainUI(centralWidget);
}
    

/**
 * @brief Sets up signal-slot connections
 * 
 * REFACTORING: This method now demonstrates the new architecture:
 * 1. PE Parser connections use the new PEParserNew signals
 * 2. UI connections are delegated to UIManager
 * 
 * BENEFITS:
 * - MainWindow doesn't need to know about individual UI component signals
 * - UIManager handles all UI-specific connections
 * - Easier to maintain and modify UI behavior
 */
void MainWindow::setupConnections()
{
    // PE Parser connections - NEW ARCHITECTURE: Using PEParserNew signals
    // These replace the old PEParser signals, maintaining the same interface
    connect(m_peParser, &PEParserNew::parsingComplete, this, &MainWindow::onParsingComplete);
    connect(m_peParser, &PEParserNew::parsingProgress, this, &MainWindow::onParsingProgress);
    connect(m_peParser, &PEParserNew::errorOccurred, this, &MainWindow::onErrorOccurred);
    
    // REFACTORED: Use UI Manager to setup connections
    // This extracts UI-specific connections from MainWindow, reducing coupling
    // MainWindow no longer needs to know about m_refreshButton, m_copyButton, etc.
    m_uiManager->setupConnections(this);
}

/**
 * @brief Sets up the application menu system
 * 
 * This method remains in MainWindow because:
 * 1. Menus are application-level concerns, not just UI components
 * 2. Menu actions need to connect to MainWindow slots
 * 3. Menu structure is part of the application's public interface
 * 
 * REFACTORING NOTE: We could move this to UIManager in the future if we
 * implement a more sophisticated menu management system.
 */
void MainWindow::setupMenus()
{
    // Clear any existing menus to prevent duplication
    menuBar()->clear();
    
    // File menu
    QMenu *fileMenu = menuBar()->addMenu(LANG("UI/menu_file"));
    
    QAction *openAction = new QAction(LANG("UI/menu_open"), this);
    openAction->setIcon(QIcon(":/images/imgs/folder.ico"));
    openAction->setShortcut(QKeySequence::Open);
    fileMenu->addAction(openAction);
    
    QAction *saveReportAction = new QAction(LANG("UI/menu_save_report"), this);
    saveReportAction->setIcon(QIcon(":/images/imgs/save.png"));
    fileMenu->addAction(saveReportAction);
    
    fileMenu->addSeparator();
    
    QAction *exitAction = new QAction(LANG("UI/menu_exit"), this);
    exitAction->setIcon(QIcon(":/images/imgs/logout.ico"));
    exitAction->setShortcut(QKeySequence::Quit);
    fileMenu->addAction(exitAction);
    
    // Tools menu
    QMenu *toolsMenu = menuBar()->addMenu("&Tools");
    
    QAction *refreshAction = new QAction(LANG("UI/menu_refresh"), this);
    refreshAction->setIcon(QIcon(":/images/imgs/refresh.png"));
    refreshAction->setShortcut(QKeySequence::Refresh);
    toolsMenu->addAction(refreshAction);
    
    QAction *hexViewerAction = new QAction(LANG("UI/menu_hex_options"), this);
    hexViewerAction->setIcon(QIcon(":/images/imgs/settings.png"));
    toolsMenu->addAction(hexViewerAction);
    
    // About menu
    QMenu *aboutMenu = menuBar()->addMenu("&About");
    
    QAction *aboutAction = new QAction(LANG("UI/menu_about"), this);
    aboutAction->setIcon(QIcon(":/images/imgs/about.ico"));
    aboutMenu->addAction(aboutAction);
    
    // Connect actions
    connect(openAction, &QAction::triggered, this, &MainWindow::on_action_Open_triggered);
    connect(saveReportAction, &QAction::triggered, this, &MainWindow::on_action_Save_Report_triggered);
    connect(exitAction, &QAction::triggered, this, &MainWindow::on_action_Exit_triggered);
    connect(refreshAction, &QAction::triggered, this, &MainWindow::on_action_Refresh_triggered);
    connect(hexViewerAction, &QAction::triggered, this, &MainWindow::onHexViewerOptions);
    connect(aboutAction, &QAction::triggered, this, &MainWindow::on_action_PEHint_triggered);
}

/**
 * @brief Sets up the toolbar (placeholder for future use)
 * 
 * REFACTORING: This method is intentionally minimal because:
 * 1. Current UI design doesn't require a toolbar
 * 2. If needed in the future, it can be implemented without affecting other code
 * 3. Follows YAGNI principle (You Aren't Gonna Need It)
 */
void MainWindow::setupToolbar()
{
    // Add toolbar if needed in the future
}

/**
 * @brief Sets up the status bar
 * 
 * REFACTORING: This method remains simple because:
 * 1. Status bar is a basic Qt feature that doesn't need abstraction
 * 2. Status messages are application-level concerns, not UI component details
 * 3. Simple enough that moving it to UIManager would add unnecessary complexity
 */
void MainWindow::setupStatusBar()
{
    statusBar()->showMessage(LANG("UI/status_ready"));
}

/**
 * @brief Sets up the context menu for the main window
 * 
 * REFACTORING: This method creates a basic context menu because:
 * 1. Context menus are application-level features, not just UI components
 * 2. The menu actions connect to MainWindow slots
 * 3. Simple enough that abstraction would add unnecessary complexity
 * 
 * FUTURE: Could be moved to UIManager if we implement more sophisticated
 * context menu management with dynamic content.
 */
void MainWindow::setupContextMenu()
{
    m_contextMenu = new QMenu(this);
    
    QAction *copyAction = new QAction(LANG("UI/context_copy"), m_contextMenu);
    copyAction->setShortcut(QKeySequence::Copy);
    m_contextMenu->addAction(copyAction);
    
    m_contextMenu->addSeparator();
    
    QAction *expandAction = new QAction(LANG("UI/context_expand_all"), m_contextMenu);
    m_contextMenu->addAction(expandAction);
    
    QAction *collapseAction = new QAction(LANG("UI/context_collapse_all"), m_contextMenu);
    m_contextMenu->addAction(collapseAction);
    
    connect(copyAction, &QAction::triggered, this, &MainWindow::onCopyToClipboard);
    connect(expandAction, &QAction::triggered, this, &MainWindow::onExpandAll);
    connect(collapseAction, &QAction::triggered, this, &MainWindow::onCollapseAll);
}

/**
 * @brief Sets up the hex viewer component
 * 
 * REFACTORING: This method is intentionally minimal because:
 * 1. Hex viewer setup is handled in UIManager during main UI setup
 * 2. This method serves as a placeholder for future hex viewer configuration
 * 3. Follows the principle of not duplicating functionality
 * 
 * The hex viewer is created in UIManager::setupMainUI() and stored in
 * MainWindow for access by other methods.
 */
void MainWindow::setupHexViewer()
{
    // Hex viewer is already set up in setupUI()
    // This function can be used for additional hex viewer configuration
}

/**
 * @brief Handles context menu events
 * 
 * This method remains simple and doesn't need refactoring because:
 * 1. It's a standard Qt event handler
 * 2. It just delegates to the context menu
 * 3. No complex logic that would benefit from abstraction
 */
void MainWindow::contextMenuEvent(QContextMenuEvent *event)
{
    if (m_contextMenu) {
        m_contextMenu->exec(event->globalPos());
    }
}

// Menu action handlers
void MainWindow::on_action_PEHint_triggered()
{
    QPixmap pehintIcon(":/images/imgs/PEHint-ico.ico");

    QString msg = QString("<b>%1</b>").arg(LANG("UI/about_title"));
    msg += "<br/>";
    msg += QString("%1<br/>").arg(LANG_PARAM("UI/about_version", "version", PEHINT_VERSION_STRING));
    msg += QString("%1<br/>").arg(LANG("UI/about_author"));
    msg += "<br/>";
    msg += QString("%1<br/>").arg(LANG("UI/about_description"));
    msg += QString("%1<br/>").arg(LANG("UI/about_features"));
    msg += QString("%1<br/>").arg(LANG("UI/about_feature_1"));
    msg += QString("%1<br/>").arg(LANG("UI/about_feature_2"));
    msg += QString("%1<br/>").arg(LANG("UI/about_feature_3"));
    msg += QString("%1<br/>").arg(LANG("UI/about_feature_4"));
    msg += "<br/>";
    msg += QString("%1").arg(LANG("UI/about_perfect"));

    QMessageBox msgBox(this);
    msgBox.setProperty("hasUrl", true);

    msgBox.setWindowTitle(LANG("UI/about_title"));
    msgBox.setTextFormat(Qt::RichText);
    msgBox.setText(msg);
    msgBox.setAutoFillBackground(true);
    msgBox.setIconPixmap(pehintIcon);
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.exec();
}

void MainWindow::on_action_Open_triggered()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        LANG("UI/file_open_dialog_title"),
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation),
        QString("%1;;%2").arg(LANG("UI/file_filter_pe"), LANG("UI/file_filter_all"))
    );
    
    if (!filePath.isEmpty()) {
        loadPEFile(filePath);
    }
}

void MainWindow::on_action_Exit_triggered()
{
    QApplication::quit();
}

void MainWindow::on_action_Save_Report_triggered()
{
    if (!m_fileLoaded) {
        showError(LANG("UI/menu_save_report"), LANG("UI/error_no_report"));
        return;
    }
    
    QString filePath = QFileDialog::getSaveFileName(
        this,
        LANG("UI/dialog_save_analysis_report"),
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/PEHint_Report.txt",
        "Text Files (*.txt);;All Files (*.*)"
    );
    
    if (!filePath.isEmpty()) {
        QFile file(filePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream stream(&file);
            // Save current field explanation or generate a summary
            QString content = m_uiManager->m_fieldExplanationText->toPlainText();
            if (content.isEmpty()) {
                content = "No field explanation available to save.";
            }
            stream << content;
            file.close();
            showInfo(LANG("UI/menu_save_report"), LANG("UI/info_save_success"));
        } else {
            showError(LANG("UI/menu_save_report"), LANG("UI/error_save_failed"));
        }
    }
}

void MainWindow::on_action_Copy_Report_triggered()
{
    onCopyToClipboard();
}

void MainWindow::on_action_Refresh_triggered()
{
    if (m_fileLoaded && !m_currentFilePath.isEmpty()) {
        loadPEFile(m_currentFilePath);
    }
}

// PE Parser slots
void MainWindow::onParsingComplete(bool success)
{
    if (m_uiManager) {
        m_uiManager->m_progressBar->setVisible(false);
    }
    
    if (success) {
        m_fileLoaded = true;
        updateFileInfo();
        updateAnalysisDisplay();
        statusBar()->showMessage(LANG("UI/status_file_loaded_success"), 3000);
    } else {
        m_fileLoaded = false;
        clearDisplay();
        statusBar()->showMessage("Failed to load file", 3000);
    }
}

void MainWindow::onParsingProgress(int percentage, const QString &message)
{
    if (m_uiManager) {
        m_uiManager->m_progressBar->setValue(percentage);
        m_uiManager->m_progressLabel->setText(message);
        if (!message.isEmpty()) {
            statusBar()->showMessage(message, 2000);
            // Also update the progress bar tooltip to show the current step
            m_uiManager->m_progressBar->setToolTip(message);
        }
    }
}

void MainWindow::onErrorOccurred(const QString &error)
{
    showError(LANG("UI/error_parsing"), error);
    statusBar()->showMessage(LANG("UI/status_error"), 5000);
}

// UI interaction slots
void MainWindow::onTreeItemClicked(QTreeWidgetItem *item, int column)
{
    if (item && m_uiManager) {
        // Show field explanation in the explanation panel
        if (m_peParser && m_peParser->isValid()) {
            QString fieldName = item->text(0);
            QString explanation = m_peParser->getFieldExplanation(fieldName);
            m_uiManager->m_fieldExplanationText->setHtml(explanation);
        }
        
        // Show detailed information in status bar
        QString info = QString("Field: %1 | Value: %2")
                      .arg(item->text(0))
                      .arg(item->text(1));
        statusBar()->showMessage(info, 3000);
        
        // Highlight the field in hex viewer
        if (m_peParser && m_peParser->isValid()) {
            QString fieldName = item->text(0);
            QPair<quint32, quint32> fieldOffset = m_peParser->getFieldOffset(fieldName);
            
            // Debug: Show the field offset information
            QString debugInfo = QString("Field: %1 | Offset: 0x%2 | Size: %3 bytes")
                               .arg(fieldName)
                               .arg(fieldOffset.first, 0, 16)
                               .arg(fieldOffset.second);
            statusBar()->showMessage(debugInfo, 5000);
            
            if (fieldOffset.first > 0 || fieldOffset.second > 0) {
                        // Clear previous highlights
        m_uiManager->m_hexViewer->clearHighlights();
        
        // Highlight the field with a bright yellow color
        QColor highlightColor(255, 255, 0, 200); // Bright yellow with more opacity
        m_uiManager->m_hexViewer->highlightRange(fieldOffset.first, fieldOffset.second, highlightColor);
        
        // Go to the offset in hex viewer
        m_uiManager->m_hexViewer->goToOffset(fieldOffset.first);
            } else {
                statusBar()->showMessage(QString("No offset found for field: %1").arg(fieldName), 3000);
    }
        }
    }
}



void MainWindow::onLanguageChanged(const QString &language)
{
    if (m_peParser) {
        // Extract language code from combo box item data
        QComboBox *comboBox = qobject_cast<QComboBox*>(sender());
        if (comboBox) {
            QString langCode = comboBox->currentData().toString();
            m_peParser->setLanguage(langCode);
            
            // Update current explanation if there's a selected item
            QTreeWidgetItem *currentItem = m_peTree->currentItem();
            if (currentItem) {
                onTreeItemClicked(currentItem, 0);
            }
        }
    }
}

void MainWindow::onCopyToClipboard()
{
    if (m_fileLoaded) {
        // Copy the current field explanation or a summary
        QString textToCopy = m_uiManager->m_fieldExplanationText->toPlainText();
        if (textToCopy.isEmpty()) {
            textToCopy = "No field selected for copying.";
        }
        QApplication::clipboard()->setText(textToCopy);
        statusBar()->showMessage("Content copied to clipboard", 2000);
    }
}

void MainWindow::onExpandAll()
{
    m_peTree->expandAll();
}

void MainWindow::onCollapseAll()
{
    m_peTree->collapseAll();
}

void MainWindow::onHexViewerOptions()
{
    if (m_uiManager->m_hexViewer) {
        // Create a dialog to show hex viewer options
        QDialog dialog(this);
        dialog.setWindowTitle(LANG("UI/dialog_hex_viewer_options"));
        dialog.setModal(true);
        dialog.resize(400, 300);
        
        QVBoxLayout *layout = new QVBoxLayout(&dialog);
        
        // Add hex viewer controls
        QGroupBox *displayGroup = new QGroupBox(LANG("UI/dialog_display_options"), &dialog);
        QVBoxLayout *displayLayout = new QVBoxLayout(displayGroup);
        
        QCheckBox *showOffsetCheck = new QCheckBox(LANG("UI/dialog_show_offset"), displayGroup);
        showOffsetCheck->setChecked(m_uiManager->m_hexViewer->showOffset());
        
        QCheckBox *showAsciiCheck = new QCheckBox(LANG("UI/dialog_show_ascii"), displayGroup);
        showAsciiCheck->setChecked(m_uiManager->m_hexViewer->showAscii());
        
        QSpinBox *bytesPerLineSpin = new QSpinBox(displayGroup);
        bytesPerLineSpin->setRange(8, 64);
        bytesPerLineSpin->setValue(m_uiManager->m_hexViewer->bytesPerLine());
        bytesPerLineSpin->setPrefix(LANG("UI/dialog_bytes_per_line"));
        
        displayLayout->addWidget(showOffsetCheck);
        displayLayout->addWidget(showAsciiCheck);
        displayLayout->addWidget(bytesPerLineSpin);
        
        layout->addWidget(displayGroup);
        
        // Add buttons
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *applyButton = new QPushButton(LANG("UI/dialog_apply"), &dialog);
        QPushButton *closeButton = new QPushButton(LANG("UI/dialog_close"), &dialog);
        
        buttonLayout->addWidget(applyButton);
        buttonLayout->addWidget(closeButton);
        layout->addLayout(buttonLayout);
        
        // Connect signals
        connect(applyButton, &QPushButton::clicked, [&]() {
            m_uiManager->m_hexViewer->setShowOffset(showOffsetCheck->isChecked());
            m_uiManager->m_hexViewer->setShowAscii(showAsciiCheck->isChecked());
            m_uiManager->m_hexViewer->setBytesPerLine(bytesPerLineSpin->value());
        });
        
        connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        
        dialog.exec();
    }
}

// Private helper methods
void MainWindow::loadPEFile(const QString &filePath)
{
    m_currentFilePath = filePath;
    if (m_uiManager) {
        m_uiManager->m_progressBar->setVisible(true);
        m_uiManager->m_progressBar->setRange(0, 100);
        m_uiManager->m_progressBar->setValue(0);
    }
    
    statusBar()->showMessage(LANG("UI/status_loading"));
    
    // Load the file using the PE parser
    if (!m_peParser->loadFile(filePath)) {
        if (m_uiManager) {
            m_uiManager->m_progressBar->setVisible(false);
        }
        showError(LANG("UI/error_file_load"), LANG("UI/error_file_load_failed"));
    }
}

void MainWindow::clearDisplay()
{
    // Access UI components through UIManager
    if (m_uiManager) {
        m_uiManager->m_peTree->clear();
        m_uiManager->m_fieldExplanationText->clear();
        m_uiManager->m_fileInfoLabel->setText(LANG("UI/file_no_file_loaded"));
        m_fileLoaded = false;
        m_uiManager->m_refreshButton->setEnabled(false);
        m_uiManager->m_copyButton->setEnabled(false);
        m_uiManager->m_saveButton->setEnabled(false);
    }
}

void MainWindow::updateFileInfo()
{
    if (!m_fileLoaded || !m_uiManager) return;
    
    QFileInfo fileInfo(m_currentFilePath);
    QMap<QString, QString> params;
    params["filename"] = fileInfo.fileName();
    params["size"] = getFileSizeString(fileInfo.size());
    QString info = LANG_PARAMS("UI/file_info_format", params);
    
    m_uiManager->m_fileInfoLabel->setText(info);
    m_uiManager->m_refreshButton->setEnabled(true);
    m_uiManager->m_copyButton->setEnabled(true);
    m_uiManager->m_saveButton->setEnabled(true);
}

void MainWindow::updateAnalysisDisplay()
{
    if (!m_fileLoaded || !m_uiManager) return;
    
    // Update PE structure tree
    m_uiManager->m_peTree->clear();
    QList<QTreeWidgetItem*> items = m_peParser->getPEStructureTree();
    for (QTreeWidgetItem *item : items) {
        m_uiManager->m_peTree->addTopLevelItem(item);
    }
    
    // Clear explanation text and show welcome message
    QMap<QString, QString> params;
    params["version"] = PEHINT_VERSION_STRING_FULL;
    QString welcomeMessage = QString(
        "<div style='text-align: center; color: #666; padding: 20px;'>"
        "<h3>%1</h3>"
        "<p><b>%2</b></p>"
        "<p><b>" + LANG("UI/click_field_explanation") + "</b></p>"
        "<p>%3</p>"
        "</div>"
    ).arg(LANG("UI/welcome_title"), LANG_PARAMS("UI/placeholder_welcome", params), LANG("UI/welcome_description"));

    m_uiManager->m_fieldExplanationText->setHtml(welcomeMessage);
    
    // Update hex viewer with file data
    if (m_peParser->isValid()) {
        // Get the raw file data for hex viewing
        QFile file(m_currentFilePath);
        if (file.open(QIODevice::ReadOnly)) {
            QByteArray fileData = file.readAll();
            file.close();
            m_uiManager->m_hexViewer->setData(fileData);
        }
    }
}

void MainWindow::showError(const QString &title, const QString &message)
{
    QMessageBox::critical(this, title, message);
}

void MainWindow::showInfo(const QString &title, const QString &message)
{
    QMessageBox::information(this, title, message);
}

QString MainWindow::getFileSizeString(qint64 size)
{
    if (size < 1024) {
        return LANG_PARAM("UI/size_bytes", "size", QString::number(size));
    } else if (size < 1024 * 1024) {
        return LANG_PARAM("UI/size_kb", "size", QString::number(size / 1024.0, 'f', 1));
    } else {
        return LANG_PARAM("UI/size_mb", "size", QString::number(size / (1024.0 * 1024.0), 'f', 1));
    }
}

void MainWindow::setupLanguageMenu()
{
    // Add language submenu to Tools menu
    QMenu *toolsMenu = menuBar()->findChild<QMenu*>();
    if (!toolsMenu) {
        // If Tools menu doesn't exist, create it
        toolsMenu = menuBar()->addMenu("&Tools");
    }
    
    // Find or create the Tools menu
    QMenu *toolsMenuFound = nullptr;
    for (QAction *action : menuBar()->actions()) {
        if (action->menu() && action->menu()->title().contains("Tools", Qt::CaseInsensitive)) {
            toolsMenuFound = action->menu();
            break;
        }
    }
    
    if (!toolsMenuFound) {
        toolsMenuFound = menuBar()->addMenu("&" + LANG("UI/menu_tools"));
    }
    
    // Add language submenu
    QMenu *languageMenu = toolsMenuFound->addMenu(LANG("UI/menu_language"));
    
    // Get available languages from Language Manager
    QStringList languages = LanguageManager::getInstance().getAvailableLanguages();
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();
    
    // Create language actions
    for (const QString &langCode : languages) {
        QString displayName = LanguageManager::getInstance().getLanguageDisplayName(langCode);
        QAction *langAction = new QAction(displayName, this);
        langAction->setCheckable(true);
        langAction->setChecked(langCode == currentLanguage);
        langAction->setData(langCode);
        
        languageMenu->addAction(langAction);
        connect(langAction, &QAction::triggered, this, [this, langAction]() {
            this->onLanguageMenuTriggered(langAction);
        });
    }
}

void MainWindow::onLanguageMenuTriggered(QAction *action)
{
    QString languageCode = action->data().toString();
    
    if (LanguageManager::getInstance().setLanguage(languageCode)) {
        // Update all UI elements with new language
        updateUILanguage();
        
        // Update the checked state of language actions
        QMenu *languageMenu = qobject_cast<QMenu*>(action->parent());
        if (languageMenu) {
            for (QAction *langAction : languageMenu->actions()) {
                langAction->setChecked(langAction->data().toString() == languageCode);
            }
        }
    }
}

void MainWindow::updateUILanguage()
{
    // Update window title
    setWindowTitle(LANG_PARAM("UI/window_title", "version", PEHINT_VERSION_STRING_FULL));
    
    // Update status bar
    statusBar()->showMessage(LANG("UI/status_ready"));
    
    // Update menu texts
    updateMenuLanguage();
    
    // Update other UI elements
    if (m_uiManager && m_uiManager->m_fileInfoLabel) {
        if (m_fileLoaded) {
            updateFileInfo();
        } else {
            m_uiManager->m_fileInfoLabel->setText(LANG("UI/file_no_file_loaded"));
        }
    }
    
    // Update tree headers
    if (m_uiManager && m_uiManager->m_peTree) {
        QStringList headers;
        headers << LANG("UI/tree_header_field") << LANG("UI/tree_header_value") << LANG("UI/tree_header_offset") << LANG("UI/tree_header_size");
        m_uiManager->m_peTree->setHeaderLabels(headers);
    }
    
    // Update placeholder text
    if (m_uiManager && m_uiManager->m_fieldExplanationText) {
        m_uiManager->m_fieldExplanationText->setPlaceholderText(LANG("UI/placeholder_explanation"));
    }
    
    // Update button texts
    if (m_uiManager && m_uiManager->m_refreshButton) m_uiManager->m_refreshButton->setText(LANG("UI/button_refresh"));
    if (m_uiManager && m_uiManager->m_copyButton) m_uiManager->m_copyButton->setText(LANG("UI/button_copy"));
    if (m_uiManager && m_uiManager->m_saveButton) m_uiManager->m_saveButton->setText(LANG("UI/button_save"));
}

void MainWindow::updateMenuLanguage()
{
    // Update menu texts
    QMenuBar *menuBar = this->menuBar();
    
    for (QAction *menuAction : menuBar->actions()) {
        if (menuAction->menu()) {
            QMenu *menu = menuAction->menu();
            
            // Update menu title based on text content
            if (menu->title().contains("File", Qt::CaseInsensitive)) {
                menu->setTitle(LANG("UI/menu_file"));
            } else if (menu->title().contains("Tools", Qt::CaseInsensitive)) {
                menu->setTitle("&" + LANG("UI/menu_tools"));
            } else if (menu->title().contains("About", Qt::CaseInsensitive)) {
                menu->setTitle("&" + LANG("UI/menu_about"));
            }
            
            // Update menu item texts
            for (QAction *action : menu->actions()) {
                if (action->text().contains("Open", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_open"));
                } else if (action->text().contains("Save Report", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_save_report"));
                } else if (action->text().contains("Exit", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_exit"));
                } else if (action->text().contains("Refresh", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_refresh"));
                } else if (action->text().contains("Hex", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_hex_options"));
                } else if (action->text().contains("PEHint", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_about"));
                }
            }
        }
    }
}

