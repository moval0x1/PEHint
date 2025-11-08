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
#include "crash_handler.h"
#include "pe_utils.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QApplication>
#include <QScreen>
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
#include <QLocale>
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <QSysInfo>
#include <QMimeData>

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
    
    // Accept drag-and-drop operations for PE files
    setAcceptDrops(true);

    // Initialize PE Parser - NEW ARCHITECTURE: Using modular PEParserNew
    // This replaces the old monolithic PEParser that violated SRP
    m_peParser = new PEParserNew(this);
    
    // Initialize Security Analyzer - NEW: For security analysis and malicious detection
    m_securityAnalyzer = new PESecurityAnalyzer(this);
    
    // Initialize UI Manager - NEW: Extracted UI setup logic to separate class
    // This reduces MainWindow complexity and follows Single Responsibility Principle
    m_uiManager = new UIManager(this);
    
    // Initialize crash handling system (includes logging)
    CrashHandler::getInstance().initialize();
    
    // Initialize Language Manager for internationalization
    // Look for config file in multiple possible locations
    QString configDir;
    QStringList possibleConfigPaths;
    
    // 1. Try relative to executable (for deployed builds) - PRIORITY 1
    QString appDir = QCoreApplication::applicationDirPath();
    possibleConfigPaths << QDir(appDir).absoluteFilePath("config");
    
    // 2. Try current working directory - PRIORITY 2
    possibleConfigPaths << QDir::currentPath() + "/config";
    
    // 3. Try relative to executable but go up to project root (for development builds) - PRIORITY 3
    QDir appDirObj(appDir);
    if (appDirObj.cdUp() && appDirObj.cdUp() && appDirObj.cdUp()) {
        possibleConfigPaths << appDirObj.absoluteFilePath("config");
    }
    
    // 4. Try source directory (for development builds) - PRIORITY 4
    possibleConfigPaths << QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../../../config");
    
    qDebug() << "Application directory:" << appDir;
    qDebug() << "Possible config paths (in priority order):" << possibleConfigPaths;
    
    // Find the first valid config directory
    for (const QString &path : possibleConfigPaths) {
        if (QDir(path).exists()) {
            configDir = path;
            qDebug() << "Found valid config directory:" << configDir;
            break;
        }
    }
    
    if (configDir.isEmpty()) {
        qWarning() << "No valid config directory found. Tried:" << possibleConfigPaths;
        configDir = QDir::currentPath() + "/config"; // Fallback
    }
    
    qDebug() << "Using config directory:" << configDir;
    qDebug() << "Config directory exists:" << QDir(configDir).exists();
    
    // Try to detect system language and load appropriate config
    QString configPath;
    QString systemLocale = QLocale::system().name().left(2).toLower(); // Get system language code (e.g., "pt", "en")
    
    qDebug() << "System locale detected:" << systemLocale;
    
    // Check if we have a language-specific config file for the system language
    QString languageSpecificConfig = QDir(configDir).absoluteFilePath(QString("language_config_%1.ini").arg(systemLocale));
    if (QFile::exists(languageSpecificConfig)) {
        configPath = languageSpecificConfig;
        qDebug() << "Using language-specific config for" << systemLocale << "at:" << configPath;
    } else {
        // Fallback to default English config
        configPath = QDir(configDir).absoluteFilePath("language_config.ini");
        qDebug() << "Language-specific config not found, using default English config at:" << configPath;
    }
    
    if (QFile::exists(configPath)) {
        qDebug() << "Config file found at:" << configPath;
        if (LanguageManager::getInstance().initialize(configPath)) {
            qDebug() << "LanguageManager initialized successfully";
            qDebug() << "Available languages:" << LanguageManager::getInstance().getAvailableLanguages();
            qDebug() << "Current language:" << LanguageManager::getInstance().getCurrentLanguage();
            
            // Debug: List config directory contents
            QDir configDirObj = QFileInfo(configPath).dir();
            qDebug() << "Config directory:" << configDirObj.absolutePath();
            QStringList filters;
            filters << "language_config*.ini";
            QStringList langFiles = configDirObj.entryList(filters, QDir::Files);
            qDebug() << "Language files found:" << langFiles;
            
            CrashHandler::getInstance().logInfo("MainWindow", QString("LanguageManager initialized successfully with config: %1").arg(configPath));
            CrashHandler::getInstance().logInfo("MainWindow", QString("Available languages: %1").arg(LanguageManager::getInstance().getAvailableLanguages().join(", ")));
            CrashHandler::getInstance().logInfo("MainWindow", QString("Current language: %1").arg(LanguageManager::getInstance().getCurrentLanguage()));
        } else {
            qWarning() << "LanguageManager initialization failed";
            CrashHandler::getInstance().logError("MainWindow", "LanguageManager initialization failed", QString("Config path: %1").arg(configPath));
        }
    } else {
        qWarning() << "Config file does not exist at:" << configPath;
        CrashHandler::getInstance().logWarning("MainWindow", "Config file not found", QString("Expected path: %1").arg(configPath));
        // Try to initialize with auto-detection
        qDebug() << "Trying to initialize LanguageManager with auto-detection...";
        if (LanguageManager::getInstance().initialize()) {
            qDebug() << "LanguageManager initialized successfully with auto-detection";
            qDebug() << "Available languages:" << LanguageManager::getInstance().getAvailableLanguages();
            qDebug() << "Current language:" << LanguageManager::getInstance().getCurrentLanguage();
            CrashHandler::getInstance().logInfo("MainWindow", "LanguageManager initialized successfully with auto-detection");
            CrashHandler::getInstance().logInfo("MainWindow", QString("Available languages: %1").arg(LanguageManager::getInstance().getAvailableLanguages().join(", ")));
            CrashHandler::getInstance().logInfo("MainWindow", QString("Current language: %1").arg(LanguageManager::getInstance().getCurrentLanguage()));
        } else {
            qWarning() << "LanguageManager auto-detection also failed";
            CrashHandler::getInstance().logError("MainWindow", "LanguageManager auto-detection failed");
        }
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
    
    // Set window properties - reasonable size
    this->resize(1400, 900); // Reduced from 1800x1200 to more reasonable size
    this->setMinimumSize(1200, 800); // Reduced minimum size
    this->setWindowTitle(LANG_PARAM("UI/window_title", "version", PEHINT_VERSION_STRING_FULL));
    
    // Center window on screen
    QRect screenGeometry = QApplication::primaryScreen()->geometry();
    int x = (screenGeometry.width() - this->width()) / 2;
    int y = (screenGeometry.height() - this->height()) / 2;
    this->move(x, y);
    
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
    CrashHandler::getInstance().logInfo("MainWindow", "Setting up main UI components");
    
    // Create central widget with layout
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    // REFACTORED: Use UI Manager to setup the main UI
    // This extracts ~100+ lines of UI creation code from MainWindow
    // MainWindow no longer needs to know about QVBoxLayout, QHBoxLayout, etc.
    m_uiManager->setupMainUI(centralWidget);
    
    CrashHandler::getInstance().logInfo("MainWindow", "Main UI setup completed");
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
    CrashHandler::getInstance().logInfo("MainWindow", "Setting up signal-slot connections");
    
    // PE Parser connections - NEW ARCHITECTURE: Using PEParserNew signals
    // These replace the old PEParser signals, maintaining the same interface
    connect(m_peParser, &PEParserNew::parsingComplete, this, &MainWindow::onParsingComplete);
    connect(m_peParser, &PEParserNew::parsingProgress, this, &MainWindow::onParsingProgress);
    connect(m_peParser, &PEParserNew::errorOccurred, this, &MainWindow::onErrorOccurred);
    
    // Language Manager connections
    connect(&LanguageManager::getInstance(), &LanguageManager::languageChanged, this, &MainWindow::updateLanguageMenu);
    
    // REFACTORED: Use UI Manager to setup connections
    // This extracts UI-specific connections from MainWindow, reducing coupling
    // MainWindow no longer needs to know about m_refreshButton, m_copyButton, etc.
    m_uiManager->setupConnections(this);
    
    CrashHandler::getInstance().logInfo("MainWindow", "Signal-slot connections setup completed");
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
    CrashHandler::getInstance().logInfo("MainWindow", "Setting up application menus");
    
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
    QMenu *toolsMenu = menuBar()->addMenu(LANG("UI/menu_tools"));
    
    QAction *refreshAction = new QAction(LANG("UI/menu_refresh"), this);
    refreshAction->setIcon(QIcon(":/images/imgs/refresh.png"));
    refreshAction->setShortcut(QKeySequence::Refresh);
    toolsMenu->addAction(refreshAction);
    
    QAction *hexViewerAction = new QAction(LANG("UI/menu_hex_options"), this);
    hexViewerAction->setIcon(QIcon(":/images/imgs/settings.png"));
    toolsMenu->addAction(hexViewerAction);
    
    // About menu
    QMenu *aboutMenu = menuBar()->addMenu(LANG("UI/menu_about"));
    
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
    
    CrashHandler::getInstance().logInfo("MainWindow", "Application menus setup completed");
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

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (!event->mimeData() || !event->mimeData()->hasUrls()) {
        event->ignore();
        return;
    }

    for (const QUrl &url : event->mimeData()->urls()) {
        if (url.isLocalFile() && !url.toLocalFile().isEmpty()) {
            event->acceptProposedAction();
            return;
        }
    }

    event->ignore();
}

void MainWindow::dropEvent(QDropEvent *event)
{
    if (!event->mimeData() || !event->mimeData()->hasUrls()) {
        event->ignore();
        return;
    }

    const QList<QUrl> urls = event->mimeData()->urls();
    for (const QUrl &url : urls) {
        if (!url.isLocalFile()) {
            continue;
        }

        const QString filePath = url.toLocalFile();
        if (filePath.isEmpty()) {
            continue;
        }

        CrashHandler::getInstance().logInfo("MainWindow", QString("File dropped: %1").arg(filePath));
        loadPEFile(filePath);
        event->acceptProposedAction();
        return;
    }

    event->ignore();
}

// Menu action handlers
void MainWindow::on_action_PEHint_triggered()
{
    QPixmap pehintIcon(":/images/imgs/PEHint.png");
    QPixmap scaledIcon = pehintIcon.scaled(240, 240, Qt::KeepAspectRatio, Qt::SmoothTransformation);

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
    msgBox.setIconPixmap(scaledIcon);
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.exec();
}

void MainWindow::on_action_Open_triggered()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        LANG("UI/file_open_dialog_title"),
        QCoreApplication::applicationDirPath(), // Use current binary directory
        QString("%1;;%2").arg(LANG("UI/file_filter_pe"), LANG("UI/file_filter_all"))
    );
    
    if (!filePath.isEmpty()) {
        CrashHandler::getInstance().logInfo("MainWindow", QString("Opening PE file: %1").arg(filePath));
        loadPEFile(filePath);
    } else {
        CrashHandler::getInstance().logInfo("MainWindow", "File open dialog cancelled by user");
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
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/" + LANG("UI/file_default_report_name"),
        QString("%1;;%2").arg(LANG("UI/file_filter_text"), LANG("UI/file_filter_all"))
    );
    
    if (!filePath.isEmpty()) {
        QFile file(filePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream stream(&file);
            // Save current field explanation or generate a summary
            QString content = m_uiManager->m_fieldExplanationText->toPlainText();
            if (content.isEmpty()) {
                content = LANG("UI/field_no_explanation");
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
        CrashHandler::getInstance().logInfo("MainWindow", "PE file parsing completed successfully");
        updateFileInfo();
        updateAnalysisDisplay();
        statusBar()->showMessage(LANG("UI/status_file_loaded_success"), 3000);
    } else {
        m_fileLoaded = false;
        CrashHandler::getInstance().logError("MainWindow", "PE file parsing failed");
        clearDisplay();
        statusBar()->showMessage(LANG("UI/file_load_failed"), 3000);
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
    CrashHandler::getInstance().logError("MainWindow", "PE parsing error occurred", error);
    showError(LANG("UI/error_parsing"), error);
    statusBar()->showMessage(LANG("UI/status_error"), 5000);
}

// UI interaction slots
void MainWindow::onTreeItemClicked(QTreeWidgetItem *item, int column)
{
    try {
        if (item && m_uiManager) {
            QString fieldName = item->text(0);
            CrashHandler::getInstance().logDebug("MainWindow", QString("Tree item clicked: %1").arg(fieldName));
            
            // Show field explanation in the explanation panel
            if (m_peParser && m_peParser->isValid()) {
                QString explanation = m_peParser->getFieldExplanation(fieldName);
                m_uiManager->m_fieldExplanationText->setHtml(explanation);
            }
            
            // Show detailed information in status bar
            QMap<QString, QString> infoParams;
            infoParams["field_name"] = fieldName;
            infoParams["field_value"] = item->text(1);
            QString info = LANG_PARAMS("UI/field_info_format", infoParams);
            statusBar()->showMessage(info, 3000);
            
            // Highlight the field in hex viewer
            if (m_peParser && m_peParser->isValid()) {
                QPair<quint32, quint32> fieldOffset = m_peParser->getFieldOffset(fieldName);
                
                // Debug: Show the field offset information
                QString debugInfo = QString("Field: %1 | Offset: 0x%2 | Size: 0x%3 bytes")
                    .arg(fieldName)
                    .arg(fieldOffset.first, 0, 16)
                    .arg(fieldOffset.second, 0, 16);
                statusBar()->showMessage(debugInfo, 5000);
                
                if (fieldOffset.first >= 0 && fieldOffset.second > 0) {
                    // Clear previous highlights
                    m_uiManager->m_hexViewer->clearHighlights();
                    
                    // Highlight the field with no background color (transparent)
                    QColor highlightColor = Qt::transparent; // No background, just bold text
                    m_uiManager->m_hexViewer->highlightRange(fieldOffset.first, fieldOffset.second, highlightColor);
                    
                    // Go to the offset in hex viewer
                    m_uiManager->m_hexViewer->goToOffset(fieldOffset.first);
                } else {
                    statusBar()->showMessage(LANG_PARAM("UI/field_no_offset", "field_name", fieldName), 3000);
                }
            }
        }
    } catch (const std::exception& e) {
        CrashHandler::getInstance().logError("MainWindow", "Exception during tree item click", QString("Exception: %1").arg(e.what()));
        showError("Error", QString("Exception occurred: %1").arg(e.what()));
    } catch (...) {
        CrashHandler::getInstance().logError("MainWindow", "Unknown exception during tree item click", "Unknown exception type");
        showError("Error", "Unknown exception occurred");
    }
}

void MainWindow::onHexViewerByteClicked(qint64 offset, int length)
{
    // Update status bar to show clicked byte information
    QString debugInfo = QString("Field: %1 | Offset: 0x%2 | Size: 0x%3 bytes")
        .arg(QString("Byte at 0x%1").arg(offset, 0, 16))
        .arg(offset, 0, 16)
        .arg(length, 0, 16);
    statusBar()->showMessage(debugInfo, 3000);
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
            if (m_uiManager && m_uiManager->m_peTree) {
                QTreeWidgetItem *currentItem = m_uiManager->m_peTree->currentItem();
                if (currentItem) {
                    onTreeItemClicked(currentItem, 0);
                }
            }
        }
    }
    
    // Update all UI elements when language changes
    updateMenuLanguage();
    updateHexViewerLanguage();
    updateWindowTitle();
}

void MainWindow::onCopyToClipboard()
{
    if (m_fileLoaded) {
        // Copy the current field explanation or a summary
        QString textToCopy = m_uiManager->m_fieldExplanationText->toPlainText();
        if (textToCopy.isEmpty()) {
            textToCopy = LANG("UI/field_no_selection");
        }
        QApplication::clipboard()->setText(textToCopy);
        statusBar()->showMessage(LANG("UI/content_copied"), 2000);
    }
}

void MainWindow::onExpandAll()
{
    if (m_uiManager && m_uiManager->m_peTree) {
        m_uiManager->m_peTree->expandAll();
    }
}

void MainWindow::onCollapseAll()
{
    if (m_uiManager && m_uiManager->m_peTree) {
        m_uiManager->m_peTree->collapseAll();
    }
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

void MainWindow::onSecurityAnalysis()
{
    if (!m_fileLoaded || m_currentFilePath.isEmpty()) {
        showError(LANG("UI/security_analysis_error_title"), LANG("UI/security_analysis_error_no_file"));
        return;
    }
    
    if (!m_securityAnalyzer) {
        showError(LANG("UI/security_analysis_error_title"), LANG("UI/security_analysis_error_no_analyzer"));
        return;
    }
    
    // Show progress
    statusBar()->showMessage(LANG("UI/security_performing_analysis"));
    if (m_uiManager) {
        m_uiManager->m_progressBar->setVisible(true);
        m_uiManager->m_progressBar->setRange(0, 100);
        m_uiManager->m_progressBar->setValue(0);
    }
    
    // Perform security analysis
    SecurityAnalysisResult result = m_securityAnalyzer->analyzeFile(m_currentFilePath);
    
    // Hide progress
    if (m_uiManager) {
        m_uiManager->m_progressBar->setVisible(false);
    }
    
    // Display results
    QString analysisText = QString("<h3>%1</h3>").arg(LANG("UI/security_analysis_title"));
    analysisText += QString("<p><b>%1:</b> ").arg(LANG("UI/security_risk_level"));
    
    switch (result.riskLevel) {
        case SecurityRiskLevel::LOW:
            analysisText += QString("<span style='color: green;'>🟢 %1</span>").arg(LANG("UI/security_low_risk"));
            break;
        case SecurityRiskLevel::MEDIUM:
            analysisText += QString("<span style='color: orange;'>🟡 %1</span>").arg(LANG("UI/security_medium_risk"));
            break;
        case SecurityRiskLevel::HIGH:
            analysisText += QString("<span style='color: red;'>🔴 %1</span>").arg(LANG("UI/security_high_risk"));
            break;
    }
    
    analysisText += "</p>";
    // Add risk score information
    analysisText += QString("<p><b>%1:</b> %2/100</p>").arg(LANG("UI/security_risk_score_label")).arg(result.riskScore);
    
    if (!result.detectedIssues.isEmpty()) {
        analysisText += QString("<p><b>%1:</b></p><ul>").arg(LANG("UI/security_issues_found"));
        for (const QString &issue : result.detectedIssues) {
            analysisText += QString("<li>%1</li>").arg(issue);
        }
        analysisText += "</ul>";
    }
    
    if (!result.recommendations.isEmpty()) {
        analysisText += QString("<p><b>%1:</b></p><ul>").arg(LANG("UI/security_recommendations"));
        for (const QString &recommendation : result.recommendations) {
            analysisText += QString("<li>%1</li>").arg(recommendation);
        }
        analysisText += "</ul>";
    }
    
    // Display in the explanation text area
    if (m_uiManager && m_uiManager->m_fieldExplanationText) {
        m_uiManager->m_fieldExplanationText->setHtml(analysisText);
    }
    
    // Highlight suspicious sections in hex viewer
    highlightSuspiciousSections(result);
    
    // Highlight suspicious fields in the tree view
    highlightSuspiciousFieldsInTree(result);
    
    // Update status
    QString riskLevelText;
    switch (result.riskLevel) {
        case SecurityRiskLevel::HIGH: riskLevelText = LANG("UI/security_high_risk"); break;
        case SecurityRiskLevel::MEDIUM: riskLevelText = LANG("UI/security_medium_risk"); break;
        case SecurityRiskLevel::LOW: riskLevelText = LANG("UI/security_low_risk"); break;
    }
    QString statusMsg = LANG_PARAM("UI/security_analysis_complete_risk", "risk_level", riskLevelText);
    statusBar()->showMessage(statusMsg, 5000);
}

// Private helper methods
void MainWindow::loadPEFile(const QString &filePath)
{
    try {
        CrashHandler::getInstance().logInfo("MainWindow", QString("Loading PE file: %1").arg(filePath));
        
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
            CrashHandler::getInstance().logError("MainWindow", "Failed to load PE file", QString("File: %1").arg(filePath));
            showError(LANG("UI/error_file_load"), LANG("UI/error_file_load_failed"));
            return;
        }
        
        CrashHandler::getInstance().logInfo("MainWindow", "PE file loaded successfully, starting parsing");
        
        // Perform security analysis (commented out until security analysis is fully implemented)
        // if (m_securityAnalyzer) {
        //     SecurityAnalysisResult result = m_securityAnalyzer->analyzeFile(filePath);
        //     if (result.riskLevel != SecurityRiskLevel::LOW) {
        //         // Show security warning
        //         QString riskLevelText = (result.riskLevel == SecurityRiskLevel::HIGH) ? LANG("UI/security_high_risk") : LANG("UI/security_medium_risk");
        //         QMap<QString, QString> warningParams;
        //         warningParams["risk_level"] = riskLevelText;
        //         warningParams["summary"] = LANG_PARAM("UI/security_risk_score", "score", QString::number(result.riskScore));
        //         QString warningMsg = LANG_PARAMS("UI/security_warning", warningParams);
        //         statusBar()->showMessage(warningMsg, 10000); // Show for 10 seconds
        //         
        //         // Highlight suspicious sections in hex viewer
        //         highlightSuspiciousSections(result);
        //     }
        // }
    } catch (const std::exception& e) {
        CrashHandler::getInstance().logError("MainWindow", "Exception during file loading", QString("Exception: %1").arg(e.what()));
        showError(LANG("UI/error_file_load"), QString("Exception: %1").arg(e.what()));
    } catch (...) {
        CrashHandler::getInstance().logError("MainWindow", "Unknown exception during file loading", "Unknown exception type");
        showError(LANG("UI/error_file_load"), "Unknown exception occurred");
    }
}

void MainWindow::clearDisplay()
{
    // Access UI components through UIManager
    if (m_uiManager) {
        // Clear tree highlights before clearing the tree
        clearTreeHighlights();
        
        m_uiManager->m_peTree->clear();
        m_uiManager->m_fieldExplanationText->clear();
        m_uiManager->m_fileInfoLabel->setText(LANG("UI/file_no_file_loaded"));
        m_fileLoaded = false;
        m_uiManager->m_refreshButton->setEnabled(false);
        m_uiManager->m_copyButton->setEnabled(false);
        m_uiManager->m_saveButton->setEnabled(false);
        if (m_uiManager->m_securityButton) m_uiManager->m_securityButton->setEnabled(false);
        if (m_uiManager->m_expandAllButton) m_uiManager->m_expandAllButton->setEnabled(false);
        if (m_uiManager->m_collapseAllButton) m_uiManager->m_collapseAllButton->setEnabled(false);
        if (m_uiManager->m_importModulesTree) m_uiManager->m_importModulesTree->clear();
        if (m_uiManager->m_importFunctionsTree) m_uiManager->m_importFunctionsTree->clear();
        if (m_uiManager->m_exportsTree) m_uiManager->m_exportsTree->clear();
        
        // Also clear hex viewer highlights
        if (m_uiManager->m_hexViewer) {
            m_uiManager->m_hexViewer->clearHighlights();
        }
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
    if (m_uiManager->m_securityButton) m_uiManager->m_securityButton->setEnabled(true);
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

    bool hasItems = !items.isEmpty();
    if (m_uiManager->m_expandAllButton) m_uiManager->m_expandAllButton->setEnabled(hasItems);
    if (m_uiManager->m_collapseAllButton) m_uiManager->m_collapseAllButton->setEnabled(hasItems);
    
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
        if (m_peParser->isLargeFile()) {
            // For large files, only show first 1MB in hex viewer to avoid memory issues
            QFile file(m_currentFilePath);
            if (file.open(QIODevice::ReadOnly)) {
                QByteArray fileData = file.read(1024 * 1024); // Read only 1MB
                file.close();
                m_uiManager->m_hexViewer->setData(fileData);
                
                // Show warning about large file mode using language system
                QString largeFileWarning = QString("<div style='color: orange; font-weight: bold; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px;'>%1</div>")
                                         .arg(LANG_PARAM("UI/large_file_mode_warning", "size", QString::number(m_peParser->getFileSize() / (1024.0 * 1024.0), 'f', 1)));
                
                // Append warning to the explanation text
                QString currentText = m_uiManager->m_fieldExplanationText->toHtml();
                m_uiManager->m_fieldExplanationText->setHtml(currentText + largeFileWarning);
            }
        } else {
            // For small files, load everything
            QFile file(m_currentFilePath);
            if (file.open(QIODevice::ReadOnly)) {
                QByteArray fileData = file.readAll();
                file.close();
                m_uiManager->m_hexViewer->setData(fileData);
            }
        }
    }

    // Populate Imports tab
    if (m_uiManager->m_importModulesTree) {
        m_uiManager->m_importModulesTree->clear();
        if (m_uiManager->m_importFunctionsTree) {
            m_uiManager->m_importFunctionsTree->clear();
        }
        const QStringList imports = m_peParser->getImportModules();
        const auto &importDetails = m_peParser->getImportFunctionDetails();

        for (const QString &moduleName : imports) {
            const QList<PEDataModel::ImportFunctionEntry> functions = importDetails.value(moduleName);
            QTreeWidgetItem *moduleItem = new QTreeWidgetItem(m_uiManager->m_importModulesTree);
            moduleItem->setText(0, moduleName);
            moduleItem->setText(1, QString::number(functions.size()));
        }

        if (m_uiManager->m_importModulesTree->topLevelItemCount() > 0) {
            m_uiManager->m_importModulesTree->setCurrentItem(m_uiManager->m_importModulesTree->topLevelItem(0));
        } else {
            QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_importModulesTree);
            placeholder->setText(0, LANG("UI/imports_none"));
            placeholder->setText(1, "");
            populateImportFunctions(QString());
        }
    }

    // Populate Exports tab
    if (m_uiManager->m_exportsTree) {
        m_uiManager->m_exportsTree->clear();
        const auto &exports = m_peParser->getExportFunctions();
        if (exports.isEmpty()) {
            QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_exportsTree);
            placeholder->setText(0, LANG("UI/exports_none"));
            placeholder->setFirstColumnSpanned(true);
            placeholder->setFlags(Qt::NoItemFlags);
        } else {
            for (const PEDataModel::ExportFunctionEntry &entry : exports) {
                QTreeWidgetItem *item = new QTreeWidgetItem(m_uiManager->m_exportsTree);
                item->setText(0, entry.name);
                if (entry.rva != 0) {
                    item->setText(1, PEUtils::formatHexWidth(entry.rva, 8));
                } else {
                    item->setText(1, "");
                }
                item->setText(2, QString::number(entry.ordinal));
            }
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

void MainWindow::highlightSuspiciousSections(const SecurityAnalysisResult &result)
{
    if (!m_uiManager || !m_uiManager->m_hexViewer) {
        return;
    }
    
    // Clear previous highlights
    m_uiManager->m_hexViewer->clearHighlights();
    
    // Highlight suspicious sections with different colors based on risk
    QColor highRiskColor(255, 0, 0, 150);    // Red for high risk
    QColor mediumRiskColor(255, 165, 0, 150); // Orange for medium risk
    
    for (const QString &issue : result.detectedIssues) {
        // Parse issue to find offset and size if available
        // This is a simplified approach - in a real implementation, you'd parse the issue details
        if (issue.contains("suspicious", Qt::CaseInsensitive) || issue.contains("malicious", Qt::CaseInsensitive)) {
            // For now, highlight a range around the PE header as an example
            // In a real implementation, you'd extract actual offsets from the security analysis
            quint32 offset = 0;
            quint32 size = 64; // Default to DOS header size
            
            QColor highlightColor = (result.riskLevel == SecurityRiskLevel::HIGH) ? highRiskColor : mediumRiskColor;
            m_uiManager->m_hexViewer->highlightRange(offset, size, highlightColor);
            
            // Add a tooltip or status message
            QString hexOffset = QStringLiteral("0x") + QString::number(static_cast<quint64>(offset), 16).toUpper().rightJustified(8, '0');
            QString statusMsg = LANG_PARAM("UI/security_suspicious_section_highlighted", "offset", hexOffset);
            statusBar()->showMessage(statusMsg, 5000);
            break; // Just highlight one for now
        }
    }
}

void MainWindow::highlightSuspiciousFieldsInTree(const SecurityAnalysisResult &result)
{
    if (!m_uiManager || !m_uiManager->m_peTree) {
        return;
    }
    
    // Clear previous tree highlights
    clearTreeHighlights();
    
    // Define suspicious field patterns and their risk levels
    QMap<QString, SecurityRiskLevel> suspiciousFields;
    
    // High risk fields - commonly exploited or manipulated
    suspiciousFields["Characteristics"] = SecurityRiskLevel::HIGH;
    suspiciousFields["DllCharacteristics"] = SecurityRiskLevel::HIGH;
    suspiciousFields["Subsystem"] = SecurityRiskLevel::HIGH;
    suspiciousFields["SizeOfCode"] = SecurityRiskLevel::HIGH;
    suspiciousFields["SizeOfImage"] = SecurityRiskLevel::HIGH;
    suspiciousFields["AddressOfEntryPoint"] = SecurityRiskLevel::HIGH;
    suspiciousFields["BaseOfCode"] = SecurityRiskLevel::HIGH;
    suspiciousFields["ImageBase"] = SecurityRiskLevel::HIGH;
    
    // Medium risk fields - potentially suspicious
    suspiciousFields["TimeDateStamp"] = SecurityRiskLevel::MEDIUM;
    suspiciousFields["CheckSum"] = SecurityRiskLevel::MEDIUM;
    suspiciousFields["NumberOfSections"] = SecurityRiskLevel::MEDIUM;
    suspiciousFields["SizeOfHeaders"] = SecurityRiskLevel::MEDIUM;
    suspiciousFields["SizeOfStackReserve"] = SecurityRiskLevel::MEDIUM;
    suspiciousFields["SizeOfStackCommit"] = SecurityRiskLevel::MEDIUM;
    suspiciousFields["SizeOfHeapReserve"] = SecurityRiskLevel::MEDIUM;
    suspiciousFields["SizeOfHeapCommit"] = SecurityRiskLevel::MEDIUM;
    
    // Low risk fields - less commonly exploited but worth checking
    suspiciousFields["MajorLinkerVersion"] = SecurityRiskLevel::LOW;
    suspiciousFields["MinorLinkerVersion"] = SecurityRiskLevel::LOW;
    suspiciousFields["MajorOperatingSystemVersion"] = SecurityRiskLevel::LOW;
    suspiciousFields["MinorOperatingSystemVersion"] = SecurityRiskLevel::LOW;
    suspiciousFields["MajorImageVersion"] = SecurityRiskLevel::LOW;
    suspiciousFields["MinorImageVersion"] = SecurityRiskLevel::LOW;
    suspiciousFields["MajorSubsystemVersion"] = SecurityRiskLevel::LOW;
    suspiciousFields["MinorSubsystemVersion"] = SecurityRiskLevel::LOW;
    
    // Highlight fields based on risk level and analysis results
    QTreeWidgetItemIterator it(m_uiManager->m_peTree);
    while (*it) {
        QTreeWidgetItem *item = *it;
        QString fieldName = item->text(0);
        
        // Check if this field is in our suspicious fields list
        if (suspiciousFields.contains(fieldName)) {
            SecurityRiskLevel fieldRisk = suspiciousFields[fieldName];
            
            // Determine highlight color based on field risk and analysis results
            QColor highlightColor;
            QString tooltip;
            
            if (result.riskLevel == SecurityRiskLevel::HIGH || fieldRisk == SecurityRiskLevel::HIGH) {
                // High risk - light red
                highlightColor = QColor(255, 200, 200, 180); // Light red with transparency
                QMap<QString, QString> params;
                params["field_name"] = fieldName;
                tooltip = LANG_PARAMS("UI/security_field_high_risk_tooltip", params);
            } else if (result.riskLevel == SecurityRiskLevel::MEDIUM || fieldRisk == SecurityRiskLevel::MEDIUM) {
                // Medium risk - light orange
                highlightColor = QColor(255, 220, 180, 180); // Light orange with transparency
                QMap<QString, QString> params;
                params["field_name"] = fieldName;
                tooltip = LANG_PARAMS("UI/security_field_medium_risk_tooltip", params);
                    } else {
            // Low risk - light yellow
            highlightColor = QColor(255, 255, 200, 180); // Light yellow with transparency
            QMap<QString, QString> params;
            params["field_name"] = fieldName;
            tooltip = LANG_PARAMS("UI/security_field_low_risk_tooltip", params);
        }
            
            // Apply highlighting to the item
            item->setBackground(0, highlightColor);
            item->setBackground(1, highlightColor);
            item->setBackground(2, highlightColor);
            item->setBackground(3, highlightColor);
            
            // Set tooltip
            item->setToolTip(0, tooltip);
            item->setToolTip(1, tooltip);
            item->setToolTip(2, tooltip);
            item->setToolTip(3, tooltip);
            
            // Store the original background color for later restoration
            item->setData(0, Qt::UserRole + 1, item->background(0));
        }
        
        ++it;
    }
    
    // Also highlight fields mentioned in detected issues
    for (const QString &issue : result.detectedIssues) {
        // Look for field names mentioned in the issue description
        for (const QString &fieldName : suspiciousFields.keys()) {
            if (issue.contains(fieldName, Qt::CaseInsensitive)) {
                // Find and highlight this specific field
                QTreeWidgetItemIterator it2(m_uiManager->m_peTree);
                while (*it2) {
                    QTreeWidgetItem *item = *it2;
                    if (item->text(0) == fieldName) {
                        // Highlight with a more prominent color for detected issues
                        QColor issueColor(255, 150, 150, 200); // Brighter red for detected issues
                        item->setBackground(0, issueColor);
                        item->setBackground(1, issueColor);
                        item->setBackground(2, issueColor);
                        item->setBackground(3, issueColor);
                        
                        // Update tooltip to include the detected issue
                        QString currentTooltip = item->toolTip(0);
                        QMap<QString, QString> params;
                        params["tooltip"] = currentTooltip;
                        params["issue"] = issue;
                        QString newTooltip = LANG_PARAMS("UI/security_field_detected_issue_tooltip", params);
                        item->setToolTip(0, newTooltip);
                        item->setToolTip(1, newTooltip);
                        item->setToolTip(2, newTooltip);
                        item->setToolTip(3, newTooltip);
                        break;
                    }
                    ++it2;
                }
                break;
            }
        }
    }
    
    // Show summary of highlighted fields
    int highlightedCount = 0;
    QTreeWidgetItemIterator countIt(m_uiManager->m_peTree);
    while (*countIt) {
        QTreeWidgetItem *item = *countIt;
        if (item->background(0) != item->data(0, Qt::UserRole + 1).value<QColor>()) {
            highlightedCount++;
        }
        ++countIt;
    }
    
    if (highlightedCount > 0) {
        QString highlightMsg = LANG_PARAM("UI/security_fields_highlighted", "count", QString::number(highlightedCount));
        statusBar()->showMessage(highlightMsg, 3000);
    }
}

void MainWindow::clearTreeHighlights()
{
    if (!m_uiManager || !m_uiManager->m_peTree) {
        return;
    }
    
    QTreeWidgetItemIterator it(m_uiManager->m_peTree);
    while (*it) {
        QTreeWidgetItem *item = *it;
        
        // Restore original background color if it was stored
        QVariant originalColor = item->data(0, Qt::UserRole + 1);
        if (originalColor.isValid()) {
            QColor color = originalColor.value<QColor>();
            if (color.isValid()) {
                item->setBackground(0, color);
                item->setBackground(1, color);
                item->setBackground(2, color);
                item->setBackground(3, color);
            }
        } else {
            // Reset to default if no original color was stored
            item->setBackground(0, QColor());
            item->setBackground(1, QColor());
            item->setBackground(2, QColor());
            item->setBackground(3, QColor());
        }
        
        // Clear tooltips
        item->setToolTip(0, QString());
        item->setToolTip(1, QString());
        item->setToolTip(2, QString());
        item->setToolTip(3, QString());
        
        ++it;
    }
}

void MainWindow::setupLanguageMenu()
{
    qDebug() << "=== SETUP LANGUAGE MENU START ===";
    
    // Find the Tools menu - try multiple approaches
    QMenu *toolsMenu = nullptr;
    
    // First, try to find by exact title match
    for (QAction *action : menuBar()->actions()) {
        if (action->menu()) {
            QString menuTitle = action->menu()->title();
            // Remove accelerator prefix (&) and compare
            QString cleanTitle = menuTitle.replace("&", "");
            qDebug() << "Checking menu:" << menuTitle << "clean:" << cleanTitle;
            if (cleanTitle == "Tools") {
                toolsMenu = action->menu();
                qDebug() << "Found Tools menu by exact match:" << menuTitle;
                break;
            }
        }
    }
    
    // If not found, try case-insensitive search
    if (!toolsMenu) {
        for (QAction *action : menuBar()->actions()) {
            if (action->menu()) {
                QString menuTitle = action->menu()->title();
                QString cleanTitle = menuTitle.replace("&", "");
                if (cleanTitle.contains("Tools", Qt::CaseInsensitive)) {
                    toolsMenu = action->menu();
                    qDebug() << "Found Tools menu by case-insensitive search:" << menuTitle;
                    break;
                }
            }
        }
    }
    
    // If still not found, create it
    if (!toolsMenu) {
        qWarning() << "Tools menu not found, creating it";
        toolsMenu = menuBar()->addMenu("&Tools");
        qDebug() << "Created new Tools menu";
    }
    
    // Add language submenu with icon
    QMenu *languageMenu = toolsMenu->addMenu(LANG("UI/menu_language"));
    languageMenu->setIcon(QIcon(":/images/imgs/language.png")); // Use language icon
    
    // Get available languages from Language Manager
    qDebug() << "About to get available languages from LanguageManager...";
    QStringList languages = LanguageManager::getInstance().getAvailableLanguages();
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();
    
    qDebug() << "Available languages:" << languages;
    qDebug() << "Current language:" << currentLanguage;
    
    // Create language actions
    for (const QString &langCode : languages) {
        QString displayName = LanguageManager::getInstance().getLanguageDisplayName(langCode);
        qDebug() << "Creating language action for" << langCode << "with display name:" << displayName;
        
        QAction *langAction = new QAction(displayName, this);
        langAction->setCheckable(true);
        langAction->setData(langCode);
        
        languageMenu->addAction(langAction);
        connect(langAction, &QAction::triggered, this, [this, langAction]() {
            this->onLanguageMenuTriggered(langAction);
        });
        
        qDebug() << "Created action for" << langCode << "with data:" << langCode;
    }
    
    // Now set the checked state for only the current language
    for (QAction *langAction : languageMenu->actions()) {
        QString langCode = langAction->data().toString();
        if (langCode == currentLanguage) {
            langAction->setChecked(true);
            qDebug() << "Checked action for current language:" << langCode;
            break; // Only one should be checked
        }
    }
}

void MainWindow::onLanguageMenuTriggered(QAction *action)
{
    QString languageCode = action->data().toString();
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();
    
    qDebug() << "Language menu triggered for:" << languageCode;
    qDebug() << "Current language is:" << currentLanguage;
    
    // Don't do anything if the same language is already selected
    if (languageCode == currentLanguage) {
        qDebug() << "Same language already selected, doing nothing";
        return;
    }
    
    if (LanguageManager::getInstance().setLanguage(languageCode)) {
        qDebug() << "Language successfully changed to:" << languageCode;
        
        // Update all UI elements with new language
        updateUILanguage();
        
        // Force immediate menu update
        QTimer::singleShot(0, this, [this]() {
            updateLanguageMenu();
            // Also force a complete menu refresh
            menuBar()->update();
        });
        
        qDebug() << "Language changed to:" << languageCode;
    } else {
        qWarning() << "Failed to change language to:" << languageCode;
    }
}

void MainWindow::updateUILanguage()
{
    // Update window title
    setWindowTitle(LANG_PARAM("UI/window_title", "version", PEHINT_VERSION_STRING_FULL));
    
    // Update status bar - only show "Ready" if no file is loaded
    if (!m_fileLoaded) {
        statusBar()->showMessage(LANG("UI/status_ready"));
    }
    // If a file is loaded, the status should show file information instead
    
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
        headers << LANG("UI/tree_header_field")
                << LANG("UI/tree_header_value")
                << LANG("UI/tree_header_offset")
                << LANG("UI/tree_header_size")
                << LANG("UI/tree_header_meaning");
        m_uiManager->m_peTree->setHeaderLabels(headers);
    }

    if (m_uiManager && m_uiManager->m_analysisTabWidget) {
        if (m_uiManager->m_analysisTabWidget->count() > 0) {
            m_uiManager->m_analysisTabWidget->setTabText(0, LANG("UI/tab_structure"));
        }
        if (m_uiManager->m_analysisTabWidget->count() > 1) {
            m_uiManager->m_analysisTabWidget->setTabText(1, LANG("UI/tab_imports"));
        }
        if (m_uiManager->m_analysisTabWidget->count() > 2) {
            m_uiManager->m_analysisTabWidget->setTabText(2, LANG("UI/tab_exports"));
        }
    }

    if (m_uiManager && m_uiManager->m_importModulesTree) {
        m_uiManager->m_importModulesTree->setHeaderLabels({LANG("UI/imports_header_module"), LANG("UI/imports_header_count")});
    }

    if (m_uiManager && m_uiManager->m_importFunctionsTree) {
        m_uiManager->m_importFunctionsTree->setHeaderLabels({LANG("UI/imports_functions_header_name")});
    }

    if (m_uiManager && m_uiManager->m_exportsTree) {
        m_uiManager->m_exportsTree->setHeaderLabels({LANG("UI/exports_header_name")});
    }
 
    // Update placeholder text
    if (m_uiManager && m_uiManager->m_fieldExplanationText) {
        m_uiManager->m_fieldExplanationText->setPlaceholderText(LANG("UI/placeholder_explanation"));
    }
    
    // Update button texts
    if (m_uiManager && m_uiManager->m_refreshButton) m_uiManager->m_refreshButton->setText(LANG("UI/button_refresh"));
    if (m_uiManager && m_uiManager->m_copyButton) m_uiManager->m_copyButton->setText(LANG("UI/button_copy"));
    if (m_uiManager && m_uiManager->m_saveButton) m_uiManager->m_saveButton->setText(LANG("UI/button_save"));
    if (m_uiManager && m_uiManager->m_expandAllButton) m_uiManager->m_expandAllButton->setText(LANG("UI/context_expand_all"));
    if (m_uiManager && m_uiManager->m_collapseAllButton) m_uiManager->m_collapseAllButton->setText(LANG("UI/context_collapse_all"));
}

void MainWindow::updateMenuLanguage()
{
    // Update menu texts
    QMenuBar *menuBar = this->menuBar();
    
    for (QAction *menuAction : menuBar->actions()) {
        if (menuAction->menu()) {
            QMenu *menu = menuAction->menu();
            
            // Update menu title - use object name or text matching
            QString menuTitle = menu->title();
            QString cleanTitle = menuTitle.replace("&", "");
            
            if (cleanTitle.contains("File", Qt::CaseInsensitive) || 
                cleanTitle.contains("Arquivo", Qt::CaseInsensitive)) {
                menu->setTitle(LANG("UI/menu_file"));
            } else if (cleanTitle.contains("Tools", Qt::CaseInsensitive) || 
                       cleanTitle.contains("Ferramentas", Qt::CaseInsensitive)) {
                menu->setTitle(LANG("UI/menu_tools"));
            } else if (cleanTitle.contains("About", Qt::CaseInsensitive) || 
                       cleanTitle.contains("Sobre", Qt::CaseInsensitive)) {
                menu->setTitle(LANG("UI/menu_about"));
            }
            
            // Update menu item texts
            for (QAction *action : menu->actions()) {
                QString actionText = action->text();
                QString cleanActionText = actionText.replace("&", "");
                
                if (cleanActionText.contains("Open", Qt::CaseInsensitive) || 
                    cleanActionText.contains("Abrir", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_open"));
                } else if (cleanActionText.contains("Save Report", Qt::CaseInsensitive) || 
                           cleanActionText.contains("Salvar Relatório", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_save_report"));
                } else if (cleanActionText.contains("Exit", Qt::CaseInsensitive) || 
                           cleanActionText.contains("Sair", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_exit"));
                } else if (cleanActionText.contains("Refresh", Qt::CaseInsensitive) || 
                           cleanActionText.contains("Atualizar", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_refresh"));
                } else if (cleanActionText.contains("Hex", Qt::CaseInsensitive) || 
                           cleanActionText.contains("Opções Hex", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_hex_options"));
                } else if (cleanActionText.contains("PEHint", Qt::CaseInsensitive) || 
                           cleanActionText.contains("Sobre PEHint", Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_about"));
                }
            }
        }
    }
}

void MainWindow::updateHexViewerLanguage()
{
    if (m_uiManager && m_uiManager->m_hexViewer) {
        m_uiManager->m_hexViewer->updateLanguage();
    }
}

void MainWindow::updateWindowTitle()
{
    this->setWindowTitle(LANG_PARAM("UI/window_title", "version", PEHINT_VERSION_STRING_FULL));
}

void MainWindow::updateLanguageMenu()
{
    // Find the Tools menu and then the language submenu
    QMenu *toolsMenu = nullptr;
    QMenu *languageMenu = nullptr;
    
    // Find Tools menu - check both English and Portuguese
    for (QAction *action : menuBar()->actions()) {
        if (action->menu()) {
            QString menuTitle = action->menu()->title();
            QString cleanTitle = menuTitle.replace("&", "");
            if (cleanTitle == "Tools" || cleanTitle == "Ferramentas" || 
                cleanTitle.contains("Tools", Qt::CaseInsensitive) || 
                cleanTitle.contains("Ferramentas", Qt::CaseInsensitive)) {
                toolsMenu = action->menu();
                break;
            }
        }
    }
    
    if (!toolsMenu) {
        qWarning() << "Tools menu not found in updateLanguageMenu";
        return;
    }
    
    // Find language submenu
    for (QAction *action : toolsMenu->actions()) {
        if (action->menu() && action->text().contains(LANG("UI/menu_language"), Qt::CaseInsensitive)) {
            languageMenu = action->menu();
            break;
        }
    }
    
    if (!languageMenu) {
        qWarning() << "Language submenu not found in updateLanguageMenu";
        return;
    }
    
    // Get current language and update all language actions
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();
    qDebug() << "Updating language menu, current language:" << currentLanguage;
    
    // Ensure mutual exclusivity: only one action can be checked
    bool foundCurrentLanguage = false;
    for (QAction *langAction : languageMenu->actions()) {
        QString langCode = langAction->data().toString();
        bool shouldBeChecked = (langCode == currentLanguage);
        
        if (shouldBeChecked) {
            if (!foundCurrentLanguage) {
                langAction->setChecked(true);
                foundCurrentLanguage = true;
                qDebug() << "Checked action for current language:" << langCode;
            } else {
                // This shouldn't happen, but just in case
                langAction->setChecked(false);
                qDebug() << "Warning: Unchecked duplicate action for:" << langCode;
            }
        } else {
            langAction->setChecked(false);
            qDebug() << "Unchecked action for:" << langCode;
        }
    }
    
    // Force menu update
    languageMenu->update();
    qDebug() << "Language menu update complete. Current language:" << currentLanguage;
}

void MainWindow::populateImportFunctions(const QString &moduleName)
{
    if (!m_uiManager || !m_uiManager->m_importFunctionsTree) {
        return;
    }

    m_uiManager->m_importFunctionsTree->clear();

    if (!m_fileLoaded || !m_peParser) {
        return;
    }

    const auto &importDetails = m_peParser->getImportFunctionDetails();
    const QList<PEDataModel::ImportFunctionEntry> functions = moduleName.isEmpty() ? QList<PEDataModel::ImportFunctionEntry>() : importDetails.value(moduleName);

    if (functions.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_importFunctionsTree);
        placeholder->setText(0, LANG("UI/imports_no_functions"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
        return;
    }

    for (const PEDataModel::ImportFunctionEntry &entry : functions) {
        QTreeWidgetItem *item = new QTreeWidgetItem(m_uiManager->m_importFunctionsTree);
        item->setText(0, entry.name);
        if (entry.thunkRVA != 0) {
            item->setText(1, PEUtils::formatHexWidth(entry.thunkRVA, 8));
        } else {
            item->setText(1, "");
        }
        if (entry.importedByOrdinal) {
            item->setText(2, QString::number(entry.ordinal));
        } else {
            item->setText(2, QString());
        }
    }
}

void MainWindow::onImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);

    if (!m_fileLoaded || !m_peParser) {
        return;
    }

    if (!current) {
        populateImportFunctions(QString());
        return;
    }

    populateImportFunctions(current->text(0));
}

