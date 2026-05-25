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

#include "mainwindow_chrome.h"
#include "version.h"
#include "language_manager.h"
#include "crash_handler.h"
#include "pe_utils.h"
#include "pe_data_model.h"
#include "pe_structures.h"
#include "pe_dependency_analyzer.h"
#include "pe_findings.h"
#include "findings_controller.h"
#include "resources_controller.h"
#include "dependencies_controller.h"
#include "imports_controller.h"
#include "strings_controller.h"
#include "exports_controller.h"
#include "structure_tree_controller.h"
#include "analysis_display_controller.h"
#include "pe_report_builder.h"
#include "section_layout_widget.h"
#include "sdk_api_markdown_reader.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStringConverter>
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
#include <QDialogButtonBox>
#include <QFrame>
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
#include <QRegularExpression>
#include <QStyle>
#include <QShortcut>
#include <QKeySequence>
#include <QSignalBlocker>
#include <QPointer>
#include <QMetaObject>
#include <algorithm>
#include <limits>

/**
 * @brief Constructor for MainWindow
 * 
 * This constructor demonstrates the new architectural approach:
 * 1. Creates the new modular PEParserNew instead of the old monolithic PEParser
 * 2. Delegates UI setup to UIManager, reducing MainWindow's responsibilities
 * 3. Maintains the same public interface for backward compatibility
 * 
 * UI orchestration is split across UIManager, tab controllers, MainWindowChrome,
 * and AnalysisDisplayController so MainWindow stays focused on file lifecycle.
 */
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , m_peParser(nullptr)
    , m_fileLoaded(false)
{
    
    // Accept drag-and-drop operations for PE files
    setAcceptDrops(true);

    // Initialize PE Parser - NEW ARCHITECTURE: Using modular PEParserNew
    // This replaces the old monolithic PEParser that violated SRP
    m_peParser = new PEParserNew(this);
    
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
    
    SdkApiMarkdownReader::instance().setContentRoot(SdkApiMarkdownReader::defaultContentRoot());
    SdkApiMarkdownReader::instance().setConsoleDocsRoot(SdkApiMarkdownReader::defaultConsoleDocsRoot());

    // Setup UI components - REFACTORED: Now delegates to UIManager
    // This must be done BEFORE trying to access UI components
    setupUI();

    m_findingsController = new FindingsController(m_uiManager, this);
    m_findingsController->setParser(m_peParser);

    m_resourcesController = new ResourcesController(m_uiManager, this);
    m_resourcesController->setParser(m_peParser);

    m_dependenciesController = new DependenciesController(m_uiManager, this);
    m_dependenciesController->setParser(m_peParser);

    m_importsController = new ImportsController(m_uiManager, this);
    m_importsController->setParser(m_peParser);

    m_stringsController = new StringsController(m_uiManager, this);
    m_stringsController->setParser(m_peParser);

    m_exportsController = new ExportsController(m_uiManager, this);
    m_exportsController->setParser(m_peParser);

    m_structureTreeController = new StructureTreeController(m_peParser, m_uiManager, this);

    m_analysisDisplay = new AnalysisDisplayController(this,
                                                      m_uiManager,
                                                      m_peParser,
                                                      m_findingsController,
                                                      m_stringsController,
                                                      m_structureTreeController,
                                                      this);
    m_analysisDisplay->setLanguageRefreshEpoch(&m_languageRefreshEpoch);
    m_analysisDisplay->setOnAnalysisTabChanged([this](int index) { onAnalysisTabChanged(index); });

    m_chrome = new MainWindowChrome(this);
    m_chrome->setUiManager(m_uiManager);
    m_chrome->setControllers(m_findingsController,
                             m_importsController,
                             m_exportsController,
                             m_resourcesController,
                             m_dependenciesController,
                             m_stringsController);

    setupConnections();
    m_chrome->setupMenus();
    m_chrome->loadRecentFiles();
    m_chrome->updateOpenRecentMenu();
    m_chrome->setupLanguageMenu();
    m_chrome->setupStatusBar();
    m_chrome->setupContextMenu();
    
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
    icon.addFile(":/images/imgs/PEHint-ico.png");
    this->setWindowIcon(icon);
    
    // Initial state - Now UI components are available
    clearDisplay();

    // Apply button tooltips and other LANG-driven chrome (e.g. Copy shortcut hint).
    updateUILanguage();
}

void MainWindow::openPeFile(const QString &filePath)
{
    loadPEFile(filePath);
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
    
    // Language Manager: always queue â€” never run UI refresh inside setLanguage()'s emit stack or while a
    // native QMenu is closing (Windows access violations otherwise).
    connect(&LanguageManager::getInstance(), &LanguageManager::languageChanged,
            this, &MainWindow::onApplicationLanguageChanged, Qt::QueuedConnection);
    
    // REFACTORED: Use UI Manager to setup connections
    // This extracts UI-specific connections from MainWindow, reducing coupling
    // MainWindow no longer needs to know about m_refreshButton, m_copyButton, etc.
    m_uiManager->setupConnections(this);

    if (m_dependenciesController) {
        m_dependenciesController->setupDepthSpin();
    }
    if (m_uiManager->m_dependenciesTree && m_dependenciesController) {
        connect(m_uiManager->m_dependenciesTree, &QTreeWidget::customContextMenuRequested,
                this, &MainWindow::onDependenciesCustomContextMenu);
    }

    if (m_resourcesController) {
        connect(m_resourcesController, &ResourcesController::requestHexHighlight, this,
                [this](quint32 offset, quint32 size) {
                    if (m_structureTreeController) {
                        m_structureTreeController->applyTabHexHighlight(offset, size, QColor(200, 230, 255));
                    }
                });
    }
    if (m_stringsController) {
        connect(m_stringsController, &StringsController::requestHexHighlight, this,
                [this](quint32 offset, quint32 size) {
                    if (m_structureTreeController) {
                        m_structureTreeController->applyTabHexHighlight(offset, size, QColor(255, 255, 0, 120));
                    }
                    if (m_uiManager && m_uiManager->m_hexViewer) {
                        m_uiManager->m_hexViewer->setFocus(Qt::OtherFocusReason);
                    }
                });
        connect(m_stringsController, &StringsController::statusMessageRequested, this,
                [this](const QString &message, int timeoutMs) {
                    statusBar()->showMessage(message, timeoutMs);
                });
        connect(m_stringsController, &StringsController::errorOccurred, this,
                [this](const QString &title, const QString &message) { showError(title, message); });
    }
    if (m_dependenciesController) {
        connect(m_dependenciesController, &DependenciesController::statusMessageRequested, this,
                [this](const QString &message, int timeoutMs) {
                    statusBar()->showMessage(message, timeoutMs);
                });
    }

    if (m_structureTreeController) {
        connect(m_structureTreeController, &StructureTreeController::statusMessageRequested, this,
                [this](const QString &message, int timeoutMs) {
                    statusBar()->showMessage(message, timeoutMs);
                });
        connect(m_structureTreeController, &StructureTreeController::errorOccurred, this,
                [this](const QString &title, const QString &message) { showError(title, message); });
    }

    if (m_findingsController && m_structureTreeController) {
        m_findingsController->setNavigationHooks(
            [this](QTreeWidgetItem *item, const QString &field) {
                return m_structureTreeController->resolveFieldHexRange(item, field);
            },
            [this](QTreeWidgetItem *item, const PeFieldHexRange &range) {
                m_structureTreeController->applyFieldHexNavigation(item, range);
            },
            [this](const QString &key) {
                return m_structureTreeController->findPeTreeItemByFieldKey(key);
            },
            [this](QTreeWidgetItem *peItem) {
                m_structureTreeController->activatePeTreeItem(peItem);
            });
        connect(m_findingsController, &FindingsController::insightHtmlChanged, this,
                &MainWindow::showFindingsInsightHtml);
        connect(m_findingsController, &FindingsController::requestClearHexHighlights, this, [this]() {
            if (m_uiManager && m_uiManager->m_hexViewer) {
                m_uiManager->m_hexViewer->clearHighlights();
            }
        });
    }

    CrashHandler::getInstance().logInfo("MainWindow", "Signal-slot connections setup completed");
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
    // Do not show the main "Copy / Expand / Collapse" menu on Imports, Exports, or Strings
    // tabs (those areas are not the PE structure tree + explanation workflow).
    if (m_uiManager && m_uiManager->m_analysisTabWidget) {
        QWidget *under = QApplication::widgetAt(event->globalPos());
        if (under) {
            QTabWidget *tw = m_uiManager->m_analysisTabWidget;
            // Tab order: 0=Structure, 1=Imports, 2=Delay Imports, 3=Exports, 4=Dependencies, 5=Strings, 6=Findings
            for (int tabIndex : {1, 2, 3, 5, 6}) {
                QWidget *tab = tw->widget(tabIndex);
                if (tab && tab->isAncestorOf(under)) {
                    event->accept();
                    return;
                }
            }
        }
    }
    if (m_chrome && m_chrome->contextMenu()) {
        m_chrome->contextMenu()->exec(event->globalPos());
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

void MainWindow::on_action_PEHint_triggered()
{
    if (m_chrome) {
        m_chrome->showAboutDialog(this);
    }
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
    if (m_chrome) {
        m_chrome->clearRecentFilesOnExitIfConfigured();
    }
    QApplication::quit();
}

void MainWindow::on_action_Save_Report_triggered()
{
    if (m_chrome && m_peParser) {
        m_chrome->saveReportToFile(m_peParser->getDataModel(), m_fileLoaded, this);
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
    if (success) {
        m_fileLoaded = true;
        if (m_importsController) {
            m_importsController->setFileLoaded(true);
        }
        if (m_stringsController) {
            m_stringsController->setFilePath(m_currentFilePath);
            m_stringsController->setFileLoaded(true);
        }
        if (m_dependenciesController) {
            m_dependenciesController->setFilePath(m_currentFilePath);
            m_dependenciesController->setFileLoaded(true);
        }
        CrashHandler::getInstance().logInfo("MainWindow", "PE file parsing completed successfully");
        const QString completedPath = m_currentFilePath;

        if (m_uiManager) {
            // Keep determinate % visible while finalizing UI.
            m_uiManager->m_progressBar->setRange(0, 100);
            m_uiManager->m_progressBar->setValue(92);
            m_uiManager->m_progressLabel->setText(QStringLiteral("92% - %1").arg(LANG("UI/status_loading")));
        }

        // Stage heavy UI work to keep the event loop responsive and avoid "Not Responding".
        QTimer::singleShot(0, this, [this, completedPath]() {
            if (completedPath != m_currentFilePath) {
                return; // A newer load is in progress.
            }

            updateFileInfo();
            if (m_uiManager) {
                m_uiManager->m_progressBar->setValue(96);
                m_uiManager->m_progressLabel->setText(QStringLiteral("96% - %1").arg(LANG("UI/status_loading")));
            }

            // Tree â†’ welcome/hex â†’ strings/tab on separate event-loop passes (keeps UI responsive).
            m_analysisDisplay->setFileLoaded(true);
            m_analysisDisplay->setCurrentFilePath(m_currentFilePath);
            m_analysisDisplay->scheduleDisplay(completedPath, [this, completedPath]() {
                if (completedPath != m_currentFilePath) {
                    return;
                }
                if (m_uiManager) {
                    m_uiManager->m_progressBar->setRange(0, 100);
                    m_uiManager->m_progressBar->setValue(100);
                    m_uiManager->m_progressLabel->setText(QStringLiteral("100% - %1").arg(LANG("UI/status_file_loaded_success")));
                    m_uiManager->m_progressBar->setVisible(false);
                }
                statusBar()->showMessage(LANG("UI/status_file_loaded_success"), 3000);
            });
        });
    } else {
        m_fileLoaded = false;
        CrashHandler::getInstance().logError("MainWindow", "PE file parsing failed");
        clearDisplay();
        if (m_uiManager) {
            m_uiManager->m_progressBar->setVisible(false);
        }
        statusBar()->showMessage(LANG("UI/file_load_failed"), 3000);
    }
}

void MainWindow::onParsingProgress(int percentage, const QString &message)
{
    if (m_uiManager) {
        m_uiManager->m_progressBar->setValue(percentage);
        if (m_uiManager->m_progressBar->minimum() == 0 && m_uiManager->m_progressBar->maximum() == 100) {
            if (!message.isEmpty()) {
                m_uiManager->m_progressLabel->setText(QStringLiteral("%1% - %2").arg(percentage).arg(message));
            } else {
                m_uiManager->m_progressLabel->setText(QStringLiteral("%1%").arg(percentage));
            }
        } else if (!message.isEmpty()) {
            // Busy/indeterminate mode (finalizing UI)
            m_uiManager->m_progressLabel->setText(message);
        }
        // Keep tooltip updated but avoid status-bar spam/misleading "Parsing complete" during post-parse work.
        if (!message.isEmpty()) {
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
void MainWindow::showFindingsInsightHtml(const QString &html)
{
    if (m_uiManager && m_uiManager->m_findingsInsightText) {
        if (html.isEmpty()) {
            m_uiManager->m_findingsInsightText->clear();
        } else {
            m_uiManager->m_findingsInsightText->setHtml(html);
        }
    }
}

void MainWindow::onTreeItemClicked(QTreeWidgetItem *item, int column)
{
    if (m_structureTreeController) {
        m_structureTreeController->handleTreeItemClicked(item, column);
    }
}

void MainWindow::onHexViewerByteClicked(qint64 offset, int length)
{
    Q_UNUSED(offset);
    Q_UNUSED(length);
}

void MainWindow::onApplicationLanguageChanged(const QString &languageCode)
{
    Q_UNUSED(languageCode);

    PEParserNew::clearFieldExplanationCaches();

    // With QueuedConnection from languageChanged, this slot runs after the menu action returns. Still defer
    // heavy PE/hex rebuild so tree/slot paths are not nested with tab widgets updating.
    updateUILanguage();
    if (m_chrome) {
        m_chrome->updateLanguageMenu();
    }
    menuBar()->update();

    if (m_fileLoaded) {
        updateHexViewerLanguage();
        ++m_languageRefreshEpoch;
        const quint64 langEpoch = m_languageRefreshEpoch;
        QTimer::singleShot(0, this, [this, langEpoch]() {
            if (!m_fileLoaded) {
                return;
            }
            if (langEpoch != m_languageRefreshEpoch) {
                return;
            }
            refreshOpenFileAfterLanguageChange(langEpoch);
            updateHexViewerLanguage();
        });
        return;
    }

    updateHexViewerLanguage();
}


void MainWindow::refreshOpenFileAfterLanguageChange(quint64 languageRefreshEpoch)
{
    if (languageRefreshEpoch != 0 && m_languageRefreshEpoch != languageRefreshEpoch) {
        return;
    }
    if (!m_fileLoaded || !m_uiManager || !m_peParser) {
        return;
    }

    if (m_structureTreeController) {
        m_structureTreeController->resetSessionState();
    }

    if (m_stringsController) {
        m_stringsController->stopExtractionSynchronously();
        m_stringsController->invalidate();
        m_stringsController->clear();
        m_stringsController->setFileLoaded(true);
        m_stringsController->setFilePath(m_currentFilePath);
    }
    if (m_importsController) {
        m_importsController->invalidate();
        m_importsController->clear();
        m_importsController->setFileLoaded(true);
    }
    if (m_resourcesController) {
        m_resourcesController->clear();
    }
    if (m_dependenciesController) {
        m_dependenciesController->invalidate();
        m_dependenciesController->clear();
        m_dependenciesController->setFileLoaded(true);
        m_dependenciesController->setFilePath(m_currentFilePath);
    }
    if (m_exportsController) {
        m_exportsController->invalidate();
    }

    m_analysisDisplay->setFileLoaded(m_fileLoaded);
    m_analysisDisplay->setCurrentFilePath(m_currentFilePath);
    m_analysisDisplay->scheduleDisplay(QString(), [this]() {
        if (m_dependenciesController) {
            m_dependenciesController->updateExpandCollapseButtonState();
        }
        if (m_uiManager && m_uiManager->m_peTree) {
            QTreeWidgetItem *currentItem = m_uiManager->m_peTree->currentItem();
            if (currentItem && currentItem->treeWidget() == m_uiManager->m_peTree) {
                onTreeItemClicked(currentItem, 0);
            }
        }
    }, languageRefreshEpoch);
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

void MainWindow::onExpandAllDependencies()
{
    if (m_dependenciesController) {
        m_dependenciesController->expandAll();
    }
}

void MainWindow::onCollapseAllDependencies()
{
    if (m_dependenciesController) {
        m_dependenciesController->collapseAll();
    }
}

void MainWindow::onDependenciesCustomContextMenu(const QPoint &pos)
{
    if (m_dependenciesController) {
        m_dependenciesController->handleCustomContextMenu(pos);
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

// Private helper methods
void MainWindow::loadPEFile(const QString &filePath)
{
    try {
        if (m_chrome) {
            m_chrome->addToRecentFiles(filePath);
        }
        CrashHandler::getInstance().logInfo("MainWindow", QString("Loading PE file: %1").arg(filePath));
        
        m_currentFilePath = filePath;
        m_fileLoaded = false;
        clearDisplay();

        if (m_uiManager) {
            m_uiManager->m_progressBar->setVisible(true);
            m_uiManager->m_progressBar->setRange(0, 100);
            m_uiManager->m_progressBar->setValue(0);
            m_uiManager->m_progressLabel->setText(QStringLiteral("0% - %1").arg(LANG("UI/status_loading")));
        }
        
        statusBar()->showMessage(LANG("UI/status_loading"));
        
        CrashHandler::getInstance().logInfo("MainWindow", "Starting async PE parsing...");
        m_peParser->loadFileAsync(filePath);
        
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
    if (m_analysisDisplay) {
        m_analysisDisplay->setFileLoaded(false);
        m_analysisDisplay->setCurrentFilePath(QString());
    }
    if (m_structureTreeController) {
        m_structureTreeController->resetSessionState();
    }
    if (m_stringsController) {
        m_stringsController->setFileLoaded(false);
        m_stringsController->stopExtractionSynchronously();
        m_stringsController->clear();
    }

    // Access UI components through UIManager
    if (m_uiManager) {
        // Clear tree highlights before clearing the tree
        if (m_structureTreeController) {
            m_structureTreeController->clearTreeHighlights();
        }
        
        m_uiManager->m_peTree->setCurrentItem(nullptr);
        m_uiManager->m_peTree->clear();
        m_uiManager->m_fieldExplanationText->clear();
        m_uiManager->m_fileInfoLabel->setText(LANG("UI/file_no_file_loaded"));
        m_fileLoaded = false;
        m_uiManager->m_refreshButton->setEnabled(false);
        m_uiManager->m_copyButton->setEnabled(false);
        m_uiManager->m_saveButton->setEnabled(false);
        if (m_uiManager->m_expandAllButton) m_uiManager->m_expandAllButton->setEnabled(false);
        if (m_uiManager->m_collapseAllButton) m_uiManager->m_collapseAllButton->setEnabled(false);
        if (m_importsController) {
            m_importsController->setFileLoaded(false);
            m_importsController->clear();
        }
        if (m_resourcesController) {
            m_resourcesController->clear();
        }
        if (m_dependenciesController) {
            m_dependenciesController->setFileLoaded(false);
            m_dependenciesController->clear();
        }
        if (m_exportsController) {
            m_exportsController->clear();
        }
        if (m_findingsController) {
            m_findingsController->clear();
        }

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

    if (m_peParser && m_peParser->isValid()) {
        const PEDataModel &dm = m_peParser->getDataModel();
        const PEOverlayInfo overlay = dm.getOverlayInfo();
        const PEEntropySummary entropy = dm.getEntropySummary();
        const PEPdbInfo pdb = dm.getPdbInfo();

        QMap<QString, QString> ap;
        ap["overlay"] = overlay.present ? LANG("UI/overlay_present_short") : LANG("UI/overlay_none_short");
        if (entropy.fileEntropyValid) {
            ap["entropy"] = QStringLiteral("%1 %2").arg(QString::number(entropy.fileEntropy, 'f', 2),
                                                        LANG("UI/entropy_unit"));
        } else {
            ap["entropy"] = QStringLiteral("-");
        }
        if (pdb.present && !pdb.path.isEmpty()) {
            ap["pdb"] = QFileInfo(pdb.path).fileName();
        } else {
            ap["pdb"] = LANG("UI/pdb_none_short");
        }
        info += QStringLiteral(" | ") + LANG_PARAMS("UI/file_analysis_summary", ap);
    }
    
    m_uiManager->m_fileInfoLabel->setText(info);
    m_uiManager->m_refreshButton->setEnabled(true);
    m_uiManager->m_copyButton->setEnabled(true);
    m_uiManager->m_saveButton->setEnabled(true);
}




void MainWindow::onFindingsFilterChanged()
{
    if (m_findingsController) {
        m_findingsController->applyFilter();
    }
}

void MainWindow::onOverviewItemClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column);
    if (m_findingsController) {
        m_findingsController->handleOverviewItemClicked(item);
    }
}

void MainWindow::onFindingsItemClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column);
    if (m_findingsController) {
        m_findingsController->handleFindingItemClicked(item);
    }
}

void MainWindow::onStringsFilterChanged()
{
    if (m_stringsController) {
        m_stringsController->handleFilterChanged(sender());
    }
}

void MainWindow::onCancelStringsExtraction()
{
    if (m_stringsController) {
        m_stringsController->handleCancelExtraction();
    }
}

void MainWindow::onExportStrings()
{
    if (m_stringsController) {
        m_stringsController->handleExport();
    }
}

void MainWindow::onStringsTreeItemDoubleClicked(QTreeWidgetItem *item, int column)
{
    if (m_stringsController) {
        m_stringsController->handleTreeItemDoubleClicked(item, column);
    }
}

void MainWindow::onResourcesItemClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column);
    if (m_resourcesController) {
        m_resourcesController->handleItemClicked(item);
    }
}

void MainWindow::onImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    if (m_importsController) {
        m_importsController->handleImportModuleSelected(current, previous);
    }
}

void MainWindow::onImportFunctionSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    if (m_importsController) {
        m_importsController->handleImportFunctionSelected(current, previous);
    }
}

void MainWindow::onDelayImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    if (m_importsController) {
        m_importsController->handleDelayImportModuleSelected(current, previous);
    }
}

void MainWindow::onAnalysisTabChanged(int index)
{
    if (!m_fileLoaded || !m_uiManager || !m_peParser || !m_peParser->isValid()) {
        return;
    }

    switch (index) {
        case 1:
            if (m_importsController) {
                m_importsController->refreshImports();
            }
            break;
        case 2:
            if (m_importsController) {
                m_importsController->refreshDelayImports();
            }
            break;
        case 3:
            if (m_exportsController) {
                m_exportsController->refresh();
            }
            break;
        case 4:
            if (m_resourcesController) {
                m_resourcesController->refresh();
            }
            break;
        case 5:
            if (m_dependenciesController) {
                m_dependenciesController->refresh();
            }
            break;
        case 6:
            if (m_stringsController) {
                m_stringsController->refresh();
            }
            break;
        default:
            break;
    }
}


void MainWindow::showError(const QString &title, const QString &message)
{
    QMessageBox::critical(this, title, message);
}

QString MainWindow::getFileSizeString(qint64 size) const
{
    if (size < 1024) {
        return LANG_PARAM("UI/size_bytes", "size", QString::number(size));
    } else if (size < 1024 * 1024) {
        return LANG_PARAM("UI/size_kb", "size", QString::number(size / 1024.0, 'f', 1));
    } else {
        return LANG_PARAM("UI/size_mb", "size", QString::number(size / (1024.0 * 1024.0), 'f', 1));
    }
}

void MainWindow::updateUILanguage()
{
    if (m_chrome) {
        m_chrome->refreshTranslatedUi(m_fileLoaded);
        if (m_fileLoaded) {
            updateFileInfo();
        }
    }
}

void MainWindow::updateHexViewerLanguage()
{
    if (m_uiManager && m_uiManager->m_hexViewer) {
        m_uiManager->m_hexViewer->updateLanguage();
    }
}
