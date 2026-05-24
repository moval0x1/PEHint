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
#include "pe_data_model.h"
#include "pe_structures.h"
#include "pe_dependency_analyzer.h"
#include "pe_string_extractor.h"
#include "pe_findings.h"
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
#include <QtConcurrent/QtConcurrent>

namespace {
QString recentFilesIniPath()
{
    const QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!baseDir.isEmpty()) {
        QDir().mkpath(baseDir);
        return QDir(baseDir).filePath(QStringLiteral("recent_files.ini"));
    }
    return QDir::home().filePath(QStringLiteral(".pehint_recent_files.ini"));
}

QString dependencyTooltipText(const DependencyNode &node)
{
    QString t;
    if (node.cycleDetected) {
        t = LANG("UI/deps_tooltip_cycle");
    } else {
        t = node.depth == 0 ? LANG("UI/deps_tooltip_direct") : LANG("UI/deps_tooltip_transitive");
        if (node.truncatedByDepth) {
            t += QStringLiteral("\n\n") + LANG("UI/deps_tooltip_truncated");
        }
        if (!node.foundOnSystem) {
            t += QStringLiteral("\n\n") + LANG("UI/deps_tooltip_not_found");
        }
    }
    const QString native = QDir::toNativeSeparators(node.resolvedPath);
    if (!native.isEmpty()) {
        t += QStringLiteral("\n\n") + LANG_PARAM("UI/deps_tooltip_resolved_line", "path", native);
    } else if (!node.foundOnSystem) {
        t += QStringLiteral("\n\n") + LANG("UI/deps_tooltip_no_path");
    }
    return t;
}

constexpr int kFieldOffsetRole = Qt::UserRole + 20;
constexpr int kFieldSizeRole = Qt::UserRole + 21;
constexpr int kImportByOrdinalRole = Qt::UserRole + 31;
constexpr int kFindingCategoryHeaderRole = Qt::UserRole + 41;
constexpr int kFindingRuleIdRole = Qt::UserRole + 42;

QColor flaggedImportRowColor(PEFindingSeverity severity)
{
    switch (severity) {
    case PEFindingSeverity::High:
        return QColor(255, 230, 230);
    case PEFindingSeverity::Medium:
        return QColor(255, 248, 220);
    case PEFindingSeverity::Low:
        return QColor(240, 248, 255);
    default:
        return QColor(245, 245, 245);
    }
}

void applyFlaggedImportRowStyle(QTreeWidgetItem *item, const QString &moduleName,
                                const PEDataModel::ImportFunctionEntry &entry)
{
    if (!item || entry.name.isEmpty() || entry.importedByOrdinal) {
        return;
    }
    PEFindingSeverity severity = PEFindingSeverity::Medium;
    QString note;
    if (!PEFindingsEngine::isFlaggedImport(moduleName, entry.name, &severity, &note)) {
        return;
    }
    const QColor bg = flaggedImportRowColor(severity);
    for (int col = 0; col < item->columnCount(); ++col) {
        item->setBackground(col, bg);
    }
    if (!note.isEmpty()) {
        QMap<QString, QString> params;
        params[QStringLiteral("note")] = note;
        item->setToolTip(0, LANG_PARAMS(QStringLiteral("UI/imports_flagged_tooltip"), params));
    } else {
        item->setToolTip(0, LANG(QStringLiteral("UI/imports_flagged_tooltip_short")));
    }
}

QString formatHardcodedMatchesInsightHtml(const QString &title, const QString &intro,
                                          const QVector<PEHardcodedMatch> &matches)
{
    QString html = QStringLiteral(
                       "<div style='font-family:\"Segoe UI\",Arial,sans-serif;font-size:11px;"
                       "color:#222;line-height:1.55;'>"
                       "<p style='font-weight:600;font-size:12px;margin:0 0 6px 0;'>%1</p>"
                       "<p style='color:#555;margin:0 0 8px 0;'>%2</p>"
                       "<ul style='margin:0;padding-left:18px;'>")
                       .arg(title.toHtmlEscaped(), intro.toHtmlEscaped());
    for (const PEHardcodedMatch &m : matches) {
        html += QStringLiteral("<li style='margin-bottom:4px;'><code>%1</code> "
                               "<span style='color:#666;'>@ %2</span></li>")
                    .arg(m.value.toHtmlEscaped(), PEUtils::formatHexWidth(m.fileOffset, 8));
    }
    html += QStringLiteral("</ul></div>");
    return html;
}

/** File Insights rows that attach explicit offset/size roles for hex sync. */
bool fileInsightUsesHexRoles(const QString &fieldName)
{
    return fieldName == QLatin1String("Overlay") || fieldName == QLatin1String("PDB Path")
           || fieldName == QLatin1String("PDB Raw") || fieldName == QLatin1String("PDB GUID")
           || fieldName == QLatin1String("PDB Age") || fieldName == QLatin1String("Entry Point");
}

/** Parse "(0xNNNN bytes)" from File Insights value text when tree size role is zero. */
bool parseInsightByteSizeFromValue(const QString &valueText, quint32 &outSize)
{
    static const QRegularExpression sizeInParens(
        QStringLiteral("\\(0x([0-9A-Fa-f]+) bytes\\)"), QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = sizeInParens.match(valueText);
    if (!match.hasMatch()) {
        return false;
    }
    bool ok = false;
    const quint32 parsed = match.captured(1).toUInt(&ok, 16);
    if (!ok || parsed == 0) {
        return false;
    }
    outSize = parsed;
    return true;
}

QString importHintPlaceholderText()
{
    return LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_placeholder"),
        QStringLiteral("Select an imported function. PEHint shows curated summaries; richer entries may include signature, parameters, and return value (informative only—not live Microsoft data)."));
}

QString importHintTitleText()
{
    return LanguageManager::getInstance().getString(QStringLiteral("UI/imports_hint_title"), QStringLiteral("API summary"));
}

QString importHintFooterText()
{
    return LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_footer"),
        QStringLiteral("Tip: On Microsoft Learn, search for the function name (for example CreateFileW) to open the full topic."));
}

QString importHintOrdinalText()
{
    return LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_ordinal"),
        QStringLiteral("This import is bound by ordinal only and PEHint could not resolve a name from the system copy of the exporting DLL (missing file or unnamed export). Check the DLL’s exports or Microsoft Learn for that ordinal."));
}

QString importHintNoneForFunction(const QString &funcName)
{
    QMap<QString, QString> p;
    p.insert(QStringLiteral("name"), funcName);
    return LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_none"),
        p,
        QStringLiteral("No built-in summary for {name}. Search Microsoft Learn for the full reference and parameters."));
}

QString formatImportHintDisplay(const ImportApiHint &h, const QString &optionalBannerHtml = QString())
{
    // Section titles and the Learn tip stay English so they match Microsoft Learn topics even when the app UI is localized.
    auto escTitle = [](const QString &s) -> QString { return QString(s).toHtmlEscaped(); };

    QStringList html;
    html << QStringLiteral("<html><head><meta charset=\"utf-8\"/><style>");
    html << QStringLiteral(
        "body{font-family:'Segoe UI',Arial,sans-serif;font-size:11px;color:#222;margin:0;padding:0;line-height:1.5;}");
    html << QStringLiteral(
        "a{color:#0066cc;text-decoration:none;} a:hover{text-decoration:underline;}");
    html << QStringLiteral(".sec{font-weight:600;margin:14px 0 6px 0;color:#111;font-size:12px;}");
    html << QStringLiteral(
        ".learn-doc{font-size:11px;color:#222;}"
        ".learn-doc table{border-collapse:collapse;width:100%;margin:8px 0;font-size:11px;}"
        ".learn-doc th,.learn-doc td{border:1px solid #e0e0e0;padding:5px 8px;text-align:left;vertical-align:top;}"
        ".learn-doc th{background:#f3f3f3;font-weight:600;}"
        ".learn-doc pre,.learn-doc code{font-family:Consolas,'Cascadia Mono','Segoe UI Mono',monospace;}"
        ".learn-doc pre{background:#f6f6f6;border:1px solid #e8e8e8;border-radius:4px;padding:8px;font-size:10px;"
        "margin:8px 0;white-space:pre-wrap;word-wrap:break-word;}"
        ".learn-doc p{margin:6px 0;}"
        ".learn-doc ul,.learn-doc ol{margin:6px 0 6px 22px;padding:0;}"
        ".learn-doc li{margin:2px 0;}"
        ".learn-doc blockquote{margin:8px 0 8px 6px;padding:4px 0 4px 10px;border-left:3px solid #ccc;color:#333;}"
        ".param-item{margin:10px 0;padding:0;border-bottom:1px solid #eee;}"
        ".param-item:last-child{border-bottom:none;}"
        ".hint-foot{margin-top:12px;padding-top:8px;border-top:1px solid #e8e8e8;color:#666;font-size:10px;}");
    html << QStringLiteral("</style></head><body>");
    if (!optionalBannerHtml.isEmpty()) {
        html << optionalBannerHtml;
    }

    if (!h.summary.isEmpty()) {
        html << h.summary;
    }
    if (!h.signature.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Signature")) + QStringLiteral("</p>") + h.signature;
    }
    if (!h.parameters.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Parameters")) + QStringLiteral("</p>");
        for (const QString &paramLine : h.parameters) {
            html << paramLine;
        }
    }
    if (!h.returns.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Return value")) + QStringLiteral("</p>") + h.returns;
    }
    if (!h.remarks.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Remarks")) + QStringLiteral("</p>") + h.remarks;
    }
    if (!h.learnUrl.isEmpty()) {
        html << QStringLiteral("<p class=\"sec\">") + escTitle(QStringLiteral("Documentation")) + QStringLiteral("</p>");
        html << QStringLiteral("<p><a href=\"")
             + h.learnUrl.toHtmlEscaped() + QStringLiteral("\">") + h.learnUrl.toHtmlEscaped()
             + QStringLiteral("</a></p>");
    } else {
        const QString foot = QStringLiteral(
                                   "Tip: On Microsoft Learn, search for the function name (for example CreateFileW) to open the full topic.")
                                   .toHtmlEscaped()
                                   .replace(QLatin1Char('\n'), QStringLiteral("<br/>"));
        html << QStringLiteral("<p class=\"hint-foot\">") + foot + QStringLiteral("</p>");
    }
    html << QStringLiteral("</body></html>");
    return html.join(QString());
}

QColor colorForTreeSelection(const QTreeWidgetItem *item)
{
    if (!item) {
        return QColor(255, 235, 120, 180);
    }

    // Resolve the top-level container so descendants keep the same family color.
    const QTreeWidgetItem *root = item;
    while (root->parent()) {
        root = root->parent();
    }

    const QString rootName = root->text(0).toLower();
    if (rootName.contains(QStringLiteral("dos"))) {
        return QColor(230, 80, 80, 185);   // Red family
    }
    if (rootName.contains(QStringLiteral("rich"))) {
        return QColor(235, 170, 65, 185);  // Orange family
    }
    if (rootName.contains(QStringLiteral("nt"))) {
        return QColor(175, 195, 95, 185);  // Olive/green family
    }
    if (rootName.contains(QStringLiteral("section"))) {
        return QColor(100, 185, 205, 185); // Cyan family
    }
    if (rootName.contains(QStringLiteral("data"))) {
        return QColor(165, 145, 220, 185); // Purple family
    }

    return QColor(255, 235, 120, 180);     // Fallback yellow
}

QString normalizedSectionName(const IMAGE_SECTION_HEADER *section)
{
    if (!section) return QStringLiteral("(unknown)");
    const char *namePtr = reinterpret_cast<const char*>(section->Name);
    bool hasPrintable = false;
    for (int i = 0; i < 8; ++i) {
        const unsigned char c = static_cast<unsigned char>(namePtr[i]);
        if (c >= 32 && c <= 126) {
            hasPrintable = true;
            break;
        }
    }
    if (hasPrintable) {
        int len = 0;
        while (len < 8) {
            const unsigned char c = static_cast<unsigned char>(namePtr[len]);
            if (c == 0 || c < 32 || c > 126) break;
            ++len;
        }
        if (len > 0) {
            return QString::fromLatin1(namePtr, len);
        }
    }
    QByteArray nameBytes(namePtr, 8);
    return QStringLiteral("0x") + QString::fromLatin1(nameBytes.toHex()).toUpper();
}

void appendDependencyTreeText(QTreeWidgetItem *item, QString *out, int depth)
{
    const QString pad(depth * 2, QLatin1Char(' '));
    *out += pad + item->text(0) + QLatin1Char('\t') + item->text(1) + QLatin1Char('\t') + item->text(2) + QLatin1Char('\n');
    for (int i = 0; i < item->childCount(); ++i) {
        appendDependencyTreeText(item->child(i), out, depth + 1);
    }
}

QString fullDependencyTreeText(QTreeWidget *tree)
{
    QString out;
    for (int i = 0; i < tree->topLevelItemCount(); ++i) {
        appendDependencyTreeText(tree->topLevelItem(i), &out, 0);
    }
    return out;
}

}

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
    , m_stringsExtractionRunning(false)
    , m_contextMenu(nullptr)
    , m_languageActionGroup(nullptr)
    , m_openRecentMenu(nullptr)
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
    
    // Now that UI is set up, we can access UI components
    setupConnections();
    setupMenus();
    loadRecentFiles();
    updateOpenRecentMenu();
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
    icon.addFile(":/images/imgs/PEHint-ico.png");
    this->setWindowIcon(icon);
    
    // Initial state - Now UI components are available
    clearDisplay();

    // Apply button tooltips and other LANG-driven chrome (e.g. Copy shortcut hint).
    updateUILanguage();
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
    
    // Language Manager: always queue — never run UI refresh inside setLanguage()'s emit stack or while a
    // native QMenu is closing (Windows access violations otherwise).
    connect(&LanguageManager::getInstance(), &LanguageManager::languageChanged,
            this, &MainWindow::onApplicationLanguageChanged, Qt::QueuedConnection);
    
    // REFACTORED: Use UI Manager to setup connections
    // This extracts UI-specific connections from MainWindow, reducing coupling
    // MainWindow no longer needs to know about m_refreshButton, m_copyButton, etc.
    m_uiManager->setupConnections(this);
    connect(&m_stringsExtractionWatcher, &QFutureWatcher<StringExtractionResult>::finished,
            this, &MainWindow::onStringsExtractionFinished);

    if (m_uiManager->m_dependenciesTree) {
        connect(m_uiManager->m_dependenciesTree, &QTreeWidget::customContextMenuRequested,
                this, &MainWindow::onDependenciesCustomContextMenu);
    }
    
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
    // PNG renders reliably in Windows menu bar; .ico often does not for QAction icons
    openAction->setIcon(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")));
    openAction->setShortcut(QKeySequence::Open);
    fileMenu->addAction(openAction);

    // Open Recent submenu (icon on the menu's QAction in the parent menu bar)
    m_openRecentMenu = fileMenu->addMenu(LANG("UI/menu_open_recent"));
    m_openRecentMenu->setEnabled(false); // Enabled once recent files are loaded
    if (QAction *recentMenuAct = m_openRecentMenu->menuAction()) {
        recentMenuAct->setIcon(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")));
    }

    QAction *clearRecentOnExitAction = new QAction(LANG("UI/menu_clear_recent_on_exit"), this);
    clearRecentOnExitAction->setCheckable(true);
    clearRecentOnExitAction->setIcon(QIcon(QStringLiteral(":/images/imgs/clear.png")));
    {
        QSettings settings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
        clearRecentOnExitAction->setChecked(settings.value(QStringLiteral("ui/clearRecentOnExit"), false).toBool());
    }
    fileMenu->addAction(clearRecentOnExitAction);
    connect(clearRecentOnExitAction, &QAction::toggled, this, [](bool checked) {
        QSettings settings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
        settings.setValue(QStringLiteral("ui/clearRecentOnExit"), checked);
    });
    
    QAction *saveReportAction = new QAction(LANG("UI/menu_save_report"), this);
    saveReportAction->setIcon(QIcon(":/images/imgs/save.png"));
    fileMenu->addAction(saveReportAction);
    
    fileMenu->addSeparator();
    
    QAction *exitAction = new QAction(LANG("UI/menu_exit"), this);
    exitAction->setIcon(QIcon(QStringLiteral(":/images/imgs/logout.png")));
    exitAction->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Q));
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

    // About menu: text label on the menu bar only (no QMenu::setIcon — that hides the title and looks wrong on Windows)
    QMenu *aboutMenu = menuBar()->addMenu(LANG("UI/menu_about"));

    QAction *aboutAction = new QAction(LANG("UI/menu_about"), this);
    aboutAction->setIcon(QIcon(QStringLiteral(":/images/imgs/about.png")));
    aboutAction->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_A));
    aboutMenu->addAction(aboutAction);
    
    // Connect actions
    connect(openAction, &QAction::triggered, this, &MainWindow::on_action_Open_triggered);
    connect(saveReportAction, &QAction::triggered, this, &MainWindow::on_action_Save_Report_triggered);
    connect(exitAction, &QAction::triggered, this, &MainWindow::on_action_Exit_triggered);
    connect(refreshAction, &QAction::triggered, this, &MainWindow::on_action_Refresh_triggered);
    connect(hexViewerAction, &QAction::triggered, this, &MainWindow::onHexViewerOptions);
    connect(aboutAction, &QAction::triggered, this, &MainWindow::on_action_PEHint_triggered);

    // Register on the main window so shortcuts (Ctrl+O, F5, etc.) work while focus is in
    // the tree, hex view, or text fields — not only when the menu bar has focus.
    addAction(openAction);
    addAction(saveReportAction);
    addAction(exitAction);
    addAction(refreshAction);
    addAction(hexViewerAction);
    addAction(aboutAction);

    CrashHandler::getInstance().logInfo("MainWindow", "Application menus setup completed");
}

void MainWindow::loadRecentFiles()
{
    QSettings recentSettings(recentFilesIniPath(), QSettings::IniFormat);
    m_recentFiles = recentSettings.value(QStringLiteral("recentFiles")).toStringList();

    // One-time migration from legacy registry-backed settings.
    if (m_recentFiles.isEmpty()) {
        QSettings legacySettings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
        const QStringList legacyRecents = legacySettings.value(QStringLiteral("recentFiles")).toStringList();
        if (!legacyRecents.isEmpty()) {
            m_recentFiles = legacyRecents;
            recentSettings.setValue(QStringLiteral("recentFiles"), m_recentFiles);
        }
    }

    // Drop entries that no longer exist on disk.
    QStringList filtered;
    for (const QString &p : m_recentFiles) {
        if (!p.trimmed().isEmpty() && QFileInfo(p).exists()) {
            filtered.append(p);
        }
    }
    m_recentFiles = filtered;
}

void MainWindow::saveRecentFiles() const
{
    QSettings recentSettings(recentFilesIniPath(), QSettings::IniFormat);
    recentSettings.setValue(QStringLiteral("recentFiles"), m_recentFiles);
}

void MainWindow::updateOpenRecentMenu()
{
    if (!m_openRecentMenu) return;

    m_openRecentMenu->clear();

    constexpr int MAX_RECENTS = 10;
    if (m_recentFiles.isEmpty()) {
        QAction *placeholder = m_openRecentMenu->addAction(LANG("UI/menu_no_recent_files"));
        placeholder->setEnabled(false);
        m_openRecentMenu->setEnabled(false);
        return;
    }

    m_openRecentMenu->setEnabled(true);
    const int count = qMin(MAX_RECENTS, m_recentFiles.size());
    for (int i = 0; i < count; ++i) {
        const QString &path = m_recentFiles.at(i);
        if (path.trimmed().isEmpty()) continue;
        const QString label = QFileInfo(path).fileName().isEmpty() ? path : QFileInfo(path).fileName();
        QAction *act = m_openRecentMenu->addAction(label);
        act->setData(path);
        connect(act, &QAction::triggered, this, [this, path]() {
            loadPEFile(path);
        });
    }

    m_openRecentMenu->addSeparator();
    QAction *clearAct = m_openRecentMenu->addAction(LANG("UI/menu_clear_recent"));
    clearAct->setIcon(QIcon(QStringLiteral(":/images/imgs/clear.png")));
    connect(clearAct, &QAction::triggered, this, [this]() {
        m_recentFiles.clear();
        saveRecentFiles();
        updateOpenRecentMenu();
    });
}

void MainWindow::addToRecentFiles(const QString &filePath)
{
    const QString trimmed = filePath.trimmed();
    if (trimmed.isEmpty()) return;
    if (!QFileInfo(trimmed).exists()) return;

    m_recentFiles.removeAll(trimmed);
    m_recentFiles.prepend(trimmed);

    // Keep list compact.
    constexpr int MAX_RECENTS = 10;
    if (m_recentFiles.size() > MAX_RECENTS) {
        m_recentFiles = m_recentFiles.mid(0, MAX_RECENTS);
    }

    saveRecentFiles();
    updateOpenRecentMenu();
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
    copyAction->setIcon(QIcon(QStringLiteral(":/images/imgs/copy.png")));
    copyAction->setShortcut(QKeySequence::Copy);
    m_contextMenu->addAction(copyAction);
    
    m_contextMenu->addSeparator();
    
    QAction *expandAction = new QAction(LANG("UI/context_expand_all"), m_contextMenu);
    expandAction->setIcon(QIcon(QStringLiteral(":/images/imgs/expand.png")));
    m_contextMenu->addAction(expandAction);
    
    QAction *collapseAction = new QAction(LANG("UI/context_collapse_all"), m_contextMenu);
    collapseAction->setIcon(QIcon(QStringLiteral(":/images/imgs/collapse.png")));
    m_contextMenu->addAction(collapseAction);
    
    connect(copyAction, &QAction::triggered, this, &MainWindow::onCopyToClipboard);
    connect(expandAction, &QAction::triggered, this, &MainWindow::onExpandAll);
    connect(collapseAction, &QAction::triggered, this, &MainWindow::onCollapseAll);

    // Same as menu actions: context menu shortcuts must be on the main window to work
    // when a child widget has focus.
    addAction(copyAction);
    addAction(expandAction);
    addAction(collapseAction);

    // Hex view installs an event filter that handles Ctrl+C for hex copy; use Ctrl+Shift+C
    // to copy the field explanation when the hex pane has keyboard focus.
    auto *copyFieldAlt = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C), this);
    copyFieldAlt->setContext(Qt::ApplicationShortcut);
    connect(copyFieldAlt, &QShortcut::activated, this, &MainWindow::onCopyToClipboard);
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

namespace {
/**
 * Resolve About-dialog strings with English fallbacks when the deployed language_config*.ini
 * is older than the app and omits keys (otherwise getString returns the raw key, e.g. "UI/about_description").
 */
QString aboutLine(const QString &key, const QString &englishFallback)
{
    const QString s = LanguageManager::getInstance().getString(key, englishFallback);
    return (s == key) ? englishFallback : s;
}

/** Strip leading "- " from feature lines for HTML bullet list display. */
QString aboutFeatureBody(const QString &line)
{
    QString t = line.trimmed();
    if (t.startsWith(QLatin1Char('-'))) {
        t = t.mid(1).trimmed();
    }
    return t;
}
} // namespace

// Menu action handlers
void MainWindow::on_action_PEHint_triggered()
{
    LanguageManager &lm = LanguageManager::getInstance();

    QMap<QString, QString> verParams;
    verParams[QStringLiteral("version")] = QStringLiteral(PEHINT_VERSION_STRING);
    const QString versionLine = lm.getString(QStringLiteral("UI/about_version"), verParams,
                                             QStringLiteral("Version: {version}"));

    const QString titleText = aboutLine(QStringLiteral("UI/about_title"), QStringLiteral("About PEHint"));
    const QString authorHtml = aboutLine(QStringLiteral("UI/about_author"),
        QStringLiteral("Author: <a href='https://moval0x1.github.io/'>moval0x1</a>"));
    const QString descText = aboutLine(QStringLiteral("UI/about_description"),
        QStringLiteral("A visual PE file analyzer for learning, reverse engineering, and quick structural inspection."));
    const QString featuresHeading = aboutLine(QStringLiteral("UI/about_features"), QStringLiteral("Features:"));
    const QString footerText = aboutLine(QStringLiteral("UI/about_perfect"),
        QStringLiteral("Open source (MIT) — learn the PE format without jumping between tools."));

    const QStringList featureLines = {
        aboutLine(QStringLiteral("UI/about_feature_1"),
                  QStringLiteral("- Interactive structure tree: DOS headers, NT headers, sections, and all 16 data directories")),
        aboutLine(QStringLiteral("UI/about_feature_2"),
                  QStringLiteral("- Field explanations in the dedicated explanation panel")),
        aboutLine(QStringLiteral("UI/about_feature_3"),
                  QStringLiteral("- Imports and Exports views; Dependencies tab with DLL resolution; Strings tab with extraction and export")),
        aboutLine(QStringLiteral("UI/about_feature_4"),
                  QStringLiteral("- Hex viewer synchronized with tree selections and field ranges")),
        aboutLine(QStringLiteral("UI/about_feature_5"),
                  QStringLiteral("- English and Portuguese UI with external JSON explanations")),
    };

    QDialog about(this);
    about.setWindowTitle(titleText);
    about.setModal(true);
    about.setMinimumWidth(580);
    about.setMaximumWidth(720);

    auto *root = new QVBoxLayout(&about);
    root->setSpacing(14);
    root->setContentsMargins(28, 22, 28, 20);

    auto *headerRow = new QHBoxLayout();
    headerRow->setSpacing(22);

    constexpr int kAboutIconSize = 96;
    auto *iconLabel = new QLabel(&about);
    {
        const QPixmap pehintIcon(QStringLiteral(":/images/imgs/PEHint.png"));
        if (!pehintIcon.isNull()) {
            iconLabel->setPixmap(pehintIcon.scaled(kAboutIconSize, kAboutIconSize, Qt::KeepAspectRatio,
                                                   Qt::SmoothTransformation));
        }
        iconLabel->setAlignment(Qt::AlignTop | Qt::AlignHCenter);
        iconLabel->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    }

    auto *headCol = new QVBoxLayout();
    headCol->setSpacing(6);

    auto *titleLbl = new QLabel(titleText, &about);
    QFont titleFont = titleLbl->font();
    titleFont.setPointSizeF(titleFont.pointSizeF() + 2.5);
    titleFont.setBold(true);
    titleLbl->setFont(titleFont);
    titleLbl->setWordWrap(true);

    auto *verLbl = new QLabel(versionLine, &about);
    verLbl->setObjectName(QStringLiteral("aboutVersion"));
    verLbl->setForegroundRole(QPalette::Mid);

    auto *authorLbl = new QLabel(authorHtml, &about);
    authorLbl->setTextFormat(Qt::RichText);
    authorLbl->setOpenExternalLinks(true);
    authorLbl->setTextInteractionFlags(Qt::TextBrowserInteraction);

    headCol->addWidget(titleLbl);
    headCol->addWidget(verLbl);
    headCol->addWidget(authorLbl);
    headCol->addStretch(0);

    headerRow->addWidget(iconLabel, 0, Qt::AlignTop);
    headerRow->addLayout(headCol, 1);

    auto *descLbl = new QLabel(descText, &about);
    descLbl->setWordWrap(true);
    descLbl->setAlignment(Qt::AlignLeft | Qt::AlignTop);

    auto *sep1 = new QFrame(&about);
    sep1->setFrameShape(QFrame::HLine);
    sep1->setFrameShadow(QFrame::Plain);
    sep1->setForegroundRole(QPalette::Mid);

    auto *featHeadLbl = new QLabel(featuresHeading, &about);
    QFont featHeadFont = featHeadLbl->font();
    featHeadFont.setBold(true);
    featHeadLbl->setFont(featHeadFont);

    QString featHtml = QStringLiteral("<ul style=\"margin-top: 4px; margin-bottom: 0; padding-left: 22px;\">");
    for (const QString &raw : featureLines) {
        const QString item = aboutFeatureBody(raw).toHtmlEscaped();
        featHtml += QStringLiteral("<li style=\"margin-top: 5px;\">%1</li>").arg(item);
    }
    featHtml += QStringLiteral("</ul>");
    auto *featLbl = new QLabel(&about);
    featLbl->setTextFormat(Qt::RichText);
    featLbl->setText(featHtml);
    featLbl->setWordWrap(true);
    featLbl->setOpenExternalLinks(false);

    auto *sep2 = new QFrame(&about);
    sep2->setFrameShape(QFrame::HLine);
    sep2->setFrameShadow(QFrame::Plain);
    sep2->setForegroundRole(QPalette::Mid);

    auto *footLbl = new QLabel(footerText, &about);
    footLbl->setWordWrap(true);
    footLbl->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    QFont footFont = footLbl->font();
    footFont.setItalic(true);
    footFont.setPointSizeF(qMax(8.0, footFont.pointSizeF() - 0.5));
    footLbl->setFont(footFont);
    footLbl->setForegroundRole(QPalette::Mid);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok, &about);
    buttonBox->setCenterButtons(true);
    QObject::connect(buttonBox, &QDialogButtonBox::accepted, &about, &QDialog::accept);

    root->addLayout(headerRow);
    root->addWidget(descLbl);
    root->addWidget(sep1);
    root->addWidget(featHeadLbl);
    root->addWidget(featLbl);
    root->addWidget(sep2);
    root->addWidget(footLbl);
    root->addWidget(buttonBox);

    about.exec();
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
    QSettings settings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
    if (settings.value(QStringLiteral("ui/clearRecentOnExit"), false).toBool()) {
        m_recentFiles.clear();
        saveRecentFiles();
    }
    QApplication::quit();
}

void MainWindow::on_action_Save_Report_triggered()
{
    if (!m_fileLoaded) {
        showError(LANG("UI/menu_save_report"), LANG("UI/error_no_report"));
        return;
    }

    const QString textFilter = LANG("UI/file_filter_text");
    const QString htmlFilter = LANG("UI/file_filter_html");
    const QString jsonFilter = LANG("UI/file_filter_json");
    const QString xmlFilter = LANG("UI/file_filter_xml");
    const QString allFilter = LANG("UI/file_filter_all");
    const QString filters = QString("%1;;%2;;%3;;%4;;%5")
        .arg(textFilter).arg(htmlFilter).arg(jsonFilter).arg(xmlFilter).arg(allFilter);

    const QString defaultName = LANG("UI/file_default_report_name");
    QString selectedFilter = textFilter;
    QString filePath = QFileDialog::getSaveFileName(
        this,
        LANG("UI/dialog_save_analysis_report"),
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/" + defaultName,
        filters,
        &selectedFilter
    );

    if (filePath.isEmpty())
        return;

    const PEDataModel &dataModel = m_peParser->getDataModel();
    QString content;
    if (selectedFilter.contains("html", Qt::CaseInsensitive) ||
        filePath.endsWith(".html", Qt::CaseInsensitive) || filePath.endsWith(".htm", Qt::CaseInsensitive))
        content = buildFullHTMLReport(dataModel);
    else if (selectedFilter.contains("json", Qt::CaseInsensitive) || filePath.endsWith(".json", Qt::CaseInsensitive))
        content = buildFullJSONReport(dataModel);
    else if (selectedFilter.contains("xml", Qt::CaseInsensitive) || filePath.endsWith(".xml", Qt::CaseInsensitive))
        content = buildFullXMLReport(dataModel);
    else
        content = buildFullTextReport(dataModel);

    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream stream(&file);
        stream.setEncoding(QStringConverter::Utf8);
        stream << content;
        file.close();
        showInfo(LANG("UI/menu_save_report"), LANG("UI/info_save_success"));
    } else {
        showError(LANG("UI/menu_save_report"), LANG("UI/error_save_failed"));
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

            // Tree → welcome/hex → strings/tab on separate event-loop passes (keeps UI responsive).
            scheduleStagedAnalysisDisplay(completedPath, [this, completedPath]() {
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
MainWindow::FieldHexRange MainWindow::resolveFieldHexRange(QTreeWidgetItem *item,
                                                           const QString &fieldName) const
{
    FieldHexRange out;
    if (!item || !m_peParser || !m_peParser->isValid()) {
        return out;
    }

    quint32 offsetValue = 0;
    quint32 sizeValue = 0;
    bool offsetOk = false;
    bool sizeOk = false;

    const QVariant roleOffset = item->data(0, kFieldOffsetRole);
    const QVariant roleSize = item->data(0, kFieldSizeRole);
    const bool hasRoleSize = roleSize.isValid();
    const bool insightHexRoles =
        fileInsightUsesHexRoles(fieldName) && roleOffset.isValid() && hasRoleSize;

    if (insightHexRoles) {
        offsetValue = roleOffset.toUInt(&offsetOk);
        sizeValue = roleSize.toUInt(&sizeOk);
    } else {
        if (roleOffset.isValid()) {
            offsetValue = roleOffset.toUInt(&offsetOk);
        }
        if (hasRoleSize) {
            sizeValue = roleSize.toUInt(&sizeOk);
        }

        if (!offsetOk) {
            const QString offsetText = item->text(2).trimmed();
            if (offsetText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
                offsetValue = offsetText.mid(2).toUInt(&offsetOk, 16);
            }
        }

        if (!hasRoleSize) {
            const QString sizeText = item->text(3);
            const QRegularExpression sizeHexRe(QStringLiteral("0x([0-9A-Fa-f]+)"));
            const QRegularExpressionMatch sizeMatch = sizeHexRe.match(sizeText);
            if (sizeMatch.hasMatch()) {
                sizeValue = sizeMatch.captured(1).toUInt(&sizeOk, 16);
            }
        }

        if (offsetOk && sizeValue == 0) {
            quint32 parsedSize = 0;
            if (parseInsightByteSizeFromValue(item->text(1), parsedSize)) {
                sizeValue = parsedSize;
                sizeOk = true;
            }
        }

        if (!offsetOk || (!hasRoleSize && !sizeOk)) {
            const QPair<quint32, quint32> fieldOffset = m_peParser->getFieldOffset(fieldName);
            if (!offsetOk && fieldOffset.second > 0) {
                offsetValue = fieldOffset.first;
                offsetOk = true;
            }
            if (!hasRoleSize && !sizeOk && fieldOffset.second > 0) {
                sizeValue = fieldOffset.second;
                sizeOk = true;
            }
        }
    }

    if (offsetOk && sizeOk && sizeValue > 0) {
        out.offset = offsetValue;
        out.size = sizeValue;
        out.canHighlight = true;
    } else if (offsetOk) {
        out.offset = offsetValue;
        out.canGoTo = true;
    }
    return out;
}

void MainWindow::applyFieldHexNavigation(QTreeWidgetItem *item, const FieldHexRange &range)
{
    if (!m_uiManager || !m_uiManager->m_hexViewer) {
        return;
    }
    HexViewer *hex = m_uiManager->m_hexViewer;
    if (range.canHighlight) {
        const qint64 hexCap = hex->getDataSize();
        if (hexCap > 0 && static_cast<qint64>(range.offset) >= hexCap) {
            return;
        }
        const QColor highlightColor = colorForTreeSelection(item);
        const quint32 rgba = highlightColor.rgba();
        const bool sameHexAsLast = (static_cast<qint64>(range.offset) == m_lastHexHighlightOffset
                                    && range.size == m_lastHexHighlightSize && rgba == m_lastHexHighlightRgba);
        if (!sameHexAsLast) {
            hex->highlightRange(range.offset, range.size, highlightColor);
            m_lastHexHighlightOffset = static_cast<qint64>(range.offset);
            m_lastHexHighlightSize = range.size;
            m_lastHexHighlightRgba = rgba;
        }
    } else if (range.canGoTo) {
        hex->goToOffset(static_cast<qint64>(range.offset));
    }
}

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
    try {
        if (item && m_uiManager) {
            const QString displayFieldName = item->text(0);
            QString fieldName = displayFieldName;
            const QVariant treeKeyVar = item->data(0, PEParserNew::kTreeFieldKeyRole);
            if (treeKeyVar.isValid() && !treeKeyVar.toString().isEmpty()) {
                fieldName = treeKeyVar.toString();
            }
            Q_UNUSED(column);

            // Fast path: avoid expensive UI refresh if user re-selects same field.
            const bool sameFieldAsLast = (fieldName == m_lastExplainedFieldName);

            // Hex sync first: explanation loads JSON/HTML and can be slower; the hex view has a fast
            // path when the visible 256 KiB window does not move (see HexViewer::highlightRange).
            // Highlight the field in hex viewer
            if (m_peParser && m_peParser->isValid()) {
                const FieldHexRange range = resolveFieldHexRange(item, fieldName);
                if (range.canHighlight) {
                    HexViewer *hex = m_uiManager->m_hexViewer;
                    const qint64 hexCap = hex ? hex->getDataSize() : 0;
                    if (hex && hexCap > 0 && static_cast<qint64>(range.offset) >= hexCap) {
                        QMap<QString, QString> hp;
                        hp[QStringLiteral("offset")] = PEUtils::formatHexWidth(range.offset, 8);
                        hp[QStringLiteral("size")] = QString::number(hexCap);
                        statusBar()->showMessage(LANG_PARAMS(QStringLiteral("UI/hex_offset_beyond_buffer"), hp),
                                                 5000);
                    } else {
                        applyFieldHexNavigation(item, range);
                    }
                } else if (range.canGoTo) {
                    applyFieldHexNavigation(item, range);
                } else {
                    statusBar()->showMessage(LANG_PARAM("UI/field_no_offset", "field_name", displayFieldName), 3000);
                }
            }

            // Show field explanation in the explanation panel (after hex so selection feels instant)
            if (!sameFieldAsLast && m_peParser && m_peParser->isValid()) {
                QString explanation = m_peParser->getFieldExplanation(fieldName);
                m_uiManager->m_fieldExplanationText->setHtml(explanation);
                m_lastExplainedFieldName = fieldName;
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
    Q_UNUSED(offset);
    Q_UNUSED(length);
}

void MainWindow::onLanguageChanged(const QString &language)
{
    Q_UNUSED(language);
    // Legacy hook: defer like LanguageManager::languageChanged so we never refresh menus synchronously.
    QTimer::singleShot(0, this, [this]() {
        onApplicationLanguageChanged(LanguageManager::getInstance().getCurrentLanguage());
    });
}

void MainWindow::onApplicationLanguageChanged(const QString &languageCode)
{
    Q_UNUSED(languageCode);

    PEParserNew::clearFieldExplanationCaches();

    // With QueuedConnection from languageChanged, this slot runs after the menu action returns. Still defer
    // heavy PE/hex rebuild so tree/slot paths are not nested with tab widgets updating.
    updateUILanguage();
    updateLanguageMenu();
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

void MainWindow::stopStringsExtractionSynchronously()
{
    const bool hadWork = m_stringsExtractionRunning || m_stringsExtractionWatcher.isRunning();
    if (hadWork) {
        // Block finished so a queued handler cannot run after we assign a new future (would call result() on the wrong future).
        m_stringsExtractionWatcher.blockSignals(true);
        m_stringsExtractionWatcher.cancel();
        if (m_stringsExtractionWatcher.isRunning()) {
            m_stringsExtractionWatcher.waitForFinished();
        }
        m_stringsExtractionWatcher.blockSignals(false);
    }
    m_stringsExtractionRunning = false;

    if (m_uiManager) {
        if (m_uiManager->m_progressBar) {
            m_uiManager->m_progressBar->setVisible(false);
            m_uiManager->m_progressBar->setRange(0, 100);
            m_uiManager->m_progressBar->setValue(0);
            m_uiManager->m_progressBar->setFormat(QString());
        }
        if (m_uiManager->m_progressLabel) {
            m_uiManager->m_progressLabel->clear();
        }
        if (m_uiManager->m_stringsCancelButton) {
            m_uiManager->m_stringsCancelButton->setEnabled(false);
        }
    }
}

void MainWindow::refreshOpenFileAfterLanguageChange(quint64 languageRefreshEpoch)
{
    if (languageRefreshEpoch != 0 && m_languageRefreshEpoch != languageRefreshEpoch) {
        return;
    }
    if (!m_fileLoaded || !m_uiManager || !m_peParser) {
        return;
    }

    m_lastExplainedFieldName.clear();
    m_lastHexHighlightOffset = -1;

    stopStringsExtractionSynchronously();

    m_importsPopulated = false;
    m_delayImportsPopulated = false;
    m_exportsPopulated = false;
    m_resourcesPopulated = false;
    m_dependenciesPopulated = false;
    m_stringsPopulated = false;

    if (m_uiManager->m_importModulesTree) {
        m_uiManager->m_importModulesTree->blockSignals(true);
        m_uiManager->m_importModulesTree->clear();
        m_uiManager->m_importModulesTree->blockSignals(false);
    }
    if (m_uiManager->m_importFunctionsTree) {
        m_uiManager->m_importFunctionsTree->blockSignals(true);
        m_uiManager->m_importFunctionsTree->clear();
        m_uiManager->m_importFunctionsTree->blockSignals(false);
    }
    if (m_uiManager->m_importHintText) {
        m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
    }
    if (m_uiManager->m_delayImportModulesTree) {
        m_uiManager->m_delayImportModulesTree->blockSignals(true);
        m_uiManager->m_delayImportModulesTree->clear();
        m_uiManager->m_delayImportModulesTree->blockSignals(false);
    }
    if (m_uiManager->m_delayImportFunctionsTree) {
        m_uiManager->m_delayImportFunctionsTree->blockSignals(true);
        m_uiManager->m_delayImportFunctionsTree->clear();
        m_uiManager->m_delayImportFunctionsTree->blockSignals(false);
    }
    if (m_uiManager->m_exportsTree) {
        m_uiManager->m_exportsTree->clear();
    }
    if (m_uiManager->m_resourcesTree) {
        m_uiManager->m_resourcesTree->clear();
    }
    if (m_uiManager->m_dependenciesTree) {
        m_uiManager->m_dependenciesTree->clear();
    }
    if (m_uiManager->m_stringsTree) {
        m_uiManager->m_stringsTree->clear();
    }
    m_extractedStrings.clear();

    scheduleStagedAnalysisDisplay(QString(), [this]() {
        updateDependenciesExpandCollapseButtonState();
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
    if (m_uiManager && m_uiManager->m_dependenciesTree) {
        m_uiManager->m_dependenciesTree->expandAll();
    }
}

void MainWindow::onCollapseAllDependencies()
{
    if (m_uiManager && m_uiManager->m_dependenciesTree) {
        m_uiManager->m_dependenciesTree->collapseAll();
    }
}

void MainWindow::onDependenciesCustomContextMenu(const QPoint &pos)
{
    if (!m_uiManager || !m_uiManager->m_dependenciesTree) {
        return;
    }
    QTreeWidget *tree = m_uiManager->m_dependenciesTree;
    const QPoint vpPos = tree->viewport()->mapFrom(tree, pos);
    QTreeWidgetItem *itemAt = tree->itemAt(vpPos);

    QMenu menu(this);
    QAction *copyAct = menu.addAction(LANG("UI/context_copy"));
    copyAct->setIcon(QIcon(QStringLiteral(":/images/imgs/copy.png")));
    menu.addSeparator();
    QAction *expandAct = menu.addAction(LANG("UI/context_expand_all"));
    expandAct->setIcon(QIcon(QStringLiteral(":/images/imgs/expand.png")));
    QAction *collapseAct = menu.addAction(LANG("UI/context_collapse_all"));
    collapseAct->setIcon(QIcon(QStringLiteral(":/images/imgs/collapse.png")));

    QAction *chosen = menu.exec(tree->viewport()->mapToGlobal(vpPos));
    if (!chosen) {
        return;
    }
    if (chosen == copyAct) {
        QString text;
        if (itemAt) {
            text = itemAt->text(0) + QLatin1Char('\t') + itemAt->text(1) + QLatin1Char('\t') + itemAt->text(2);
        } else {
            text = fullDependencyTreeText(tree);
        }
        if (!text.isEmpty()) {
            QApplication::clipboard()->setText(text);
            statusBar()->showMessage(LANG("UI/content_copied"), 2000);
        }
    } else if (chosen == expandAct) {
        onExpandAllDependencies();
    } else if (chosen == collapseAct) {
        onCollapseAllDependencies();
    }
}

void MainWindow::updateDependenciesExpandCollapseButtonState()
{
    if (!m_uiManager) {
        return;
    }
    const bool on = m_fileLoaded && m_uiManager->m_dependenciesTree
        && m_uiManager->m_dependenciesTree->topLevelItemCount() > 0;
    if (m_uiManager->m_dependenciesExpandAllButton) {
        m_uiManager->m_dependenciesExpandAllButton->setEnabled(on);
    }
    if (m_uiManager->m_dependenciesCollapseAllButton) {
        m_uiManager->m_dependenciesCollapseAllButton->setEnabled(on);
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
        addToRecentFiles(filePath);
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
    m_lastExplainedFieldName.clear();
    m_lastHexHighlightOffset = -1;
    m_lastHexHighlightSize = 0;
    m_lastHexHighlightRgba = 0;
    stopStringsExtractionSynchronously();

    // Access UI components through UIManager
    if (m_uiManager) {
        // Clear tree highlights before clearing the tree
        clearTreeHighlights();
        
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
        if (m_uiManager->m_importModulesTree) m_uiManager->m_importModulesTree->clear();
        if (m_uiManager->m_importFunctionsTree) m_uiManager->m_importFunctionsTree->clear();
        if (m_uiManager->m_importHintText) {
            m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
        }
        if (m_uiManager->m_delayImportModulesTree) m_uiManager->m_delayImportModulesTree->clear();
        if (m_uiManager->m_delayImportFunctionsTree) m_uiManager->m_delayImportFunctionsTree->clear();
        if (m_uiManager->m_exportsTree) m_uiManager->m_exportsTree->clear();
        if (m_uiManager->m_dependenciesTree) m_uiManager->m_dependenciesTree->clear();
        if (m_uiManager->m_stringsTree) m_uiManager->m_stringsTree->clear();
        m_extractedStrings.clear();
        if (m_uiManager->m_stringsFilterEdit) m_uiManager->m_stringsFilterEdit->clear();
        if (m_uiManager->m_stringsTypeCombo) m_uiManager->m_stringsTypeCombo->setCurrentIndex(0);
        if (m_uiManager->m_stringsSectionCombo) {
            m_uiManager->m_stringsSectionCombo->clear();
            m_uiManager->m_stringsSectionCombo->addItem(LANG("UI/strings_all_sections"), QStringLiteral("__all__"));
        }
        if (m_uiManager->m_stringsCancelButton) m_uiManager->m_stringsCancelButton->setEnabled(false);
        if (m_uiManager->m_stringsExportButton) m_uiManager->m_stringsExportButton->setEnabled(false);
        if (m_uiManager->m_findingsTree) {
            m_uiManager->m_findingsTree->clear();
        }
        if (m_uiManager->m_findingsOverviewTree) {
            m_uiManager->m_findingsOverviewTree->clear();
        }
        m_cachedFindings.clear();
        m_cachedPassFindings.clear();
        if (m_uiManager->m_findingsSummaryLabel) {
            m_uiManager->m_findingsSummaryLabel->setText(LANG(QStringLiteral("findings/summary_none")));
        }
        showFindingsInsightHtml(QString());

        // Also clear hex viewer highlights
        if (m_uiManager->m_hexViewer) {
            m_uiManager->m_hexViewer->clearHighlights();
        }

        // Reset lazy-population flags for the next file.
        m_importsPopulated = false;
        m_delayImportsPopulated = false;
        m_exportsPopulated = false;
        m_resourcesPopulated = false;
        m_dependenciesPopulated = false;
        m_stringsPopulated = false;
        updateDependenciesExpandCollapseButtonState();
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

void MainWindow::scheduleStagedAnalysisDisplay(const QString &pathGuard, std::function<void()> onComplete,
                                               quint64 languageRefreshEpoch)
{
    auto guard = [this, pathGuard, languageRefreshEpoch]() -> bool {
        if (!m_fileLoaded || !m_uiManager || !m_peParser) {
            return false;
        }
        if (!pathGuard.isEmpty() && m_currentFilePath != pathGuard) {
            return false;
        }
        if (languageRefreshEpoch != 0 && m_languageRefreshEpoch != languageRefreshEpoch) {
            return false;
        }
        return true;
    };

    QTimer::singleShot(0, this, [this, guard, pathGuard, languageRefreshEpoch,
                                 onComplete = std::move(onComplete)]() mutable {
        if (!guard()) {
            if (onComplete) {
                onComplete();
            }
            return;
        }
        analysisDisplayPhaseTree();
        QTimer::singleShot(0, this, [this, guard, pathGuard, languageRefreshEpoch,
                                     onComplete = std::move(onComplete)]() mutable {
            if (!guard()) {
                if (onComplete) {
                    onComplete();
                }
                return;
            }
            analysisDisplayPhaseWelcomeOnly();
            QTimer::singleShot(0, this, [this, guard, pathGuard, languageRefreshEpoch,
                                         onComplete = std::move(onComplete)]() mutable {
                if (!guard()) {
                    if (onComplete) {
                        onComplete();
                    }
                    return;
                }
                analysisDisplayPhaseHexSetData();
                QTimer::singleShot(0, this, [this, guard, pathGuard, languageRefreshEpoch,
                                             onComplete = std::move(onComplete)]() mutable {
                    if (!guard()) {
                        if (onComplete) {
                            onComplete();
                        }
                        return;
                    }
                    analysisDisplayPhaseStringsTab();

                    HexViewer *hexViewer = m_uiManager ? m_uiManager->m_hexViewer : nullptr;
                    if (hexViewer && hexViewer->isHexDocumentBuildInProgress()) {
                        // Large files: hex text is built on a worker thread; do not claim "fully loaded" yet.
                        if (m_uiManager->m_progressBar) {
                            m_uiManager->m_progressBar->setVisible(true);
                            m_uiManager->m_progressBar->setRange(0, 0); // busy / indeterminate
                        }
                        if (m_uiManager->m_progressLabel) {
                            m_uiManager->m_progressLabel->setText(
                                LANG(QStringLiteral("UI/status_preparing_hex_view")));
                        }
                        statusBar()->showMessage(LANG(QStringLiteral("UI/status_preparing_hex_view")));
                        connect(hexViewer, &HexViewer::hexContentReady, this,
                                [this, pathGuard, languageRefreshEpoch,
                                 oc = std::move(onComplete)]() mutable {
                                    if (!m_fileLoaded || !m_uiManager) {
                                        return;
                                    }
                                    if (languageRefreshEpoch != 0
                                        && m_languageRefreshEpoch != languageRefreshEpoch) {
                                        return;
                                    }
                                    if (!pathGuard.isEmpty() && m_currentFilePath != pathGuard) {
                                        return;
                                    }
                                    if (m_uiManager->m_progressBar) {
                                        m_uiManager->m_progressBar->setRange(0, 100);
                                    }
                                    if (oc) {
                                        oc();
                                    }
                                },
                                Qt::SingleShotConnection);
                    } else {
                        if (onComplete) {
                            onComplete();
                        }
                    }
                });
            });
        });
    });
}

void MainWindow::updateAnalysisDisplay()
{
    scheduleStagedAnalysisDisplay(QString());
}

void MainWindow::analysisDisplayPhaseTree()
{
    if (!m_fileLoaded || !m_uiManager || !m_peParser) {
        return;
    }

    m_uiManager->m_peTree->setUpdatesEnabled(false);
    m_uiManager->m_peTree->blockSignals(true);
    m_uiManager->m_peTree->setCurrentItem(nullptr);
    m_uiManager->m_peTree->clear();
    QList<QTreeWidgetItem *> items = m_peParser->getPEStructureTree();
    for (QTreeWidgetItem *item : items) {
        m_uiManager->m_peTree->addTopLevelItem(item);
    }
    m_uiManager->m_peTree->blockSignals(false);
    m_uiManager->m_peTree->setUpdatesEnabled(true);

    const bool hasItems = !items.isEmpty();
    if (m_uiManager->m_expandAllButton) {
        m_uiManager->m_expandAllButton->setEnabled(hasItems);
    }
    if (m_uiManager->m_collapseAllButton) {
        m_uiManager->m_collapseAllButton->setEnabled(hasItems);
    }

    populateFindingsTab();
}

void MainWindow::populateFindingsTab()
{
    if (!m_uiManager || !m_peParser || !m_peParser->isValid()) {
        return;
    }

    PEFindingsEngine::loadRules();

    const auto rvaToFo = [this](quint32 rva) -> quint32 {
        return m_peParser ? m_peParser->rvaToFileOffset(rva) : 0u;
    };
    m_cachedFindings = PEFindingsEngine::evaluate(m_peParser->getDataModel(), rvaToFo);
    m_cachedPassFindings = PEFindingsEngine::evaluateHardeningPasses(m_peParser->getDataModel());

    populateFindingsOverview();
    applyFindingsFilter();
}

void MainWindow::populateFindingsOverview()
{
    if (!m_uiManager || !m_uiManager->m_findingsOverviewTree || !m_peParser || !m_peParser->isValid()) {
        return;
    }

    m_uiManager->m_findingsOverviewTree->clear();
    QTreeWidgetItem *insights = m_peParser->buildFileInsightsItem();
    if (!insights) {
        return;
    }

    for (int i = 0; i < insights->childCount(); ++i) {
        QTreeWidgetItem *src = insights->child(i);
        QTreeWidgetItem *row = new QTreeWidgetItem(m_uiManager->m_findingsOverviewTree);
        row->setText(0, src->text(0));
        row->setText(1, src->text(1));
        const QString fieldKey = src->data(0, PEParserNew::kTreeFieldKeyRole).toString();
        if (!fieldKey.isEmpty()) {
            row->setData(0, PEParserNew::kTreeFieldKeyRole, fieldKey);
        }
        const QVariant offVar = src->data(0, kFieldOffsetRole);
        const QVariant sizeVar = src->data(0, kFieldSizeRole);
        if (offVar.isValid()) {
            row->setData(0, kFieldOffsetRole, offVar);
        }
        if (sizeVar.isValid()) {
            row->setData(0, kFieldSizeRole, sizeVar);
        }

        if (fieldKey == QLatin1String("Signed") && m_peParser) {
            const PEFileMetrics metrics = m_peParser->getDataModel().getFileMetrics();
            const QColor bg = metrics.authenticodePresent ? QColor(230, 255, 230) : QColor(255, 243, 224);
            const QColor fg = metrics.authenticodePresent ? QColor(22, 101, 52) : QColor(146, 64, 14);
            for (int col = 0; col < 2; ++col) {
                row->setBackground(col, bg);
                row->setForeground(col, fg);
            }
            row->setText(1, metrics.authenticodePresent ? LANG(QStringLiteral("UI/signed_table_yes"))
                                                        : LANG(QStringLiteral("UI/signed_table_no")));
        }

        if (!row->text(1).isEmpty()) {
            row->setToolTip(1, row->text(1));
        }
    }
    delete insights;

    QTreeWidget *tree = m_uiManager->m_findingsOverviewTree;
    const int rows = tree->topLevelItemCount();
    int rowHeight = rows > 0 ? tree->sizeHintForRow(0) : 22;
    if (rowHeight < 20) {
        rowHeight = 22;
    }
    constexpr int kOverviewHeaderHeight = 26;
    constexpr int kMaxVisibleRows = 6;
    const int visibleRows = qMin(rows, kMaxVisibleRows);
    const int contentHeight = kOverviewHeaderHeight + visibleRows * rowHeight + 6;
    tree->setFixedHeight(contentHeight);

    tree->resizeColumnToContents(0);
    tree->resizeColumnToContents(1);
    constexpr int kOverviewChrome = 28;
    constexpr int kMaxOverviewWidth = 560;
    constexpr int kMaxFieldColumnWidth = 118;
    if (tree->columnWidth(0) > kMaxFieldColumnWidth) {
        tree->setColumnWidth(0, kMaxFieldColumnWidth);
    }
    const int tableWidth = tree->columnWidth(0) + tree->columnWidth(1) + kOverviewChrome;
    tree->setFixedWidth(qMin(tableWidth, kMaxOverviewWidth));

    if (m_uiManager->m_findingsInsightText) {
        const int insightHeight = qBound(72, contentHeight, 132);
        m_uiManager->m_findingsInsightText->setFixedHeight(insightHeight);
    }

    if (m_uiManager->m_sectionLayoutWidget && m_peParser) {
        const PEDataModel &model = m_peParser->getDataModel();
        quint32 imageSize = 0;
        if (const IMAGE_OPTIONAL_HEADER *opt = model.getOptionalHeader()) {
            imageSize = opt->SizeOfImage;
        }
        m_uiManager->m_sectionLayoutWidget->setSections(model.getSections(), imageSize);
    }

    if (rows > kMaxVisibleRows) {
        tree->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    } else {
        tree->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    }
}

void MainWindow::applyFindingsFilter()
{
    if (!m_uiManager || !m_uiManager->m_findingsTree) {
        return;
    }

    m_uiManager->m_findingsTree->clear();

    const QString severityFilter = m_uiManager->m_findingsSeverityCombo
        ? m_uiManager->m_findingsSeverityCombo->currentData().toString()
        : QStringLiteral("all");
    const bool showPasses =
        m_uiManager->m_findingsShowPassesCheck && m_uiManager->m_findingsShowPassesCheck->isChecked();

    QVector<PEFindingInstance> visible = m_cachedFindings;
    if (showPasses) {
        visible += m_cachedPassFindings;
    }

    auto severityMatches = [&](const PEFindingInstance &f) -> bool {
        if (severityFilter == QStringLiteral("all")) {
            return true;
        }
        if (f.isPass) {
            return severityFilter == QStringLiteral("info");
        }
        switch (f.severity) {
        case PEFindingSeverity::High:
            return severityFilter == QStringLiteral("high");
        case PEFindingSeverity::Medium:
            return severityFilter == QStringLiteral("medium");
        case PEFindingSeverity::Low:
            return severityFilter == QStringLiteral("low");
        default:
            return severityFilter == QStringLiteral("info");
        }
    };

    QVector<PEFindingInstance> filtered;
    filtered.reserve(visible.size());
    for (const PEFindingInstance &f : visible) {
        if (f.isPass && !showPasses) {
            continue;
        }
        if (severityMatches(f)) {
            filtered.append(f);
        }
    }

    if (m_uiManager->m_findingsSummaryLabel) {
        if (filtered.isEmpty()) {
            m_uiManager->m_findingsSummaryLabel->setText(LANG(QStringLiteral("findings/summary_none")));
        } else {
            QMap<QString, QString> params;
            params[QStringLiteral("count")] = QString::number(filtered.size());
            m_uiManager->m_findingsSummaryLabel->setText(
                LANG_PARAMS(QStringLiteral("findings/summary_count"), params));
        }
    }

    auto severityColor = [](const PEFindingInstance &finding) -> QColor {
        if (finding.isPass) {
            return QColor(230, 255, 230);
        }
        switch (finding.severity) {
        case PEFindingSeverity::High:
            return QColor(255, 230, 230);
        case PEFindingSeverity::Medium:
            return QColor(255, 248, 220);
        case PEFindingSeverity::Low:
            return QColor(240, 248, 255);
        default:
            return QColor(245, 245, 245);
        }
    };

    const QVector<PEFindingRule> &rules = PEFindingsEngine::rules();
    static const char *const kCategoryOrder[] = {"hardening", "content", "metadata", "imports", "other"};

    auto categoryForFinding = [&](const PEFindingInstance &finding) -> QString {
        if (!finding.category.isEmpty()) {
            return finding.category;
        }
        for (const PEFindingRule &rule : rules) {
            if (rule.id == finding.ruleId) {
                return PEFindingsEngine::categoryKeyForRule(rule);
            }
        }
        return finding.isPass ? QStringLiteral("hardening") : QStringLiteral("other");
    };

    QMap<QString, QTreeWidgetItem *> categoryNodes;

    for (const char *catKey : kCategoryOrder) {
        const QString key = QString::fromLatin1(catKey);
        QTreeWidgetItem *catItem = new QTreeWidgetItem(m_uiManager->m_findingsTree);
        catItem->setText(0, QString());
        catItem->setText(1, PEFindingsEngine::categoryDisplayName(key));
        catItem->setText(2, QString());
        catItem->setData(0, kFindingCategoryHeaderRole, true);
        catItem->setFirstColumnSpanned(false);
        catItem->setExpanded(true);
        const QFont bold = catItem->font(1);
        QFont f = bold;
        f.setBold(true);
        catItem->setFont(1, f);
        categoryNodes.insert(key, catItem);
    }

    for (const PEFindingInstance &finding : filtered) {
        QString title = finding.title;
        QString detail = finding.detail;
        for (const PEFindingRule &rule : rules) {
            if (rule.id == finding.ruleId) {
                title = LANG(rule.titleKey);
                if (detail.isEmpty() || detail.startsWith(QStringLiteral("findings/"))) {
                    detail = LANG(rule.detailKey);
                }
                break;
            }
        }

        const QString catKey = categoryForFinding(finding);
        QTreeWidgetItem *parent = categoryNodes.value(catKey, categoryNodes.value(QStringLiteral("other")));
        if (!parent) {
            parent = categoryNodes.value(QStringLiteral("other"));
        }

        QTreeWidgetItem *row = new QTreeWidgetItem(parent);
        if (finding.isPass) {
            row->setText(0, LANG(QStringLiteral("findings/severity_pass")));
        } else {
            row->setText(0, PEFindingsEngine::severityDisplayName(finding.severity));
        }
        row->setText(1, title);
        row->setText(2, detail);
        if (!finding.treeField.isEmpty()) {
            row->setData(0, PEParserNew::kTreeFieldKeyRole, finding.treeField);
        }
        if (finding.hasHexNav && finding.hexSize > 0) {
            row->setData(0, kFieldOffsetRole, finding.hexOffset);
            row->setData(0, kFieldSizeRole, finding.hexSize);
        }
        if (!finding.ruleId.isEmpty()) {
            row->setData(0, kFindingRuleIdRole, finding.ruleId);
        }
        const QColor bg = severityColor(finding);
        for (int col = 0; col < 3; ++col) {
            row->setBackground(col, bg);
        }
    }

    for (const char *catKey : kCategoryOrder) {
        QTreeWidgetItem *catItem = categoryNodes.value(QString::fromLatin1(catKey));
        if (catItem && catItem->childCount() == 0) {
            catItem->setHidden(true);
        }
    }
}

void MainWindow::onFindingsFilterChanged()
{
    applyFindingsFilter();
}

void MainWindow::onOverviewItemClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column);
    if (!item || !m_uiManager || !m_peParser || !m_peParser->isValid()) {
        return;
    }

    const QString treeField = item->data(0, PEParserNew::kTreeFieldKeyRole).toString();
    const FieldHexRange range = resolveFieldHexRange(item, treeField);

    if (!treeField.isEmpty()) {
        const QString richExplanation = m_peParser->getFileInsightExplanation(treeField);
        if (!richExplanation.isEmpty()) {
            showFindingsInsightHtml(richExplanation);
            m_lastExplainedFieldName = treeField;
        }
    }

    if (range.canHighlight || range.canGoTo) {
        applyFieldHexNavigation(item, range);
    } else if (m_uiManager->m_hexViewer) {
        m_uiManager->m_hexViewer->clearHighlights();
    }
}

void MainWindow::selectPeTreeItemForContext(QTreeWidgetItem *item)
{
    if (!item || !m_uiManager || !m_uiManager->m_peTree) {
        return;
    }
    QTreeWidgetItem *parent = item->parent();
    while (parent) {
        parent->setExpanded(true);
        parent = parent->parent();
    }
    m_uiManager->m_peTree->setCurrentItem(item);
    m_uiManager->m_peTree->scrollToItem(item);
}

QTreeWidgetItem *MainWindow::findPeTreeItemByFieldKey(const QString &fieldKey) const
{
    if (fieldKey.isEmpty() || !m_uiManager || !m_uiManager->m_peTree) {
        return nullptr;
    }
    QTreeWidgetItemIterator it(m_uiManager->m_peTree);
    while (*it) {
        const QString key = (*it)->data(0, PEParserNew::kTreeFieldKeyRole).toString();
        if (key == fieldKey) {
            return *it;
        }
        ++it;
    }
    return nullptr;
}

void MainWindow::onFindingsItemClicked(QTreeWidgetItem *item, int column)
{
    Q_UNUSED(column);
    if (!item || !m_uiManager || !m_peParser || !m_peParser->isValid()) {
        return;
    }
    if (item->data(0, kFindingCategoryHeaderRole).toBool()) {
        return;
    }

    const QString treeField = item->data(0, PEParserNew::kTreeFieldKeyRole).toString();
    const FieldHexRange range = resolveFieldHexRange(item, treeField);
    QTreeWidgetItem *peItem = treeField.isEmpty() ? nullptr : findPeTreeItemByFieldKey(treeField);

    if (peItem) {
        if (m_uiManager->m_analysisTabWidget) {
            m_uiManager->m_analysisTabWidget->setCurrentIndex(0);
        }
        QTreeWidgetItem *parent = peItem->parent();
        while (parent) {
            parent->setExpanded(true);
            parent = parent->parent();
        }
        m_uiManager->m_peTree->setCurrentItem(peItem);
        m_uiManager->m_peTree->scrollToItem(peItem);
        onTreeItemClicked(peItem, 0);
        return;
    }

    if (range.canHighlight || range.canGoTo) {
        applyFieldHexNavigation(item, range);
    }

    const QString ruleId = item->data(0, kFindingRuleIdRole).toString();
    const QString baseRuleId = ruleId.section(QLatin1Char(':'), 0, 0);
    if (baseRuleId == QStringLiteral("hardcoded_url") || baseRuleId == QStringLiteral("hardcoded_ip")
        || baseRuleId == QStringLiteral("hardcoded_registry")
        || baseRuleId == QStringLiteral("suspicious_command")) {
        const PEContentScan scan = m_peParser->getDataModel().getContentScan();
        const QVector<PEHardcodedMatch> &matches =
            baseRuleId == QStringLiteral("hardcoded_url") ? scan.urls
            : baseRuleId == QStringLiteral("hardcoded_ip") ? scan.ips
            : baseRuleId == QStringLiteral("hardcoded_registry") ? scan.registryPaths
            : scan.suspiciousCommands;
        const QString title = item->text(1);
        const QString intro = LANG(QStringLiteral("findings/hardcoded_matches_intro"));
        showFindingsInsightHtml(formatHardcodedMatchesInsightHtml(title, intro, matches));
        return;
    }

    const QString title = item->text(1);
    const QString detail = item->text(2);
    const QString helpKey = QStringLiteral("findings/") + baseRuleId + QStringLiteral("_help");
    const QString helpText = LANG(helpKey);
    QString html = QStringLiteral(
                             "<div style='font-family:\"Segoe UI\",Arial,sans-serif;font-size:11px;"
                             "color:#222;line-height:1.55;'>"
                             "<div style='font-weight:600;font-size:12px;margin-bottom:8px;'>%1</div>"
                             "<div style='color:#333;'>%2</div>")
                             .arg(title.toHtmlEscaped(), detail.toHtmlEscaped());
    if (!helpText.isEmpty() && helpText != helpKey) {
        html += QStringLiteral(
                    "<div style='margin-top:10px;padding:8px 10px;background:#f0f9ff;border-left:3px solid "
                    "#38bdf8;border-radius:4px;color:#0c4a6e;'>%1</div>")
                    .arg(helpText.toHtmlEscaped());
    }
    html += QStringLiteral("</div>");
    showFindingsInsightHtml(html);
}

void MainWindow::analysisDisplayPhaseWelcomeOnly()
{
    if (!m_fileLoaded || !m_uiManager || !m_peParser) {
        return;
    }

    QMap<QString, QString> params;
    params[QStringLiteral("version")] = PEHINT_VERSION_STRING_FULL;
    const QString welcomeMessage = QString(
                                           QStringLiteral("<div style='text-align: center; color: #666; padding: 20px;'>"
                                                          "<h3>%1</h3>"
                                                          "<p><b>%2</b></p>"
                                                          "<p><b>%3</b></p>"
                                                          "<p>%4</p>"
                                                          "</div>"))
                                       .arg(LANG(QStringLiteral("UI/welcome_title")),
                                            LANG_PARAMS(QStringLiteral("UI/placeholder_welcome"), params),
                                            LANG(QStringLiteral("UI/click_field_explanation")),
                                            LANG(QStringLiteral("UI/welcome_description")));

    QString extraWelcomeHtml;
    if (m_peParser->isValid() && m_peParser->isLargeFile()) {
        QMap<QString, QString> lf;
        lf[QStringLiteral("size")] = QString::number(m_peParser->getFileSize() / (1024.0 * 1024.0), 'f', 1);
        extraWelcomeHtml = QStringLiteral("<div style='color: orange; font-weight: bold; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px;'>%1</div>")
                               .arg(LANG_PARAMS(QStringLiteral("UI/large_file_memory_note"), lf));
    }
    if (!extraWelcomeHtml.isEmpty()) {
        m_uiManager->m_fieldExplanationText->setHtml(welcomeMessage + extraWelcomeHtml);
    } else {
        m_uiManager->m_fieldExplanationText->setHtml(welcomeMessage);
    }
}

void MainWindow::analysisDisplayPhaseHexSetData()
{
    if (!m_fileLoaded || !m_uiManager || !m_peParser) {
        return;
    }
    if (!m_peParser->isValid() || !m_uiManager->m_hexViewer) {
        return;
    }

    const QByteArray &fileData = m_peParser->getFileData();
    QByteArray diskData;
    const QByteArray *useData = nullptr;
    if (!fileData.isEmpty()) {
        useData = &fileData;
    } else {
        QFile file(m_currentFilePath);
        if (file.open(QIODevice::ReadOnly)) {
            diskData = file.readAll();
            file.close();
            useData = &diskData;
        }
    }
    if (useData && !useData->isEmpty()) {
        m_uiManager->m_hexViewer->setData(*useData, useData->size());
    }
}

void MainWindow::analysisDisplayPhaseStringsTab()
{
    if (!m_fileLoaded || !m_uiManager || !m_peParser) {
        return;
    }

    if (m_uiManager->m_stringsSectionCombo) {
        // clear()/addItem() emit currentIndexChanged; while empty, currentData() is invalid. On the Strings tab
        // that triggered populateStringsTab() with selectedSection != "__all__", the worker returned no strings,
        // and onAnalysisTabChanged then skipped repopulate because extraction was already "running".
        QSignalBlocker blocker(m_uiManager->m_stringsSectionCombo);
        m_uiManager->m_stringsSectionCombo->clear();
        m_uiManager->m_stringsSectionCombo->addItem(LANG(QStringLiteral("UI/strings_all_sections")), QStringLiteral("__all__"));
        const QList<const IMAGE_SECTION_HEADER *> &sections = m_peParser->getDataModel().getSections();
        for (const IMAGE_SECTION_HEADER *sec : sections) {
            if (!sec) {
                continue;
            }
            const QString label = normalizedSectionName(sec);
            m_uiManager->m_stringsSectionCombo->addItem(label, label);
        }
    }

    if (m_uiManager->m_analysisTabWidget) {
        onAnalysisTabChanged(m_uiManager->m_analysisTabWidget->currentIndex());
    }
}

void MainWindow::onStringsFilterChanged()
{
    if (!m_fileLoaded || !m_uiManager) return;
    const bool stringsTabActive = m_uiManager->m_analysisTabWidget && m_uiManager->m_analysisTabWidget->currentIndex() == 6;
    const bool senderTriggersExtraction =
        sender() == m_uiManager->m_stringsMinLengthSpin ||
        sender() == m_uiManager->m_stringsSectionCombo;
    if (stringsTabActive && senderTriggersExtraction && !m_stringsExtractionRunning) {
        // Min-length or section scope change requires re-extraction from file bytes.
        m_stringsPopulated = false;
        populateStringsTab();
        return;
    }
    applyStringsFilter();
}

void MainWindow::onAnalysisTabChanged(int index)
{
    if (!m_fileLoaded || !m_uiManager || !m_peParser || !m_peParser->isValid()) return;

    // Tab order in UIManager:
    // 0 = Structure, 1 = Imports, 2 = Delay Imports, 3 = Exports, 4 = Resources,
    // 5 = Dependencies, 6 = Strings, 7 = Findings
    switch (index) {
        case 1:
            populateImportsTab();
            break;
        case 2:
            populateDelayImportsTab();
            break;
        case 3:
            populateExportsTab();
            break;
        case 4:
            populateResourcesTab();
            break;
        case 5:
            populateDependenciesTab();
            break;
        case 6:
            populateStringsTab();
            break;
        default:
            break;
    }
}

void MainWindow::populateImportsTab()
{
    if (m_importsPopulated) return;
    if (!m_uiManager || !m_uiManager->m_importModulesTree) return;

    m_uiManager->m_importModulesTree->blockSignals(true);
    m_uiManager->m_importModulesTree->clear();
    if (m_uiManager->m_importFunctionsTree) {
        m_uiManager->m_importFunctionsTree->blockSignals(true);
        m_uiManager->m_importFunctionsTree->clear();
        m_uiManager->m_importFunctionsTree->blockSignals(false);
    }
    m_uiManager->m_importModulesTree->blockSignals(false);

    const QStringList imports = m_peParser->getImportModules();
    const auto &importDetails = m_peParser->getImportFunctionDetails();

    for (const QString &moduleName : imports) {
        const QList<PEDataModel::ImportFunctionEntry> functions = importDetails.value(moduleName);
        QTreeWidgetItem *moduleItem = new QTreeWidgetItem(m_uiManager->m_importModulesTree);
        moduleItem->setText(0, moduleName);
        moduleItem->setText(1, QString::number(functions.size()));
        int flaggedCount = 0;
        for (const PEDataModel::ImportFunctionEntry &entry : functions) {
            if (!entry.importedByOrdinal
                && PEFindingsEngine::isFlaggedImport(moduleName, entry.name)) {
                ++flaggedCount;
            }
        }
        if (flaggedCount > 0) {
            const QColor bg = QColor(255, 248, 220);
            moduleItem->setBackground(0, bg);
            moduleItem->setBackground(1, bg);
            QMap<QString, QString> params;
            params[QStringLiteral("count")] = QString::number(flaggedCount);
            moduleItem->setToolTip(0, LANG_PARAMS(QStringLiteral("UI/imports_module_flagged_tooltip"), params));
        }
    }

    if (m_uiManager->m_importModulesTree->topLevelItemCount() > 0) {
        // Selecting the first module triggers onImportModuleSelected() to fill functions.
        m_uiManager->m_importModulesTree->setCurrentItem(m_uiManager->m_importModulesTree->topLevelItem(0));
    } else if (m_uiManager->m_importFunctionsTree) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_importModulesTree);
        placeholder->setText(0, LANG("UI/imports_none"));
        placeholder->setText(1, "");
        populateImportFunctions(QString());
    }

    m_importsPopulated = true;
}

void MainWindow::populateDelayImportsTab()
{
    if (m_delayImportsPopulated) return;
    if (!m_uiManager || !m_uiManager->m_delayImportModulesTree) return;

    m_uiManager->m_delayImportModulesTree->blockSignals(true);
    m_uiManager->m_delayImportModulesTree->clear();
    if (m_uiManager->m_delayImportFunctionsTree) {
        m_uiManager->m_delayImportFunctionsTree->blockSignals(true);
        m_uiManager->m_delayImportFunctionsTree->clear();
        m_uiManager->m_delayImportFunctionsTree->blockSignals(false);
    }
    m_uiManager->m_delayImportModulesTree->blockSignals(false);

    const QStringList delayImports = m_peParser->getDelayImportModules();
    const auto &delayImportDetails = m_peParser->getDelayImportFunctionDetails();

    for (const QString &moduleName : delayImports) {
        const QList<PEDataModel::ImportFunctionEntry> functions = delayImportDetails.value(moduleName);
        QTreeWidgetItem *moduleItem = new QTreeWidgetItem(m_uiManager->m_delayImportModulesTree);
        moduleItem->setText(0, moduleName);
        moduleItem->setText(1, QString::number(functions.size()));
        int flaggedCount = 0;
        for (const PEDataModel::ImportFunctionEntry &entry : functions) {
            if (!entry.importedByOrdinal
                && PEFindingsEngine::isFlaggedImport(moduleName, entry.name)) {
                ++flaggedCount;
            }
        }
        if (flaggedCount > 0) {
            const QColor bg = QColor(255, 248, 220);
            moduleItem->setBackground(0, bg);
            moduleItem->setBackground(1, bg);
            QMap<QString, QString> params;
            params[QStringLiteral("count")] = QString::number(flaggedCount);
            moduleItem->setToolTip(0, LANG_PARAMS(QStringLiteral("UI/imports_module_flagged_tooltip"), params));
        }
    }

    if (m_uiManager->m_delayImportModulesTree->topLevelItemCount() > 0) {
        m_uiManager->m_delayImportModulesTree->setCurrentItem(
            m_uiManager->m_delayImportModulesTree->topLevelItem(0));
    } else {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_delayImportModulesTree);
        placeholder->setText(0, LANG("UI/delay_imports_none"));
        placeholder->setText(1, QString());
        populateDelayImportFunctions(QString());
    }

    m_delayImportsPopulated = true;
}

void MainWindow::populateExportsTab()
{
    if (m_exportsPopulated) return;
    if (!m_uiManager || !m_uiManager->m_exportsTree) return;

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
            item->setText(1, entry.rva != 0 ? PEUtils::formatHexWidth(entry.rva, 8) : QString());
            item->setText(2, QString::number(entry.ordinal));
        }
    }

    m_exportsPopulated = true;
}

void MainWindow::populateResourcesTab()
{
    if (m_resourcesPopulated) {
        return;
    }
    if (!m_uiManager || !m_uiManager->m_resourcesTree || !m_peParser) {
        return;
    }

    m_uiManager->m_resourcesTree->clear();
    const QVector<PEResourceItem> &resources = m_peParser->getResourceEntries();
    if (resources.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_resourcesTree);
        placeholder->setText(0, LANG("UI/resources_none"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
    } else {
        constexpr int kResourceOffsetRole = Qt::UserRole;
        constexpr int kResourceSizeRole = Qt::UserRole + 1;
        m_uiManager->m_resourcesTree->setUpdatesEnabled(false);
        for (const PEResourceItem &entry : resources) {
            QTreeWidgetItem *item = new QTreeWidgetItem(m_uiManager->m_resourcesTree);
            item->setText(0, entry.typeName);
            item->setText(1, entry.resourceName);
            item->setText(2, entry.languageId != 0 ? QString::number(entry.languageId) : QString());
            item->setText(3, QString::number(entry.size));
            item->setText(4, entry.fileOffset != 0 ? PEUtils::formatHexWidth(entry.fileOffset, 8) : QString());
            if (entry.fileOffset != 0) {
                item->setData(0, kResourceOffsetRole, QVariant::fromValue(entry.fileOffset));
                item->setData(0, kResourceSizeRole, QVariant::fromValue(entry.size));
            }
            if (entry.rva != 0) {
                const QString tip = QStringLiteral("RVA %1, %2 bytes")
                                        .arg(PEUtils::formatHexWidth(entry.rva, 8))
                                        .arg(entry.size);
                item->setToolTip(0, tip);
                item->setToolTip(1, tip);
                item->setToolTip(2, tip);
                item->setToolTip(3, tip);
                item->setToolTip(4, tip);
            }
        }
        m_uiManager->m_resourcesTree->setUpdatesEnabled(true);
    }

    m_resourcesPopulated = true;
}

void MainWindow::onResourcesItemClicked(QTreeWidgetItem *item, int /*column*/)
{
    if (!item || !m_uiManager || !m_uiManager->m_hexViewer) {
        return;
    }
    constexpr int kResourceOffsetRole = Qt::UserRole;
    constexpr int kResourceSizeRole = Qt::UserRole + 1;
    const QVariant offsetVar = item->data(0, kResourceOffsetRole);
    if (!offsetVar.isValid()) {
        return;
    }
    const quint32 offset = offsetVar.toUInt();
    const quint32 size = item->data(0, kResourceSizeRole).toUInt();
    HexViewer *hex = m_uiManager->m_hexViewer;
    if (size > 0) {
        hex->highlightRange(offset, size, QColor(200, 230, 255));
        m_lastHexHighlightOffset = static_cast<qint64>(offset);
        m_lastHexHighlightSize = size;
        m_lastHexHighlightRgba = QColor(200, 230, 255).rgba();
    } else {
        hex->goToOffset(static_cast<qint64>(offset));
    }
}

void MainWindow::populateDependenciesTab()
{
    if (m_dependenciesPopulated) return;
    if (!m_uiManager || !m_uiManager->m_dependenciesTree) return;

    auto addDependencyNode = [this](const DependencyNode &node, QTreeWidgetItem *parent, auto &addRef) -> void {
        QTreeWidgetItem *item = parent
            ? new QTreeWidgetItem(parent)
            : new QTreeWidgetItem(m_uiManager->m_dependenciesTree);
        QString moduleText = node.moduleName;
        if (node.cycleDetected) {
            moduleText += QStringLiteral(" [") + LANG("UI/deps_tag_cycle") + QStringLiteral("]");
        } else if (node.truncatedByDepth) {
            moduleText += QStringLiteral(" [") + LANG("UI/deps_tag_max_depth") + QStringLiteral("]");
        }
        item->setText(0, moduleText);
        item->setText(1, QDir::toNativeSeparators(node.resolvedPath));
        item->setText(2, node.foundOnSystem ? LANG("UI/deps_found_yes") : LANG("UI/deps_found_no"));
        const QString tip = dependencyTooltipText(node);
        item->setToolTip(0, tip);
        item->setToolTip(1, tip);
        item->setToolTip(2, tip);
        for (const DependencyNode &child : node.children) {
            addRef(child, item, addRef);
        }
    };

    m_uiManager->m_dependenciesTree->setUpdatesEnabled(false);
    m_uiManager->m_dependenciesTree->clear();
    const QStringList imports = m_peParser->getImportModules();
    if (imports.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_dependenciesTree);
        placeholder->setText(0, LANG("UI/imports_none"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
    } else {
        constexpr int kMaxDependencyDepth = 2;
        const DependencyAnalysisResult depResult =
            PEDependencyAnalyzer::analyzeTransitive(imports, m_currentFilePath, kMaxDependencyDepth);

        for (const DependencyNode &node : depResult.dependencyTree) {
            addDependencyNode(node, nullptr, addDependencyNode);
        }
        m_uiManager->m_dependenciesTree->expandToDepth(1);
    }
    m_uiManager->m_dependenciesTree->setUpdatesEnabled(true);

    m_dependenciesPopulated = true;
    updateDependenciesExpandCollapseButtonState();
}

void MainWindow::populateStringsTab()
{
    if (!m_uiManager || !m_uiManager->m_stringsTree) return;
    if (!m_fileLoaded || !m_peParser || !m_peParser->isValid()) return;
    if (m_stringsPopulated && !m_stringsExtractionRunning) {
        // Stale state: extraction finished with no strings (bug paths) or filters yielded nothing in memory
        // but m_extractedStrings is empty — must not short-circuit forever; re-run extraction.
        if (!m_extractedStrings.isEmpty()) {
            applyStringsFilter();
            return;
        }
        m_stringsPopulated = false;
    }
    if (m_stringsExtractionRunning) {
        return;
    }

    m_uiManager->m_stringsTree->clear();
    m_extractedStrings.clear();
    const int minLen = (m_uiManager->m_stringsMinLengthSpin ? m_uiManager->m_stringsMinLengthSpin->value() : 4);
    QString selectedSection = (m_uiManager->m_stringsSectionCombo
                               ? m_uiManager->m_stringsSectionCombo->currentData().toString()
                               : QStringLiteral("__all__"));
    if (selectedSection.isEmpty()) {
        selectedSection = QStringLiteral("__all__");
    }
    if (m_uiManager->m_stringsCancelButton) m_uiManager->m_stringsCancelButton->setEnabled(true);
    if (m_uiManager->m_stringsExportButton) m_uiManager->m_stringsExportButton->setEnabled(false);
    if (m_uiManager->m_progressBar) {
        m_uiManager->m_progressBar->setVisible(true);
        m_uiManager->m_progressBar->setRange(0, 100);
        m_uiManager->m_progressBar->setValue(0);
        m_uiManager->m_progressBar->setTextVisible(true);
        m_uiManager->m_progressBar->setFormat(QStringLiteral("%p%"));
    }
    const QString stringsProgressMsg = LANG("UI/strings_progress_extracting");
    if (m_uiManager->m_progressLabel) {
        m_uiManager->m_progressLabel->setText(QStringLiteral("0% — %1").arg(stringsProgressMsg));
    }

    m_stringsExtractionRunning = true;
    m_stringsPopulated = false;
    struct SectionSlice { QString name; quint32 offset; quint32 size; };
    QList<SectionSlice> sectionSlices;
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_peParser->getDataModel().getSections();
    for (const IMAGE_SECTION_HEADER *sec : sections) {
        if (!sec) continue;
        SectionSlice s;
        s.name = normalizedSectionName(sec);
        s.offset = sec->PointerToRawData;
        s.size = sec->SizeOfRawData;
        sectionSlices.append(s);
    }

    const QString filePath = m_currentFilePath;
    const QPointer<MainWindow> self(this);
    m_stringsExtractionWatcher.setFuture(QtConcurrent::run(
        [self, filePath, minLen, selectedSection, sectionSlices, stringsProgressMsg]() {
            StringExtractionResult out;
            out.minLength = minLen;

            const auto pushProgress = [self, stringsProgressMsg](int uiPercent) {
                if (!self) {
                    return;
                }
                const int p = qBound(0, uiPercent, 100);
                QMetaObject::invokeMethod(
                    self.data(),
                    [self, p, stringsProgressMsg]() {
                        if (!self || !self->m_uiManager || !self->m_uiManager->m_progressBar) {
                            return;
                        }
                        self->m_uiManager->m_progressBar->setRange(0, 100);
                        self->m_uiManager->m_progressBar->setValue(p);
                        if (self->m_uiManager->m_progressLabel) {
                            self->m_uiManager->m_progressLabel->setText(QStringLiteral("%1% — %2").arg(p).arg(stringsProgressMsg));
                        }
                    },
                    Qt::QueuedConnection);
            };

            const auto extractProgress = [&pushProgress](int extractPct) {
                pushProgress(5 + (extractPct * 95) / 100);
            };

            QFile f(filePath);
            if (!f.open(QIODevice::ReadOnly)) {
                return out;
            }
            const QByteArray fullData = f.readAll();
            f.close();
            if (fullData.isEmpty()) {
                return out;
            }

            pushProgress(5);

            if (selectedSection != QStringLiteral("__all__")) {
                for (const auto &s : sectionSlices) {
                    if (s.name.compare(selectedSection, Qt::CaseInsensitive) != 0) {
                        continue;
                    }
                    if (s.offset >= static_cast<quint32>(fullData.size())) {
                        break;
                    }
                    const quint32 cappedSize = qMin(s.size, static_cast<quint32>(fullData.size() - s.offset));
                    StringExtractionResult sectionRes = PEStringExtractor::extractFromData(
                        fullData.mid(static_cast<int>(s.offset), static_cast<int>(cappedSize)), minLen, extractProgress);
                    for (ExtractedString e : sectionRes.strings) {
                        e.fileOffset += s.offset;
                        out.strings.append(e);
                    }
                    pushProgress(100);
                    return out;
                }
                pushProgress(100);
                return out;
            }

            out = PEStringExtractor::extractFromData(fullData, minLen, extractProgress);
            pushProgress(100);
            return out;
        }));
}

void MainWindow::onStringsExtractionFinished()
{
    m_stringsExtractionRunning = false;
    if (!m_uiManager) return;

    const QFuture<StringExtractionResult> fut = m_stringsExtractionWatcher.future();
    if (!fut.isFinished()) {
        return;
    }

    if (m_uiManager->m_progressBar) {
        m_uiManager->m_progressBar->setVisible(false);
        m_uiManager->m_progressBar->setRange(0, 100);
        m_uiManager->m_progressBar->setValue(0);
        m_uiManager->m_progressBar->setFormat(QString());
    }
    if (m_uiManager->m_progressLabel) {
        m_uiManager->m_progressLabel->clear();
    }
    if (m_uiManager->m_stringsCancelButton) {
        m_uiManager->m_stringsCancelButton->setEnabled(false);
    }
    if (m_uiManager->m_stringsExportButton) {
        m_uiManager->m_stringsExportButton->setEnabled(true);
    }

    if (fut.isCanceled()) {
        m_extractedStrings.clear();
        m_stringsPopulated = false;
        return;
    }

    if (!m_fileLoaded || !m_peParser || !m_peParser->isValid()) {
        m_extractedStrings.clear();
        m_stringsPopulated = false;
        return;
    }

    const StringExtractionResult strResult = fut.result();
    m_extractedStrings = strResult.strings;
    m_stringsPopulated = true;
    if (m_uiManager->m_stringsExportButton) {
        m_uiManager->m_stringsExportButton->setEnabled(!m_extractedStrings.isEmpty());
    }
    applyStringsFilter();
}

void MainWindow::onCancelStringsExtraction()
{
    if (!m_stringsExtractionRunning) return;
    m_stringsExtractionWatcher.cancel();
    m_stringsExtractionRunning = false;
    if (!m_uiManager) return;
    if (m_uiManager->m_progressBar) {
        m_uiManager->m_progressBar->setVisible(false);
        m_uiManager->m_progressBar->setRange(0, 100);
        m_uiManager->m_progressBar->setValue(0);
        m_uiManager->m_progressBar->setFormat(QString());
    }
    if (m_uiManager->m_progressLabel) {
        m_uiManager->m_progressLabel->setText(LANG("UI/strings_progress_cancelled"));
    }
    if (m_uiManager->m_stringsCancelButton) {
        m_uiManager->m_stringsCancelButton->setEnabled(false);
    }
    if (m_uiManager->m_stringsExportButton) {
        m_uiManager->m_stringsExportButton->setEnabled(!m_extractedStrings.isEmpty());
    }
}

void MainWindow::onExportStrings()
{
    if (!m_uiManager || !m_uiManager->m_stringsTree) return;
    if (m_uiManager->m_stringsTree->topLevelItemCount() == 0) {
        statusBar()->showMessage(LANG("UI/strings_export_none"), 2500);
        return;
    }

    QString selectedFilter;
    const QString outPath = QFileDialog::getSaveFileName(
        this,
        LANG("UI/strings_export_dialog_title"),
        QDir::homePath() + QStringLiteral("/pehint_strings.csv"),
        LANG("UI/strings_export_filter"),
        &selectedFilter);
    if (outPath.isEmpty()) return;

    const QString nativeOutPath = QDir::toNativeSeparators(outPath);

    QString content;
    if (selectedFilter.contains(QStringLiteral("JSON"))) {
        QJsonArray arr;
        for (int i = 0; i < m_uiManager->m_stringsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem *it = m_uiManager->m_stringsTree->topLevelItem(i);
            if (!it) continue;
            QJsonObject o;
            o["offset"] = it->text(0);
            o["section"] = it->text(1);
            o["type"] = it->text(2);
            o["value"] = it->text(3);
            arr.append(o);
        }
        QJsonObject root;
        root["file"] = m_currentFilePath;
        root["count"] = arr.size();
        root["strings"] = arr;
        content = QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
    } else if (selectedFilter.contains(QStringLiteral("Text"))) {
        QStringList lines;
        lines << LanguageManager::getInstance().getString(
            QStringLiteral("UI/strings_export_header_tsv"),
            QStringLiteral("offset\tsection\ttype\tvalue"));
        for (int i = 0; i < m_uiManager->m_stringsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem *it = m_uiManager->m_stringsTree->topLevelItem(i);
            if (!it) continue;
            lines << QStringLiteral("%1\t%2\t%3\t%4")
                         .arg(it->text(0), it->text(1), it->text(2), it->text(3));
        }
        content = lines.join(QLatin1Char('\n'));
    } else {
        QStringList lines;
        lines << LanguageManager::getInstance().getString(
            QStringLiteral("UI/strings_export_header_csv"),
            QStringLiteral("offset,section,type,value"));
        for (int i = 0; i < m_uiManager->m_stringsTree->topLevelItemCount(); ++i) {
            QTreeWidgetItem *it = m_uiManager->m_stringsTree->topLevelItem(i);
            if (!it) continue;
            auto csv = [](const QString &s) {
                QString v = s;
                v.replace('"', "\"\"");
                return QStringLiteral("\"%1\"").arg(v);
            };
            lines << QStringLiteral("%1,%2,%3,%4")
                         .arg(csv(it->text(0)), csv(it->text(1)), csv(it->text(2)), csv(it->text(3)));
        }
        content = lines.join(QLatin1Char('\n'));
    }

    QFile out(outPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        showError(LANG("UI/strings_export_error_title"),
                  LANG_PARAM("UI/strings_export_error_write", "path", nativeOutPath));
        return;
    }
    out.write(content.toUtf8());
    out.close();
    statusBar()->showMessage(LANG_PARAM("UI/strings_export_success", "path", nativeOutPath), 3500);
}

void MainWindow::applyStringsFilter()
{
    if (!m_uiManager->m_stringsTree) return;
    m_uiManager->m_stringsTree->clear();

    if (m_stringsExtractionRunning) {
        QTreeWidgetItem *loading = new QTreeWidgetItem(m_uiManager->m_stringsTree);
        loading->setText(0, LANG("UI/strings_progress_extracting"));
        loading->setFirstColumnSpanned(true);
        loading->setFlags(Qt::NoItemFlags);
        return;
    }

    QString filterText;
    QString typeFilter = QStringLiteral("all");
    if (m_uiManager->m_stringsFilterEdit) filterText = m_uiManager->m_stringsFilterEdit->text().trimmed();
    if (m_uiManager->m_stringsTypeCombo) typeFilter = m_uiManager->m_stringsTypeCombo->currentData().toString();

    if (m_extractedStrings.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_stringsTree);
        placeholder->setText(0, LanguageManager::getInstance().getString(
            QStringLiteral("UI/strings_list_empty"),
            QStringLiteral("No strings to display. Try Refresh or change filters.")));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
        return;
    }

    const bool sectionModelOk = m_fileLoaded && m_peParser && m_peParser->isValid();

    for (const ExtractedString &s : m_extractedStrings) {
        if (typeFilter == QLatin1String("ascii") && s.isUnicode) continue;
        if (typeFilter == QLatin1String("unicode") && !s.isUnicode) continue;
        if ((typeFilter == QLatin1String("url") || typeFilter == QLatin1String("ip")
             || typeFilter == QLatin1String("registry") || typeFilter == QLatin1String("command"))
            && !PEStringExtractor::matchesContentFilter(s.value, typeFilter)) {
            continue;
        }
        if (!filterText.isEmpty() && !s.value.contains(filterText, Qt::CaseInsensitive)) continue;

        QString displayValue = s.value;
        for (int i = 0; i < displayValue.size(); ++i) {
            QChar c = displayValue[i];
            if (c < QChar(0x20) && c != QChar('\t')) displayValue[i] = QChar('.');
            else if (c == QChar('\t')) displayValue[i] = QChar(' ');
        }
        if (displayValue.length() > 512) displayValue = displayValue.left(512) + QStringLiteral("...");
        QTreeWidgetItem *item = new QTreeWidgetItem(m_uiManager->m_stringsTree);
        item->setText(0, PEUtils::formatHexWidth(s.fileOffset, 8));
        QString sectionName = QStringLiteral("-");
        if (sectionModelOk) {
            for (const IMAGE_SECTION_HEADER *sec : m_peParser->getDataModel().getSections()) {
                if (!sec) continue;
                const quint32 start = sec->PointerToRawData;
                const quint32 end = start + sec->SizeOfRawData;
                if (s.fileOffset >= start && s.fileOffset < end) {
                    sectionName = normalizedSectionName(sec);
                    break;
                }
            }
        }
        item->setText(1, sectionName);
        item->setText(2, s.isUnicode ? LANG("UI/strings_type_unicode") : LANG("UI/strings_type_ascii"));
        item->setText(3, displayValue);
        if (s.value.length() > 512) item->setToolTip(3, s.value);
        item->setData(0, Qt::UserRole, static_cast<qulonglong>(s.fileOffset));
        const int byteLen = s.isUnicode ? (s.value.size() * 2) : s.value.size();
        item->setData(0, static_cast<int>(Qt::UserRole) + 1, byteLen);
    }
    if (m_uiManager->m_stringsExportButton) {
        m_uiManager->m_stringsExportButton->setEnabled(m_uiManager->m_stringsTree->topLevelItemCount() > 0);
    }
}

void MainWindow::onStringsTreeItemDoubleClicked(QTreeWidgetItem *item, int /*column*/)
{
    if (!item || !m_uiManager || !m_uiManager->m_hexViewer || !m_fileLoaded) {
        return;
    }
    if (item->flags() == Qt::NoItemFlags) {
        return;
    }
    const QVariant v = item->data(0, Qt::UserRole);
    if (!v.isValid()) {
        return;
    }
    bool ok = false;
    const quint64 off64 = v.toULongLong(&ok);
    if (!ok || off64 > static_cast<quint64>(std::numeric_limits<quint32>::max())) {
        return;
    }
    const quint32 off = static_cast<quint32>(off64);
    int len = item->data(0, static_cast<int>(Qt::UserRole) + 1).toInt();
    if (len <= 0) {
        return;
    }
    const qint64 dataSize = m_uiManager->m_hexViewer->getDataSize();
    if (dataSize <= 0 || static_cast<qint64>(off) >= dataSize) {
        return;
    }
    len = static_cast<int>(qMin<qint64>(len, dataSize - static_cast<qint64>(off)));

    HexViewer *hex = m_uiManager->m_hexViewer;
    hex->highlightRange(off, static_cast<quint32>(len), QColor(255, 255, 0, 120));
    hex->setFocus(Qt::OtherFocusReason);
}

void MainWindow::showError(const QString &title, const QString &message)
{
    QMessageBox::critical(this, title, message);
}

void MainWindow::showInfo(const QString &title, const QString &message)
{
    QMessageBox::information(this, title, message);
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

QString MainWindow::escapeXml(const QString &str)
{
    QString out;
    out.reserve(static_cast<int>(str.size() * 1.1));
    for (QChar c : str) {
        if (c == QLatin1Char('&'))
            out += QLatin1String("&amp;");
        else if (c == QLatin1Char('<'))
            out += QLatin1String("&lt;");
        else if (c == QLatin1Char('>'))
            out += QLatin1String("&gt;");
        else if (c == QLatin1Char('"'))
            out += QLatin1String("&quot;");
        else if (c == QLatin1Char('\''))
            out += QLatin1String("&apos;");
        else
            out += c;
    }
    return out;
}

QString MainWindow::buildFullTextReport(const PEDataModel &dataModel) const
{
    if (!dataModel.isValid()) return QString();

    QString out;
    QTextStream s(&out);
    const QString path = dataModel.getFilePath();
    const qint64 fsize = dataModel.getFileSize();
    s << "PEHint Analysis Report\n";
    s << "=====================\n\n";
    s << "File: " << path << "\n";
    s << "Size: " << getFileSizeString(fsize) << " (" << fsize << " bytes)\n\n";

    const IMAGE_DOS_HEADER *dos = dataModel.getDOSHeader();
    if (dos) {
        s << "--- DOS Header ---\n";
        s << "  e_magic:     " << PEUtils::formatHexWidth(dos->e_magic, 4) << " (MZ)\n";
        s << "  e_lfanew:    " << PEUtils::formatHex(dos->e_lfanew) << "\n\n";
    }

    const IMAGE_FILE_HEADER *fh = dataModel.getFileHeader();
    if (fh) {
        s << "--- File Header ---\n";
        s << "  Machine:              " << PEUtils::formatHexWidth(fh->Machine, 4) << " (" << PEUtils::getMachineType(fh->Machine) << ")\n";
        s << "  NumberOfSections:     " << fh->NumberOfSections << "\n";
        s << "  Characteristics:      " << PEUtils::formatHexWidth(fh->Characteristics, 4) << " (" << PEUtils::getFileCharacteristics(fh->Characteristics) << ")\n\n";
    }

    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    if (opt) {
        s << "--- Optional Header ---\n";
        s << "  Magic:                 " << PEUtils::formatHexWidth(opt->Magic, 4) << (opt->Magic == 0x20b ? " (PE32+)" : " (PE32)") << "\n";
        s << "  AddressOfEntryPoint:   " << PEUtils::formatHex(opt->AddressOfEntryPoint) << "\n";
        s << "  Subsystem:             " << PEUtils::formatHexWidth(opt->Subsystem, 4) << " (" << PEUtils::getSubsystem(opt->Subsystem) << ")\n";
        s << "  SizeOfImage:           " << PEUtils::formatHex(opt->SizeOfImage) << "\n\n";
    }

    const QList<const IMAGE_SECTION_HEADER*> &sections = dataModel.getSections();
    if (!sections.isEmpty()) {
        s << "--- Sections (" << sections.size() << ") ---\n";
        for (const IMAGE_SECTION_HEADER *sec : sections) {
            QString name = QString::fromLatin1(sec->Name, 8).trimmed();
            s << "  " << name << "  VA=" << PEUtils::formatHex(sec->VirtualAddress)
              << "  VSize=" << PEUtils::formatHex(sec->Misc.VirtualSize)
              << "  RawSize=" << PEUtils::formatHex(sec->SizeOfRawData)
              << "  " << PEUtils::getSectionCharacteristics(sec->Characteristics) << "\n";
        }
        s << "\n";
    }

    const QStringList imports = dataModel.getImports();
    if (!imports.isEmpty()) {
        s << "--- Imports ---\n";
        const auto &importDetails = dataModel.getImportFunctions();
        for (const QString &mod : imports) {
            s << "  " << mod << "\n";
            for (const PEDataModel::ImportFunctionEntry &e : importDetails.value(mod)) {
                s << "    " << (e.importedByOrdinal ? QString("#%1").arg(e.ordinal) : e.name)
                  << "  RVA=" << PEUtils::formatHex(e.thunkRVA) << "\n";
            }
        }
        s << "\n";
    }

    const QList<PEDataModel::ExportFunctionEntry> &exports = dataModel.getExportFunctions();
    if (!exports.isEmpty()) {
        s << "--- Exports ---\n";
        for (const PEDataModel::ExportFunctionEntry &e : exports) {
            s << "  " << (e.name.isEmpty() ? QString("[%1]").arg(e.ordinal) : e.name)
              << "  ordinal=" << e.ordinal << "  RVA=" << PEUtils::formatHex(e.rva) << "\n";
        }
    }
    return out;
}

QString MainWindow::buildFullHTMLReport(const PEDataModel &dataModel) const
{
    QString body = buildFullTextReport(dataModel);
    if (body.isEmpty()) return QString();
    body = body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>\n");
    return QStringLiteral(
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>PEHint Report</title>"
        "<style>body{font-family:Consolas,monospace;margin:1em;} pre{white-space:pre-wrap;}</style></head>"
        "<body><h1>PEHint Analysis Report</h1><pre>") + body + QStringLiteral("</pre></body></html>");
}

QString MainWindow::buildFullJSONReport(const PEDataModel &dataModel) const
{
    if (!dataModel.isValid()) return QString();

    QJsonObject root;
    root["filePath"] = dataModel.getFilePath();
    root["fileSize"] = static_cast<qint64>(dataModel.getFileSize());

    const IMAGE_DOS_HEADER *dos = dataModel.getDOSHeader();
    if (dos) {
        QJsonObject o;
        o["e_magic"] = QString(PEUtils::formatHexWidth(dos->e_magic, 4));
        o["e_lfanew"] = static_cast<int>(dos->e_lfanew);
        root["dosHeader"] = o;
    }

    const IMAGE_FILE_HEADER *fh = dataModel.getFileHeader();
    if (fh) {
        QJsonObject o;
        o["machine"] = static_cast<int>(fh->Machine);
        o["machineType"] = PEUtils::getMachineType(fh->Machine);
        o["numberOfSections"] = fh->NumberOfSections;
        o["characteristics"] = QString(PEUtils::formatHexWidth(fh->Characteristics, 4));
        root["fileHeader"] = o;
    }

    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    if (opt) {
        QJsonObject o;
        o["magic"] = static_cast<int>(opt->Magic);
        o["addressOfEntryPoint"] = QString(PEUtils::formatHex(opt->AddressOfEntryPoint));
        o["subsystem"] = static_cast<int>(opt->Subsystem);
        o["subsystemName"] = PEUtils::getSubsystem(opt->Subsystem);
        o["sizeOfImage"] = static_cast<int>(opt->SizeOfImage);
        root["optionalHeader"] = o;
    }

    QJsonArray secArr;
    for (const IMAGE_SECTION_HEADER *sec : dataModel.getSections()) {
        QJsonObject o;
        o["name"] = QString::fromLatin1(sec->Name, 8).trimmed();
        o["virtualAddress"] = QString(PEUtils::formatHex(sec->VirtualAddress));
        o["virtualSize"] = static_cast<int>(sec->Misc.VirtualSize);
        o["sizeOfRawData"] = static_cast<int>(sec->SizeOfRawData);
        secArr.append(o);
    }
    if (!secArr.isEmpty()) root["sections"] = secArr;

    const auto &importDetails = dataModel.getImportFunctions();
    QJsonObject importObj;
    for (const QString &mod : dataModel.getImports()) {
        QJsonArray arr;
        for (const PEDataModel::ImportFunctionEntry &e : importDetails.value(mod))
            arr.append(e.importedByOrdinal ? QString("#%1").arg(e.ordinal) : e.name);
        importObj[mod] = arr;
    }
    if (!importObj.isEmpty()) root["imports"] = importObj;

    QJsonArray expArr;
    for (const PEDataModel::ExportFunctionEntry &e : dataModel.getExportFunctions()) {
        QJsonObject o;
        o["name"] = e.name.isEmpty() ? QString("[%1]").arg(e.ordinal) : e.name;
        o["ordinal"] = e.ordinal;
        o["rva"] = QString(PEUtils::formatHex(e.rva));
        expArr.append(o);
    }
    if (!expArr.isEmpty()) root["exports"] = expArr;

    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

QString MainWindow::buildFullXMLReport(const PEDataModel &dataModel) const
{
    if (!dataModel.isValid()) return QString();

    QString out;
    QTextStream s(&out);
    s << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PEHintReport>\n";
    s << "  <file path=\"" << escapeXml(dataModel.getFilePath()) << "\" size=\"" << dataModel.getFileSize() << "\" />\n";

    const IMAGE_DOS_HEADER *dos = dataModel.getDOSHeader();
    if (dos) {
        s << "  <dosHeader e_magic=\"" << PEUtils::formatHexWidth(dos->e_magic, 4) << "\" e_lfanew=\"" << dos->e_lfanew << "\" />\n";
    }
    const IMAGE_FILE_HEADER *fh = dataModel.getFileHeader();
    if (fh) {
        s << "  <fileHeader machine=\"" << fh->Machine << "\" machineType=\"" << escapeXml(PEUtils::getMachineType(fh->Machine))
          << "\" numberOfSections=\"" << fh->NumberOfSections << "\" />\n";
    }
    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    if (opt) {
        s << "  <optionalHeader magic=\"" << opt->Magic << "\" addressOfEntryPoint=\"" << PEUtils::formatHex(opt->AddressOfEntryPoint)
          << "\" subsystem=\"" << opt->Subsystem << "\" subsystemName=\"" << escapeXml(PEUtils::getSubsystem(opt->Subsystem)) << "\" />\n";
    }
    s << "  <sections>\n";
    for (const IMAGE_SECTION_HEADER *sec : dataModel.getSections()) {
        QString name = QString::fromLatin1(sec->Name, 8).trimmed();
        s << "    <section name=\"" << escapeXml(name) << "\" virtualAddress=\"" << PEUtils::formatHex(sec->VirtualAddress)
          << "\" virtualSize=\"" << sec->Misc.VirtualSize << "\" sizeOfRawData=\"" << sec->SizeOfRawData << "\" />\n";
    }
    s << "  </sections>\n  <imports>\n";
    const auto &importDetails = dataModel.getImportFunctions();
    for (const QString &mod : dataModel.getImports()) {
        s << "    <module name=\"" << escapeXml(mod) << "\">\n";
        for (const PEDataModel::ImportFunctionEntry &e : importDetails.value(mod))
            s << "      <import>" << escapeXml(e.importedByOrdinal ? QString("#%1").arg(e.ordinal) : e.name) << "</import>\n";
        s << "    </module>\n";
    }
    s << "  </imports>\n  <exports>\n";
    for (const PEDataModel::ExportFunctionEntry &e : dataModel.getExportFunctions()) {
        s << "    <export name=\"" << escapeXml(e.name.isEmpty() ? QString::number(e.ordinal) : e.name)
          << "\" ordinal=\"" << e.ordinal << "\" rva=\"" << PEUtils::formatHex(e.rva) << "\" />\n";
    }
    s << "  </exports>\n</PEHintReport>\n";
    return out;
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

    // Same discovery as updateLanguageMenu / updateMenuLanguage: support EN + PT titles
    QMenu *toolsMenu = nullptr;
    for (QAction *action : menuBar()->actions()) {
        if (!action->menu()) {
            continue;
        }
        QString cleanTitle = action->menu()->title();
        cleanTitle.remove(QLatin1Char('&'));
        if (cleanTitle == QLatin1String("Tools") || cleanTitle == QLatin1String("Ferramentas")
            || cleanTitle.contains(QLatin1String("Tools"), Qt::CaseInsensitive)
            || cleanTitle.contains(QLatin1String("Ferramentas"), Qt::CaseInsensitive)) {
            toolsMenu = action->menu();
            break;
        }
    }

    if (!toolsMenu) {
        qWarning() << "Tools menu not found, creating it";
        toolsMenu = menuBar()->addMenu(LANG("UI/menu_tools"));
    }

    // Add language submenu with icon
    QMenu *languageMenu = toolsMenu->addMenu(LANG("UI/menu_language"));
    languageMenu->setIcon(QIcon(":/images/imgs/language.png"));

    if (!m_languageActionGroup) {
        m_languageActionGroup = new QActionGroup(this);
        m_languageActionGroup->setExclusive(true);
    }

    QStringList languages = LanguageManager::getInstance().getAvailableLanguages();
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();

    for (const QString &langCode : languages) {
        QString displayName = LanguageManager::getInstance().getLanguageDisplayName(langCode);
        auto *langAction = new QAction(displayName, this);
        langAction->setCheckable(true);
        langAction->setData(langCode);
        languageMenu->addAction(langAction);
        m_languageActionGroup->addAction(langAction);
        connect(langAction, &QAction::triggered, this, [this, langAction]() {
            onLanguageMenuTriggered(langAction);
        }, Qt::QueuedConnection);
    }

    const QList<QAction *> initialLangActions = languageMenu->actions();
    for (QAction *langAction : initialLangActions) {
        langAction->blockSignals(true);
    }
    for (QAction *langAction : initialLangActions) {
        const QString langCode = langAction->data().toString();
        langAction->setChecked(langCode == currentLanguage);
    }
    for (QAction *langAction : initialLangActions) {
        langAction->blockSignals(false);
    }
}

void MainWindow::onLanguageMenuTriggered(QAction *action)
{
    QString languageCode = action->data().toString();
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();
    
    qDebug() << "Language menu triggered for:" << languageCode;
    qDebug() << "Current language is:" << currentLanguage;
    
    // Resync checkmarks (exclusive group can toggle before we noop) — defer: same stack as open menu.
    if (languageCode == currentLanguage) {
        qDebug() << "Same language already selected, doing nothing";
        QTimer::singleShot(0, this, [this]() { updateLanguageMenu(); });
        return;
    }
    
    if (LanguageManager::getInstance().setLanguage(languageCode)) {
        qDebug() << "Language successfully changed to:" << languageCode;
        // onApplicationLanguageChanged is invoked via LanguageManager::languageChanged

        qDebug() << "Language changed to:" << languageCode;
    } else {
        qWarning() << "Failed to change language to:" << languageCode;
        QTimer::singleShot(0, this, [this]() { updateLanguageMenu(); });
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
        QTabWidget *tw = m_uiManager->m_analysisTabWidget;
        if (tw->count() > 0) {
            tw->setTabText(0, LANG("UI/tab_structure"));
        }
        if (tw->count() > 1) {
            tw->setTabText(1, LANG("UI/tab_imports"));
        }
        if (tw->count() > 2) {
            tw->setTabText(2, LANG("UI/tab_delay_imports"));
        }
        if (tw->count() > 3) {
            tw->setTabText(3, LANG("UI/tab_exports"));
        }
        if (tw->count() > 4) {
            tw->setTabText(4, LANG("UI/tab_dependencies"));
        }
        if (tw->count() > 5) {
            tw->setTabText(5, LANG("UI/tab_strings"));
        }
        if (tw->count() > 6) {
            tw->setTabText(6, LANG("UI/tab_findings"));
        }
        if (m_fileLoaded && m_peParser && m_peParser->isValid()) {
            populateFindingsTab();
        }
    }

    if (m_uiManager && m_uiManager->m_findingsTree) {
        m_uiManager->m_findingsTree->setHeaderLabels({
            LANG(QStringLiteral("findings/header_severity")),
            LANG(QStringLiteral("findings/header_title")),
            LANG(QStringLiteral("findings/header_detail"))
        });
    }
    if (m_uiManager && m_uiManager->m_findingsOverviewTree) {
        m_uiManager->m_findingsOverviewTree->setHeaderLabels({
            LANG("UI/tree_header_field"),
            LANG("UI/tree_header_value")
        });
    }
    if (m_uiManager && m_uiManager->m_findingsShowPassesCheck) {
        m_uiManager->m_findingsShowPassesCheck->setText(LANG(QStringLiteral("findings/show_passes")));
    }
    if (m_uiManager && m_uiManager->m_findingsInsightTitleLabel) {
        m_uiManager->m_findingsInsightTitleLabel->setText(LANG(QStringLiteral("findings/insight_title")));
    }
    if (m_uiManager && m_uiManager->m_findingsInsightText) {
        m_uiManager->m_findingsInsightText->setPlaceholderText(LANG(QStringLiteral("findings/insight_placeholder")));
    }
    if (m_uiManager && m_uiManager->m_findingsSeverityCombo) {
        const int idx = m_uiManager->m_findingsSeverityCombo->currentIndex();
        m_uiManager->m_findingsSeverityCombo->setItemText(0, LANG(QStringLiteral("findings/filter_severity_all")));
        m_uiManager->m_findingsSeverityCombo->setItemText(1, LANG(QStringLiteral("findings/filter_severity_high")));
        m_uiManager->m_findingsSeverityCombo->setItemText(2, LANG(QStringLiteral("findings/filter_severity_medium")));
        m_uiManager->m_findingsSeverityCombo->setItemText(3, LANG(QStringLiteral("findings/filter_severity_low")));
        m_uiManager->m_findingsSeverityCombo->setItemText(4, LANG(QStringLiteral("findings/filter_severity_info")));
        m_uiManager->m_findingsSeverityCombo->setCurrentIndex(idx);
    }
    if (m_uiManager && m_uiManager->m_findingsSummaryLabel && m_uiManager->m_findingsTree) {
        if (m_uiManager->m_findingsTree->topLevelItemCount() == 0) {
            m_uiManager->m_findingsSummaryLabel->setText(LANG(QStringLiteral("findings/summary_none")));
        }
    }

    if (m_uiManager && m_uiManager->m_importModulesTree) {
        m_uiManager->m_importModulesTree->setHeaderLabels({LANG("UI/imports_header_module"), LANG("UI/imports_header_count")});
    }

    if (m_uiManager && m_uiManager->m_importFunctionsTree) {
        m_uiManager->m_importFunctionsTree->setHeaderLabels({
            LANG("UI/imports_functions_header_name"),
            LANG("UI/imports_functions_header_offset"),
            LANG("UI/imports_functions_header_ordinal")
        });
    }

    if (m_uiManager && m_uiManager->m_delayImportModulesTree) {
        m_uiManager->m_delayImportModulesTree->setHeaderLabels(
            {LANG("UI/imports_header_module"), LANG("UI/imports_header_count")});
    }
    if (m_uiManager && m_uiManager->m_delayImportFunctionsTree) {
        m_uiManager->m_delayImportFunctionsTree->setHeaderLabels({
            LANG("UI/imports_functions_header_name"),
            LANG("UI/imports_functions_header_offset"),
            LANG("UI/imports_functions_header_ordinal")
        });
    }

    if (m_uiManager && m_uiManager->m_importHintTitleLabel) {
        m_uiManager->m_importHintTitleLabel->setText(importHintTitleText());
    }
    if (m_uiManager && m_uiManager->m_importHintText && !m_fileLoaded) {
        m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
    }

    if (m_uiManager && m_uiManager->m_exportsTree) {
        m_uiManager->m_exportsTree->setHeaderLabels({
            LANG("UI/exports_header_name"),
            LANG("UI/exports_header_offset"),
            LANG("UI/exports_header_ordinal")
        });
    }

    if (m_uiManager && m_uiManager->m_dependenciesTree) {
        m_uiManager->m_dependenciesTree->setHeaderLabels({
            LANG("UI/deps_header_module"),
            LANG("UI/deps_header_resolved_path"),
            LANG("UI/deps_header_found")
        });
    }

    if (m_uiManager && m_uiManager->m_stringsTree) {
        m_uiManager->m_stringsTree->setHeaderLabels({
            LANG("UI/strings_header_offset"),
            LANG("UI/strings_header_section"),
            LANG("UI/strings_header_type"),
            LANG("UI/strings_header_value")
        });
    }

    if (m_uiManager && m_uiManager->m_stringsFilterEdit) {
        m_uiManager->m_stringsFilterEdit->setPlaceholderText(LANG("UI/strings_filter_placeholder"));
    }
    if (m_uiManager && m_uiManager->m_stringsTypeCombo && m_uiManager->m_stringsTypeCombo->count() >= 6) {
        m_uiManager->m_stringsTypeCombo->setItemText(0, LANG("UI/strings_filter_type_all"));
        m_uiManager->m_stringsTypeCombo->setItemText(1, LANG("UI/strings_filter_type_ascii"));
        m_uiManager->m_stringsTypeCombo->setItemText(2, LANG("UI/strings_filter_type_unicode"));
        m_uiManager->m_stringsTypeCombo->setItemText(3, LANG("UI/strings_filter_type_url"));
        m_uiManager->m_stringsTypeCombo->setItemText(4, LANG("UI/strings_filter_type_ip"));
        m_uiManager->m_stringsTypeCombo->setItemText(5, LANG("UI/strings_filter_type_registry"));
        m_uiManager->m_stringsTypeCombo->setItemText(6, LANG("UI/strings_filter_type_command"));
    }
    if (m_uiManager && m_uiManager->m_stringsMinLengthSpin) {
        m_uiManager->m_stringsMinLengthSpin->setPrefix(LANG("UI/strings_min_len_prefix"));
    }
    if (m_uiManager && m_uiManager->m_stringsSectionCombo && m_uiManager->m_stringsSectionCombo->count() > 0) {
        m_uiManager->m_stringsSectionCombo->setItemText(0, LANG("UI/strings_all_sections"));
    }

    if (m_uiManager && m_uiManager->m_fieldExplanationTitleLabel) {
        m_uiManager->m_fieldExplanationTitleLabel->setText(LANG("UI/explanation_label"));
    }

    // Update placeholder text
    if (m_uiManager && m_uiManager->m_fieldExplanationText) {
        m_uiManager->m_fieldExplanationText->setPlaceholderText(LANG("UI/placeholder_explanation"));
    }
    
    // Update button texts
    if (m_uiManager && m_uiManager->m_refreshButton) m_uiManager->m_refreshButton->setText(LANG("UI/button_refresh"));
    if (m_uiManager && m_uiManager->m_copyButton) {
        m_uiManager->m_copyButton->setText(LANG("UI/button_copy"));
        m_uiManager->m_copyButton->setToolTip(LANG("UI/button_copy_tooltip"));
    }
    if (m_uiManager && m_uiManager->m_saveButton) m_uiManager->m_saveButton->setText(LANG("UI/button_save"));
    if (m_uiManager && m_uiManager->m_expandAllButton) m_uiManager->m_expandAllButton->setText(LANG("UI/context_expand_all"));
    if (m_uiManager && m_uiManager->m_collapseAllButton) m_uiManager->m_collapseAllButton->setText(LANG("UI/context_collapse_all"));
    if (m_uiManager && m_uiManager->m_dependenciesExpandAllButton) {
        m_uiManager->m_dependenciesExpandAllButton->setText(LANG("UI/context_expand_all"));
    }
    if (m_uiManager && m_uiManager->m_dependenciesCollapseAllButton) {
        m_uiManager->m_dependenciesCollapseAllButton->setText(LANG("UI/context_collapse_all"));
    }
    if (m_uiManager && m_uiManager->m_stringsExportButton) {
        m_uiManager->m_stringsExportButton->setText(LANG("UI/button_export"));
    }
    if (m_uiManager && m_uiManager->m_stringsCancelButton) {
        m_uiManager->m_stringsCancelButton->setText(LANG("UI/button_cancel"));
    }
}

void MainWindow::updateMenuLanguage()
{
    // Update menu texts
    QMenuBar *menuBar = this->menuBar();
    
    const QList<QAction *> topLevelMenuActions = menuBar->actions();
    for (QAction *menuAction : topLevelMenuActions) {
        if (menuAction->menu()) {
            QMenu *menu = menuAction->menu();
            
            // Update menu title - use object name or text matching
            QString cleanTitle = menu->title();
            cleanTitle.replace(QLatin1Char('&'), QString());
            
            if (cleanTitle.contains("File", Qt::CaseInsensitive) || 
                cleanTitle.contains("Arquivo", Qt::CaseInsensitive)) {
                menu->setTitle(LANG("UI/menu_file"));
            } else if (cleanTitle.contains("Tools", Qt::CaseInsensitive) || 
                       cleanTitle.contains("Ferramentas", Qt::CaseInsensitive)) {
                menu->setTitle(LANG("UI/menu_tools"));
            } else if (cleanTitle.contains("About", Qt::CaseInsensitive) || 
                       cleanTitle.contains("Sobre", Qt::CaseInsensitive)) {
                menu->setTitle(LANG("UI/menu_about"));
                // Do not setIcon() on this QMenu — on Windows the menu bar shows only the icon
                // and hides the "About" text (see setupMenus comment above).
            }
            
            // Update menu item texts (order matters: specific strings before generic "Open"/"Abrir")
            const QList<QAction *> menuActions = menu->actions();
            for (QAction *action : menuActions) {
                QString actionText = action->text();
                QString cleanActionText = actionText;
                cleanActionText.replace(QLatin1Char('&'), QString());

                if (cleanActionText.contains(QStringLiteral("Open Recent"), Qt::CaseInsensitive) ||
                    cleanActionText.contains(QStringLiteral("Abrir Recente"), Qt::CaseInsensitive) ||
                    cleanActionText.contains(QStringLiteral("Abrir Recentes"), Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_open_recent"));
                    if (action->menu() == m_openRecentMenu) {
                        action->setIcon(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")));
                    }
                } else if (cleanActionText.contains(QStringLiteral("Clear Recent on Exit"), Qt::CaseInsensitive) ||
                           cleanActionText.contains(QStringLiteral("Limpar Recentes ao Sair"), Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_clear_recent_on_exit"));
                    action->setIcon(QIcon(QStringLiteral(":/images/imgs/clear.png")));
                } else if (cleanActionText.compare(QStringLiteral("Open"), Qt::CaseInsensitive) == 0 ||
                           cleanActionText.compare(QStringLiteral("Abrir"), Qt::CaseInsensitive) == 0) {
                    action->setText(LANG("UI/menu_open"));
                    action->setIcon(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")));
                } else if (cleanActionText.contains(QStringLiteral("Save Report"), Qt::CaseInsensitive) ||
                           cleanActionText.contains(QStringLiteral("Salvar Relatório"), Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_save_report"));
                } else if (cleanActionText.contains(QStringLiteral("Exit"), Qt::CaseInsensitive) ||
                           cleanActionText.compare(QStringLiteral("Sair"), Qt::CaseInsensitive) == 0) {
                    action->setText(LANG("UI/menu_exit"));
                    action->setIcon(QIcon(QStringLiteral(":/images/imgs/logout.png")));
                } else if (cleanActionText.contains(QStringLiteral("Refresh"), Qt::CaseInsensitive) ||
                           cleanActionText.contains(QStringLiteral("Atualizar"), Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_refresh"));
                } else if (cleanActionText.contains(QStringLiteral("Hex"), Qt::CaseInsensitive) ||
                           cleanActionText.contains(QStringLiteral("Opções Hex"), Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_hex_options"));
                } else if (cleanActionText.compare(QStringLiteral("About"), Qt::CaseInsensitive) == 0 ||
                           cleanActionText.contains(QStringLiteral("PEHint"), Qt::CaseInsensitive) ||
                           cleanActionText.contains(QStringLiteral("Sobre PEHint"), Qt::CaseInsensitive)) {
                    action->setText(LANG("UI/menu_about"));
                    action->setIcon(QIcon(QStringLiteral(":/images/imgs/about.png")));
                }
            }
        }
    }

    // Refresh recent-files submenu labels (and icons on dynamic actions)
    updateOpenRecentMenu();
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
    const QList<QAction *> barActionsForTools = menuBar()->actions();
    for (QAction *action : barActionsForTools) {
        if (action->menu()) {
            QString cleanTitle = action->menu()->title();
            cleanTitle.replace(QLatin1Char('&'), QString());
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
    
    // Find language submenu: prefer structure (items carry lang codes), not translated title text
    const QStringList avail = LanguageManager::getInstance().getAvailableLanguages();
    const QList<QAction *> toolsMenuActions = toolsMenu->actions();
    for (QAction *action : toolsMenuActions) {
        if (!action->menu()) {
            continue;
        }
        QMenu *candidate = action->menu();
        const QList<QAction *> candidateActions = candidate->actions();
        for (QAction *sub : candidateActions) {
            const QString code = sub->data().toString();
            if (!code.isEmpty() && avail.contains(code)) {
                languageMenu = candidate;
                break;
            }
        }
        if (languageMenu) {
            break;
        }
    }
    if (!languageMenu) {
        for (QAction *action : toolsMenuActions) {
            if (action->menu() && action->text().contains(LANG("UI/menu_language"), Qt::CaseInsensitive)) {
                languageMenu = action->menu();
                break;
            }
        }
    }

    if (!languageMenu) {
        qWarning() << "Language submenu not found in updateLanguageMenu";
        return;
    }
    
    // Get current language and update all language actions
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();
    qDebug() << "Updating language menu, current language:" << currentLanguage;
    
    // Ensure mutual exclusivity: only one action can be checked. Block signals so QActionGroup / checkable
    // actions do not re-emit triggered() while we sync state (avoids re-entrancy into setLanguage).
    bool foundCurrentLanguage = false;
    const QList<QAction *> languageActions = languageMenu->actions();
    for (QAction *langAction : languageActions) {
        langAction->blockSignals(true);
    }
    for (QAction *langAction : languageActions) {
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
    for (QAction *langAction : languageActions) {
        langAction->blockSignals(false);
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

    m_uiManager->m_importFunctionsTree->blockSignals(true);
    m_uiManager->m_importFunctionsTree->clear();
    m_uiManager->m_importFunctionsTree->blockSignals(false);

    if (!m_fileLoaded || !m_peParser) {
        if (m_uiManager->m_importHintText) {
            m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
        }
        return;
    }

    const auto &importDetails = m_peParser->getImportFunctionDetails();
    const QList<PEDataModel::ImportFunctionEntry> functions = moduleName.isEmpty() ? QList<PEDataModel::ImportFunctionEntry>() : importDetails.value(moduleName);

    if (functions.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_importFunctionsTree);
        placeholder->setText(0, LANG("UI/imports_no_functions"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
        if (m_uiManager->m_importHintText) {
            m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
        }
        return;
    }

    for (const PEDataModel::ImportFunctionEntry &entry : functions) {
        QTreeWidgetItem *item = new QTreeWidgetItem(m_uiManager->m_importFunctionsTree);
        item->setText(0, entry.name);
        item->setData(0, kImportByOrdinalRole, entry.importedByOrdinal);
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
        applyFlaggedImportRowStyle(item, moduleName, entry);
    }

    if (m_uiManager->m_importFunctionsTree->topLevelItemCount() > 0) {
        QTreeWidgetItem *first = m_uiManager->m_importFunctionsTree->topLevelItem(0);
        if (first->flags() != Qt::NoItemFlags) {
            m_uiManager->m_importFunctionsTree->setCurrentItem(first);
        }
    }
}

void MainWindow::onImportFunctionSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);
    if (!m_uiManager || !m_uiManager->m_importHintText) {
        return;
    }
    if (!current || current->flags() == Qt::NoItemFlags) {
        m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
        return;
    }
    QTreeWidgetItem *modItem = m_uiManager->m_importModulesTree
        ? m_uiManager->m_importModulesTree->currentItem()
        : nullptr;
    if (!modItem) {
        m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
        return;
    }
    const QString moduleName = modItem->text(0);
    if (moduleName == LanguageManager::getInstance().getString(QStringLiteral("UI/imports_none"), QStringLiteral("No imported modules"))) {
        m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
        return;
    }
    const QString funcName = current->text(0);
    if (funcName == LanguageManager::getInstance().getString(QStringLiteral("UI/imports_no_functions"), QStringLiteral("No imported functions"))) {
        m_uiManager->m_importHintText->setPlainText(importHintPlaceholderText());
        return;
    }
    const bool importByOrdinal = current->data(0, kImportByOrdinalRole).toBool();
    if (importByOrdinal) {
        if (funcName == QStringLiteral("[ - ]")) {
            QString t = importHintOrdinalText();
            t += QStringLiteral("\n\n");
            t += importHintFooterText();
            m_uiManager->m_importHintText->setPlainText(t);
            return;
        }
        const ImportApiHint hintOrd = SdkApiMarkdownReader::instance().hintForImport(moduleName, funcName);
        if (hintOrd.hasContent()) {
            const QString banner = QStringLiteral("<p style=\"color:#444;font-size:10px;margin:0 0 10px 0;padding:6px 8px;background:#fafafa;"
                                                  "border-left:3px solid #bbb;\">")
                + QStringLiteral("Imported by <strong>ordinal</strong> in this PE; the name in the list was resolved from the export table of the system copy of ")
                + moduleName.toHtmlEscaped()
                + QStringLiteral(" (not stored in the PE).</p>");
            m_uiManager->m_importHintText->setHtml(formatImportHintDisplay(hintOrd, banner));
            return;
        }
        QString t = importHintOrdinalText();
        t += QStringLiteral("\n\n");
        t += importHintFooterText();
        m_uiManager->m_importHintText->setPlainText(t);
        return;
    }
    const ImportApiHint hint = SdkApiMarkdownReader::instance().hintForImport(moduleName, funcName);
    if (!hint.hasContent()) {
        QString t = importHintNoneForFunction(funcName);
        t += QStringLiteral("\n\n");
        t += importHintFooterText();
        m_uiManager->m_importHintText->setPlainText(t);
        return;
    }
    m_uiManager->m_importHintText->setHtml(formatImportHintDisplay(hint));
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

void MainWindow::populateDelayImportFunctions(const QString &moduleName)
{
    if (!m_uiManager || !m_uiManager->m_delayImportFunctionsTree) {
        return;
    }

    m_uiManager->m_delayImportFunctionsTree->blockSignals(true);
    m_uiManager->m_delayImportFunctionsTree->clear();
    m_uiManager->m_delayImportFunctionsTree->blockSignals(false);

    if (!m_fileLoaded || !m_peParser) {
        return;
    }

    const auto &delayImportDetails = m_peParser->getDelayImportFunctionDetails();
    const QList<PEDataModel::ImportFunctionEntry> functions =
        moduleName.isEmpty() ? QList<PEDataModel::ImportFunctionEntry>() : delayImportDetails.value(moduleName);

    if (functions.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_uiManager->m_delayImportFunctionsTree);
        placeholder->setText(0, LANG("UI/delay_imports_no_functions"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
        return;
    }

    for (const PEDataModel::ImportFunctionEntry &entry : functions) {
        QTreeWidgetItem *item = new QTreeWidgetItem(m_uiManager->m_delayImportFunctionsTree);
        item->setText(0, entry.name);
        if (entry.thunkRVA != 0) {
            item->setText(1, PEUtils::formatHexWidth(entry.thunkRVA, 8));
        } else {
            item->setText(1, QString());
        }
        if (entry.importedByOrdinal) {
            item->setText(2, QString::number(entry.ordinal));
        } else {
            item->setText(2, QString());
        }
        applyFlaggedImportRowStyle(item, moduleName, entry);
    }
}

void MainWindow::onDelayImportModuleSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);

    if (!m_fileLoaded || !m_peParser) {
        return;
    }

    if (!current) {
        populateDelayImportFunctions(QString());
        return;
    }

    const QString noneLabel = LanguageManager::getInstance().getString(
        QStringLiteral("UI/delay_imports_none"), QStringLiteral("No delay-import modules"));
    if (current->text(0) == noneLabel) {
        populateDelayImportFunctions(QString());
        return;
    }

    populateDelayImportFunctions(current->text(0));
}

