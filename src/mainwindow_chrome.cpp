#include "mainwindow_chrome.h"

#include "mainwindow.h"
#include "version.h"
#include "language_manager.h"
#include "crash_handler.h"
#include "pe_report_builder.h"
#include "pe_data_model.h"
#include "findings_controller.h"
#include "imports_controller.h"
#include "exports_controller.h"
#include "resources_controller.h"
#include "dependencies_controller.h"
#include "strings_controller.h"
#include "pe_ui_manager.h"
#include "hexviewer.h"

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QIcon>
#include <QKeySequence>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QSettings>
#include <QShortcut>
#include <QStandardPaths>
#include <QStatusBar>
#include <QTabWidget>
#include <QTextStream>
#include <QStringConverter>
#include <QTimer>
#include <QTreeWidget>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFrame>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>
#include <QPixmap>

namespace {

QString aboutLine(const QString &key, const QString &englishFallback)
{
    const QString s = LanguageManager::getInstance().getString(key, englishFallback);
    return (s == key) ? englishFallback : s;
}

QString aboutFeatureBody(const QString &line)
{
    QString t = line.trimmed();
    if (t.startsWith(QLatin1Char('-'))) {
        t = t.mid(1).trimmed();
    }
    return t;
}

QString recentFilesIniPath()
{
    const QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!baseDir.isEmpty()) {
        QDir().mkpath(baseDir);
        return QDir(baseDir).filePath(QStringLiteral("recent_files.ini"));
    }
    return QDir::home().filePath(QStringLiteral(".pehint_recent_files.ini"));
}

} // namespace

MainWindowChrome::MainWindowChrome(MainWindow *window)
    : QObject(window)
    , m_window(window)
{
}

void MainWindowChrome::setUiManager(UIManager *ui)
{
    m_ui = ui;
}

void MainWindowChrome::setControllers(FindingsController *findings,
                                      ImportsController *imports,
                                      ExportsController *exports,
                                      ResourcesController *resources,
                                      DependenciesController *dependencies,
                                      StringsController *strings)
{
    m_findingsController = findings;
    m_importsController = imports;
    m_exportsController = exports;
    m_resourcesController = resources;
    m_dependenciesController = dependencies;
    m_stringsController = strings;
}

void MainWindowChrome::setupMenus()
{
    CrashHandler::getInstance().logInfo("MainWindowChrome", "Setting up application menus");

    m_window->menuBar()->clear();

    QMenu *fileMenu = m_window->menuBar()->addMenu(LANG("UI/menu_file"));

    QAction *openAction = new QAction(LANG("UI/menu_open"), m_window);
    openAction->setIcon(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")));
    openAction->setShortcut(QKeySequence::Open);
    fileMenu->addAction(openAction);

    m_openRecentMenu = fileMenu->addMenu(LANG("UI/menu_open_recent"));
    m_openRecentMenu->setEnabled(false);
    if (QAction *recentMenuAct = m_openRecentMenu->menuAction()) {
        recentMenuAct->setIcon(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")));
    }

    QAction *clearRecentOnExitAction = new QAction(LANG("UI/menu_clear_recent_on_exit"), m_window);
    clearRecentOnExitAction->setCheckable(true);
    clearRecentOnExitAction->setIcon(QIcon(QStringLiteral(":/images/imgs/clear.png")));
    {
        QSettings settings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
        clearRecentOnExitAction->setChecked(settings.value(QStringLiteral("ui/clearRecentOnExit"), false).toBool());
    }
    fileMenu->addAction(clearRecentOnExitAction);
    connect(clearRecentOnExitAction, &QAction::toggled, m_window, [](bool checked) {
        QSettings settings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
        settings.setValue(QStringLiteral("ui/clearRecentOnExit"), checked);
    });

    QAction *saveReportAction = new QAction(LANG("UI/menu_save_report"), m_window);
    saveReportAction->setIcon(QIcon(QStringLiteral(":/images/imgs/save.png")));
    fileMenu->addAction(saveReportAction);

    fileMenu->addSeparator();

    QAction *exitAction = new QAction(LANG("UI/menu_exit"), m_window);
    exitAction->setIcon(QIcon(QStringLiteral(":/images/imgs/logout.png")));
    exitAction->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Q));
    fileMenu->addAction(exitAction);

    QMenu *toolsMenu = m_window->menuBar()->addMenu(LANG("UI/menu_tools"));

    QAction *refreshAction = new QAction(LANG("UI/menu_refresh"), m_window);
    refreshAction->setIcon(QIcon(QStringLiteral(":/images/imgs/refresh.png")));
    refreshAction->setShortcut(QKeySequence::Refresh);
    toolsMenu->addAction(refreshAction);

    QAction *hexViewerAction = new QAction(LANG("UI/menu_hex_options"), m_window);
    hexViewerAction->setIcon(QIcon(QStringLiteral(":/images/imgs/settings.png")));
    toolsMenu->addAction(hexViewerAction);

    QAction *compareAction = new QAction(LANG("UI/menu_compare"), m_window);
    compareAction->setIcon(QIcon(QStringLiteral(":/images/imgs/compare.png")));
    compareAction->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_D));
    toolsMenu->addAction(compareAction);

    QMenu *aboutMenu = m_window->menuBar()->addMenu(LANG("UI/menu_about"));
    QAction *aboutAction = new QAction(LANG("UI/menu_about"), m_window);
    aboutAction->setIcon(QIcon(QStringLiteral(":/images/imgs/about.png")));
    aboutAction->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_A));
    aboutMenu->addAction(aboutAction);

    connect(openAction, &QAction::triggered, m_window, &MainWindow::on_action_Open_triggered);
    connect(saveReportAction, &QAction::triggered, m_window, &MainWindow::on_action_Save_Report_triggered);
    connect(exitAction, &QAction::triggered, m_window, &MainWindow::on_action_Exit_triggered);
    connect(refreshAction, &QAction::triggered, m_window, &MainWindow::on_action_Refresh_triggered);
    connect(hexViewerAction, &QAction::triggered, m_window, &MainWindow::onHexViewerOptions);
    connect(compareAction, &QAction::triggered, m_window, &MainWindow::onCompareFiles);
    connect(aboutAction, &QAction::triggered, m_window, &MainWindow::on_action_PEHint_triggered);

    m_window->addAction(openAction);
    m_window->addAction(saveReportAction);
    m_window->addAction(exitAction);
    m_window->addAction(refreshAction);
    m_window->addAction(hexViewerAction);
    m_window->addAction(aboutAction);

    CrashHandler::getInstance().logInfo("MainWindowChrome", "Application menus setup completed");
}

void MainWindowChrome::loadRecentFiles()
{
    QSettings recentSettings(recentFilesIniPath(), QSettings::IniFormat);
    m_recentFiles = recentSettings.value(QStringLiteral("recentFiles")).toStringList();

    if (m_recentFiles.isEmpty()) {
        QSettings legacySettings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
        const QStringList legacyRecents = legacySettings.value(QStringLiteral("recentFiles")).toStringList();
        if (!legacyRecents.isEmpty()) {
            m_recentFiles = legacyRecents;
            recentSettings.setValue(QStringLiteral("recentFiles"), m_recentFiles);
        }
    }

    QStringList filtered;
    for (const QString &p : m_recentFiles) {
        if (!p.trimmed().isEmpty() && QFileInfo(p).exists()) {
            filtered.append(p);
        }
    }
    m_recentFiles = filtered;
}

void MainWindowChrome::saveRecentFiles() const
{
    QSettings recentSettings(recentFilesIniPath(), QSettings::IniFormat);
    recentSettings.setValue(QStringLiteral("recentFiles"), m_recentFiles);
}

void MainWindowChrome::updateOpenRecentMenu()
{
    if (!m_openRecentMenu) {
        return;
    }

    m_openRecentMenu->clear();

    constexpr int kMaxRecents = 10;
    if (m_recentFiles.isEmpty()) {
        QAction *placeholder = m_openRecentMenu->addAction(LANG("UI/menu_no_recent_files"));
        placeholder->setEnabled(false);
        m_openRecentMenu->setEnabled(false);
        return;
    }

    m_openRecentMenu->setEnabled(true);
    const int count = qMin(kMaxRecents, m_recentFiles.size());
    for (int i = 0; i < count; ++i) {
        const QString &path = m_recentFiles.at(i);
        if (path.trimmed().isEmpty()) {
            continue;
        }
        const QString label = QFileInfo(path).fileName().isEmpty() ? path : QFileInfo(path).fileName();
        QAction *act = m_openRecentMenu->addAction(label);
        act->setData(path);
        connect(act, &QAction::triggered, m_window, [this, path]() {
            m_window->openPeFile(path);
        });
    }

    m_openRecentMenu->addSeparator();
    QAction *clearAct = m_openRecentMenu->addAction(LANG("UI/menu_clear_recent"));
    clearAct->setIcon(QIcon(QStringLiteral(":/images/imgs/clear.png")));
    connect(clearAct, &QAction::triggered, m_window, [this]() {
        m_recentFiles.clear();
        saveRecentFiles();
        updateOpenRecentMenu();
    });
}

void MainWindowChrome::addToRecentFiles(const QString &filePath)
{
    const QString trimmed = filePath.trimmed();
    if (trimmed.isEmpty() || !QFileInfo(trimmed).exists()) {
        return;
    }

    m_recentFiles.removeAll(trimmed);
    m_recentFiles.prepend(trimmed);

    constexpr int kMaxRecents = 10;
    if (m_recentFiles.size() > kMaxRecents) {
        m_recentFiles = m_recentFiles.mid(0, kMaxRecents);
    }

    saveRecentFiles();
    updateOpenRecentMenu();
}

void MainWindowChrome::clearRecentFilesOnExitIfConfigured()
{
    QSettings settings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
    if (settings.value(QStringLiteral("ui/clearRecentOnExit"), false).toBool()) {
        m_recentFiles.clear();
        saveRecentFiles();
    }
}

void MainWindowChrome::setupStatusBar()
{
    m_window->statusBar()->showMessage(LANG("UI/status_ready"));
}

void MainWindowChrome::setupContextMenu()
{
    m_contextMenu = new QMenu(m_window);

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

    m_contextMenu->addSeparator();

    QAction *compareContextAction = new QAction(LANG("UI/menu_compare"), m_contextMenu);
    compareContextAction->setIcon(QIcon(QStringLiteral(":/images/imgs/compare.png")));
    m_contextMenu->addAction(compareContextAction);

    connect(copyAction, &QAction::triggered, m_window, &MainWindow::onCopyToClipboard);
    connect(expandAction, &QAction::triggered, m_window, &MainWindow::onExpandAll);
    connect(collapseAction, &QAction::triggered, m_window, &MainWindow::onCollapseAll);
    connect(compareContextAction, &QAction::triggered, m_window, &MainWindow::onCompareFiles);

    m_window->addAction(copyAction);
    m_window->addAction(expandAction);
    m_window->addAction(collapseAction);

    auto *copyFieldAlt = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C), m_window);
    copyFieldAlt->setContext(Qt::ApplicationShortcut);
    connect(copyFieldAlt, &QShortcut::activated, m_window, &MainWindow::onCopyToClipboard);
}

void MainWindowChrome::setupLanguageMenu()
{
    QMenu *toolsMenu = findToolsMenu();
    if (!toolsMenu) {
        toolsMenu = m_window->menuBar()->addMenu(LANG("UI/menu_tools"));
    }

    QMenu *languageMenu = toolsMenu->addMenu(LANG("UI/menu_language"));
    languageMenu->setIcon(QIcon(QStringLiteral(":/images/imgs/language.png")));

    if (!m_languageActionGroup) {
        m_languageActionGroup = new QActionGroup(m_window);
        m_languageActionGroup->setExclusive(true);
    }

    const QStringList languages = LanguageManager::getInstance().getAvailableLanguages();
    const QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();

    for (const QString &langCode : languages) {
        const QString displayName = LanguageManager::getInstance().getLanguageDisplayName(langCode);
        auto *langAction = new QAction(displayName, m_window);
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

QMenu *MainWindowChrome::findToolsMenu() const
{
    for (QAction *action : m_window->menuBar()->actions()) {
        if (!action->menu()) {
            continue;
        }
        QString cleanTitle = action->menu()->title();
        cleanTitle.remove(QLatin1Char('&'));
        if (cleanTitle == QLatin1String("Tools") || cleanTitle == QLatin1String("Ferramentas")
            || cleanTitle.contains(QLatin1String("Tools"), Qt::CaseInsensitive)
            || cleanTitle.contains(QLatin1String("Ferramentas"), Qt::CaseInsensitive)) {
            return action->menu();
        }
    }
    return nullptr;
}

void MainWindowChrome::onLanguageMenuTriggered(QAction *action)
{
    const QString languageCode = action->data().toString();
    const QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();

    if (languageCode == currentLanguage) {
        QTimer::singleShot(0, this, [this]() { updateLanguageMenu(); });
        return;
    }

    if (LanguageManager::getInstance().setLanguage(languageCode)) {
        return;
    }

    QTimer::singleShot(0, this, [this]() { updateLanguageMenu(); });
}

void MainWindowChrome::updateWindowTitle()
{
    m_window->setWindowTitle(LANG_PARAM("UI/window_title", "version", PEHINT_VERSION_STRING_FULL));
}

void MainWindowChrome::refreshTranslatedUi(bool fileLoaded)
{
    updateWindowTitle();

    if (!fileLoaded) {
        m_window->statusBar()->showMessage(LANG("UI/status_ready"));
    }

    updateMenuLanguage();

    if (m_ui && m_ui->m_fileInfoLabel && !fileLoaded) {
        m_ui->m_fileInfoLabel->setText(LANG("UI/file_no_file_loaded"));
    }

    if (m_ui && m_ui->m_peTree) {
        m_ui->m_peTree->setHeaderLabels({
            LANG("UI/tree_header_field"),
            LANG("UI/tree_header_value"),
            LANG("UI/tree_header_offset"),
            LANG("UI/tree_header_size"),
            LANG("UI/tree_header_meaning")
        });
    }

    if (m_ui && m_ui->m_analysisTabWidget) {
        QTabWidget *tw = m_ui->m_analysisTabWidget;
        if (tw->count() > 0) tw->setTabText(0, LANG("UI/tab_structure"));
        if (tw->count() > 1) tw->setTabText(1, LANG("UI/tab_imports"));
        if (tw->count() > 2) tw->setTabText(2, LANG("UI/tab_delay_imports"));
        if (tw->count() > 3) tw->setTabText(3, LANG("UI/tab_exports"));
        if (tw->count() > 4) tw->setTabText(4, LANG("UI/tab_resources"));
        if (tw->count() > 5) tw->setTabText(5, LANG("UI/tab_dependencies"));
        if (tw->count() > 6) tw->setTabText(6, LANG("UI/tab_strings"));
        if (tw->count() > 7) tw->setTabText(7, LANG("UI/tab_findings"));
    }

    if (m_findingsController) m_findingsController->updateLanguageStrings();
    if (m_importsController) m_importsController->updateLanguageStrings();
    if (m_resourcesController) m_resourcesController->updateLanguageStrings();
    if (m_dependenciesController) m_dependenciesController->updateLanguageStrings();
    if (m_stringsController) m_stringsController->updateLanguageStrings();
    if (m_exportsController) m_exportsController->updateLanguageStrings();

    if (m_ui && m_ui->m_exportsTree) {
        m_ui->m_exportsTree->setHeaderLabels({
            LANG("UI/exports_header_name"),
            LANG("UI/exports_header_offset"),
            LANG("UI/exports_header_ordinal")
        });
    }

    if (m_ui && m_ui->m_fieldExplanationTitleLabel) {
        m_ui->m_fieldExplanationTitleLabel->setText(LANG("UI/explanation_label"));
    }
    if (m_ui && m_ui->m_fieldExplanationText) {
        m_ui->m_fieldExplanationText->setPlaceholderText(LANG("UI/placeholder_explanation"));
    }

    if (m_ui && m_ui->m_refreshButton) m_ui->m_refreshButton->setText(LANG("UI/button_refresh"));
    if (m_ui && m_ui->m_copyButton) {
        m_ui->m_copyButton->setText(LANG("UI/button_copy"));
        m_ui->m_copyButton->setToolTip(LANG("UI/button_copy_tooltip"));
    }
    if (m_ui && m_ui->m_saveButton) m_ui->m_saveButton->setText(LANG("UI/button_save"));
    if (m_ui && m_ui->m_expandAllButton) m_ui->m_expandAllButton->setText(LANG("UI/context_expand_all"));
    if (m_ui && m_ui->m_collapseAllButton) m_ui->m_collapseAllButton->setText(LANG("UI/context_collapse_all"));
    if (m_ui && m_ui->m_dependenciesExpandAllButton) {
        m_ui->m_dependenciesExpandAllButton->setText(LANG("UI/context_expand_all"));
    }
    if (m_ui && m_ui->m_dependenciesCollapseAllButton) {
        m_ui->m_dependenciesCollapseAllButton->setText(LANG("UI/context_collapse_all"));
    }
    if (m_ui && m_ui->m_stringsExportButton) {
        m_ui->m_stringsExportButton->setText(LANG("UI/button_export"));
    }
    if (m_ui && m_ui->m_stringsCancelButton) {
        m_ui->m_stringsCancelButton->setText(LANG("UI/button_cancel"));
    }
}

void MainWindowChrome::updateMenuLanguage()
{
    QMenuBar *menuBar = m_window->menuBar();

    for (QAction *menuAction : menuBar->actions()) {
        if (!menuAction->menu()) {
            continue;
        }
        QMenu *menu = menuAction->menu();

        QString cleanTitle = menu->title();
        cleanTitle.replace(QLatin1Char('&'), QString());

        if (cleanTitle.contains(QStringLiteral("File"), Qt::CaseInsensitive)
            || cleanTitle.contains(QStringLiteral("Arquivo"), Qt::CaseInsensitive)) {
            menu->setTitle(LANG("UI/menu_file"));
        } else if (cleanTitle.contains(QStringLiteral("Tools"), Qt::CaseInsensitive)
                   || cleanTitle.contains(QStringLiteral("Ferramentas"), Qt::CaseInsensitive)) {
            menu->setTitle(LANG("UI/menu_tools"));
        } else if (cleanTitle.contains(QStringLiteral("About"), Qt::CaseInsensitive)
                   || cleanTitle.contains(QStringLiteral("Sobre"), Qt::CaseInsensitive)) {
            menu->setTitle(LANG("UI/menu_about"));
        }

        for (QAction *action : menu->actions()) {
            QString cleanActionText = action->text();
            cleanActionText.replace(QLatin1Char('&'), QString());

            if (cleanActionText.contains(QStringLiteral("Open Recent"), Qt::CaseInsensitive)
                || cleanActionText.contains(QStringLiteral("Abrir Recente"), Qt::CaseInsensitive)
                || cleanActionText.contains(QStringLiteral("Abrir Recentes"), Qt::CaseInsensitive)) {
                action->setText(LANG("UI/menu_open_recent"));
                if (action->menu() == m_openRecentMenu) {
                    action->setIcon(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")));
                }
            } else if (cleanActionText.contains(QStringLiteral("Clear Recent on Exit"), Qt::CaseInsensitive)
                       || cleanActionText.contains(QStringLiteral("Limpar Recentes ao Sair"), Qt::CaseInsensitive)) {
                action->setText(LANG("UI/menu_clear_recent_on_exit"));
                action->setIcon(QIcon(QStringLiteral(":/images/imgs/clear.png")));
            } else if (cleanActionText.compare(QStringLiteral("Open"), Qt::CaseInsensitive) == 0
                       || cleanActionText.compare(QStringLiteral("Abrir"), Qt::CaseInsensitive) == 0) {
                action->setText(LANG("UI/menu_open"));
                action->setIcon(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")));
            } else if (cleanActionText.contains(QStringLiteral("Save Report"), Qt::CaseInsensitive)
                       || cleanActionText.contains(QStringLiteral("Salvar Rel"), Qt::CaseInsensitive)) {
                action->setText(LANG("UI/menu_save_report"));
            } else if (cleanActionText.contains(QStringLiteral("Exit"), Qt::CaseInsensitive)
                       || cleanActionText.compare(QStringLiteral("Sair"), Qt::CaseInsensitive) == 0) {
                action->setText(LANG("UI/menu_exit"));
                action->setIcon(QIcon(QStringLiteral(":/images/imgs/logout.png")));
            } else if (cleanActionText.contains(QStringLiteral("Refresh"), Qt::CaseInsensitive)
                       || cleanActionText.contains(QStringLiteral("Atualizar"), Qt::CaseInsensitive)) {
                action->setText(LANG("UI/menu_refresh"));
            } else if (cleanActionText.contains(QStringLiteral("Hex"), Qt::CaseInsensitive)) {
                action->setText(LANG("UI/menu_hex_options"));
            } else if (cleanActionText.compare(QStringLiteral("About"), Qt::CaseInsensitive) == 0
                       || cleanActionText.contains(QStringLiteral("PEHint"), Qt::CaseInsensitive)
                       || cleanActionText.contains(QStringLiteral("Sobre PEHint"), Qt::CaseInsensitive)) {
                action->setText(LANG("UI/menu_about"));
                action->setIcon(QIcon(QStringLiteral(":/images/imgs/about.png")));
            }
        }
    }

    updateOpenRecentMenu();
}

void MainWindowChrome::updateLanguageMenu()
{
    QMenu *toolsMenu = findToolsMenu();
    if (!toolsMenu) {
        return;
    }

    QMenu *languageMenu = nullptr;
    const QStringList avail = LanguageManager::getInstance().getAvailableLanguages();
    for (QAction *action : toolsMenu->actions()) {
        if (!action->menu()) {
            continue;
        }
        QMenu *candidate = action->menu();
        for (QAction *sub : candidate->actions()) {
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
        for (QAction *action : toolsMenu->actions()) {
            if (action->menu() && action->text().contains(LANG("UI/menu_language"), Qt::CaseInsensitive)) {
                languageMenu = action->menu();
                break;
            }
        }
    }

    if (!languageMenu) {
        return;
    }

    const QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();
    const QList<QAction *> languageActions = languageMenu->actions();
    for (QAction *langAction : languageActions) {
        langAction->blockSignals(true);
    }
    for (QAction *langAction : languageActions) {
        const QString langCode = langAction->data().toString();
        langAction->setChecked(langCode == currentLanguage);
    }
    for (QAction *langAction : languageActions) {
        langAction->blockSignals(false);
    }

    languageMenu->setTitle(LANG("UI/menu_language"));
}

bool MainWindowChrome::saveReportToFile(const PEDataModel &model, bool fileLoaded, QWidget *parent)
{
    if (!fileLoaded) {
        QMessageBox::critical(parent, LANG("UI/menu_save_report"), LANG("UI/error_no_report"));
        return false;
    }

    const QString textFilter = LANG("UI/file_filter_text");
    const QString htmlFilter = LANG("UI/file_filter_html");
    const QString jsonFilter = LANG("UI/file_filter_json");
    const QString xmlFilter = LANG("UI/file_filter_xml");
    const QString allFilter = LANG("UI/file_filter_all");
    const QString filters = QString("%1;;%2;;%3;;%4;;%5")
                                .arg(textFilter, htmlFilter, jsonFilter, xmlFilter, allFilter);

    const QString defaultName = LANG("UI/file_default_report_name");
    QString selectedFilter = textFilter;
    const QString filePath = QFileDialog::getSaveFileName(
        parent,
        LANG("UI/dialog_save_analysis_report"),
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + QStringLiteral("/") + defaultName,
        filters,
        &selectedFilter);

    if (filePath.isEmpty()) {
        return false;
    }

    QString content;
    if (selectedFilter.contains(QStringLiteral("html"), Qt::CaseInsensitive)
        || filePath.endsWith(QStringLiteral(".html"), Qt::CaseInsensitive)
        || filePath.endsWith(QStringLiteral(".htm"), Qt::CaseInsensitive)) {
        content = PEReportBuilder::buildHtmlReport(model);
    } else if (selectedFilter.contains(QStringLiteral("json"), Qt::CaseInsensitive)
               || filePath.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive)) {
        content = PEReportBuilder::buildJsonReport(model);
    } else if (selectedFilter.contains(QStringLiteral("xml"), Qt::CaseInsensitive)
               || filePath.endsWith(QStringLiteral(".xml"), Qt::CaseInsensitive)) {
        content = PEReportBuilder::buildXmlReport(model);
    } else {
        content = PEReportBuilder::buildTextReport(model);
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(parent, LANG("UI/menu_save_report"), LANG("UI/error_save_failed"));
        return false;
    }

    QTextStream stream(&file);
    stream.setEncoding(QStringConverter::Utf8);
    stream << content;
    file.close();
    QMessageBox::information(parent, LANG("UI/menu_save_report"), LANG("UI/info_save_success"));
    return true;
}

void MainWindowChrome::showAboutDialog(QWidget *parent)
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
                  QStringLiteral("- Interactive structure tree: all 16 data directories, field explanations, synchronized hex view")),
        aboutLine(QStringLiteral("UI/about_feature_2"),
                  QStringLiteral("- Heuristic Findings panel: 41 rules across hardening, content, metadata, and imports; category filter; one-click navigation")),
        aboutLine(QStringLiteral("UI/about_feature_3"),
                  QStringLiteral("- Imports / Exports / Delay Imports / Dependencies / Resources / Strings tabs")),
        aboutLine(QStringLiteral("UI/about_feature_4"),
                  QStringLiteral("- Authenticode trust verification with publisher, certificate chain, and revocation status (Windows)")),
        aboutLine(QStringLiteral("UI/about_feature_5"),
                  QStringLiteral("- CLI batch triage: --scan, --dir, --recursive, --watch; text and JSON output")),
        aboutLine(QStringLiteral("UI/about_feature_6"),
                  QStringLiteral("- PE Compare: structural diff between two PE files (headers, sections, imports, findings)")),
        aboutLine(QStringLiteral("UI/about_feature_7"),
                  QStringLiteral("- English and Portuguese UI; config-driven rules, explanations, and import API hints")),
    };

    QDialog about(parent);
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
