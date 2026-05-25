#ifndef MAINWINDOW_CHROME_H
#define MAINWINDOW_CHROME_H

#include <QObject>
#include <QStringList>

class QAction;
class QActionGroup;
class MainWindow;
class PEDataModel;
class QMenu;
class QWidget;

class FindingsController;
class ImportsController;
class ExportsController;
class ResourcesController;
class DependenciesController;
class StringsController;
class UIManager;

/** Menus, recent files, context menu, status bar, and translated UI chrome. */
class MainWindowChrome : public QObject
{
    Q_OBJECT

public:
    explicit MainWindowChrome(MainWindow *window);

    void setUiManager(UIManager *ui);
    void setControllers(FindingsController *findings,
                        ImportsController *imports,
                        ExportsController *exports,
                        ResourcesController *resources,
                        DependenciesController *dependencies,
                        StringsController *strings);

    void setupMenus();
    void setupLanguageMenu();
    void setupStatusBar();
    void setupContextMenu();

    void loadRecentFiles();
    void saveRecentFiles() const;
    void updateOpenRecentMenu();
    void addToRecentFiles(const QString &filePath);
    void clearRecentFilesOnExitIfConfigured();

    void updateMenuLanguage();
    void updateLanguageMenu();
    void updateWindowTitle();
    void refreshTranslatedUi(bool fileLoaded);

    bool saveReportToFile(const PEDataModel &model, bool fileLoaded, QWidget *parent);
    void showAboutDialog(QWidget *parent);

    QMenu *contextMenu() const { return m_contextMenu; }

private slots:
    void onLanguageMenuTriggered(QAction *action);

private:
    QMenu *findToolsMenu() const;

    MainWindow *m_window = nullptr;
    UIManager *m_ui = nullptr;
    FindingsController *m_findingsController = nullptr;
    ImportsController *m_importsController = nullptr;
    ExportsController *m_exportsController = nullptr;
    ResourcesController *m_resourcesController = nullptr;
    DependenciesController *m_dependenciesController = nullptr;
    StringsController *m_stringsController = nullptr;

    QMenu *m_openRecentMenu = nullptr;
    QMenu *m_contextMenu = nullptr;
    QActionGroup *m_languageActionGroup = nullptr;
    QStringList m_recentFiles;
};

#endif // MAINWINDOW_CHROME_H
