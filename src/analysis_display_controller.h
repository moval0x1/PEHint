#ifndef ANALYSIS_DISPLAY_CONTROLLER_H
#define ANALYSIS_DISPLAY_CONTROLLER_H

#include <QObject>
#include <QString>
#include <functional>

class FindingsController;
class HexViewer;
class MainWindow;
class PEParserNew;
class StringsController;
class StructureTreeController;
class UIManager;

/** Staged post-parse UI refresh (structure tree, welcome, hex, strings tab). */
class AnalysisDisplayController : public QObject
{
    Q_OBJECT

public:
    AnalysisDisplayController(MainWindow *window,
                              UIManager *ui,
                              PEParserNew *parser,
                              FindingsController *findings,
                              StringsController *strings,
                              StructureTreeController *structure,
                              QObject *parent = nullptr);

    void setFileLoaded(bool loaded) { m_fileLoaded = loaded; }
    void setCurrentFilePath(const QString &path) { m_currentFilePath = path; }
    void setLanguageRefreshEpoch(quint64 *epochPtr) { m_languageRefreshEpoch = epochPtr; }

    void scheduleDisplay(const QString &pathGuard = QString(),
                         std::function<void()> onComplete = nullptr,
                         quint64 languageRefreshEpoch = 0);

    void phaseTree();
    void phaseWelcomeOnly();
    void phaseHexSetData();
    void phaseStringsTab();

    void setOnAnalysisTabChanged(std::function<void(int)> callback)
    {
        m_onAnalysisTabChanged = std::move(callback);
    }

private:
    bool displayGuard(const QString &pathGuard, quint64 languageRefreshEpoch) const;

    MainWindow *m_window = nullptr;
    UIManager *m_ui = nullptr;
    PEParserNew *m_parser = nullptr;
    FindingsController *m_findings = nullptr;
    StringsController *m_strings = nullptr;
    StructureTreeController *m_structure = nullptr;

    bool m_fileLoaded = false;
    QString m_currentFilePath;
    quint64 *m_languageRefreshEpoch = nullptr;
    std::function<void(int)> m_onAnalysisTabChanged;
};

#endif // ANALYSIS_DISPLAY_CONTROLLER_H
