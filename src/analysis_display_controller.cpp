#include "analysis_display_controller.h"

#include "findings_controller.h"
#include "hexviewer.h"
#include "language_manager.h"
#include "mainwindow.h"
#include "pe_parser_new.h"
#include "pe_ui_manager.h"
#include "strings_controller.h"
#include "structure_tree_controller.h"
#include "version.h"

#include <QFile>
#include <QProgressBar>
#include <QLabel>
#include <QStatusBar>
#include <QTimer>
#include <QTreeWidget>

AnalysisDisplayController::AnalysisDisplayController(MainWindow *window,
                                                     UIManager *ui,
                                                     PEParserNew *parser,
                                                     FindingsController *findings,
                                                     StringsController *strings,
                                                     StructureTreeController *structure,
                                                     QObject *parent)
    : QObject(parent)
    , m_window(window)
    , m_ui(ui)
    , m_parser(parser)
    , m_findings(findings)
    , m_strings(strings)
    , m_structure(structure)
{
}

bool AnalysisDisplayController::displayGuard(const QString &pathGuard, quint64 languageRefreshEpoch) const
{
    if (!m_fileLoaded || !m_ui || !m_parser) {
        return false;
    }
    if (!pathGuard.isEmpty() && m_currentFilePath != pathGuard) {
        return false;
    }
    if (languageRefreshEpoch != 0 && m_languageRefreshEpoch
        && *m_languageRefreshEpoch != languageRefreshEpoch) {
        return false;
    }
    return true;
}

void AnalysisDisplayController::scheduleDisplay(const QString &pathGuard,
                                                std::function<void()> onComplete,
                                                quint64 languageRefreshEpoch)
{
    auto guard = [this, pathGuard, languageRefreshEpoch]() -> bool {
        return displayGuard(pathGuard, languageRefreshEpoch);
    };

    QTimer::singleShot(0, m_window, [this, guard, pathGuard, languageRefreshEpoch,
                                     onComplete = std::move(onComplete)]() mutable {
        if (!guard()) {
            if (onComplete) {
                onComplete();
            }
            return;
        }
        phaseTree();
        QTimer::singleShot(0, m_window, [this, guard, pathGuard, languageRefreshEpoch,
                                           onComplete = std::move(onComplete)]() mutable {
            if (!guard()) {
                if (onComplete) {
                    onComplete();
                }
                return;
            }
            phaseWelcomeOnly();
            QTimer::singleShot(0, m_window, [this, guard, pathGuard, languageRefreshEpoch,
                                             onComplete = std::move(onComplete)]() mutable {
                if (!guard()) {
                    if (onComplete) {
                        onComplete();
                    }
                    return;
                }
                phaseHexSetData();
                QTimer::singleShot(0, m_window, [this, guard, pathGuard, languageRefreshEpoch,
                                                 onComplete = std::move(onComplete)]() mutable {
                    if (!guard()) {
                        if (onComplete) {
                            onComplete();
                        }
                        return;
                    }
                    phaseStringsTab();

                    HexViewer *hexViewer = m_ui ? m_ui->m_hexViewer : nullptr;
                    if (hexViewer && hexViewer->isHexDocumentBuildInProgress()) {
                        if (m_ui->m_progressBar) {
                            m_ui->m_progressBar->setVisible(true);
                            m_ui->m_progressBar->setRange(0, 0);
                        }
                        if (m_ui->m_progressLabel) {
                            m_ui->m_progressLabel->setText(
                                LANG(QStringLiteral("UI/status_preparing_hex_view")));
                        }
                        m_window->statusBar()->showMessage(
                            LANG(QStringLiteral("UI/status_preparing_hex_view")));
                        connect(hexViewer, &HexViewer::hexContentReady, m_window,
                                [this, pathGuard, languageRefreshEpoch, oc = std::move(onComplete)]() mutable {
                                    if (!m_fileLoaded || !m_ui) {
                                        return;
                                    }
                                    if (languageRefreshEpoch != 0 && m_languageRefreshEpoch
                                        && *m_languageRefreshEpoch != languageRefreshEpoch) {
                                        return;
                                    }
                                    if (!pathGuard.isEmpty() && m_currentFilePath != pathGuard) {
                                        return;
                                    }
                                    if (m_ui->m_progressBar) {
                                        m_ui->m_progressBar->setRange(0, 100);
                                    }
                                    if (oc) {
                                        oc();
                                    }
                                },
                                Qt::SingleShotConnection);
                    } else if (onComplete) {
                        onComplete();
                    }
                });
            });
        });
    });
}

void AnalysisDisplayController::phaseTree()
{
    if (!m_fileLoaded || !m_ui || !m_parser) {
        return;
    }

    m_ui->m_peTree->setUpdatesEnabled(false);
    m_ui->m_peTree->blockSignals(true);
    m_ui->m_peTree->setCurrentItem(nullptr);
    m_ui->m_peTree->clear();
    const QList<QTreeWidgetItem *> items = m_parser->getPEStructureTree();
    for (QTreeWidgetItem *item : items) {
        m_ui->m_peTree->addTopLevelItem(item);
    }
    m_ui->m_peTree->blockSignals(false);
    m_ui->m_peTree->setUpdatesEnabled(true);

    const bool hasItems = !items.isEmpty();
    if (m_ui->m_expandAllButton) {
        m_ui->m_expandAllButton->setEnabled(hasItems);
    }
    if (m_ui->m_collapseAllButton) {
        m_ui->m_collapseAllButton->setEnabled(hasItems);
    }

    if (m_findings) {
        m_findings->refresh();
    }
}

void AnalysisDisplayController::phaseWelcomeOnly()
{
    if (!m_fileLoaded || !m_ui || !m_parser) {
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
    if (m_parser->isValid() && m_parser->isLargeFile()) {
        QMap<QString, QString> lf;
        lf[QStringLiteral("size")] = QString::number(m_parser->getFileSize() / (1024.0 * 1024.0), 'f', 1);
        extraWelcomeHtml = QStringLiteral("<div style='color: orange; font-weight: bold; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px;'>%1</div>")
                               .arg(LANG_PARAMS(QStringLiteral("UI/large_file_memory_note"), lf));
    }
    if (!extraWelcomeHtml.isEmpty()) {
        m_ui->m_fieldExplanationText->setHtml(welcomeMessage + extraWelcomeHtml);
    } else {
        m_ui->m_fieldExplanationText->setHtml(welcomeMessage);
    }
}

void AnalysisDisplayController::phaseHexSetData()
{
    if (!m_fileLoaded || !m_ui || !m_parser) {
        return;
    }
    if (!m_parser->isValid() || !m_ui->m_hexViewer) {
        return;
    }

    const QByteArray &fileData = m_parser->getFileData();
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
        m_ui->m_hexViewer->setData(*useData, useData->size());
    }
}

void AnalysisDisplayController::phaseStringsTab()
{
    if (!m_fileLoaded || !m_ui || !m_parser) {
        return;
    }

    if (m_strings) {
        m_strings->populateSectionCombo();
    }

    if (m_ui->m_analysisTabWidget && m_onAnalysisTabChanged) {
        m_onAnalysisTabChanged(m_ui->m_analysisTabWidget->currentIndex());
    }
}
