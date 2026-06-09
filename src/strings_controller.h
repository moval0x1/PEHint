#ifndef STRINGS_CONTROLLER_H
#define STRINGS_CONTROLLER_H

#include "pe_string_extractor.h"

#include <QFutureWatcher>
#include <QList>
#include <QObject>
#include <QString>

class PEParserNew;
class QTreeWidgetItem;
class UIManager;

class StringsController : public QObject
{
    Q_OBJECT

public:
    explicit StringsController(UIManager *ui, QObject *parent = nullptr);

    void setParser(PEParserNew *parser);
    void setFilePath(const QString &path);
    void setFileLoaded(bool loaded);

    void refresh();
    void clear();
    void invalidate();
    void stopExtractionSynchronously();
    void populateSectionCombo();
    void updateLanguageStrings();

    void handleFilterChanged(QObject *sender);
    void handleExtractionFinished();
    void handleCancelExtraction();
    void handleExport();
    void handleTreeItemDoubleClicked(QTreeWidgetItem *item, int column);

    bool isExtractionRunning() const { return m_stringsExtractionRunning; }

signals:
    void requestHexHighlight(quint32 offset, quint32 size);
    void statusMessageRequested(const QString &message, int timeoutMs);
    void errorOccurred(const QString &title, const QString &message);

private:
    void applyFilter();
    void populate();

    UIManager *m_ui = nullptr;
    PEParserNew *m_parser = nullptr;
    QString m_filePath;
    bool m_fileLoaded = false;
    QList<ExtractedString> m_extractedStrings;
    QFutureWatcher<StringExtractionResult> m_stringsExtractionWatcher;
    bool m_stringsExtractionRunning = false;
    bool m_stringsPopulated = false;
};

#endif // STRINGS_CONTROLLER_H
