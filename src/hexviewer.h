#ifndef HEXVIEWER_H
#define HEXVIEWER_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QSpinBox>
#include <QByteArray>
#include <QFont>
#include <QVector>

class VirtualHexWidget;

class HexViewer : public QWidget
{
    Q_OBJECT

public:
    explicit HexViewer(QWidget *parent = nullptr);
    ~HexViewer();

    void setData(const QByteArray &data, qint64 logicalTotalBytes = -1);
    void clear();
    void goToOffset(qint64 offset);

    void setBytesPerLine(int bytesPerLine);
    void setShowAscii(bool show);
    void setShowOffset(bool show);

    void highlightRange(quint32 startOffset, quint32 length, const QColor &color = QColor(255, 255, 0, 100));
    void clearHighlights();

    struct SearchResult {
        qint64 offset;
        qint64 length;
        QByteArray pattern;
    };

    void findHexPattern(const QString &pattern, bool caseSensitive = false);
    /** Search raw file bytes for UTF-8 encoded @p text (checkbox "Hex only" off). */
    void findTextPattern(const QString &text, bool caseSensitive = false);
    void findNext();
    void findPrevious();
    void clearSearchResults(bool rebuildHex = true);

    bool hasData() const { return !m_data.isEmpty(); }
    qint64 getDataSize() const { return m_data.size(); }
    qint64 logicalDataSize() const;
    bool showOffset() const { return m_showOffset; }
    bool showAscii() const { return m_showAscii; }
    int bytesPerLine() const { return m_bytesPerLine; }
    /** Kept for API compatibility; virtual hex is always synchronous. */
    bool isHexDocumentBuildInProgress() const { return false; }

    void updateLanguage();

signals:
    void byteClicked(qint64 offset, int length);
    void hexContentReady();

protected:
    void focusInEvent(QFocusEvent *event) override;
    void focusOutEvent(QFocusEvent *event) override;

private slots:
    void onOffsetChanged(int value);
    void onBytesPerLineChanged(int value);
    void onShowAsciiToggled(bool checked);
    void onShowOffsetToggled(bool checked);
    void onCopyHexSelection();
    void onCopyAsciiSelection();
    void onFindText();
    void updateSelectionOffsetStatus();

private:
    void setupUI();
    void setupConnections();
    void applyHexFont();
    void updateDisplay();
    void syncHighlightsToWidget();

    QByteArray m_data;
    qint64 m_logicalDataSize = -1;

    VirtualHexWidget *m_virtualHex = nullptr;

    QSpinBox *m_offsetSpinBox = nullptr;
    QSpinBox *m_bytesPerLineSpinBox = nullptr;
    QPushButton *m_showAsciiButton = nullptr;
    QPushButton *m_showOffsetButton = nullptr;
    QPushButton *m_copyHexButton = nullptr;
    QPushButton *m_copyAsciiButton = nullptr;
    QPushButton *m_findButton = nullptr;
    QPushButton *m_findNextButton = nullptr;
    QPushButton *m_findPrevButton = nullptr;
    QLabel *m_offsetLabel = nullptr;
    QLabel *m_bytesLabel = nullptr;
    QLabel *m_statusLabel = nullptr;

    bool m_showAscii = true;
    bool m_showOffset = true;
    int m_bytesPerLine = 16;

    struct HighlightRange {
        quint32 startOffset = 0;
        quint32 length = 0;
        QColor color;
    };
    QList<HighlightRange> m_highlights;

    QList<SearchResult> m_searchResults;
    int m_currentSearchIndex = -1;
    QByteArray m_lastSearchPattern;
    bool m_lastSearchCaseSensitive = false;

    QByteArray parseHexPattern(const QString &pattern);
    QList<SearchResult> findPatternInData(const QByteArray &pattern, bool caseSensitive);
    void highlightSearchResults();
    void goToSearchResult(int index);

    bool selectedFileByteRange(qint64 &start, qint64 &end) const;
    QString clipboardHexForRange(qint64 start, qint64 end) const;
    QString clipboardAsciiForRange(qint64 start, qint64 end) const;
};

#endif
