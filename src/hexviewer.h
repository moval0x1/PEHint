#ifndef HEXVIEWER_H
#define HEXVIEWER_H

#include <QWidget>
#include <QTextEdit>
#include <QScrollBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QSpinBox>
#include <QByteArray>
#include <QFont>

class HexViewer : public QWidget
{
    Q_OBJECT

public:
    explicit HexViewer(QWidget *parent = nullptr);
    ~HexViewer();

    // Data management
    void setData(const QByteArray &data);
    void clear();
    void goToOffset(qint64 offset);
    
    // Display options
    void setBytesPerLine(int bytesPerLine);
    void setShowAscii(bool show);
    void setShowOffset(bool show);
    
    // Highlighting
    void highlightRange(quint32 startOffset, quint32 length, const QColor &color = QColor(255, 255, 0, 100));
    void clearHighlights();
    
    // Search functionality
    struct SearchResult {
        qint64 offset;
        qint64 length;
        QByteArray pattern;
    };
    
    void findHexPattern(const QString &pattern, bool caseSensitive = false);
    void findNext();
    void findPrevious();
    void clearSearchResults();
    
    // Getters
    bool hasData() const { return !m_data.isEmpty(); }
    qint64 getDataSize() const { return m_data.size(); }
    bool showOffset() const { return m_showOffset; }
    bool showAscii() const { return m_showAscii; }
    int bytesPerLine() const { return m_bytesPerLine; }

signals:
    void byteClicked(qint64 offset, int length);

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;
    void focusInEvent(QFocusEvent *event) override;
    void focusOutEvent(QFocusEvent *event) override;

private slots:
    void onOffsetChanged(int value);
    void onBytesPerLineChanged(int value);
    void onShowAsciiToggled(bool checked);
    void onShowOffsetToggled(bool checked);
    void onCopySelection();
    void onFindText();
    void onHexTextClicked();

private:
    // Data
    QByteArray m_data;
    
    // UI Components
    QTextEdit *m_hexText;
    QScrollBar *m_verticalScrollBar;
    QScrollBar *m_horizontalScrollBar;
    
    // Controls
    QSpinBox *m_offsetSpinBox;
    QSpinBox *m_bytesPerLineSpinBox;
    QPushButton *m_showAsciiButton;
    QPushButton *m_showOffsetButton;
    QPushButton *m_copyButton;
    QPushButton *m_findButton;
    QPushButton *m_findNextButton;
    QPushButton *m_findPrevButton;
    
    // Display options
    bool m_showAscii;
    bool m_showOffset;
    int m_bytesPerLine;
    
    // Highlighting
    struct HighlightRange {
        quint32 startOffset;
        quint32 length;
        QColor color;
    };
    QList<HighlightRange> m_highlights;
    
    // Search functionality
    QList<SearchResult> m_searchResults;
    int m_currentSearchIndex;
    QByteArray m_lastSearchPattern;
    bool m_lastSearchCaseSensitive;
    
    // Methods
    void setupUI();
    void setupConnections();
    void updateDisplay();
    void renderHexData();
    QString formatHexLine(const QByteArray &lineData, qint64 offset);
    QString formatAsciiLine(const QByteArray &lineData);
    QString formatOffset(qint64 offset);
    void applyHighlights();
    
    // Search methods
    QByteArray parseHexPattern(const QString &pattern);
    QList<SearchResult> findPatternInData(const QByteArray &pattern, bool caseSensitive);
    void highlightSearchResults();
    void goToSearchResult(int index);
    
    // Utility
    QByteArray getLineData(qint64 offset, int maxBytes);
    void highlightOffset(qint64 offset);
    qint64 calculateOffsetFromPosition(const QPoint &pos);
};

#endif // HEXVIEWER_H
