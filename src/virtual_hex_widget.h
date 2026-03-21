#ifndef VIRTUAL_HEX_WIDGET_H
#define VIRTUAL_HEX_WIDGET_H

#include <QAbstractScrollArea>
#include <QByteArray>
#include <QColor>
#include <QList>

/**
 * Virtualized hex dump: paints only visible rows (010-style), no QTextDocument.
 */
class VirtualHexWidget : public QAbstractScrollArea
{
    Q_OBJECT

public:
    struct HighlightSeg {
        qint64 start = 0;
        qint64 length = 0;
        QColor color;
    };

    explicit VirtualHexWidget(QWidget *parent = nullptr);

    /** Non-owning pointer; must outlive setData calls or until clear(). */
    void setData(const QByteArray *data);
    void setBytesPerLine(int bpl);
    void setShowOffset(bool show);
    void setShowAscii(bool show);
    void setHeaderLabels(const QString &offsetColumnTitle, const QString &asciiColumnTitle);

    void setHighlights(const QList<HighlightSeg> &segments);
    void clearHighlights();

    void scrollToByteOffset(qint64 offset, bool centerVertically = false);

    qint64 selectionStart() const { return m_selStart; }
    qint64 selectionEnd() const { return m_selEnd; } // inclusive
    bool hasSelection() const { return m_hasSelection; }
    void clearSelection();

    QString hexClipboardText(qint64 start, qint64 endInclusive) const;
    QString asciiClipboardText(qint64 start, qint64 endInclusive) const;

    qint64 byteCount() const;

signals:
    void selectionChanged();
    void byteClicked(qint64 offset, int length);

protected:
    bool viewportEvent(QEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void focusInEvent(QFocusEvent *event) override;
    void focusOutEvent(QFocusEvent *event) override;

private:
    void updateGeometryMetrics();
    void updateScrollBars();
    void paintViewport(QPainter &p, const QRect &clip);

    int rowHeight() const;
    qint64 totalDataRows() const;
    int headerHeight() const;
    int gutterLeft() const;
    int hexColumnLeft() const;
    int asciiColumnLeft() const;
    int hexCellAdvance(int byteIndexInLine) const;
    int hexAreaWidth() const;

    qint64 byteAtViewportPos(const QPoint &vp, bool *inHexPane = nullptr) const;
    void normalizeSelection();

    const QByteArray *m_data = nullptr;
    int m_bytesPerLine = 16;
    bool m_showOffset = true;
    bool m_showAscii = true;
    QString m_offsetHdr;
    QString m_asciiHdr;

    int m_rowHeight = 0;
    int m_charAdvance = 0; // monospace digit width ~
    /** Width reserved for offset column (header label vs 0xXXXXXXXX, whichever wider). */
    int m_offsetColumnWidth = 0;

    int m_scrollYPx = 0; // pixel scroll of data rows (not including frozen header)

    QList<HighlightSeg> m_highlights;

    bool m_dragging = false;
    qint64 m_anchorByte = 0;
    qint64 m_selStart = 0;
    qint64 m_selEnd = 0;
    bool m_hasSelection = false;
};

#endif
