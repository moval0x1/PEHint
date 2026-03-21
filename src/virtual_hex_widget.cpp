#include "virtual_hex_widget.h"

#include <QApplication>
#include <QClipboard>
#include <QEvent>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QPainter>
#include <QResizeEvent>
#include <QScrollBar>
#include <QWheelEvent>
#include <QtMath>

namespace {
constexpr int kGutter = 6;
const QColor kOffsetAccent(0, 120, 215);
}

VirtualHexWidget::VirtualHexWidget(QWidget *parent)
    : QAbstractScrollArea(parent)
{
    setFocusPolicy(Qt::StrongFocus);
    setFocusProxy(viewport());
    viewport()->setMouseTracking(true);
    viewport()->setFocusPolicy(Qt::StrongFocus);
    viewport()->setBackgroundRole(QPalette::Base);
    horizontalScrollBar()->setVisible(false);
    viewport()->installEventFilter(this);

    connect(verticalScrollBar(), &QAbstractSlider::valueChanged, this, [this](int v) {
        m_scrollYPx = v;
        viewport()->update();
    });
}

void VirtualHexWidget::setData(const QByteArray *data)
{
    m_data = data;
    m_scrollYPx = 0;
    clearSelection();
    updateGeometryMetrics();
    updateScrollBars();
    verticalScrollBar()->setValue(0);
    viewport()->update();
}

void VirtualHexWidget::setBytesPerLine(int bpl)
{
    m_bytesPerLine = qBound(8, bpl, 64);
    updateGeometryMetrics();
    updateScrollBars();
    viewport()->update();
}

void VirtualHexWidget::setShowOffset(bool show)
{
    m_showOffset = show;
    updateGeometryMetrics();
    viewport()->update();
}

void VirtualHexWidget::setShowAscii(bool show)
{
    m_showAscii = show;
    updateGeometryMetrics();
    viewport()->update();
}

void VirtualHexWidget::setHeaderLabels(const QString &offsetColumnTitle, const QString &asciiColumnTitle)
{
    m_offsetHdr = offsetColumnTitle;
    m_asciiHdr = asciiColumnTitle;
    viewport()->update();
}

void VirtualHexWidget::setHighlights(const QList<HighlightSeg> &segments)
{
    m_highlights = segments;
    viewport()->update();
}

void VirtualHexWidget::clearHighlights()
{
    m_highlights.clear();
    viewport()->update();
}

qint64 VirtualHexWidget::byteCount() const
{
    return m_data ? static_cast<qint64>(m_data->size()) : 0LL;
}

int VirtualHexWidget::rowHeight() const
{
    return qMax(1, m_rowHeight);
}

int VirtualHexWidget::headerHeight() const
{
    return rowHeight();
}

qint64 VirtualHexWidget::totalDataRows() const
{
    const qint64 n = byteCount();
    if (n <= 0) {
        return 0;
    }
    const int bpl = qMax(1, m_bytesPerLine);
    return (n + bpl - 1) / bpl;
}

void VirtualHexWidget::updateGeometryMetrics()
{
    const QFontMetrics fm(font());
    m_rowHeight = fm.lineSpacing() + 2;
    m_charAdvance = qMax(1, fm.horizontalAdvance(QLatin1Char('0')));
    m_offsetColumnWidth = 0;
    if (m_showOffset) {
        // Same format as painted offsets: "0x" + 8 hex digits (no phantom spaces).
        const int addrW = fm.horizontalAdvance(QStringLiteral("0x00000000"));
        const QString lbl = m_offsetHdr.isEmpty() ? QStringLiteral("Offset") : m_offsetHdr;
        const int labelW = fm.horizontalAdvance(lbl);
        m_offsetColumnWidth = qMax(addrW, labelW);
        // Breathing room before hex column (replaces old hard-coded template trailing spaces).
        m_offsetColumnWidth += fm.horizontalAdvance(QStringLiteral("  "));
    }
}

int VirtualHexWidget::gutterLeft() const
{
    return kGutter;
}

int VirtualHexWidget::hexAreaWidth() const
{
    const int bpl = qMax(1, m_bytesPerLine);
    int w = 0;
    for (int i = 0; i < bpl; ++i) {
        w += 3 * m_charAdvance;
        if ((i + 1) % 8 == 0 && i < bpl - 1) {
            w += m_charAdvance;
        }
    }
    return w;
}

int VirtualHexWidget::hexColumnLeft() const
{
    return gutterLeft() + (m_showOffset ? m_offsetColumnWidth : 0);
}

int VirtualHexWidget::asciiColumnLeft() const
{
    if (!m_showAscii) {
        return hexColumnLeft() + hexAreaWidth();
    }
    QFontMetrics fm(font());
    return hexColumnLeft() + hexAreaWidth() + fm.horizontalAdvance(QStringLiteral("  "));
}

void VirtualHexWidget::updateScrollBars()
{
    const int hh = headerHeight();
    const int vh = viewport()->height();
    const qint64 rows = totalDataRows();
    const int rh = rowHeight();
    const int dataPx = static_cast<int>(rows * rh);
    const int visibleData = qMax(0, vh - hh);
    const int maxScroll = qMax(0, dataPx - visibleData);

    QSignalBlocker block(verticalScrollBar());
    verticalScrollBar()->setRange(0, maxScroll);
    verticalScrollBar()->setSingleStep(rh);
    verticalScrollBar()->setPageStep(qMax(rh, visibleData));
    if (m_scrollYPx > maxScroll) {
        m_scrollYPx = maxScroll;
    }
    verticalScrollBar()->setValue(m_scrollYPx);
}

void VirtualHexWidget::scrollToByteOffset(qint64 offset, bool centerVertically)
{
    if (!m_data || m_data->isEmpty() || offset < 0) {
        return;
    }
    const qint64 n = byteCount();
    if (offset >= n) {
        offset = n - 1;
    }
    const int bpl = qMax(1, m_bytesPerLine);
    const qint64 row = offset / bpl;
    const int rh = rowHeight();
    const int hh = headerHeight();
    const int vh = viewport()->height();
    const int visibleData = qMax(0, vh - hh);
    int target = static_cast<int>(row * rh);
    if (centerVertically) {
        target = static_cast<int>(target - visibleData / 2 + rh / 2);
    }
    target = qBound(0, target, verticalScrollBar()->maximum());
    verticalScrollBar()->setValue(target);
}

void VirtualHexWidget::clearSelection()
{
    m_hasSelection = false;
    m_dragging = false;
    m_selStart = m_selEnd = 0;
    viewport()->update();
    emit selectionChanged();
}

void VirtualHexWidget::normalizeSelection()
{
    if (m_selStart > m_selEnd) {
        const qint64 t = m_selStart;
        m_selStart = m_selEnd;
        m_selEnd = t;
    }
}

QString VirtualHexWidget::hexClipboardText(qint64 start, qint64 endInclusive) const
{
    if (!m_data || start < 0 || endInclusive < start) {
        return {};
    }
    const qint64 n = byteCount();
    endInclusive = qMin(endInclusive, n - 1);
    const int len = static_cast<int>(endInclusive - start + 1);
    const QByteArray slice = m_data->mid(static_cast<int>(start), len);
    QString out;
    out.reserve(slice.size() * 3);
    for (int i = 0; i < slice.size(); ++i) {
        if (i > 0) {
            out += QLatin1Char(' ');
        }
        out += QStringLiteral("%1").arg(static_cast<quint8>(slice[i]), 2, 16, QLatin1Char('0')).toUpper();
    }
    return out;
}

QString VirtualHexWidget::asciiClipboardText(qint64 start, qint64 endInclusive) const
{
    if (!m_data || start < 0 || endInclusive < start) {
        return {};
    }
    const qint64 n = byteCount();
    endInclusive = qMin(endInclusive, n - 1);
    const int len = static_cast<int>(endInclusive - start + 1);
    const QByteArray slice = m_data->mid(static_cast<int>(start), len);
    QString out;
    out.reserve(slice.size());
    for (unsigned char uc : slice) {
        if (uc >= 32 && uc <= 126) {
            out += QLatin1Char(static_cast<char>(uc));
        } else {
            out += QLatin1Char('.');
        }
    }
    return out;
}

static QColor highlightAt(const QList<VirtualHexWidget::HighlightSeg> &segs, qint64 off)
{
    for (const VirtualHexWidget::HighlightSeg &s : segs) {
        if (off >= s.start && off < s.start + s.length) {
            return s.color;
        }
    }
    return QColor();
}

void VirtualHexWidget::paintViewport(QPainter &p, const QRect &clip)
{
    p.fillRect(clip, palette().base());
    if (!m_data || m_data->isEmpty()) {
        return;
    }

    const int hh = headerHeight();
    const int rh = rowHeight();
    const int bpl = qMax(1, m_bytesPerLine);
    const qint64 n = byteCount();
    QFontMetrics fm(p.font());

    // --- header ---
    p.setPen(kOffsetAccent);
    int x = gutterLeft();
    if (m_showOffset) {
        const QString offLabel = m_offsetHdr.isEmpty() ? QStringLiteral("Offset") : m_offsetHdr;
        p.drawText(x, fm.ascent() + 1, offLabel);
    }
    x = hexColumnLeft();
    for (int i = 0; i < bpl; ++i) {
        p.drawText(x, fm.ascent() + 1, QStringLiteral("%1").arg(i, 2, 16, QLatin1Char('0')).toUpper());
        x += 3 * m_charAdvance;
        if ((i + 1) % 8 == 0 && i < bpl - 1) {
            x += m_charAdvance;
        }
    }
    if (m_showAscii) {
        x = asciiColumnLeft();
        const QString asc = m_asciiHdr.isEmpty() ? QStringLiteral("Decoded") : m_asciiHdr;
        p.drawText(x, fm.ascent() + 1, asc);
    }

    p.setPen(palette().color(QPalette::Text));

    const int topDataY = hh;
    const int firstRow = m_scrollYPx / rh;
    const int ySkip = m_scrollYPx % rh;
    int y = topDataY - ySkip;

    for (qint64 row = firstRow; y < viewport()->height() && row * bpl < n; ++row) {
        const QRect rowRect(0, y, viewport()->width(), rh);
        if (!rowRect.intersects(clip)) {
            y += rh;
            continue;
        }

        const qint64 lineStart = row * bpl;
        const int count = static_cast<int>(qMin<qint64>(bpl, n - lineStart));

        // Offset column
        if (m_showOffset) {
            const QString off = QStringLiteral("0x%1")
                                    .arg(QString::number(static_cast<quint64>(lineStart), 16).toUpper()
                                             .rightJustified(8, QLatin1Char('0')));
            p.setPen(kOffsetAccent);
            p.drawText(gutterLeft(), y + fm.ascent() + 1, off);
            p.setPen(palette().color(QPalette::Text));
        }

        // Hex + ASCII
        x = hexColumnLeft();
        for (int i = 0; i < count; ++i) {
            const qint64 absOff = lineStart + i;
            const quint8 byte = static_cast<quint8>((*m_data)[static_cast<int>(absOff)]);

            const int cellW = 3 * m_charAdvance;
            const QRect hexCell(x, y, cellW, rh);
            const QColor hi = highlightAt(m_highlights, absOff);
            if (m_hasSelection && absOff >= qMin(m_selStart, m_selEnd) && absOff <= qMax(m_selStart, m_selEnd)) {
                p.fillRect(hexCell, palette().color(QPalette::Highlight));
            } else if (hi.isValid()) {
                p.fillRect(hexCell, hi);
            }

            const QString hx = QStringLiteral("%1 ").arg(byte, 2, 16, QLatin1Char('0')).toUpper();
            p.drawText(x, y + fm.ascent() + 1, hx);
            x += cellW;
            if ((i + 1) % 8 == 0 && i < count - 1) {
                x += m_charAdvance;
            }
        }

        if (m_showAscii) {
            x = asciiColumnLeft();
            for (int i = 0; i < count; ++i) {
                const qint64 absOff = lineStart + i;
                const char c = (*m_data)[static_cast<int>(absOff)];
                const int cw = m_charAdvance;
                const QRect ac(x, y, cw, rh);
                const QColor hi = highlightAt(m_highlights, absOff);
                if (m_hasSelection && absOff >= qMin(m_selStart, m_selEnd) && absOff <= qMax(m_selStart, m_selEnd)) {
                    p.fillRect(ac, palette().color(QPalette::Highlight));
                } else if (hi.isValid()) {
                    p.fillRect(ac, hi);
                }
                const QString ch = (c >= 32 && c <= 126) ? QString(QLatin1Char(c)) : QStringLiteral(".");
                p.drawText(x, y + fm.ascent() + 1, ch);
                x += cw;
            }
        }

        y += rh;
    }
}

bool VirtualHexWidget::viewportEvent(QEvent *event)
{
    if (event->type() == QEvent::Paint) {
        QPaintEvent *pe = static_cast<QPaintEvent *>(event);
        QPainter p(viewport());
        paintViewport(p, pe->rect());
        return true;
    }
    return QAbstractScrollArea::viewportEvent(event);
}

void VirtualHexWidget::resizeEvent(QResizeEvent *event)
{
    QAbstractScrollArea::resizeEvent(event);
    updateScrollBars();
}

qint64 VirtualHexWidget::byteAtViewportPos(const QPoint &vp, bool *inHexPane) const
{
    if (inHexPane) {
        *inHexPane = false;
    }
    if (!m_data || m_data->isEmpty()) {
        return -1;
    }
    const int hh = headerHeight();
    if (vp.y() < hh) {
        return -1;
    }
    const int rh = rowHeight();
    const int bpl = qMax(1, m_bytesPerLine);
    const qint64 n = byteCount();

    const int relY = vp.y() - hh + m_scrollYPx;
    if (relY < 0) {
        return -1;
    }
    const qint64 row = relY / rh;
    const qint64 lineStart = row * bpl;
    if (lineStart >= n) {
        return -1;
    }

    const int hxLeft = hexColumnLeft();
    const int hxRight = m_showAscii ? asciiColumnLeft() : (hexColumnLeft() + hexAreaWidth());

    if (vp.x() >= hxLeft && vp.x() < hxRight) {
        if (inHexPane) {
            *inHexPane = true;
        }
        int x = hxLeft;
        const int count = static_cast<int>(qMin<qint64>(bpl, n - lineStart));
        for (int i = 0; i < count; ++i) {
            const int cellW = 3 * m_charAdvance;
            if (vp.x() >= x && vp.x() < x + cellW) {
                return lineStart + i;
            }
            x += cellW;
            if ((i + 1) % 8 == 0 && i < count - 1) {
                x += m_charAdvance;
            }
        }
        return lineStart;
    }

    if (m_showAscii) {
        int x = asciiColumnLeft();
        const int count = static_cast<int>(qMin<qint64>(bpl, n - lineStart));
        for (int i = 0; i < count; ++i) {
            if (vp.x() >= x && vp.x() < x + m_charAdvance) {
                return lineStart + i;
            }
            x += m_charAdvance;
        }
    }

    if (m_showOffset && vp.x() < hexColumnLeft()) {
        return lineStart;
    }

    return -1;
}

bool VirtualHexWidget::eventFilter(QObject *watched, QEvent *event)
{
    if (watched != viewport()) {
        return QAbstractScrollArea::eventFilter(watched, event);
    }

    switch (event->type()) {
    case QEvent::MouseButtonPress: {
        auto *me = static_cast<QMouseEvent *>(event);
        if (me->button() == Qt::LeftButton && m_data && !m_data->isEmpty()) {
            const qint64 off = byteAtViewportPos(me->position().toPoint());
            if (off >= 0) {
                m_dragging = true;
                m_anchorByte = off;
                m_selStart = m_selEnd = off;
                m_hasSelection = true;
                viewport()->update();
                emit selectionChanged();
                emit byteClicked(off, 1);
            }
            return true;
        }
        break;
    }
    case QEvent::MouseMove: {
        auto *me = static_cast<QMouseEvent *>(event);
        if (m_dragging && m_data && !m_data->isEmpty()) {
            const qint64 off = byteAtViewportPos(me->position().toPoint());
            if (off >= 0) {
                m_selStart = m_anchorByte;
                m_selEnd = off;
                m_hasSelection = true;
                viewport()->update();
                emit selectionChanged();
            }
            return true;
        }
        break;
    }
    case QEvent::MouseButtonRelease: {
        auto *me = static_cast<QMouseEvent *>(event);
        if (me->button() == Qt::LeftButton && m_dragging) {
            m_dragging = false;
            normalizeSelection();
            viewport()->update();
            emit selectionChanged();
            return true;
        }
        break;
    }
    case QEvent::Wheel: {
        auto *we = static_cast<QWheelEvent *>(event);
        int delta = we->angleDelta().y();
        if (delta == 0) {
            delta = we->angleDelta().x();
        }
        verticalScrollBar()->setValue(verticalScrollBar()->value() - delta);
        return true;
    }
    case QEvent::KeyPress: {
        auto *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_C && (ke->modifiers() & Qt::ControlModifier)
            && (ke->modifiers() & Qt::ShiftModifier)) {
            if (m_hasSelection && m_data) {
                normalizeSelection();
                QApplication::clipboard()->setText(asciiClipboardText(m_selStart, m_selEnd));
            }
            return true;
        }
        if (ke->matches(QKeySequence::Copy)) {
            if (m_hasSelection && m_data) {
                normalizeSelection();
                QApplication::clipboard()->setText(hexClipboardText(m_selStart, m_selEnd));
            }
            return true;
        }
        break;
    }
    default:
        break;
    }
    return false;
}

void VirtualHexWidget::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_C && (event->modifiers() & Qt::ControlModifier)
        && (event->modifiers() & Qt::ShiftModifier)) {
        if (m_hasSelection && m_data) {
            normalizeSelection();
            QApplication::clipboard()->setText(asciiClipboardText(m_selStart, m_selEnd));
        }
        event->accept();
        return;
    }
    if (event->matches(QKeySequence::Copy)) {
        if (m_hasSelection && m_data) {
            normalizeSelection();
            QApplication::clipboard()->setText(hexClipboardText(m_selStart, m_selEnd));
        }
        event->accept();
        return;
    }
    QAbstractScrollArea::keyPressEvent(event);
}

void VirtualHexWidget::focusInEvent(QFocusEvent *event)
{
    QAbstractScrollArea::focusInEvent(event);
    viewport()->update();
}

void VirtualHexWidget::focusOutEvent(QFocusEvent *event)
{
    QAbstractScrollArea::focusOutEvent(event);
    viewport()->update();
}
