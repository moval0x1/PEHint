#include "section_layout_widget.h"

#include <QPainter>
#include <QFont>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QHash>
#include <QToolTip>

namespace {

QString sectionDisplayName(const IMAGE_SECTION_HEADER *section)
{
    if (!section) {
        return QStringLiteral("?");
    }
    int len = 0;
    while (len < 8 && section->Name[len] != '\0') {
        ++len;
    }
    return QString::fromLatin1(reinterpret_cast<const char *>(section->Name), len).trimmed();
}

QColor colorForSectionName(const QString &name)
{
    static const QHash<QString, QColor> kNamed = {
        {QStringLiteral(".text"), QColor(59, 130, 246)},
        {QStringLiteral(".rdata"), QColor(16, 185, 129)},
        {QStringLiteral(".data"), QColor(245, 158, 11)},
        {QStringLiteral(".rsrc"), QColor(168, 85, 247)},
        {QStringLiteral(".reloc"), QColor(107, 114, 128)},
        {QStringLiteral(".pdata"), QColor(236, 72, 153)},
    };
    const QColor named = kNamed.value(name);
    if (named.isValid()) {
        return named;
    }
    const uint hash = qHash(name);
    return QColor(static_cast<int>(hash % 156) + 80, static_cast<int>((hash >> 8) % 120) + 80,
                  static_cast<int>((hash >> 16) % 120) + 80);
}

} // namespace

SectionLayoutWidget::SectionLayoutWidget(QWidget *parent)
    : QWidget(parent)
{
    setFixedHeight(54);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setMouseTracking(true);
    setToolTip(QStringLiteral("Each colored segment is a PE section; width is proportional to virtual size."));
}

void SectionLayoutWidget::setSections(const QList<const IMAGE_SECTION_HEADER *> &sections, quint32 imageSize)
{
    m_sections = sections;
    m_mapSize = 0;
    for (const IMAGE_SECTION_HEADER *section : sections) {
        if (!section) {
            continue;
        }
        const quint32 virtualSize = qMax(section->Misc.VirtualSize, section->SizeOfRawData);
        if (virtualSize == 0) {
            continue;
        }
        m_mapSize = qMax(m_mapSize, section->VirtualAddress + virtualSize);
    }
    if (m_mapSize == 0) {
        m_mapSize = imageSize;
    }
    m_hits.clear();
    update();
}

void SectionLayoutWidget::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRect area = rect().adjusted(4, 2, -4, -2);
    painter.fillRect(area, QColor(248, 250, 252));
    painter.setPen(QColor(226, 232, 240));
    painter.drawRoundedRect(area, 3, 3);

    if (m_sections.isEmpty() || m_mapSize == 0) {
        painter.setPen(QColor(148, 163, 184));
        painter.setFont(QFont(QStringLiteral("Segoe UI"), 9));
        painter.drawText(area, Qt::AlignCenter, QStringLiteral("Section layout"));
        return;
    }

    const QRect track = QRect(area.left() + 4, area.top() + 4, area.width() - 8, 18);
    const QRect legendArea(area.left() + 4, track.bottom() + 4, area.width() - 8, area.bottom() - track.bottom() - 4);

    painter.fillRect(track, QColor(241, 245, 249));
    painter.setPen(QColor(203, 213, 225));
    painter.drawRect(track);

    m_hits.clear();
    quint64 totalVirtual = 0;
    for (const IMAGE_SECTION_HEADER *section : m_sections) {
        if (!section) {
            continue;
        }
        totalVirtual += qMax(section->Misc.VirtualSize, section->SizeOfRawData);
    }

    for (const IMAGE_SECTION_HEADER *section : m_sections) {
        if (!section) {
            continue;
        }
        const quint32 virtualSize = qMax(section->Misc.VirtualSize, section->SizeOfRawData);
        if (virtualSize == 0) {
            continue;
        }
        const QString name = sectionDisplayName(section);
        const double startRatio = static_cast<double>(section->VirtualAddress) / static_cast<double>(m_mapSize);
        const double sizeRatio = static_cast<double>(virtualSize) / static_cast<double>(m_mapSize);
        const int x = track.left() + static_cast<int>(startRatio * track.width());
        const int w = qMax(2, static_cast<int>(sizeRatio * track.width()));
        const int clampedW = qMin(w, track.right() - x + 1);
        if (clampedW <= 0) {
            continue;
        }

        const QColor color = colorForSectionName(name);
        const QRect barRect(x, track.top(), clampedW, track.height());
        painter.fillRect(barRect, color);
        painter.setPen(color.darker(115));
        painter.drawRect(barRect);

        SectionHit hit;
        hit.name = name;
        hit.virtualAddress = section->VirtualAddress;
        hit.virtualSize = virtualSize;
        hit.sharePercent = totalVirtual > 0 ? (100.0 * virtualSize / static_cast<double>(totalVirtual)) : 0.0;
        hit.rect = barRect;
        hit.color = color;
        m_hits.append(hit);
    }

    QFont scaleFont(QStringLiteral("Segoe UI"), 7);
    painter.setFont(scaleFont);
    painter.setPen(QColor(100, 116, 139));
    painter.drawText(track.adjusted(0, -1, 0, 0), Qt::AlignLeft | Qt::AlignTop, QStringLiteral("0"));
    painter.drawText(track.adjusted(0, -1, 0, 0), Qt::AlignRight | Qt::AlignTop,
                     QStringLiteral("RVA 0x%1").arg(m_mapSize, 0, 16));

    int legendX = legendArea.left();
    const int legendY = legendArea.top();
    QFont legendFont(QStringLiteral("Segoe UI"), 8);
    painter.setFont(legendFont);
    const QFontMetrics fm(legendFont);

    for (const SectionHit &hit : m_hits) {
        const QString label =
            QStringLiteral("%1 %2%").arg(hit.name).arg(hit.sharePercent, 0, 'f', 0);
        const int chip = 8;
        const int textW = fm.horizontalAdvance(label);
        const int itemW = chip + 4 + textW + 10;
        if (legendX + itemW > legendArea.right()) {
            break;
        }

        painter.fillRect(legendX, legendY + 2, chip, chip, hit.color);
        painter.setPen(QColor(55, 65, 81));
        painter.drawText(legendX + chip + 4, legendY + fm.ascent() + 1, label);
        legendX += itemW;
    }

    if (legendX == legendArea.left() && !m_hits.isEmpty()) {
        painter.setPen(QColor(100, 116, 139));
        painter.drawText(legendArea, Qt::AlignLeft | Qt::AlignVCenter,
                         QStringLiteral("Hover a segment for RVA and size"));
    }
}

void SectionLayoutWidget::mouseMoveEvent(QMouseEvent *event)
{
    for (const SectionHit &hit : m_hits) {
        if (hit.rect.contains(event->pos())) {
            QToolTip::showText(
                event->globalPosition().toPoint(),
                QStringLiteral("%1 — RVA 0x%2, virtual size 0x%3 (%4%)")
                    .arg(hit.name)
                    .arg(hit.virtualAddress, 0, 16)
                    .arg(hit.virtualSize, 0, 16)
                    .arg(hit.sharePercent, 0, 'f', 1));
            return;
        }
    }
    QToolTip::hideText();
    QWidget::mouseMoveEvent(event);
}

void SectionLayoutWidget::leaveEvent(QEvent *event)
{
    QToolTip::hideText();
    QWidget::leaveEvent(event);
}
