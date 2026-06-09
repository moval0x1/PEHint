#ifndef SECTION_LAYOUT_WIDGET_H
#define SECTION_LAYOUT_WIDGET_H

#include "pe_structures.h"

#include <QList>
#include <QRect>
#include <QWidget>

class SectionLayoutWidget : public QWidget
{
public:
    explicit SectionLayoutWidget(QWidget *parent = nullptr);

    void setSections(const QList<const IMAGE_SECTION_HEADER *> &sections, quint32 imageSize);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    struct SectionHit {
        QString name;
        quint32 virtualAddress = 0;
        quint32 virtualSize = 0;
        double sharePercent = 0.0;
        QRect rect;
        QColor color;
    };

    QList<const IMAGE_SECTION_HEADER *> m_sections;
    quint32 m_mapSize = 0;
    QVector<SectionHit> m_hits;
};

#endif // SECTION_LAYOUT_WIDGET_H
