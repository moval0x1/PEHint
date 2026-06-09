#ifndef PE_RESOURCE_PREVIEW_H
#define PE_RESOURCE_PREVIEW_H

#include "pe_analysis.h"

#include <QImage>
#include <QString>
#include <QVector>

struct ResourcePreviewImageEntry {
    QImage image;
    QString label;
};

struct ResourcePreview {
    enum class Kind {
        Empty,
        Text,
        Html,
        Image,
        ImageGallery,
        Hex
    };

    Kind kind = Kind::Empty;
    QString title;
    QString textContent;
    QString htmlContent;
    QImage image;
    QVector<ResourcePreviewImageEntry> images;
    QString hexPreview;
};

ResourcePreview buildResourcePreview(const QByteArray &fileData,
                                     const PEResourceItem &item,
                                     const QVector<PEResourceItem> &allItems = {});

#endif // PE_RESOURCE_PREVIEW_H
