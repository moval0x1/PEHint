#ifndef PE_RESOURCE_PREVIEW_H
#define PE_RESOURCE_PREVIEW_H

#include "pe_analysis.h"

#include <QImage>
#include <QString>

struct ResourcePreview {
    enum class Kind {
        Empty,
        Text,
        Html,
        Image,
        Hex
    };

    Kind kind = Kind::Empty;
    QString title;
    QString textContent;
    QString htmlContent;
    QImage image;
    QString hexPreview;
};

ResourcePreview buildResourcePreview(const QByteArray &fileData, const PEResourceItem &item);

#endif // PE_RESOURCE_PREVIEW_H
