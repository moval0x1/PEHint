#ifndef PE_FILE_INSIGHTS_H
#define PE_FILE_INSIGHTS_H

#include "pe_data_model.h"

#include <QByteArray>
#include <QString>

namespace PEFileInsights {

QString buildInsightExplanationHtml(const QString &fieldKey,
                                    const PEDataModel &model,
                                    const QByteArray &fileData,
                                    qint64 fileSizeOnDisk);

QString relatedStructureFieldForInsight(const QString &fieldKey);

bool fileInsightHasHexTarget(const QString &fieldKey, const PEDataModel &model);

} // namespace PEFileInsights

#endif // PE_FILE_INSIGHTS_H
