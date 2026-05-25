#ifndef PE_TREE_INSIGHT_HELPERS_H
#define PE_TREE_INSIGHT_HELPERS_H

#include "pe_analysis.h"

#include <QByteArray>
#include <QString>
#include <QStringList>

namespace PeTreeInsight {

QString uiStringWithFallback(const QString &key, const QString &fallback);
QString formatHexPreview(const QByteArray &data, int maxBytes = 72);
QString peTreeSizeBytesText(const QString &sizeHexToken);
QString peTreeEntriesText(const QString &countToken);
QString formatCodeViewRawTreeValue(const PEPdbInfo &pdb);
QString formatEntryPointSummary(const PEFileMetrics &metrics);

bool isFileInsightJsonKey(const QString &jsonFieldKey);
QString insightMeaningText(const QString &jsonFieldKey);
QString insightExplanationHtml(const QString &jsonFieldKey);
QString fileInsightFieldLabel(const QString &fieldKey);

const QStringList &dataDirectoryFieldKeys();

quint32 readLe32(const uchar *p);
quint16 readLe16(const uchar *p);
quint64 readLe64(const uchar *p);

QString resourceTypeIdLabel(quint32 id);
bool findEmbeddedManifestRva(const QByteArray &data,
                            quint32 rootFo,
                            quint32 absEnd,
                            quint32 *outRva,
                            quint32 *outSize);

} // namespace PeTreeInsight

#endif // PE_TREE_INSIGHT_HELPERS_H
