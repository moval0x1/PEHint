#ifndef PE_REPORT_BUILDER_H
#define PE_REPORT_BUILDER_H

#include <QtGlobal>

class PEDataModel;
class QString;

class PEReportBuilder
{
public:
    static QString buildTextReport(const PEDataModel &dataModel);
    static QString buildHtmlReport(const PEDataModel &dataModel);
    static QString buildJsonReport(const PEDataModel &dataModel);
    static QString buildXmlReport(const PEDataModel &dataModel);

private:
    static QString escapeXml(const QString &str);
    static QString formatFileSize(qint64 size);
};

#endif // PE_REPORT_BUILDER_H
