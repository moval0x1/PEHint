#ifndef PE_FINDINGS_H
#define PE_FINDINGS_H

#include "pe_data_model.h"

#include <QString>
#include <QVector>
#include <functional>

enum class PEFindingSeverity {
    Info,
    Low,
    Medium,
    High
};

struct PEFindingRule {
    QString id;
    QString check;
    PEFindingSeverity severity = PEFindingSeverity::Medium;
    QString titleKey;
    QString detailKey;
    QString treeField;
    bool enabled = true;
    double threshold = 7.0;
    int maxImports = 3;
};

struct PEFindingInstance {
    QString ruleId;
    PEFindingSeverity severity = PEFindingSeverity::Medium;
    QString title;
    QString detail;
    QString treeField;
    quint32 hexOffset = 0;
    quint32 hexSize = 0;
    bool hasHexNav = false;
};

class PEFindingsEngine
{
public:
    static bool loadRules(QString *errorOut = nullptr);
    static const QVector<PEFindingRule> &rules();

    static QVector<PEFindingInstance> evaluate(
        const PEDataModel &model,
        const std::function<quint32(quint32)> &rvaToFileOffset);

    static QString severityDisplayName(PEFindingSeverity severity);
};

#endif // PE_FINDINGS_H
