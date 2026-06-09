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
    QString category;
    bool enabled = true;
    double threshold = 7.0;
    int maxImports = 3;
    int minCount = 5;
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
    bool isPass = false;
    QString category;
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
    static QString categoryDisplayName(const QString &categoryKey);
    static QString categoryKeyForRule(const PEFindingRule &rule);
    static QVector<PEFindingInstance> evaluateHardeningPasses(const PEDataModel &model);

    /** True when @p functionName matches an entry in config/import_flags.json (optional @p moduleName). */
    static bool isFlaggedImport(const QString &moduleName, const QString &functionName,
                                PEFindingSeverity *severityOut = nullptr, QString *noteOut = nullptr);
};

#endif // PE_FINDINGS_H
