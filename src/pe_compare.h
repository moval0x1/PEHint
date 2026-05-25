#ifndef PE_COMPARE_H
#define PE_COMPARE_H

#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>

class PEDataModel;

namespace PECompare {

struct FieldDiff {
    QString name;
    QString valueA;
    QString valueB;
};

struct SectionDiff {
    QString name;
    bool onlyInA = false;
    bool onlyInB = false;
    QList<FieldDiff> fields;
    double entropyA = -1.0; ///< -1 if not computed
    double entropyB = -1.0;
};

struct ModuleDiff {
    QString moduleName;
    QStringList onlyInA;
    QStringList onlyInB;
};

struct Result {
    QString filePathA;
    QString filePathB;

    QList<FieldDiff> headerFields;
    QList<SectionDiff> sections;
    QList<ModuleDiff> imports;
    QStringList exportsOnlyInA;
    QStringList exportsOnlyInB;
    QStringList findingsOnlyInA;
    QStringList findingsOnlyInB;
    QMap<QString, QString> findingTitles; ///< ruleId → human-readable title

    QList<FieldDiff> versionFields;
    QList<FieldDiff> pdbFields;
    QList<FieldDiff> tlsFields;
    QList<FieldDiff> resourceFields;
    QList<FieldDiff> signatureFields;

    int totalDifferences() const;
};

Result compare(const PEDataModel &a, const PEDataModel &b,
               const QString &pathA = QString(), const QString &pathB = QString());

/** Render the result as an HTML string suitable for QTextBrowser. */
QString toHtml(const Result &result);

} // namespace PECompare

#endif // PE_COMPARE_H
