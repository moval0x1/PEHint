#ifndef PE_COMPARE_H
#define PE_COMPARE_H

#include <QString>
#include <QStringList>
#include <QList>

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
};

struct ModuleDiff {
    QString moduleName;
    QStringList onlyInA;
    QStringList onlyInB;
};

struct Result {
    QString filePathA;
    QString filePathB;

    QList<FieldDiff> headerFields;   // DOS + File + Optional header
    QList<SectionDiff> sections;
    QList<ModuleDiff> imports;
    QStringList findingsOnlyInA;
    QStringList findingsOnlyInB;
    QStringList exportsOnlyInA;
    QStringList exportsOnlyInB;

    int totalDifferences() const;
};

Result compare(const PEDataModel &a, const PEDataModel &b,
               const QString &pathA = QString(), const QString &pathB = QString());

/** Render the result as an HTML string suitable for QTextBrowser. */
QString toHtml(const Result &result);

} // namespace PECompare

#endif // PE_COMPARE_H
