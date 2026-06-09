#ifndef FINDINGS_CONTROLLER_H
#define FINDINGS_CONTROLLER_H

#include "pe_field_hex.h"
#include "pe_findings.h"

#include <QObject>
#include <QVector>
#include <functional>

class PEParserNew;
class QTreeWidgetItem;
class UIManager;

class FindingsController : public QObject
{
    Q_OBJECT

public:
    using ResolveHexRangeFn = std::function<PeFieldHexRange(QTreeWidgetItem *, const QString &)>;
    using ApplyHexNavFn = std::function<void(QTreeWidgetItem *, const PeFieldHexRange &)>;
    using FindStructureFieldFn = std::function<QTreeWidgetItem *(const QString &)>;
    using ActivateStructureFieldFn = std::function<void(QTreeWidgetItem *)>;

    explicit FindingsController(UIManager *ui, QObject *parent = nullptr);

    void setParser(PEParserNew *parser);
    void setNavigationHooks(ResolveHexRangeFn resolveHex,
                            ApplyHexNavFn applyHex,
                            FindStructureFieldFn findField,
                            ActivateStructureFieldFn activateField);

    void refresh();
    void clear();
    void applyFilter();
    void updateLanguageStrings();

    void handleOverviewItemClicked(QTreeWidgetItem *item);
    void handleFindingItemClicked(QTreeWidgetItem *item);

signals:
    void insightHtmlChanged(const QString &html);
    void requestClearHexHighlights();

private:
    void populateOverview();
    void populateFindingsList();

    UIManager *m_ui = nullptr;
    PEParserNew *m_parser = nullptr;
    QVector<PEFindingInstance> m_cachedFindings;
    QVector<PEFindingInstance> m_cachedPassFindings;

    ResolveHexRangeFn m_resolveHex;
    ApplyHexNavFn m_applyHex;
    FindStructureFieldFn m_findField;
    ActivateStructureFieldFn m_activateField;
};

#endif // FINDINGS_CONTROLLER_H
