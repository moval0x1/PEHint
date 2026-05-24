#include "findings_controller.h"

#include "pe_ui_manager.h"
#include "pe_parser_new.h"
#include "pe_ui_presenter.h"
#include "language_manager.h"
#include "section_layout_widget.h"
#include "pe_utils.h"

#include <QTreeWidget>
#include <QFont>
#include <QColor>
#include <QRegularExpression>
#include <QMap>

#include <type_traits>
#include <utility>

namespace {

constexpr int kFieldOffsetRole = Qt::UserRole + 20;
constexpr int kFieldSizeRole = Qt::UserRole + 21;
constexpr int kFindingCategoryHeaderRole = Qt::UserRole + 41;
constexpr int kFindingRuleIdRole = Qt::UserRole + 42;

QString formatHardcodedMatchesInsightHtml(const QString &title, const QString &intro,
                                          const QVector<PEHardcodedMatch> &matches)
{
    QString html = QStringLiteral(
                       "<div style='font-family:\"Segoe UI\",Arial,sans-serif;font-size:11px;"
                       "color:#222;line-height:1.55;'>"
                       "<p style='font-weight:600;font-size:12px;margin:0 0 6px 0;'>%1</p>"
                       "<p style='color:#555;margin:0 0 8px 0;'>%2</p>"
                       "<ul style='margin:0;padding-left:18px;'>")
                       .arg(title.toHtmlEscaped(), intro.toHtmlEscaped());
    for (const PEHardcodedMatch &m : matches) {
        html += QStringLiteral("<li style='margin-bottom:4px;'><code>%1</code> "
                               "<span style='color:#666;'>@ %2</span></li>")
                    .arg(m.value.toHtmlEscaped(), PEUtils::formatHexWidth(m.fileOffset, 8));
    }
    html += QStringLiteral("</ul></div>");
    return html;
}

bool parseInsightByteSizeFromValue(const QString &valueText, quint32 &outSize)
{
    static const QRegularExpression sizeInParens(
        QStringLiteral("\\(0x([0-9A-Fa-f]+) bytes\\)"), QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = sizeInParens.match(valueText);
    if (!match.hasMatch()) {
        return false;
    }
    bool ok = false;
    const quint32 parsed = match.captured(1).toUInt(&ok, 16);
    if (!ok || parsed == 0) {
        return false;
    }
    outSize = parsed;
    return true;
}

PeFieldHexRange fallbackHexRange(QTreeWidgetItem *item)
{
    PeFieldHexRange range;
    if (!item) {
        return range;
    }

    const QVariant roleOffset = item->data(0, kFieldOffsetRole);
    const QVariant roleSize = item->data(0, kFieldSizeRole);
    if (!roleOffset.isValid()) {
        return range;
    }

    bool okOffset = false;
    const quint32 offset = roleOffset.toUInt(&okOffset);
    if (!okOffset) {
        return range;
    }

    bool okSize = false;
    quint32 size = roleSize.toUInt(&okSize);
    if (!okSize || size == 0) {
        quint32 parsedSize = 0;
        if (parseInsightByteSizeFromValue(item->text(1), parsedSize)) {
            size = parsedSize;
        }
    }

    range.offset = offset;
    range.size = size;
    range.canGoTo = true;
    range.canHighlight = size > 0;
    return range;
}

template <typename T, typename = void>
struct HasBuildFileInsightsOverview : std::false_type {
};

template <typename T>
struct HasBuildFileInsightsOverview<T, std::void_t<decltype(std::declval<T &>().buildFileInsightsOverview())>>
    : std::true_type {
};

template <typename PresenterT>
QTreeWidgetItem *buildInsightsOverviewCompat(PEParserNew *parser)
{
    if (!parser) {
        return nullptr;
    }

    if constexpr (HasBuildFileInsightsOverview<PresenterT>::value) {
        PresenterT presenter(parser);
        return presenter.buildFileInsightsOverview();
    }

    return parser->buildFileInsightsItem();
}

} // namespace

FindingsController::FindingsController(UIManager *ui, QObject *parent)
    : QObject(parent), m_ui(ui)
{
}

void FindingsController::setParser(PEParserNew *parser)
{
    m_parser = parser;
}

void FindingsController::setNavigationHooks(ResolveHexRangeFn resolveHex, ApplyHexNavFn applyHex,
                                            FindStructureFieldFn findField,
                                            ActivateStructureFieldFn activateField)
{
    m_resolveHex = std::move(resolveHex);
    m_applyHex = std::move(applyHex);
    m_findField = std::move(findField);
    m_activateField = std::move(activateField);
}

void FindingsController::refresh()
{
    if (!m_ui || !m_parser || !m_parser->isValid()) {
        return;
    }

    PEFindingsEngine::loadRules();

    const auto rvaToFo = [this](quint32 rva) -> quint32 {
        return m_parser ? m_parser->rvaToFileOffset(rva) : 0u;
    };

    m_cachedFindings = PEFindingsEngine::evaluate(m_parser->getDataModel(), rvaToFo);
    m_cachedPassFindings = PEFindingsEngine::evaluateHardeningPasses(m_parser->getDataModel());

    populateOverview();
    applyFilter();
}

void FindingsController::clear()
{
    if (!m_ui) {
        m_cachedFindings.clear();
        m_cachedPassFindings.clear();
        emit insightHtmlChanged(QString());
        emit requestClearHexHighlights();
        return;
    }

    if (m_ui->m_findingsTree) {
        m_ui->m_findingsTree->clear();
    }
    if (m_ui->m_findingsOverviewTree) {
        m_ui->m_findingsOverviewTree->clear();
    }
    if (m_ui->m_sectionLayoutWidget) {
        m_ui->m_sectionLayoutWidget->setSections({}, 0);
    }

    m_cachedFindings.clear();
    m_cachedPassFindings.clear();

    if (m_ui->m_findingsSummaryLabel) {
        m_ui->m_findingsSummaryLabel->setText(LANG(QStringLiteral("findings/summary_none")));
    }

    emit insightHtmlChanged(QString());
    emit requestClearHexHighlights();
}

void FindingsController::applyFilter()
{
    populateFindingsList();
}

void FindingsController::updateLanguageStrings()
{
    if (!m_ui) {
        return;
    }

    if (m_ui->m_findingsTree) {
        m_ui->m_findingsTree->setHeaderLabels(
            {LANG(QStringLiteral("findings/header_severity")),
             LANG(QStringLiteral("findings/header_title")),
             LANG(QStringLiteral("findings/header_detail"))});
    }

    if (m_ui->m_findingsOverviewTree) {
        m_ui->m_findingsOverviewTree->setHeaderLabels(
            {LANG(QStringLiteral("UI/tree_header_field")), LANG(QStringLiteral("UI/tree_header_value"))});
    }

    if (m_ui->m_findingsShowPassesCheck) {
        m_ui->m_findingsShowPassesCheck->setText(LANG(QStringLiteral("findings/show_passes")));
    }

    if (m_ui->m_findingsInsightTitleLabel) {
        m_ui->m_findingsInsightTitleLabel->setText(LANG(QStringLiteral("findings/insight_title")));
    }

    if (m_ui->m_findingsInsightText) {
        m_ui->m_findingsInsightText->setPlaceholderText(
            LANG(QStringLiteral("findings/insight_placeholder")));
    }

    if (m_ui->m_findingsSeverityCombo) {
        const int idx = m_ui->m_findingsSeverityCombo->currentIndex();
        m_ui->m_findingsSeverityCombo->setItemText(
            0, LANG(QStringLiteral("findings/filter_severity_all")));
        m_ui->m_findingsSeverityCombo->setItemText(
            1, LANG(QStringLiteral("findings/filter_severity_high")));
        m_ui->m_findingsSeverityCombo->setItemText(
            2, LANG(QStringLiteral("findings/filter_severity_medium")));
        m_ui->m_findingsSeverityCombo->setItemText(
            3, LANG(QStringLiteral("findings/filter_severity_low")));
        m_ui->m_findingsSeverityCombo->setItemText(
            4, LANG(QStringLiteral("findings/filter_severity_info")));
        m_ui->m_findingsSeverityCombo->setCurrentIndex(idx);
    }

    if (m_parser && m_parser->isValid()) {
        populateOverview();
        applyFilter();
    } else if (m_ui->m_findingsSummaryLabel) {
        m_ui->m_findingsSummaryLabel->setText(LANG(QStringLiteral("findings/summary_none")));
    }
}

void FindingsController::handleOverviewItemClicked(QTreeWidgetItem *item)
{
    if (!item || !m_ui || !m_parser || !m_parser->isValid()) {
        return;
    }

    const QString treeField = item->data(0, PEParserNew::kTreeFieldKeyRole).toString();

    PeFieldHexRange range;
    if (m_resolveHex) {
        range = m_resolveHex(item, treeField);
    }
    if (!range.canHighlight && !range.canGoTo) {
        range = fallbackHexRange(item);
    }

    if (!treeField.isEmpty()) {
        const QString richExplanation = m_parser->getFileInsightExplanation(treeField);
        if (!richExplanation.isEmpty()) {
            emit insightHtmlChanged(richExplanation);
        }
    }

    if ((range.canHighlight || range.canGoTo) && m_applyHex) {
        m_applyHex(item, range);
    } else if (!range.canHighlight && !range.canGoTo) {
        emit requestClearHexHighlights();
    }
}

void FindingsController::handleFindingItemClicked(QTreeWidgetItem *item)
{
    if (!item || !m_ui || !m_parser || !m_parser->isValid()) {
        return;
    }
    if (item->data(0, kFindingCategoryHeaderRole).toBool()) {
        return;
    }

    const QString treeField = item->data(0, PEParserNew::kTreeFieldKeyRole).toString();
    PeFieldHexRange range;
    if (m_resolveHex) {
        range = m_resolveHex(item, treeField);
    }
    if (!range.canHighlight && !range.canGoTo) {
        range = fallbackHexRange(item);
    }

    QTreeWidgetItem *peItem = (treeField.isEmpty() || !m_findField) ? nullptr : m_findField(treeField);
    if (peItem && m_activateField) {
        m_activateField(peItem);
        return;
    }

    if ((range.canHighlight || range.canGoTo) && m_applyHex) {
        m_applyHex(item, range);
    }

    const QString ruleId = item->data(0, kFindingRuleIdRole).toString();
    const QString baseRuleId = ruleId.section(QLatin1Char(':'), 0, 0);
    if (baseRuleId == QStringLiteral("hardcoded_url") || baseRuleId == QStringLiteral("hardcoded_ip")
        || baseRuleId == QStringLiteral("hardcoded_registry")
        || baseRuleId == QStringLiteral("suspicious_command")) {
        const PEContentScan scan = m_parser->getDataModel().getContentScan();
        const QVector<PEHardcodedMatch> &matches =
            baseRuleId == QStringLiteral("hardcoded_url")
            ? scan.urls
            : baseRuleId == QStringLiteral("hardcoded_ip")
                ? scan.ips
                : baseRuleId == QStringLiteral("hardcoded_registry") ? scan.registryPaths
                                                                      : scan.suspiciousCommands;
        const QString title = item->text(1);
        const QString intro = LANG(QStringLiteral("findings/hardcoded_matches_intro"));
        emit insightHtmlChanged(formatHardcodedMatchesInsightHtml(title, intro, matches));
        return;
    }

    const QString title = item->text(1);
    const QString detail = item->text(2);
    const QString helpKey = QStringLiteral("findings/") + baseRuleId + QStringLiteral("_help");
    const QString helpText = LANG(helpKey);
    QString html = QStringLiteral(
                       "<div style='font-family:\"Segoe UI\",Arial,sans-serif;font-size:11px;"
                       "color:#222;line-height:1.55;'>"
                       "<div style='font-weight:600;font-size:12px;margin-bottom:8px;'>%1</div>"
                       "<div style='color:#333;'>%2</div>")
                       .arg(title.toHtmlEscaped(), detail.toHtmlEscaped());
    if (!helpText.isEmpty() && helpText != helpKey) {
        html += QStringLiteral(
                    "<div style='margin-top:10px;padding:8px 10px;background:#f0f9ff;border-left:3px solid "
                    "#38bdf8;border-radius:4px;color:#0c4a6e;'>%1</div>")
                    .arg(helpText.toHtmlEscaped());
    }
    html += QStringLiteral("</div>");
    emit insightHtmlChanged(html);
}

void FindingsController::populateOverview()
{
    if (!m_ui || !m_ui->m_findingsOverviewTree || !m_parser || !m_parser->isValid()) {
        return;
    }

    m_ui->m_findingsOverviewTree->clear();

    QTreeWidgetItem *insights = buildInsightsOverviewCompat<PEUIPresenter>(m_parser);
    if (!insights) {
        return;
    }

    for (int i = 0; i < insights->childCount(); ++i) {
        QTreeWidgetItem *src = insights->child(i);
        QTreeWidgetItem *row = new QTreeWidgetItem(m_ui->m_findingsOverviewTree);
        row->setText(0, src->text(0));
        row->setText(1, src->text(1));

        const QString fieldKey = src->data(0, PEParserNew::kTreeFieldKeyRole).toString();
        if (!fieldKey.isEmpty()) {
            row->setData(0, PEParserNew::kTreeFieldKeyRole, fieldKey);
        }

        const QVariant offVar = src->data(0, kFieldOffsetRole);
        const QVariant sizeVar = src->data(0, kFieldSizeRole);
        if (offVar.isValid()) {
            row->setData(0, kFieldOffsetRole, offVar);
        }
        if (sizeVar.isValid()) {
            row->setData(0, kFieldSizeRole, sizeVar);
        }

        if (fieldKey == QLatin1String("Signed")) {
            const PEFileMetrics metrics = m_parser->getDataModel().getFileMetrics();
            const QColor bg = metrics.authenticodePresent ? QColor(230, 255, 230) : QColor(255, 243, 224);
            const QColor fg = metrics.authenticodePresent ? QColor(22, 101, 52) : QColor(146, 64, 14);
            for (int col = 0; col < 2; ++col) {
                row->setBackground(col, bg);
                row->setForeground(col, fg);
            }
            row->setText(1, metrics.authenticodePresent ? LANG(QStringLiteral("UI/signed_table_yes"))
                                                        : LANG(QStringLiteral("UI/signed_table_no")));
        }

        if (!row->text(1).isEmpty()) {
            row->setToolTip(1, row->text(1));
        }
    }
    delete insights;

    QTreeWidget *tree = m_ui->m_findingsOverviewTree;
    const int rows = tree->topLevelItemCount();
    int rowHeight = rows > 0 ? tree->sizeHintForRow(0) : 22;
    if (rowHeight < 20) {
        rowHeight = 22;
    }

    constexpr int kOverviewHeaderHeight = 26;
    constexpr int kMaxVisibleRows = 6;
    const int visibleRows = qMin(rows, kMaxVisibleRows);
    const int contentHeight = kOverviewHeaderHeight + visibleRows * rowHeight + 6;
    tree->setFixedHeight(contentHeight);

    tree->resizeColumnToContents(0);
    tree->resizeColumnToContents(1);
    constexpr int kOverviewChrome = 28;
    constexpr int kMaxOverviewWidth = 560;
    constexpr int kMaxFieldColumnWidth = 118;
    if (tree->columnWidth(0) > kMaxFieldColumnWidth) {
        tree->setColumnWidth(0, kMaxFieldColumnWidth);
    }
    const int tableWidth = tree->columnWidth(0) + tree->columnWidth(1) + kOverviewChrome;
    tree->setFixedWidth(qMin(tableWidth, kMaxOverviewWidth));

    if (m_ui->m_findingsInsightText) {
        const int insightHeight = qBound(72, contentHeight, 132);
        m_ui->m_findingsInsightText->setFixedHeight(insightHeight);
    }

    if (m_ui->m_sectionLayoutWidget) {
        const PEDataModel &model = m_parser->getDataModel();
        quint32 imageSize = 0;
        if (const IMAGE_OPTIONAL_HEADER *opt = model.getOptionalHeader()) {
            imageSize = opt->SizeOfImage;
        }
        m_ui->m_sectionLayoutWidget->setSections(model.getSections(), imageSize);
    }

    if (rows > kMaxVisibleRows) {
        tree->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    } else {
        tree->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    }
}

void FindingsController::populateFindingsList()
{
    if (!m_ui || !m_ui->m_findingsTree) {
        return;
    }

    m_ui->m_findingsTree->clear();

    const QString severityFilter =
        m_ui->m_findingsSeverityCombo ? m_ui->m_findingsSeverityCombo->currentData().toString()
                                      : QStringLiteral("all");
    const bool showPasses =
        m_ui->m_findingsShowPassesCheck && m_ui->m_findingsShowPassesCheck->isChecked();

    QVector<PEFindingInstance> visible = m_cachedFindings;
    if (showPasses) {
        visible += m_cachedPassFindings;
    }

    const auto severityMatches = [&](const PEFindingInstance &finding) -> bool {
        if (severityFilter == QStringLiteral("all")) {
            return true;
        }
        if (finding.isPass) {
            return severityFilter == QStringLiteral("info");
        }
        switch (finding.severity) {
        case PEFindingSeverity::High:
            return severityFilter == QStringLiteral("high");
        case PEFindingSeverity::Medium:
            return severityFilter == QStringLiteral("medium");
        case PEFindingSeverity::Low:
            return severityFilter == QStringLiteral("low");
        default:
            return severityFilter == QStringLiteral("info");
        }
    };

    QVector<PEFindingInstance> filtered;
    filtered.reserve(visible.size());
    for (const PEFindingInstance &finding : visible) {
        if (finding.isPass && !showPasses) {
            continue;
        }
        if (severityMatches(finding)) {
            filtered.append(finding);
        }
    }

    if (m_ui->m_findingsSummaryLabel) {
        if (filtered.isEmpty()) {
            m_ui->m_findingsSummaryLabel->setText(LANG(QStringLiteral("findings/summary_none")));
        } else {
            QMap<QString, QString> params;
            params[QStringLiteral("count")] = QString::number(filtered.size());
            m_ui->m_findingsSummaryLabel->setText(
                LANG_PARAMS(QStringLiteral("findings/summary_count"), params));
        }
    }

    const auto severityColor = [](const PEFindingInstance &finding) -> QColor {
        if (finding.isPass) {
            return QColor(230, 255, 230);
        }
        switch (finding.severity) {
        case PEFindingSeverity::High:
            return QColor(255, 230, 230);
        case PEFindingSeverity::Medium:
            return QColor(255, 248, 220);
        case PEFindingSeverity::Low:
            return QColor(240, 248, 255);
        default:
            return QColor(245, 245, 245);
        }
    };

    const QVector<PEFindingRule> &rules = PEFindingsEngine::rules();
    static const char *const kCategoryOrder[] = {"hardening", "content", "metadata", "imports", "other"};

    const auto categoryForFinding = [&](const PEFindingInstance &finding) -> QString {
        if (!finding.category.isEmpty()) {
            return finding.category;
        }
        for (const PEFindingRule &rule : rules) {
            if (rule.id == finding.ruleId) {
                return PEFindingsEngine::categoryKeyForRule(rule);
            }
        }
        return finding.isPass ? QStringLiteral("hardening") : QStringLiteral("other");
    };

    QMap<QString, QTreeWidgetItem *> categoryNodes;
    for (const char *catKey : kCategoryOrder) {
        const QString key = QString::fromLatin1(catKey);
        QTreeWidgetItem *catItem = new QTreeWidgetItem(m_ui->m_findingsTree);
        catItem->setText(0, QString());
        catItem->setText(1, PEFindingsEngine::categoryDisplayName(key));
        catItem->setText(2, QString());
        catItem->setData(0, kFindingCategoryHeaderRole, true);
        catItem->setFirstColumnSpanned(false);
        catItem->setExpanded(true);
        QFont f = catItem->font(1);
        f.setBold(true);
        catItem->setFont(1, f);
        categoryNodes.insert(key, catItem);
    }

    for (const PEFindingInstance &finding : filtered) {
        QString title = finding.title;
        QString detail = finding.detail;
        for (const PEFindingRule &rule : rules) {
            if (rule.id == finding.ruleId) {
                title = LANG(rule.titleKey);
                if (detail.isEmpty() || detail.startsWith(QStringLiteral("findings/"))) {
                    detail = LANG(rule.detailKey);
                }
                break;
            }
        }

        const QString catKey = categoryForFinding(finding);
        QTreeWidgetItem *parent = categoryNodes.value(catKey, categoryNodes.value(QStringLiteral("other")));
        if (!parent) {
            parent = categoryNodes.value(QStringLiteral("other"));
        }

        QTreeWidgetItem *row = new QTreeWidgetItem(parent);
        row->setText(0, finding.isPass ? LANG(QStringLiteral("findings/severity_pass"))
                                       : PEFindingsEngine::severityDisplayName(finding.severity));
        row->setText(1, title);
        row->setText(2, detail);

        if (!finding.treeField.isEmpty()) {
            row->setData(0, PEParserNew::kTreeFieldKeyRole, finding.treeField);
        }
        if (finding.hasHexNav && finding.hexSize > 0) {
            row->setData(0, kFieldOffsetRole, finding.hexOffset);
            row->setData(0, kFieldSizeRole, finding.hexSize);
        }
        if (!finding.ruleId.isEmpty()) {
            row->setData(0, kFindingRuleIdRole, finding.ruleId);
        }

        const QColor bg = severityColor(finding);
        for (int col = 0; col < 3; ++col) {
            row->setBackground(col, bg);
        }
    }

    for (const char *catKey : kCategoryOrder) {
        QTreeWidgetItem *catItem = categoryNodes.value(QString::fromLatin1(catKey));
        if (catItem && catItem->childCount() == 0) {
            catItem->setHidden(true);
        }
    }
}
