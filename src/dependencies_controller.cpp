#include "dependencies_controller.h"

#include "pe_dependency_analyzer.h"
#include "pe_parser_new.h"
#include "pe_ui_manager.h"
#include "language_manager.h"

#include <QApplication>
#include <QClipboard>
#include <QDir>
#include <QIcon>
#include <QMenu>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QTreeWidget>

namespace {

QString dependencyTooltipText(const DependencyNode &node)
{
    QString t;
    if (node.cycleDetected) {
        t = LANG("UI/deps_tooltip_cycle");
    } else {
        t = node.depth == 0 ? LANG("UI/deps_tooltip_direct") : LANG("UI/deps_tooltip_transitive");
        if (node.truncatedByDepth) {
            t += QStringLiteral("\n\n") + LANG("UI/deps_tooltip_truncated");
        }
        if (!node.foundOnSystem) {
            t += QStringLiteral("\n\n") + LANG("UI/deps_tooltip_not_found");
        }
    }
    const QString native = QDir::toNativeSeparators(node.resolvedPath);
    if (!native.isEmpty()) {
        t += QStringLiteral("\n\n") + LANG_PARAM("UI/deps_tooltip_resolved_line", "path", native);
    } else if (!node.foundOnSystem) {
        t += QStringLiteral("\n\n") + LANG("UI/deps_tooltip_no_path");
    }
    return t;
}

void appendDependencyTreeText(QTreeWidgetItem *item, QString *out, int depth)
{
    const QString pad(depth * 2, QLatin1Char(' '));
    *out += pad + item->text(0) + QLatin1Char('\t') + item->text(1) + QLatin1Char('\t') + item->text(2)
            + QLatin1Char('\n');
    for (int i = 0; i < item->childCount(); ++i) {
        appendDependencyTreeText(item->child(i), out, depth + 1);
    }
}

QString fullDependencyTreeText(QTreeWidget *tree)
{
    QString out;
    for (int i = 0; i < tree->topLevelItemCount(); ++i) {
        appendDependencyTreeText(tree->topLevelItem(i), &out, 0);
    }
    return out;
}

} // namespace

DependenciesController::DependenciesController(UIManager *ui, QObject *parent)
    : QObject(parent), m_ui(ui)
{
}

void DependenciesController::setParser(PEParserNew *parser)
{
    m_parser = parser;
}

void DependenciesController::setFilePath(const QString &path)
{
    m_filePath = path;
}

void DependenciesController::setFileLoaded(bool loaded)
{
    m_fileLoaded = loaded;
}

void DependenciesController::setupDepthSpin()
{
    if (!m_ui || !m_ui->m_dependenciesDepthSpin) {
        return;
    }

    QSettings settings(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
    m_ui->m_dependenciesDepthSpin->setValue(
        settings.value(QStringLiteral("dependencies/maxDepth"), 8).toInt());

    connect(m_ui->m_dependenciesDepthSpin, QOverload<int>::of(&QSpinBox::valueChanged), this,
            [this](int value) {
                QSettings s(QStringLiteral("PEHint"), QStringLiteral("PEHint"));
                s.setValue(QStringLiteral("dependencies/maxDepth"), value);
                if (m_fileLoaded && m_parser && m_parser->isValid()) {
                    m_populated = false;
                    refresh();
                }
            });
}

void DependenciesController::refresh()
{
    populate();
}

void DependenciesController::clear()
{
    if (m_ui && m_ui->m_dependenciesTree) {
        m_ui->m_dependenciesTree->clear();
    }
    m_populated = false;
    updateExpandCollapseButtonState();
}

void DependenciesController::invalidate()
{
    m_populated = false;
}

void DependenciesController::updateLanguageStrings()
{
    if (!m_ui) {
        return;
    }

    if (m_ui->m_dependenciesTree) {
        m_ui->m_dependenciesTree->setHeaderLabels({
            LANG("UI/deps_header_module"),
            LANG("UI/deps_header_resolved_path"),
            LANG("UI/deps_header_found")
        });
    }
    if (m_ui->m_dependenciesDepthLabel) {
        m_ui->m_dependenciesDepthLabel->setText(LANG("UI/deps_depth_label"));
    }
    if (m_ui->m_dependenciesDepthSpin) {
        m_ui->m_dependenciesDepthSpin->setSpecialValueText(LANG("UI/deps_depth_unlimited"));
        m_ui->m_dependenciesDepthSpin->setToolTip(LANG("UI/deps_depth_tooltip"));
    }
}

void DependenciesController::updateExpandCollapseButtonState()
{
    if (!m_ui) {
        return;
    }
    const bool on = m_fileLoaded && m_ui->m_dependenciesTree
                    && m_ui->m_dependenciesTree->topLevelItemCount() > 0;
    if (m_ui->m_dependenciesExpandAllButton) {
        m_ui->m_dependenciesExpandAllButton->setEnabled(on);
    }
    if (m_ui->m_dependenciesCollapseAllButton) {
        m_ui->m_dependenciesCollapseAllButton->setEnabled(on);
    }
}

void DependenciesController::handleCustomContextMenu(const QPoint &pos)
{
    if (!m_ui || !m_ui->m_dependenciesTree) {
        return;
    }
    QTreeWidget *tree = m_ui->m_dependenciesTree;
    const QPoint vpPos = tree->viewport()->mapFrom(tree, pos);
    QTreeWidgetItem *itemAt = tree->itemAt(vpPos);

    QMenu menu;
    QAction *copyAct = menu.addAction(LANG("UI/context_copy"));
    copyAct->setIcon(QIcon(QStringLiteral(":/images/imgs/copy.png")));
    menu.addSeparator();
    QAction *expandAct = menu.addAction(LANG("UI/context_expand_all"));
    expandAct->setIcon(QIcon(QStringLiteral(":/images/imgs/expand.png")));
    QAction *collapseAct = menu.addAction(LANG("UI/context_collapse_all"));
    collapseAct->setIcon(QIcon(QStringLiteral(":/images/imgs/collapse.png")));

    QAction *chosen = menu.exec(tree->viewport()->mapToGlobal(vpPos));
    if (!chosen) {
        return;
    }
    if (chosen == copyAct) {
        QString text;
        if (itemAt) {
            text = itemAt->text(0) + QLatin1Char('\t') + itemAt->text(1) + QLatin1Char('\t') + itemAt->text(2);
        } else {
            text = fullDependencyTreeText(tree);
        }
        if (!text.isEmpty()) {
            QApplication::clipboard()->setText(text);
            emit statusMessageRequested(LANG("UI/content_copied"), 2000);
        }
    } else if (chosen == expandAct) {
        expandAll();
    } else if (chosen == collapseAct) {
        collapseAll();
    }
}

void DependenciesController::expandAll()
{
    if (m_ui && m_ui->m_dependenciesTree) {
        m_ui->m_dependenciesTree->expandAll();
    }
}

void DependenciesController::collapseAll()
{
    if (m_ui && m_ui->m_dependenciesTree) {
        m_ui->m_dependenciesTree->collapseAll();
    }
}

void DependenciesController::populate()
{
    if (m_populated) {
        return;
    }
    if (!m_ui || !m_ui->m_dependenciesTree || !m_parser) {
        return;
    }

    auto addDependencyNode = [this](const DependencyNode &node, QTreeWidgetItem *parent, auto &addRef) -> void {
        QTreeWidgetItem *item = parent ? new QTreeWidgetItem(parent)
                                       : new QTreeWidgetItem(m_ui->m_dependenciesTree);
        QString moduleText = node.moduleName;
        if (node.cycleDetected) {
            moduleText += QStringLiteral(" [") + LANG("UI/deps_tag_cycle") + QStringLiteral("]");
        } else if (node.truncatedByDepth) {
            moduleText += QStringLiteral(" [") + LANG("UI/deps_tag_max_depth") + QStringLiteral("]");
        }
        item->setText(0, moduleText);
        item->setText(1, QDir::toNativeSeparators(node.resolvedPath));
        item->setText(2, node.foundOnSystem ? LANG("UI/deps_found_yes") : LANG("UI/deps_found_no"));
        const QString tip = dependencyTooltipText(node);
        item->setToolTip(0, tip);
        item->setToolTip(1, tip);
        item->setToolTip(2, tip);
        for (const DependencyNode &child : node.children) {
            addRef(child, item, addRef);
        }
    };

    m_ui->m_dependenciesTree->setUpdatesEnabled(false);
    m_ui->m_dependenciesTree->clear();
    const QStringList imports = m_parser->getImportModules();
    if (imports.isEmpty()) {
        QTreeWidgetItem *placeholder = new QTreeWidgetItem(m_ui->m_dependenciesTree);
        placeholder->setText(0, LANG("UI/imports_none"));
        placeholder->setFirstColumnSpanned(true);
        placeholder->setFlags(Qt::NoItemFlags);
    } else {
        constexpr int kMaxUnlimitedDependencyDepth = 64;
        int maxDepth = 8;
        if (m_ui->m_dependenciesDepthSpin) {
            maxDepth = m_ui->m_dependenciesDepthSpin->value();
            if (maxDepth == 0) {
                maxDepth = kMaxUnlimitedDependencyDepth;
            }
        }
        const DependencyAnalysisResult depResult =
            PEDependencyAnalyzer::analyzeTransitive(imports, m_filePath, maxDepth);

        for (const DependencyNode &node : depResult.dependencyTree) {
            addDependencyNode(node, nullptr, addDependencyNode);
        }
        m_ui->m_dependenciesTree->expandToDepth(1);
    }
    m_ui->m_dependenciesTree->setUpdatesEnabled(true);

    m_populated = true;
    updateExpandCollapseButtonState();
}
