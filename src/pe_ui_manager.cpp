/**
 * @file pe_ui_manager.cpp
 * @brief Implementation of UIManager class for PEHint
 * 
 * This file contains the implementation of the UI setup logic that was
 * previously scattered throughout MainWindow. The refactoring extracts
 * this logic into a focused, maintainable class.
 * 
 * IMPLEMENTATION NOTES:
 * - Each setup method creates a specific section of the UI
 * - Methods are organized by UI functionality, not by Qt widget type
 * - Styling and layout are centralized for consistency
 * - Component references are stored for MainWindow access
 */

#include "pe_ui_manager.h"
#include "mainwindow.h"
#include "hexviewer.h"
#include "language_manager.h"
#include <QApplication>
#include <QIcon>
#include <QSplitter>

/**
 * @brief Constructor for UIManager
 * @param parent Pointer to the MainWindow that owns this UIManager
 * 
 * This constructor initializes all UI component pointers to nullptr.
 * The actual components are created later in setupMainUI() when needed.
 * 
 * REFACTORING BENEFIT: Previously, MainWindow had to manage all these
 * pointers and their lifecycle. Now UIManager handles component creation
 * and MainWindow just accesses them when needed.
 */
UIManager::UIManager(MainWindow *parent)
    : QObject(parent)
    , m_mainWindow(parent)
    , m_fileInfoLabel(nullptr)
    , m_progressBar(nullptr)
    , m_progressLabel(nullptr)
    , m_refreshButton(nullptr)
    , m_copyButton(nullptr)
    , m_saveButton(nullptr)
    , m_expandAllButton(nullptr)
    , m_collapseAllButton(nullptr)
    , m_peTree(nullptr)
    , m_fieldExplanationTitleLabel(nullptr)
    , m_fieldExplanationText(nullptr)
    , m_contextMenu(nullptr)
    , m_analysisTabWidget(nullptr)
    , m_importModulesTree(nullptr)
    , m_importFunctionsTree(nullptr)
    , m_importHintTitleLabel(nullptr)
    , m_importHintText(nullptr)
    , m_exportsTree(nullptr)
    , m_dependenciesTree(nullptr)
    , m_dependenciesExpandAllButton(nullptr)
    , m_dependenciesCollapseAllButton(nullptr)
    , m_stringsTree(nullptr)
    , m_findingsTree(nullptr)
    , m_findingsSummaryLabel(nullptr)
    , m_stringsFilterEdit(nullptr)
    , m_stringsTypeCombo(nullptr)
    , m_stringsMinLengthSpin(nullptr)
    , m_stringsSectionCombo(nullptr)
    , m_stringsCancelButton(nullptr)
    , m_stringsExportButton(nullptr)
    , m_hexViewer(nullptr)
{
}

/**
 * @brief Sets up the main UI layout and components
 * @param centralWidget The central widget to populate
 * 
 * This method orchestrates the creation of the entire UI by calling
 * specialized setup methods for each section. It creates a vertical
 * layout and populates it with organized sections.
 * 
 * REFACTORING BENEFIT: Previously, MainWindow::setupUI() contained
 * ~100+ lines of mixed UI creation code. Now it's organized into
 * logical, focused methods that are easy to understand and modify.
 * 
 * UI STRUCTURE:
 * 1. File Info Section (file info + refresh button)
 * 2. Progress Section (progress bar + status label)
 * 3. Tree Section (PE structure tree + field explanations)
 * 4. Button Section (copy + save buttons)
 */
void UIManager::setupMainUI(QWidget *centralWidget)
{
    // Create the main vertical layout that will contain all UI sections
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(8, 8, 8, 8);
    mainLayout->setSpacing(8);
    
    // Set size policy for central widget to allow proper resizing
    centralWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    
    // REFACTORING: Each section is now handled by a focused method
    // This makes the code easier to read, understand, and maintain
    setupFileInfoSection(mainLayout);
    setupProgressSection(mainLayout);
    setupTreeSection(mainLayout);
    setupButtonSection(mainLayout);
    
    // Create hex viewer component and add it to the layout
    m_hexViewer = new HexViewer(centralWidget);
    m_hexViewer->setVisible(true); // Make hex viewer visible
    m_hexViewer->setMinimumHeight(180);
    m_hexViewer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::MinimumExpanding);
    mainLayout->addWidget(m_hexViewer, 0);

    // Keep a stable, readable vertical balance between tabs and hex view.
    // Item index map:
    // 0=file info, 1=progress, 2=analysis tabs, 3=buttons, 4=hex viewer
    mainLayout->setStretch(2, 5);
    mainLayout->setStretch(4, 3);
}

/**
 * @brief Sets up the file information section
 * @param mainLayout The main vertical layout to add the section to
 * 
 * This method creates the top section of the UI that displays:
 * - A folder icon for visual identification
 * - Current file information (filename, size, type)
 * - Refresh button for reloading analysis
 * 
 * REFACTORING BENEFIT: Previously, this logic was mixed with other UI setup
 * in MainWindow. Now it's organized into a focused method that's easy to
 * understand and modify.
 * 
 * DESIGN DECISIONS:
 * - Uses horizontal layout for icon + label + button arrangement
 * - Icon provides visual context for the file information
 * - Refresh button is right-aligned for easy access
 * - Styling is consistent with the overall application theme
 */
void UIManager::setupFileInfoSection(QVBoxLayout *mainLayout)
{
    QHBoxLayout *fileInfoLayout = new QHBoxLayout();
    
    // Add folder icon for visual context
    QLabel *fileIconLabel = new QLabel();
    fileIconLabel->setPixmap(QIcon(QStringLiteral(":/images/imgs/folder-icon.png")).pixmap(24, 24));
    fileInfoLayout->addWidget(fileIconLabel);
    
    // Create file info label with consistent styling
    m_fileInfoLabel = new QLabel(LANG("UI/file_no_file_loaded"));
    m_fileInfoLabel->setStyleSheet("QLabel { font-weight: bold; color: #666; font-size: 12px; }");
    fileInfoLayout->addWidget(m_fileInfoLabel);
    
    // Add stretch to push refresh button to the right
    fileInfoLayout->addStretch();
    
    // Create refresh button with icon and consistent styling
    m_refreshButton = new QPushButton(LANG("UI/button_refresh"));
    m_refreshButton->setIcon(QIcon(":/images/imgs/refresh.png"));
    m_refreshButton->setStyleSheet("QPushButton { padding: 5px 10px; font-size: 11px; }");
    m_refreshButton->setEnabled(false); // Initially disabled until file is loaded
    fileInfoLayout->addWidget(m_refreshButton);
    
    // Add the file info section to the main layout
    mainLayout->addLayout(fileInfoLayout);
}

/**
 * @brief Sets up the progress section
 * @param mainLayout The main vertical layout to add the section to
 * 
 * This method creates the progress tracking section that shows:
 * - Progress bar for parsing operations
 * - Status label for current operation description
 * 
 * REFACTORING BENEFIT: Progress UI is now centralized and easy to modify
 * without affecting other parts of the application. Previously, progress
 * setup was scattered throughout MainWindow.
 * 
 * DESIGN DECISIONS:
 * - Progress bar is initially hidden (shown only during operations)
 * - Status label provides context for the progress bar
 * - Horizontal layout with label on left, progress bar on right
 * - Progress bar takes most of the horizontal space
 */
void UIManager::setupProgressSection(QVBoxLayout *mainLayout)
{
    // Create progress bar with consistent styling
    m_progressBar = new QProgressBar();
    m_progressBar->setVisible(false); // Hidden until needed
    m_progressBar->setRange(0, 100);
    m_progressBar->setTextVisible(true);
    
    // Create status label for progress messages
    m_progressLabel = new QLabel(""); // Empty initially, will be updated during progress
    m_progressLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
    
    // Create horizontal layout for progress section
    QHBoxLayout *progressLayout = new QHBoxLayout();
    progressLayout->addWidget(m_progressLabel);
    progressLayout->addWidget(m_progressBar);
    progressLayout->setStretch(0, 1); // Label takes minimal space
    progressLayout->setStretch(1, 4); // Progress bar takes most space
    
    // Add the progress section to the main layout
    mainLayout->addLayout(progressLayout);
}

/**
 * @brief Sets up the tree section
 * @param mainLayout The main vertical layout to add the section to
 * 
 * This method creates the main analysis display section:
 * - PE structure tree widget for displaying parsed data
 * - Field explanation text area for showing field details
 * 
 * REFACTORING BENEFIT: Tree and explanation UI is now organized together,
 * making it easier to maintain the relationship between these components.
 * Previously, this logic was mixed with other UI setup in MainWindow.
 * 
 * DESIGN DECISIONS:
 * - Tree widget shows PE structure with multiple columns
 * - Alternating row colors improve readability
 * - Field explanation area is below the tree for easy reference
 * - Consistent styling with the rest of the application
 */
void UIManager::setupTreeSection(QVBoxLayout *mainLayout)
{
    // Create main tab widget for structure/import/export views
    m_analysisTabWidget = new QTabWidget();
    m_analysisTabWidget->setObjectName("analysisTabWidget");
    m_analysisTabWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // --------------------------------------------------------------------
    // Structure tab (original tree + explanations)
    // --------------------------------------------------------------------

    // Create PE Structure Tree with comprehensive columns
    m_peTree = new QTreeWidget();
    QStringList headers;
    headers << LANG("UI/tree_header_field") << LANG("UI/tree_header_value") << LANG("UI/tree_header_offset") << LANG("UI/tree_header_size") << LANG("UI/tree_header_meaning");
    m_peTree->setHeaderLabels(headers);
    m_peTree->setAlternatingRowColors(true); // Improves readability

    // Enhanced styling to indicate clickable items
    m_peTree->setStyleSheet(
        "QTreeWidget { "
        "   font-size: 11px; "
        "   selection-background-color: #0078d4; "
        "   selection-color: white; "
        "} "
        "QTreeWidget::item { "
        "   padding: 2px; "
        "   border: 1px solid transparent; "
        "} "
        "QTreeWidget::item:hover { "
        "   background-color: #f0f0f0; "
        "   border: 1px solid #0078d4; "
        "   border-radius: 3px; "
        "   box-shadow: 0 2px 4px rgba(0, 120, 212, 0.15); "
        "} "
        "QTreeWidget::item:selected { "
        "   background-color: #0078d4; "
        "   color: white; "
        "   border: 2px solid #005a9e; "
        "   border-radius: 4px; "
        "   box-shadow: 0 0 8px rgba(0, 120, 212, 0.4); "
        "} "
        "QTreeWidget::item:pressed { "
        "   background-color: #005a9e; "
        "   color: white; "
        "   border: 2px solid #003d6b; "
        "   border-radius: 4px; "
        "   box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.2); "
        "}"
    );

    // Enable mouse tracking for hover effects
    m_peTree->setMouseTracking(true);

    // Set cursor to indicate clickable items
    m_peTree->setCursor(Qt::PointingHandCursor);

    // Set column widths for optimal display
    m_peTree->setColumnWidth(0, 320);
    m_peTree->setColumnWidth(1, 150);
    m_peTree->setColumnWidth(2, 110);
    m_peTree->setColumnWidth(3, 80);
    m_peTree->setColumnWidth(4, 400);

    m_peTree->setMinimumHeight(300);
    m_peTree->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_peTree->setMinimumWidth(600);

    QWidget *treeContainer = new QWidget();
    treeContainer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    QVBoxLayout *treeContainerLayout = new QVBoxLayout(treeContainer);
    treeContainerLayout->setContentsMargins(0, 0, 0, 0);
    treeContainerLayout->setSpacing(0);

    QWidget *treeControlsWidget = new QWidget(treeContainer);
    QHBoxLayout *treeControlsLayout = new QHBoxLayout(treeControlsWidget);
    treeControlsLayout->setContentsMargins(0, 0, 0, 4);
    treeControlsLayout->setSpacing(6);

    treeControlsLayout->addStretch();

    m_expandAllButton = new QPushButton(LANG("UI/context_expand_all"));
    m_expandAllButton->setObjectName("expandAllButton");
    m_expandAllButton->setEnabled(false);
    m_expandAllButton->setCursor(Qt::PointingHandCursor);
    m_expandAllButton->setStyleSheet("QPushButton { padding: 4px 10px; font-size: 10px; } QPushButton:disabled { color: #999; }");
    treeControlsLayout->addWidget(m_expandAllButton);

    m_collapseAllButton = new QPushButton(LANG("UI/context_collapse_all"));
    m_collapseAllButton->setObjectName("collapseAllButton");
    m_collapseAllButton->setEnabled(false);
    m_collapseAllButton->setCursor(Qt::PointingHandCursor);
    m_collapseAllButton->setStyleSheet("QPushButton { padding: 4px 10px; font-size: 10px; } QPushButton:disabled { color: #999; }");
    treeControlsLayout->addWidget(m_collapseAllButton);

    treeContainerLayout->addWidget(treeControlsWidget);
    treeContainerLayout->addWidget(m_peTree, 1);

    QWidget *explanationContainer = new QWidget();
    explanationContainer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    QVBoxLayout *explanationLayout = new QVBoxLayout(explanationContainer);
    explanationLayout->setContentsMargins(0, 12, 0, 0);  /* top margin so "Field Explanations" doesn't overlap table */
    explanationLayout->setSpacing(6);

    m_fieldExplanationTitleLabel = new QLabel(LANG("UI/explanation_label"));
    QLabel *explanationLabel = m_fieldExplanationTitleLabel;
    explanationLabel->setStyleSheet(
        "QLabel { "
        "   color: #0078d4; "
        "   font-size: 10px; "
        "   font-weight: bold; "
        "   margin-bottom: 4px; "
        "   padding: 2px 6px; "
        "   background-color: #f0f8ff; "
        "   border: 1px solid #cce7ff; "
        "   border-radius: 3px; "
        "   box-shadow: 0 2px 4px rgba(0, 120, 212, 0.15); "
        "   transition: all 0.3s ease; "
        "} "
        "QLabel:hover { "
        "   background-color: #e3f2fd; "
        "   border-color: #0078d4; "
        "   transform: translateY(-1px); "
        "   box-shadow: 0 3px 6px rgba(0, 120, 212, 0.25); "
        "}"
    );
    explanationLayout->addWidget(explanationLabel);

    m_fieldExplanationText = new QTextEdit();
    m_fieldExplanationText->setMinimumHeight(140);
    m_fieldExplanationText->setMinimumWidth(200);
    m_fieldExplanationText->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_fieldExplanationText->setReadOnly(true);
    // Always show a vertical scrollbar so long field explanations are reachable.
    m_fieldExplanationText->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    m_fieldExplanationText->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_fieldExplanationText->setLineWrapMode(QTextEdit::WidgetWidth);
    m_fieldExplanationText->setStyleSheet(
        "QTextEdit { "
        "   font-size: 11px; "
        "   background-color: #f8f8f8; "
        "   border: 1px solid #ddd; "
        "   border-radius: 4px; "
        "   padding: 8px; "
        "   border-left: 4px solid #0078d4; "
        "} "
        "QTextEdit:focus { "
        "   background-color: #ffffff; "
        "   border: 1px solid #0078d4; "
        "   border-left: 4px solid #0078d4; "
        "   box-shadow: 0 0 5px rgba(0, 120, 212, 0.3); "
        "}"
    );
    m_fieldExplanationText->setPlaceholderText(LANG("UI/placeholder_explanation"));
    explanationLayout->addWidget(m_fieldExplanationText, 1);

    treeContainer->setMinimumSize(600, 200);
    explanationContainer->setMinimumSize(600, 140);

    QWidget *structureTab = new QWidget();
    QVBoxLayout *structureLayout = new QVBoxLayout(structureTab);
    structureLayout->setContentsMargins(0, 0, 0, 0);
    structureLayout->setSpacing(6);

    // Move explanations to the right side for better readability while browsing fields.
    QSplitter *structureSplitter = new QSplitter(Qt::Horizontal, structureTab);
    structureSplitter->setChildrenCollapsible(false);
    structureSplitter->setHandleWidth(5);
    structureSplitter->addWidget(treeContainer);
    structureSplitter->addWidget(explanationContainer);
    structureSplitter->setStretchFactor(0, 3);
    structureSplitter->setStretchFactor(1, 2);
    structureSplitter->setSizes({900, 420});

    structureLayout->addWidget(structureSplitter);

    m_analysisTabWidget->addTab(structureTab, LANG("UI/tab_structure"));

    // --------------------------------------------------------------------
    // Imports tab
    // --------------------------------------------------------------------
    QWidget *importsTab = new QWidget();
    QVBoxLayout *importsLayout = new QVBoxLayout(importsTab);
    importsLayout->setContentsMargins(0, 0, 0, 0);
    importsLayout->setSpacing(4);

    QSplitter *importsOuter = new QSplitter(Qt::Horizontal);
    importsOuter->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    importsOuter->setChildrenCollapsible(false);
    importsOuter->setHandleWidth(5);

    m_importModulesTree = new QTreeWidget();
    m_importModulesTree->setAlternatingRowColors(true);
    m_importModulesTree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_importModulesTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_importModulesTree->setHeaderLabels({LANG("UI/imports_header_module"), LANG("UI/imports_header_count")});
    m_importModulesTree->setColumnWidth(0, 250);
    m_importModulesTree->setColumnWidth(1, 120);

    QSplitter *importsRight = new QSplitter(Qt::Vertical);
    importsRight->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    importsRight->setChildrenCollapsible(false);
    importsRight->setHandleWidth(5);

    m_importFunctionsTree = new QTreeWidget();
    m_importFunctionsTree->setAlternatingRowColors(true);
    m_importFunctionsTree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_importFunctionsTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_importFunctionsTree->setHeaderLabels({
        LANG("UI/imports_functions_header_name"),
        LANG("UI/imports_functions_header_offset"),
        LANG("UI/imports_functions_header_ordinal")
    });
    m_importFunctionsTree->setColumnWidth(0, 260);
    m_importFunctionsTree->setColumnWidth(1, 140);
    m_importFunctionsTree->setColumnWidth(2, 100);

    QWidget *importHintPanel = new QWidget();
    QVBoxLayout *importHintLayout = new QVBoxLayout(importHintPanel);
    importHintLayout->setContentsMargins(0, 0, 0, 0);
    importHintLayout->setSpacing(4);
    m_importHintTitleLabel = new QLabel(LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_title"), QStringLiteral("API summary")));
    m_importHintTitleLabel->setStyleSheet(QStringLiteral("font-weight: bold; font-size: 11px;"));
    m_importHintText = new QTextBrowser();
    m_importHintText->setReadOnly(true);
    m_importHintText->setOpenExternalLinks(true);
    m_importHintText->setObjectName(QStringLiteral("importHintText"));
    m_importHintText->setMinimumHeight(96);
    m_importHintText->setStyleSheet(
        QStringLiteral("QTextEdit { background-color: #fafafa; border: 1px solid #ddd; border-radius: 4px; "
                       "font-family: 'Segoe UI', Arial; font-size: 11px; padding: 6px; }"));
    m_importHintText->setPlainText(LanguageManager::getInstance().getString(
        QStringLiteral("UI/imports_hint_placeholder"),
        QStringLiteral("Select an imported function. PEHint shows curated summaries; richer entries may include signature, parameters, and return value (informative only—not live Microsoft data).")));
    importHintLayout->addWidget(m_importHintTitleLabel);
    importHintLayout->addWidget(m_importHintText, 1);

    importsRight->addWidget(m_importFunctionsTree);
    importsRight->addWidget(importHintPanel);
    importsRight->setStretchFactor(0, 3);
    importsRight->setStretchFactor(1, 2);
    importsRight->setSizes({280, 220});

    importsOuter->addWidget(m_importModulesTree);
    importsOuter->addWidget(importsRight);
    importsOuter->setStretchFactor(0, 1);
    importsOuter->setStretchFactor(1, 3);
    importsOuter->setSizes({280, 720});

    importsLayout->addWidget(importsOuter);
    m_analysisTabWidget->addTab(importsTab, LANG("UI/tab_imports"));

    // --------------------------------------------------------------------
    // Exports tab
    // --------------------------------------------------------------------
    QWidget *exportsTab = new QWidget();
    QVBoxLayout *exportsLayout = new QVBoxLayout(exportsTab);
    exportsLayout->setContentsMargins(0, 0, 0, 0);
    exportsLayout->setSpacing(4);

    m_exportsTree = new QTreeWidget();
    m_exportsTree->setAlternatingRowColors(true);
    m_exportsTree->setSelectionMode(QAbstractItemView::NoSelection);
    m_exportsTree->setHeaderLabels({
        LANG("UI/exports_header_name"),
        LANG("UI/exports_header_offset"),
        LANG("UI/exports_header_ordinal")
    });
    m_exportsTree->setColumnWidth(0, 260);
    m_exportsTree->setColumnWidth(1, 140);
    m_exportsTree->setColumnWidth(2, 100);

    exportsLayout->addWidget(m_exportsTree);
    m_analysisTabWidget->addTab(exportsTab, LANG("UI/tab_exports"));

    // --------------------------------------------------------------------
    // Dependencies tab
    // --------------------------------------------------------------------
    QWidget *dependenciesTab = new QWidget();
    QVBoxLayout *dependenciesLayout = new QVBoxLayout(dependenciesTab);
    dependenciesLayout->setContentsMargins(0, 0, 0, 0);

    QHBoxLayout *dependenciesToolbarLayout = new QHBoxLayout();
    dependenciesToolbarLayout->setContentsMargins(0, 0, 0, 4);
    dependenciesToolbarLayout->addStretch();
    m_dependenciesExpandAllButton = new QPushButton(LANG("UI/context_expand_all"));
    m_dependenciesExpandAllButton->setObjectName(QStringLiteral("dependenciesExpandAllButton"));
    m_dependenciesExpandAllButton->setEnabled(false);
    m_dependenciesExpandAllButton->setCursor(Qt::PointingHandCursor);
    m_dependenciesExpandAllButton->setStyleSheet(
        "QPushButton { padding: 4px 10px; font-size: 10px; } QPushButton:disabled { color: #999; }");
    m_dependenciesCollapseAllButton = new QPushButton(LANG("UI/context_collapse_all"));
    m_dependenciesCollapseAllButton->setObjectName(QStringLiteral("dependenciesCollapseAllButton"));
    m_dependenciesCollapseAllButton->setEnabled(false);
    m_dependenciesCollapseAllButton->setCursor(Qt::PointingHandCursor);
    m_dependenciesCollapseAllButton->setStyleSheet(
        "QPushButton { padding: 4px 10px; font-size: 10px; } QPushButton:disabled { color: #999; }");
    dependenciesToolbarLayout->addWidget(m_dependenciesExpandAllButton);
    dependenciesToolbarLayout->addWidget(m_dependenciesCollapseAllButton);
    dependenciesLayout->addLayout(dependenciesToolbarLayout);

    m_dependenciesTree = new QTreeWidget();
    m_dependenciesTree->setAlternatingRowColors(true);
    m_dependenciesTree->setSelectionMode(QAbstractItemView::NoSelection);
    // Context menu is handled in MainWindow (customContextMenuRequested); not the main window's contextMenuEvent.
    m_dependenciesTree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_dependenciesTree->setHeaderLabels({
        LANG("UI/deps_header_module"),
        LANG("UI/deps_header_resolved_path"),
        LANG("UI/deps_header_found")
    });
    m_dependenciesTree->setColumnWidth(0, 200);
    m_dependenciesTree->setColumnWidth(1, 350);
    m_dependenciesTree->setColumnWidth(2, 80);
    dependenciesLayout->addWidget(m_dependenciesTree);
    m_analysisTabWidget->addTab(dependenciesTab, LANG("UI/tab_dependencies"));

    // --------------------------------------------------------------------
    // Strings tab
    // --------------------------------------------------------------------
    QWidget *stringsTab = new QWidget();
    QVBoxLayout *stringsLayout = new QVBoxLayout(stringsTab);
    stringsLayout->setContentsMargins(0, 0, 0, 0);
    QHBoxLayout *stringsFilterLayout = new QHBoxLayout();
    stringsFilterLayout->setContentsMargins(0, 0, 0, 4);
    m_stringsFilterEdit = new QLineEdit();
    m_stringsFilterEdit->setPlaceholderText(LANG("UI/strings_filter_placeholder"));
    m_stringsFilterEdit->setClearButtonEnabled(true);
    m_stringsFilterEdit->setMaximumWidth(320);
    m_stringsTypeCombo = new QComboBox();
    m_stringsTypeCombo->addItem(LANG("UI/strings_filter_type_all"), QStringLiteral("all"));
    m_stringsTypeCombo->addItem(LANG("UI/strings_filter_type_ascii"), QStringLiteral("ascii"));
    m_stringsTypeCombo->addItem(LANG("UI/strings_filter_type_unicode"), QStringLiteral("unicode"));
    m_stringsTypeCombo->setMaximumWidth(120);
    m_stringsMinLengthSpin = new QSpinBox();
    m_stringsMinLengthSpin->setRange(2, 64);
    m_stringsMinLengthSpin->setValue(4);
    m_stringsMinLengthSpin->setPrefix(LANG("UI/strings_min_len_prefix"));
    m_stringsMinLengthSpin->setMaximumWidth(120);
    m_stringsSectionCombo = new QComboBox();
    m_stringsSectionCombo->setMaximumWidth(180);
    m_stringsSectionCombo->addItem(LANG("UI/strings_all_sections"), QStringLiteral("__all__"));
    m_stringsCancelButton = new QPushButton(LANG("UI/button_cancel"));
    m_stringsCancelButton->setEnabled(false);
    m_stringsCancelButton->setMaximumWidth(90);
    m_stringsExportButton = new QPushButton(LANG("UI/button_export"));
    m_stringsExportButton->setEnabled(false);
    m_stringsExportButton->setMaximumWidth(90);
    stringsFilterLayout->addWidget(m_stringsFilterEdit);
    stringsFilterLayout->addWidget(m_stringsTypeCombo);
    stringsFilterLayout->addWidget(m_stringsMinLengthSpin);
    stringsFilterLayout->addWidget(m_stringsSectionCombo);
    stringsFilterLayout->addWidget(m_stringsCancelButton);
    stringsFilterLayout->addWidget(m_stringsExportButton);
    stringsFilterLayout->addStretch();
    stringsLayout->addLayout(stringsFilterLayout);
    m_stringsTree = new QTreeWidget();
    m_stringsTree->setAlternatingRowColors(true);
    m_stringsTree->setSelectionMode(QAbstractItemView::NoSelection);
    m_stringsTree->setHeaderLabels({
        LANG("UI/strings_header_offset"),
        LANG("UI/strings_header_section"),
        LANG("UI/strings_header_type"),
        LANG("UI/strings_header_value")
    });
    m_stringsTree->setColumnWidth(0, 100);
    m_stringsTree->setColumnWidth(1, 120);
    m_stringsTree->setColumnWidth(2, 72);
    m_stringsTree->setColumnWidth(3, 420);
    stringsLayout->addWidget(m_stringsTree);
    m_analysisTabWidget->addTab(stringsTab, LANG("UI/tab_strings"));

    // --------------------------------------------------------------------
    // Findings tab (heuristic checklist)
    // --------------------------------------------------------------------
    QWidget *findingsTab = new QWidget();
    QVBoxLayout *findingsLayout = new QVBoxLayout(findingsTab);
    findingsLayout->setContentsMargins(0, 0, 0, 0);
    findingsLayout->setSpacing(4);

    m_findingsSummaryLabel = new QLabel(LANG("findings/summary_none"));
    m_findingsSummaryLabel->setWordWrap(true);
    m_findingsSummaryLabel->setStyleSheet(
        QStringLiteral("QLabel { color: #444; font-size: 11px; padding: 4px 2px; }"));
    findingsLayout->addWidget(m_findingsSummaryLabel);

    m_findingsTree = new QTreeWidget();
    m_findingsTree->setAlternatingRowColors(true);
    m_findingsTree->setRootIsDecorated(false);
    m_findingsTree->setHeaderLabels({
        LANG("findings/header_severity"),
        LANG("findings/header_title"),
        LANG("findings/header_detail")
    });
    m_findingsTree->setColumnWidth(0, 88);
    m_findingsTree->setColumnWidth(1, 220);
    m_findingsTree->setColumnWidth(2, 480);
    m_findingsTree->setCursor(Qt::PointingHandCursor);
    findingsLayout->addWidget(m_findingsTree, 1);

    m_analysisTabWidget->addTab(findingsTab, LANG("UI/tab_findings"));

    // --------------------------------------------------------------------

    mainLayout->addWidget(m_analysisTabWidget, 1);
}

/**
 * @brief Sets up the button section
 * @param mainLayout The main vertical layout to add the section to
 * 
 * This method creates the action buttons section:
 * - Copy to clipboard button for copying current content
 * - Save report button for saving analysis results
 * 
 * REFACTORING BENEFIT: Button layout and styling is now centralized,
 * making it easy to add new buttons or modify existing ones. Previously,
 * button setup was scattered throughout MainWindow.
 * 
 * DESIGN DECISIONS:
 * - Buttons are left-aligned for easy access
 * - Consistent styling and sizing for all buttons
 * - Icons provide visual context for button actions
 * - Buttons are initially disabled until file is loaded
 */
void UIManager::setupButtonSection(QVBoxLayout *mainLayout)
{
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    // Create Copy to Clipboard button
    m_copyButton = new QPushButton(LANG("UI/button_copy"));
    m_copyButton->setIcon(QIcon(":/images/imgs/copy.png"));
    m_copyButton->setStyleSheet("QPushButton { padding: 5px 10px; font-size: 11px; }");
    m_copyButton->setEnabled(false); // Initially disabled until file is loaded
    
    // Create Save Report button
    m_saveButton = new QPushButton(LANG("UI/button_save"));
    m_saveButton->setIcon(QIcon(":/images/imgs/save.png"));
    m_saveButton->setStyleSheet("QPushButton { padding: 5px 10px; font-size: 11px; }");
    m_saveButton->setEnabled(false); // Initially disabled until file is loaded
    
    // Add buttons to horizontal layout
    buttonLayout->addWidget(m_copyButton);
    buttonLayout->addWidget(m_saveButton);
    buttonLayout->addStretch(); // Push buttons to the left
    
    // Add the button section to the main layout
    mainLayout->addLayout(buttonLayout);
}

/**
 * @brief Sets up signal-slot connections for UI components
 * @param mainWindow Pointer to MainWindow for connecting signals to slots
 * 
 * This method handles all UI-specific connections, reducing the coupling
 * between MainWindow and individual UI components. MainWindow no longer
 * needs to know about m_refreshButton, m_copyButton, etc.
 * 
 * REFACTORING BENEFIT: Previously, MainWindow had to connect each UI
 * component individually. Now it just calls this method once and all
 * connections are established automatically.
 * 
 * CONNECTION STRATEGY:
 * - UI components emit signals (button clicks, tree selections)
 * - MainWindow provides slots to handle these signals
 * - UIManager connects the two, maintaining loose coupling
 */
void UIManager::setupConnections(MainWindow *mainWindow)
{
    // Connect UI signals to MainWindow slots
    // REFACTORING: This centralizes all UI connections in one place
    connect(m_refreshButton, &QPushButton::clicked, mainWindow, &MainWindow::on_action_Refresh_triggered);
    connect(m_copyButton, &QPushButton::clicked, mainWindow, &MainWindow::onCopyToClipboard);
    connect(m_saveButton, &QPushButton::clicked, mainWindow, &MainWindow::on_action_Save_Report_triggered);
    if (m_expandAllButton) {
        connect(m_expandAllButton, &QPushButton::clicked, mainWindow, &MainWindow::onExpandAll);
    }
    if (m_collapseAllButton) {
        connect(m_collapseAllButton, &QPushButton::clicked, mainWindow, &MainWindow::onCollapseAll);
    }
    if (m_dependenciesExpandAllButton) {
        connect(m_dependenciesExpandAllButton, &QPushButton::clicked, mainWindow, &MainWindow::onExpandAllDependencies);
    }
    if (m_dependenciesCollapseAllButton) {
        connect(m_dependenciesCollapseAllButton, &QPushButton::clicked, mainWindow, &MainWindow::onCollapseAllDependencies);
    }
    if (m_importModulesTree) {
        connect(m_importModulesTree, &QTreeWidget::currentItemChanged, mainWindow, &MainWindow::onImportModuleSelected);
    }
    if (m_importFunctionsTree) {
        connect(m_importFunctionsTree, &QTreeWidget::currentItemChanged, mainWindow, &MainWindow::onImportFunctionSelected);
    }
    // Use currentItemChanged to avoid duplicate work with itemClicked.
    // It also covers keyboard navigation and mouse selection.
    connect(m_peTree, &QTreeWidget::currentItemChanged, mainWindow,
            [mainWindow](QTreeWidgetItem *current, QTreeWidgetItem *) {
                if (current) {
                    mainWindow->onTreeItemClicked(current, 0);
                }
            });
    
    // Connect hex viewer signals
    if (m_hexViewer) {
        connect(m_hexViewer, &HexViewer::byteClicked, mainWindow, &MainWindow::onHexViewerByteClicked);
    }
    if (m_stringsFilterEdit) {
        connect(m_stringsFilterEdit, &QLineEdit::textChanged, mainWindow, &MainWindow::onStringsFilterChanged);
    }
    if (m_stringsTypeCombo) {
        connect(m_stringsTypeCombo, &QComboBox::currentIndexChanged, mainWindow, &MainWindow::onStringsFilterChanged);
    }
    if (m_stringsMinLengthSpin) {
        connect(m_stringsMinLengthSpin, QOverload<int>::of(&QSpinBox::valueChanged), mainWindow, &MainWindow::onStringsFilterChanged);
    }
    if (m_stringsSectionCombo) {
        connect(m_stringsSectionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), mainWindow, &MainWindow::onStringsFilterChanged);
    }
    if (m_stringsCancelButton) {
        connect(m_stringsCancelButton, &QPushButton::clicked, mainWindow, &MainWindow::onCancelStringsExtraction);
    }
    if (m_stringsExportButton) {
        connect(m_stringsExportButton, &QPushButton::clicked, mainWindow, &MainWindow::onExportStrings);
    }
    if (m_stringsTree) {
        connect(m_stringsTree, &QTreeWidget::itemDoubleClicked, mainWindow,
                &MainWindow::onStringsTreeItemDoubleClicked);
    }

    // Lazily populate heavy tabs in MainWindow.
    if (m_findingsTree) {
        connect(m_findingsTree, &QTreeWidget::itemClicked, mainWindow, &MainWindow::onFindingsItemClicked);
    }

    if (m_analysisTabWidget) {
        connect(m_analysisTabWidget, &QTabWidget::currentChanged, mainWindow, &MainWindow::onAnalysisTabChanged);
    }
}

/**
 * @brief Sets up application menus (placeholder for future use)
 * @param mainWindow Pointer to MainWindow for menu setup
 * 
 * REFACTORING NOTE: Currently, menus are still handled by MainWindow
 * because they're application-level concerns, not just UI components.
 * This method is a placeholder for future menu management if needed.
 * 
 * FUTURE ENHANCEMENTS:
 * - Dynamic menu creation based on application state
 * - Context-sensitive menu items
 * - Menu customization options
 */
void UIManager::setupMenus(MainWindow *mainWindow)
{
    // Menu setup will be handled by MainWindow
    // This method is a placeholder for future menu management
}

/**
 * @brief Sets up toolbar (placeholder for future use)
 * @param mainWindow Pointer to MainWindow for toolbar setup
 * 
 * REFACTORING NOTE: Toolbar setup is minimal and could be moved here
 * if we implement more sophisticated toolbar management.
 * 
 * FUTURE ENHANCEMENTS:
 * - Customizable toolbar with user-defined actions
 * - Toolbar state persistence
 * - Context-sensitive toolbar items
 */
void UIManager::setupToolbar(MainWindow *mainWindow)
{
    // Toolbar setup will be handled by MainWindow
    // This method is a placeholder for future toolbar management
}

/**
 * @brief Sets up status bar (placeholder for future use)
 * @param mainWindow Pointer to MainWindow for status bar setup
 * 
 * REFACTORING NOTE: Status bar setup is simple enough that it doesn't
 * need abstraction. This method is a placeholder for future use.
 * 
 * FUTURE ENHANCEMENTS:
 * - Dynamic status bar content
 * - Status bar customization options
 * - Progress indicators in status bar
 */
void UIManager::setupStatusBar(MainWindow *mainWindow)
{
    // Status bar setup will be handled by MainWindow
    // This method is a placeholder for future status bar management
}

/**
 * @brief Sets up context menu for the main window
 * @param mainWindow Pointer to MainWindow for context menu setup
 * 
 * This method creates a basic context menu with common actions.
 * It could be enhanced in the future to support dynamic menu content
 * based on the current state or selected items.
 * 
 * REFACTORING BENEFIT: Context menu setup is now centralized and
 * easy to modify without affecting other parts of the application.
 * 
 * FUTURE ENHANCEMENTS:
 * - Dynamic menu items based on selected content
 * - Context-sensitive actions
 * - User-customizable context menus
 */
void UIManager::setupContextMenu(MainWindow *mainWindow)
{
    m_contextMenu = new QMenu(mainWindow);
    QAction *copyAct = m_contextMenu->addAction(LANG("UI/context_copy"), mainWindow, &MainWindow::onCopyToClipboard);
    copyAct->setIcon(QIcon(QStringLiteral(":/images/imgs/copy.png")));
    m_contextMenu->addSeparator();
    QAction *expandAct = m_contextMenu->addAction(LANG("UI/context_expand_all"), mainWindow, &MainWindow::onExpandAll);
    expandAct->setIcon(QIcon(QStringLiteral(":/images/imgs/expand.png")));
    QAction *collapseAct = m_contextMenu->addAction(LANG("UI/context_collapse_all"), mainWindow, &MainWindow::onCollapseAll);
    collapseAct->setIcon(QIcon(QStringLiteral(":/images/imgs/collapse.png")));
}

/**
 * @brief Sets up hex viewer component (placeholder for future use)
 * @param mainWindow Pointer to MainWindow for hex viewer setup
 * 
 * REFACTORING NOTE: Hex viewer setup is currently handled in setupMainUI()
 * because it's part of the main UI layout. This method is a placeholder
 * for future hex viewer configuration if needed.
 * 
 * FUTURE ENHANCEMENTS:
 * - Hex viewer configuration options
 * - Custom hex viewer themes
 * - Advanced hex viewer features
 */
void UIManager::setupHexViewer(MainWindow *mainWindow)
{
    // Hex viewer setup will be handled by MainWindow
    // This method is a placeholder for future hex viewer configuration
}
