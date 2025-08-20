/**
 * @file pe_ui_manager.h
 * @brief UI Manager class for PEHint - Extracted from MainWindow during refactoring
 * 
 * This class was created during the refactoring to address the Single Responsibility
 * Principle violation in MainWindow. The original MainWindow was doing too many things:
 * - Managing the application lifecycle
 * - Creating and configuring UI components
 * - Handling PE file parsing
 * - Managing user interactions
 * 
 * REFACTORING PURPOSE:
 * - Extract UI component creation and layout logic from MainWindow
 * - Reduce MainWindow complexity from ~1500 lines to under 500 lines
 * - Make UI changes independent of application logic changes
 * - Improve maintainability and testability
 * 
 * RESPONSIBILITIES:
 * - Create and configure all UI components (labels, buttons, tree, text areas)
 * - Set up UI layouts and styling
 * - Connect UI signals to MainWindow slots
 * - Manage UI component references for MainWindow access
 * 
 * ARCHITECTURAL BENEFITS:
 * - Single Responsibility: UIManager only handles UI creation and layout
 * - Open/Closed: Easy to add new UI components without modifying MainWindow
 * - Dependency Inversion: MainWindow depends on UIManager interface, not UI details
 * - Reduced Coupling: UI changes don't affect MainWindow's core logic
 */

#ifndef PE_UI_MANAGER_H
#define PE_UI_MANAGER_H

#include <QObject>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QTreeWidget>
#include <QTextEdit>
#include <QMenu>
#include "hexviewer.h"

class MainWindow;

/**
 * @brief Manages all UI component creation and layout for PEHint
 * 
 * This class encapsulates the UI setup logic that was previously scattered
 * throughout MainWindow. It follows the Single Responsibility Principle by
 * focusing solely on UI component creation and configuration.
 * 
 * DESIGN PATTERN: This implements the "Extract Class" refactoring pattern,
 * where a large class with multiple responsibilities is broken down into
 * smaller, focused classes.
 * 
 * USAGE: MainWindow creates a UIManager instance and delegates UI setup to it.
 * The UIManager creates all UI components and stores references to them,
 * allowing MainWindow to access them when needed.
 */
class UIManager : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructor for UIManager
     * @param parent Pointer to the MainWindow that owns this UIManager
     * 
     * The parent relationship ensures proper memory management and allows
     * the UIManager to access MainWindow methods when setting up connections.
     */
    explicit UIManager(MainWindow *parent = nullptr);
    
    // UI Components - These are created by UIManager but accessible to MainWindow
    // REFACTORING NOTE: These were previously direct members of MainWindow
    // Moving them here centralizes UI component management
    
    QLabel *m_fileInfoLabel;        ///< Displays current file information
    QProgressBar *m_progressBar;    ///< Shows parsing progress
    QLabel *m_progressLabel;        ///< Shows progress status messages
    QPushButton *m_refreshButton;   ///< Refreshes the current analysis
    QPushButton *m_copyButton;      ///< Copies current content to clipboard
    QPushButton *m_saveButton;      ///< Saves analysis report to file
    QTreeWidget *m_peTree;         ///< Displays PE structure hierarchy
    QTextEdit *m_fieldExplanationText; ///< Shows field explanations
    QMenu *m_contextMenu;           ///< Right-click context menu
    HexViewer *m_hexViewer;        ///< Hex viewer for binary data display
    
    // Setup methods - These replace the UI setup logic that was in MainWindow
    
    /**
     * @brief Sets up the main UI layout and components
     * @param centralWidget The central widget to populate
     * 
     * This method replaces the complex UI setup that was previously in
     * MainWindow::setupUI(). It creates all UI components, sets up layouts,
     * and configures styling in a centralized, maintainable way.
     * 
     * REFACTORING BENEFIT: Previously, MainWindow had to know about QVBoxLayout,
     * QHBoxLayout, and other Qt layout classes. Now MainWindow just calls
     * this method and gets a fully configured UI.
     */
    void setupMainUI(QWidget *centralWidget);
    
    /**
     * @brief Sets up signal-slot connections for UI components
     * @param mainWindow Pointer to MainWindow for connecting signals to slots
     * 
     * This method handles all UI-specific connections, reducing the coupling
     * between MainWindow and individual UI components. MainWindow no longer
     * needs to know about m_refreshButton, m_copyButton, etc.
     * 
     * REFACTORING BENEFIT: Previously, MainWindow had to connect each UI
     * component individually. Now it just calls this method once.
     */
    void setupConnections(MainWindow *mainWindow);
    
    /**
     * @brief Sets up application menus (placeholder for future use)
     * @param mainWindow Pointer to MainWindow for menu setup
     * 
     * REFACTORING NOTE: Currently, menus are still handled by MainWindow
     * because they're application-level concerns. This method is a placeholder
     * for future menu management if needed.
     */
    void setupMenus(MainWindow *mainWindow);
    
    /**
     * @brief Sets up toolbar (placeholder for future use)
     * @param mainWindow Pointer to MainWindow for toolbar setup
     * 
     * REFACTORING NOTE: Toolbar setup is minimal and could be moved here
     * if we implement more sophisticated toolbar management.
     */
    void setupToolbar(MainWindow *mainWindow);
    
    /**
     * @brief Sets up status bar (placeholder for future use)
     * @param mainWindow Pointer to MainWindow for status bar setup
     * 
     * REFACTORING NOTE: Status bar setup is simple enough that it doesn't
     * need abstraction. This method is a placeholder for future use.
     */
    void setupStatusBar(MainWindow *mainWindow);
    
    /**
     * @brief Sets up context menu for the main window
     * @param mainWindow Pointer to MainWindow for context menu setup
     * 
     * This method creates a basic context menu with common actions.
     * It could be enhanced in the future to support dynamic menu content
     * based on the current state or selected items.
     */
    void setupContextMenu(MainWindow *mainWindow);
    
    /**
     * @brief Sets up hex viewer component (placeholder for future use)
     * @param mainWindow Pointer to MainWindow for hex viewer setup
     * 
     * REFACTORING NOTE: Hex viewer setup is currently handled in setupMainUI()
     * because it's part of the main UI layout. This method is a placeholder
     * for future hex viewer configuration if needed.
     */
    void setupHexViewer(MainWindow *mainWindow);
    
private:
    MainWindow *m_mainWindow; ///< Reference to the parent MainWindow
    
    // Private helper methods for organizing UI setup into logical sections
    
    /**
     * @brief Sets up the file information section (file info label + refresh button)
     * @param mainLayout The main vertical layout to add the section to
     * 
     * This method creates the top section of the UI that shows:
     * - Current file information
     * - Refresh button for reloading analysis
     * 
     * REFACTORING BENEFIT: Previously, this logic was mixed with other UI setup
     * in MainWindow. Now it's organized into logical, focused methods.
     */
    void setupFileInfoSection(QVBoxLayout *mainLayout);
    
    /**
     * @brief Sets up the progress section (progress bar + status label)
     * @param mainLayout The main vertical layout to add the section to
     * 
     * This method creates the progress tracking section that shows:
     * - Progress bar for parsing operations
     * - Status label for current operation description
     * 
     * REFACTORING BENEFIT: Progress UI is now centralized and easy to modify
     * without affecting other parts of the application.
     */
    void setupProgressSection(QVBoxLayout *mainLayout);
    
    /**
     * @brief Sets up the tree section (PE structure tree + field explanations)
     * @param mainLayout The main vertical layout to add the section to
     * 
     * This method creates the main analysis display section:
     * - PE structure tree widget
     * - Field explanation text area
     * 
     * REFACTORING BENEFIT: Tree and explanation UI is now organized together,
     * making it easier to maintain the relationship between these components.
     */
    void setupTreeSection(QVBoxLayout *mainLayout);
    
    /**
     * @brief Sets up the button section (copy + save buttons)
     * @param mainLayout The main vertical layout to add the section to
     * 
     * This method creates the action buttons section:
     * - Copy to clipboard button
     * - Save report button
     * 
     * REFACTORING BENEFIT: Button layout and styling is now centralized,
     * making it easy to add new buttons or modify existing ones.
     */
    void setupButtonSection(QVBoxLayout *mainLayout);
};

#endif // PE_UI_MANAGER_H
