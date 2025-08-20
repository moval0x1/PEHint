/**
 * @file pe_ui_presenter.h
 * @brief PE UI Presenter for PEHint - Provides clean interface between data model and UI
 * 
 * This class implements the Presenter pattern to separate UI logic from business logic.
 * It acts as an intermediary between the PE data model and the UI components,
 * providing a clean, testable interface for displaying PE information.
 * 
 * REFACTORING PURPOSE:
 * - Extract UI presentation logic from the old monolithic PEParser
 * - Provide consistent data formatting and display logic
 * - Enable easy UI updates without modifying core parsing logic
 * - Support multiple UI representations of the same data
 * 
 * PRESENTER PATTERN IMPLEMENTATION:
 * - Handles data formatting and presentation logic
 * - Manages UI state and updates
 * - Provides consistent data access patterns
 * - Separates concerns between data and presentation
 * 
 * SOLID PRINCIPLES IMPLEMENTATION:
 * - Single Responsibility: Only handles UI presentation logic
 * - Open/Closed: Easy to extend with new presentation formats
 * - Liskov Substitution: Can be extended through inheritance
 * - Interface Segregation: Clean, focused presentation interface
 * - Dependency Inversion: Depends on abstractions, not concrete implementations
 */

#ifndef PE_UI_PRESENTER_H
#define PE_UI_PRESENTER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>
#include <QVariant>
#include <QTreeWidgetItem>
#include <QTextEdit>
#include <QTableWidget>

// Forward declarations
class PEDataModel;
class PESecurityAnalyzer;
struct SecurityAnalysisResult;

/**
 * @brief Display format options for PE data
 * 
 * This enum provides different display formats for PE information,
 * allowing users to choose their preferred way of viewing the data.
 */
enum class DisplayFormat {
    TREE_VIEW,          ///< Hierarchical tree structure
    TABLE_VIEW,         ///< Tabular data format
    TEXT_VIEW,          ///< Plain text format
    JSON_VIEW,          ///< JSON format for data export
    XML_VIEW,           ///< XML format for data export
    HTML_VIEW           ///< HTML format for rich display
};

/**
 * @brief UI presentation configuration
 * 
 * This structure contains configuration options for how PE data
 * should be presented in the user interface.
 */
struct UIPresentationConfig {
    DisplayFormat displayFormat;                    ///< Preferred display format
    bool showTechnicalDetails;                      ///< Show technical/low-level details
    bool showSecurityAnalysis;                      ///< Include security analysis results
    bool showFieldExplanations;                     ///< Show field explanations
    bool showOffsets;                               ///< Show field offsets and sizes
    bool showHexValues;                             ///< Show hexadecimal values
    bool showDecimalValues;                         ///< Show decimal values
    QString language;                               ///< Display language
    int maxTreeDepth;                               ///< Maximum tree expansion depth
    bool autoExpandCommonSections;                  ///< Auto-expand common PE sections
};

/**
 * @brief PE UI Presenter class
 * 
 * This class implements the Presenter pattern to provide a clean
 * interface between the PE data model and UI components. It handles
 * all data formatting, presentation logic, and UI state management
 * without mixing business logic with presentation concerns.
 * 
 * DESIGN PATTERN: This implements the "Presenter" pattern, which
 * is part of the Model-View-Presenter (MVP) architecture. The
 * Presenter acts as an intermediary between the Model (PEDataModel)
 * and the View (UI components), handling all presentation logic.
 * 
 * USAGE: Create an instance with a PEDataModel, configure the
 * presentation options, and use the various presentation methods
 * to display PE information in different formats.
 */
class PEUIPresenter : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructor for PEUIPresenter
     * @param dataModel Pointer to the PE data model
     * @param parent Parent QObject for memory management
     * 
     * This constructor initializes the presenter with a data model
     * and sets up default presentation configuration. The presenter
     * will use this data model to generate all UI presentations.
     */
    explicit PEUIPresenter(PEDataModel *dataModel, QObject *parent = nullptr);
    
    /**
     * @brief Destructor for PEUIPresenter
     * 
     * Ensures proper cleanup of resources and presentation data.
     */
    ~PEUIPresenter();
    
    // Main presentation interface
    
    /**
     * @brief Creates a tree widget representation of PE structure
     * @param config Presentation configuration options
     * @return List of tree widget items representing the PE structure
     * 
     * This method creates a hierarchical tree representation of the
     * PE file structure, suitable for QTreeWidget display. The tree
     * includes all major PE components with proper organization and
     * formatting based on the configuration options.
     */
    QList<QTreeWidgetItem*> createPEStructureTree(const UIPresentationConfig &config = UIPresentationConfig());
    
    /**
     * @brief Creates a table representation of PE data
     * @param config Presentation configuration options
     * @return Table data suitable for QTableWidget
     * 
     * This method creates a tabular representation of PE data,
     * organizing information into rows and columns for easy
     * viewing and comparison.
     */
    QList<QList<QVariant>> createPETableData(const UIPresentationConfig &config = UIPresentationConfig());
    
    /**
     * @brief Creates a text representation of PE information
     * @param config Presentation configuration options
     * @return Formatted text representation
     * 
     * This method creates a plain text representation of PE data,
     * suitable for display in QTextEdit or for export to text files.
     * The text is formatted for human readability.
     */
    QString createPETextReport(const UIPresentationConfig &config = UIPresentationConfig());
    
    /**
     * @brief Creates an HTML representation of PE information
     * @param config Presentation configuration options
     * @return HTML formatted representation
     * 
     * This method creates an HTML representation of PE data,
     * suitable for rich text display or export to HTML files.
     * The HTML includes styling and formatting for better readability.
     */
    QString createPEHTMLReport(const UIPresentationConfig &config = UIPresentationConfig());
    
    /**
     * @brief Creates a JSON representation of PE data
     * @param config Presentation configuration options
     * @return JSON formatted data
     * 
     * This method creates a JSON representation of PE data,
     * suitable for data export, API responses, or programmatic
     * processing by other tools.
     */
    QString createPEJSONReport(const UIPresentationConfig &config = UIPresentationConfig());
    
    /**
     * @brief Creates an XML representation of PE data
     * @param config Presentation configuration options
     * @return XML formatted data
     * 
     * This method creates an XML representation of PE data,
     * suitable for data export, integration with XML-based tools,
     * or structured data processing.
     */
    QString createPEXMLReport(const UIPresentationConfig &config = UIPresentationConfig());
    
    // Field-specific presentation methods
    
    /**
     * @brief Gets formatted explanation for a specific PE field
     * @param fieldName Name of the field to explain
     * @param config Presentation configuration options
     * @return Formatted field explanation
     * 
     * This method provides detailed explanations for PE fields,
     * including technical details, usage information, and security
     * implications based on the configuration options.
     */
    QString getFieldExplanation(const QString &fieldName, const UIPresentationConfig &config = UIPresentationConfig());
    
    /**
     * @brief Gets formatted field information including offset and size
     * @param fieldName Name of the field to get information for
     * @param config Presentation configuration options
     * @return Formatted field information
     * 
     * This method provides comprehensive field information including
     * offset, size, value, and other relevant details formatted
     * according to the presentation configuration.
     */
    QString getFieldInformation(const QString &fieldName, const UIPresentationConfig &config = UIPresentationConfig());
    
    /**
     * @brief Gets security analysis presentation
     * @param securityResult Security analysis results to present
     * @param config Presentation configuration options
     * @return Formatted security analysis presentation
     * 
     * This method creates a user-friendly presentation of security
     * analysis results, highlighting important findings and providing
     * actionable recommendations.
     */
    QString getSecurityAnalysisPresentation(const SecurityAnalysisResult &securityResult, 
                                          const UIPresentationConfig &config = UIPresentationConfig());
    
    // Configuration methods
    
    /**
     * @brief Sets the data model for the presenter
     * @param dataModel Pointer to the new PE data model
     * 
     * This method allows changing the data model used by the presenter,
     * useful for switching between different PE files or data sources.
     */
    void setDataModel(PEDataModel *dataModel);
    
    /**
     * @brief Gets the current data model
     * @return Pointer to the current PE data model
     * 
     * This method provides access to the current data model for
     * debugging, validation, or integration purposes.
     */
    PEDataModel* getDataModel() const;
    
    /**
     * @brief Sets the security analyzer for security presentations
     * @param securityAnalyzer Pointer to the security analyzer
     * 
     * This method sets the security analyzer used for generating
     * security-related presentations and analysis displays.
     */
    void setSecurityAnalyzer(PESecurityAnalyzer *securityAnalyzer);
    
    /**
     * @brief Gets the current security analyzer
     * @return Pointer to the current security analyzer
     * 
     * This method provides access to the current security analyzer
     * for debugging or integration purposes.
     */
    PESecurityAnalyzer* getSecurityAnalyzer() const;
    
    /**
     * @brief Sets default presentation configuration
     * @param config New default configuration
     * 
     * This method sets the default presentation configuration used
     * when no specific configuration is provided to presentation methods.
     */
    void setDefaultConfig(const UIPresentationConfig &config);
    
    /**
     * @brief Gets the default presentation configuration
     * @return Current default configuration
     * 
     * This method provides access to the current default configuration
     * for debugging or configuration management purposes.
     */
    UIPresentationConfig getDefaultConfig() const;
    
    // Utility methods
    
    /**
     * @brief Formats a value according to configuration options
     * @param value Raw value to format
     * @param config Presentation configuration options
     * @return Formatted value string
     * 
     * This method formats raw values according to the presentation
     * configuration, handling different data types and format preferences.
     */
    QString formatValue(const QVariant &value, const UIPresentationConfig &config);
    
    /**
     * @brief Formats an offset value with proper hexadecimal display
     * @param offset Offset value to format
     * @param config Presentation configuration options
     * @return Formatted offset string
     * 
     * This method formats offset values with proper hexadecimal
     * notation and optional decimal display based on configuration.
     */
    QString formatOffset(quint32 offset, const UIPresentationConfig &config);
    
    /**
     * @brief Formats a size value with appropriate units
     * @param size Size value in bytes
     * @param config Presentation configuration options
     * @return Formatted size string
     * 
     * This method formats size values with appropriate units (bytes,
     * KB, MB, GB) and precision based on the configuration.
     */
    QString formatSize(quint64 size, const UIPresentationConfig &config);
    
    /**
     * @brief Checks if the presenter has valid data to present
     * @return true if data is available, false otherwise
     * 
     * This method checks if the presenter has valid data available
     * for presentation, useful for UI state management.
     */
    bool hasValidData() const;
    
    /**
     * @brief Gets a summary of available PE data
     * @return Summary string describing available data
     * 
     * This method provides a human-readable summary of what PE data
     * is available for presentation, useful for UI status displays.
     */
    QString getDataSummary() const;
    
    // Signals for UI updates
    
signals:
    /**
     * @brief Emitted when presentation data is updated
     * @param message Description of the update
     * 
     * This signal notifies the UI when presentation data has been
     * updated, allowing for real-time UI refresh and status updates.
     */
    void presentationUpdated(const QString &message);
    
    /**
     * @brief Emitted when presentation configuration changes
     * @param config New configuration settings
     * 
     * This signal notifies the UI when presentation configuration
     * has changed, allowing for UI updates based on new settings.
     */
    void configurationChanged(const UIPresentationConfig &config);
    
    /**
     * @brief Emitted when data model changes
     * @param hasData Whether new data is available
     * 
     * This signal notifies the UI when the underlying data model
     * has changed, allowing for appropriate UI state updates.
     */
    void dataModelChanged(bool hasData);

private:
    // Private helper methods for internal presentation logic
    
    /**
     * @brief Creates tree items for DOS header information
     * @param config Presentation configuration options
     * @return List of tree items for DOS header
     * 
     * This method creates tree items representing DOS header
     * information, including all relevant fields and values.
     */
    QList<QTreeWidgetItem*> createDOSHeaderTree(const UIPresentationConfig &config);
    
    /**
     * @brief Creates tree items for PE header information
     * @param config Presentation configuration options
     * @return List of tree items for PE header
     * 
     * This method creates tree items representing PE header
     * information, including file header and optional header details.
     */
    QList<QTreeWidgetItem*> createPEHeaderTree(const UIPresentationConfig &config);
    
    /**
     * @brief Creates tree items for section information
     * @param config Presentation configuration options
     * @return List of tree items for sections
     * 
     * This method creates tree items representing section
     * information, including all section headers and characteristics.
     */
    QList<QTreeWidgetItem*> createSectionTree(const UIPresentationConfig &config);
    
    /**
     * @brief Creates tree items for import/export information
     * @param config Presentation configuration options
     * @return List of tree items for imports/exports
     * 
     * This method creates tree items representing import and
     * export table information with proper organization.
     */
    QList<QTreeWidgetItem*> createImportExportTree(const UIPresentationConfig &config);
    
    /**
     * @brief Creates tree items for data directory information
     * @param config Presentation configuration options
     * @return List of tree items for data directories
     * 
     * This method creates tree items representing data directory
     * information, including all 16 standard data directories.
     */
    QList<QTreeWidgetItem*> createDataDirectoryTree(const UIPresentationConfig &config);
    
    /**
     * @brief Creates tree items for resource information
     * @param config Presentation configuration options
     * @return List of tree items for resources
     * 
     * This method creates tree items representing resource
     * information, including all resource types and entries.
     */
    QList<QTreeWidgetItem*> createResourceTree(const UIPresentationConfig &config);
    
    // Data members
    
    PEDataModel *m_dataModel;                       ///< Pointer to PE data model
    PESecurityAnalyzer *m_securityAnalyzer;         ///< Pointer to security analyzer
    UIPresentationConfig m_defaultConfig;           ///< Default presentation configuration
    
    // Constants for presentation formatting
    
    static const int DEFAULT_MAX_TREE_DEPTH = 5;    ///< Default maximum tree depth
    static const QString DEFAULT_LANGUAGE;          ///< Default display language
};

#endif // PE_UI_PRESENTER_H
