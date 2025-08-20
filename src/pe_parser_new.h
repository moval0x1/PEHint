/**
 * @file pe_parser_new.h
 * @brief New modular PE Parser for PEHint - Replaces the old monolithic PEParser
 * 
 * This class represents the refactored PE parsing architecture that addresses
 * the Single Responsibility Principle violations in the original PEParser.
 * 
 * REFACTORING PURPOSE:
 * - Break down the monolithic PEParser (63.68 KB, 1558 lines) into focused components
 * - Separate parsing logic from data storage and UI concerns
 * - Make the codebase more maintainable and testable
 * - Follow SOLID principles for better architecture
 * 
 * ARCHITECTURAL DECISIONS:
 * - PEParserNew: Focuses solely on parsing logic and orchestration
 * - PEDataModel: Stores parsed data and provides access methods
 * - PEDataDirectoryParser: Handles specific data directory parsing
 * - PEImportExportParser: Handles import/export table parsing
 * - PEUtils: Provides utility functions for PE format operations
 * 
 * SOLID PRINCIPLES IMPLEMENTATION:
 * - Single Responsibility: Each class has one clear purpose
 * - Open/Closed: Easy to extend with new parsing features
 * - Liskov Substitution: Can be extended through inheritance
 * - Interface Segregation: Clean, focused interfaces
 * - Dependency Inversion: Depends on abstractions, not concrete implementations
 */

#ifndef PE_PARSER_NEW_H
#define PE_PARSER_NEW_H

#include "pe_data_model.h"
#include "pe_structures.h"
#include "pe_data_directory_parser.h"
#include "language_manager.h"
#include <QObject>
#include <QString>
#include <QByteArray>
#include <QFile>
#include <QFuture>
#include <QMutex>
#include <QtConcurrent/QtConcurrent>
#include <QTreeWidgetItem>
#include <QJsonDocument>
#include <QJsonObject>

/**
 * @brief New modular PE Parser that follows SOLID principles
 * 
 * This class replaces the old monolithic PEParser that violated the Single
 * Responsibility Principle by handling parsing, data storage, and UI concerns.
 * 
 * NEW ARCHITECTURE:
 * - PEParserNew: Orchestrates parsing and manages the parsing workflow
 * - PEDataModel: Stores all parsed PE data in an organized structure
 * - PEDataDirectoryParser: Handles the 16 Data Directory entries
 * - PEImportExportParser: Handles import and export table parsing
 * - PEUtils: Provides utility functions for PE format operations
 * 
 * BENEFITS OF THE NEW ARCHITECTURE:
 * - Easier to test individual components
 * - Easier to add new parsing features
 * - Better separation of concerns
 * - More maintainable codebase
 * - Follows Microsoft PE Format specification more closely
 * 
 * BACKWARD COMPATIBILITY:
 * - Provides adapter methods for UI compatibility
 * - Maintains the same public interface for existing code
 * - Gradual migration path from old architecture
 */
class PEParserNew : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructor for PEParserNew
     * @param parent Parent QObject for memory management
     * 
     * This constructor initializes the new modular architecture:
     * - Creates a PEDataModel for storing parsed data
     * - Initializes PEDataDirectoryParser for data directory handling
     * - Sets up async parsing support for large files
     */
    explicit PEParserNew(QObject *parent = nullptr);
    
    /**
     * @brief Destructor for PEParserNew
     * 
     * Ensures proper cleanup of resources and cancels any ongoing
     * async parsing operations.
     */
    ~PEParserNew();
    
    // Main parsing interface - Core functionality for PE file analysis
    
    /**
     * @brief Loads and parses a PE file synchronously
     * @param filePath Path to the PE file to parse
     * @return true if parsing succeeded, false otherwise
     * 
     * This method provides synchronous parsing for small files or when
     * blocking behavior is acceptable. It follows the Microsoft PE
     * Format specification for accurate parsing.
     */
    bool loadFile(const QString &filePath);
    
    /**
     * @brief Loads and parses a PE file asynchronously
     * @param filePath Path to the PE file to parse
     * 
     * This method provides non-blocking parsing for large files or
     * when the UI should remain responsive during parsing. It uses
     * QtConcurrent for background processing.
     */
    void loadFileAsync(const QString &filePath);
    
    /**
     * @brief Clears all parsed data and resets the parser state
     * 
     * This method is called when switching files or when errors occur.
     * It ensures clean state for the next parsing operation.
     */
    void clear();
    
    // Status queries - Information about current parser state
    
    /**
     * @brief Checks if the parser has valid parsed data
     * @return true if data is valid, false otherwise
     * 
     * This method indicates whether the last parsing operation succeeded
     * and produced valid PE data.
     */
    bool isValid() const;
    
    /**
     * @brief Checks if the parser is currently parsing a file
     * @return true if parsing is in progress, false otherwise
     * 
     * This method is useful for UI state management and preventing
     * multiple simultaneous parsing operations.
     */
    bool isParsing() const;
    
    /**
     * @brief Gets the path of the currently loaded file
     * @return File path or empty string if no file is loaded
     * 
     * This method provides access to the current file path for UI
     * display and file operations.
     */
    QString getFilePath() const;
    
    /**
     * @brief Gets a human-readable representation of the file size
     * @return Formatted file size string (e.g., "1.5 MB")
     * 
     * This method converts the raw file size to a user-friendly format
     * for display in the UI.
     */
    QString getFileSizeString() const;
    
    /**
     * @brief Gets the raw file size in bytes
     * @return File size in bytes
     */
    qint64 getFileSize() const { return m_dataModel.getFileSize(); }
    
    /**
     * @brief Checks if the current file is considered "large"
     * @return true if file exceeds the large file threshold
     * 
     * This method helps determine parsing strategy for large files,
     * allowing optimization of memory usage and parsing performance.
     */
    bool isLargeFile() const;
    
    /**
     * @brief Checks if the current file is considered "very large"
     * @return true if file exceeds the very large file threshold
     * 
     * This method helps determine parsing strategy for very large files,
     * allowing aggressive optimization of memory usage and parsing performance.
     */
    bool isVeryLargeFile() const;
    
    /**
     * @brief Loads large files using streaming approach to avoid memory issues
     * @return true if loading succeeded, false otherwise
     * 
     * This method reads only essential headers and structure information
     * without loading the entire file into memory.
     */
    bool loadLargeFileStreaming();
    
    // Data access - Access to parsed PE information
    
    /**
     * @brief Gets access to the parsed PE data model
     * @return Const reference to the PEDataModel containing all parsed data
     * 
     * This method provides access to the organized PE data structure.
     * The const reference ensures data integrity while allowing read access.
     */
    const PEDataModel& getDataModel() const;
    
    // Field explanation and offset methods (for UI compatibility)
    // REFACTORING: These methods provide backward compatibility with the old UI
    // They will be enhanced in future iterations to use the new data model
    
    /**
     * @brief Gets explanation text for a specific PE field
     * @param fieldName Name of the field to get explanation for
     * @return HTML-formatted explanation text
     * 
     * REFACTORING NOTE: This method currently returns placeholder text.
     * Future implementation will use the new PEDataModel to provide
     * accurate, detailed field explanations.
     */
    QString getFieldExplanation(const QString &fieldName);
    
    /**
     * @brief Gets the file offset and size for a specific PE field
     * @param fieldName Name of the field to get offset information for
     * @return Pair containing (offset, size) in bytes
     * 
     * REFACTORING NOTE: This method currently returns placeholder values.
     * Future implementation will calculate actual offsets from the parsed
     * PE structure data.
     */
    QPair<quint32, quint32> getFieldOffset(const QString &fieldName);
    
    /**
     * @brief Sets the language for field explanations
     * @param language Language code for explanations
     * 
     * REFACTORING NOTE: This method is a placeholder for future
     * internationalization support in the new architecture.
     */
    void setLanguage(const QString &language);
    
    // Tree building method (for UI compatibility)
    
    /**
     * @brief Builds a tree structure for UI display
     * @return List of tree items representing the PE structure
     * 
     * REFACTORING NOTE: This method currently returns an empty list.
     * Future implementation will build the tree from the new PEDataModel,
     * providing a comprehensive view of the PE structure.
     */
    QList<QTreeWidgetItem*> getPEStructureTree();
    
    // Async parsing support - For handling large files without blocking UI
    
    /**
     * @brief Cancels any ongoing async parsing operation
     * 
     * This method allows users to cancel long-running parsing operations
     * for large files, improving the user experience.
     */
    void cancelParsing();
    
    // Signals - Communication with the UI layer
    
signals:
    /**
     * @brief Emitted during parsing to show progress
     * @param percentage Progress percentage (0-100)
     * @param message Description of current parsing step
     * 
     * This signal allows the UI to show real-time progress information
     * during file parsing, especially useful for large files.
     */
    void parsingProgress(int percentage, const QString &message);
    
    /**
     * @brief Emitted when parsing completes
     * @param success true if parsing succeeded, false if it failed
     * 
     * This signal notifies the UI that parsing has finished, allowing
     * it to update its state and display the results.
     */
    void parsingComplete(bool success);
    
    /**
     * @brief Emitted when parsing errors occur
     * @param error Description of the error that occurred
     * 
     * This signal provides detailed error information to the UI for
     * user notification and debugging purposes.
     */
    void errorOccurred(const QString &error);
    
    /**
     * @brief Emitted when the language is changed
     * @param language New language code
     * 
     * This signal notifies the UI that the language has been changed,
     * allowing it to update its display accordingly.
     */
    void languageChanged(const QString &language);
    
    // Private slots - Internal signal handling
    
private slots:
    /**
     * @brief Handles completion of async parsing operations
     * 
     * This slot is called when background parsing completes, ensuring
     * proper signal emission and state management.
     */
    void onAsyncParsingComplete();
    
    // Private methods - Core parsing logic implementation
    
private:
    // Core parsing methods (Microsoft PE Format compliant)
    // These methods implement the actual PE parsing logic according to
    // the Microsoft PE Format specification
    
    /**
     * @brief Parses the DOS header of the PE file
     * @return true if DOS header is valid, false otherwise
     * 
     * This method validates the DOS header and extracts the PE header
     * offset, following the Microsoft PE Format specification.
     */
    bool parseDOSHeader();
    
    /**
     * @brief Parses the PE headers (signature, file header, optional header)
     * @return true if PE headers are valid, false otherwise
     * 
     * This method parses the core PE structure headers, including
     * the file header and optional header with all their fields.
     */
    bool parsePEHeaders();
    
    /**
     * @brief Parses the section table and section headers
     * @return true if sections are valid, false otherwise
     * 
     * This method parses all section headers, providing information
     * about code, data, and other sections in the PE file.
     */
    bool parseSections();
    
    /**
     * @brief Parses the data directory entries
     * @return true if data directories are valid, false otherwise
     * 
     * NEW ARCHITECTURE: This method uses the specialized PEDataDirectoryParser
     * to handle all 16 Data Directory entries according to the Microsoft
     * PE Format specification.
     */
    bool parseDataDirectories(); // NEW: Proper data directory parsing
    
    // Helper methods - Utility functions for parsing operations
    
    /**
     * @brief Validates the overall file structure
     * @return true if file is valid, false otherwise
     * 
     * This method performs basic file validation before parsing begins,
     * checking file size and basic structure requirements.
     */
    bool validateFile();
    
    /**
     * @brief Validates parsed headers for consistency
     * @return true if headers are consistent, false otherwise
     * 
     * This method performs cross-validation of parsed headers to ensure
     * they form a valid, consistent PE structure.
     */
    bool validateHeaders();
    
    /**
     * @brief Converts RVA (Relative Virtual Address) to file offset
     * @param rva Relative Virtual Address to convert
     * @return File offset in bytes, or 0 if conversion fails
     * 
     * This method implements the RVA-to-file-offset conversion algorithm
     * as specified in the Microsoft PE Format documentation.
     */
    quint32 rvaToFileOffset(quint32 rva);
    
    /**
     * @brief Finds a configuration file in multiple possible locations
     * @param fileName Name of the configuration file to find
     * @return Full path to the found configuration file, or empty string if not found
     * 
     * This method searches for configuration files in multiple locations:
     * 1. Relative to executable (for deployed builds)
     * 2. Relative to executable but going up to project root (for development builds)
     * 3. Current working directory
     * 4. Source directory (for development builds)
     */
    QString findConfigFile(const QString &fileName) const;
    
    // Tree building methods - For UI compatibility
    
    /**
     * @brief Adds DOS header fields to a tree item
     * @param parent Parent tree item
     * @param dosHeader DOS header structure
     */
    void addDOSHeaderFields(QTreeWidgetItem *parent, const IMAGE_DOS_HEADER *dosHeader);
    
    /**
     * @brief Adds PE header fields to a tree item
     * @param parent Parent tree item
     * @param fileHeader File header structure
     */
    void addPEHeaderFields(QTreeWidgetItem *parent, const IMAGE_FILE_HEADER *fileHeader);
    
    /**
     * @brief Adds optional header fields to a tree item
     * @param parent Parent tree item
     * @param optionalHeader Optional header structure
     */
    void addOptionalHeaderFields(QTreeWidgetItem *parent, const IMAGE_OPTIONAL_HEADER *optionalHeader);
    
    /**
     * @brief Adds section fields to a tree item
     * @param parent Parent tree item
     */
    void addSectionFields(QTreeWidgetItem *parent);
    
    /**
     * @brief Adds data directory fields to a tree item
     * @param parent Parent tree item
     */
    void addDataDirectoryFields(QTreeWidgetItem *parent);
    
    /**
     * @brief Adds a field to a tree item
     * @param parent Parent tree item
     * @param name Field name
     * @param value Field value
     * @param offset Field offset
     * @param size Field size
     */
    void addTreeField(QTreeWidgetItem *parent, const QString &name, const QString &value, quint32 offset, quint32 size);
    
    // File data - Storage for file content and parsed information
    
    QFile m_file;                    ///< File handle for reading PE data
    QByteArray m_fileData;           ///< Raw file data in memory
    PEDataModel m_dataModel;         ///< NEW: Organized storage for parsed data
    PEDataDirectoryParser m_dataDirectoryParser; ///< NEW: Specialized data directory parser
    
    // Async parsing support - For non-blocking file processing
    
    bool m_isValid;                  ///< Flag indicating if the current file is valid
    bool m_isParsing;                ///< Flag indicating parsing is in progress
    QMutex m_parsingMutex;           ///< Mutex for thread-safe parsing operations
    QFuture<void> m_parsingFuture;   ///< Future for async parsing operations
    
    // Constants - Configuration values for parsing behavior
    
    static const qint64 LARGE_FILE_THRESHOLD = 5 * 1024 * 1024;      ///< 5MB threshold for large files
    static const qint64 VERY_LARGE_FILE_THRESHOLD = 20 * 1024 * 1024; ///< 20MB threshold for very large files
};

#endif // PE_PARSER_NEW_H
