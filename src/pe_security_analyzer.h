/**
 * @file pe_security_analyzer.h
 * @brief PE Security Analyzer for PEHint - Analyzes PE files for security concerns
 * 
 * This class implements security analysis for PE files, focusing on:
 * - Malware detection patterns
 * - Suspicious characteristics analysis
 * - Security feature identification
 * - Risk assessment and scoring
 * 
 * REFACTORING PURPOSE:
 * - Extract security analysis logic from the old monolithic PEParser
 * - Provide focused, testable security analysis functionality
 * - Enable independent security analysis without full PE parsing
 * - Support both real-time and batch security analysis
 * 
 * SECURITY ANALYSIS CAPABILITIES:
 * - File entropy analysis for packed/obfuscated content
 * - Suspicious import/export analysis
 * - Section characteristics security assessment
 * - Resource analysis for malicious content
 * - Digital signature validation
 * - Anti-debugging and anti-VM detection
 * 
 * SOLID PRINCIPLES IMPLEMENTATION:
 * - Single Responsibility: Only handles security analysis
 * - Open/Closed: Easy to extend with new security checks
 * - Liskov Substitution: Can be extended through inheritance
 * - Interface Segregation: Clean, focused security analysis interface
 * - Dependency Inversion: Depends on abstractions, not concrete implementations
 */

#ifndef PE_SECURITY_ANALYZER_H
#define PE_SECURITY_ANALYZER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>
#include <QByteArray>
#include <QFile>

// Forward declarations
class SecurityConfigManager;

// Forward declarations to avoid circular dependencies
struct IMAGE_DOS_HEADER;
struct IMAGE_FILE_HEADER;
struct IMAGE_OPTIONAL_HEADER;
struct IMAGE_SECTION_HEADER;

/**
 * @brief Security risk levels for PE file analysis
 * 
 * This enum provides standardized risk levels that can be used
 * consistently across the application for security reporting.
 */
enum class SecurityRiskLevel {
    SAFE = 0,           ///< No security concerns detected
    LOW = 1,            ///< Minor security concerns
    MEDIUM = 2,         ///< Moderate security concerns
    HIGH = 3,           ///< Significant security concerns
    CRITICAL = 4        ///< Critical security issues detected
};

/**
 * @brief Security analysis result structure
 * 
 * This structure contains comprehensive security analysis results,
 * including risk assessment, detected issues, and recommendations.
 */
struct SecurityAnalysisResult {
    SecurityRiskLevel riskLevel;                    ///< Overall security risk level
    int riskScore;                                  ///< Numerical risk score (0-100)
    QStringList detectedIssues;                     ///< List of detected security issues
    QStringList recommendations;                    ///< Security recommendations
    QMap<QString, QString> detailedAnalysis;       ///< Detailed analysis by category
    bool isPacked;                                  ///< Indicates if file appears packed
    bool isObfuscated;                              ///< Indicates if file appears obfuscated
    bool hasAntiDebug;                              ///< Indicates anti-debugging techniques
    bool hasAntiVM;                                 ///< Indicates anti-VM techniques
    QString entropyAnalysis;                        ///< File entropy analysis results
    QString digitalSignatureStatus;                 ///< Digital signature validation status
};

/**
 * @brief PE Security Analyzer class
 * 
 * This class provides comprehensive security analysis for PE files,
 * implementing various detection techniques and security assessments.
 * It follows the Single Responsibility Principle by focusing solely
 * on security analysis functionality.
 * 
 * DESIGN PATTERN: This implements the "Strategy" pattern, allowing
 * different security analysis strategies to be implemented and
 * combined for comprehensive analysis.
 * 
 * USAGE: Create an instance, configure analysis options, and call
 * analyzeFile() to perform security analysis on PE files.
 */
class PESecurityAnalyzer : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructor for PESecurityAnalyzer
     * @param parent Parent QObject for memory management
     * 
     * This constructor initializes the security analyzer with default
     * analysis settings and prepares it for security analysis operations.
     */
    explicit PESecurityAnalyzer(QObject *parent = nullptr);
    
    /**
     * @brief Destructor for PESecurityAnalyzer
     * 
     * Ensures proper cleanup of resources and analysis data.
     */
    ~PESecurityAnalyzer();
    
    // Main security analysis interface
    
    /**
     * @brief Performs comprehensive security analysis on a PE file
     * @param filePath Path to the PE file to analyze
     * @return SecurityAnalysisResult containing analysis findings
     * 
     * This method performs a complete security analysis including:
     * - File entropy analysis
     * - Section characteristics analysis
     * - Import/export analysis
     * - Resource analysis
     * - Digital signature validation
     * - Anti-debugging detection
     * - Anti-VM detection
     * 
     * The analysis is comprehensive and follows industry best practices
     * for PE file security assessment.
     */
    SecurityAnalysisResult analyzeFile(const QString &filePath);
    
    /**
     * @brief Performs security analysis on raw PE data
     * @param peData Raw PE file data as QByteArray
     * @return SecurityAnalysisResult containing analysis findings
     * 
     * This method is useful when you already have the PE data in memory
     * and want to perform security analysis without file I/O operations.
     */
    SecurityAnalysisResult analyzeData(const QByteArray &peData);
    
    /**
     * @brief Performs quick security scan for basic threats
     * @param filePath Path to the PE file to scan
     * @return SecurityRiskLevel indicating basic threat level
     * 
     * This method provides a fast, lightweight security assessment
     * suitable for real-time scanning and initial threat detection.
     */
    SecurityRiskLevel quickScan(const QString &filePath);
    
    // Configuration methods
    
    /**
     * @brief Enables or disables specific security checks
     * @param checkName Name of the security check to configure
     * @param enabled Whether the check should be enabled
     * 
     * This method allows fine-tuning of security analysis by enabling
     * or disabling specific security checks based on requirements.
     */
    void setSecurityCheckEnabled(const QString &checkName, bool enabled);
    
    /**
     * @brief Sets the sensitivity level for security analysis
     * @param sensitivity Sensitivity level (1-10, where 10 is most sensitive)
     * 
     * This method adjusts the sensitivity of security detection,
     * allowing customization of false positive vs. false negative trade-offs.
     */
    void setSensitivityLevel(int sensitivity);
    
    /**
     * @brief Gets the current security analysis configuration
     * @return SecurityConfigManager pointer for configuration access
     * 
     * This method provides access to the configuration manager
     * for debugging and configuration management.
     */
    SecurityConfigManager* getConfigurationManager() const;
    
    // Utility methods
    
    /**
     * @brief Calculates file entropy for a specific range
     * @param data Data to analyze
     * @param startOffset Starting offset for analysis
     * @param length Length of data to analyze
     * @return Entropy value (0.0 to 8.0, where 8.0 is maximum entropy)
     * 
     * Entropy analysis helps detect packed, encrypted, or obfuscated
     * content that may indicate malicious intent.
     */
    double calculateEntropy(const QByteArray &data, qint64 startOffset = 0, qint64 length = -1);
    
    /**
     * @brief Checks if a file appears to be packed
     * @param filePath Path to the file to check
     * @return true if file appears packed, false otherwise
     * 
     * Packed files often indicate obfuscation or compression that
     * may be used to hide malicious code.
     */
    bool isFilePacked(const QString &filePath);
    
    /**
     * @brief Validates digital signatures in PE files
     * @param filePath Path to the PE file to validate
     * @return Digital signature validation result
     * 
     * Digital signature validation helps establish file authenticity
     * and provides confidence in file origin and integrity.
     */
    QString validateDigitalSignature(const QString &filePath);
    
    // Signals for progress reporting and results
    
signals:
    /**
     * @brief Emitted during security analysis to show progress
     * @param percentage Progress percentage (0-100)
     * @param message Description of current analysis step
     * 
     * This signal allows the UI to show real-time progress during
     * security analysis, especially useful for large files.
     */
    void analysisProgress(int percentage, const QString &message);
    
    /**
     * @brief Emitted when security analysis completes
     * @param result Security analysis results
     * 
     * This signal notifies when security analysis has finished,
     * providing the complete analysis results.
     */
    void analysisComplete(const SecurityAnalysisResult &result);
    
    /**
     * @brief Emitted when security threats are detected
     * @param threatLevel Level of threat detected
     * @param description Description of the detected threat
     * 
     * This signal provides immediate notification of security
     * threats as they are detected during analysis.
     */
    void threatDetected(SecurityRiskLevel threatLevel, const QString &description);

private:
    // Private analysis methods - Internal implementation details
    
    /**
     * @brief Analyzes file entropy for security assessment
     * @param filePath Path to the file to analyze
     * @return Entropy analysis results
     * 
     * This method performs detailed entropy analysis to detect
     * packed, encrypted, or obfuscated content.
     */
    QString analyzeFileEntropy(const QString &filePath);
    
    /**
     * @brief Analyzes section characteristics for security concerns
     * @param sections List of PE section headers to analyze
     * @return Section security analysis results
     * 
     * This method examines section characteristics to identify
     * suspicious or potentially malicious sections.
     */
    QString analyzeSectionSecurity(const QList<const IMAGE_SECTION_HEADER*> &sections);
    
    /**
     * @brief Analyzes imports for suspicious or malicious functions
     * @param imports List of imported functions to analyze
     * @return Import security analysis results
     * 
     * This method examines imported functions to identify
     * suspicious APIs commonly used in malware.
     */
    QString analyzeImportSecurity(const QStringList &imports);
    
    /**
     * @brief Detects anti-debugging and anti-VM techniques
     * @param peData Raw PE file data to analyze
     * @return Anti-debugging/anti-VM detection results
     * 
     * This method identifies techniques commonly used to
     * evade analysis and detection systems.
     */
    QString detectAntiAnalysisTechniques(const QByteArray &peData);
    
    /**
     * @brief Calculates overall security risk score
     * @param issues List of detected security issues
     * @return Numerical risk score (0-100)
     * 
     * This method calculates a comprehensive risk score based
     * on the severity and quantity of detected security issues.
     */
    int calculateRiskScore(const QStringList &issues);
    
    // Configuration and state
    
    SecurityConfigManager *m_configManager;         ///< Configuration manager for security analysis
    QFile m_analysisFile;                           ///< File handle for analysis
    QByteArray m_fileData;                          ///< File data for analysis
};

#endif // PE_SECURITY_ANALYZER_H
