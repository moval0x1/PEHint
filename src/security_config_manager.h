/**
 * @file security_config_manager.h
 * @brief Security Configuration Manager for PEHint - Manages security analysis configuration
 * 
 * This class provides a centralized way to manage all security analysis configuration
 * parameters, reading them from a config.ini file and providing easy access to
 * configurable security analysis settings.
 * 
 * REFACTORING PURPOSE:
 * - Centralize all security analysis configuration in external files
 * - Make security analysis behavior easily configurable without code changes
 * - Support runtime configuration updates
 * - Provide validation and default values for configuration parameters
 * 
 * CONFIGURATION MANAGEMENT:
 * - Reads configuration from config.ini files
 * - Provides default values for missing configuration
 * - Validates configuration parameters
 * - Supports hot-reloading of configuration
 * - Caches configuration for performance
 * 
 * SOLID PRINCIPLES IMPLEMENTATION:
 * - Single Responsibility: Only handles configuration management
 * - Open/Closed: Easy to extend with new configuration sections
 * - Liskov Substitution: Can be extended through inheritance
 * - Interface Segregation: Clean, focused configuration interface
 * - Dependency Inversion: Depends on abstractions, not concrete implementations
 */

#ifndef SECURITY_CONFIG_MANAGER_H
#define SECURITY_CONFIG_MANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>
#include <QVariant>
#include <QSettings>
#include <QFileSystemWatcher>

/**
 * @brief Security analysis configuration structure
 * 
 * This structure contains all configurable security analysis parameters,
 * organized by category for easy access and management.
 */
struct SecurityAnalysisConfig {
    // General settings
    int defaultSensitivityLevel;
    bool enableEntropyAnalysis;
    bool enableSectionAnalysis;
    bool enableImportAnalysis;
    bool enableResourceAnalysis;
    bool enableDigitalSignatureValidation;
    bool enableAntiDebugDetection;
    bool enableAntiVMDetection;
    bool enablePackerDetection;
    bool enableSuspiciousAPIDetection;
    bool enableCodeInjectionDetection;
    
    // Entropy thresholds
    double highEntropyThreshold;
    double mediumEntropyThreshold;
    double lowEntropyThreshold;
    int entropyAnalysisChunkSize;
    int entropyAnalysisOverlap;
    bool enableSectionEntropyAnalysis;
    bool enableHeaderEntropyAnalysis;
    
    // Suspicious sections
    QStringList suspiciousSectionPatterns;
    QStringList suspiciousSectionCharacteristics;
    qint64 maxSectionSizeThreshold;
    QStringList suspiciousPermissions;
    
    // Anti-debugging detection
    QStringList antiDebugAPIs;
    QStringList antiDebugPatterns;
    bool timingDetectionEnabled;
    int timingThresholdMs;
    
    // Anti-VM detection
    QStringList antiVMStrings;
    QStringList antiVMRegistryKeys;
    QStringList antiVMFilePaths;
    QStringList antiVMProcesses;
    
    // Suspicious APIs by category
    QStringList processInjectionAPIs;
    QStringList networkAPIs;
    QStringList registryAPIs;
    QStringList fileSystemAPIs;
    QStringList systemAPIs;
    
    // Code injection detection
    QStringList codeInjectionPatterns;
    QStringList dllInjectionPatterns;
    
    // Packer detection
    QStringList packerSignatures;
    QStringList packerPatterns;
    
    // Resource analysis
    QStringList suspiciousResourceTypes;
    QStringList suspiciousResourceNames;
    qint64 maxResourceSizeThreshold;
    
    // Digital signature validation
    bool enableSignatureValidation;
    bool checkCertificateRevocation;
    bool validateTimestamp;
    bool trustedPublishersOnly;
    int minCertificateStrength;
    bool checkCertificateExpiry;
    bool checkCertificateChain;
    
    // Risk scoring
    int criticalIssuePoints;
    int highRiskPoints;
    int mediumRiskPoints;
    int lowRiskPoints;
    QStringList criticalIssues;
    QStringList highRiskIssues;
    QStringList mediumRiskIssues;
    QStringList lowRiskIssues;
    bool multipleIssuesBonus;
    int criticalMultipleBonus;
    int highMultipleBonus;
    int mediumMultipleBonus;
    int lowMultipleBonus;
    int criticalRiskThreshold;
    int highRiskThreshold;
    int mediumRiskThreshold;
    int lowRiskThreshold;
    
    // Reporting
    bool includeTechnicalDetails;
    bool includeRecommendations;
    bool includeRiskScore;
    bool includeEntropyAnalysis;
    bool includeSectionAnalysis;
    bool includeImportAnalysis;
    bool includeResourceAnalysis;
    bool includeAntiAnalysisDetection;
    QString defaultReportFormat;
    QStringList availableFormats;
    QString defaultLanguage;
    QStringList availableLanguages;
    
    // Performance
    bool enableProgressReporting;
    int progressUpdateIntervalMs;
    bool enableAsyncAnalysis;
    int maxAnalysisThreads;
    bool enableCaching;
    int cacheExpiryHours;
    
    // Logging
    bool enableLogging;
    QString logLevel;
    QString logFilePath;
    int maxLogFileSizeMB;
    int maxLogFiles;
    QString logTimestampFormat;
    bool logEntropyAnalysis;
    bool logSectionAnalysis;
    bool logImportAnalysis;
    bool logAntiAnalysisDetection;
    bool logRiskScoring;
    bool logPerformanceMetrics;
};

/**
 * @brief Security Configuration Manager class
 * 
 * This class manages all security analysis configuration parameters,
 * reading them from config.ini files and providing easy access to
 * configurable settings. It supports hot-reloading and validation
 * of configuration parameters.
 * 
 * DESIGN PATTERN: This implements the "Configuration Manager" pattern,
 * providing centralized configuration management with validation,
 * caching, and hot-reloading capabilities.
 * 
 * USAGE: Create an instance, specify the config file path, and use
 * the various getter methods to access configuration parameters.
 * The manager automatically handles file watching and configuration
 * updates.
 */
class SecurityConfigManager : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructor for SecurityConfigManager
     * @param configFilePath Path to the configuration file
     * @param parent Parent QObject for memory management
     * 
     * This constructor initializes the configuration manager with
     * the specified configuration file and sets up file watching
     * for hot-reloading capabilities.
     */
    explicit SecurityConfigManager(const QString &configFilePath = "config/security_config.ini", QObject *parent = nullptr);
    
    /**
     * @brief Destructor for SecurityConfigManager
     * 
     * Ensures proper cleanup of resources and file watchers.
     */
    ~SecurityConfigManager();
    
    // Configuration access methods
    
    /**
     * @brief Gets the complete security analysis configuration
     * @return SecurityAnalysisConfig structure containing all settings
     * 
     * This method returns the complete configuration structure
     * with all current security analysis settings.
     */
    SecurityAnalysisConfig getConfiguration() const;
    
    /**
     * @brief Gets a specific configuration value by key
     * @param key Configuration key in format "section/key"
     * @param defaultValue Default value if key is not found
     * @return Configuration value as QVariant
     * 
     * This method provides direct access to configuration values
     * using a hierarchical key format (e.g., "General/default_sensitivity_level").
     */
    QVariant getValue(const QString &key, const QVariant &defaultValue = QVariant()) const;
    
    /**
     * @brief Gets a string list configuration value
     * @param key Configuration key in format "section/key"
     * @param defaultValue Default value if key is not found
     * @return Configuration value as QStringList
     * 
     * This method is specialized for string list values, handling
     * comma-separated values in the configuration file.
     */
    QStringList getStringList(const QString &key, const QStringList &defaultValue = QStringList()) const;
    
    /**
     * @brief Gets a boolean configuration value
     * @param key Configuration key in format "section/key"
     * @param defaultValue Default value if key is not found
     * @return Configuration value as bool
     * 
     * This method is specialized for boolean values, handling
     * various boolean representations in the configuration file.
     */
    bool getBool(const QString &key, bool defaultValue = false) const;
    
    /**
     * @brief Gets an integer configuration value
     * @param key Configuration key in format "section/key"
     * @param defaultValue Default value if key is not found
     * @return Configuration value as int
     * 
     * This method is specialized for integer values, handling
     * various integer representations in the configuration file.
     */
    int getInt(const QString &key, int defaultValue = 0) const;
    
    /**
     * @brief Gets a double configuration value
     * @param key Configuration key in format "section/key"
     * @param defaultValue Default value if key is not found
     * @return Configuration value as double
     * 
     * This method is specialized for double values, handling
     * various floating-point representations in the configuration file.
     */
    double getDouble(const QString &key, double defaultValue = 0.0) const;
    
    /**
     * @brief Gets a qint64 configuration value
     * @param key Configuration key in format "section/key"
     * @param defaultValue Default value if key is not found
     * @return Configuration value as qint64
     * 
     * This method is specialized for qint64 values, handling
     * large integer values in the configuration file.
     */
    qint64 getInt64(const QString &key, qint64 defaultValue = 0) const;
    
    // Configuration management methods
    
    /**
     * @brief Reloads configuration from the file
     * @return true if reload was successful, false otherwise
     * 
     * This method forces a reload of the configuration file,
     * useful for manual configuration updates or error recovery.
     */
    bool reloadConfiguration();
    
    /**
     * @brief Sets a new configuration file path
     * @param configFilePath New path to the configuration file
     * @return true if the file was loaded successfully, false otherwise
     * 
     * This method allows changing the configuration file at runtime,
     * useful for switching between different configuration profiles.
     */
    bool setConfigFilePath(const QString &configFilePath);
    
    /**
     * @brief Gets the current configuration file path
     * @return Current configuration file path
     * 
     * This method provides access to the current configuration
     * file path for debugging and configuration management.
     */
    QString getConfigFilePath() const;
    
    /**
     * @brief Checks if the configuration file exists and is valid
     * @return true if configuration is valid, false otherwise
     * 
     * This method validates the configuration file and its contents,
     * ensuring that all required sections and keys are present.
     */
    bool isConfigurationValid() const;
    
    /**
     * @brief Gets configuration validation errors
     * @return List of validation error messages
     * 
     * This method provides detailed information about configuration
     * validation errors, useful for troubleshooting configuration issues.
     */
    QStringList getValidationErrors() const;
    
    /**
     * @brief Sets a configuration value (for runtime updates)
     * @param key Configuration key in format "section/key"
     * @param value New value to set
     * @return true if the value was set successfully, false otherwise
     * 
     * This method allows runtime updates to configuration values,
     * useful for dynamic configuration changes without file reloading.
     */
    bool setValue(const QString &key, const QVariant &value);
    
    /**
     * @brief Resets configuration to default values
     * 
     * This method resets all configuration values to their
     * built-in defaults, useful for configuration recovery.
     */
    void resetToDefaults();
    
    /**
     * @brief Exports current configuration to a file
     * @param filePath Path where to save the configuration
     * @return true if export was successful, false otherwise
     * 
     * This method exports the current configuration to a file,
     * useful for backup or configuration sharing purposes.
     */
    bool exportConfiguration(const QString &filePath) const;
    
    // Utility methods
    
    /**
     * @brief Gets a list of all available configuration keys
     * @return List of all configuration keys
     * 
     * This method provides a complete list of all available
     * configuration keys for documentation and debugging purposes.
     */
    QStringList getAllKeys() const;
    
    /**
     * @brief Gets a list of all configuration sections
     * @return List of all configuration sections
     * 
     * This method provides a complete list of all configuration
     * sections for documentation and debugging purposes.
     */
    QStringList getAllSections() const;
    
    /**
     * @brief Gets configuration summary information
     * @return Summary string describing the configuration
     * 
     * This method provides a human-readable summary of the
     * current configuration for status displays and debugging.
     */
    QString getConfigurationSummary() const;

signals:
    /**
     * @brief Emitted when configuration is reloaded
     * @param success Whether the reload was successful
     * @param message Description of the reload operation
     * 
     * This signal notifies when configuration has been reloaded,
     * providing status information about the operation.
     */
    void configurationReloaded(bool success, const QString &message);
    
    /**
     * @brief Emitted when configuration validation fails
     * @param errors List of validation error messages
     * 
     * This signal notifies when configuration validation fails,
     * providing detailed error information for troubleshooting.
     */
    void configurationValidationFailed(const QStringList &errors);
    
    /**
     * @brief Emitted when configuration values change
     * @param key Configuration key that changed
     * @param oldValue Previous value
     * @param newValue New value
     * 
     * This signal notifies when configuration values change,
     * allowing for dynamic updates to dependent components.
     */
    void configurationValueChanged(const QString &key, const QVariant &oldValue, const QVariant &newValue);

private slots:
    /**
     * @brief Handles configuration file changes
     * @param filePath Path to the changed file
     * 
     * This slot is called when the configuration file is modified,
     * triggering automatic configuration reloading.
     */
    void onConfigFileChanged(const QString &filePath);

private:
    // Private helper methods
    
    /**
     * @brief Loads configuration from the file
     * @return true if loading was successful, false otherwise
     * 
     * This method handles the actual loading of configuration
     * from the file, including parsing and validation.
     */
    bool loadConfiguration();
    
    /**
     * @brief Validates the loaded configuration
     * @return true if configuration is valid, false otherwise
     * 
     * This method validates the loaded configuration against
     * required sections and keys, ensuring completeness.
     */
    bool validateConfiguration();
    
    /**
     * @brief Sets default configuration values
     * 
     * This method sets built-in default values for all
     * configuration parameters, used when no file is available.
     */
    void setDefaultConfiguration();
    
    /**
     * @brief Parses a string list from configuration
     * @param value Raw configuration value
     * @return Parsed QStringList
     * 
     * This method parses comma-separated string values from
     * the configuration file into QStringList objects.
     */
    QStringList parseStringList(const QString &value) const;
    
    /**
     * @brief Parses a hexadecimal value from configuration
     * @param value Raw configuration value
     * @return Parsed qint64 value
     * 
     * This method parses hexadecimal values from the configuration
     * file, supporting both decimal and hex notation.
     */
    qint64 parseHexValue(const QString &value) const;
    
    // Data members
    
    QString m_configFilePath;                        ///< Path to the configuration file
    QSettings *m_settings;                           ///< QSettings object for configuration access
    QFileSystemWatcher *m_fileWatcher;               ///< File watcher for hot-reloading
    SecurityAnalysisConfig m_config;                 ///< Current configuration cache
    QStringList m_validationErrors;                  ///< Configuration validation errors
    bool m_configurationValid;                       ///< Whether configuration is currently valid
    
    // Constants for default configuration
    
    static const int DEFAULT_SENSITIVITY_LEVEL = 5;
    static constexpr double DEFAULT_HIGH_ENTROPY_THRESHOLD = 7.5;
    static constexpr double DEFAULT_MEDIUM_ENTROPY_THRESHOLD = 6.0;
    static constexpr double DEFAULT_LOW_ENTROPY_THRESHOLD = 4.0;
    static const int DEFAULT_ENTROPY_CHUNK_SIZE = 1024;
    static const int DEFAULT_ENTROPY_OVERLAP = 512;
    static const qint64 DEFAULT_MAX_SECTION_SIZE = 10485760;
    static const qint64 DEFAULT_MAX_RESOURCE_SIZE = 5242880;
    static const int DEFAULT_TIMING_THRESHOLD = 100;
    static const int DEFAULT_CRITICAL_POINTS = 25;
    static const int DEFAULT_HIGH_POINTS = 15;
    static const int DEFAULT_MEDIUM_POINTS = 10;
    static const int DEFAULT_LOW_POINTS = 5;
    static const int DEFAULT_CRITICAL_THRESHOLD = 80;
    static const int DEFAULT_HIGH_THRESHOLD = 60;
    static const int DEFAULT_MEDIUM_THRESHOLD = 40;
    static const int DEFAULT_LOW_THRESHOLD = 20;
    static const int DEFAULT_PROGRESS_INTERVAL = 100;
    static const int DEFAULT_MAX_THREADS = 4;
    static const int DEFAULT_CACHE_EXPIRY = 24;
    static const int DEFAULT_MAX_LOG_SIZE = 10;
    static const int DEFAULT_MAX_LOG_FILES = 5;
};

#endif // SECURITY_CONFIG_MANAGER_H
