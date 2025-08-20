#ifndef LANGUAGE_MANAGER_H
#define LANGUAGE_MANAGER_H

#include <QObject>
#include <QString>
#include <QMap>
#include <QSettings>
#include <QTranslator>
#include <QLocale>

/**
 * @file language_manager.h
 * @brief Language Manager for PEHint Internationalization
 * 
 * This class provides a centralized way to manage all user-facing strings
 * in the application, supporting multiple languages and easy string retrieval.
 * 
 * DESIGN PATTERNS:
 * - Singleton Pattern: Ensures single instance for consistent language state
 * - Strategy Pattern: Different language implementations
 * - Factory Pattern: Creates appropriate translators
 * 
 * SOLID PRINCIPLES:
 * - Single Responsibility: Only handles language and string management
 * - Open/Closed: Easy to add new languages without modifying existing code
 * - Dependency Inversion: Depends on abstractions (QTranslator)
 * 
 * FEATURES:
 * - Dynamic language switching at runtime
 * - Fallback to default language if translation fails
 * - Support for Qt's built-in translation system (.ts files)
 * - Configuration-based string management
 * - Template string support with parameter substitution
 */

class LanguageManager : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Get the singleton instance of LanguageManager
     * @return Reference to the singleton instance
     */
    static LanguageManager& getInstance();

    /**
     * @brief Destructor
     */
    ~LanguageManager();

    /**
     * @brief Initialize the language manager
     * @param configPath Path to the language configuration file
     * @return true if initialization successful, false otherwise
     */
    bool initialize(const QString &configPath = QString());

    /**
     * @brief Set the current language
     * @param languageCode Language code (e.g., "en", "pt", "es")
     * @return true if language was set successfully, false otherwise
     */
    bool setLanguage(const QString &languageCode);

    /**
     * @brief Get the current language code
     * @return Current language code
     */
    QString getCurrentLanguage() const;

    /**
     * @brief Get available languages
     * @return List of available language codes
     */
    QStringList getAvailableLanguages() const;

    /**
     * @brief Get a localized string by key
     * @param key String key from configuration
     * @param defaultValue Default value if key not found
     * @return Localized string
     */
    QString getString(const QString &key, const QString &defaultValue = "") const;

    /**
     * @brief Get a localized string with parameter substitution
     * @param key String key from configuration
     * @param params Map of parameter names to values
     * @param defaultValue Default value if key not found
     * @return Localized string with substituted parameters
     */
    QString getString(const QString &key, const QMap<QString, QString> &params, const QString &defaultValue = "") const;

    /**
     * @brief Get a localized string with simple parameter substitution
     * @param key String key from configuration
     * @param paramName Parameter name
     * @param paramValue Parameter value
     * @param defaultValue Default value if key not found
     * @return Localized string with substituted parameter
     */
    QString getString(const QString &key, const QString &paramName, const QString &paramValue, const QString &defaultValue = "") const;

    /**
     * @brief Check if a string key exists
     * @param key String key to check
     * @return true if key exists, false otherwise
     */
    bool hasString(const QString &key) const;

    /**
     * @brief Reload language configuration
     * @return true if reload successful, false otherwise
     */
    bool reloadConfiguration();

    /**
     * @brief Get language display name
     * @param languageCode Language code
     * @return Human-readable language name
     */
    QString getLanguageDisplayName(const QString &languageCode) const;

    /**
     * @brief Check if the language manager is initialized
     * @return true if initialized, false otherwise
     */
    bool isInitialized() const;

signals:
    /**
     * @brief Emitted when language changes
     * @param languageCode New language code
     */
    void languageChanged(const QString &languageCode);

    /**
     * @brief Emitted when configuration is reloaded
     */
    void configurationReloaded();

private:
    /**
     * @brief Private constructor for singleton pattern
     */
    LanguageManager();

    /**
     * @brief Copy constructor (disabled for singleton)
     */
    LanguageManager(const LanguageManager&) = delete;

    /**
     * @brief Assignment operator (disabled for singleton)
     */
    LanguageManager& operator=(const LanguageManager&) = delete;

    /**
     * @brief Load Qt translation files
     * @param languageCode Language code to load
     * @return true if translation loaded successfully, false otherwise
     */
    bool loadQtTranslations(const QString &languageCode);

    /**
     * @brief Load language configuration
     * @return true if configuration loaded successfully, false otherwise
     */
    bool loadLanguageConfiguration();

    /**
     * @brief Substitute parameters in a string
     * @param text Text with parameters
     * @param params Parameter map
     * @return Text with substituted parameters
     */
    QString substituteParameters(const QString &text, const QMap<QString, QString> &params) const;
    
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

    /**
     * @brief Get Qt translator for a language
     * @param languageCode Language code
     * @return QTranslator instance
     */
    QTranslator* getQtTranslator(const QString &languageCode);

    // Member variables
    QString m_configPath;
    QString m_currentLanguage;
    QString m_defaultLanguage;
    QStringList m_availableLanguages;
    QMap<QString, QString> m_strings;
    QMap<QString, QString> m_languageNames;
    QSettings *m_settings;
    QTranslator *m_qtTranslator;
    QTranslator *m_appTranslator;
    bool m_initialized;
};

// Convenience macro for getting strings
#define LANG(key) LanguageManager::getInstance().getString(key)
#define LANG_PARAM(key, paramName, paramValue) LanguageManager::getInstance().getString(key, paramName, paramValue)
#define LANG_PARAMS(key, params) LanguageManager::getInstance().getString(key, params)

#endif // LANGUAGE_MANAGER_H
