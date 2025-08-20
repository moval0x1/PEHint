#include "language_manager.h"
#include <QApplication>
#include <QDir>
#include <QDebug>
#include <QCoreApplication>
#include <QLibraryInfo>
#include <QFileInfo>
#include <QRegularExpression>

/**
 * @file language_manager.cpp
 * @brief Implementation of Language Manager for PEHint Internationalization
 * 
 * This file implements the LanguageManager class that provides centralized
 * string management and internationalization support for the application.
 */

LanguageManager::LanguageManager()
    : m_settings(nullptr)
    , m_qtTranslator(nullptr)
    , m_appTranslator(nullptr)
    , m_initialized(false)
{
    // Initialize language names mapping
    m_languageNames["en"] = "English";
    m_languageNames["pt"] = "Português";
    m_languageNames["es"] = "Español";
    m_languageNames["fr"] = "Français";
    m_languageNames["de"] = "Deutsch";
}

LanguageManager::~LanguageManager()
{
    if (m_qtTranslator) {
        QApplication::removeTranslator(m_qtTranslator);
        delete m_qtTranslator;
    }
    if (m_appTranslator) {
        QApplication::removeTranslator(m_appTranslator);
        delete m_appTranslator;
    }
    if (m_settings) {
        delete m_settings;
    }
}

LanguageManager& LanguageManager::getInstance()
{
    static LanguageManager instance;
    return instance;
}

bool LanguageManager::initialize(const QString &configPath)
{
    if (m_initialized) {
        qDebug() << "LanguageManager already initialized, skipping re-initialization";
        return true;
    }
    
    // If no config path provided, try to find it automatically
    if (configPath.isEmpty()) {
        m_configPath = findConfigFile("language_config.ini");
        qDebug() << "Auto-detected language config path:" << m_configPath;
    } else {
        m_configPath = configPath;
    }
    
    if (m_configPath.isEmpty()) {
        qWarning() << "No language config file found";
        return false;
    }
    
    // Load language configuration
    if (!loadLanguageConfiguration()) {
        qWarning() << "Failed to load language configuration from" << m_configPath;
        return false;
    }
    
    // Set default language
    m_defaultLanguage = m_settings->value("General/default_language", "en").toString();
    m_currentLanguage = m_defaultLanguage;
    
    // Get available languages from config and validate they exist
    QString availableLanguagesStr = m_settings->value("General/available_languages", "en").toString();
    QStringList configLanguages = availableLanguagesStr.split(",", Qt::SkipEmptyParts);
    
    // Check which language files actually exist
    QDir configDir = QFileInfo(configPath).dir();
    m_availableLanguages.clear();
    
    // First, always add English since we have the main config file
    m_availableLanguages.append("en");
    qDebug() << "Added English language (main config file)";
    
    // Get the actual config directory where the main config file is located
    QDir actualConfigDir = QFileInfo(m_configPath).absoluteDir();
    qDebug() << "Actual config directory (absolute):" << actualConfigDir.absolutePath();
    
    // List all files in the config directory to see what's actually there
    QStringList allFiles = actualConfigDir.entryList(QDir::Files);
    qDebug() << "Files in config directory:" << allFiles;
    
    // Filter for language config files
    QStringList langFiles = actualConfigDir.entryList(QStringList("language_config*.ini"), QDir::Files);
    qDebug() << "Language config files found:" << langFiles;
    
    // Now check for other language files from config
    for (const QString &langCode : configLanguages) {
        if (langCode == "en") {
            continue; // Already added above
        }
        
        QString langFile = QString("language_config_%1.ini").arg(langCode);
        QString fullPath = actualConfigDir.absoluteFilePath(langFile);
        
        qDebug() << "Checking for language file:" << langFile;
        qDebug() << "Full path:" << fullPath;
        qDebug() << "File exists:" << QFile::exists(fullPath);
        
        if (QFile::exists(fullPath)) {
            m_availableLanguages.append(langCode);
            qDebug() << "✓ Found language file for" << langCode << "at:" << fullPath;
        } else {
            qDebug() << "✗ Language file not found for" << langCode;
        }
    }
    
    // Also scan for any additional language files that might not be in the config
    qDebug() << "Scanning for additional language files...";
    for (const QString &fileName : langFiles) {
        if (fileName == "language_config.ini") {
            continue; // Skip the main English config
        }
        
        // Extract language code from filename: language_config_XX.ini
        QRegularExpression regex("language_config_([a-z]{2})\\.ini");
        QRegularExpressionMatch match = regex.match(fileName);
        if (match.hasMatch()) {
            QString langCode = match.captured(1);
            if (!m_availableLanguages.contains(langCode)) {
                m_availableLanguages.append(langCode);
                qDebug() << "✓ Found additional language file for" << langCode << ":" << fileName;
            }
        }
    }
    
    
    // Validate default language
    if (!m_availableLanguages.contains(m_defaultLanguage)) {
        qWarning() << "Default language" << m_defaultLanguage << "not in available languages list";
        m_defaultLanguage = "en";
        m_currentLanguage = "en";
    }
    
    // Load Qt translations for current language
    if (!loadQtTranslations(m_currentLanguage)) {
        qWarning() << "Failed to load Qt translations for" << m_currentLanguage;
    }
    
    m_initialized = true;
    qDebug() << "LanguageManager initialized with language:" << m_currentLanguage;
    return true;
}

bool LanguageManager::setLanguage(const QString &languageCode)
{
    if (!m_initialized) {
        qWarning() << "LanguageManager not initialized";
        return false;
    }
    
    if (!m_availableLanguages.contains(languageCode)) {
        qWarning() << "Language" << languageCode << "not available";
        return false;
    }
    
    if (m_currentLanguage == languageCode) {
        return true; // Already set
    }
    
    // Load language-specific configuration file
    QString oldConfigPath = m_configPath;
    QDir configDir = QFileInfo(m_configPath).absoluteDir();
    QString langFile;
    if (languageCode == "en") {
        langFile = "language_config.ini";
    } else {
        langFile = QString("language_config_%1.ini").arg(languageCode);
    }
    
    QString newConfigPath = configDir.absoluteFilePath(langFile);
    qDebug() << "Loading language config from:" << newConfigPath;
    
    // Temporarily change config path and reload configuration
    m_configPath = newConfigPath;
    if (!loadLanguageConfiguration()) {
        qWarning() << "Failed to load language configuration for" << languageCode;
        m_configPath = oldConfigPath; // Restore old path
        return false;
    }
    
    // Restore the original config path to maintain available languages list
    m_configPath = oldConfigPath;
    
    // Load Qt translations for new language
    if (!loadQtTranslations(languageCode)) {
        qWarning() << "Failed to load Qt translations for" << languageCode;
    }
    
    m_currentLanguage = languageCode;
    qDebug() << "Language changed to:" << languageCode;
    
    emit languageChanged(languageCode);
    return true;
}

QString LanguageManager::getCurrentLanguage() const
{
    return m_currentLanguage;
}

QStringList LanguageManager::getAvailableLanguages() const
{
    qDebug() << "getAvailableLanguages() called, returning:" << m_availableLanguages;
    qDebug() << "m_availableLanguages size:" << m_availableLanguages.size();
    qDebug() << "m_availableLanguages content:" << m_availableLanguages.join(", ");
    return m_availableLanguages;
}

QString LanguageManager::getString(const QString &key, const QString &defaultValue) const
{
    if (!m_initialized) {
        qDebug() << "LanguageManager not initialized, returning:" << (defaultValue.isEmpty() ? key : defaultValue);
        return defaultValue.isEmpty() ? key : defaultValue;
    }
    
    // Try to get from configuration first
    QString value = m_strings.value(key, "");
    if (!value.isEmpty()) {
        qDebug() << "Found string for key" << key << ":" << value;
        return value;
    }
    
    // If key starts with "UI/", try without the prefix
    QString alternativeKey = key;
    if (key.startsWith("UI/")) {
        alternativeKey = key.mid(3); // Remove "UI/" prefix
        value = m_strings.value(alternativeKey, "");
        if (!value.isEmpty()) {
            qDebug() << "Found string for alternative key" << alternativeKey << ":" << value;
            return value;
        }
    }
    
    qDebug() << "String not found for key:" << key << "in" << m_strings.keys();
    
    // Fallback to Qt's translation system
    QString qtTranslation = QCoreApplication::translate("PEHint", key.toUtf8().constData());
    if (!qtTranslation.isEmpty() && qtTranslation != key) {
        return qtTranslation;
    }
    
    return defaultValue.isEmpty() ? key : defaultValue;
}

QString LanguageManager::getString(const QString &key, const QMap<QString, QString> &params, const QString &defaultValue) const
{
    QString text = getString(key, defaultValue);
    return substituteParameters(text, params);
}

QString LanguageManager::getString(const QString &key, const QString &paramName, const QString &paramValue, const QString &defaultValue) const
{
    QMap<QString, QString> params;
    params[paramName] = paramValue;
    return getString(key, params, defaultValue);
}

bool LanguageManager::hasString(const QString &key) const
{
    if (!m_initialized) {
        return false;
    }
    
    return m_strings.contains(key) || !QCoreApplication::translate("PEHint", key.toUtf8().constData()).isEmpty();
}

bool LanguageManager::reloadConfiguration()
{
    if (!m_initialized) {
        return false;
    }
    
    // Reload language configuration
    if (!loadLanguageConfiguration()) {
        return false;
    }
    
    // Reload Qt translations
    if (!loadQtTranslations(m_currentLanguage)) {
        qWarning() << "Failed to reload Qt translations for" << m_currentLanguage;
    }
    
    emit configurationReloaded();
    return true;
}

QString LanguageManager::getLanguageDisplayName(const QString &languageCode) const
{
    return m_languageNames.value(languageCode, languageCode);
}

bool LanguageManager::loadQtTranslations(const QString &languageCode)
{
    // Remove existing translators
    if (m_qtTranslator) {
        QApplication::removeTranslator(m_qtTranslator);
        delete m_qtTranslator;
        m_qtTranslator = nullptr;
    }
    if (m_appTranslator) {
        QApplication::removeTranslator(m_appTranslator);
        delete m_appTranslator;
        m_appTranslator = nullptr;
    }
    
    // Create new translators
    m_qtTranslator = new QTranslator(this);
    m_appTranslator = new QTranslator(this);
    
    // Try to load Qt translations
    QString qtTranslationsPath = QLibraryInfo::path(QLibraryInfo::TranslationsPath);
    QString qtTranslationsFile = QString("qt_%1").arg(languageCode);
    
    if (m_qtTranslator->load(qtTranslationsFile, qtTranslationsPath)) {
        QApplication::installTranslator(m_qtTranslator);
        qDebug() << "Loaded Qt translations from" << qtTranslationsPath << "for" << languageCode;
    } else {
        qDebug() << "No Qt translations found for" << languageCode << "in" << qtTranslationsPath;
    }
    
    // Try to load application translations
    QString appTranslationsPath = QCoreApplication::applicationDirPath() + "/translations";
    QString appTranslationsFile = QString("pehint_%1").arg(languageCode);
    
    if (m_appTranslator->load(appTranslationsFile, appTranslationsPath)) {
        QApplication::installTranslator(m_appTranslator);
        qDebug() << "Loaded app translations from" << appTranslationsPath << "for" << languageCode;
    } else {
        qDebug() << "No app translations found for" << languageCode << "in" << appTranslationsPath;
    }
    
    return true;
}

bool LanguageManager::loadLanguageConfiguration()
{
    qDebug() << "Loading language configuration from:" << m_configPath;
    
    if (m_settings) {
        delete m_settings;
    }
    
    // Check if file exists before trying to open it
    QFileInfo fileInfo(m_configPath);
    if (!fileInfo.exists()) {
        qWarning() << "Language config file does not exist:" << m_configPath;
        return false;
    }
    
    if (!fileInfo.isReadable()) {
        qWarning() << "Language config file is not readable:" << m_configPath;
        return false;
    }
    
    qDebug() << "File exists and is readable. File size:" << fileInfo.size() << "bytes";
    
    m_settings = new QSettings(m_configPath, QSettings::IniFormat);
    
    if (m_settings->status() != QSettings::NoError) {
        qWarning() << "Failed to open language configuration file:" << m_configPath;
        qWarning() << "QSettings status:" << m_settings->status();
        return false;
    }
    
    qDebug() << "QSettings opened successfully";
    
    // Load all strings from configuration
    m_strings.clear();
    
    // Load UI strings
    m_settings->beginGroup("UI");
    QStringList uiKeys = m_settings->allKeys();
    qDebug() << "Found" << uiKeys.size() << "UI keys:";
    for (const QString &key : uiKeys) {
        qDebug() << "  UI key:" << key;
    }
    
    for (const QString &key : uiKeys) {
        QString value = m_settings->value(key).toString();
        if (!value.isEmpty()) {
            // Store both with and without UI/ prefix for compatibility
            m_strings[key] = value;
            m_strings["UI/" + key] = value; // Also store with UI/ prefix
            qDebug() << "  Loaded UI string:" << key << "=" << value;
            qDebug() << "  Also stored as: UI/" << key << "=" << value;
        } else {
            qDebug() << "  Empty UI string for key:" << key;
        }
    }
    m_settings->endGroup();
    
    // Load other sections
    QStringList sections = {"General", "Progress", "Error", "Info", "Button", "Menu", "Context", "Tree", "Placeholder", "Size", "Field", "Machine", "Subsystem", "Section", "File", "Resource", "Import", "Export", "Hex"};
    
    for (const QString &section : sections) {
        m_settings->beginGroup(section);
        QStringList keys = m_settings->allKeys();
        if (!keys.isEmpty()) {
            qDebug() << "Found" << keys.size() << "keys in section:" << section;
        }
        for (const QString &key : keys) {
            QString value = m_settings->value(key).toString();
            if (!value.isEmpty()) {
                QString fullKey = QString("%1/%2").arg(section, key);
                m_strings[fullKey] = value;
                qDebug() << "  Loaded string:" << fullKey << "=" << value;
            }
        }
        m_settings->endGroup();
    }
    
    qDebug() << "Total loaded strings:" << m_strings.size();
    
    // Debug: Print some loaded strings
    qDebug() << "Sample loaded strings:";
    int count = 0;
    for (auto it = m_strings.constBegin(); it != m_strings.constEnd() && count < 10; ++it) {
        qDebug() << "  " << it.key() << "=" << it.value();
        count++;
    }
    
    return m_strings.size() > 0;
}

QString LanguageManager::substituteParameters(const QString &text, const QMap<QString, QString> &params) const
{
    QString result = text;
    
    for (auto it = params.constBegin(); it != params.constEnd(); ++it) {
        QString placeholder = QString("{%1}").arg(it.key());
        result.replace(placeholder, it.value());
    }
    
    return result;
}

QTranslator* LanguageManager::getQtTranslator(const QString &languageCode)
{
    return m_qtTranslator;
}

bool LanguageManager::isInitialized() const
{
    return m_initialized;
}

QString LanguageManager::findConfigFile(const QString &fileName) const
{
    QStringList possibleConfigPaths;
    
    // 1. Try relative to executable (for deployed builds)
    QString appDir = QCoreApplication::applicationDirPath();
    possibleConfigPaths << QDir(appDir).absoluteFilePath("config/" + fileName);
    
    // 2. Try relative to executable but go up to project root (for development builds)
    QDir appDirObj(appDir);
    if (appDirObj.cdUp() && appDirObj.cdUp() && appDirObj.cdUp()) {
        possibleConfigPaths << appDirObj.absoluteFilePath("config/" + fileName);
    }
    
    // 3. Try current working directory
    possibleConfigPaths << QDir::currentPath() + "/config/" + fileName;
    
    // 4. Try source directory (for development builds)
    possibleConfigPaths << QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../../../config/" + fileName);
    
    qDebug() << "Searching for config file:" << fileName;
    qDebug() << "Possible paths:" << possibleConfigPaths;
    
    // Find the first valid config file
    for (const QString &path : possibleConfigPaths) {
        if (QFile::exists(path)) {
            qDebug() << "Found config file at:" << path;
            return path;
        }
    }
    
    qWarning() << "Config file not found in any of these locations:" << possibleConfigPaths;
    return QString();
}
