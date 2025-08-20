#include "language_manager.h"
#include <QApplication>
#include <QDir>
#include <QDebug>
#include <QCoreApplication>
#include <QLibraryInfo>
#include <QFileInfo>

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
    m_configPath = configPath;
    
    // Load language configuration
    if (!loadLanguageConfiguration()) {
        qWarning() << "Failed to load language configuration from" << configPath;
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
    
    qDebug() << "Config directory:" << configDir.absolutePath();
    qDebug() << "Looking for language files in:" << configDir.absolutePath();
    
    // First, always add English since we have the main config file
    m_availableLanguages.append("en");
    qDebug() << "Added English language (main config file)";
    
    // Now check for other language files
    for (const QString &langCode : configLanguages) {
        if (langCode == "en") {
            continue; // Already added
        }
        
        QString langFile = QString("language_config_%1.ini").arg(langCode);
        QString fullPath = configDir.absoluteFilePath(langFile);
        qDebug() << "Checking for language file:" << langFile << "at full path:" << fullPath;
        
        if (QFile::exists(fullPath)) {
            m_availableLanguages.append(langCode);
            qDebug() << "Found language file for" << langCode << "at" << fullPath;
        } else {
            qDebug() << "Language file not found for" << langCode << "at" << fullPath;
        }
    }
    
    qDebug() << "Available languages after validation:" << m_availableLanguages;
    
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
    QDir configDir = QFileInfo(m_configPath).dir();
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
