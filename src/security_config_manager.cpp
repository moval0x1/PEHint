/**
 * @file security_config_manager.cpp
 * @brief Implementation of Security Configuration Manager for PEHint
 */

#include "security_config_manager.h"
#include <QDebug>
#include <QDir>
#include <QCoreApplication>

SecurityConfigManager::SecurityConfigManager(const QString &configFilePath, QObject *parent)
    : QObject(parent)
    , m_configFilePath(configFilePath)
    , m_settings(nullptr)
    , m_fileWatcher(nullptr)
    , m_configurationValid(false)
{
    // Initialize default configuration
    setDefaultConfiguration();
    
    // If no config file path provided, try to find it automatically
    if (m_configFilePath.isEmpty()) {
        m_configFilePath = findConfigFile("security_config.ini");
        qDebug() << "Auto-detected config file path:" << m_configFilePath;
    }
    
    // Try to load configuration from file
    if (loadConfiguration()) {
        qDebug() << "Configuration loaded successfully from:" << m_configFilePath;
    } else {
        qWarning() << "Failed to load configuration from:" << m_configFilePath << "- using defaults";
    }
    
    // Set up file watching for hot-reloading
    m_fileWatcher = new QFileSystemWatcher(this);
    if (m_fileWatcher->addPath(m_configFilePath)) {
        connect(m_fileWatcher, &QFileSystemWatcher::fileChanged, this, &SecurityConfigManager::onConfigFileChanged);
        qDebug() << "File watching enabled for:" << m_configFilePath;
    } else {
        qWarning() << "Failed to set up file watching for:" << m_configFilePath;
    }
}

SecurityConfigManager::~SecurityConfigManager()
{
    if (m_settings) {
        delete m_settings;
    }
}

SecurityAnalysisConfig SecurityConfigManager::getConfiguration() const
{
    return m_config;
}

QVariant SecurityConfigManager::getValue(const QString &key, const QVariant &defaultValue) const
{
    if (!m_settings) {
        return defaultValue;
    }
    
    return m_settings->value(key, defaultValue);
}

QStringList SecurityConfigManager::getStringList(const QString &key, const QStringList &defaultValue) const
{
    if (!m_settings) {
        return defaultValue;
    }
    
    QString value = m_settings->value(key, "").toString();
    if (value.isEmpty()) {
        return defaultValue;
    }
    
    return parseStringList(value);
}

bool SecurityConfigManager::getBool(const QString &key, bool defaultValue) const
{
    if (!m_settings) {
        return defaultValue;
    }
    
    return m_settings->value(key, defaultValue).toBool();
}

int SecurityConfigManager::getInt(const QString &key, int defaultValue) const
{
    if (!m_settings) {
        return defaultValue;
    }
    
    return m_settings->value(key, defaultValue).toInt();
}

double SecurityConfigManager::getDouble(const QString &key, double defaultValue) const
{
    if (!m_settings) {
        return defaultValue;
    }
    
    return m_settings->value(key, defaultValue).toDouble();
}

qint64 SecurityConfigManager::getInt64(const QString &key, qint64 defaultValue) const
{
    if (!m_settings) {
        return defaultValue;
    }
    
    return m_settings->value(key, defaultValue).toLongLong();
}

bool SecurityConfigManager::reloadConfiguration()
{
    return loadConfiguration();
}

bool SecurityConfigManager::setConfigFilePath(const QString &configFilePath)
{
    if (m_configFilePath == configFilePath) {
        return true;
    }
    
    m_configFilePath = configFilePath;
    
    // Update file watcher
    if (m_fileWatcher) {
        m_fileWatcher->removePath(m_configFilePath);
        m_fileWatcher->addPath(configFilePath);
    }
    
    return loadConfiguration();
}

QString SecurityConfigManager::getConfigFilePath() const
{
    return m_configFilePath;
}

bool SecurityConfigManager::isConfigurationValid() const
{
    return m_configurationValid;
}

QStringList SecurityConfigManager::getValidationErrors() const
{
    return m_validationErrors;
}

bool SecurityConfigManager::setValue(const QString &key, const QVariant &value)
{
    if (!m_settings) {
        return false;
    }
    
    QVariant oldValue = m_settings->value(key);
    m_settings->setValue(key, value);
    
    emit configurationValueChanged(key, oldValue, value);
    return true;
}

void SecurityConfigManager::resetToDefaults()
{
    setDefaultConfiguration();
    emit configurationReloaded(true, "Configuration reset to defaults");
}

bool SecurityConfigManager::exportConfiguration(const QString &filePath) const
{
    if (!m_settings) {
        return false;
    }
    
    QSettings exportSettings(filePath, QSettings::IniFormat);
    
    // Export all current settings
    QStringList allKeys = m_settings->allKeys();
    for (const QString &key : allKeys) {
        exportSettings.setValue(key, m_settings->value(key));
    }
    
    exportSettings.sync();
    return exportSettings.status() == QSettings::NoError;
}

QStringList SecurityConfigManager::getAllKeys() const
{
    if (!m_settings) {
        return QStringList();
    }
    
    return m_settings->allKeys();
}

QStringList SecurityConfigManager::getAllSections() const
{
    if (!m_settings) {
        return QStringList();
    }
    
    QStringList sections;
    QStringList allKeys = m_settings->allKeys();
    
    for (const QString &key : allKeys) {
        QString section = key.split('/').first();
        if (!sections.contains(section)) {
            sections.append(section);
        }
    }
    
    return sections;
}

QString SecurityConfigManager::getConfigurationSummary() const
{
    if (!m_configurationValid) {
        return "Configuration: Invalid or not loaded";
    }
    
    return QString("Configuration: Loaded from %1 (%2 sections, %3 keys)")
        .arg(m_configFilePath)
        .arg(getAllSections().size())
        .arg(getAllKeys().size());
}

void SecurityConfigManager::onConfigFileChanged(const QString &filePath)
{
    Q_UNUSED(filePath)
    
    qDebug() << "Configuration file changed, reloading...";
    if (loadConfiguration()) {
        emit configurationReloaded(true, "Configuration reloaded from file changes");
    } else {
        emit configurationReloaded(false, "Failed to reload configuration from file changes");
    }
}

bool SecurityConfigManager::loadConfiguration()
{
    // Create QSettings object
    if (m_settings) {
        delete m_settings;
    }
    
    m_settings = new QSettings(m_configFilePath, QSettings::IniFormat);
    
    if (m_settings->status() != QSettings::NoError) {
        qWarning() << "Failed to create QSettings for:" << m_configFilePath;
        return false;
    }
    
    // Load configuration values
    m_config.defaultSensitivityLevel = getInt("General/default_sensitivity_level", DEFAULT_SENSITIVITY_LEVEL);
    m_config.enableEntropyAnalysis = getBool("General/enable_entropy_analysis", true);
    m_config.enableSectionAnalysis = getBool("General/enable_section_analysis", true);
    m_config.enableImportAnalysis = getBool("General/enable_import_analysis", true);
    m_config.enableResourceAnalysis = getBool("General/enable_resource_analysis", true);
    m_config.enableDigitalSignatureValidation = getBool("General/enable_digital_signature_validation", true);
    m_config.enableAntiDebugDetection = getBool("General/enable_anti_debug_detection", true);
    m_config.enableAntiVMDetection = getBool("General/enable_anti_vm_detection", true);
    m_config.enablePackerDetection = getBool("General/enable_packer_detection", true);
    m_config.enableSuspiciousAPIDetection = getBool("General/enable_suspicious_api_detection", true);
    m_config.enableCodeInjectionDetection = getBool("General/enable_code_injection_detection", true);
    
    // Load entropy thresholds
    m_config.highEntropyThreshold = getDouble("EntropyThresholds/high_entropy_threshold", DEFAULT_HIGH_ENTROPY_THRESHOLD);
    m_config.mediumEntropyThreshold = getDouble("EntropyThresholds/medium_entropy_threshold", DEFAULT_MEDIUM_ENTROPY_THRESHOLD);
    m_config.lowEntropyThreshold = getDouble("EntropyThresholds/low_entropy_threshold", DEFAULT_LOW_ENTROPY_THRESHOLD);
    m_config.entropyAnalysisChunkSize = getInt("EntropyThresholds/entropy_analysis_chunk_size", DEFAULT_ENTROPY_CHUNK_SIZE);
    m_config.entropyAnalysisOverlap = getInt("EntropyThresholds/entropy_analysis_overlap", DEFAULT_ENTROPY_OVERLAP);
    
    // Load suspicious sections configuration
    m_config.suspiciousSectionPatterns = getStringList("SuspiciousSections/suspicious_section_patterns");
    m_config.suspiciousSectionCharacteristics = getStringList("SuspiciousSections/suspicious_section_characteristics");
    m_config.maxSectionSizeThreshold = getInt64("SuspiciousSections/max_section_size_threshold", DEFAULT_MAX_SECTION_SIZE);
    
    // Load anti-debugging configuration
    m_config.antiDebugAPIs = getStringList("AntiDebugTechniques/anti_debug_apis");
    m_config.antiDebugPatterns = getStringList("AntiDebugTechniques/anti_debug_patterns");
    m_config.timingDetectionEnabled = getBool("AntiDebugTechniques/timing_detection_enabled", true);
    m_config.timingThresholdMs = getInt("AntiDebugTechniques/timing_threshold_ms", DEFAULT_TIMING_THRESHOLD);
    
    // Load anti-VM configuration
    m_config.antiVMStrings = getStringList("AntiVMTechniques/anti_vm_strings");
    m_config.antiVMRegistryKeys = getStringList("AntiVMTechniques/anti_vm_registry_keys");
    m_config.antiVMFilePaths = getStringList("AntiVMTechniques/anti_vm_file_paths");
    m_config.antiVMProcesses = getStringList("AntiVMTechniques/anti_vm_processes");
    
    // Load suspicious APIs configuration
    m_config.processInjectionAPIs = getStringList("SuspiciousAPIs/ProcessInjectionAPIs/process_injection_apis");
    m_config.networkAPIs = getStringList("SuspiciousAPIs/NetworkAPIs/network_apis");
    m_config.registryAPIs = getStringList("SuspiciousAPIs/RegistryAPIs/registry_apis");
    m_config.fileSystemAPIs = getStringList("SuspiciousAPIs/FileSystemAPIs/filesystem_apis");
    m_config.systemAPIs = getStringList("SuspiciousAPIs/SystemAPIs/system_apis");
    
    // Load code injection configuration
    m_config.codeInjectionPatterns = getStringList("CodeInjectionTechniques/code_injection_patterns");
    m_config.dllInjectionPatterns = getStringList("CodeInjectionTechniques/dll_injection_patterns");
    
    // Load packer detection configuration
    m_config.packerSignatures = getStringList("PackerSignatures/packer_signatures");
    m_config.packerPatterns = getStringList("PackerSignatures/packer_patterns");
    
    // Load resource analysis configuration
    m_config.suspiciousResourceTypes = getStringList("ResourceAnalysis/suspicious_resource_types");
    m_config.suspiciousResourceNames = getStringList("ResourceAnalysis/suspicious_resource_names");
    m_config.maxResourceSizeThreshold = getInt64("ResourceAnalysis/max_resource_size_threshold", DEFAULT_MAX_RESOURCE_SIZE);
    
    // Load digital signature configuration
    m_config.enableSignatureValidation = getBool("DigitalSignature/enable_signature_validation", true);
    m_config.checkCertificateRevocation = getBool("DigitalSignature/check_certificate_revocation", true);
    m_config.validateTimestamp = getBool("DigitalSignature/validate_timestamp", true);
    m_config.trustedPublishersOnly = getBool("DigitalSignature/trusted_publishers_only", false);
    m_config.minCertificateStrength = getInt("DigitalSignature/min_certificate_strength", 128);
    m_config.checkCertificateExpiry = getBool("DigitalSignature/check_certificate_expiry", true);
    m_config.checkCertificateChain = getBool("DigitalSignature/check_certificate_chain", true);
    
    // Load risk scoring configuration
    m_config.criticalIssuePoints = getInt("RiskScoring/critical_issue_points", DEFAULT_CRITICAL_POINTS);
    m_config.highRiskPoints = getInt("RiskScoring/high_risk_points", DEFAULT_HIGH_POINTS);
    m_config.mediumRiskPoints = getInt("RiskScoring/medium_risk_points", DEFAULT_MEDIUM_POINTS);
    m_config.lowRiskPoints = getInt("RiskScoring/low_risk_points", DEFAULT_LOW_POINTS);
    m_config.criticalIssues = getStringList("RiskScoring/critical_issues");
    m_config.highRiskIssues = getStringList("RiskScoring/high_risk_issues");
    m_config.mediumRiskIssues = getStringList("RiskScoring/medium_risk_issues");
    m_config.lowRiskIssues = getStringList("RiskScoring/low_risk_issues");
    m_config.multipleIssuesBonus = getBool("RiskScoring/multiple_issues_bonus", true);
    m_config.criticalMultipleBonus = getInt("RiskScoring/critical_multiple_bonus", 10);
    m_config.highMultipleBonus = getInt("RiskScoring/high_multiple_bonus", 8);
    m_config.mediumMultipleBonus = getInt("RiskScoring/medium_multiple_bonus", 5);
    m_config.lowMultipleBonus = getInt("RiskScoring/low_multiple_bonus", 3);
    m_config.criticalRiskThreshold = getInt("RiskScoring/critical_risk_threshold", DEFAULT_CRITICAL_THRESHOLD);
    m_config.highRiskThreshold = getInt("RiskScoring/high_risk_threshold", DEFAULT_HIGH_THRESHOLD);
    m_config.mediumRiskThreshold = getInt("RiskScoring/medium_risk_threshold", DEFAULT_MEDIUM_THRESHOLD);
    m_config.lowRiskThreshold = getInt("RiskScoring/low_risk_threshold", DEFAULT_LOW_THRESHOLD);
    
    // Validate configuration
    m_configurationValid = validateConfiguration();
    
    return m_configurationValid;
}

bool SecurityConfigManager::validateConfiguration()
{
    m_validationErrors.clear();
    
    // Basic validation checks
    if (m_config.highEntropyThreshold <= m_config.mediumEntropyThreshold) {
        m_validationErrors.append("High entropy threshold must be greater than medium threshold");
    }
    
    if (m_config.mediumEntropyThreshold <= m_config.lowEntropyThreshold) {
        m_validationErrors.append("Medium entropy threshold must be greater than low threshold");
    }
    
    if (m_config.criticalRiskThreshold <= m_config.highRiskThreshold) {
        m_validationErrors.append("Critical risk threshold must be greater than high risk threshold");
    }
    
    if (m_config.highRiskThreshold <= m_config.mediumRiskThreshold) {
        m_validationErrors.append("High risk threshold must be greater than medium risk threshold");
    }
    
    if (m_config.mediumRiskThreshold <= m_config.lowRiskThreshold) {
        m_validationErrors.append("Medium risk threshold must be greater than low risk threshold");
    }
    
    return m_validationErrors.isEmpty();
}

void SecurityConfigManager::setDefaultConfiguration()
{
    // Set all default values
    m_config.defaultSensitivityLevel = DEFAULT_SENSITIVITY_LEVEL;
    m_config.enableEntropyAnalysis = true;
    m_config.enableSectionAnalysis = true;
    m_config.enableImportAnalysis = true;
    m_config.enableResourceAnalysis = true;
    m_config.enableDigitalSignatureValidation = true;
    m_config.enableAntiDebugDetection = true;
    m_config.enableAntiVMDetection = true;
    m_config.enablePackerDetection = true;
    m_config.enableSuspiciousAPIDetection = true;
    m_config.enableCodeInjectionDetection = true;
    
    m_config.highEntropyThreshold = DEFAULT_HIGH_ENTROPY_THRESHOLD;
    m_config.mediumEntropyThreshold = DEFAULT_MEDIUM_ENTROPY_THRESHOLD;
    m_config.lowEntropyThreshold = DEFAULT_LOW_ENTROPY_THRESHOLD;
    m_config.entropyAnalysisChunkSize = DEFAULT_ENTROPY_CHUNK_SIZE;
    m_config.entropyAnalysisOverlap = DEFAULT_ENTROPY_OVERLAP;
    
    m_config.suspiciousSectionPatterns = QStringList{"UPX", "PACK", "CRYPT", "ENCRYPT", "OBFUSC", "PROTECT", "SHIELD", "GUARD", "WRAP", "HIDE"};
    m_config.suspiciousSectionCharacteristics = QStringList{"0xE0000000", "0xC0000000", "0x80000000"};
    m_config.maxSectionSizeThreshold = DEFAULT_MAX_SECTION_SIZE;
    
    m_config.antiDebugAPIs = QStringList{"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "QueryPerformanceCounter"};
    m_config.antiDebugPatterns = QStringList{"int3", "0xCC", "0xCD", "0xCE", "0xCF"};
    m_config.timingDetectionEnabled = true;
    m_config.timingThresholdMs = DEFAULT_TIMING_THRESHOLD;
    
    m_config.antiVMStrings = QStringList{"VMware", "VBox", "VirtualBox", "QEMU", "Xen", "Parallels", "HyperV", "VirtualPC", "Bochs", "KVM"};
    m_config.antiVMRegistryKeys = QStringList{"SOFTWARE\\VMware, Inc.\\VMware Tools", "SOFTWARE\\Oracle\\VirtualBox Guest Additions"};
    m_config.antiVMFilePaths = QStringList{"C:\\WINDOWS\\system32\\drivers\\vmmouse.sys", "C:\\WINDOWS\\system32\\drivers\\vmscsi.sys"};
    m_config.antiVMProcesses = QStringList{"vmtoolsd.exe", "VBoxService.exe", "VBoxTray.exe"};
    
    m_config.processInjectionAPIs = QStringList{"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess", "SetWindowsHookEx", "CreateProcess"};
    m_config.networkAPIs = QStringList{"WSAConnect", "connect", "send", "recv", "HttpOpenRequestA", "InternetConnectA", "URLDownloadToFileA"};
    m_config.registryAPIs = QStringList{"RegCreateKeyExA", "RegSetValueExA", "RegDeleteValueA", "RegOpenKeyExA", "RegQueryValueExA"};
    m_config.fileSystemAPIs = QStringList{"CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW"};
    m_config.systemAPIs = QStringList{"CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"};
    
    m_config.codeInjectionPatterns = QStringList{"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "SetWindowsHookEx", "QueueUserAPC", "NtCreateThreadEx"};
    m_config.dllInjectionPatterns = QStringList{"LoadLibraryA", "LoadLibraryW", "GetProcAddress", "FreeLibrary", "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"};
    
    m_config.packerSignatures = QStringList{"UPX", "ASPack", "PECompact", "Themida", "VMProtect", "Armadillo", "Obsidium", "Enigma"};
    m_config.packerPatterns = QStringList{"UPX!", "ASPack", "PECompact", "Themida", "VMProtect", "Armadillo", "Obsidium", "Enigma"};
    
    m_config.suspiciousResourceTypes = QStringList{"RT_RCDATA", "RT_STRING", "RT_VERSION", "RT_MANIFEST", "RT_HTML", "RT_XML"};
    m_config.suspiciousResourceNames = QStringList{"config", "settings", "data", "payload", "shellcode", "encrypted", "packed", "obfuscated"};
    m_config.maxResourceSizeThreshold = DEFAULT_MAX_RESOURCE_SIZE;
    
    m_config.enableSignatureValidation = true;
    m_config.checkCertificateRevocation = true;
    m_config.validateTimestamp = true;
    m_config.trustedPublishersOnly = false;
    m_config.minCertificateStrength = 128;
    m_config.checkCertificateExpiry = true;
    m_config.checkCertificateChain = true;
    
    m_config.criticalIssuePoints = DEFAULT_CRITICAL_POINTS;
    m_config.highRiskPoints = DEFAULT_HIGH_POINTS;
    m_config.mediumRiskPoints = DEFAULT_MEDIUM_POINTS;
    m_config.lowRiskPoints = DEFAULT_LOW_POINTS;
    m_config.criticalIssues = QStringList{"file_not_found", "file_not_readable", "invalid_pe_structure", "invalid_dos_header", "file_too_small"};
    m_config.highRiskIssues = QStringList{"high_entropy", "packed_file", "anti_debug_detected", "anti_vm_detected", "suspicious_section", "large_section"};
    m_config.mediumRiskIssues = QStringList{"moderate_entropy", "suspicious_imports", "process_injection_apis", "network_apis", "registry_apis"};
    m_config.lowRiskIssues = QStringList{"suspicious_resource", "unusual_characteristics", "non_standard_extension"};
    m_config.multipleIssuesBonus = true;
    m_config.criticalMultipleBonus = 10;
    m_config.highMultipleBonus = 8;
    m_config.mediumMultipleBonus = 5;
    m_config.lowMultipleBonus = 3;
    m_config.criticalRiskThreshold = DEFAULT_CRITICAL_THRESHOLD;
    m_config.highRiskThreshold = DEFAULT_HIGH_THRESHOLD;
    m_config.mediumRiskThreshold = DEFAULT_MEDIUM_THRESHOLD;
    m_config.lowRiskThreshold = DEFAULT_LOW_THRESHOLD;
    
    m_configurationValid = true;
}

QStringList SecurityConfigManager::parseStringList(const QString &value) const
{
    if (value.isEmpty()) {
        return QStringList();
    }
    
            return value.split(',', Qt::SkipEmptyParts);
}

qint64 SecurityConfigManager::parseHexValue(const QString &value) const
{
    bool ok;
    if (value.startsWith("0x", Qt::CaseInsensitive)) {
        return value.toLongLong(&ok, 16);
    } else {
        return value.toLongLong(&ok, 10);
    }
}

QString SecurityConfigManager::findConfigFile(const QString &fileName) const
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
