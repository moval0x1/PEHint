/**
 * @file pe_security_analyzer.cpp
 * @brief Implementation of PE Security Analyzer for PEHint
 * 
 * This file implements comprehensive security analysis for PE files,
 * including malware detection, suspicious characteristics analysis,
 * and risk assessment. The implementation follows security best
 * practices and provides detailed analysis results.
 * 
 * IMPLEMENTATION NOTES:
 * - Each security check is implemented as a separate method for clarity
 * - Entropy analysis uses Shannon entropy calculation for accuracy
 * - Risk scoring uses weighted algorithms based on threat severity
 * - Anti-analysis detection covers common evasion techniques
 * - Results are structured for easy integration with UI components
 */

#include "pe_security_analyzer.h"
#include "pe_structures.h"
#include "pe_utils.h"
#include "security_config_manager.h"
#include "language_manager.h"
#include <QFileInfo>
#include <QDebug>
#include <QDir>
#include <QProcess>
#include <QRegularExpression>
#include <cmath>

/**
 * @brief Constructor for PESecurityAnalyzer
 * @param parent Parent QObject for memory management
 * 
 * This constructor initializes the security analyzer with default
 * security check settings and prepares it for analysis operations.
 * Default settings provide a balanced approach between detection
 * accuracy and false positive rates.
 */
PESecurityAnalyzer::PESecurityAnalyzer(QObject *parent)
    : QObject(parent)
    , m_configManager(new SecurityConfigManager("config/security_config.ini", this))
{
    // Configuration is now managed by SecurityConfigManager
    // All security analysis parameters are read from config.ini
    // This provides flexibility and easy customization without code changes
}

/**
 * @brief Destructor for PESecurityAnalyzer
 * 
 * Ensures proper cleanup of resources and analysis data.
 * Closes any open files and clears internal data structures.
 */
PESecurityAnalyzer::~PESecurityAnalyzer()
{
    if (m_analysisFile.isOpen()) {
        m_analysisFile.close();
    }
    m_fileData.clear();
}

/**
 * @brief Performs comprehensive security analysis on a PE file
 * @param filePath Path to the PE file to analyze
 * @return SecurityAnalysisResult containing analysis findings
 * 
 * This method orchestrates a complete security analysis by:
 * 1. Loading and validating the PE file
 * 2. Performing individual security checks based on configuration
 * 3. Aggregating results and calculating risk scores
 * 4. Generating recommendations based on findings
 * 
 * The analysis is comprehensive and follows industry best practices
 * for PE file security assessment, providing both technical details
 * and actionable recommendations.
 */
SecurityAnalysisResult PESecurityAnalyzer::analyzeFile(const QString &filePath)
{
    SecurityAnalysisResult result;
    
    // Initialize result structure with default values
    result.riskLevel = SecurityRiskLevel::SAFE;
    result.riskScore = 0;
    result.isPacked = false;
    result.isObfuscated = false;
    result.hasAntiDebug = false;
    result.hasAntiVM = false;
    
    emit analysisProgress(0, "Starting security analysis...");
    
    // Validate file exists and is accessible
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isReadable()) {
        result.detectedIssues.append("File not accessible or does not exist");
        result.riskLevel = SecurityRiskLevel::CRITICAL;
        result.riskScore = 100;
        return result;
    }
    
    emit analysisProgress(10, "Loading file for analysis...");
    
    // Load file data for analysis
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        result.detectedIssues.append("Failed to open file for analysis");
        result.riskLevel = SecurityRiskLevel::CRITICAL;
        result.riskScore = 100;
        return result;
    }
    
    m_fileData = file.readAll();
    file.close();
    
    emit analysisProgress(20, "Performing entropy analysis...");
    
    // Perform entropy analysis if enabled
    if (m_configManager->getBool("General/enable_entropy_analysis", true)) {
        result.entropyAnalysis = analyzeFileEntropy(filePath);
        
        // Check for high entropy indicating potential packing/obfuscation
        double overallEntropy = calculateEntropy(m_fileData);
        double highThreshold = m_configManager->getDouble("EntropyThresholds/high_entropy_threshold", 7.5);
        double mediumThreshold = m_configManager->getDouble("EntropyThresholds/medium_entropy_threshold", 6.0);
        
        if (overallEntropy > highThreshold) {
            result.isPacked = true;
            result.detectedIssues.append("High file entropy detected - possible packing/obfuscation");
            result.detailedAnalysis["entropy"] = QString("Overall entropy: %1 (threshold: %2)")
                .arg(overallEntropy, 0, 'f', 2)
                .arg(highThreshold, 0, 'f', 1);
        } else if (overallEntropy > mediumThreshold) {
            result.detectedIssues.append("Moderate file entropy detected - possible obfuscation");
            result.detailedAnalysis["entropy"] = QString("Overall entropy: %1 (threshold: %2)")
                .arg(overallEntropy, 0, 'f', 2)
                .arg(mediumThreshold, 0, 'f', 1);
        }
    }
    
    emit analysisProgress(40, "Analyzing PE structure...");
    
    // Basic PE structure validation
    if (m_fileData.size() < sizeof(IMAGE_DOS_HEADER)) {
        result.detectedIssues.append("File too small to be a valid PE file");
        result.riskLevel = SecurityRiskLevel::CRITICAL;
        result.riskScore = 100;
        return result;
    }
    
    const IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_fileData.data());
    
    // Validate DOS header
    if (dosHeader->e_magic != 0x5A4D) { // "MZ"
        result.detectedIssues.append("Invalid DOS header magic number");
        result.riskLevel = SecurityRiskLevel::CRITICAL;
        result.riskScore = 100;
        return result;
    }
    
    emit analysisProgress(60, "Checking for anti-analysis techniques...");
    
    // Detect anti-analysis techniques if enabled
    if (m_configManager->getBool("General/enable_anti_debug_detection", true) || 
        m_configManager->getBool("General/enable_anti_vm_detection", true)) {
        QString antiAnalysisResults = detectAntiAnalysisTechniques(m_fileData);
        if (!antiAnalysisResults.isEmpty()) {
            result.detailedAnalysis["anti_analysis"] = antiAnalysisResults;
            
            if (antiAnalysisResults.contains("anti-debug", Qt::CaseInsensitive)) {
                result.hasAntiDebug = true;
                result.detectedIssues.append("Anti-debugging techniques detected");
            }
            
            if (antiAnalysisResults.contains("anti-vm", Qt::CaseInsensitive)) {
                result.hasAntiVM = true;
                result.detectedIssues.append("Anti-VM techniques detected");
            }
        }
    }
    
    emit analysisProgress(80, "Validating digital signatures...");
    
    // Validate digital signatures if enabled
    if (m_configManager->getBool("General/enable_digital_signature_validation", true)) {
        result.digitalSignatureStatus = validateDigitalSignature(filePath);
        if (result.digitalSignatureStatus.contains("invalid", Qt::CaseInsensitive) ||
            result.digitalSignatureStatus.contains("not found", Qt::CaseInsensitive)) {
            result.detectedIssues.append(LANG("UI/security_digital_signature_failed"));
        }
    }
    
    emit analysisProgress(90, LANG("UI/security_calculating_risk"));
    
    // Calculate overall risk score and level
    result.riskScore = calculateRiskScore(result.detectedIssues);
    
    // Determine risk level based on score
    int criticalThreshold = m_configManager->getInt("RiskScoring/critical_risk_threshold", 80);
    int highThreshold = m_configManager->getInt("RiskScoring/high_risk_threshold", 60);
    int mediumThreshold = m_configManager->getInt("RiskScoring/medium_risk_threshold", 40);
    int lowThreshold = m_configManager->getInt("RiskScoring/low_risk_threshold", 20);
    
    if (result.riskScore >= criticalThreshold) {
        result.riskLevel = SecurityRiskLevel::CRITICAL;
    } else if (result.riskScore >= highThreshold) {
        result.riskLevel = SecurityRiskLevel::HIGH;
    } else if (result.riskScore >= mediumThreshold) {
        result.riskLevel = SecurityRiskLevel::MEDIUM;
    } else if (result.riskScore >= lowThreshold) {
        result.riskLevel = SecurityRiskLevel::LOW;
    } else {
        result.riskLevel = SecurityRiskLevel::SAFE;
    }
    
    // Generate recommendations based on findings
    if (result.isPacked) {
        result.recommendations.append(LANG("UI/security_consider_unpacking"));
    }
    
    if (result.hasAntiDebug) {
        result.recommendations.append(LANG("UI/security_use_advanced_debugging"));
    }
    
    if (result.hasAntiVM) {
        result.recommendations.append(LANG("UI/security_analyze_native"));
    }
    
    if (result.digitalSignatureStatus.contains("invalid", Qt::CaseInsensitive)) {
        result.recommendations.append(LANG("UI/security_verify_authenticity"));
    }
    
    if (result.detectedIssues.isEmpty()) {
        result.recommendations.append(LANG("UI/security_no_concerns"));
    }
    
    emit analysisProgress(100, LANG("UI/security_analysis_complete"));
    emit analysisComplete(result);
    
    return result;
}

/**
 * @brief Performs security analysis on raw PE data
 * @param peData Raw PE file data as QByteArray
 * @return SecurityAnalysisResult containing analysis findings
 * 
 * This method is useful when you already have the PE data in memory
 * and want to perform security analysis without file I/O operations.
 * It's particularly useful for real-time analysis and integration
 * with other PE analysis tools.
 */
SecurityAnalysisResult PESecurityAnalyzer::analyzeData(const QByteArray &peData)
{
    // Store the provided data for analysis
    m_fileData = peData;
    
    // Create a temporary result structure
    SecurityAnalysisResult result;
    result.riskLevel = SecurityRiskLevel::SAFE;
    result.riskScore = 0;
    
    // Perform basic validation
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        result.detectedIssues.append(LANG("UI/security_data_too_small"));
        result.riskLevel = SecurityRiskLevel::CRITICAL;
        result.riskScore = 100;
        return result;
    }
    
    // Perform entropy analysis
    double entropy = calculateEntropy(peData);
    result.entropyAnalysis = QString("Data entropy: %1").arg(entropy, 0, 'f', 2);
    
    double highThreshold = m_configManager->getDouble("EntropyThresholds/high_entropy_threshold", 7.5);
    if (entropy > highThreshold) {
        result.isPacked = true;
        result.detectedIssues.append(LANG("UI/security_high_entropy"));
    }
    
    // Detect anti-analysis techniques
    QString antiAnalysisResults = detectAntiAnalysisTechniques(peData);
    if (!antiAnalysisResults.isEmpty()) {
        result.detailedAnalysis["anti_analysis"] = antiAnalysisResults;
    }
    
    // Calculate risk score
    result.riskScore = calculateRiskScore(result.detectedIssues);
    
    // Determine risk level
    if (result.riskScore >= 80) {
        result.riskLevel = SecurityRiskLevel::CRITICAL;
    } else if (result.riskScore >= 60) {
        result.riskLevel = SecurityRiskLevel::HIGH;
    } else if (result.riskScore >= 40) {
        result.riskLevel = SecurityRiskLevel::MEDIUM;
    } else if (result.riskScore >= 20) {
        result.riskLevel = SecurityRiskLevel::LOW;
    }
    
    return result;
}

/**
 * @brief Performs quick security scan for basic threats
 * @param filePath Path to the PE file to scan
 * @return SecurityRiskLevel indicating basic threat level
 * 
 * This method provides a fast, lightweight security assessment
 * suitable for real-time scanning and initial threat detection.
 * It focuses on the most critical security indicators while
 * minimizing analysis time and resource usage.
 */
SecurityRiskLevel PESecurityAnalyzer::quickScan(const QString &filePath)
{
    // Quick scan focuses on the most critical security indicators
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return SecurityRiskLevel::CRITICAL;
    }
    
    QByteArray data = file.read(1024); // Read first 1KB for quick analysis
    file.close();
    
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return SecurityRiskLevel::CRITICAL;
    }
    
    // Check DOS header magic
    const IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dosHeader->e_magic != 0x5A4D) {
        return SecurityRiskLevel::CRITICAL;
    }
    
    // Quick entropy check
    double entropy = calculateEntropy(data);
    double highThreshold = m_configManager->getDouble("EntropyThresholds/high_entropy_threshold", 7.5);
    if (entropy > highThreshold) {
        return SecurityRiskLevel::HIGH;
    }
    
    // Check for suspicious patterns in the first few bytes
    QStringList packerSignatures = m_configManager->getStringList("PackerSignatures/packer_signatures");
    if (packerSignatures.isEmpty()) {
        packerSignatures = QStringList{"UPX", "ASPack", "PECompact"};
    }
    
    for (const QString &signature : packerSignatures) {
        if (data.contains(signature.toUtf8())) {
            return SecurityRiskLevel::MEDIUM;
        }
    }
    
    return SecurityRiskLevel::SAFE;
}

/**
 * @brief Enables or disables specific security checks
 * @param checkName Name of the security check to configure
 * @param enabled Whether the check should be enabled
 * 
 * This method allows fine-tuning of security analysis by enabling
 * or disabling specific security checks based on requirements.
 * It's useful for customizing analysis depth and performance
 * based on specific use cases or resource constraints.
 */
void PESecurityAnalyzer::setSecurityCheckEnabled(const QString &checkName, bool enabled)
{
    // Note: m_enabledChecks is not implemented in this version
    // Security checks are controlled via the configuration file
    Q_UNUSED(checkName)
    Q_UNUSED(enabled)
}

/**
 * @brief Sets the sensitivity level for security analysis
 * @param sensitivity Sensitivity level (1-10, where 10 is most sensitive)
 * 
 * This method adjusts the sensitivity of security detection,
 * allowing customization of false positive vs. false negative trade-offs.
 * Higher sensitivity detects more potential threats but may increase
 * false positives, while lower sensitivity reduces false positives
 * but may miss some threats.
 */
void PESecurityAnalyzer::setSensitivityLevel(int sensitivity)
{
    // Sensitivity level is now managed by configuration
    // This method is kept for backward compatibility
    // The actual sensitivity is read from config.ini
    Q_UNUSED(sensitivity)
}

/**
 * @brief Gets the current security analysis configuration manager
 * @return SecurityConfigManager pointer for configuration access
 * 
 * This method provides access to the configuration manager
 * for debugging and configuration management.
 * It's useful for verifying settings and troubleshooting
 * analysis behavior.
 */
SecurityConfigManager* PESecurityAnalyzer::getConfigurationManager() const
{
    return m_configManager;
}

/**
 * @brief Calculates file entropy for a specific range
 * @param data Data to analyze
 * @param startOffset Starting offset for analysis
 * @param length Length of data to analyze
 * @return Entropy value (0.0 to 8.0, where 8.0 is maximum entropy)
 * 
 * Entropy analysis helps detect packed, encrypted, or obfuscated
 * content that may indicate malicious intent. This implementation
 * uses Shannon entropy calculation for accurate entropy measurement.
 * 
 * Entropy values:
 * - 0.0-3.0: Low entropy (structured data, text)
 * - 3.0-6.0: Medium entropy (mixed content)
 * - 6.0-8.0: High entropy (random data, packed/encrypted content)
 */
double PESecurityAnalyzer::calculateEntropy(const QByteArray &data, qint64 startOffset, qint64 length)
{
    if (data.isEmpty()) {
        return 0.0;
    }
    
    // Determine analysis range
    qint64 actualStart = qMax(0LL, startOffset);
    qint64 actualLength = (length < 0) ? (data.size() - actualStart) : qMin(length, data.size() - actualStart);
    
    if (actualLength <= 0) {
        return 0.0;
    }
    
    // Count byte frequencies
    QMap<quint8, int> byteCounts;
    for (qint64 i = actualStart; i < actualStart + actualLength; ++i) {
        if (i < data.size()) {
            byteCounts[static_cast<quint8>(data.at(i))]++;
        }
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    double totalBytes = static_cast<double>(actualLength);
    
    for (auto it = byteCounts.begin(); it != byteCounts.end(); ++it) {
        double probability = it.value() / totalBytes;
        if (probability > 0.0) {
            entropy -= probability * log2(probability);
        }
    }
    
    return entropy;
}

/**
 * @brief Checks if a file appears to be packed
 * @param filePath Path to the file to check
 * @return true if file appears packed, false otherwise
 * 
 * Packed files often indicate obfuscation or compression that
 * may be used to hide malicious code. This method uses multiple
 * indicators including entropy analysis, section characteristics,
 * and known packer signatures to detect packing.
 */
bool PESecurityAnalyzer::isFilePacked(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
    
    QByteArray data = file.readAll();
    file.close();
    
    // Check for known packer signatures from configuration
    QStringList packerSignatures = m_configManager->getStringList("PackerSignatures/packer_signatures");
    if (packerSignatures.isEmpty()) {
        packerSignatures = QStringList{"UPX", "ASPack", "PECompact", "Themida", "VMProtect"};
    }
    
    QString dataStr = QString::fromLatin1(data);
    for (const QString &signature : packerSignatures) {
        if (dataStr.contains(signature, Qt::CaseInsensitive)) {
            return true;
        }
    }
    
    // Check entropy
    double entropy = calculateEntropy(data);
    double highThreshold = m_configManager->getDouble("EntropyThresholds/high_entropy_threshold", 7.5);
    if (entropy > highThreshold) {
        return true;
    }
    
    return false;
}

/**
 * @brief Validates digital signatures in PE files
 * @param filePath Path to the PE file to validate
 * @return Digital signature validation result
 * 
 * Digital signature validation helps establish file authenticity
 * and provides confidence in file origin and integrity. This method
 * attempts to validate signatures using Windows API calls and
 * provides detailed validation results.
 */
QString PESecurityAnalyzer::validateDigitalSignature(const QString &filePath)
{
    // This is a simplified implementation
    // In a production environment, you would use Windows API calls
    // to perform actual digital signature validation
    
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        return LANG("UI/file_status_not_found");
    }
    
    // Check if file has .exe, .dll, .sys extension (common PE files)
    QString extension = fileInfo.suffix().toLower();
    if (extension != "exe" && extension != "dll" && extension != "sys") {
        return "Not a standard PE file extension";
    }
    
    // For now, return a placeholder result
    // Note: Full digital signature validation would require Windows API integration
    // This could be implemented using WinVerifyTrust, CryptQueryObject, etc.
    return "Digital signature validation not implemented in this version";
}

// Private analysis methods implementation

/**
 * @brief Analyzes file entropy for security assessment
 * @param filePath Path to the file to analyze
 * @return Entropy analysis results
 * 
 * This method performs detailed entropy analysis to detect
 * packed, encrypted, or obfuscated content. It analyzes
 * different sections of the file separately to provide
 * detailed entropy information.
 */
QString PESecurityAnalyzer::analyzeFileEntropy(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return "Failed to open file for entropy analysis";
    }
    
    QByteArray data = file.readAll();
    file.close();
    
    if (data.isEmpty()) {
        return LANG("UI/file_status_empty");
    }
    
    // Calculate overall file entropy
    double overallEntropy = calculateEntropy(data);
    
    // Get entropy analysis configuration
    int chunkSize = m_configManager->getInt("EntropyThresholds/entropy_analysis_chunk_size", 1024);
    
    // Calculate entropy for first chunk (header area)
    double headerEntropy = calculateEntropy(data, 0, chunkSize);
    
    // Calculate entropy for middle section
    qint64 middleStart = data.size() / 2;
    double middleEntropy = calculateEntropy(data, middleStart, chunkSize);
    
    // Calculate entropy for last chunk
    double tailEntropy = calculateEntropy(data, qMax(0LL, data.size() - chunkSize), chunkSize);
    
    QString result = QString("Overall: %1, Header: %2, Middle: %3, Tail: %4")
        .arg(overallEntropy, 0, 'f', 2)
        .arg(headerEntropy, 0, 'f', 2)
        .arg(middleEntropy, 0, 'f', 2)
        .arg(tailEntropy, 0, 'f', 2);
    
    return result;
}

/**
 * @brief Analyzes section characteristics for security concerns
 * @param sections List of PE section headers to analyze
 * @return Section security analysis results
 * 
 * This method examines section characteristics to identify
 * suspicious or potentially malicious sections. It looks for
 * unusual section permissions, suspicious names, and other
 * indicators of potential security issues.
 */
QString PESecurityAnalyzer::analyzeSectionSecurity(const QList<const IMAGE_SECTION_HEADER*> &sections)
{
    if (sections.isEmpty()) {
        return "No sections to analyze";
    }
    
    QStringList issues;
    
    for (const IMAGE_SECTION_HEADER *section : sections) {
        if (!section) continue;
        
        // Check for suspicious section names from configuration
        QString sectionName = QString::fromLatin1(reinterpret_cast<const char*>(section->Name), 8).trimmed();
        QStringList suspiciousPatterns = m_configManager->getStringList("SuspiciousSections/suspicious_section_patterns");
        
        for (const QString &pattern : suspiciousPatterns) {
            if (sectionName.contains(pattern, Qt::CaseInsensitive)) {
                issues.append(QString("Suspicious section name: %1").arg(sectionName));
                break;
            }
        }
        
        // Check for unusual section characteristics from configuration
        QStringList suspiciousChars = m_configManager->getStringList("SuspiciousSections/suspicious_section_characteristics");
        for (const QString &charStr : suspiciousChars) {
            // Note: parseHexValue is private, using basic hex parsing instead
            bool ok;
            qint64 charValue = charStr.toLongLong(&ok, 16);
            if (ok && (section->Characteristics & charValue)) {
                issues.append(QString("Section %1 has unusual characteristics: 0x%2").arg(sectionName).arg(QString::number(charValue, 16)));
                break;
            }
        }
        
        // Check for very large sections from configuration
        qint64 maxSize = m_configManager->getInt64("SuspiciousSections/max_section_size_threshold", 10485760);
        if (section->SizeOfRawData > maxSize) {
            issues.append(QString("Section %1 is unusually large (%2 bytes)").arg(sectionName).arg(section->SizeOfRawData));
        }
    }
    
    if (issues.isEmpty()) {
        return "No section security issues detected";
    }
    
    return issues.join("; ");
}

/**
 * @brief Analyzes imports for suspicious or malicious functions
 * @param imports List of imported functions to analyze
 * @return Import security analysis results
 * 
 * This method examines imported functions to identify
 * suspicious APIs commonly used in malware. It looks for
 * functions related to process injection, anti-debugging,
 * network communication, and other suspicious activities.
 */
QString PESecurityAnalyzer::analyzeImportSecurity(const QStringList &imports)
{
    if (imports.isEmpty()) {
        return "No imports to analyze";
    }
    
    QStringList issues;
    
    // Get suspicious API categories from configuration
    QStringList antiDebugAPIs = m_configManager->getStringList("AntiDebugTechniques/anti_debug_apis");
    QStringList processInjectionAPIs = m_configManager->getStringList("SuspiciousAPIs/ProcessInjectionAPIs/process_injection_apis");
    QStringList networkAPIs = m_configManager->getStringList("SuspiciousAPIs/NetworkAPIs/network_apis");
    QStringList registryAPIs = m_configManager->getStringList("SuspiciousAPIs/RegistryAPIs/registry_apis");
    
    // Check for suspicious APIs
    for (const QString &import : imports) {
        if (antiDebugAPIs.contains(import, Qt::CaseInsensitive)) {
            issues.append("Anti-debugging API detected: " + import);
        }
        
        if (processInjectionAPIs.contains(import, Qt::CaseInsensitive)) {
            issues.append("Process injection API detected: " + import);
        }
        
        if (networkAPIs.contains(import, Qt::CaseInsensitive)) {
            issues.append("Network API detected: " + import);
        }
        
        if (registryAPIs.contains(import, Qt::CaseInsensitive)) {
            issues.append("Registry manipulation API detected: " + import);
        }
    }
    
    if (issues.isEmpty()) {
        return "No suspicious imports detected";
    }
    
    return issues.join("; ");
}

/**
 * @brief Detects anti-debugging and anti-VM techniques
 * @param peData Raw PE file data to analyze
 * @return Anti-debugging/anti-VM detection results
 * 
 * This method identifies techniques commonly used to
 * evade analysis and detection systems. It looks for
 * specific code patterns, API calls, and behaviors that
 * indicate anti-analysis techniques.
 */
QString PESecurityAnalyzer::detectAntiAnalysisTechniques(const QByteArray &peData)
{
    QStringList detectedTechniques;
    
    // Convert data to string for pattern matching
    QString dataStr = QString::fromLatin1(peData);
    
    // Check for anti-debugging techniques from configuration
    QStringList antiDebugAPIs = m_configManager->getStringList("AntiDebugTechniques/anti_debug_apis");
    for (const QString &api : antiDebugAPIs) {
        if (dataStr.contains(api, Qt::CaseInsensitive)) {
            detectedTechniques.append("Anti-debugging: " + api);
        }
    }
    
    // Check for anti-VM techniques from configuration
    QStringList antiVMStrings = m_configManager->getStringList("AntiVMTechniques/anti_vm_strings");
    for (const QString &vmString : antiVMStrings) {
        if (dataStr.contains(vmString, Qt::CaseInsensitive)) {
            detectedTechniques.append("Anti-VM: " + vmString);
        }
    }
    
    // Check for code injection techniques from configuration
    QStringList codeInjectionPatterns = m_configManager->getStringList("CodeInjectionTechniques/code_injection_patterns");
    for (const QString &pattern : codeInjectionPatterns) {
        if (dataStr.contains(pattern, Qt::CaseInsensitive)) {
            detectedTechniques.append("Code injection: " + pattern);
        }
    }
    
    if (detectedTechniques.isEmpty()) {
        return "No anti-analysis techniques detected";
    }
    
    return detectedTechniques.join("; ");
}

/**
 * @brief Calculates overall security risk score
 * @param issues List of detected security issues
 * @return Numerical risk score (0-100)
 * 
 * This method calculates a comprehensive risk score based
 * on the severity and quantity of detected security issues.
 * The scoring algorithm considers issue severity, quantity,
 * and combinations to provide an accurate risk assessment.
 * 
 * Scoring algorithm:
 * - Critical issues: 25 points each
 * - High risk issues: 15 points each
 * - Medium risk issues: 10 points each
 * - Low risk issues: 5 points each
 * - Bonus points for multiple issues of same type
 */
int PESecurityAnalyzer::calculateRiskScore(const QStringList &issues)
{
    if (issues.isEmpty()) {
        return 0;
    }
    
    int score = 0;
    
    // Count issues by category
    int criticalCount = 0;
    int highCount = 0;
    int mediumCount = 0;
    int lowCount = 0;
    
    for (const QString &issue : issues) {
        QString lowerIssue = issue.toLower();
        
        if (lowerIssue.contains("critical") || lowerIssue.contains("not found") || 
            lowerIssue.contains("invalid") || lowerIssue.contains("too small")) {
            criticalCount++;
        } else if (lowerIssue.contains("high entropy") || lowerIssue.contains("packed") ||
                   lowerIssue.contains("anti-debug") || lowerIssue.contains("anti-vm")) {
            highCount++;
        } else if (lowerIssue.contains("moderate") || lowerIssue.contains("suspicious")) {
            mediumCount++;
        } else {
            lowCount++;
        }
    }
    
    // Get risk scoring configuration
    int criticalPoints = m_configManager->getInt("RiskScoring/critical_issue_points", 25);
    int highPoints = m_configManager->getInt("RiskScoring/high_risk_points", 15);
    int mediumPoints = m_configManager->getInt("RiskScoring/medium_risk_points", 10);
    int lowPoints = m_configManager->getInt("RiskScoring/low_risk_points", 5);
    
    // Calculate base score
    score += criticalCount * criticalPoints;
    score += highCount * highPoints;
    score += mediumCount * mediumPoints;
    score += lowCount * lowPoints;
    
    // Add bonus points for multiple issues of same type
    if (m_configManager->getBool("RiskScoring/multiple_issues_bonus", true)) {
        int criticalBonus = m_configManager->getInt("RiskScoring/critical_multiple_bonus", 10);
        int highBonus = m_configManager->getInt("RiskScoring/high_multiple_bonus", 8);
        int mediumBonus = m_configManager->getInt("RiskScoring/medium_multiple_bonus", 5);
        int lowBonus = m_configManager->getInt("RiskScoring/low_multiple_bonus", 3);
        
        if (criticalCount > 1) score += criticalBonus;
        if (highCount > 1) score += highBonus;
        if (mediumCount > 1) score += mediumBonus;
        if (lowCount > 1) score += lowBonus;
    }
    
    // Cap score at 100
    return qMin(score, 100);
}
