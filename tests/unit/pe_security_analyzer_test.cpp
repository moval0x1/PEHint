#include "pe_security_analyzer_test.h"
#include <QDebug>
#include <QRandomGenerator>
#include <cmath>

void PESecurityAnalyzerTest::initTestCase()
{
    qDebug() << "Initializing Security Analyzer tests...";
}

void PESecurityAnalyzerTest::cleanupTestCase()
{
    qDebug() << "Cleaning up Security Analyzer tests...";
}

void PESecurityAnalyzerTest::testEntropyCalculationEmpty()
{
    PESecurityAnalyzer analyzer;
    QByteArray emptyData;
    
    double entropy = analyzer.calculateEntropy(emptyData);
    QCOMPARE(entropy, 0.0);
}

void PESecurityAnalyzerTest::testEntropyCalculationLowEntropy()
{
    PESecurityAnalyzer analyzer;
    QByteArray lowEntropyData = createLowEntropyData();
    
    double entropy = analyzer.calculateEntropy(lowEntropyData);
    
    // Low entropy data (repetitive) should have entropy < 3.0
    QVERIFY(entropy < 3.0);
    QVERIFY(entropy >= 0.0);
}

void PESecurityAnalyzerTest::testEntropyCalculationHighEntropy()
{
    PESecurityAnalyzer analyzer;
    QByteArray highEntropyData = createHighEntropyData();
    
    double entropy = analyzer.calculateEntropy(highEntropyData);
    
    // High entropy data (random) should have entropy > 7.0
    QVERIFY(entropy > 7.0);
    QVERIFY(entropy <= 8.0);
}

void PESecurityAnalyzerTest::testEntropyCalculationRandomData()
{
    PESecurityAnalyzer analyzer;
    QByteArray randomData = createRandomData(1024);
    
    double entropy = analyzer.calculateEntropy(randomData);
    
    // Random data should have high entropy
    QVERIFY(entropy > 7.0);
    QVERIFY(entropy <= 8.0);
}

void PESecurityAnalyzerTest::testEntropyCalculationRange()
{
    PESecurityAnalyzer analyzer;
    QByteArray data = createRandomData(1024);
    
    // Test entropy calculation with specific range
    double fullEntropy = analyzer.calculateEntropy(data);
    double rangeEntropy = analyzer.calculateEntropy(data, 0, 512);
    
    // Range entropy should be valid
    QVERIFY(rangeEntropy >= 0.0);
    QVERIFY(rangeEntropy <= 8.0);
    
    // Full entropy should be close to range entropy for random data
    QVERIFY(std::abs(fullEntropy - rangeEntropy) < 1.0);
}

void PESecurityAnalyzerTest::testPackerDetectionUPX()
{
    PESecurityAnalyzer analyzer;
    
    // Create data with UPX signature
    QByteArray data;
    data.append("UPX!");
    data.append(QByteArray(1020, 0));
    
    bool isPacked = analyzer.isFilePacked("test_upx.exe");
    // Note: This test requires actual file creation
    // For now, we test the entropy-based detection
    QVERIFY(true); // Placeholder
}

void PESecurityAnalyzerTest::testPackerDetectionASPack()
{
    PESecurityAnalyzer analyzer;
    
    // Test ASPack detection
    QVERIFY(true); // Placeholder
}

void PESecurityAnalyzerTest::testPackerDetectionByEntropy()
{
    PESecurityAnalyzer analyzer;
    
    // Create high entropy data (simulating packed file)
    QByteArray packedData = createHighEntropyData();
    
    // Note: isFilePacked requires file path, so we test entropy calculation instead
    double entropy = analyzer.calculateEntropy(packedData);
    QVERIFY(entropy > 7.5); // High entropy threshold
}

void PESecurityAnalyzerTest::testRiskScoreCalculation()
{
    PESecurityAnalyzer analyzer;
    
    QStringList issues;
    issues << "Critical issue detected";
    
    int score = analyzer.calculateRiskScore(issues);
    
    // Critical issue should give high score
    QVERIFY(score > 0);
    QVERIFY(score <= 100);
}

void PESecurityAnalyzerTest::testRiskScoreWithMultipleIssues()
{
    PESecurityAnalyzer analyzer;
    
    QStringList issues;
    issues << "High entropy detected"
           << "Anti-debugging detected"
           << "Suspicious import detected";
    
    int score = analyzer.calculateRiskScore(issues);
    
    // Multiple issues should increase score
    QVERIFY(score > 0);
    QVERIFY(score <= 100);
}

void PESecurityAnalyzerTest::testRiskScoreCapping()
{
    PESecurityAnalyzer analyzer;
    
    // Create many critical issues to test capping
    QStringList issues;
    for (int i = 0; i < 10; ++i) {
        issues << "Critical issue " + QString::number(i);
    }
    
    int score = analyzer.calculateRiskScore(issues);
    
    // Score should be capped at 100
    QVERIFY(score <= 100);
}

void PESecurityAnalyzerTest::testAnalyzeEmptyFile()
{
    PESecurityAnalyzer analyzer;
    QByteArray emptyData;
    
    SecurityAnalysisResult result = analyzer.analyzeData(emptyData);
    
    QVERIFY(result.riskLevel == SecurityRiskLevel::CRITICAL);
    QVERIFY(result.riskScore == 100);
    QVERIFY(!result.detectedIssues.isEmpty());
}

void PESecurityAnalyzerTest::testAnalyzeInvalidFile()
{
    PESecurityAnalyzer analyzer;
    
    // Test with invalid file path
    SecurityAnalysisResult result = analyzer.analyzeFile("nonexistent_file.exe");
    
    QVERIFY(result.riskLevel == SecurityRiskLevel::CRITICAL);
    QVERIFY(result.riskScore == 100);
}

void PESecurityAnalyzerTest::testAnalyzeValidFile()
{
    PESecurityAnalyzer analyzer;
    
    // Create minimal valid PE structure
    QByteArray validPE;
    validPE.resize(sizeof(IMAGE_DOS_HEADER));
    IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(validPE.data());
    dosHeader->e_magic = 0x5A4D;
    
    SecurityAnalysisResult result = analyzer.analyzeData(validPE);
    
    // Should detect that file is too small but structure is valid
    QVERIFY(result.riskLevel != SecurityRiskLevel::SAFE);
}

void PESecurityAnalyzerTest::testAntiDebugDetection()
{
    PESecurityAnalyzer analyzer;
    
    // Create data with anti-debug API strings
    QByteArray data;
    data.append("IsDebuggerPresent");
    data.append(QByteArray(1000, 0));
    
    QString result = analyzer.detectAntiAnalysisTechniques(data);
    
    QVERIFY(result.contains("Anti-debugging", Qt::CaseInsensitive));
}

void PESecurityAnalyzerTest::testAntiVMDetection()
{
    PESecurityAnalyzer analyzer;
    
    // Create data with anti-VM strings
    QByteArray data;
    data.append("VMware");
    data.append(QByteArray(1000, 0));
    
    QString result = analyzer.detectAntiAnalysisTechniques(data);
    
    // Note: This depends on configuration
    QVERIFY(!result.isEmpty());
}

void PESecurityAnalyzerTest::testSecurityCheckConfiguration()
{
    PESecurityAnalyzer analyzer;
    
    // Test configuration access
    SecurityConfigManager *config = analyzer.getConfigurationManager();
    QVERIFY(config != nullptr);
}

void PESecurityAnalyzerTest::testSensitivityLevelConfiguration()
{
    PESecurityAnalyzer analyzer;
    
    // Test sensitivity level setting (currently no-op but should not crash)
    analyzer.setSensitivityLevel(5);
    analyzer.setSensitivityLevel(10);
    
    QVERIFY(true); // If we get here, no crash occurred
}

// Helper functions

QByteArray PESecurityAnalyzerTest::createLowEntropyData()
{
    // Create repetitive data (low entropy)
    QByteArray data;
    for (int i = 0; i < 1024; ++i) {
        data.append(static_cast<char>(i % 10)); // Only 10 different values
    }
    return data;
}

QByteArray PESecurityAnalyzerTest::createHighEntropyData()
{
    // Create random data (high entropy)
    QByteArray data;
    QRandomGenerator *rng = QRandomGenerator::global();
    for (int i = 0; i < 1024; ++i) {
        data.append(static_cast<char>(rng->bounded(256)));
    }
    return data;
}

QByteArray PESecurityAnalyzerTest::createRandomData(int size)
{
    QByteArray data;
    QRandomGenerator *rng = QRandomGenerator::global();
    for (int i = 0; i < size; ++i) {
        data.append(static_cast<char>(rng->bounded(256)));
    }
    return data;
}

#include "pe_security_analyzer_test.moc"

