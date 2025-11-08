#ifndef PE_SECURITY_ANALYZER_TEST_H
#define PE_SECURITY_ANALYZER_TEST_H

#include <QtTest>
#include "pe_security_analyzer.h"

class PESecurityAnalyzerTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    
    // Entropy tests
    void testEntropyCalculationEmpty();
    void testEntropyCalculationLowEntropy();
    void testEntropyCalculationHighEntropy();
    void testEntropyCalculationRandomData();
    void testEntropyCalculationRange();
    
    // Packer detection tests
    void testPackerDetectionUPX();
    void testPackerDetectionASPack();
    void testPackerDetectionByEntropy();
    
    // Risk scoring tests
    void testRiskScoreCalculation();
    void testRiskScoreWithMultipleIssues();
    void testRiskScoreCapping();
    
    // Security analysis tests
    void testAnalyzeEmptyFile();
    void testAnalyzeInvalidFile();
    void testAnalyzeValidFile();
    
    // Anti-analysis detection tests
    void testAntiDebugDetection();
    void testAntiVMDetection();
    
    // Configuration tests
    void testSecurityCheckConfiguration();
    void testSensitivityLevelConfiguration();

private:
    QByteArray createLowEntropyData();
    QByteArray createHighEntropyData();
    QByteArray createRandomData(int size);
};

#endif // PE_SECURITY_ANALYZER_TEST_H

