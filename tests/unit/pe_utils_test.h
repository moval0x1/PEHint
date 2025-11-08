#ifndef PE_UTILS_TEST_H
#define PE_UTILS_TEST_H

#include <QtTest>
#include "pe_utils.h"

class PEUtilsTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    
    // Validation tests
    void testDOSMagicValidation();
    void testPESignatureValidation();
    void testOptionalHeaderMagicValidation();
    
    // Calculation tests
    void testSectionTableOffsetCalculation();
    void testDataDirectoryOffsetCalculation();
    
    // Formatting tests
    void testHexFormatting();
    void testRVAFormatting();

private:
};

#endif // PE_UTILS_TEST_H

