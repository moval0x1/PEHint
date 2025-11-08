#ifndef PE_PARSER_TEST_H
#define PE_PARSER_TEST_H

#include <QtTest>
#include "pe_parser_new.h"
#include "pe_data_model.h"

class PEParserTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    
    // DOS Header tests
    void testValidDOSHeader();
    void testInvalidDOSHeader();
    void testDOSHeaderMagicValidation();
    
    // PE Header tests
    void testPESignatureValidation();
    void testFileHeaderParsing();
    void testOptionalHeaderParsing();
    
    // Section tests
    void testSectionParsing();
    void testSectionTableValidation();
    
    // Data Directory tests
    void testDataDirectoryParsing();
    
    // Large file tests
    void testLargeFileHandling();
    void testVeryLargeFileHandling();
    
    // Error handling tests
    void testInvalidFileHandling();
    void testCorruptedFileHandling();
    
    // Utility tests
    void testRVAtoFileOffset();
    void testFieldOffsetCalculation();

private:
    QString createTestPEFile();
    void cleanupTestFile(const QString &filePath);
};

#endif // PE_PARSER_TEST_H

