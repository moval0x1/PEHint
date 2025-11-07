#include "pe_parser_test.h"
#include "pe_utils.h"
#include "pe_structures.h"
#include <QFile>
#include <QDir>
#include <QDebug>

void PEParserTest::initTestCase()
{
    qDebug() << "Initializing PE Parser tests...";
}

void PEParserTest::cleanupTestCase()
{
    qDebug() << "Cleaning up PE Parser tests...";
}

void PEParserTest::testValidDOSHeader()
{
    // Create a minimal valid PE file structure
    QByteArray testData;
    testData.resize(sizeof(IMAGE_DOS_HEADER));
    
    IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(testData.data());
    dosHeader->e_magic = 0x5A4D; // "MZ"
    dosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
    
    // Test DOS header validation
    QVERIFY(PEUtils::isValidDOSMagic(dosHeader->e_magic));
    QVERIFY(dosHeader->e_magic == 0x5A4D);
}

void PEParserTest::testInvalidDOSHeader()
{
    // Test invalid DOS magic
    QByteArray testData;
    testData.resize(sizeof(IMAGE_DOS_HEADER));
    
    IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(testData.data());
    dosHeader->e_magic = 0x0000; // Invalid magic
    
    QVERIFY(!PEUtils::isValidDOSMagic(dosHeader->e_magic));
}

void PEParserTest::testDOSHeaderMagicValidation()
{
    // Test valid magic
    QVERIFY(PEUtils::isValidDOSMagic(0x5A4D));
    
    // Test invalid magic values
    QVERIFY(!PEUtils::isValidDOSMagic(0x0000));
    QVERIFY(!PEUtils::isValidDOSMagic(0xFFFF));
    QVERIFY(!PEUtils::isValidDOSMagic(0x4D5A)); // Reversed
}

void PEParserTest::testPESignatureValidation()
{
    // Test valid PE signature
    QVERIFY(PEUtils::isValidPESignature(0x00004550)); // "PE\0\0"
    
    // Test invalid PE signatures
    QVERIFY(!PEUtils::isValidPESignature(0x00000000));
    QVERIFY(!PEUtils::isValidPESignature(0xFFFFFFFF));
    QVERIFY(!PEUtils::isValidPESignature(0x50450000)); // Reversed
}

void PEParserTest::testFileHeaderParsing()
{
    // This test would require a complete PE file structure
    // For now, we test the validation functions
    QVERIFY(true); // Placeholder - implement with actual PE file
}

void PEParserTest::testOptionalHeaderParsing()
{
    // Test optional header magic validation
    QVERIFY(PEUtils::isValidOptionalHeaderMagic(0x10B)); // PE32
    QVERIFY(PEUtils::isValidOptionalHeaderMagic(0x20B)); // PE32+
    
    // Test invalid magic
    QVERIFY(!PEUtils::isValidOptionalHeaderMagic(0x0000));
    QVERIFY(!PEUtils::isValidOptionalHeaderMagic(0xFFFF));
}

void PEParserTest::testSectionParsing()
{
    // Placeholder - implement with actual PE file
    QVERIFY(true);
}

void PEParserTest::testSectionTableValidation()
{
    // Placeholder - implement validation tests
    QVERIFY(true);
}

void PEParserTest::testDataDirectoryParsing()
{
    // Placeholder - implement data directory tests
    QVERIFY(true);
}

void PEParserTest::testLargeFileHandling()
{
    PEParserNew parser;
    
    // Test that large file threshold is correctly identified
    // Note: This would require creating a large test file
    QVERIFY(parser.isLargeFile() == false); // Empty parser should return false
}

void PEParserTest::testVeryLargeFileHandling()
{
    PEParserNew parser;
    
    // Test very large file threshold
    QVERIFY(true); // Placeholder
}

void PEParserTest::testInvalidFileHandling()
{
    PEParserNew parser;
    
    // Test loading non-existent file
    bool result = parser.loadFile("nonexistent_file.exe");
    QVERIFY(result == false);
    QVERIFY(parser.isValid() == false);
}

void PEParserTest::testCorruptedFileHandling()
{
    PEParserNew parser;
    
    // Test loading empty file
    QString tempFile = QDir::temp().absoluteFilePath("test_empty.exe");
    QFile file(tempFile);
    if (file.open(QIODevice::WriteOnly)) {
        file.close();
        
        bool result = parser.loadFile(tempFile);
        QVERIFY(result == false);
        
        QFile::remove(tempFile);
    }
}

void PEParserTest::testRVAtoFileOffset()
{
    PEParserNew parser;
    
    // Test RVA conversion (requires loaded PE file)
    // Placeholder - implement with actual PE file
    QVERIFY(true);
}

void PEParserTest::testFieldOffsetCalculation()
{
    PEParserNew parser;
    
    // Test field offset calculation
    QPair<quint32, quint32> offset = parser.getFieldOffset("e_magic");
    QVERIFY(offset.first == 0);
    QVERIFY(offset.second == sizeof(quint16));
}

QString PEParserTest::createTestPEFile()
{
    // Helper function to create a minimal valid PE file for testing
    // This is a placeholder - implement with actual PE file structure
    return QString();
}

void PEParserTest::cleanupTestFile(const QString &filePath)
{
    if (QFile::exists(filePath)) {
        QFile::remove(filePath);
    }
}

#include "pe_parser_test.moc"
