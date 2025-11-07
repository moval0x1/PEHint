#include "pe_utils_test.h"
#include "pe_utils.h"
#include <QDebug>

void PEUtilsTest::initTestCase()
{
    qDebug() << "Initializing PE Utils tests...";
}

void PEUtilsTest::cleanupTestCase()
{
    qDebug() << "Cleaning up PE Utils tests...";
}

void PEUtilsTest::testDOSMagicValidation()
{
    QVERIFY(PEUtils::isValidDOSMagic(0x5A4D)); // Valid "MZ"
    QVERIFY(!PEUtils::isValidDOSMagic(0x0000)); // Invalid
    QVERIFY(!PEUtils::isValidDOSMagic(0xFFFF)); // Invalid
}

void PEUtilsTest::testPESignatureValidation()
{
    QVERIFY(PEUtils::isValidPESignature(0x00004550)); // Valid "PE\0\0"
    QVERIFY(!PEUtils::isValidPESignature(0x00000000)); // Invalid
    QVERIFY(!PEUtils::isValidPESignature(0xFFFFFFFF)); // Invalid
}

void PEUtilsTest::testOptionalHeaderMagicValidation()
{
    QVERIFY(PEUtils::isValidOptionalHeaderMagic(0x10B)); // PE32
    QVERIFY(PEUtils::isValidOptionalHeaderMagic(0x20B)); // PE32+
    QVERIFY(!PEUtils::isValidOptionalHeaderMagic(0x0000)); // Invalid
}

void PEUtilsTest::testSectionTableOffsetCalculation()
{
    quint32 dosHeaderOffset = 0;
    quint32 peOffset = 64; // e_lfanew
    quint16 optionalHeaderSize = 224; // Standard PE32 optional header size
    
    quint32 sectionTableOffset = PEUtils::calculateSectionTableOffset(peOffset, optionalHeaderSize);
    
    // Section table should be after PE signature + file header + optional header
    quint32 expected = peOffset + sizeof(IMAGE_FILE_HEADER) + optionalHeaderSize;
    QCOMPARE(sectionTableOffset, expected);
}

void PEUtilsTest::testDataDirectoryOffsetCalculation()
{
    quint32 optionalHeaderStart = 64 + 4 + sizeof(IMAGE_FILE_HEADER); // After PE sig + file header
    quint16 optionalHeaderSize = 224;
    quint32 dataDirIndex = 0; // First data directory
    
    quint32 dataDirOffset = PEUtils::calculateDataDirectoryOffset(
        optionalHeaderStart, optionalHeaderSize, dataDirIndex);
    
    // Data directories start at offset 96 in optional header (standard)
    quint32 expected = optionalHeaderStart + 96 + (dataDirIndex * sizeof(IMAGE_DATA_DIRECTORY));
    QCOMPARE(dataDirOffset, expected);
}

void PEUtilsTest::testHexFormatting()
{
    QString hex1 = PEUtils::formatHex(0x5A4D);
    QVERIFY(hex1.contains("5A4D", Qt::CaseInsensitive));
    
    QString hex2 = PEUtils::formatHex(0x00004550);
    QVERIFY(hex2.contains("4550", Qt::CaseInsensitive));
}

void PEUtilsTest::testRVAFormatting()
{
    QString rva1 = PEUtils::formatRVA(0x1000);
    QVERIFY(rva1.contains("1000", Qt::CaseInsensitive));
    
    QString rva2 = PEUtils::formatRVA(0x400000);
    QVERIFY(rva2.contains("400000", Qt::CaseInsensitive));
}

#include "pe_utils_test.moc"

