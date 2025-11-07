#include "pe_data_model_test.h"
#include "pe_structures.h"
#include <QDebug>
#include <cstring>

void PEDataModelTest::initTestCase()
{
    qDebug() << "Initializing PE Data Model tests...";
}

void PEDataModelTest::cleanupTestCase()
{
    qDebug() << "Cleaning up PE Data Model tests...";
}

void PEDataModelTest::testFilePath()
{
    PEDataModel model;
    
    QString testPath = "test.exe";
    model.setFilePath(testPath);
    
    QCOMPARE(model.getFilePath(), testPath);
}

void PEDataModelTest::testFileSize()
{
    PEDataModel model;
    
    qint64 testSize = 1024 * 1024; // 1MB
    model.setFileSize(testSize);
    
    QCOMPARE(model.getFileSize(), testSize);
}

void PEDataModelTest::testDOSHeader()
{
    PEDataModel model;
    IMAGE_DOS_HEADER dosHeader = createTestDOSHeader();
    
    model.setDOSHeader(&dosHeader);
    const IMAGE_DOS_HEADER *retrieved = model.getDOSHeader();
    
    QVERIFY(retrieved != nullptr);
    QCOMPARE(retrieved->e_magic, dosHeader.e_magic);
    QCOMPARE(retrieved->e_lfanew, dosHeader.e_lfanew);
}

void PEDataModelTest::testFileHeader()
{
    PEDataModel model;
    IMAGE_FILE_HEADER fileHeader = createTestFileHeader();
    
    model.setFileHeader(&fileHeader);
    const IMAGE_FILE_HEADER *retrieved = model.getFileHeader();
    
    QVERIFY(retrieved != nullptr);
    QCOMPARE(retrieved->Machine, fileHeader.Machine);
    QCOMPARE(retrieved->NumberOfSections, fileHeader.NumberOfSections);
}

void PEDataModelTest::testOptionalHeader()
{
    PEDataModel model;
    IMAGE_OPTIONAL_HEADER optionalHeader = createTestOptionalHeader();
    
    model.setOptionalHeader(&optionalHeader);
    const IMAGE_OPTIONAL_HEADER *retrieved = model.getOptionalHeader();
    
    QVERIFY(retrieved != nullptr);
    QCOMPARE(retrieved->Magic, optionalHeader.Magic);
}

void PEDataModelTest::testAddSection()
{
    PEDataModel model;
    IMAGE_SECTION_HEADER section = createTestSectionHeader();
    
    model.addSection(&section);
    
    QCOMPARE(model.getSections().size(), 1);
}

void PEDataModelTest::testGetSections()
{
    PEDataModel model;
    
    // Add multiple sections
    for (int i = 0; i < 3; ++i) {
        IMAGE_SECTION_HEADER section = createTestSectionHeader();
        strncpy_s(reinterpret_cast<char*>(section.Name), 8, 
                  QString(".text%1").arg(i).toLatin1().data(), 8);
        model.addSection(&section);
    }
    
    QCOMPARE(model.getSections().size(), 3);
}

void PEDataModelTest::testImports()
{
    PEDataModel model;
    
    QStringList imports;
    imports << "kernel32.dll" << "user32.dll" << "ntdll.dll";
    
    model.setImports(imports);
    
    QCOMPARE(model.getImports().size(), 3);
    QVERIFY(model.getImports().contains("kernel32.dll"));
}

void PEDataModelTest::testExports()
{
    PEDataModel model;
    
    QStringList exports;
    exports << "ExportFunction1" << "ExportFunction2";
    
    model.setExports(exports);
    
    QCOMPARE(model.getExports().size(), 2);
    QVERIFY(model.getExports().contains("ExportFunction1"));
}

void PEDataModelTest::testClear()
{
    PEDataModel model;
    
    // Add some data
    model.setFilePath("test.exe");
    model.setFileSize(1024);
    IMAGE_DOS_HEADER dosHeader = createTestDOSHeader();
    model.setDOSHeader(&dosHeader);
    
    // Clear and verify
    model.clear();
    
    QVERIFY(model.getFilePath().isEmpty());
    QCOMPARE(model.getFileSize(), 0LL);
    QVERIFY(model.getDOSHeader() == nullptr);
}

void PEDataModelTest::testValidState()
{
    PEDataModel model;
    
    // Initially should be invalid
    QVERIFY(!model.isValid());
    
    // Set valid data
    model.setFilePath("test.exe");
    IMAGE_DOS_HEADER dosHeader = createTestDOSHeader();
    model.setDOSHeader(&dosHeader);
    model.setValid(true);
    
    QVERIFY(model.isValid());
}

// Helper functions

IMAGE_DOS_HEADER PEDataModelTest::createTestDOSHeader()
{
    IMAGE_DOS_HEADER header = {};
    header.e_magic = 0x5A4D; // "MZ"
    header.e_lfanew = sizeof(IMAGE_DOS_HEADER);
    return header;
}

IMAGE_FILE_HEADER PEDataModelTest::createTestFileHeader()
{
    IMAGE_FILE_HEADER header = {};
    header.Machine = 0x014C; // IMAGE_FILE_MACHINE_I386
    header.NumberOfSections = 3;
    header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    return header;
}

IMAGE_OPTIONAL_HEADER PEDataModelTest::createTestOptionalHeader()
{
    IMAGE_OPTIONAL_HEADER header = {};
    header.Magic = 0x10B; // PE32
    header.AddressOfEntryPoint = 0x1000;
    header.ImageBase = 0x400000;
    return header;
}

IMAGE_SECTION_HEADER PEDataModelTest::createTestSectionHeader()
{
    IMAGE_SECTION_HEADER header = {};
    strncpy_s(reinterpret_cast<char*>(header.Name), 8, ".text", 8);
    header.VirtualAddress = 0x1000;
    header.SizeOfRawData = 0x1000;
    header.PointerToRawData = 0x400;
    header.Characteristics = 0x60000020; // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    return header;
}

#include "pe_data_model_test.moc"

