#ifndef PE_DATA_MODEL_TEST_H
#define PE_DATA_MODEL_TEST_H

#include <QtTest>
#include "pe_data_model.h"

class PEDataModelTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    
    // File information tests
    void testFilePath();
    void testFileSize();
    
    // Header data tests
    void testDOSHeader();
    void testFileHeader();
    void testOptionalHeader();
    
    // Section tests
    void testAddSection();
    void testGetSections();
    
    // Import/Export tests
    void testImports();
    void testExports();
    
    // Data model state tests
    void testClear();
    void testValidState();

private:
    IMAGE_DOS_HEADER createTestDOSHeader();
    IMAGE_FILE_HEADER createTestFileHeader();
    IMAGE_OPTIONAL_HEADER createTestOptionalHeader();
    IMAGE_SECTION_HEADER createTestSectionHeader();
};

#endif // PE_DATA_MODEL_TEST_H

