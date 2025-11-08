#include <QtTest>
#include <QCoreApplication>
#include "pe_parser_test.h"
#include "pe_data_model_test.h"
#include "pe_security_analyzer_test.h"
#include "pe_utils_test.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    
    int result = 0;
    
    // Run all test suites
    result |= QTest::qExec(new PEParserTest, argc, argv);
    result |= QTest::qExec(new PEDataModelTest, argc, argv);
    result |= QTest::qExec(new PESecurityAnalyzerTest, argc, argv);
    result |= QTest::qExec(new PEUtilsTest, argc, argv);
    
    return result;
}

