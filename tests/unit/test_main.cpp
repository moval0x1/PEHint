#include <QtTest>
#include <QCoreApplication>
#include <iostream>
#include "pe_parser_test.h"
#include "pe_data_model_test.h"
#include "pe_utils_test.h"
#include "pe_dependency_analyzer_test.h"
#include "pe_string_extractor_test.h"

bool runPeAnalysisSelfTests();
bool runPeFindingsSelfTests();

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    int failures = 0;
    auto runSuite = [&failures, argc, argv](const char *name, QObject *suite) {
        const int f = QTest::qExec(suite, argc, argv);
        delete suite;
        if (f != 0) {
            std::cerr << "Test suite " << name << " reported " << f << " failed function(s)\n";
        }
        failures += f;
    };
    runSuite("PEParserTest", new PEParserTest);
    runSuite("PEDataModelTest", new PEDataModelTest);
    runSuite("PEUtilsTest", new PEUtilsTest);
    runSuite("PEDependencyAnalyzerTest", new PEDependencyAnalyzerTest);
    runSuite("PEStringExtractorTest", new PEStringExtractorTest);

    if (!runPeAnalysisSelfTests()) {
        std::cerr << "PE analysis self-tests failed\n";
        ++failures;
    }

    if (!runPeFindingsSelfTests()) {
        std::cerr << "PE findings self-tests failed\n";
        ++failures;
    }

    return failures > 0 ? 1 : 0;
}
