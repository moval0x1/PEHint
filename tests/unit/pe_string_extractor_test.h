#ifndef PE_STRING_EXTRACTOR_TEST_H
#define PE_STRING_EXTRACTOR_TEST_H

#include <QtTest>
#include <QObject>

class PEStringExtractorTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testAsciiMinLength();
    void testAsciiMultiple();
    void testUnicodeUtf16Le();
    void testExtractFromFile();
    void testEmptyData();
    void testContentFilters();
};

#endif
