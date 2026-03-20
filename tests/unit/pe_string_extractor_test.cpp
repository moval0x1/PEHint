#include "pe_string_extractor_test.h"
#include "pe_string_extractor.h"
#include <QFile>
#include <QTemporaryFile>

void PEStringExtractorTest::initTestCase() {}

void PEStringExtractorTest::cleanupTestCase() {}

void PEStringExtractorTest::testEmptyData()
{
    StringExtractionResult r = PEStringExtractor::extractFromData(QByteArray(), 4);
    QVERIFY(r.strings.isEmpty());
    r = PEStringExtractor::extractFromData(QByteArray("ab"), 4);
    QVERIFY(r.strings.isEmpty());
}

void PEStringExtractorTest::testAsciiMinLength()
{
    QByteArray d = "abcd"; // length 4
    StringExtractionResult r = PEStringExtractor::extractFromData(d, 4);
    QCOMPARE(r.strings.size(), 1);
    QVERIFY(!r.strings[0].isUnicode);
    QCOMPARE(r.strings[0].fileOffset, 0u);
    QCOMPARE(r.strings[0].value, QStringLiteral("abcd"));

    d = "abc"; // too short
    r = PEStringExtractor::extractFromData(d, 4);
    QVERIFY(r.strings.isEmpty());
}

void PEStringExtractorTest::testAsciiMultiple()
{
    QByteArray d = QByteArrayLiteral("skip");
    d.append(char(0));
    d.append(QByteArrayLiteral("hello"));
    d.append(char(0));
    d.append(QByteArrayLiteral("world!!!!"));
    StringExtractionResult r = PEStringExtractor::extractFromData(d, 5);
    bool foundHello = false, foundWorld = false;
    for (const ExtractedString &s : r.strings) {
        if (!s.isUnicode) {
            if (s.value == QStringLiteral("hello")) foundHello = true;
            if (s.value == QStringLiteral("world!!!!")) foundWorld = true;
        }
    }
    QVERIFY(foundHello);
    QVERIFY(foundWorld);
}

void PEStringExtractorTest::testUnicodeUtf16Le()
{
    // "test" in UTF-16LE: t\0 e\0 s\0 t\0
    QByteArray d;
    d.append(QByteArray::fromHex("7400650073007400"));
    StringExtractionResult r = PEStringExtractor::extractFromData(d, 4);
    QCOMPARE(r.strings.size(), 1);
    QVERIFY(r.strings[0].isUnicode);
    QCOMPARE(r.strings[0].value, QStringLiteral("test"));
    QCOMPARE(r.strings[0].fileOffset, 0u);
}

void PEStringExtractorTest::testExtractFromFile()
{
    QTemporaryFile f;
    f.setAutoRemove(false);
    QVERIFY(f.open());
    QByteArray payload = QByteArrayLiteral("ZZZZpadding");
    payload.append(char(0));
    payload.append(QByteArrayLiteral("abcdefgh"));
    f.write(payload);
    f.flush();
    const QString path = f.fileName();
    f.close();

    StringExtractionResult r = PEStringExtractor::extractFromFile(path, 8);
    QFile::remove(path);
    bool found = false;
    for (const ExtractedString &s : r.strings) {
        if (!s.isUnicode && s.value == QStringLiteral("abcdefgh"))
            found = true;
    }
    QVERIFY(found);
}

