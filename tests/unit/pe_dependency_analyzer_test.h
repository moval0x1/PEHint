#ifndef PE_DEPENDENCY_ANALYZER_TEST_H
#define PE_DEPENDENCY_ANALYZER_TEST_H

#include <QtTest>
#include <QObject>

class PEDependencyAnalyzerTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testEmptyImports();
    void testResolveInPeDirectory();
    void testMissingModule();
    void testTransitiveEmpty();
    void testTransitiveMissingRoot();
    void testExtraPathsFromManifestWinSxS();
    void testExtraPathsFromManifestPrivatePath();
};

#endif
