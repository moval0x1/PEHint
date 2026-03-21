#include "pe_dependency_analyzer_test.h"
#include "pe_dependency_analyzer.h"
#include <QDir>
#include <QFile>
#include <QTemporaryDir>

void PEDependencyAnalyzerTest::initTestCase() {}

void PEDependencyAnalyzerTest::cleanupTestCase() {}

void PEDependencyAnalyzerTest::testEmptyImports()
{
    DependencyAnalysisResult r = PEDependencyAnalyzer::analyze(QStringList(), QString());
    QVERIFY(r.dependencies.isEmpty());
}

void PEDependencyAnalyzerTest::testResolveInPeDirectory()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString modName = QStringLiteral("PEHintTestMod.dll");
    const QString modPath = QDir(dir.path()).absoluteFilePath(modName);
    QFile f(modPath);
    QVERIFY(f.open(QIODevice::WriteOnly));
    f.write("x");
    f.close();

    const QString fakePe = QDir(dir.path()).absoluteFilePath(QStringLiteral("app.exe"));
    QFile pe(fakePe);
    QVERIFY(pe.open(QIODevice::WriteOnly));
    pe.close();

    DependencyAnalysisResult r = PEDependencyAnalyzer::analyze(QStringList{modName}, fakePe);
    QCOMPARE(r.dependencies.size(), 1);
    QCOMPARE(r.dependencies[0].moduleName, modName);
    QVERIFY(r.dependencies[0].foundOnSystem);
    QCOMPARE(r.dependencies[0].resolvedPath, modPath);
}

void PEDependencyAnalyzerTest::testMissingModule()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString fakePe = QDir(dir.path()).absoluteFilePath(QStringLiteral("lonely.exe"));
    QFile pe(fakePe);
    QVERIFY(pe.open(QIODevice::WriteOnly));
    pe.close();

    DependencyAnalysisResult r =
        PEDependencyAnalyzer::analyze(QStringList{QStringLiteral("Nonexistent999.dll")}, fakePe);
    QCOMPARE(r.dependencies.size(), 1);
    QVERIFY(!r.dependencies[0].foundOnSystem);
    QVERIFY(r.dependencies[0].resolvedPath.isEmpty());
}

void PEDependencyAnalyzerTest::testTransitiveEmpty()
{
    DependencyAnalysisResult r = PEDependencyAnalyzer::analyzeTransitive(QStringList(), QString(), 2);
    QVERIFY(r.dependencies.isEmpty());
    QVERIFY(r.dependencyTree.isEmpty());
}

void PEDependencyAnalyzerTest::testTransitiveMissingRoot()
{
    DependencyAnalysisResult r = PEDependencyAnalyzer::analyzeTransitive(
        QStringList{QStringLiteral("DefinitelyMissing_Dep_Test_001.dll")}, QString(), 2);
    QCOMPARE(r.dependencies.size(), 1);
    QCOMPARE(r.dependencyTree.size(), 1);
    QCOMPARE(r.dependencyTree[0].moduleName, QStringLiteral("DefinitelyMissing_Dep_Test_001.dll"));
    QVERIFY(!r.dependencyTree[0].foundOnSystem);
    QVERIFY(r.dependencyTree[0].children.isEmpty());
}

void PEDependencyAnalyzerTest::testExtraPathsFromManifestWinSxS()
{
#ifdef Q_OS_WIN
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString fakeWin = QDir(dir.path()).absoluteFilePath(QStringLiteral("Windows"));
    const QString sxDir = QDir(fakeWin).absoluteFilePath(
        QStringLiteral("WinSxS/amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.21022.8_none_deadbeef"));
    QVERIFY(QDir().mkpath(sxDir));

    const QString xml = QStringLiteral(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
        "  <dependency>\n"
        "    <dependentAssembly>\n"
        "      <assemblyIdentity name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" "
        "publicKeyToken=\"1fc8b3b9a1e18e3b\" processorArchitecture=\"amd64\" type=\"win32\"/>\n"
        "    </dependentAssembly>\n"
        "  </dependency>\n"
        "</assembly>\n");

    const QStringList paths =
        PEDependencyAnalyzer::extraSearchPathsFromManifestXml(xml, dir.path(), fakeWin);
    QVERIFY(!paths.isEmpty());
    QVERIFY(paths.contains(QDir(sxDir).absolutePath()));
#else
    QSKIP("WinSxS path matching is implemented on Windows only.");
#endif
}

void PEDependencyAnalyzerTest::testExtraPathsFromManifestPrivatePath()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    QVERIFY(QDir().mkpath(QDir(dir.path()).absoluteFilePath(QStringLiteral("subdir"))));

    const QString xml = QStringLiteral(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n"
        "  <probing privatePath=\"subdir\"/>\n"
        "</assembly>\n");

    const QStringList paths =
        PEDependencyAnalyzer::extraSearchPathsFromManifestXml(xml, dir.path(), QStringLiteral("C:\\Windows"));
    QCOMPARE(paths.size(), 1);
    QCOMPARE(paths.at(0), QDir(dir.path()).absoluteFilePath(QStringLiteral("subdir")));
}

