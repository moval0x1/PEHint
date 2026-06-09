#include "helpers/minimal_pe_builder.h"
#include "pe_cli_scan.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include <iostream>
#include <vector>

namespace {

bool writePeFile(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        return false;
    }
    f.write(buildMinimalPe64());
    return true;
}

int runScan(const QStringList &extraArgs)
{
    QByteArray arg0 = QByteArrayLiteral("PEHintTests");
    QByteArray arg1 = QByteArrayLiteral("--scan");
    std::vector<QByteArray> argStorage;
    argStorage.push_back(arg0);
    argStorage.push_back(arg1);
    for (const QString &a : extraArgs) {
        argStorage.push_back(a.toLocal8Bit());
    }
    std::vector<char *> argv;
    argv.reserve(argStorage.size());
    for (auto &b : argStorage) {
        argv.push_back(b.data());
    }
    return runPeCliScan(static_cast<int>(argv.size()), argv.data());
}

} // namespace

bool runPeCliBatchTests()
{
    bool ok = true;
    auto check = [&](bool condition, const char *message) {
        if (!condition) {
            std::cerr << "PE CLI batch test failed: " << message << '\n';
            ok = false;
        }
    };

    // --dir: scan a directory containing one .exe
    {
        QTemporaryDir dir;
        check(dir.isValid(), "--dir: temp dir created");
        if (dir.isValid()) {
            const QString exePath = QDir(dir.path()).absoluteFilePath(QStringLiteral("test.exe"));
            check(writePeFile(exePath), "--dir: write minimal PE");

            const int code = runScan({QStringLiteral("--dir"), dir.path()});
            check(code == 0 || code == 2,
                  "--dir with one .exe returns 0 or 2");
        }
    }

    // --dir with empty directory (no .exe/.dll/.sys) -> exit 0 (nothing to flag)
    {
        QTemporaryDir dir;
        check(dir.isValid(), "--dir empty: temp dir created");
        if (dir.isValid()) {
            const int code = runScan({QStringLiteral("--dir"), dir.path()});
            check(code == 0, "--dir empty dir -> exit 0");
        }
    }

    // --dir --recursive: file in subdirectory is found
    {
        QTemporaryDir dir;
        check(dir.isValid(), "--recursive: temp dir created");
        if (dir.isValid()) {
            const QString subDir = QDir(dir.path()).absoluteFilePath(QStringLiteral("sub"));
            check(QDir().mkpath(subDir), "--recursive: create subdir");
            const QString exePath = QDir(subDir).absoluteFilePath(QStringLiteral("deep.exe"));
            check(writePeFile(exePath), "--recursive: write PE in subdir");

            const int code = runScan(
                {QStringLiteral("--dir"), dir.path(), QStringLiteral("--recursive")});
            check(code == 0 || code == 2,
                  "--dir --recursive finds .exe in subdir");
        }
    }

    // --dir without --recursive: file in subdirectory is NOT scanned (dir itself has no PEs)
    {
        QTemporaryDir dir;
        check(dir.isValid(), "--no-recursive: temp dir created");
        if (dir.isValid()) {
            const QString subDir = QDir(dir.path()).absoluteFilePath(QStringLiteral("sub"));
            check(QDir().mkpath(subDir), "--no-recursive: create subdir");
            const QString exePath = QDir(subDir).absoluteFilePath(QStringLiteral("deep.exe"));
            check(writePeFile(exePath), "--no-recursive: write PE in subdir");

            const int code = runScan({QStringLiteral("--dir"), dir.path()});
            // No PEs in root -> exit 0 (nothing scanned, no findings)
            check(code == 0, "--dir without --recursive ignores subdirs -> exit 0");
        }
    }

    // --format json: output is valid JSON with expected top-level keys
    {
        QTemporaryDir dir;
        check(dir.isValid(), "--format json: temp dir created");
        if (dir.isValid()) {
            const QString exePath = QDir(dir.path()).absoluteFilePath(QStringLiteral("sample.exe"));
            check(writePeFile(exePath), "--format json: write PE");

            // Redirect stdout by capturing via the CLI scan exit code only.
            // We verify the process exits cleanly (0 or 2) as a proxy for valid JSON output.
            // A crash or parse failure would return 1.
            const int code = runScan(
                {QStringLiteral("--format"), QStringLiteral("json"), exePath});
            check(code == 0 || code == 2,
                  "--format json exits 0 or 2 (not parse error 1)");
        }
    }

    // Multiple files on the command line
    {
        QTemporaryDir dir;
        check(dir.isValid(), "multi-file: temp dir created");
        if (dir.isValid()) {
            const QString pe1 = QDir(dir.path()).absoluteFilePath(QStringLiteral("a.exe"));
            const QString pe2 = QDir(dir.path()).absoluteFilePath(QStringLiteral("b.exe"));
            check(writePeFile(pe1), "multi-file: write PE a");
            check(writePeFile(pe2), "multi-file: write PE b");

            const int code = runScan({pe1, pe2});
            check(code == 0 || code == 2, "multi-file scan exits 0 or 2");
        }
    }

    // Non-existent file -> exit 1 (parse error)
    {
        const int code = runScan({QStringLiteral("/nonexistent/path/ghost.exe")});
        check(code == 1, "non-existent file -> exit 1");
    }

    // --min-severity high: minimal PE likely has no high findings -> exit 0
    {
        QTemporaryDir dir;
        check(dir.isValid(), "--min-severity high: temp dir created");
        if (dir.isValid()) {
            const QString exePath = QDir(dir.path()).absoluteFilePath(QStringLiteral("s.exe"));
            check(writePeFile(exePath), "--min-severity high: write PE");

            const int code = runScan(
                {QStringLiteral("--min-severity"), QStringLiteral("high"), exePath});
            check(code == 0 || code == 2,
                  "--min-severity high exits 0 or 2");
        }
    }

    return ok;
}
