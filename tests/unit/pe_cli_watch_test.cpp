#include "helpers/minimal_pe_builder.h"
#include "pe_cli_scan.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTemporaryFile>

#include <iostream>
#include <vector>

namespace {

int runScanArgs(const QStringList &args)
{
    QByteArray arg0 = QByteArrayLiteral("PEHintTests");
    QByteArray arg1 = QByteArrayLiteral("--scan");
    std::vector<QByteArray> storage;
    storage.push_back(arg0);
    storage.push_back(arg1);
    for (const QString &a : args) {
        storage.push_back(a.toLocal8Bit());
    }
    std::vector<char *> argv;
    argv.reserve(storage.size());
    for (auto &b : storage) {
        argv.push_back(b.data());
    }
    return runPeCliScan(static_cast<int>(argv.size()), argv.data());
}

} // namespace

bool runPeCliWatchTests()
{
    bool ok = true;
    auto check = [&](bool condition, const char *message) {
        if (!condition) {
            std::cerr << "PE CLI watch test failed: " << message << '\n';
            ok = false;
        }
    };

    // --watch with a non-existent path returns exit 1 (error before event loop)
    {
        const int code = runScanArgs(
            {QStringLiteral("--watch"), QStringLiteral("/nonexistent/path/xyz_pehint_test")});
        check(code == 1, "--watch nonexistent dir -> exit 1");
    }

    // --watch with a file path (not a directory) returns exit 1
    {
        QTemporaryFile f;
        f.setAutoRemove(true);
        if (f.open()) {
            f.write(buildMinimalPe64());
            f.close();
            const QString filePath = f.fileName();
            // Rename so it has a .exe extension (isSupportedPeFilePath needs it)
            const QString exePath = filePath + QStringLiteral(".exe");
            QFile::rename(filePath, exePath);
            const int code = runScanArgs(
                {QStringLiteral("--watch"), exePath});
            check(code == 1, "--watch <file-not-dir> -> exit 1");
            QFile::remove(exePath);
        }
    }

    // --watch with empty string value (treated as no watch path) — falls back to error
    // about missing files (exit 1 because no files to scan)
    {
        const int code = runScanArgs({QStringLiteral("--watch"), QStringLiteral("")});
        // An empty watch path is treated as absent; no files → error
        check(code == 1, "--watch with empty value -> exit 1");
    }

    // NOTE: Testing the active --watch event loop is intentionally omitted.
    // --watch calls QCoreApplication::exec() which blocks indefinitely.
    // The polling/detection logic is exercised indirectly through --dir tests,
    // since both use listSupportedFilesInDirectory() and mtime detection.

    return ok;
}
