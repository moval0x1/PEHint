#include "minimal_pe_builder.h"
#include "pe_cli_scan.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <iostream>
#include <vector>

bool runPeCliScanSelfTests()
{
    QTemporaryDir tempDir;
    if (!tempDir.isValid()) {
        std::cerr << "PE CLI self-test failed: temporary directory creation\n";
        return false;
    }

    const QString pePath = QDir(tempDir.path()).absoluteFilePath(QStringLiteral("minimal.exe"));
    QFile file(pePath);
    if (!file.open(QIODevice::WriteOnly)) {
        std::cerr << "PE CLI self-test failed: write minimal file\n";
        return false;
    }
    file.write(buildMinimalPe64());
    file.close();

    QByteArray arg0 = QByteArrayLiteral("PEHintTests");
    QByteArray arg1 = QByteArrayLiteral("--scan");
    QByteArray arg2 = pePath.toLocal8Bit();
    std::vector<char *> argv = {arg0.data(), arg1.data(), arg2.data()};
    const int exitCode = runPeCliScan(static_cast<int>(argv.size()), argv.data());
    if (exitCode != 0 && exitCode != 2) {
        std::cerr << "PE CLI self-test failed: unexpected exit code " << exitCode << '\n';
        return false;
    }
    return true;
}
