#include "pe_analysis.h"
#include "pe_structures.h"

#include <QByteArray>
#include <QtTest>
#include <cstring>
#include <iostream>

bool runPeAnalysisSelfTests()
{
    bool ok = true;
    auto check = [&](bool condition, const char *message) {
        if (!condition) {
            std::cerr << "PEAnalysis self-test failed: " << message << '\n';
            ok = false;
        }
    };

    check(qAbs(PEAnalysis::shannonEntropy(QByteArray())) < 0.01, "empty entropy");
    const QByteArray zeros(256, '\x00');
    check(qAbs(PEAnalysis::shannonEntropy(zeros)) < 0.01, "zero entropy");
    QByteArray alternating;
    alternating.append('\x01');
    alternating.append('\x00');
    alternating.append('\x01');
    alternating.append('\x00');
    alternating.append('\x01');
    alternating.append('\x00');
    alternating.append('\x01');
    alternating.append('\x00');
    check(alternating.size() == 8, "alternating size");
    check(qAbs(PEAnalysis::shannonEntropy(alternating) - 1.0) < 0.01, "alternating entropy");

    QByteArray file(200, '\x00');
    IMAGE_SECTION_HEADER sec{};
    std::memcpy(sec.Name, ".text", 5);
    sec.PointerToRawData = 0x40;
    sec.SizeOfRawData = 0x20;
    QList<const IMAGE_SECTION_HEADER *> sections;
    sections.append(&sec);
    const PEOverlayInfo none = PEAnalysis::detectOverlay(file, sections, 0x60);
    check(!none.present, "no overlay");
    const PEOverlayInfo ov = PEAnalysis::detectOverlay(file, sections, static_cast<qint64>(file.size()));
    check(ov.present, "overlay present");
    check(ov.fileOffset == 0x60u, "overlay offset");
    check(ov.size == 0x68u, "overlay size");

    QByteArray rsds(32, '\0');
    rsds[0] = 'R';
    rsds[1] = 'S';
    rsds[2] = 'D';
    rsds[3] = 'S';
    rsds[20] = 42;
    const char path[] = "app.pdb";
    std::memcpy(rsds.data() + 24, path, sizeof(path));
    const PEPdbInfo rsdsInfo = PEAnalysis::parseCodeViewDebugData(rsds, 0, static_cast<quint32>(rsds.size()));
    check(rsdsInfo.present, "rsds present");
    check(rsdsInfo.path == QStringLiteral("app.pdb"), "rsds path");
    check(rsdsInfo.age == 42u, "rsds age");
    check(rsdsInfo.pathFileOffset == 24u, "rsds path offset");
    check(rsdsInfo.pathByteSize == 8u, "rsds path size");

    QByteArray nb10(24, '\0');
    nb10[0] = 'N';
    nb10[1] = 'B';
    nb10[2] = '1';
    nb10[3] = '0';
    nb10[8] = 7;
    const char nbPath[] = "legacy.pdb";
    std::memcpy(nb10.data() + 12, nbPath, sizeof(nbPath));
    const PEPdbInfo nbInfo = PEAnalysis::parseCodeViewDebugData(nb10, 0, static_cast<quint32>(nb10.size()));
    check(nbInfo.present, "nb10 present");
    check(nbInfo.path == QStringLiteral("legacy.pdb"), "nb10 path");
    check(nbInfo.pathFileOffset == 12u, "nb10 path offset");
    check(nbInfo.pathByteSize == 11u, "nb10 path size");

    const quint32 rsdsRecSize = PEAnalysis::codeViewRecordByteSize(rsds, 0, static_cast<quint32>(rsds.size()));
    check(rsdsRecSize == static_cast<quint32>(rsds.size()), "rsds record size");

    return ok;
}
