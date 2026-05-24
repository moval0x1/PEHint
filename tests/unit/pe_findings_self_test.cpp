#include "pe_findings.h"
#include "pe_analysis.h"
#include "pe_structures.h"
#include "pe_utils.h"

#include <QCoreApplication>
#include <cstring>
#include <iostream>

bool runPeFindingsSelfTests()
{
    bool ok = true;
    auto check = [&](bool condition, const char *message) {
        if (!condition) {
            std::cerr << "PEFindings self-test failed: " << message << '\n';
            ok = false;
        }
    };

    PEFindingsEngine::loadRules();

    PEDataModel model;
    model.setValid(true);

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    model.setDOSHeader(&dos);

    IMAGE_FILE_HEADER fileHdr{};
    fileHdr.Machine = IMAGE_FILE_MACHINE_AMD64;
    fileHdr.NumberOfSections = 1;
    fileHdr.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    fileHdr.TimeDateStamp = 0;
    model.setFileHeader(&fileHdr);

    IMAGE_OPTIONAL_HEADER opt{};
    opt.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt.AddressOfEntryPoint = 0x1000;
    opt.DllCharacteristics = 0;
    opt.CheckSum = 0;
    opt.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    model.setOptionalHeader(&opt);

    IMAGE_SECTION_HEADER sec{};
    std::memcpy(sec.Name, ".text", 5);
    sec.VirtualAddress = 0x1000;
    sec.Misc.VirtualSize = 0x1000;
    sec.SizeOfRawData = 0x200;
    sec.PointerToRawData = 0x400;
    sec.Characteristics = 0x60000020u;
    model.addSection(&sec);

    PEAnalysisMetadata metadata;
    metadata.imageChecksumComputed = true;
    metadata.richHeaderPresent = false;
    model.setAnalysisMetadata(metadata);

    const auto findings = PEFindingsEngine::evaluate(model, [](quint32) -> quint32 { return 0u; });

    bool hasAslr = false;
    bool hasZeroTs = false;
    bool hasChecksumZero = false;
    bool hasNoRich = false;
    for (const PEFindingInstance &f : findings) {
        if (f.ruleId == QStringLiteral("missing_aslr")) {
            hasAslr = true;
        }
        if (f.ruleId == QStringLiteral("zero_timestamp")) {
            hasZeroTs = true;
        }
        if (f.ruleId == QStringLiteral("checksum_zero")) {
            hasChecksumZero = true;
        }
        if (f.ruleId == QStringLiteral("no_rich_header")) {
            hasNoRich = true;
        }
    }
    check(hasAslr, "missing_aslr triggered");
    check(hasZeroTs, "zero_timestamp triggered");
    check(hasChecksumZero, "checksum_zero triggered");
    check(hasNoRich, "no_rich_header triggered");

    IMAGE_SECTION_HEADER writableText{};
    std::memcpy(writableText.Name, ".text", 5);
    writableText.VirtualAddress = 0x2000;
    writableText.Misc.VirtualSize = 0x400;
    writableText.SizeOfRawData = 0x400;
    writableText.PointerToRawData = 0x800;
    writableText.Characteristics = 0xE0000020u | 0x08000000u;
    model.addSection(&writableText);

    const auto findings2 = PEFindingsEngine::evaluate(model, [](quint32) -> quint32 { return 0u; });
    bool hasWritableCode = false;
    for (const PEFindingInstance &f : findings2) {
        if (f.ruleId == QStringLiteral("writable_code_section")) {
            hasWritableCode = true;
            break;
        }
    }
    check(hasWritableCode, "writable_code_section triggered");

    const quint32 checksumOffset = PEUtils::optionalHeaderChecksumFileOffset(dos, fileHdr);
    check(checksumOffset > 0, "optionalHeaderChecksumFileOffset > 0");

    QMap<QString, QList<PEDataModel::ImportFunctionEntry>> imports;
    PEDataModel::ImportFunctionEntry imp;
    imp.name = QStringLiteral("VirtualAllocEx");
    imp.thunkOffset = 0x500;
    imports.insert(QStringLiteral("KERNEL32.dll"), {imp});
    model.setImportFunctions(imports);

    PEContentScan scan;
    scan.dosStubNonStandard = true;
    scan.dosStubMessage = QStringLiteral("Custom DOS stub text");
    scan.dosStubOffset = 0x40;
    scan.dosStubSize = 0x20;
    PEHardcodedMatch urlMatch;
    urlMatch.value = QStringLiteral("http://example.test/a");
    urlMatch.fileOffset = 0x450;
    urlMatch.length = 22;
    scan.urls.append(urlMatch);
    model.setContentScan(scan);

    QList<PEDataModel::ExportFunctionEntry> exports;
    PEDataModel::ExportFunctionEntry ex1;
    ex1.name = QStringLiteral("SameName");
    ex1.ordinal = 1;
    PEDataModel::ExportFunctionEntry ex2 = ex1;
    ex2.ordinal = 2;
    exports << ex1 << ex2;
    model.setExportFunctions(exports);

    const auto findings3 = PEFindingsEngine::evaluate(model, [](quint32) -> quint32 { return 0u; });
    bool hasFlaggedImport = false;
    bool hasDosStub = false;
    bool hasUrl = false;
    bool hasDupExport = false;
    for (const PEFindingInstance &f : findings3) {
        if (f.ruleId.startsWith(QStringLiteral("flagged_import:"))) {
            hasFlaggedImport = true;
        }
        if (f.ruleId == QStringLiteral("nonstandard_dos_stub")) {
            hasDosStub = true;
        }
        if (f.ruleId == QStringLiteral("hardcoded_url")) {
            hasUrl = true;
        }
        if (f.ruleId == QStringLiteral("duplicate_exports")) {
            hasDupExport = true;
        }
    }
    check(hasFlaggedImport, "flagged_import triggered");
    check(hasDosStub, "nonstandard_dos_stub triggered");
    check(hasUrl, "hardcoded_url triggered");
    check(hasDupExport, "duplicate_exports triggered");

    QByteArray fileData(0x600, '\0');
    fileData.insert(0x450, "http://test.local/x");
    const PEContentScan computed = PEAnalysis::computeContentScan(fileData, model);
    check(!computed.urls.isEmpty(), "computeContentScan finds URL in section");

    QByteArray manifestData(0x800, '\0');
    manifestData.insert(0x100, "version='6.0.0.0' processorArchitecture='amd64'");
    IMAGE_SECTION_HEADER rdata{};
    std::memcpy(rdata.Name, ".rdata", 6);
    rdata.PointerToRawData = 0x100;
    rdata.SizeOfRawData = 0x200;
    PEDataModel manifestModel;
    manifestModel.setValid(true);
    manifestModel.addSection(&rdata);
    const PEContentScan manifestScan = PEAnalysis::computeContentScan(manifestData, manifestModel);
    check(manifestScan.ips.isEmpty(), "6.0.0.0 in manifest is not flagged as IP");

    QByteArray dotnetMeta(0x400, '\0');
    dotnetMeta.insert(0x80, "4.2.8.5.NETFramework,Version=v4.8,FrameworkDisplayName.NET Framework 4.8");
    dotnetMeta.insert(0x140, "Target 17.7.0.0 runtime");
    IMAGE_SECTION_HEADER metaSec{};
    std::memcpy(metaSec.Name, ".rsrc", 5);
    metaSec.PointerToRawData = 0x80;
    metaSec.SizeOfRawData = 0x200;
    PEDataModel dotnetModel;
    dotnetModel.setValid(true);
    dotnetModel.addSection(&metaSec);
    const PEContentScan dotnetScan = PEAnalysis::computeContentScan(dotnetMeta, dotnetModel);
    check(dotnetScan.ips.isEmpty(), ".NET metadata version strings are not flagged as IP");

    QByteArray realIpData(0x200, '\0');
    realIpData.insert(0x20, "connect to 192.168.1.50 now");
    IMAGE_SECTION_HEADER dataSec{};
    std::memcpy(dataSec.Name, ".data", 5);
    dataSec.PointerToRawData = 0x20;
    dataSec.SizeOfRawData = 0x100;
    PEDataModel ipModel;
    ipModel.setValid(true);
    ipModel.addSection(&dataSec);
    const PEContentScan realIpScan = PEAnalysis::computeContentScan(realIpData, ipModel);
    check(!realIpScan.ips.isEmpty(), "192.168.1.50 is still detected as IP");

    QByteArray urlData(0x400, '\0');
    urlData.insert(0x50, "see http://llvm.org/); for info");
    IMAGE_SECTION_HEADER text{};
    std::memcpy(text.Name, ".text", 5);
    text.PointerToRawData = 0x50;
    text.SizeOfRawData = 0x100;
    PEDataModel urlModel;
    urlModel.setValid(true);
    urlModel.addSection(&text);
    const PEContentScan urlScan = PEAnalysis::computeContentScan(urlData, urlModel);
    check(!urlScan.urls.isEmpty() && urlScan.urls.first().value == QStringLiteral("http://llvm.org/"),
          "URL trailing ); is trimmed");

    return ok;
}
