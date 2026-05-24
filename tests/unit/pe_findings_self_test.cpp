#include "pe_findings.h"
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

    return ok;
}
