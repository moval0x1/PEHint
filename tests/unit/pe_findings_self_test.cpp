#include "pe_findings.h"
#include "pe_structures.h"

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
    model.setOptionalHeader(&opt);

    IMAGE_SECTION_HEADER sec{};
    std::memcpy(sec.Name, ".text", 5);
    sec.VirtualAddress = 0x1000;
    sec.Misc.VirtualSize = 0x1000;
    sec.SizeOfRawData = 0x200;
    sec.PointerToRawData = 0x400;
    sec.Characteristics = 0x60000020u;
    model.addSection(&sec);

    const auto findings = PEFindingsEngine::evaluate(model, [](quint32) -> quint32 { return 0u; });

    bool hasAslr = false;
    bool hasZeroTs = false;
    for (const PEFindingInstance &f : findings) {
        if (f.ruleId == QStringLiteral("missing_aslr")) {
            hasAslr = true;
        }
        if (f.ruleId == QStringLiteral("zero_timestamp")) {
            hasZeroTs = true;
        }
    }
    check(hasAslr, "missing_aslr triggered");
    check(hasZeroTs, "zero_timestamp triggered");

    return ok;
}
