#include "minimal_pe_builder.h"

#include "pe_structures.h"

#include <cstring>

namespace {

template <typename T>
void appendStruct(QByteArray &out, const T &value)
{
    out.append(reinterpret_cast<const char *>(&value), static_cast<int>(sizeof(T)));
}

void appendPadding(QByteArray &out, int count, char fill = '\0')
{
    out.append(QByteArray(count, fill));
}

} // namespace

QByteArray buildMinimalPe64()
{
    QByteArray pe;
    pe.reserve(1024);

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_cblp = 0x90;
    dos.e_cp = 0x3;
    dos.e_lfarlc = 0x40;
    dos.e_lfanew = 0x80;
    appendStruct(pe, dos);
    appendPadding(pe, 0x80 - pe.size());

    const char peSig[] = "PE\0\0";
    pe.append(peSig, 4);

    IMAGE_FILE_HEADER file{};
    file.Machine = IMAGE_FILE_MACHINE_AMD64;
    file.NumberOfSections = 1;
    file.TimeDateStamp = 0;
    file.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    file.Characteristics = 0x0022; // executable
    appendStruct(pe, file);

    IMAGE_OPTIONAL_HEADER64 opt{};
    opt.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt.MajorLinkerVersion = 14;
    opt.MinorLinkerVersion = 0;
    opt.SizeOfCode = 0x200;
    opt.SizeOfInitializedData = 0;
    opt.AddressOfEntryPoint = 0x1000;
    opt.BaseOfCode = 0x1000;
    opt.ImageBase = 0x140000000ULL;
    opt.SectionAlignment = 0x1000;
    opt.FileAlignment = 0x200;
    opt.MajorOperatingSystemVersion = 6;
    opt.MinorOperatingSystemVersion = 0;
    opt.MajorSubsystemVersion = 6;
    opt.MinorSubsystemVersion = 0;
    opt.SizeOfImage = 0x2000;
    opt.SizeOfHeaders = 0x200;
    opt.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt.NumberOfRvaAndSizes = 16;
    appendStruct(pe, opt);

    IMAGE_SECTION_HEADER text{};
    std::memcpy(text.Name, ".text", 5);
    text.Misc.VirtualSize = 0x200;
    text.VirtualAddress = 0x1000;
    text.SizeOfRawData = 0x200;
    text.PointerToRawData = 0x200;
    text.Characteristics = 0x60000020; // code | execute | read
    appendStruct(pe, text);

    appendPadding(pe, 0x200 - pe.size());
    // Typical x64 prologue + call
    const unsigned char code[] = {0x48, 0x83, 0xEC, 0x28, 0xE8, 0x05, 0x00, 0x00, 0x00, 0x90};
    pe.append(reinterpret_cast<const char *>(code), static_cast<int>(sizeof(code)));
    appendPadding(pe, 0x400 - pe.size());

    return pe;
}
