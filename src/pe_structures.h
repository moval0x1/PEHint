#ifndef PE_STRUCTURES_H
#define PE_STRUCTURES_H

#include <QtGlobal>

// PE file structures - Pure data structures only
#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
    quint16 e_magic;      // Magic number
    quint16 e_cblp;       // Bytes on last page of file
    quint16 e_cp;         // Pages in file
    quint16 e_crlc;       // Relocations
    quint16 e_cparhdr;    // Size of header in paragraphs
    quint16 e_minalloc;   // Minimum extra paragraphs needed
    quint16 e_maxalloc;   // Maximum extra paragraphs needed
    quint16 e_ss;         // Initial (relative) SS value
    quint16 e_sp;         // Initial SP value
    quint16 e_csum;       // Checksum
    quint16 e_ip;         // Initial IP value
    quint16 e_cs;         // Initial (relative) CS value
    quint16 e_lfarlc;     // File address of relocation table
    quint16 e_ovno;       // Overlay number
    quint16 e_res[4];     // Reserved words
    quint16 e_oemid;      // OEM identifier
    quint16 e_oeminfo;    // OEM information
    quint16 e_res2[10];   // Reserved words
    qint32  e_lfanew;     // File address of new exe header
};

struct IMAGE_FILE_HEADER {
    quint32 Signature;        // PE signature
    quint16 Machine;          // Machine type
    quint16 NumberOfSections; // Number of sections
    quint32 TimeDateStamp;    // Time/date stamp
    quint32 PointerToSymbolTable; // Pointer to symbol table
    quint32 NumberOfSymbols;  // Number of symbols
    quint16 SizeOfOptionalHeader; // Size of optional header
    quint16 Characteristics;  // File characteristics
};

struct IMAGE_OPTIONAL_HEADER {
    quint16 Magic;                    // Magic number
    quint8  MajorLinkerVersion;       // Major linker version
    quint8  MinorLinkerVersion;       // Minor linker version
    quint32 SizeOfCode;               // Size of code section
    quint32 SizeOfInitializedData;    // Size of initialized data
    quint32 SizeOfUninitializedData;  // Size of uninitialized data
    quint32 AddressOfEntryPoint;      // Address of entry point
    quint32 BaseOfCode;               // Base of code
    quint32 BaseOfData;               // Base of data
    quint32 ImageBase;                // Image base
    quint32 SectionAlignment;         // Section alignment
    quint32 FileAlignment;            // File alignment
    quint16 MajorOperatingSystemVersion; // Major OS version
    quint16 MinorOperatingSystemVersion; // Minor OS version
    quint16 MajorImageVersion;        // Major image version
    quint16 MinorImageVersion;        // Minor image version
    quint16 MajorSubsystemVersion;    // Major subsystem version
    quint16 MinorSubsystemVersion;    // Minor subsystem version
    quint32 Win32VersionValue;        // Win32 version value
    quint32 SizeOfImage;              // Size of image
    quint32 SizeOfHeaders;            // Size of headers
    quint32 CheckSum;                 // Checksum
    quint16 Subsystem;                // Subsystem
    quint16 DllCharacteristics;       // DLL characteristics
    quint32 SizeOfStackReserve;       // Size of stack reserve
    quint32 SizeOfStackCommit;        // Size of stack commit
    quint32 SizeOfHeapReserve;        // Size of heap reserve
    quint32 SizeOfHeapCommit;         // Size of heap commit
    quint32 LoaderFlags;              // Loader flags
    quint32 NumberOfRvaAndSizes;      // Number of RVA and sizes
};

// Data Directory structure
struct IMAGE_DATA_DIRECTORY {
    quint32 VirtualAddress;   // RVA of the data
    quint32 Size;             // Size of the data
};

// Import Directory structure
struct IMAGE_IMPORT_DESCRIPTOR {
    quint32 OriginalFirstThunk;   // RVA to original thunk table
    quint32 TimeDateStamp;        // Time/date stamp
    quint32 ForwarderChain;       // Forwarder chain index
    quint32 Name;                 // RVA to DLL name
    quint32 FirstThunk;           // RVA to import address table
};

// Export Directory structure
struct IMAGE_EXPORT_DIRECTORY {
    quint32 Characteristics;      // Export flags
    quint32 TimeDateStamp;        // Time/date stamp
    quint16 MajorVersion;         // Major version number
    quint16 MinorVersion;         // Minor version number
    quint32 Name;                 // RVA to module name
    quint32 OrdinalBase;          // Ordinal base
    quint32 NumberOfFunctions;    // Number of exported functions
    quint32 NumberOfNames;        // Number of exported names
    quint32 AddressOfFunctions;   // RVA to address table
    quint32 AddressOfNames;       // RVA to name pointer table
    quint32 AddressOfNameOrdinals; // RVA to ordinal table
};

struct IMAGE_SECTION_HEADER {
    char Name[8];           // Section name
    quint32 VirtualSize;    // Virtual size of section
    quint32 VirtualAddress; // Virtual address of section
    quint32 SizeOfRawData;  // Size of raw data
    quint32 PointerToRawData; // File pointer to raw data
    quint32 PointerToRelocations; // File pointer to relocations
    quint32 PointerToLinenumbers; // File pointer to line number
    quint16 NumberOfRelocations; // Number of relocations
    quint16 NumberOfLinenumbers; // Number of line numbers
    quint32 Characteristics; // Section characteristics
};

// Resource structures
struct IMAGE_RESOURCE_DIRECTORY {
    quint32 Characteristics;
    quint32 TimeDateStamp;
    quint16 MajorVersion;
    quint16 MinorVersion;
    quint16 NumberOfNamedEntries;
    quint16 NumberOfIdEntries;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    quint32 Name;
    quint32 OffsetToData;
};

struct IMAGE_RESOURCE_DATA_ENTRY {
    quint32 OffsetToData;
    quint32 Size;
    quint32 CodePage;
    quint32 Reserved;
};

// Debug Directory structures
struct IMAGE_DEBUG_DIRECTORY {
    quint32 Characteristics;
    quint32 TimeDateStamp;
    quint16 MajorVersion;
    quint16 MinorVersion;
    quint32 Type;
    quint32 SizeOfData;
    quint32 AddressOfRawData;
    quint32 PointerToRawData;
};

// TLS (Thread Local Storage) structure
struct IMAGE_TLS_DIRECTORY {
    quint32 StartAddressOfRawData;
    quint32 EndAddressOfRawData;
    quint32 AddressOfIndex;
    quint32 AddressOfCallBacks;
    quint32 SizeOfZeroFill;
    quint32 Characteristics;
};

// Load Configuration structure
struct IMAGE_LOAD_CONFIG_DIRECTORY {
    quint32 Size;
    quint32 TimeDateStamp;
    quint16 MajorVersion;
    quint16 MinorVersion;
    quint32 GlobalFlagsClear;
    quint32 GlobalFlagsSet;
    quint32 CriticalSectionDefaultTimeout;
    quint32 DeCommitFreeBlockThreshold;
    quint32 DeCommitTotalFreeThreshold;
    quint32 LockPrefixTable;
    quint32 MaximumAllocationSize;
    quint32 VirtualMemoryThreshold;
    quint32 ProcessAffinityMask;
    quint32 ProcessHeapFlags;
    quint16 CSDVersion;
    quint16 Reserved;
    quint32 EditList;
    quint32 SecurityCookie;
    quint32 SEHandlerTable;
    quint32 SEHandlerCount;
};

// Base Relocation structure
struct IMAGE_BASE_RELOCATION {
    quint32 VirtualAddress;
    quint32 SizeOfBlock;
};

// WIN_CERTIFICATE structure (Authenticode)
struct WIN_CERTIFICATE {
    quint32 dwLength;
    quint16 wRevision;
    quint16 wCertificateType;
    quint8  bCertificate[1]; // Variable length
};

#pragma pack(pop)

#endif // PE_STRUCTURES_H
