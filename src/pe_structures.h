#ifndef PE_STRUCTURES_H
#define PE_STRUCTURES_H

#include <QtGlobal>

// PE file structures - Pure data structures only
#pragma pack(push, 1)

// ============================================================================
// CONSTANTS AND MAGIC NUMBERS
// ============================================================================

// PE Magic Numbers
#define IMAGE_DOS_SIGNATURE    0x5A4D       // MZ
#define IMAGE_NT_SIGNATURE     0x00004550   // PE00
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b  // PE32
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b  // PE32+

// Machine Types
#define IMAGE_FILE_MACHINE_UNKNOWN     0x0000
#define IMAGE_FILE_MACHINE_AM33        0x01d3
#define IMAGE_FILE_MACHINE_AMD64       0x8664
#define IMAGE_FILE_MACHINE_ARM         0x01c0
#define IMAGE_FILE_MACHINE_ARM64       0xaa64
#define IMAGE_FILE_MACHINE_ARMNT       0x01c4
#define IMAGE_FILE_MACHINE_EBC         0x0ebc
#define IMAGE_FILE_MACHINE_I386        0x014c
#define IMAGE_FILE_MACHINE_IA64        0x0200
#define IMAGE_FILE_MACHINE_M32R        0x9041
#define IMAGE_FILE_MACHINE_MIPS16      0x0266
#define IMAGE_FILE_MACHINE_MIPSFPU     0x0366
#define IMAGE_FILE_MACHINE_MIPSFPU16   0x0466
#define IMAGE_FILE_MACHINE_POWERPC     0x01f0
#define IMAGE_FILE_MACHINE_POWERPCFPU  0x01f1
#define IMAGE_FILE_MACHINE_R4000       0x0166
#define IMAGE_FILE_MACHINE_SH3         0x01a2
#define IMAGE_FILE_MACHINE_SH3DSP      0x01a3
#define IMAGE_FILE_MACHINE_SH4         0x01a6
#define IMAGE_FILE_MACHINE_SH5         0x01a8
#define IMAGE_FILE_MACHINE_THUMB       0x01c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2   0x0169

// Subsystem Types
#define IMAGE_SUBSYSTEM_UNKNOWN                0
#define IMAGE_SUBSYSTEM_NATIVE                 1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI            2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI            3
#define IMAGE_SUBSYSTEM_OS2_CUI                5
#define IMAGE_SUBSYSTEM_POSIX_CUI              7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS         8
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI         9
#define IMAGE_SUBSYSTEM_EFI_APPLICATION        10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER     12
#define IMAGE_SUBSYSTEM_EFI_ROM                13
#define IMAGE_SUBSYSTEM_XBOX                   14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

// DLL Characteristics
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       0x0020
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT             0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND               0x0800
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER          0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            0x2000
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF              0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

// ============================================================================
// BASIC PE STRUCTURES
// ============================================================================

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

// ============================================================================
// DATA DIRECTORY STRUCTURES
// ============================================================================

struct IMAGE_DATA_DIRECTORY {
    quint32 VirtualAddress;   // RVA of the data
    quint32 Size;             // Size of the data
};

// ============================================================================
// OPTIONAL HEADERS (32-bit and 64-bit)
// ============================================================================

// 32-bit Optional Header (PE32)
struct IMAGE_OPTIONAL_HEADER32 {
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
    
    // Data Directory array (16 entries)
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

// 64-bit Optional Header (PE32+)
struct IMAGE_OPTIONAL_HEADER64 {
    quint16 Magic;                    // Magic number
    quint8  MajorLinkerVersion;       // Major linker version
    quint8  MinorLinkerVersion;       // Minor linker version
    quint32 SizeOfCode;               // Size of code section
    quint32 SizeOfInitializedData;    // Size of initialized data
    quint32 SizeOfUninitializedData;  // Size of uninitialized data
    quint32 AddressOfEntryPoint;      // Address of entry point
    quint32 BaseOfCode;               // Base of code
    quint64 ImageBase;                // Image base (64-bit)
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
    quint64 SizeOfStackReserve;       // Size of stack reserve (64-bit)
    quint64 SizeOfStackCommit;        // Size of stack commit (64-bit)
    quint64 SizeOfHeapReserve;        // Size of heap reserve (64-bit)
    quint64 SizeOfHeapCommit;         // Size of heap commit (64-bit)
    quint32 LoaderFlags;              // Loader flags
    quint32 NumberOfRvaAndSizes;      // Number of RVA and sizes
    
    // Data Directory array (16 entries)
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

// Legacy compatibility - keep the old name for existing code
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;

// ============================================================================
// RICH HEADER STRUCTURES (Compiler Identification)
// ============================================================================

struct IMAGE_RICH_HEADER {
    quint32 XorKey;           // XOR key for decryption
    quint32 RichSignature;     // Rich signature
    quint32 RichVersion;       // Rich version
    quint32 RichCount;         // Number of rich entries
};

struct IMAGE_RICH_ENTRY {
    quint16 ProductId;         // Product ID
    quint16 ProductVersion;    // Product version
    quint32 ProductCount;      // Product count
    quint32 ProductTimestamp;  // Product timestamp
};

// ============================================================================
// IMPORT/EXPORT STRUCTURES
// ============================================================================

struct IMAGE_IMPORT_DESCRIPTOR {
    quint32 OriginalFirstThunk;   // RVA to original thunk table
    quint32 TimeDateStamp;        // Time/date stamp
    quint32 ForwarderChain;       // Forwarder chain index
    quint32 Name;                 // RVA to DLL name
    quint32 FirstThunk;           // RVA to import address table
};

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

// Thunk data structures (32-bit and 64-bit)
struct IMAGE_THUNK_DATA32 {
    union {
        quint32 ForwarderString;      // RVA to forwarder string
        quint32 Function;             // RVA to function
        quint32 Ordinal;              // Ordinal
        quint32 AddressOfData;        // RVA to import name table
    } u1;
};

struct IMAGE_THUNK_DATA64 {
    union {
        quint64 ForwarderString;      // RVA to forwarder string
        quint64 Function;             // RVA to function
        quint64 Ordinal;              // Ordinal
        quint64 AddressOfData;        // RVA to import name table
    } u1;
};

// Import name table entry
struct IMAGE_IMPORT_BY_NAME {
    quint16 Hint;                     // Ordinal hint
    char Name[1];                     // Function name (variable length)
};

// ============================================================================
// SECTION STRUCTURES
// ============================================================================

struct IMAGE_SECTION_HEADER {
    char Name[8];           // Section name
    union {
        quint32 PhysicalAddress;      // Physical address
        quint32 VirtualSize;          // Virtual size of section
    } Misc;
    quint32 VirtualAddress; // Virtual address of section
    quint32 SizeOfRawData;  // Size of raw data
    quint32 PointerToRawData; // File pointer to raw data
    quint32 PointerToRelocations; // File pointer to relocations
    quint32 PointerToLinenumbers; // File pointer to line number
    quint16 NumberOfRelocations; // Number of relocations
    quint16 NumberOfLinenumbers; // Number of line numbers
    quint32 Characteristics; // Section characteristics
    
    // Backward compatibility accessors
    quint32 getVirtualSize() const { return Misc.VirtualSize; }
    quint32 getPhysicalAddress() const { return Misc.PhysicalAddress; }
};

// ============================================================================
// RESOURCE STRUCTURES
// ============================================================================

struct IMAGE_RESOURCE_DIRECTORY {
    quint32 Characteristics;
    quint32 TimeDateStamp;
    quint16 MajorVersion;
    quint16 MinorVersion;
    quint16 NumberOfNamedEntries;
    quint16 NumberOfIdEntries;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            quint32 NameOffset : 31;
            quint32 NameIsString : 1;
        } Name;
        quint32 NameOrId;
    } u1;
    union {
        quint32 OffsetToData;
        struct {
            quint32 DataOffset : 31;
            quint32 DataIsDirectory : 1;
        } Offset;
    } u2;
    
    // Backward compatibility accessors
    quint32 getName() const { return u1.NameOrId; }
    quint32 getOffsetToData() const { return u2.OffsetToData; }
    bool isNameString() const { return u1.Name.NameIsString != 0; }
    bool isDataDirectory() const { return u2.Offset.DataIsDirectory != 0; }
};

struct IMAGE_RESOURCE_DATA_ENTRY {
    quint32 OffsetToData;
    quint32 Size;
    quint32 CodePage;
    quint32 Reserved;
};

// ============================================================================
// DEBUG STRUCTURES
// ============================================================================

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

// Debug types
#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2
#define IMAGE_DEBUG_TYPE_FPO              3
#define IMAGE_DEBUG_TYPE_MISC             4
#define IMAGE_DEBUG_TYPE_EXCEPTION        5
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
#define IMAGE_DEBUG_TYPE_BORLAND          9
#define IMAGE_DEBUG_TYPE_RESERVED10       10
#define IMAGE_DEBUG_TYPE_CLSID            11
#define IMAGE_DEBUG_TYPE_MPX              12
#define IMAGE_DEBUG_TYPE_REPRO            13
#define IMAGE_DEBUG_TYPE_EMBEDDED_SOURCE  14
#define IMAGE_DEBUG_TYPE_RESERVED15       15
#define IMAGE_DEBUG_TYPE_POGO             16
#define IMAGE_DEBUG_TYPE_ILTCG            17
#define IMAGE_DEBUG_TYPE_MPX2             18
#define IMAGE_DEBUG_TYPE_HOTPATCH         19
#define IMAGE_DEBUG_TYPE_MPX3             20
#define IMAGE_DEBUG_TYPE_PDB_CHECKSUM     21

// CodeView debug information
struct CV_INFO_PDB70 {
    quint32 CvSignature;           // CodeView signature
    quint8  Signature[16];         // PDB signature
    quint32 Age;                   // PDB age
    char PdbFileName[1];           // PDB file name (variable length)
};

// ============================================================================
// TLS (Thread Local Storage) STRUCTURES
// ============================================================================

struct IMAGE_TLS_DIRECTORY32 {
    quint32 StartAddressOfRawData;
    quint32 EndAddressOfRawData;
    quint32 AddressOfIndex;
    quint32 AddressOfCallBacks;
    quint32 SizeOfZeroFill;
    quint32 Characteristics;
};

struct IMAGE_TLS_DIRECTORY64 {
    quint64 StartAddressOfRawData;
    quint64 EndAddressOfRawData;
    quint64 AddressOfIndex;
    quint64 AddressOfCallBacks;
    quint32 SizeOfZeroFill;
    quint32 Characteristics;
};

// Legacy compatibility
typedef IMAGE_TLS_DIRECTORY32 IMAGE_TLS_DIRECTORY;

// ============================================================================
// LOAD CONFIGURATION STRUCTURES
// ============================================================================

// 32-bit Load Configuration Directory
struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
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

// 64-bit Load Configuration Directory
struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    quint32 Size;
    quint32 TimeDateStamp;
    quint16 MajorVersion;
    quint16 MinorVersion;
    quint32 GlobalFlagsClear;
    quint32 GlobalFlagsSet;
    quint32 CriticalSectionDefaultTimeout;
    quint64 DeCommitFreeBlockThreshold;
    quint64 DeCommitTotalFreeThreshold;
    quint64 LockPrefixTable;
    quint64 MaximumAllocationSize;
    quint64 VirtualMemoryThreshold;
    quint64 ProcessAffinityMask;
    quint32 ProcessHeapFlags;
    quint16 CSDVersion;
    quint16 Reserved;
    quint64 EditList;
    quint64 SecurityCookie;
    quint64 SEHandlerTable;
    quint32 SEHandlerCount;
};

// Legacy compatibility
typedef IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY;

// ============================================================================
// EXCEPTION HANDLING STRUCTURES
// ============================================================================

struct IMAGE_RUNTIME_FUNCTION_ENTRY {
    quint32 BeginAddress;
    quint32 EndAddress;
    quint32 UnwindInfoAddress;
};

struct IMAGE_RUNTIME_FUNCTION_ENTRY64 {
    quint32 BeginAddress;
    quint32 EndAddress;
    quint32 UnwindInfoAddress;
};

// ============================================================================
// BASE RELOCATION STRUCTURES
// ============================================================================

struct IMAGE_BASE_RELOCATION {
    quint32 VirtualAddress;
    quint32 SizeOfBlock;
};

struct IMAGE_RELOCATION {
    quint16 Offset : 12;
    quint16 Type : 4;
};

// Relocation types
#define IMAGE_REL_BASED_ABSOLUTE        0
#define IMAGE_REL_BASED_HIGH            1
#define IMAGE_REL_BASED_LOW             2
#define IMAGE_REL_BASED_HIGHLOW         3
#define IMAGE_REL_BASED_HIGHADJ         4
#define IMAGE_REL_BASED_MIPS_JMPADDR    5
#define IMAGE_REL_BASED_SECTION         6
#define IMAGE_REL_BASED_REL32           7
#define IMAGE_REL_BASED_MIPS_JMPADDR16  9
#define IMAGE_REL_BASED_IA64_IMM64      9
#define IMAGE_REL_BASED_DIR64           10
#define IMAGE_REL_BASED_HIGH3ADJ        11

// ============================================================================
// CERTIFICATE STRUCTURES (Authenticode)
// ============================================================================

struct WIN_CERTIFICATE {
    quint32 dwLength;
    quint16 wRevision;
    quint16 wCertificateType;
    quint8  bCertificate[1]; // Variable length
};

// Certificate types
#define WIN_CERT_TYPE_X509               0x0001
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA   0x0002
#define WIN_CERT_TYPE_RESERVED_1         0x0003
#define WIN_CERT_TYPE_TS_STACK_SIGNED    0x0004

// ============================================================================
// BOUND IMPORT STRUCTURES
// ============================================================================

struct IMAGE_BOUND_IMPORT_DESCRIPTOR {
    quint32 TimeDateStamp;
    quint16 OffsetModuleName;
    quint16 NumberOfModuleForwarderRefs;
};

struct IMAGE_BOUND_FORWARDER_REF {
    quint32 TimeDateStamp;
    quint16 OffsetModuleName;
    quint16 Reserved;
};

// ============================================================================
// DELAY IMPORT STRUCTURES
// ============================================================================

struct IMAGE_DELAYLOAD_DESCRIPTOR {
    union {
        quint32 AllAttributes;
        struct {
            quint32 RvaBased : 1;
            quint32 ReservedAttributes : 31;
        } Attributes;
    } Attributes;
    quint32 DllNameRVA;
    quint32 ModuleHandleRVA;
    quint32 ImportAddressTableRVA;
    quint32 ImportNameTableRVA;
    quint32 BoundImportAddressTableRVA;
    quint32 UnloadInformationTableRVA;
    quint32 TimeDateStamp;
};

// ============================================================================
// ARCHITECTURE SPECIFIC STRUCTURES
// ============================================================================

// ARM64 specific
struct IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY {
    quint32 BeginAddress;
    union {
        quint32 UnwindData;
        struct {
            quint32 Flag : 2;
            quint32 FunctionLength : 11;
            quint32 RegF : 3;
            quint32 RegI : 4;
            quint32 H : 1;
            quint32 CR : 2;
            quint32 FrameSize : 9;
        } PackedUnwindData;
    } UnwindData;
};

// x64 specific
struct IMAGE_RUNTIME_FUNCTION_ENTRY_X64 {
    quint32 BeginAddress;
    quint32 EndAddress;
    quint32 UnwindInfoAddress;
};

#pragma pack(pop)

#endif // PE_STRUCTURES_H
