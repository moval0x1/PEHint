/*

    Header from: https://github.com/0xRick/PE-Parser/blob/main/PE-Parser/PEFILE_CUSTOM_STRUCTS.h
    Explanation: https://cr0mll.github.io/cyberclopaedia/Reverse%20Engineering/Binary%20Formats/PE/The%20Rich%20Header.html

*/

#ifndef PEFILE_CUSTOM_STRUCTS_H
#define PEFILE_CUSTOM_STRUCTS_H

#include "winntdef.h"

typedef struct __RICH_HEADER_INFO {
    int size;
    char* ptrToBuffer;
    int entries;
} RICH_HEADER_INFO, * PRICH_HEADER_INFO;

typedef struct __RICH_HEADER_ENTRY {
    WORD  prodID;
    WORD  buildID;
    DWORD useCount;
} RICH_HEADER_ENTRY, * PRICH_HEADER_ENTRY;

typedef struct __RICH_HEADER {
    PRICH_HEADER_ENTRY entries;
} RICH_HEADER, * PRICH_HEADER;

typedef struct __ILT_ENTRY_64 {
    union {
        DWORD ORDINAL : 16;
        DWORD HINT_NAME_TABE : 32;
    } FIELD_2;
    DWORD ORDINAL_NAME_FLAG : 1;
} ILT_ENTRY_64, * PILT_ENTRY_64;

typedef struct __ILT_ENTRY_32 {
    union {
        DWORD ORDINAL : 16;
        DWORD HINT_NAME_TABE : 32;
        DWORD ORDINAL_NAME_FLAG : 1;
    } FIELD_1;
} ILT_ENTRY_32, * PILT_ENTRY_32;

typedef struct __BASE_RELOC_ENTRY {
    WORD OFFSET : 12;
    WORD TYPE : 4;
} BASE_RELOC_ENTRY, * PBASE_RELOC_ENTRY;

#endif // PEFILE_CUSTOM_STRUCTS_H
