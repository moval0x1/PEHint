#include "pe_utils.h"
#include "language_manager.h"
#include "pe_data_model.h"
#include <QString>
#include <QDateTime>
#include <QDebug>

QString PEUtils::formatHexInternal(quint64 value, int width)
{
    QString digits = QString::number(value, 16).toUpper();
    if (width > 0) {
        digits = digits.rightJustified(width, '0');
    }
    return QStringLiteral("0x") + digits;
}

// Formatting utilities
QString PEUtils::formatHex(quint32 value)
{
    return formatHexInternal(static_cast<quint64>(value), 8);
}

QString PEUtils::formatHex(quint16 value)
{
    return formatHexInternal(static_cast<quint64>(value), 4);
}

QString PEUtils::formatHex(qint32 value)
{
    return formatHexInternal(static_cast<quint64>(static_cast<quint32>(value)), 8);
}

QString PEUtils::formatHex(quint64 value)
{
    return formatHexInternal(value, 16);
}

QString PEUtils::formatHexWidth(quint64 value, int width)
{
    return formatHexInternal(value, width);
}

QString PEUtils::formatHex(const QByteArray &data)
{
    QString result;
    for (int i = 0; i < data.size() && i < 16; ++i) {
        if (i > 0) result += " ";
        result += QString("%1").arg(static_cast<quint8>(data[i]), 2, 16, QChar('0')).toUpper();
    }
    if (data.size() > 16) result += "...";
    return result;
}

// Type conversion utilities
QString PEUtils::getMachineType(quint16 machine)
{
    switch (machine) {
        case 0x014c: return LANG("UI/machine_386");
        case 0x014d: return LANG("UI/machine_486");
        case 0x014e: return LANG("UI/machine_586");
        case 0x8664: return LANG("UI/machine_amd64");
        case 0x01c0: return LANG("UI/machine_arm");
        case 0xaa64: return LANG("UI/machine_arm64");
        default: return LANG_PARAM("UI/machine_unknown", "value", QString("%1").arg(machine, 4, 16, QChar('0')));
    }
}

QString PEUtils::getSubsystem(quint16 subsystem)
{
    switch (subsystem) {
        case 0: return LANG("UI/subsystem_unknown");
        case 1: return LANG("UI/subsystem_native");
        case 2: return LANG("UI/subsystem_windows_gui");
        case 3: return LANG("UI/subsystem_windows_cui");
        case 5: return LANG("UI/subsystem_os2_cui");
        case 7: return LANG("UI/subsystem_posix_cui");
        case 9: return LANG("UI/subsystem_windows_ce_gui");
        case 10: return LANG("UI/subsystem_efi_app");
        case 11: return LANG("UI/subsystem_efi_boot");
        case 12: return LANG("UI/subsystem_efi_runtime");
        case 13: return LANG("UI/subsystem_efi_rom");
        case 14: return LANG("UI/subsystem_xbox");
        default: return LANG_PARAM("UI/subsystem_unknown_value", "value", QString::number(subsystem));
    }
}

QString PEUtils::getSectionCharacteristics(quint32 characteristics)
{
    QStringList chars;
    
    if (characteristics & 0x00000020) chars << LANG("UI/section_char_code");
    if (characteristics & 0x00000040) chars << LANG("UI/section_char_initialized");
    if (characteristics & 0x00000080) chars << LANG("UI/section_char_uninitialized");
    if (characteristics & 0x02000000) chars << LANG("UI/section_char_execute");
    if (characteristics & 0x04000000) chars << LANG("UI/section_char_read");
    if (characteristics & 0x08000000) chars << LANG("UI/section_char_write");
    if (characteristics & 0x10000000) chars << LANG("UI/section_char_shared");
    
    return chars.isEmpty() ? LANG("UI/section_char_none") : chars.join(", ");
}

QString PEUtils::getFileCharacteristics(quint16 characteristics)
{
    QStringList chars;
    
    if (characteristics & 0x0001) chars << LANG("UI/file_char_reloc_stripped");
    if (characteristics & 0x0002) chars << LANG("UI/file_char_executable");
    if (characteristics & 0x0004) chars << LANG("UI/file_char_line_numbers_stripped");
    if (characteristics & 0x0008) chars << LANG("UI/file_char_local_symbols_stripped");
    if (characteristics & 0x0010) chars << LANG("UI/file_char_aggressive_ws_trim");
    if (characteristics & 0x0020) chars << LANG("UI/file_char_large_address_aware");
    if (characteristics & 0x0040) chars << LANG("UI/file_char_16bit");
    if (characteristics & 0x0080) chars << LANG("UI/file_char_bytes_reserved_low");
    if (characteristics & 0x0100) chars << LANG("UI/file_char_32bit");
    if (characteristics & 0x0200) chars << LANG("UI/file_char_debug_info_stripped");
    if (characteristics & 0x0400) chars << LANG("UI/file_char_removable_run_from_swap");
    if (characteristics & 0x0800) chars << LANG("UI/file_char_net_run_from_swap");
    if (characteristics & 0x1000) chars << LANG("UI/file_char_system");
    if (characteristics & 0x2000) chars << LANG("UI/file_char_dll");
    if (characteristics & 0x4000) chars << LANG("UI/file_char_up_system_only");
    if (characteristics & 0x8000) chars << LANG("UI/file_char_bytes_reserved_high");
    
    return chars.isEmpty() ? LANG("UI/section_char_none") : chars.join(", ");
}

QString PEUtils::getResourceTypeName(quint32 typeId)
{
    switch (typeId) {
        case 1: return LANG("UI/resource_cursor");
        case 2: return LANG("UI/resource_bitmap");
        case 3: return LANG("UI/resource_icon");
        case 4: return LANG("UI/resource_menu");
        case 5: return LANG("UI/resource_dialog");
        case 6: return LANG("UI/resource_string");
        case 7: return LANG("UI/resource_font_directory");
        case 8: return LANG("UI/resource_font");
        case 9: return LANG("UI/resource_accelerator");
        case 10: return LANG("UI/resource_rc_data");
        case 11: return LANG("UI/resource_message_table");
        case 12: return LANG("UI/resource_group_cursor");
        case 14: return LANG("UI/resource_group_icon");
        case 16: return LANG("UI/resource_version");
        case 17: return LANG("UI/resource_dialog_include");
        case 19: return LANG("UI/resource_plug_and_play");
        case 20: return LANG("UI/resource_vxd");
        case 21: return LANG("UI/resource_animated_cursor");
        case 22: return LANG("UI/resource_animated_icon");
        case 23: return LANG("UI/resource_html");
        case 24: return LANG("UI/resource_manifest");
        default: return LANG_PARAM("UI/subsystem_unknown_value", "value", QString::number(typeId));
    }
}

QString PEUtils::getDebugTypeName(quint32 typeId)
{
    switch (typeId) {
        case 0: return LANG("UI/debug_unknown");
        case 1: return LANG("UI/debug_coff");
        case 2: return LANG("UI/debug_codeview");
        case 3: return LANG("UI/debug_fpo");
        case 4: return LANG("UI/debug_misc");
        case 5: return LANG("UI/debug_exception");
        case 6: return LANG("UI/debug_fixup");
        case 7: return LANG("UI/debug_omap_to_src");
        case 8: return LANG("UI/debug_omap_from_src");
        case 9: return LANG("UI/debug_borland");
        case 10: return LANG("UI/debug_reserved");
        case 11: return LANG("UI/debug_clsid");
        case 12: return LANG("UI/debug_pogo");
        case 13: return LANG("UI/debug_iltcg");
        case 14: return LANG("UI/debug_mpx");
        case 15: return LANG("UI/debug_repro");
        case 16: return LANG("UI/debug_exdll_characteristics");
        default: return LANG_PARAM("UI/debug_unknown", "value", QString::number(typeId));
    }
}

QString PEUtils::getDLLCharacteristics(quint16 characteristics)
{
    QStringList chars;
    
    if (characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) 
        chars << LANG("UI/dll_char_high_entropy_va");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) 
        chars << LANG("UI/dll_char_dynamic_base");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) 
        chars << LANG("UI/dll_char_force_integrity");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) 
        chars << LANG("UI/dll_char_nx_compat");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) 
        chars << LANG("UI/dll_char_no_isolation");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) 
        chars << LANG("UI/dll_char_no_seh");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) 
        chars << LANG("UI/dll_char_no_bind");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) 
        chars << LANG("UI/dll_char_appcontainer");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) 
        chars << LANG("UI/dll_char_wdm_driver");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) 
        chars << LANG("UI/dll_char_guard_cf");
    if (characteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) 
        chars << LANG("UI/dll_char_terminal_server_aware");
    
    return chars.isEmpty() ? LANG("UI/dll_char_none") : chars.join(", ");
}

QString PEUtils::getRichHeaderProductName(quint16 productId)
{
    switch (productId) {
        case 0x0001: return "Microsoft Visual C++";
        case 0x0002: return "Microsoft Visual Basic";
        case 0x0003: return "Microsoft Visual C++ (Debug)";
        case 0x0004: return "Microsoft Visual Basic (Debug)";
        case 0x0005: return "Microsoft Visual C++ (Release)";
        case 0x0006: return "Microsoft Visual Basic (Release)";
        case 0x0007: return "Microsoft Visual C++ (Debug Runtime)";
        case 0x0008: return "Microsoft Visual Basic (Debug Runtime)";
        case 0x0009: return "Microsoft Visual C++ (Release Runtime)";
        case 0x000A: return "Microsoft Visual Basic (Release Runtime)";
        case 0x000B: return "Microsoft Visual C++ (Debug DLL)";
        case 0x000C: return "Microsoft Visual Basic (Debug DLL)";
        case 0x000D: return "Microsoft Visual C++ (Release DLL)";
        case 0x000E: return "Microsoft Visual Basic (Release DLL)";
        case 0x000F: return "Microsoft Visual C++ (Debug Static)";
        case 0x0010: return "Microsoft Visual Basic (Debug Static)";
        case 0x0011: return "Microsoft Visual C++ (Release Static)";
        case 0x0012: return "Microsoft Visual Basic (Release Static)";
        default: return QString("Unknown Product (0x%1)").arg(productId, 4, 16, QChar('0'));
    }
}

// Validation utilities
bool PEUtils::isValidDOSMagic(quint16 magic)
{
    return magic == 0x5A4D; // "MZ"
}

bool PEUtils::isValidDOSHeader(const IMAGE_DOS_HEADER &dosHeader)
{
    // Check magic number
    if (!isValidDOSMagic(dosHeader.e_magic)) {
        return false;
    }
    
    // Check if PE header offset is reasonable
    if (dosHeader.e_lfanew < sizeof(IMAGE_DOS_HEADER) || dosHeader.e_lfanew > 0x10000) {
        return false;
    }
    
    return true;
}

bool PEUtils::isValidPESignature(quint32 signature)
{
    return signature == 0x00004550; // "PE\0\0"
}

bool PEUtils::isValidOptionalHeaderMagic(quint16 magic)
{
    return magic == 0x10b || magic == 0x20b; // PE32 or PE32+
}

// Calculation utilities
quint32 PEUtils::calculateSectionTableOffset(quint32 peOffset, quint32 optionalHeaderSize)
{
    return peOffset + sizeof(IMAGE_FILE_HEADER) + optionalHeaderSize;
}

quint32 PEUtils::calculateDataDirectoryOffset(quint32 optionalHeaderOffset, quint32 optionalHeaderSize, int directoryIndex)
{
    return optionalHeaderOffset + optionalHeaderSize + (directoryIndex * sizeof(IMAGE_DATA_DIRECTORY));
}

// ============================================================================
// NEW UTILITY FUNCTIONS FOR ENHANCED PE SUPPORT
// ============================================================================

bool PEUtils::isPE32File(quint16 magic)
{
    return magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
}

bool PEUtils::isPE32PlusFile(quint16 magic)
{
    return magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

bool PEUtils::is64BitPE(quint16 magic)
{
    return magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

bool PEUtils::isValidMachineType(quint16 machine)
{
    switch (machine) {
        case IMAGE_FILE_MACHINE_UNKNOWN:
        case IMAGE_FILE_MACHINE_I386:
        case IMAGE_FILE_MACHINE_AMD64:
        case IMAGE_FILE_MACHINE_ARM:
        case IMAGE_FILE_MACHINE_ARM64:
        case IMAGE_FILE_MACHINE_ARMNT:
        case IMAGE_FILE_MACHINE_IA64:
        case IMAGE_FILE_MACHINE_POWERPC:
        case IMAGE_FILE_MACHINE_MIPS16:
        case IMAGE_FILE_MACHINE_MIPSFPU:
        case IMAGE_FILE_MACHINE_SH3:
        case IMAGE_FILE_MACHINE_SH4:
        case IMAGE_FILE_MACHINE_THUMB:
        case IMAGE_FILE_MACHINE_AM33:
        case IMAGE_FILE_MACHINE_EBC:
        case IMAGE_FILE_MACHINE_M32R:
        case IMAGE_FILE_MACHINE_R4000:
        case IMAGE_FILE_MACHINE_SH3DSP:
        case IMAGE_FILE_MACHINE_SH5:
        case IMAGE_FILE_MACHINE_WCEMIPSV2:
            return true;
        default:
            return false;
    }
}

bool PEUtils::isValidSubsystem(quint16 subsystem)
{
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_UNKNOWN:
        case IMAGE_SUBSYSTEM_NATIVE:
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        case IMAGE_SUBSYSTEM_OS2_CUI:
        case IMAGE_SUBSYSTEM_POSIX_CUI:
        case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        case IMAGE_SUBSYSTEM_EFI_ROM:
        case IMAGE_SUBSYSTEM_XBOX:
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
            return true;
        default:
            return false;
    }
}

quint32 PEUtils::calculateRichHeaderOffset(const IMAGE_DOS_HEADER &dosHeader)
{
    // Rich header is located after the DOS stub and before the PE header
    // It starts after the DOS header (0x40) and ends before e_lfanew
    // We need to search for the Rich signature "DanS" (0x536E6144) XORed with a key
    // The signature appears as 0x6869 ("hi") when XORed
    
    // Start searching from end of DOS header (0x40) up to PE header
    // Rich header typically starts around 0x80, but can vary
    return 0x80; // Default location, but should be searched dynamically
}

bool PEUtils::findRichHeaderOffset(const QByteArray &fileData, const IMAGE_DOS_HEADER &dosHeader, quint32 &richOffset)
{
    // Rich header is located between DOS header end and PE header start
    quint32 dosHeaderEnd = sizeof(IMAGE_DOS_HEADER); // 0x40
    quint32 peHeaderStart = dosHeader.e_lfanew;
    
    // Rich header structure:
    // - Starts with XOR key (dword)
    // - Then "DanS" (0x536E6144) XORed with the key
    // - Then version and count
    // - Then entries
    // - Ends with "Rich" (0x68636952) XORed with the key
    
    // Search for "DanS" signature (0x536E6144) XORed
    const quint32 DAN_SIGNATURE = 0x536E6144; // "DanS"
    const quint32 RICH_SIGNATURE = 0x68636952; // "Rich"
    
    // Search byte-by-byte for better accuracy (Rich Header can start at any 4-byte aligned offset)
    for (quint32 offset = dosHeaderEnd; offset < peHeaderStart - 16; offset++) {
        if (offset + 16 > fileData.size()) {
            break;
        }
        
        // Check if offset is 4-byte aligned (Rich Header must be dword-aligned)
        if (offset % 4 != 0) {
            continue;
        }
        
        // Read potential XOR key and signature
        const quint32 *data = reinterpret_cast<const quint32*>(fileData.data() + offset);
        quint32 xorKey = data[0];
        quint32 signature = data[1];
        
        // Check if signature XOR key gives us "DanS"
        if ((signature ^ xorKey) == DAN_SIGNATURE) {
            // Verify it's a valid Rich header by checking reasonable values
            quint32 version = data[2];
            quint32 count = data[3];
            
            if (count > 0 && count < 1000 && version < 0x10000) {
                // Try to verify the end marker "Rich" exists later (but don't require it)
                quint32 expectedEndOffset = offset + 16 + (count * 12); // 16 bytes header + entries
                bool hasRichMarker = false;
                
                if (expectedEndOffset + 4 < peHeaderStart && expectedEndOffset + 4 < fileData.size()) {
                    const quint32 *endData = reinterpret_cast<const quint32*>(fileData.data() + expectedEndOffset);
                    quint32 richSignature = endData[0];
                    if ((richSignature ^ xorKey) == RICH_SIGNATURE) {
                        hasRichMarker = true;
                    }
                }
                
                // Accept if we have "DanS" signature and reasonable count, even without "Rich" marker
                // (some files may have Rich Header without the end marker)
                if (hasRichMarker || (expectedEndOffset < peHeaderStart && count > 0 && count < 100)) {
                    richOffset = offset;
                    return true;
                }
            }
        }
    }
    
    return false;
}

quint32 PEUtils::calculateRichHeaderSize(const QByteArray &fileData, quint32 richHeaderOffset)
{
    if (richHeaderOffset + 16 > fileData.size()) {
        return 0;
    }
    
    // Read the header to get count
    const quint32 *data = reinterpret_cast<const quint32*>(fileData.data() + richHeaderOffset);
    quint32 count = data[3]; // RichCount
    
    // Calculate size: 4 dwords (16 bytes) + entries (each entry is 12 bytes) + "Rich" marker (4 bytes) + checksum (4 bytes)
    return 16 + (count * sizeof(IMAGE_RICH_ENTRY)) + 8;
}

bool PEUtils::hasRichHeader(const QByteArray &fileData, const IMAGE_DOS_HEADER &dosHeader)
{
    quint32 richOffset;
    return findRichHeaderOffset(fileData, dosHeader, richOffset);
}

// ============================================================================
// DATA DIRECTORY ACCESS UTILITIES (Proper Implementation)
// ============================================================================

bool PEUtils::hasLoadConfiguration(const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 10) {
        return false;
    }
    
    // Load configuration is at index 10
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &loadConfigDir = optionalHeader.DataDirectory[10];
    return loadConfigDir.VirtualAddress != 0 && loadConfigDir.Size != 0;
}

bool PEUtils::hasLoadConfiguration(const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 10) {
        return false;
    }
    
    // Load configuration is at index 10
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &loadConfigDir = optionalHeader.DataDirectory[10];
    return loadConfigDir.VirtualAddress != 0 && loadConfigDir.Size != 0;
}

bool PEUtils::hasTLS(const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 9) {
        return false;
    }
    
    // TLS is at index 9
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &tlsDir = optionalHeader.DataDirectory[9];
    return tlsDir.VirtualAddress != 0 && tlsDir.Size != 0;
}

bool PEUtils::hasTLS(const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 9) {
        return false;
    }
    
    // TLS is at index 9
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &tlsDir = optionalHeader.DataDirectory[9];
    return tlsDir.VirtualAddress != 0 && tlsDir.Size != 0;
}

bool PEUtils::hasBoundImports(const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 11) {
        return false;
    }
    
    // Bound imports is at index 11
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &boundImportDir = optionalHeader.DataDirectory[11];
    return boundImportDir.VirtualAddress != 0 && boundImportDir.Size != 0;
}

bool PEUtils::hasBoundImports(const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 11) {
        return false;
    }
    
    // Bound imports is at index 11
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &boundImportDir = optionalHeader.DataDirectory[11];
    return boundImportDir.VirtualAddress != 0 && boundImportDir.Size != 0;
}

bool PEUtils::hasDelayImports(const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 13) {
        return false;
    }
    
    // Delay imports is at index 13
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &delayImportDir = optionalHeader.DataDirectory[13];
    return delayImportDir.VirtualAddress != 0 && delayImportDir.Size != 0;
}

bool PEUtils::hasDelayImports(const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 13) {
        return false;
    }
    
    // Delay imports is at index 13
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &delayImportDir = optionalHeader.DataDirectory[13];
    return delayImportDir.VirtualAddress != 0 && delayImportDir.Size != 0;
}

bool PEUtils::hasAuthenticode(const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 4) {
        return false;
    }
    
    // Certificate directory is at index 4
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &certDir = optionalHeader.DataDirectory[4];
    return certDir.VirtualAddress != 0 && certDir.Size != 0;
}

bool PEUtils::hasAuthenticode(const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 4) {
        return false;
    }
    
    // Certificate directory is at index 4
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &certDir = optionalHeader.DataDirectory[4];
    return certDir.VirtualAddress != 0 && certDir.Size != 0;
}

bool PEUtils::hasStrongNameSignature(const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 14) {
        return false;
    }
    
    // COM+ Runtime directory is at index 14
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &comDir = optionalHeader.DataDirectory[14];
    return comDir.VirtualAddress != 0 && comDir.Size != 0;
}

bool PEUtils::hasStrongNameSignature(const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    if (optionalHeader.NumberOfRvaAndSizes < 14) {
        return false;
    }
    
    // COM+ Runtime directory is at index 14
    // Access the data directory directly from the parsed header
    const IMAGE_DATA_DIRECTORY &comDir = optionalHeader.DataDirectory[14];
    return comDir.VirtualAddress != 0 && comDir.Size != 0;
}

// ============================================================================
// LEGACY FUNCTIONS (Deprecated - kept for backward compatibility)
// ============================================================================

bool PEUtils::parseRichHeader(const QByteArray &fileData, quint32 offset, IMAGE_RICH_HEADER &richHeader)
{
    if (offset + 16 > fileData.size()) {
        return false;
    }
    
    // Rich header structure: [XOR Key][DanS XORed][Version][Count]
    const quint32 *data = reinterpret_cast<const quint32*>(fileData.data() + offset);
    
    richHeader.XorKey = data[0];
    richHeader.RichSignature = data[1]; // This is "DanS" XORed
    richHeader.RichVersion = data[2];
    richHeader.RichCount = data[3];
    
    return true;
}

QList<IMAGE_RICH_ENTRY> PEUtils::parseRichEntries(const QByteArray &fileData, quint32 offset, quint32 count)
{
    QList<IMAGE_RICH_ENTRY> entries;
    
    // Rich entries start after the 4 dwords (16 bytes) of header
    quint32 entriesOffset = offset + 16;
    
    if (entriesOffset + (count * 12) > fileData.size()) { // Each entry is 12 bytes (3 dwords)
        return entries;
    }
    
    // Read XOR key from header
    const quint32 *headerData = reinterpret_cast<const quint32*>(fileData.data() + offset);
    quint32 xorKey = headerData[0];
    
    // Read entries (they are XORed, need to decrypt)
    const quint32 *entryData = reinterpret_cast<const quint32*>(fileData.data() + entriesOffset);
    
    for (quint32 i = 0; i < count; ++i) {
        IMAGE_RICH_ENTRY entry;
        // Each entry is 12 bytes (3 dwords)
        // Entry structure: [ProductId|ProductVersion][ProductCount][ProductTimestamp]
        quint32 dword0 = entryData[i * 3] ^ xorKey;
        quint32 dword1 = entryData[i * 3 + 1] ^ xorKey;
        quint32 dword2 = entryData[i * 3 + 2] ^ xorKey;
        
        entry.ProductId = dword0 & 0xFFFF;
        entry.ProductVersion = (dword0 >> 16) & 0xFFFF;
        entry.ProductCount = dword1;
        entry.ProductTimestamp = dword2;
        
        entries.append(entry);
    }
    
    return entries;
}

QString PEUtils::getRichHeaderInfo(const QByteArray &fileData, const IMAGE_DOS_HEADER &dosHeader)
{
    quint32 richOffset;
    if (!findRichHeaderOffset(fileData, dosHeader, richOffset)) {
        return LANG("UI/rich_header_not_found");
    }
    
    IMAGE_RICH_HEADER richHeader;
    if (!parseRichHeader(fileData, richOffset, richHeader)) {
        return LANG("UI/rich_header_parse_error");
    }
    
    QList<IMAGE_RICH_ENTRY> entries = parseRichEntries(fileData, richOffset, richHeader.RichCount);
    
    QString info = QString("Rich Header Information:\n");
    info += QString("XOR Key: %1\n").arg(formatHex(richHeader.XorKey));
    info += QString("Signature: %1\n").arg(formatHex(richHeader.RichSignature));
    info += QString("Version: %1\n").arg(formatHex(richHeader.RichVersion));
    info += QString("Entry Count: %1\n\n").arg(richHeader.RichCount);
    
    info += "Product Entries:\n";
    for (const IMAGE_RICH_ENTRY &entry : entries) {
        info += QString("- %1 (v%2.%3) - Count: %4, Timestamp: %5\n")
                .arg(getRichHeaderProductName(entry.ProductId))
                .arg(entry.ProductVersion >> 8)
                .arg(entry.ProductVersion & 0xFF)
                .arg(entry.ProductCount)
                .arg(formatTimestamp(entry.ProductTimestamp));
    }
    
    return info;
}

QString PEUtils::getArchitectureString(quint16 machine, quint16 magic)
{
    QString arch = getMachineType(machine);
    QString format = is64BitPE(magic) ? " (64-bit)" : " (32-bit)";
    return arch + format;
}

QString PEUtils::getLinkerVersionString(quint8 major, quint8 minor)
{
    return QString("%1.%2").arg(major).arg(minor);
}

QString PEUtils::getOSVersionString(quint16 major, quint16 minor)
{
    return QString("%1.%2").arg(major).arg(minor);
}

QString PEUtils::getSubsystemVersionString(quint16 major, quint16 minor)
{
    return QString("%1.%2").arg(major).arg(minor);
}

bool PEUtils::hasASLR(quint16 dllCharacteristics)
{
    return (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
}

bool PEUtils::hasDEP(quint16 dllCharacteristics)
{
    return (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
}

bool PEUtils::hasControlFlowGuard(quint16 dllCharacteristics)
{
    return (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
}

QString PEUtils::formatTimestamp(quint32 timestamp)
{
    if (timestamp == 0) {
        return LANG("UI/timestamp_unknown");
    }
    
    QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
    return dateTime.toString("yyyy-MM-dd hh:mm:ss");
}

QString PEUtils::formatFileSize(quint64 size)
{
    if (size < 1024) {
        return QString("%1 bytes").arg(size);
    } else if (size < 1024 * 1024) {
        return QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
    } else if (size < 1024 * 1024 * 1024) {
        return QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
    } else {
        return QString("%1 GB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
    }
}

QString PEUtils::formatAddress(quint32 address, bool is64Bit)
{
    if (is64Bit) {
        return formatHexInternal(static_cast<quint64>(address), 16);
    }
    return formatHexInternal(static_cast<quint64>(address), 8);
}

QString PEUtils::formatAddress(quint64 address)
{
    if (address > 0xFFFFFFFFULL) {
        return formatHexInternal(address, 16);
    }
    return formatHexInternal(static_cast<quint64>(address), 8);
}

QString PEUtils::formatRVA(quint32 rva)
{
    return QString("RVA: %1").arg(formatHexInternal(static_cast<quint64>(rva), 8));
}

QString PEUtils::formatVA(quint64 va)
{
    return QString("VA: %1").arg(formatHexInternal(va, 16));
}

// ============================================================================
// LEGACY FUNCTIONS (Deprecated - kept for backward compatibility)
// ============================================================================

bool PEUtils::hasLoadConfiguration(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasLoadConfiguration(optionalHeader);
}

bool PEUtils::hasLoadConfiguration(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasLoadConfiguration(optionalHeader);
}

bool PEUtils::hasTLS(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasTLS(optionalHeader);
}

bool PEUtils::hasTLS(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasTLS(optionalHeader);
}

bool PEUtils::hasBoundImports(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasBoundImports(optionalHeader);
}

bool PEUtils::hasBoundImports(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasBoundImports(optionalHeader);
}

bool PEUtils::hasDelayImports(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasDelayImports(optionalHeader);
}

bool PEUtils::hasDelayImports(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasDelayImports(optionalHeader);
}

bool PEUtils::hasAuthenticode(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasAuthenticode(optionalHeader);
}

bool PEUtils::hasAuthenticode(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasAuthenticode(optionalHeader);
}

bool PEUtils::hasStrongNameSignature(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasStrongNameSignature(optionalHeader);
}

bool PEUtils::hasStrongNameSignature(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader)
{
    Q_UNUSED(fileData); // Legacy parameter, not used in new implementation
    return hasStrongNameSignature(optionalHeader);
}
