#include "pe_utils.h"
#include "language_manager.h"
#include <QString>

// Formatting utilities
QString PEUtils::formatHex(quint32 value)
{
    return QString("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
}

QString PEUtils::formatHex(quint16 value)
{
    return QString("0x%1").arg(value, 4, 16, QChar('0')).toUpper();
}

QString PEUtils::formatHex(qint32 value)
{
    return QString("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
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
