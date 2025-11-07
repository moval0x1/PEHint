#ifndef PE_UTILS_H
#define PE_UTILS_H

#include <QString>
#include <QtGlobal>
#include "pe_structures.h"
#include <QByteArray>
#include <QList>

// Forward declarations
class PEDataModel;

class PEUtils
{
public:
    // ============================================================================
    // FORMATTING UTILITIES
    // ============================================================================
    
    static QString formatHex(quint32 value);
    static QString formatHex(quint16 value);
    static QString formatHex(qint32 value);
    static QString formatHex(quint64 value);
    static QString formatHexWidth(quint64 value, int width);
    static QString formatHex(const QByteArray &data);
    
    // ============================================================================
    // TYPE CONVERSION UTILITIES
    // ============================================================================
    
    static QString getMachineType(quint16 machine);
    static QString getSubsystem(quint16 subsystem);
    static QString getSectionCharacteristics(quint32 characteristics);
    static QString getFileCharacteristics(quint16 characteristics);
    static QString getResourceTypeName(quint32 typeId);
    static QString getDebugTypeName(quint32 typeId);
    static QString getDLLCharacteristics(quint16 characteristics);
    static QString getRichHeaderProductName(quint16 productId);
    
    // ============================================================================
    // VALIDATION UTILITIES
    // ============================================================================
    
    static bool isValidDOSMagic(quint16 magic);
    static bool isValidDOSHeader(const IMAGE_DOS_HEADER &dosHeader);
    static bool isValidPESignature(quint32 signature);
    static bool isValidOptionalHeaderMagic(quint16 magic);
    static bool isPE32File(quint16 magic);
    static bool isPE32PlusFile(quint16 magic);
    static bool is64BitPE(quint16 magic);
    static bool isValidMachineType(quint16 machine);
    static bool isValidSubsystem(quint16 subsystem);
    
    // ============================================================================
    // CALCULATION UTILITIES
    // ============================================================================
    
    static quint32 calculateSectionTableOffset(quint32 peOffset, quint32 optionalHeaderSize);
    static quint32 calculateDataDirectoryOffset(quint32 optionalHeaderOffset, quint32 optionalHeaderSize, int directoryIndex);
    static quint32 calculateRichHeaderOffset(const IMAGE_DOS_HEADER &dosHeader);
    static quint32 calculateRichHeaderSize(const QByteArray &fileData, quint32 richHeaderOffset);
    static bool findRichHeaderOffset(const QByteArray &fileData, const IMAGE_DOS_HEADER &dosHeader, quint32 &richOffset);
    
    // ============================================================================
    // STRUCTURE DETECTION UTILITIES
    // ============================================================================
    
    static bool hasRichHeader(const QByteArray &fileData, const IMAGE_DOS_HEADER &dosHeader);
    static bool hasLoadConfiguration(const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasLoadConfiguration(const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasTLS(const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasTLS(const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasBoundImports(const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasBoundImports(const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasDelayImports(const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasDelayImports(const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    
    // ============================================================================
    // RICH HEADER UTILITIES
    // ============================================================================
    
    static bool parseRichHeader(const QByteArray &fileData, quint32 offset, IMAGE_RICH_HEADER &richHeader);
    static QList<IMAGE_RICH_ENTRY> parseRichEntries(const QByteArray &fileData, quint32 offset, quint32 count);
    static QString getRichHeaderInfo(const QByteArray &fileData, const IMAGE_DOS_HEADER &dosHeader);
    
    // ============================================================================
    // ARCHITECTURE DETECTION
    // ============================================================================
    
    static QString getArchitectureString(quint16 machine, quint16 magic);
    static QString getLinkerVersionString(quint8 major, quint8 minor);
    static QString getOSVersionString(quint16 major, quint16 minor);
    static QString getSubsystemVersionString(quint16 major, quint16 minor);
    
    // ============================================================================
    // SECURITY FEATURES DETECTION
    // ============================================================================
    
    static bool hasASLR(quint16 dllCharacteristics);
    static bool hasDEP(quint16 dllCharacteristics);
    static bool hasControlFlowGuard(quint16 dllCharacteristics);
    static bool hasAuthenticode(const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasAuthenticode(const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasStrongNameSignature(const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasStrongNameSignature(const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    
    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================
    
    static QString formatTimestamp(quint32 timestamp);
    static QString formatFileSize(quint64 size);
    static QString formatAddress(quint32 address, bool is64Bit = false);
    static QString formatAddress(quint64 address);
    static QString formatRVA(quint32 rva);
    static QString formatVA(quint64 va);
    
    // ============================================================================
    // DATA DIRECTORY ACCESS UTILITIES (Proper Implementation)
    // ============================================================================
    
    // Access data directories from parsed PE data model (proper approach)
    static bool hasLoadConfiguration(const PEDataModel &dataModel);
    static bool hasTLS(const PEDataModel &dataModel);
    static bool hasBoundImports(const PEDataModel &dataModel);
    static bool hasDelayImports(const PEDataModel &dataModel);
    static bool hasAuthenticode(const PEDataModel &dataModel);
    static bool hasStrongNameSignature(const PEDataModel &dataModel);
    
    // ============================================================================
    // LEGACY FUNCTIONS (Deprecated - kept for backward compatibility)
    // ============================================================================
    
    // Legacy functions that take fileData parameter (deprecated)
    static bool hasLoadConfiguration(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasLoadConfiguration(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasTLS(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasTLS(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasBoundImports(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasBoundImports(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasDelayImports(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasDelayImports(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasAuthenticode(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasAuthenticode(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    static bool hasStrongNameSignature(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER32 &optionalHeader);
    static bool hasStrongNameSignature(const QByteArray &fileData, const IMAGE_OPTIONAL_HEADER64 &optionalHeader);
    
private:
    PEUtils() = delete; // Static class, prevent instantiation
    
    // Internal helper functions
    static QString formatHexInternal(quint64 value, int width = 0);
    static QString getCharacteristicFlag(quint32 value, quint32 flag, const QString &flagName);
    static QString getDLLCharacteristicFlag(quint16 value, quint16 flag, const QString &flagName);
};

#endif // PE_UTILS_H
