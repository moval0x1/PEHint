#ifndef PE_UTILS_H
#define PE_UTILS_H

#include <QString>
#include <QtGlobal>

class PEUtils
{
public:
    // Formatting utilities
    static QString formatHex(quint32 value);
    static QString formatHex(quint16 value);
    static QString formatHex(qint32 value);
    
    // Type conversion utilities
    static QString getMachineType(quint16 machine);
    static QString getSubsystem(quint16 subsystem);
    static QString getSectionCharacteristics(quint32 characteristics);
    static QString getFileCharacteristics(quint16 characteristics);
    static QString getResourceTypeName(quint32 typeId);
    static QString getDebugTypeName(quint32 typeId);
    
    // Validation utilities
    static bool isValidDOSMagic(quint16 magic);
    static bool isValidPESignature(quint32 signature);
    static bool isValidOptionalHeaderMagic(quint16 magic);
    
    // Calculation utilities
    static quint32 calculateSectionTableOffset(quint32 peOffset, quint32 optionalHeaderSize);
    static quint32 calculateDataDirectoryOffset(quint32 optionalHeaderOffset, quint32 optionalHeaderSize, int directoryIndex);
    
private:
    PEUtils() = delete; // Static class, prevent instantiation
};

#endif // PE_UTILS_H
