#ifndef PE_DATA_DIRECTORY_TYPES_H
#define PE_DATA_DIRECTORY_TYPES_H

#include <QString>
#include <QVector>

/** Parsed IMAGE_DEBUG_DIRECTORY entry (data directory index 6). */
struct PEDebugDirectoryEntry {
    quint32 type = 0;
    QString typeName;
    quint32 timeDateStamp = 0;
    quint16 majorVersion = 0;
    quint16 minorVersion = 0;
    quint32 sizeOfData = 0;
    quint32 addressOfRawData = 0;
    quint32 pointerToRawData = 0;
};

/** Parsed IMAGE_TLS_DIRECTORY32/64 (data directory index 9). */
struct PETlsDirectoryInfo {
    bool present = false;
    quint64 startAddressOfRawData = 0;
    quint64 endAddressOfRawData = 0;
    quint64 addressOfIndex = 0;
    quint64 addressOfCallbacks = 0;
    quint32 sizeOfZeroFill = 0;
    quint32 characteristics = 0;
    bool callbacksPresent = false;
};

/** Parsed IMAGE_LOAD_CONFIG_DIRECTORY32/64 (data directory index 10). */
struct PELoadConfigDirectoryInfo {
    bool present = false;
    quint32 size = 0;
    quint32 timeDateStamp = 0;
    quint16 majorVersion = 0;
    quint16 minorVersion = 0;
};

#endif // PE_DATA_DIRECTORY_TYPES_H
