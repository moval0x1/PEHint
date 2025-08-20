#ifndef PE_DATA_DIRECTORY_PARSER_H
#define PE_DATA_DIRECTORY_PARSER_H

#include "pe_structures.h"
#include "pe_data_model.h"
#include <QByteArray>
#include <QString>

class PEDataDirectoryParser
{
public:
    PEDataDirectoryParser(const QByteArray &fileData);
    
    // Main parsing function (Microsoft PE Format compliant)
    bool parseDataDirectories(const IMAGE_OPTIONAL_HEADER *optionalHeader, 
                            quint32 dataDirectoryOffset, 
                            PEDataModel &dataModel);
    
    // Individual directory parsers
    bool parseExportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseImportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseResourceDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseExceptionDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseCertificateDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseBaseRelocationDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseDebugDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseArchitectureDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseGlobalPointerDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseTLSDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseLoadConfigDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseBoundImportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseImportAddressTableDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseDelayImportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    bool parseCOMRuntimeDirectory(quint32 rva, quint32 size, PEDataModel &dataModel);
    
    // Helper methods
    quint32 rvaToFileOffset(quint32 rva, const QList<const IMAGE_SECTION_HEADER*> &sections);
    QString readStringFromRVA(quint32 rva, const QList<const IMAGE_SECTION_HEADER*> &sections);
    
private:
    // Resource parsing helpers
    bool parseResourceDirectoryEntry(const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry, 
                                   quint32 resourceOffset, 
                                   PEDataModel &dataModel);
    
    // Debug parsing helpers
    bool parseDebugDirectoryEntry(const IMAGE_DEBUG_DIRECTORY *debugDir, 
                                 PEDataModel &dataModel);
    
    // Data
    const QByteArray &m_fileData;
    
    // Constants
    static const int MAX_RESOURCE_ENTRIES = 1000;
    static const int MAX_DEBUG_ENTRIES = 100;
};

#endif // PE_DATA_DIRECTORY_PARSER_H
