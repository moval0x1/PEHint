#ifndef PE_IMPORT_EXPORT_PARSER_H
#define PE_IMPORT_EXPORT_PARSER_H

#include "pe_structures.h"
#include "pe_data_model.h"
#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QMap>

class PEImportExportParser
{
public:
    PEImportExportParser(const QByteArray &fileData);
    
    // Import parsing (Microsoft PE Format compliant)
    bool parseImports(quint32 importDirectoryRVA, quint32 size, PEDataModel &dataModel);
    
    // Export parsing (Microsoft PE Format compliant)
    bool parseExports(quint32 exportDirectoryRVA, quint32 size, PEDataModel &dataModel);
    
    // Helper methods
    QString readStringFromRVA(quint32 rva);
    quint32 rvaToFileOffset(quint32 rva, const QList<const IMAGE_SECTION_HEADER*> &sections);
    
private:
    // Import parsing helpers
    bool parseImportDescriptor(const IMAGE_IMPORT_DESCRIPTOR *importDesc, PEDataModel &dataModel);
    bool parseThunkTable(quint32 thunkRVA, const QString &dllName, PEDataModel &dataModel);
    QString getFunctionName(quint32 nameRVA);
    QString getFunctionNameByOrdinal(quint16 ordinal);
    
    // Export parsing helpers
    bool parseExportDirectory(const IMAGE_EXPORT_DIRECTORY *exportDir, PEDataModel &dataModel);
    QString getExportFunctionName(quint32 nameRVA);
    
    // Data
    const QByteArray &m_fileData;
    
    // Constants
    static const int MAX_IMPORT_DESCRIPTORS = 1000; // Safety limit
    static const int MAX_EXPORT_FUNCTIONS = 10000;  // Safety limit
};

#endif // PE_IMPORT_EXPORT_PARSER_H
