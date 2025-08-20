#include "pe_import_export_parser.h"
#include "language_manager.h"
#include <QDebug>

PEImportExportParser::PEImportExportParser(const QByteArray &fileData)
    : m_fileData(fileData)
{
}

bool PEImportExportParser::parseImports(quint32 importDirectoryRVA, quint32 size, PEDataModel &dataModel)
{
    if (importDirectoryRVA == 0 || size == 0) {
        return true; // No imports
    }
    
    quint32 fileOffset = rvaToFileOffset(importDirectoryRVA, dataModel.getSections());
    if (fileOffset == 0) {
        qWarning() << "Failed to convert import directory RVA to file offset";
        return false;
    }
    
    QStringList imports;
    QMap<QString, QList<QString>> importDetails;
    
    const IMAGE_IMPORT_DESCRIPTOR *importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        m_fileData.data() + fileOffset
    );
    
    int descriptorCount = 0;
    while (importDesc->Name != 0 && descriptorCount < MAX_IMPORT_DESCRIPTORS) {
        if (!parseImportDescriptor(importDesc, dataModel)) {
            qWarning() << "Failed to parse import descriptor" << descriptorCount;
        }
        
        importDesc++;
        descriptorCount++;
    }
    
    return true;
}

bool PEImportExportParser::parseImportDescriptor(const IMAGE_IMPORT_DESCRIPTOR *importDesc, PEDataModel &dataModel)
{
    if (importDesc->Name == 0) {
        return false;
    }
    
    // Read DLL name from RVA
    QString dllName = readStringFromRVA(importDesc->Name);
    if (dllName.isEmpty()) {
        qWarning() << "Failed to read DLL name from RVA" << importDesc->Name;
        return false;
    }
    
    // Add to imports list
    QStringList currentImports = dataModel.getImports();
    if (!currentImports.contains(dllName)) {
        currentImports.append(dllName);
        dataModel.setImports(currentImports);
    }
    
    // Parse thunk tables for function names
    QList<QString> functions;
    
    // Parse original thunk table (contains function names/ordinals)
    if (importDesc->OriginalFirstThunk != 0) {
        parseThunkTable(importDesc->OriginalFirstThunk, dllName, dataModel);
    }
    // Parse first thunk table (contains function addresses)
    else if (importDesc->FirstThunk != 0) {
        parseThunkTable(importDesc->FirstThunk, dllName, dataModel);
    }
    
    return true;
}

bool PEImportExportParser::parseThunkTable(quint32 thunkRVA, const QString &dllName, PEDataModel &dataModel)
{
    quint32 fileOffset = rvaToFileOffset(thunkRVA, dataModel.getSections());
    if (fileOffset == 0) {
        return false;
    }
    
    QList<QString> functions;
    const quint32 *thunk = reinterpret_cast<const quint32*>(m_fileData.data() + fileOffset);
    
    int functionCount = 0;
    while (*thunk != 0 && functionCount < MAX_EXPORT_FUNCTIONS) {
        QString functionName;
        
        if (*thunk & 0x80000000) {
            // Import by ordinal (high bit set)
            quint16 ordinal = static_cast<quint16>(*thunk & 0xFFFF);
            functionName = getFunctionNameByOrdinal(ordinal);
        } else {
            // Import by name
            functionName = getFunctionName(*thunk);
        }
        
        if (!functionName.isEmpty()) {
            functions.append(functionName);
        }
        
        thunk++;
        functionCount++;
    }
    
    // Update import details
    QMap<QString, QList<QString>> importDetails = dataModel.getImportDetails();
    importDetails[dllName] = functions;
    dataModel.setImportDetails(importDetails);
    
    return true;
}

QString PEImportExportParser::getFunctionName(quint32 nameRVA)
{
    if (nameRVA == 0) return QString();
    
    quint32 fileOffset = rvaToFileOffset(nameRVA, QList<const IMAGE_SECTION_HEADER*>());
    if (fileOffset == 0) return QString();
    
    // Skip 2-byte hint
    const char *namePtr = m_fileData.data() + fileOffset + 2;
    return QString::fromLatin1(namePtr);
}

QString PEImportExportParser::getFunctionNameByOrdinal(quint16 ordinal)
{
    return LANG_PARAM("UI/ordinal_format", "value", QString::number(ordinal));
}

bool PEImportExportParser::parseExports(quint32 exportDirectoryRVA, quint32 size, PEDataModel &dataModel)
{
    if (exportDirectoryRVA == 0 || size == 0) {
        return true; // No exports
    }
    
    quint32 fileOffset = rvaToFileOffset(exportDirectoryRVA, dataModel.getSections());
    if (fileOffset == 0) {
        qWarning() << "Failed to convert export directory RVA to file offset";
        return false;
    }
    
    const IMAGE_EXPORT_DIRECTORY *exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        m_fileData.data() + fileOffset
    );
    
    return parseExportDirectory(exportDir, dataModel);
}

bool PEImportExportParser::parseExportDirectory(const IMAGE_EXPORT_DIRECTORY *exportDir, PEDataModel &dataModel)
{
    if (!exportDir) return false;
    
    QStringList exports;
    QStringList exportDetails;
    
    // Parse function names
    if (exportDir->AddressOfNames != 0) {
        quint32 namesOffset = rvaToFileOffset(exportDir->AddressOfNames, dataModel.getSections());
        if (namesOffset != 0) {
            const quint32 *nameRVAs = reinterpret_cast<const quint32*>(m_fileData.data() + namesOffset);
            
            for (quint32 i = 0; i < exportDir->NumberOfNames && i < MAX_EXPORT_FUNCTIONS; ++i) {
                QString functionName = getExportFunctionName(nameRVAs[i]);
                if (!functionName.isEmpty()) {
                    exports.append(functionName);
                    exportDetails.append(functionName);
                }
            }
        }
    }
    
    // Parse functions by ordinal
    if (exportDir->AddressOfFunctions != 0) {
        quint32 functionsOffset = rvaToFileOffset(exportDir->AddressOfFunctions, dataModel.getSections());
        if (functionsOffset != 0) {
            const quint32 *functionRVAs = reinterpret_cast<const quint32*>(m_fileData.data() + functionsOffset);
            
            for (quint32 i = 0; i < exportDir->NumberOfFunctions && i < MAX_EXPORT_FUNCTIONS; ++i) {
                QString functionName = LANG_PARAM("UI/ordinal_format", "value", QString::number(exportDir->OrdinalBase + i));
                if (!exports.contains(functionName)) {
                    exports.append(functionName);
                    exportDetails.append(functionName);
                }
            }
        }
    }
    
    dataModel.setExports(exports);
    dataModel.setExportDetails(exportDetails);
    
    return true;
}

QString PEImportExportParser::getExportFunctionName(quint32 nameRVA)
{
    if (nameRVA == 0) return QString();
    
    quint32 fileOffset = rvaToFileOffset(nameRVA, QList<const IMAGE_SECTION_HEADER*>());
    if (fileOffset == 0) return QString();
    
    return QString::fromLatin1(m_fileData.data() + fileOffset);
}

QString PEImportExportParser::readStringFromRVA(quint32 rva)
{
    if (rva == 0) return QString();
    
    quint32 fileOffset = rvaToFileOffset(rva, QList<const IMAGE_SECTION_HEADER*>());
    if (fileOffset == 0) return QString();
    
    return QString::fromLatin1(m_fileData.data() + fileOffset);
}

quint32 PEImportExportParser::rvaToFileOffset(quint32 rva, const QList<const IMAGE_SECTION_HEADER*> &sections)
{
    if (sections.isEmpty()) return 0;
    
    // Find the section that contains this RVA
    for (const IMAGE_SECTION_HEADER *section : sections) {
        quint32 sectionStart = section->VirtualAddress;
        quint32 sectionEnd = sectionStart + section->VirtualSize;
        
        if (rva >= sectionStart && rva < sectionEnd) {
            // Calculate file offset
            quint32 offsetInSection = rva - sectionStart;
            return section->PointerToRawData + offsetInSection;
        }
    }
    
    return 0;
}
