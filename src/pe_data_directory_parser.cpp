#include "pe_data_directory_parser.h"
#include "pe_utils.h"
#include "language_manager.h"
#include <QDebug>

PEDataDirectoryParser::PEDataDirectoryParser(const QByteArray &fileData)
    : m_fileData(fileData)
{
}

bool PEDataDirectoryParser::parseDataDirectories(const IMAGE_OPTIONAL_HEADER *optionalHeader, 
                                                quint32 dataDirectoryOffset, 
                                                PEDataModel &dataModel)
{
    if (!optionalHeader || dataDirectoryOffset == 0) {
        return false;
    }
    
    // Data directories start immediately after the optional header
    // According to Microsoft: "The data directory is the last part of the optional header"
    const IMAGE_DATA_DIRECTORY *dataDirectories = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(
        m_fileData.data() + dataDirectoryOffset
    );
    
    // Parse all 16 data directories as defined by Microsoft
    for (int i = 0; i < 16; i++) {
        const IMAGE_DATA_DIRECTORY &dir = dataDirectories[i];
        
        if (dir.VirtualAddress != 0 && dir.Size != 0) {
            switch (i) {
                case 0: // Export Directory
                    parseExportDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 1: // Import Directory
                    parseImportDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 2: // Resource Directory
                    parseResourceDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 3: // Exception Directory
                    parseExceptionDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 4: // Certificate Directory
                    parseCertificateDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 5: // Base Relocation Directory
                    parseBaseRelocationDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 6: // Debug Directory
                    parseDebugDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 7: // Architecture Directory
                    parseArchitectureDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 8: // Global Pointer Directory
                    parseGlobalPointerDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 9: // TLS Directory
                    parseTLSDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 10: // Load Configuration Directory
                    parseLoadConfigDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 11: // Bound Import Directory
                    parseBoundImportDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 12: // Import Address Table Directory
                    parseImportAddressTableDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 13: // Delay Import Directory
                    parseDelayImportDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 14: // COM+ Runtime Header Directory
                    parseCOMRuntimeDirectory(dir.VirtualAddress, dir.Size, dataModel);
                    break;
                    
                case 15: // Reserved Directory
                    // Reserved for future use
                    break;
            }
        }
    }
    
    return true;
}

bool PEDataDirectoryParser::parseExportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    const IMAGE_EXPORT_DIRECTORY *exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        m_fileData.data() + fileOffset
    );
    
    QStringList exports;
    QStringList exportDetails;
    
    // Parse function names
    if (exportDir->AddressOfNames != 0) {
        quint32 namesOffset = rvaToFileOffset(exportDir->AddressOfNames, dataModel.getSections());
        if (namesOffset != 0) {
            const quint32 *nameRVAs = reinterpret_cast<const quint32*>(m_fileData.data() + namesOffset);
            
            for (quint32 i = 0; i < exportDir->NumberOfNames; ++i) {
                QString functionName = readStringFromRVA(nameRVAs[i], dataModel.getSections());
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
            
            for (quint32 i = 0; i < exportDir->NumberOfFunctions; ++i) {
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

bool PEDataDirectoryParser::parseImportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList imports;
    QMap<QString, QList<QString>> importDetails;
    
    const IMAGE_IMPORT_DESCRIPTOR *importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        m_fileData.data() + fileOffset
    );
    
    int descriptorCount = 0;
    while (importDesc->Name != 0 && descriptorCount < 1000) { // Safety limit
        // Read DLL name from RVA
        QString dllName = readStringFromRVA(importDesc->Name, dataModel.getSections());
        if (!dllName.isEmpty()) {
            imports.append(dllName);
            
            // Parse thunk tables for function names
            QList<QString> functions;
            
            if (importDesc->OriginalFirstThunk != 0) {
                // Parse original thunk table (contains function names/ordinals)
                quint32 thunkOffset = rvaToFileOffset(importDesc->OriginalFirstThunk, dataModel.getSections());
                if (thunkOffset != 0) {
                    const quint32 *thunk = reinterpret_cast<const quint32*>(m_fileData.data() + thunkOffset);
                    
                    while (*thunk != 0) {
                        QString functionName;
                        if (*thunk & 0x80000000) {
                            // Import by ordinal
                            quint16 ordinal = static_cast<quint16>(*thunk & 0xFFFF);
                            functionName = LANG_PARAM("UI/ordinal_format", "value", QString::number(ordinal));
                        } else {
                            // Import by name
                            functionName = readStringFromRVA(*thunk + 2, dataModel.getSections()); // Skip 2-byte hint
                        }
                        
                        if (!functionName.isEmpty()) {
                            functions.append(functionName);
                        }
                        
                        thunk++;
                    }
                }
            }
            
            importDetails[dllName] = functions;
        }
        
        importDesc++;
        descriptorCount++;
    }
    
    dataModel.setImports(imports);
    dataModel.setImportDetails(importDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseResourceDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList resourceTypes;
    QMap<QString, QMap<QString, QString>> resources;
    
    const IMAGE_RESOURCE_DIRECTORY *resourceDir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(
        m_fileData.data() + fileOffset
    );
    
    quint32 totalEntries = resourceDir->NumberOfNamedEntries + resourceDir->NumberOfIdEntries;
    quint32 entryOffset = fileOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
    
    for (quint32 i = 0; i < totalEntries && i < MAX_RESOURCE_ENTRIES; ++i) {
        const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
            m_fileData.data() + entryOffset
        );
        
        QString resourceType = PEUtils::getResourceTypeName(entry->Name);
        resourceTypes.append(resourceType);
        
        // Parse the resource data
        if (entry->OffsetToData & 0x80000000) {
            // Named entry - Name contains offset to string
            if (entry->Name != 0) {
                quint32 nameOffset = fileOffset + (entry->Name & 0x7FFFFFFF);
                if (nameOffset + 2 <= m_fileData.size()) {
                    quint16 nameLength = *reinterpret_cast<const quint16*>(m_fileData.data() + nameOffset);
                    if (nameOffset + 2 + nameLength * 2 <= m_fileData.size()) {
                        const wchar_t* namePtr = reinterpret_cast<const wchar_t*>(m_fileData.data() + nameOffset + 2);
                        QString resourceName = QString::fromWCharArray(namePtr, nameLength);
                        resources[resourceType][resourceName] = LANG("UI/resource_named");
                    } else {
                        resources[resourceType][QString("Invalid Name")] = LANG("UI/resource_named");
                    }
                } else {
                    resources[resourceType][QString("Invalid Name")] = LANG("UI/resource_named");
                }
            } else {
                resources[resourceType][QString("Empty Name")] = LANG("UI/resource_named");
            }
        } else {
            // ID entry
            QString resourceId = QString::number(entry->Name);
            resources[resourceType][resourceId] = LANG("UI/resource_id");
        }
        
        entryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    }
    
    dataModel.setResourceTypes(resourceTypes);
    dataModel.setResources(resources);
    
    return true;
}

bool PEDataDirectoryParser::parseDebugDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList debugInfo;
    QMap<QString, QString> debugDetails;
    
    // Parse debug directory entries
    int entryCount = size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (int i = 0; i < entryCount && i < MAX_DEBUG_ENTRIES; i++) {
        quint32 entryOffset = fileOffset + (i * sizeof(IMAGE_DEBUG_DIRECTORY));
        if (entryOffset + sizeof(IMAGE_DEBUG_DIRECTORY) <= m_fileData.size()) {
            const IMAGE_DEBUG_DIRECTORY *debugDir = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
                m_fileData.data() + entryOffset
            );
            
            QString debugType = PEUtils::getDebugTypeName(debugDir->Type);
            QMap<QString, QString> debugParams;
            debugParams["size"] = QString::number(debugDir->SizeOfData);
            debugParams["rva"] = PEUtils::formatHex(debugDir->AddressOfRawData);
            debugParams["raw"] = PEUtils::formatHex(debugDir->PointerToRawData);
            QString debugDetailsStr = LANG_PARAMS("UI/debug_details_format", debugParams);
            
            debugInfo.append(debugType);
            debugDetails[debugType] = debugDetailsStr;
        }
    }
    
    dataModel.setDebugInfo(debugInfo);
    dataModel.setDebugDetails(debugDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseTLSDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    const IMAGE_TLS_DIRECTORY *tlsDir = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(
        m_fileData.data() + fileOffset
    );
    
    QStringList tlsInfo;
    QMap<QString, QString> tlsDetails;
    
    // Parse TLS directory structure
    QMap<QString, QString> tlsParams;
    tlsParams["rva"] = PEUtils::formatHex(tlsDir->AddressOfCallBacks);
    tlsParams["size"] = QString::number(tlsDir->SizeOfZeroFill);
    QString tlsData = LANG_PARAMS("UI/tls_details_format", tlsParams);
    
    tlsInfo.append(LANG("UI/data_dir_tls"));
    tlsDetails[LANG("UI/data_dir_tls")] = tlsData;
    
    dataModel.setTLSInfo(tlsInfo);
    dataModel.setTLSDetails(tlsDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseLoadConfigDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    const IMAGE_LOAD_CONFIG_DIRECTORY *loadConfigDir = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY*>(
        m_fileData.data() + fileOffset
    );
    
    QStringList loadConfigInfo;
    QMap<QString, QString> loadConfigDetails;
    
    // Parse Load Configuration directory structure
    QMap<QString, QString> configParams;
    configParams["size"] = QString::number(loadConfigDir->Size);
    configParams["time"] = PEUtils::formatHex(loadConfigDir->TimeDateStamp);
    configParams["version"] = QString::number(loadConfigDir->MajorVersion);
    QString configData = LANG_PARAMS("UI/load_config_details_format", configParams);
    
    loadConfigInfo.append(LANG("UI/data_dir_load_config"));
    loadConfigDetails[LANG("UI/data_dir_load_config")] = configData;
    
    dataModel.setLoadConfigInfo(loadConfigInfo);
    dataModel.setLoadConfigDetails(loadConfigDetails);
    
    return true;
}

quint32 PEDataDirectoryParser::rvaToFileOffset(quint32 rva, const QList<const IMAGE_SECTION_HEADER*> &sections)
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

QString PEDataDirectoryParser::readStringFromRVA(quint32 rva, const QList<const IMAGE_SECTION_HEADER*> &sections)
{
    if (rva == 0) return QString();
    
    quint32 fileOffset = rvaToFileOffset(rva, sections);
    if (fileOffset == 0) return QString();
    
    return QString::fromLatin1(m_fileData.data() + fileOffset);
}

// ============================================================================
// New Data Directory Parser Implementations
// ============================================================================

bool PEDataDirectoryParser::parseExceptionDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList exceptionInfo;
    QMap<QString, QString> exceptionDetails;
    
    // Parse exception directory (typically contains exception handling information)
    // For x64, this contains RUNTIME_FUNCTION structures
    QMap<QString, QString> exceptionParams;
    exceptionParams["rva"] = PEUtils::formatHex(rva);
    exceptionParams["size"] = QString::number(size);
    QString exceptionData = LANG_PARAMS("UI/exception_details_format", exceptionParams);
    
    exceptionInfo.append(LANG("UI/data_dir_exception"));
    exceptionDetails[LANG("UI/data_dir_exception")] = exceptionData;
    
    dataModel.setExceptionInfo(exceptionInfo);
    dataModel.setExceptionDetails(exceptionDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseCertificateDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList certificateInfo;
    QMap<QString, QString> certificateDetails;
    
    // Parse certificate directory (Authenticode signatures)
    if (fileOffset + sizeof(WIN_CERTIFICATE) <= m_fileData.size()) {
        const WIN_CERTIFICATE *cert = reinterpret_cast<const WIN_CERTIFICATE*>(
            m_fileData.data() + fileOffset
        );
        
        QString certData = QString("Type: %1, Version: %2, Size: %3 bytes")
                          .arg(PEUtils::formatHex(static_cast<quint32>(cert->wRevision)))
                          .arg(PEUtils::formatHex(static_cast<quint32>(cert->wCertificateType)))
                          .arg(cert->dwLength);
        
        certificateInfo.append(LANG("UI/data_dir_certificate"));
        certificateDetails[LANG("UI/data_dir_certificate")] = certData;
    } else {
        certificateInfo.append(LANG("UI/data_dir_certificate"));
        certificateDetails[LANG("UI/data_dir_certificate")] = QString("RVA: 0x%1, Size: %2 bytes").arg(PEUtils::formatHex(rva)).arg(size);
    }
    
    dataModel.setCertificateInfo(certificateInfo);
    dataModel.setCertificateDetails(certificateDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseBaseRelocationDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList relocationInfo;
    QMap<QString, QString> relocationDetails;
    
    // Parse base relocation directory
    const IMAGE_BASE_RELOCATION *relocDir = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
        m_fileData.data() + fileOffset
    );
    
    if (fileOffset + sizeof(IMAGE_BASE_RELOCATION) <= m_fileData.size()) {
        QString relocData = QString("Virtual Address: 0x%1, Size: %2 bytes")
                           .arg(PEUtils::formatHex(relocDir->VirtualAddress))
                           .arg(relocDir->SizeOfBlock);
        
        relocationInfo.append(LANG("UI/data_dir_base_relocation"));
        relocationDetails[LANG("UI/data_dir_base_relocation")] = relocData;
    } else {
        relocationInfo.append(LANG("UI/data_dir_base_relocation"));
        relocationDetails[LANG("UI/data_dir_base_relocation")] = QString("RVA: 0x%1, Size: %2 bytes").arg(PEUtils::formatHex(rva)).arg(size);
    }
    
    dataModel.setRelocationInfo(relocationInfo);
    dataModel.setRelocationDetails(relocationDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseArchitectureDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList architectureInfo;
    QMap<QString, QString> architectureDetails;
    
    // Parse architecture directory (typically contains architecture-specific data)
    QString archData = QString("RVA: 0x%1, Size: %2 bytes")
                      .arg(PEUtils::formatHex(rva))
                      .arg(size);
    
    architectureInfo.append(LANG("UI/data_dir_architecture"));
    architectureDetails[LANG("UI/data_dir_architecture")] = archData;
    
    dataModel.setArchitectureInfo(architectureInfo);
    dataModel.setArchitectureDetails(architectureDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseGlobalPointerDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList globalPtrInfo;
    QMap<QString, QString> globalPtrDetails;
    
    // Parse global pointer directory (typically contains global pointer value)
    QString gpData = QString("RVA: 0x%1, Size: %2 bytes")
                    .arg(PEUtils::formatHex(rva))
                    .arg(size);
    
    globalPtrInfo.append(LANG("UI/data_dir_global_pointer"));
    globalPtrDetails[LANG("UI/data_dir_global_pointer")] = gpData;
    
    dataModel.setGlobalPointerInfo(globalPtrInfo);
    dataModel.setGlobalPointerDetails(globalPtrDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseBoundImportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList boundImportInfo;
    QMap<QString, QString> boundImportDetails;
    
    // Parse bound import directory
    QString boundData = QString("RVA: 0x%1, Size: %2 bytes")
                       .arg(PEUtils::formatHex(rva))
                       .arg(size);
    
    boundImportInfo.append(LANG("UI/data_dir_bound_import"));
    boundImportDetails[LANG("UI/data_dir_bound_import")] = boundData;
    
    dataModel.setBoundImportInfo(boundImportInfo);
    dataModel.setBoundImportDetails(boundImportDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseImportAddressTableDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList iatInfo;
    QMap<QString, QString> iatDetails;
    
    // Parse Import Address Table directory
    QString iatData = QString("RVA: 0x%1, Size: %2 bytes")
                     .arg(PEUtils::formatHex(rva))
                     .arg(size);
    
    iatInfo.append(LANG("UI/data_dir_iat"));
    iatDetails[LANG("UI/data_dir_iat")] = iatData;
    
    dataModel.setIATInfo(iatInfo);
    dataModel.setIATDetails(iatDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseDelayImportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList delayImportInfo;
    QMap<QString, QString> delayImportDetails;
    
    // Parse delay import directory
    QString delayData = QString("RVA: 0x%1, Size: %2 bytes")
                       .arg(PEUtils::formatHex(rva))
                       .arg(size);
    
    delayImportInfo.append(LANG("UI/data_dir_delay_import"));
    delayImportDetails[LANG("UI/data_dir_delay_import")] = delayData;
    
    dataModel.setDelayImportInfo(delayImportInfo);
    dataModel.setDelayImportDetails(delayImportDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseCOMRuntimeDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList comRuntimeInfo;
    QMap<QString, QString> comRuntimeDetails;
    
    // Parse COM+ Runtime Header directory
    QString comData = QString("RVA: 0x%1, Size: %2 bytes")
                     .arg(PEUtils::formatHex(rva))
                     .arg(size);
    
    comRuntimeInfo.append(LANG("UI/data_dir_com_runtime"));
    comRuntimeDetails[LANG("UI/data_dir_com_runtime")] = comData;
    
    dataModel.setCOMRuntimeInfo(comRuntimeInfo);
    dataModel.setCOMRuntimeDetails(comRuntimeDetails);
    
    return true;
}
