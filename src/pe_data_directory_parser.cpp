#include "pe_data_directory_parser.h"
#include "pe_analysis.h"
#include "pe_system_dll_ordinal_resolver.h"
#include "pe_utils.h"
#include "language_manager.h"
#include <QDebug>
#include <QtGlobal>
#include <QHash>
#include <cstring>

namespace {
constexpr int MAX_EXPORT_FUNCTIONS_LIMIT = 10000;

QString dataDirectoryDisplayName(int index)
{
    static const char *const kNames[] = {
        "Export", "Import", "Resource", "Exception", "Security", "Base Relocation", "Debug",
        "Architecture", "Global Ptr", "TLS", "Load Config", "Bound Import", "IAT",
        "Delay Import", "CLR", "Reserved"
    };
    if (index >= 0 && index < 16) {
        return QString::fromLatin1(kNames[index]);
    }
    return QStringLiteral("Unknown");
}

void appendDetailMapFields(QVector<PEDataDirectoryField> &fields, const QMap<QString, QString> &details)
{
    for (auto it = details.constBegin(); it != details.constEnd(); ++it) {
        PEDataDirectoryField field;
        field.label = it.key();
        field.value = it.value();
        fields.append(field);
    }
}

void storeParsedDirectoryFields(PEDataModel &dataModel, int directoryIndex, const QMap<QString, QString> &details)
{
    QVector<PEDataDirectoryField> fields;
    appendDetailMapFields(fields, details);
    dataModel.setParsedDirectoryFields(directoryIndex, fields);
}

void storeResourceDirectoryFields(PEDataModel &dataModel,
                                  const QStringList &resourceTypes,
                                  const QMap<QString, QMap<QString, QString>> &resources)
{
    QVector<PEDataDirectoryField> fields;
    if (!resourceTypes.isEmpty()) {
        fields.append({QStringLiteral("Resource Types"), QString::number(resourceTypes.size())});
    }
    for (auto typeIt = resources.constBegin(); typeIt != resources.constEnd(); ++typeIt) {
        for (auto resIt = typeIt.value().constBegin(); resIt != typeIt.value().constEnd(); ++resIt) {
            fields.append({typeIt.key() + QStringLiteral(": ") + resIt.key(), resIt.value()});
        }
    }
    dataModel.setParsedDirectoryFields(2, fields);
}

void appendParsedDirectoryFields(QVector<PEDataDirectoryField> &fields,
                                 const QVector<PEDataDirectoryField> &parsed)
{
    fields += parsed;
}

void buildDataDirectoryRecords(const IMAGE_DATA_DIRECTORY *dataDirectories, PEDataModel &dataModel)
{
    QVector<PEDataDirectoryRecord> records;
    records.reserve(16);

    for (int i = 0; i < 16; ++i) {
        PEDataDirectoryRecord record;
        record.directoryIndex = i;
        record.name = dataDirectoryDisplayName(i);
        record.virtualAddress = dataDirectories[i].VirtualAddress;
        record.size = dataDirectories[i].Size;

        QVector<PEDataDirectoryField> fields;
        if (record.virtualAddress != 0 || record.size != 0) {
            PEDataDirectoryField rvaField;
            rvaField.label = (i == 4) ? QStringLiteral("File Offset") : QStringLiteral("RVA");
            rvaField.value = PEUtils::formatHex(record.virtualAddress);
            fields.append(rvaField);

            PEDataDirectoryField sizeField;
            sizeField.label = QStringLiteral("Size");
            sizeField.value = QString::number(record.size);
            fields.append(sizeField);
        }

        switch (i) {
        case 0:
            if (!dataModel.getExportFunctions().isEmpty()) {
                fields.append({QStringLiteral("Export Functions"),
                               QString::number(dataModel.getExportFunctions().size())});
            }
            break;
        case 1:
            if (!dataModel.getImports().isEmpty()) {
                fields.append({QStringLiteral("Import Modules"),
                               QString::number(dataModel.getImports().size())});
            }
            break;
        case 2:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(2));
            if (!dataModel.getResourceEntries().isEmpty()) {
                fields.append({QStringLiteral("Resource Entries"),
                               QString::number(dataModel.getResourceEntries().size())});
            }
            break;
        case 4:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(4));
            break;
        case 6:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(6));
            break;
        case 3:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(3));
            break;
        case 5:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(5));
            break;
        case 7:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(7));
            break;
        case 8:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(8));
            break;
        case 9:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(9));
            break;
        case 10:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(10));
            break;
        case 11:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(11));
            break;
        case 12:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(12));
            break;
        case 13:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(13));
            if (!dataModel.getDelayImports().isEmpty()) {
                fields.append({QStringLiteral("Delay Import Modules"),
                               QString::number(dataModel.getDelayImports().size())});
            }
            break;
        case 14:
            appendParsedDirectoryFields(fields, dataModel.parsedDirectoryFields(14));
            break;
        default:
            break;
        }

        record.fields = fields;
        records.append(record);
    }

    dataModel.setDataDirectoryRecords(records);
}
} // namespace

#ifndef IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL_FLAG32 0x80000000
#endif

#ifndef IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL
#endif

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
    if (dataDirectoryOffset + 16 * sizeof(IMAGE_DATA_DIRECTORY) > static_cast<quint32>(m_fileData.size())) {
        qWarning() << "Data directory table extends beyond file size";
        return false;
    }

    const IMAGE_DATA_DIRECTORY *dataDirectories = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(
        m_fileData.constData() + dataDirectoryOffset
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

    buildDataDirectoryRecords(dataDirectories, dataModel);
    
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
    QList<PEDataModel::ExportFunctionEntry> exportFunctions;

    if (exportDir->NumberOfFunctions == 0) {
        dataModel.setExportFunctions(exportFunctions);
        return true;
    }

    quint32 functionsOffset = rvaToFileOffset(exportDir->AddressOfFunctions, dataModel.getSections());
    if (functionsOffset == 0 || functionsOffset + exportDir->NumberOfFunctions * sizeof(quint32) > static_cast<quint32>(m_fileData.size())) {
        dataModel.setExportFunctions(exportFunctions);
        return true;
    }

    const quint32 *functionRVAs = reinterpret_cast<const quint32*>(m_fileData.constData() + functionsOffset);

    QHash<quint16, QString> nameByIndex;
    if (exportDir->AddressOfNames != 0 && exportDir->AddressOfNameOrdinals != 0) {
        quint32 namesOffset = rvaToFileOffset(exportDir->AddressOfNames, dataModel.getSections());
        quint32 ordinalsOffset = rvaToFileOffset(exportDir->AddressOfNameOrdinals, dataModel.getSections());
        if (namesOffset != 0 && ordinalsOffset != 0) {
            const quint32 *nameRVAs = reinterpret_cast<const quint32*>(m_fileData.constData() + namesOffset);
            const quint16 *nameOrdinals = reinterpret_cast<const quint16*>(m_fileData.constData() + ordinalsOffset);
            quint32 maxNames = qMin(exportDir->NumberOfNames, static_cast<quint32>(MAX_EXPORT_FUNCTIONS_LIMIT));
            for (quint32 i = 0; i < maxNames; ++i) {
                quint16 funcIndex = nameOrdinals[i];
                if (funcIndex >= exportDir->NumberOfFunctions) {
                    continue;
                }
                QString functionName = readStringFromRVA(nameRVAs[i], dataModel.getSections());
                if (!functionName.isEmpty()) {
                    nameByIndex.insert(funcIndex, functionName);
                }
            }
        }
    }

    quint32 maxFunctions = qMin(exportDir->NumberOfFunctions, static_cast<quint32>(MAX_EXPORT_FUNCTIONS_LIMIT));
    for (quint32 i = 0; i < maxFunctions; ++i) {
        PEDataModel::ExportFunctionEntry entry;
        entry.ordinal = static_cast<quint16>(exportDir->OrdinalBase + i);
        entry.rva = functionRVAs[i];
        entry.fileOffset = (entry.rva != 0) ? rvaToFileOffset(entry.rva, dataModel.getSections()) : 0;
        entry.name = nameByIndex.value(static_cast<quint16>(i));
        if (entry.name.isEmpty()) {
            entry.name = QStringLiteral("[ - ]");
        }
        exportFunctions.append(entry);
    }

    dataModel.setExportFunctions(exportFunctions);
    
    return true;
}

bool PEDataDirectoryParser::parseImportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList imports;
    QMap<QString, QList<PEDataModel::ImportFunctionEntry>> importDetails;

    const IMAGE_OPTIONAL_HEADER *optionalHeader = dataModel.getOptionalHeader();
    bool isPE64 = optionalHeader && optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    const IMAGE_IMPORT_DESCRIPTOR *importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        m_fileData.data() + fileOffset
    );
    
    int descriptorCount = 0;
    while (importDesc->Name != 0 && descriptorCount < 1000) { // Safety limit
        // Read DLL name from RVA
        QString dllName = readStringFromRVA(importDesc->Name, dataModel.getSections());
        if (!dllName.isEmpty()) {
            imports.append(dllName);
            
            QList<PEDataModel::ImportFunctionEntry> functions;

            quint32 nameTableRVA = (importDesc->OriginalFirstThunk != 0) ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
            quint32 thunkTableRVA = (importDesc->FirstThunk != 0) ? importDesc->FirstThunk : nameTableRVA;

            quint32 nameTableOffset = (nameTableRVA != 0) ? rvaToFileOffset(nameTableRVA, dataModel.getSections()) : 0;
            quint32 thunkTableOffset = (thunkTableRVA != 0) ? rvaToFileOffset(thunkTableRVA, dataModel.getSections()) : 0;

            if (nameTableOffset != 0 && nameTableOffset < static_cast<quint32>(m_fileData.size())) {
                const char *tablePtr = m_fileData.constData() + nameTableOffset;
                int entrySize = isPE64 ? static_cast<int>(sizeof(quint64)) : static_cast<int>(sizeof(quint32));

                for (int index = 0; ; ++index) {
                    qsizetype nameEntryOffset = index * entrySize;
                    qsizetype remaining = m_fileData.size() - static_cast<qsizetype>(nameTableOffset);
                    if (nameEntryOffset + entrySize > remaining) {
                        break;
                    }

                    quint64 rawValue = 0;
                    std::memcpy(&rawValue, tablePtr + nameEntryOffset, entrySize);
                    if (rawValue == 0) {
                        break;
                    }

                    quint32 thunkEntryRVA = thunkTableRVA + static_cast<quint32>(index * entrySize);
                    quint32 thunkEntryOffset = rvaToFileOffset(thunkEntryRVA, dataModel.getSections());

                    PEDataModel::ImportFunctionEntry entry;
                    entry.thunkRVA = thunkEntryRVA;
                    entry.thunkOffset = thunkEntryOffset;

                    bool importByOrdinal = (isPE64 && (rawValue & IMAGE_ORDINAL_FLAG64)) || (!isPE64 && (rawValue & IMAGE_ORDINAL_FLAG32));
                    if (importByOrdinal) {
                        quint16 ordinal = static_cast<quint16>(rawValue & 0xFFFF);
                        entry.importedByOrdinal = true;
                        entry.ordinal = ordinal;
                        const QString resolved = resolveImportOrdinalToName(dllName, ordinal, isPE64);
                        entry.name = resolved.isEmpty() ? QStringLiteral("[ - ]") : resolved;
                    } else {
                        quint32 importByNameRVA = static_cast<quint32>(rawValue & 0xFFFFFFFF);
                        QString functionName = readStringFromRVA(importByNameRVA + 2, dataModel.getSections());
                        if (functionName.isEmpty()) {
                            functionName = QStringLiteral("0x%1").arg(importByNameRVA, 0, 16).toUpper();
                        }
                        entry.name = functionName;
                    }

                    functions.append(entry);
                }
            }

            importDetails[dllName] = functions;
        }
        
        importDesc++;
        descriptorCount++;
    }
    
    dataModel.setImports(imports);
    dataModel.setImportFunctions(importDetails);
    
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
        
        QString resourceType = PEUtils::getResourceTypeName(entry->getName());
        resourceTypes.append(resourceType);
        
        // Check if this is a directory or data entry
        if (entry->getOffsetToData() & 0x80000000) {
            // Directory entry
            if (entry->getName() != 0) {
                quint32 nameOffset = fileOffset + (entry->getName() & 0x7FFFFFFF);
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
            // Data entry
            QString resourceId = QString::number(entry->getName());
            resources[resourceType][resourceId] = LANG("UI/resource_id");
        }
        
        entryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    }
    
    storeResourceDirectoryFields(dataModel, resourceTypes, resources);
    
    return true;
}

bool PEDataDirectoryParser::parseDebugDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;
    
    QStringList debugInfo;
    QMap<QString, QString> debugDetails;
    QVector<PEDebugDirectoryEntry> debugEntries;
    
    // Parse debug directory entries
    int entryCount = size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (int i = 0; i < entryCount && i < MAX_DEBUG_ENTRIES; i++) {
        quint32 entryOffset = fileOffset + (i * sizeof(IMAGE_DEBUG_DIRECTORY));
        if (entryOffset + sizeof(IMAGE_DEBUG_DIRECTORY) <= m_fileData.size()) {
            const IMAGE_DEBUG_DIRECTORY *debugDir = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
                m_fileData.data() + entryOffset
            );

            PEDebugDirectoryEntry entry;
            entry.type = debugDir->Type;
            entry.typeName = PEUtils::getDebugTypeName(debugDir->Type);
            entry.timeDateStamp = debugDir->TimeDateStamp;
            entry.majorVersion = debugDir->MajorVersion;
            entry.minorVersion = debugDir->MinorVersion;
            entry.sizeOfData = debugDir->SizeOfData;
            entry.addressOfRawData = debugDir->AddressOfRawData;
            entry.pointerToRawData = debugDir->PointerToRawData;
            debugEntries.append(entry);
            
            QString debugType = entry.typeName;
            QMap<QString, QString> debugParams;
            debugParams["size"] = QString::number(debugDir->SizeOfData);
            debugParams["rva"] = PEUtils::formatHex(debugDir->AddressOfRawData);
            debugParams["raw"] = PEUtils::formatHex(debugDir->PointerToRawData);
            QString debugDetailsStr = LANG_PARAMS("UI/debug_details_format", debugParams);

            if (debugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW && debugDir->SizeOfData > 0) {
                quint32 cvFileOffset = debugDir->PointerToRawData;
                if (cvFileOffset == 0 && debugDir->AddressOfRawData != 0) {
                    cvFileOffset = rvaToFileOffset(debugDir->AddressOfRawData, dataModel.getSections());
                }
                if (cvFileOffset == 0) {
                    continue;
                }
                const PEPdbInfo pdb = PEAnalysis::parseCodeViewDebugData(
                    m_fileData, cvFileOffset, debugDir->SizeOfData);
                if (pdb.present) {
                    PEPdbInfo merged = pdb;
                    merged.codeViewFileOffset = cvFileOffset;
                    merged.codeViewSize = PEAnalysis::codeViewRecordByteSize(
                        m_fileData, cvFileOffset, debugDir->SizeOfData);
                    if (merged.codeViewSize == 0) {
                        merged.codeViewSize = debugDir->SizeOfData;
                    }
                    PEPdbInfo existing = dataModel.getPdbInfo();
                    const bool replace = !existing.present || existing.path.isEmpty()
                                         || (merged.codeViewFileOffset > 0
                                             && existing.codeViewFileOffset == 0);
                    if (replace) {
                        dataModel.setPdbInfo(merged);
                    }
                    QString pdbExtra = QStringLiteral("%1 | %2 | age %3")
                                           .arg(pdb.format, pdb.path, QString::number(pdb.age));
                    if (!pdb.guid.isEmpty()) {
                        pdbExtra += QStringLiteral(" | %1").arg(pdb.guid);
                    }
                    debugDetailsStr += QStringLiteral("\n") + pdbExtra;
                }
            }
            
            debugInfo.append(debugType);
            debugDetails[debugType] = debugDetailsStr;
        }
    }
    
    storeParsedDirectoryFields(dataModel, 6, debugDetails);
    dataModel.setDebugDirectoryEntries(debugEntries);
    
    return true;
}

bool PEDataDirectoryParser::parseTLSDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;

    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    const bool pe32Plus = opt && opt->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC;

    QStringList tlsInfo;
    QMap<QString, QString> tlsDetails;
    QMap<QString, QString> tlsParams;
    PETlsDirectoryInfo tlsInfoStruct;
    tlsInfoStruct.present = true;

    if (pe32Plus) {
        if (fileOffset + sizeof(IMAGE_TLS_DIRECTORY64) > static_cast<quint32>(m_fileData.size())) {
            return false;
        }
        const auto *tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64 *>(m_fileData.constData() + fileOffset);
        tlsInfoStruct.startAddressOfRawData = tls->StartAddressOfRawData;
        tlsInfoStruct.endAddressOfRawData = tls->EndAddressOfRawData;
        tlsInfoStruct.addressOfIndex = tls->AddressOfIndex;
        tlsInfoStruct.addressOfCallbacks = tls->AddressOfCallBacks;
        tlsInfoStruct.sizeOfZeroFill = tls->SizeOfZeroFill;
        tlsInfoStruct.characteristics = tls->Characteristics;
        tlsParams[QStringLiteral("rva")] = PEUtils::formatHex(static_cast<quint64>(tls->AddressOfCallBacks));
        tlsParams[QStringLiteral("size")] = QString::number(tls->SizeOfZeroFill);
        tlsParams[QStringLiteral("start")] = PEUtils::formatHex(static_cast<quint64>(tls->StartAddressOfRawData));
        if (tls->AddressOfCallBacks != 0) {
            tlsInfoStruct.callbacksPresent = true;
            dataModel.setTlsCallbacksPresent(true);
        }
    } else {
        if (fileOffset + sizeof(IMAGE_TLS_DIRECTORY32) > static_cast<quint32>(m_fileData.size())) {
            return false;
        }
        const auto *tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY32 *>(m_fileData.constData() + fileOffset);
        tlsInfoStruct.startAddressOfRawData = tls->StartAddressOfRawData;
        tlsInfoStruct.endAddressOfRawData = tls->EndAddressOfRawData;
        tlsInfoStruct.addressOfIndex = tls->AddressOfIndex;
        tlsInfoStruct.addressOfCallbacks = tls->AddressOfCallBacks;
        tlsInfoStruct.sizeOfZeroFill = tls->SizeOfZeroFill;
        tlsInfoStruct.characteristics = tls->Characteristics;
        tlsParams[QStringLiteral("rva")] = PEUtils::formatHex(tls->AddressOfCallBacks);
        tlsParams[QStringLiteral("size")] = QString::number(tls->SizeOfZeroFill);
        tlsParams[QStringLiteral("start")] = PEUtils::formatHex(tls->StartAddressOfRawData);
        if (tls->AddressOfCallBacks != 0) {
            tlsInfoStruct.callbacksPresent = true;
            dataModel.setTlsCallbacksPresent(true);
        }
    }

    QString tlsData = LANG_PARAMS("UI/tls_details_format", tlsParams);
    tlsInfo.append(LANG("UI/data_dir_tls"));
    tlsDetails[LANG("UI/data_dir_tls")] = tlsData;

    storeParsedDirectoryFields(dataModel, 9, tlsDetails);
    dataModel.setTlsDirectoryInfo(tlsInfoStruct);

    return true;
}

bool PEDataDirectoryParser::parseLoadConfigDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;
    
    quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) return false;

    if (fileOffset + 4 > static_cast<quint32>(m_fileData.size())) {
        return false;
    }

    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    const bool pe32Plus = opt && opt->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC;

    QStringList loadConfigInfo;
    QMap<QString, QString> loadConfigDetails;
    QMap<QString, QString> configParams;
    PELoadConfigDirectoryInfo loadConfigStruct;
    loadConfigStruct.present = true;

    if (pe32Plus) {
        if (fileOffset + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) > static_cast<quint32>(m_fileData.size())) {
            return false;
        }
        const auto *loadConfigDir =
            reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY64 *>(m_fileData.constData() + fileOffset);
        loadConfigStruct.size = loadConfigDir->Size;
        loadConfigStruct.timeDateStamp = loadConfigDir->TimeDateStamp;
        loadConfigStruct.majorVersion = loadConfigDir->MajorVersion;
        loadConfigStruct.minorVersion = loadConfigDir->MinorVersion;
        configParams[QStringLiteral("size")] = QString::number(loadConfigDir->Size);
        configParams[QStringLiteral("time")] = PEUtils::formatHex(loadConfigDir->TimeDateStamp);
        configParams[QStringLiteral("version")] =
            QStringLiteral("%1.%2").arg(loadConfigDir->MajorVersion).arg(loadConfigDir->MinorVersion);
    } else {
        if (fileOffset + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32) > static_cast<quint32>(m_fileData.size())) {
            return false;
        }
        const auto *loadConfigDir =
            reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY32 *>(m_fileData.constData() + fileOffset);
        loadConfigStruct.size = loadConfigDir->Size;
        loadConfigStruct.timeDateStamp = loadConfigDir->TimeDateStamp;
        loadConfigStruct.majorVersion = loadConfigDir->MajorVersion;
        loadConfigStruct.minorVersion = loadConfigDir->MinorVersion;
        configParams[QStringLiteral("size")] = QString::number(loadConfigDir->Size);
        configParams[QStringLiteral("time")] = PEUtils::formatHex(loadConfigDir->TimeDateStamp);
        configParams[QStringLiteral("version")] =
            QStringLiteral("%1.%2").arg(loadConfigDir->MajorVersion).arg(loadConfigDir->MinorVersion);
    }

    QString configData = LANG_PARAMS("UI/load_config_details_format", configParams);
    loadConfigInfo.append(LANG("UI/data_dir_load_config"));
    loadConfigDetails[LANG("UI/data_dir_load_config")] = configData;

    storeParsedDirectoryFields(dataModel, 10, loadConfigDetails);
    dataModel.setLoadConfigDirectoryInfo(loadConfigStruct);

    return true;
}

quint32 PEDataDirectoryParser::rvaToFileOffset(quint32 rva, const QList<const IMAGE_SECTION_HEADER*> &sections)
{
    if (sections.isEmpty()) return 0;
    
    // Find the section that contains this RVA
    for (const IMAGE_SECTION_HEADER *section : sections) {
        quint32 sectionStart = section->VirtualAddress;
        quint32 sectionSize = qMax(section->getVirtualSize(), section->SizeOfRawData);
        quint32 sectionEnd = sectionStart + sectionSize;
        
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
    if (fileOffset == 0 || fileOffset >= static_cast<quint32>(m_fileData.size())) {
        return QString();
    }

    QByteArray buffer;
    buffer.reserve(256);

    const int maxLength = 512; // Safety cap for malformed data
    for (int i = 0; i < maxLength && (fileOffset + static_cast<quint32>(i)) < static_cast<quint32>(m_fileData.size()); ++i) {
        qsizetype index = static_cast<qsizetype>(fileOffset) + i;
        char ch = m_fileData.at(index);
        if (ch == '\0') {
            break;
        }

        unsigned char uch = static_cast<unsigned char>(ch);
        if (uch < 0x20 || uch > 0x7E) {
            // Stop on non-printable ASCII once we have captured some characters
            if (!buffer.isEmpty()) {
                break;
            }
            // No printable characters encountered yet – abort
            return QString();
        }

        buffer.append(ch);
    }

    return QString::fromLatin1(buffer);
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
    
    storeParsedDirectoryFields(dataModel, 3, exceptionDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseCertificateDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) return true;

    // PE spec: IMAGE_DIRECTORY_ENTRY_SECURITY.VirtualAddress is a raw file offset to the first
    // WIN_CERTIFICATE, NOT an RVA. Do not pass this through rvaToFileOffset().
    const quint32 fileOffset = rva;
    
    QStringList certificateInfo;
    QMap<QString, QString> certificateDetails;
    
    // Parse certificate directory (Authenticode signatures)
    if (fileOffset + sizeof(WIN_CERTIFICATE) <= m_fileData.size()) {
        const WIN_CERTIFICATE *cert = reinterpret_cast<const WIN_CERTIFICATE*>(
            m_fileData.data() + fileOffset
        );
        
        QString certData = QStringLiteral("Revision: %1, CertificateType: %2, Length: %3 bytes")
                          .arg(PEUtils::formatHex(static_cast<quint32>(cert->wRevision)))
                          .arg(PEUtils::formatHex(static_cast<quint32>(cert->wCertificateType)))
                          .arg(cert->dwLength);
        
        certificateInfo.append(LANG("UI/data_dir_certificate"));
        certificateDetails[LANG("UI/data_dir_certificate")] = certData;
    } else {
        certificateInfo.append(LANG("UI/data_dir_certificate"));
        certificateDetails[LANG("UI/data_dir_certificate")] =
            QStringLiteral("File offset: 0x%1, Size: %2 bytes (security directory uses file pointers, not RVAs)")
                .arg(PEUtils::formatHex(rva))
                .arg(size);
    }
    
    storeParsedDirectoryFields(dataModel, 4, certificateDetails);
    
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
    
    storeParsedDirectoryFields(dataModel, 5, relocationDetails);
    
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
    
    storeParsedDirectoryFields(dataModel, 7, architectureDetails);
    
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
    
    storeParsedDirectoryFields(dataModel, 8, globalPtrDetails);
    
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
    
    storeParsedDirectoryFields(dataModel, 11, boundImportDetails);
    
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
    
    storeParsedDirectoryFields(dataModel, 12, iatDetails);
    
    return true;
}

bool PEDataDirectoryParser::parseDelayImportDirectory(quint32 rva, quint32 size, PEDataModel &dataModel)
{
    if (rva == 0 || size == 0) {
        return true;
    }

    const quint32 fileOffset = rvaToFileOffset(rva, dataModel.getSections());
    if (fileOffset == 0) {
        return false;
    }

    QStringList delayImports;
    QMap<QString, QList<PEDataModel::ImportFunctionEntry>> delayImportDetails;

    const IMAGE_OPTIONAL_HEADER *optionalHeader = dataModel.getOptionalHeader();
    const bool isPE64 = optionalHeader && optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    const auto *delayDesc = reinterpret_cast<const IMAGE_DELAYLOAD_DESCRIPTOR *>(m_fileData.constData() + fileOffset);

    int descriptorCount = 0;
    while (delayDesc->DllNameRVA != 0 && descriptorCount < 1000) {
        const QString dllName = readStringFromRVA(delayDesc->DllNameRVA, dataModel.getSections());
        if (!dllName.isEmpty()) {
            delayImports.append(dllName);

            QList<PEDataModel::ImportFunctionEntry> functions;
            const quint32 nameTableRVA = delayDesc->ImportNameTableRVA;
            const quint32 thunkTableRVA = delayDesc->ImportAddressTableRVA;
            const quint32 nameTableOffset =
                nameTableRVA != 0 ? rvaToFileOffset(nameTableRVA, dataModel.getSections()) : 0;

            if (nameTableOffset != 0 && nameTableOffset < static_cast<quint32>(m_fileData.size())) {
                const char *tablePtr = m_fileData.constData() + nameTableOffset;
                const int entrySize =
                    isPE64 ? static_cast<int>(sizeof(quint64)) : static_cast<int>(sizeof(quint32));

                for (int index = 0;; ++index) {
                    const qsizetype nameEntryOffset = index * entrySize;
                    const qsizetype remaining = m_fileData.size() - static_cast<qsizetype>(nameTableOffset);
                    if (nameEntryOffset + entrySize > remaining) {
                        break;
                    }

                    quint64 rawValue = 0;
                    std::memcpy(&rawValue, tablePtr + nameEntryOffset, entrySize);
                    if (rawValue == 0) {
                        break;
                    }

                    const quint32 thunkEntryRVA = thunkTableRVA + static_cast<quint32>(index * entrySize);
                    const quint32 thunkEntryOffset = rvaToFileOffset(thunkEntryRVA, dataModel.getSections());

                    PEDataModel::ImportFunctionEntry entry;
                    entry.thunkRVA = thunkEntryRVA;
                    entry.thunkOffset = thunkEntryOffset;

                    const bool importByOrdinal =
                        (isPE64 && (rawValue & IMAGE_ORDINAL_FLAG64))
                        || (!isPE64 && (rawValue & IMAGE_ORDINAL_FLAG32));
                    if (importByOrdinal) {
                        const quint16 ordinal = static_cast<quint16>(rawValue & 0xFFFF);
                        entry.importedByOrdinal = true;
                        entry.ordinal = ordinal;
                        const QString resolved = resolveImportOrdinalToName(dllName, ordinal, isPE64);
                        entry.name = resolved.isEmpty() ? QStringLiteral("[ - ]") : resolved;
                    } else {
                        const quint32 importByNameRVA = static_cast<quint32>(rawValue & 0xFFFFFFFF);
                        QString functionName = readStringFromRVA(importByNameRVA + 2, dataModel.getSections());
                        if (functionName.isEmpty()) {
                            functionName =
                                QStringLiteral("0x%1").arg(importByNameRVA, 0, 16).toUpper();
                        }
                        entry.name = functionName;
                    }

                    functions.append(entry);
                }
            }

            delayImportDetails[dllName] = functions;
        }

        ++delayDesc;
        ++descriptorCount;
    }

    dataModel.setDelayImports(delayImports);
    dataModel.setDelayImportFunctions(delayImportDetails);

    QStringList delayImportInfo;
    QMap<QString, QString> delayImportMeta;
    delayImportInfo.append(LANG("UI/data_dir_delay_import"));
    delayImportMeta[LANG("UI/data_dir_delay_import")] =
        QStringLiteral("RVA: 0x%1, Size: %2 bytes, Modules: %3")
            .arg(PEUtils::formatHex(rva), QString::number(size), QString::number(delayImports.size()));
    storeParsedDirectoryFields(dataModel, 13, delayImportMeta);

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
    
    storeParsedDirectoryFields(dataModel, 14, comRuntimeDetails);
    
    return true;
}
