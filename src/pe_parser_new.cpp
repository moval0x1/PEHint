#include "pe_parser_new.h"
#include "pe_utils.h"
#include "language_manager.h"
#include <QDebug>
#include <QFileInfo>
#include <QTreeWidgetItem>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QCoreApplication>
#include <QDir>
#include <QDateTime>
#include <QtGlobal>

PEParserNew::PEParserNew(QObject *parent)
    : QObject(parent)
    , m_isValid(false)
    , m_isParsing(false)
    , m_dataDirectoryParser(m_fileData)
{
}

PEParserNew::~PEParserNew()
{
    clear();
}

bool PEParserNew::loadFile(const QString &filePath)
{
    clear();
    
    m_file.setFileName(filePath);
    if (!m_file.open(QIODevice::ReadOnly)) {
        emit errorOccurred(LANG_PARAM("UI/error_file_open_generic", "filepath", filePath));
        return false;
    }
    
    m_dataModel.setFilePath(filePath);
    m_dataModel.setFileSize(m_file.size());
    
    // For large files, use streaming approach to avoid memory issues
    if (m_file.size() > LARGE_FILE_THRESHOLD) {
        emit parsingProgress(5, LANG("UI/progress_large_file_detected"));
        bool success = loadLargeFileStreaming();
        if (success) {
            m_dataModel.setValid(true);
            m_isValid = true;
            emit parsingProgress(100, LANG("UI/progress_large_file_complete"));
            emit parsingComplete(true);
        }
        return success;
    }
    
    // For small files, load everything (current approach)
    emit parsingProgress(5, LANG("UI/progress_file_loaded"));
    m_fileData = m_file.readAll();
    m_file.close();
    
    // Parse DOS header
    if (!parseDOSHeader()) {
        return false;
    }
    
    emit parsingProgress(15, LANG("UI/progress_dos_header"));
    
    // Parse PE headers
    if (!parsePEHeaders()) {
        return false;
    }
    
    emit parsingProgress(25, LANG("UI/progress_pe_headers"));
    
    // Parse sections
    if (!parseSections()) {
        return false;
    }
    
    emit parsingProgress(35, LANG("UI/progress_sections"));
    
    // Parse data directories (NEW: Microsoft PE Format compliant)
    if (!parseDataDirectories()) {
        return false;
    }
    
    emit parsingProgress(50, LANG("UI/progress_data_directories"));
    
    m_dataModel.setValid(true);
    m_isValid = true;
    
    emit parsingProgress(100, LANG("UI/progress_complete"));
    emit parsingComplete(true);
    return true;
}

void PEParserNew::loadFileAsync(const QString &filePath)
{
    if (m_isParsing) {
        m_parsingFuture.waitForFinished();
    }
    
    m_isParsing = true;
    emit parsingProgress(0, LANG("UI/progress_async_start"));
    
    m_parsingFuture = QtConcurrent::run([this, filePath]() {
        QMutexLocker locker(&m_parsingMutex);
        
        emit parsingProgress(1, LANG("UI/progress_async_loading"));
        
        bool success = loadFile(filePath);
        m_isParsing = false;
        
        QMetaObject::invokeMethod(this, [this, success]() {
            if (success) {
                emit parsingProgress(100, LANG("UI/progress_async_complete"));
            } else {
                emit parsingProgress(100, LANG("UI/progress_async_failed"));
            }
            emit parsingComplete(success);
        }, Qt::QueuedConnection);
    });
}

void PEParserNew::clear()
{
    m_file.close();
    m_fileData.clear();
    m_dataModel.clear();
    m_optionalHeaderBuffer.clear();
    m_cachedSections.clear();
    m_cachedDosHeader = IMAGE_DOS_HEADER{};
    m_cachedFileHeader = IMAGE_FILE_HEADER{};
    m_isValid = false;
    m_isParsing = false;
}

bool PEParserNew::isValid() const
{
    return m_isValid;
}

bool PEParserNew::isParsing() const
{
    return m_isParsing;
}

QString PEParserNew::getFilePath() const
{
    return m_dataModel.getFilePath();
}



const PEDataModel& PEParserNew::getDataModel() const
{
    return m_dataModel;
}

void PEParserNew::cancelParsing()
{
    if (m_isParsing) {
        m_parsingFuture.waitForFinished();
        m_isParsing = false;
    }
}

void PEParserNew::onAsyncParsingComplete()
{
    // This slot is called when async parsing completes
}

// Core parsing methods (Microsoft PE Format compliant)
bool PEParserNew::parseDOSHeader()
{
    if (m_fileData.size() < sizeof(IMAGE_DOS_HEADER)) {
        emit errorOccurred(LANG("UI/error_file_too_small"));
        return false;
    }
    
    const IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_fileData.data());
    
    // Validate DOS magic number
    if (!PEUtils::isValidDOSMagic(dosHeader->e_magic)) {
        emit errorOccurred(LANG("UI/error_invalid_dos"));
        return false;
    }
    
    // Check if PE header exists
    if (dosHeader->e_lfanew >= m_fileData.size() || 
        dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER)) {
        emit errorOccurred(LANG("UI/error_invalid_pe_offset"));
        return false;
    }
    
    m_cachedDosHeader = *dosHeader;
    m_dataModel.setDOSHeader(&m_cachedDosHeader);
    return true;
}

bool PEParserNew::parsePEHeaders()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    if (!dosHeader) return false;
    
    quint32 peOffset = dosHeader->e_lfanew;
    
    // Parse PE signature
    if (peOffset + sizeof(quint32) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_pe_signature_beyond"));
        return false;
    }
    
    quint32 peSignature = *reinterpret_cast<const quint32*>(m_fileData.data() + peOffset);
    if (!PEUtils::isValidPESignature(peSignature)) {
        emit errorOccurred(LANG("UI/error_invalid_pe_signature"));
        return false;
    }
    
    // Parse file header (immediately after the PE signature)
    quint32 fileHeaderOffset = peOffset + sizeof(quint32);
    if (fileHeaderOffset + sizeof(IMAGE_FILE_HEADER) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_pe_header_beyond"));
        return false;
    }
    
    const IMAGE_FILE_HEADER *fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_fileData.data() + fileHeaderOffset
    );
    m_cachedFileHeader = *fileHeader;
    m_dataModel.setFileHeader(&m_cachedFileHeader);
    
    // Parse optional header
    quint32 optionalHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeaderOffset + fileHeader->SizeOfOptionalHeader > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_optional_header_beyond"));
        return false;
    }
    
    const IMAGE_OPTIONAL_HEADER *optionalHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER*>(
        m_fileData.data() + optionalHeaderOffset
    );
    
    if (!PEUtils::isValidOptionalHeaderMagic(optionalHeader->Magic)) {
        qWarning() << "Unexpected optional header magic" << QString::number(optionalHeader->Magic, 16)
                   << "at offset" << QString("0x%1").arg(optionalHeaderOffset, 0, 16);
        emit errorOccurred(LANG("UI/error_invalid_optional_magic"));
        return false;
    }
    
    m_dataModel.setOptionalHeader(optionalHeader);
    return true;
}

bool PEParserNew::parseSections()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return false;
    }
    
    // Calculate section table offset (PE signature + file header + optional header)
    quint32 sectionTableOffset = dosHeader->e_lfanew
                               + sizeof(quint32) // PE signature
                               + sizeof(IMAGE_FILE_HEADER)
                               + fileHeader->SizeOfOptionalHeader;
    
    if (sectionTableOffset + (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_section_table_beyond"));
        return false;
    }
    
    // Parse each section header from the in-memory buffer
    for (quint16 i = 0; i < fileHeader->NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER *section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            m_fileData.constData() + sectionTableOffset + (i * sizeof(IMAGE_SECTION_HEADER))
        );
        m_dataModel.addSection(section);
    }
    
    return true;
}

bool PEParserNew::parseDataDirectories()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return false;
    }
    
    // Calculate the start of the data directories inside the optional header
    quint32 optionalHeaderOffset = dosHeader->e_lfanew
                                + sizeof(quint32) // PE signature
                                + sizeof(IMAGE_FILE_HEADER);
    
    quint16 magic = optionalHeader->Magic;
    quint32 numberOfRvaAndSizesOffset = (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 92 : 108; // 0x5C / 0x6C
    quint32 dataDirectoryOffset = optionalHeaderOffset + numberOfRvaAndSizesOffset + sizeof(quint32);
    
    // Use the specialized data directory parser
    return m_dataDirectoryParser.parseDataDirectories(optionalHeader, dataDirectoryOffset, m_dataModel);
}

quint32 PEParserNew::rvaToFileOffset(quint32 rva)
{
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_dataModel.getSections();
    
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

bool PEParserNew::isLargeFile() const
{
    return m_dataModel.getFileSize() > LARGE_FILE_THRESHOLD;
}

bool PEParserNew::isVeryLargeFile() const
{
    return m_dataModel.getFileSize() > VERY_LARGE_FILE_THRESHOLD;
}

bool PEParserNew::loadLargeFileStreaming()
{
    // For large files, we only read essential headers and structure information
    // This avoids loading the entire file into memory
    
    emit parsingProgress(10, LANG("UI/progress_reading_dos_header"));
    
    // Read DOS header (64 bytes)
    IMAGE_DOS_HEADER dosHeader;
    if (m_file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER)) != sizeof(IMAGE_DOS_HEADER)) {
        emit errorOccurred(LANG("UI/error_reading_dos_header"));
        return false;
    }
    
    // Validate DOS header
    if (!PEUtils::isValidDOSHeader(dosHeader)) {
        emit errorOccurred(LANG("UI/error_invalid_dos_header"));
        return false;
    }
    
    m_cachedDosHeader = dosHeader;
    m_dataModel.setDOSHeader(&m_cachedDosHeader);
    
    emit parsingProgress(20, LANG("UI/progress_reading_pe_headers"));
    
    // Read PE signature and file header
    if (!m_file.seek(dosHeader.e_lfanew)) {
        emit errorOccurred(LANG("UI/error_seeking_pe_header"));
        return false;
    }
    
    // Read PE signature
    quint32 peSignature;
    if (m_file.read(reinterpret_cast<char*>(&peSignature), sizeof(quint32)) != sizeof(quint32)) {
        emit errorOccurred(LANG("UI/error_reading_pe_signature"));
        return false;
    }
    
    if (!PEUtils::isValidPESignature(peSignature)) {
        emit errorOccurred(LANG("UI/error_invalid_pe_signature"));
        return false;
    }
    
    // Read file header
    IMAGE_FILE_HEADER fileHeader;
    if (m_file.read(reinterpret_cast<char*>(&fileHeader), sizeof(IMAGE_FILE_HEADER)) != sizeof(IMAGE_FILE_HEADER)) {
        emit errorOccurred(LANG("UI/error_reading_file_header"));
        return false;
    }
    
    m_cachedFileHeader = fileHeader;
    m_dataModel.setFileHeader(&m_cachedFileHeader);
    
    emit parsingProgress(30, LANG("UI/progress_reading_optional_header"));
    
    // Read optional header - must read exactly SizeOfOptionalHeader bytes
    // Allocate buffer for the optional header (max size is 224 bytes for PE32+)
    QByteArray optionalHeaderBuffer(fileHeader.SizeOfOptionalHeader, 0);
    if (m_file.read(optionalHeaderBuffer.data(), fileHeader.SizeOfOptionalHeader) != fileHeader.SizeOfOptionalHeader) {
        emit errorOccurred(LANG("UI/error_reading_optional_header"));
        return false;
    }
    
    // Check magic number to determine if it's PE32 or PE32+
    quint16 magic = *reinterpret_cast<const quint16*>(optionalHeaderBuffer.data());
    if (!PEUtils::isValidOptionalHeaderMagic(magic)) {
        emit errorOccurred(LANG("UI/error_invalid_optional_magic"));
        return false;
    }
    
    // Store the optional header buffer in the data model
    // We need to keep the buffer alive, so we'll store it in m_fileData
    // For now, we'll create a properly sized structure
    if (magic == 0x10b) {
        // PE32 (32-bit)
        if (optionalHeaderBuffer.size() < static_cast<int>(sizeof(IMAGE_OPTIONAL_HEADER32))) {
            emit errorOccurred(LANG("UI/error_optional_header_too_small"));
            return false;
        }
        const IMAGE_OPTIONAL_HEADER32 *optHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalHeaderBuffer.data());
        m_dataModel.setOptionalHeader(reinterpret_cast<const IMAGE_OPTIONAL_HEADER*>(optHeader));
    } else if (magic == 0x20b) {
        // PE32+ (64-bit)
        if (optionalHeaderBuffer.size() < static_cast<int>(sizeof(IMAGE_OPTIONAL_HEADER64))) {
            emit errorOccurred(LANG("UI/error_optional_header_too_small"));
            return false;
        }
        // For 64-bit, we need to handle it differently, but for now use the same structure
        // The DataDirectory array is at the same relative offset in both
        const IMAGE_OPTIONAL_HEADER64 *optHeader64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalHeaderBuffer.data());
        // Store as 32-bit structure but we'll need to adjust access
        m_dataModel.setOptionalHeader(reinterpret_cast<const IMAGE_OPTIONAL_HEADER*>(optHeader64));
    }
    
    // Store the buffer so it doesn't go out of scope
    m_optionalHeaderBuffer = optionalHeaderBuffer;
    
    // Load at least the headers into m_fileData so we can access Data Directories
    // Calculate the size needed: DOS header + PE headers + Optional header + Section headers
    quint32 headersSize = dosHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader + 
                          (fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if (!m_file.seek(0)) {
        emit errorOccurred(LANG("UI/error_seeking_file_start"));
        return false;
    }
    m_fileData = m_file.read(headersSize); // Read only headers, not entire file
    
    emit parsingProgress(40, LANG("UI/progress_reading_sections"));
    
    // Read section table (typically < 1KB even for large files)
    quint32 sectionTableOffset = dosHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
    if (!m_file.seek(sectionTableOffset)) {
        emit errorOccurred(LANG("UI/error_seeking_section_table"));
        return false;
    }
    
    // Read each section header
    m_cachedSections.clear();
    m_cachedSections.reserve(fileHeader.NumberOfSections);
    
    for (quint16 i = 0; i < fileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        if (m_file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER)) != sizeof(IMAGE_SECTION_HEADER)) {
            emit errorOccurred(LANG("UI/error_reading_section_header"));
            return false;
        }
        m_cachedSections.append(sectionHeader);
        m_dataModel.addSection(&m_cachedSections.last());
    }
    
    emit parsingProgress(60, LANG("UI/progress_analyzing_structure"));
    
    // For large files, we skip detailed data directory parsing
    // as it would require reading large portions of the file
    emit parsingProgress(80, LANG("UI/progress_large_file_optimization"));
    
    // Don't close the file yet - we might need it for specific field access
    // m_file.close(); // Keep file open for streaming access
    
    emit parsingProgress(90, LANG("UI/progress_large_file_complete"));
    
    return true;
}

// Field explanation and offset methods (for UI compatibility)
QString PEParserNew::getFieldExplanation(const QString &fieldName)
{
    // Get current language from language manager
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();
    
    // Load explanations from the language-specific JSON file
    QString explanationsPath;
    
    if (currentLanguage == "pt") {
        explanationsPath = findConfigFile("explanations_pt.json");
    } else {
        explanationsPath = findConfigFile("explanations.json");
    }
    
    QFile explanationsFile(explanationsPath);
    if (explanationsFile.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(explanationsFile.readAll());
        QJsonObject root = doc.object();
        
        // Search for the field in the explanations
        // The structure has field names under language keys ("en", "pt")
        if (root.contains(currentLanguage)) {
            QJsonObject languageObj = root[currentLanguage].toObject();
            
            // Handle section names dynamically (e.g., "Section 1: .text", "Section 2: .data")
            if (fieldName.startsWith("Section ")) {
                // Extract section name if possible
                QString sectionInfo = fieldName;
                QString sectionName = "";
                if (fieldName.contains(": ")) {
                    sectionName = fieldName.split(": ").last();
                }
                
                // Try to get generic "Section" explanation
                if (languageObj.contains("Section")) {
                    QJsonObject sectionObj = languageObj["Section"].toObject();
                    QString description = sectionObj["description"].toString();
                    QString purpose = sectionObj["purpose"].toString();
                    QString note = sectionObj["note"].toString();
                    QString securityNotes = sectionObj["security_notes"].toString();
                    
                    // Format the explanation with section-specific information
                    QString explanation;
                    explanation += QString("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>").arg(description);
                    
                    if (!sectionName.isEmpty() && sectionName != "0x") {
                        // Add section-specific information
                        QString sectionTypeInfo = "";
                        QString sectionTypeKey = "";
                        if (sectionName == ".text") {
                            sectionTypeKey = "section_info_text";
                        } else if (sectionName == ".data") {
                            sectionTypeKey = "section_info_data";
                        } else if (sectionName == ".rdata") {
                            sectionTypeKey = "section_info_rdata";
                        } else if (sectionName == ".rsrc") {
                            sectionTypeKey = "section_info_rsrc";
                        } else if (sectionName == ".reloc") {
                            sectionTypeKey = "section_info_reloc";
                        } else if (sectionName == ".idata") {
                            sectionTypeKey = "section_info_idata";
                        } else if (sectionName == ".edata") {
                            sectionTypeKey = "section_info_edata";
                        }
                        
                        if (!sectionTypeKey.isEmpty()) {
                            sectionTypeInfo = LanguageManager::getInstance().getString(sectionTypeKey, "");
                            if (sectionTypeInfo.isEmpty()) {
                                sectionTypeInfo = LanguageManager::getInstance().getString("UI/" + sectionTypeKey, "");
                            }
                        }
                        
                        if (!sectionTypeInfo.isEmpty()) {
                            explanation += QString("<div style='margin-bottom: 8px; padding: 8px; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 4px;'><b style='color: #1e40af;'>Section: %1</b><br>%2</div>").arg(sectionName, sectionTypeInfo);
                        }
                    }
                    
                    if (!purpose.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #1d4ed8;'>Purpose:</b> %1</div>").arg(purpose);
                    }
                    
                    if (!note.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7c3aed;'>Note:</b> %1</div>").arg(note);
                    }
                    
                    if (!securityNotes.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7f1d1d;'>Security Notes:</b> %1</div>").arg(securityNotes);
                    }
                    
                    return explanation;
                }
            }
            
            // Check for exact field name match
            if (languageObj.contains(fieldName)) {
                QJsonObject fieldObj = languageObj[fieldName].toObject();
                QString description = fieldObj["description"].toString();
                QString purpose = fieldObj["purpose"].toString();
                QString securityNotes = fieldObj["security_notes"].toString();
                QString value = fieldObj["value"].toString();
                QString note = fieldObj["note"].toString();
                QString commonNames = fieldObj["common_names"].toString();
                
                // Format the explanation with HTML for better presentation
                QString explanation;
                
                // Main description
                explanation += QString("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>").arg(description);
                
                // Value field (if exists)
                if (!value.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #059669;'>Value:</b> <span style='font-family: monospace; background: #f3f4f6; padding: 2px 6px; border-radius: 4px;'>%1</span></div>").arg(value);
                }
                
                // Purpose field
                if (!purpose.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #1d4ed8;'>Purpose:</b> %1</div>").arg(purpose);
                }
                
                // Note field (if exists)
                if (!note.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7c3aed;'>Note:</b> %1</div>").arg(note);
                }
                
                // Common names field (if exists)
                if (!commonNames.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #dc2626;'>Common Names:</b> <span style='font-family: monospace; background: #fef2f2; padding: 2px 6px; border-radius: 4px; color: #991b1b;'>%1</span></div>").arg(commonNames);
                }
                
                // Security notes - bold and dark red
                if (!securityNotes.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7f1d1d;'>Security Notes:</b> %1</div>").arg(securityNotes);
                }
                
                return explanation;
            }
        }
    }
    
    // Fallback to placeholder if field not found in JSON
    // All explanations should be in the config JSON files
    return LANG_PARAM("UI/field_explanation_placeholder", "fieldname", fieldName);
}

QPair<quint32, quint32> PEParserNew::getFieldOffset(const QString &fieldName)
{
    // Calculate field offset based on the field name and current data model
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return QPair<quint32, quint32>(0, 0);
    }
    
    // Map field names to their offsets and sizes
    QMap<QString, QPair<quint32, quint32>> fieldOffsets;
    
    // DOS Header fields
    fieldOffsets["e_magic"] = QPair<quint32, quint32>(0, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_cblp"] = QPair<quint32, quint32>(2, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_cp"] = QPair<quint32, quint32>(4, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_crlc"] = QPair<quint32, quint32>(6, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_cparhdr"] = QPair<quint32, quint32>(8, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_minalloc"] = QPair<quint32, quint32>(10, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_maxalloc"] = QPair<quint32, quint32>(12, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_ss"] = QPair<quint32, quint32>(14, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_sp"] = QPair<quint32, quint32>(16, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_csum"] = QPair<quint32, quint32>(18, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_ip"] = QPair<quint32, quint32>(20, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_cs"] = QPair<quint32, quint32>(22, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_lfarlc"] = QPair<quint32, quint32>(24, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_ovno"] = QPair<quint32, quint32>(26, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_res"] = QPair<quint32, quint32>(28, static_cast<quint32>(sizeof(quint16) * 4));
    fieldOffsets["e_oemid"] = QPair<quint32, quint32>(36, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_oeminfo"] = QPair<quint32, quint32>(38, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets["e_res2"] = QPair<quint32, quint32>(40, static_cast<quint32>(sizeof(quint16) * 10));
    fieldOffsets["e_lfanew"] = QPair<quint32, quint32>(60, static_cast<quint32>(sizeof(quint32)));
    
    // PE Header fields
    quint32 peHeaderOffset = dosHeader->e_lfanew;
    fieldOffsets["Signature"] = QPair<quint32, quint32>(peHeaderOffset, sizeof(quint32));
    
    // File Header fields
    quint32 fileHeaderOffset = peHeaderOffset + sizeof(quint32);
    fieldOffsets["Machine"] = QPair<quint32, quint32>(fileHeaderOffset, sizeof(quint16));
    fieldOffsets["NumberOfSections"] = QPair<quint32, quint32>(fileHeaderOffset + 2, sizeof(quint16));
    fieldOffsets["TimeDateStamp"] = QPair<quint32, quint32>(fileHeaderOffset + 4, sizeof(quint32));
    fieldOffsets["PointerToSymbolTable"] = QPair<quint32, quint32>(fileHeaderOffset + 8, sizeof(quint32));
    fieldOffsets["NumberOfSymbols"] = QPair<quint32, quint32>(fileHeaderOffset + 12, sizeof(quint32));
    fieldOffsets["SizeOfOptionalHeader"] = QPair<quint32, quint32>(fileHeaderOffset + 16, sizeof(quint16));
    fieldOffsets["Characteristics"] = QPair<quint32, quint32>(fileHeaderOffset + 18, sizeof(quint16));
    
    // Optional Header fields
    quint32 optionalHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    fieldOffsets["Magic"] = QPair<quint32, quint32>(optionalHeaderOffset, sizeof(quint16));
    fieldOffsets["MajorLinkerVersion"] = QPair<quint32, quint32>(optionalHeaderOffset + 2, sizeof(quint8));
    fieldOffsets["MinorLinkerVersion"] = QPair<quint32, quint32>(optionalHeaderOffset + 3, sizeof(quint8));
    fieldOffsets["SizeOfCode"] = QPair<quint32, quint32>(optionalHeaderOffset + 4, sizeof(quint32));
    fieldOffsets["SizeOfInitializedData"] = QPair<quint32, quint32>(optionalHeaderOffset + 8, sizeof(quint32));
    fieldOffsets["SizeOfUninitializedData"] = QPair<quint32, quint32>(optionalHeaderOffset + 12, sizeof(quint32));
    fieldOffsets["AddressOfEntryPoint"] = QPair<quint32, quint32>(optionalHeaderOffset + 16, sizeof(quint32));
    fieldOffsets["BaseOfCode"] = QPair<quint32, quint32>(optionalHeaderOffset + 20, sizeof(quint32));
    fieldOffsets["BaseOfData"] = QPair<quint32, quint32>(optionalHeaderOffset + 24, sizeof(quint32));
    fieldOffsets["ImageBase"] = QPair<quint32, quint32>(optionalHeaderOffset + 28, sizeof(quint32));
    fieldOffsets["SectionAlignment"] = QPair<quint32, quint32>(optionalHeaderOffset + 32, sizeof(quint32));
    fieldOffsets["FileAlignment"] = QPair<quint32, quint32>(optionalHeaderOffset + 36, sizeof(quint32));
    fieldOffsets["MajorOperatingSystemVersion"] = QPair<quint32, quint32>(optionalHeaderOffset + 40, sizeof(quint16));
    fieldOffsets["MinorOperatingSystemVersion"] = QPair<quint32, quint32>(optionalHeaderOffset + 42, sizeof(quint16));
    fieldOffsets["MajorImageVersion"] = QPair<quint32, quint32>(optionalHeaderOffset + 44, sizeof(quint16));
    fieldOffsets["MinorImageVersion"] = QPair<quint32, quint32>(optionalHeaderOffset + 46, sizeof(quint16));
    fieldOffsets["MajorSubsystemVersion"] = QPair<quint32, quint32>(optionalHeaderOffset + 48, sizeof(quint16));
    fieldOffsets["MinorSubsystemVersion"] = QPair<quint32, quint32>(optionalHeaderOffset + 50, sizeof(quint16));
    fieldOffsets["Win32VersionValue"] = QPair<quint32, quint32>(optionalHeaderOffset + 52, sizeof(quint32));
    fieldOffsets["SizeOfImage"] = QPair<quint32, quint32>(optionalHeaderOffset + 56, sizeof(quint32));
    fieldOffsets["SizeOfHeaders"] = QPair<quint32, quint32>(optionalHeaderOffset + 60, sizeof(quint32));
    fieldOffsets["CheckSum"] = QPair<quint32, quint32>(optionalHeaderOffset + 64, sizeof(quint32));
    fieldOffsets["Subsystem"] = QPair<quint32, quint32>(optionalHeaderOffset + 68, sizeof(quint16));
    fieldOffsets["DllCharacteristics"] = QPair<quint32, quint32>(optionalHeaderOffset + 70, sizeof(quint16));
    fieldOffsets["SizeOfStackReserve"] = QPair<quint32, quint32>(optionalHeaderOffset + 72, sizeof(quint32));
    fieldOffsets["SizeOfStackCommit"] = QPair<quint32, quint32>(optionalHeaderOffset + 76, sizeof(quint32));
    fieldOffsets["SizeOfHeapReserve"] = QPair<quint32, quint32>(optionalHeaderOffset + 80, sizeof(quint32));
    fieldOffsets["SizeOfHeapCommit"] = QPair<quint32, quint32>(optionalHeaderOffset + 84, sizeof(quint32));
    fieldOffsets["LoaderFlags"] = QPair<quint32, quint32>(optionalHeaderOffset + 88, sizeof(quint32));
    fieldOffsets["NumberOfRvaAndSizes"] = QPair<quint32, quint32>(optionalHeaderOffset + 92, sizeof(quint32));
    
    // Add container items for major PE sections
    fieldOffsets["DOS Header"] = QPair<quint32, quint32>(0, static_cast<quint32>(sizeof(IMAGE_DOS_HEADER)));
    fieldOffsets["PE Header"] = QPair<quint32, quint32>(peHeaderOffset, static_cast<quint32>(sizeof(quint32) + sizeof(IMAGE_FILE_HEADER)));
    fieldOffsets["File Header"] = QPair<quint32, quint32>(fileHeaderOffset, static_cast<quint32>(sizeof(IMAGE_FILE_HEADER)));
    fieldOffsets["Optional Header"] = QPair<quint32, quint32>(optionalHeaderOffset, static_cast<quint32>(fileHeader->SizeOfOptionalHeader));
    
    // Calculate sections container offset and size
    quint32 sectionsOffset = optionalHeaderOffset + fileHeader->SizeOfOptionalHeader;
    quint32 sectionsSize = fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    fieldOffsets["Sections"] = QPair<quint32, quint32>(sectionsOffset, sectionsSize);
    
    // Add Data Directories container
    // Data Directories start after NumberOfRvaAndSizes field
    // NumberOfRvaAndSizes is at offset 96 (0x60) for PE32, but we need to check the actual structure
    // For PE32: offset 96 (0x60) from Optional Header start
    // For PE32+: offset 112 (0x70) from Optional Header start (because ImageBase is 64-bit)
    quint16 magic = optionalHeader->Magic;
    quint32 dataDirectoriesOffset;
    if (magic == 0x10b) {
        // PE32 (32-bit) - NumberOfRvaAndSizes is at offset 96
        dataDirectoriesOffset = optionalHeaderOffset + 96;
    } else {
        // PE32+ (64-bit) - NumberOfRvaAndSizes is at offset 112
        dataDirectoriesOffset = optionalHeaderOffset + 112;
    }
    quint32 dataDirectoriesSize = 16 * sizeof(IMAGE_DATA_DIRECTORY); // 16 data directories
    fieldOffsets["Data Directories"] = QPair<quint32, quint32>(dataDirectoriesOffset, dataDirectoriesSize);
    
    // Add Data Directory fields - now structured as "Directory Name" with "Address" and "Size" children
    // Use the same translation keys as in addDataDirectoryFields to ensure names match
    QStringList dirNames = {LANG("UI/data_dir_export"), LANG("UI/data_dir_import"), LANG("UI/data_dir_resource"), LANG("UI/data_dir_exception"),
                           LANG("UI/data_dir_certificate"), LANG("UI/data_dir_base_relocation"), LANG("UI/data_dir_debug"), LANG("UI/data_dir_architecture"),
                           LANG("UI/data_dir_global_pointer"), LANG("UI/data_dir_tls"), LANG("UI/data_dir_load_config"), LANG("UI/data_dir_bound_import"),
                           LANG("UI/data_dir_iat"), LANG("UI/data_dir_delay_import"), LANG("UI/data_dir_com_runtime"), LANG("UI/data_dir_reserved")};
    for (int i = 0; i < 16; ++i) {
        quint32 addressOffset = dataDirectoriesOffset + (i * 8);      // Address (RVA) is at base + (i * 8)
        quint32 sizeOffset = dataDirectoriesOffset + (i * 8) + 4;     // Size is at base + (i * 8) + 4
        // Directory parent item (points to the start of the directory entry)
        fieldOffsets[dirNames[i]] = QPair<quint32, quint32>(addressOffset, 8);
        // Address child field
        fieldOffsets[dirNames[i] + " Address"] = QPair<quint32, quint32>(addressOffset, 4);
        // Size child field
        fieldOffsets[dirNames[i] + " Size"] = QPair<quint32, quint32>(sizeOffset, 4);
    }
    
    // Section fields - these will be calculated dynamically based on section index
    // For now, we'll add common section field names that can be used for lookup
    if (fieldName == "VirtualAddress" || fieldName == "SizeOfRawData" || 
        fieldName == "PointerToRawData" || fieldName == "PointerToRelocations" ||
        fieldName == "PointerToLineNumbers" || fieldName == "NumberOfRelocations" ||
        fieldName == "NumberOfLineNumbers" || fieldName == "Characteristics") {
        // These are section-specific fields, return a placeholder
        // The actual offset will depend on which section is being examined
        return QPair<quint32, quint32>(0, 0);
    }
    
    // Return the field offset if found
    if (fieldOffsets.contains(fieldName)) {
        return fieldOffsets[fieldName];
    }
    
    return QPair<quint32, quint32>(0, 0);
}

void PEParserNew::setLanguage(const QString &language)
{
    // Set the language for the language manager
    LanguageManager::getInstance().setLanguage(language);
    
    // Emit signal to notify UI of language change
    emit languageChanged(language);
}

QList<QTreeWidgetItem*> PEParserNew::getPEStructureTree()
{
    QList<QTreeWidgetItem*> treeItems;
    
    // Create DOS Header section
    QTreeWidgetItem *dosHeaderItem = new QTreeWidgetItem();
    dosHeaderItem->setText(0, LANG("UI/pe_structure_dos_header"));
    dosHeaderItem->setText(1, "");
    dosHeaderItem->setText(2, "0x00000000");
    dosHeaderItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", "0x40"));
    
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    if (dosHeader) {
        addDOSHeaderFields(dosHeaderItem, dosHeader);
    }
    treeItems.append(dosHeaderItem);
    
    // Create Rich Header section (if present)
    if (dosHeader) {
        quint32 richOffset;
        if (PEUtils::findRichHeaderOffset(m_fileData, *dosHeader, richOffset)) {
            quint32 richSize = PEUtils::calculateRichHeaderSize(m_fileData, richOffset);
            
            QTreeWidgetItem *richHeaderItem = new QTreeWidgetItem();
            richHeaderItem->setText(0, "Rich Header");
            richHeaderItem->setText(1, "");
            richHeaderItem->setText(2, PEUtils::formatHexWidth(richOffset, 8));
            richHeaderItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", PEUtils::formatHexWidth(richSize, 0)));
            richHeaderItem->setText(4, ""); // No meaning for section header
            
            addRichHeaderFields(richHeaderItem, richOffset);
            treeItems.append(richHeaderItem);
        }
    }
    
    // Create NT Headers section (parent container for File Header, Optional Header, and Section Headers)
    quint32 ntHeadersOffset = dosHeader ? dosHeader->e_lfanew : 0;
    QTreeWidgetItem *ntHeadersItem = new QTreeWidgetItem();
    ntHeadersItem->setText(0, "NT Headers");
    ntHeadersItem->setText(1, "");
    ntHeadersItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset, 8));
    // NT Headers size = PE Signature (4) + File Header (20) + Optional Header + Section Headers
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    quint32 ntHeadersSize = 4 + 20 + (optionalHeader ? optionalHeader->SizeOfHeaders : 0);
    ntHeadersItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", PEUtils::formatHexWidth(ntHeadersSize, 0)));
    ntHeadersItem->setText(4, ""); // No meaning for container
    
    // Add PE Signature as first field of NT Headers
    if (ntHeadersOffset + 4 <= m_fileData.size()) {
        quint32 peSignature = *reinterpret_cast<const quint32*>(m_fileData.data() + ntHeadersOffset);
        addTreeField(ntHeadersItem, "Signature", PEUtils::formatHexWidth(peSignature, 8), 0, sizeof(quint32));
    }
    
    // Create File Header as child of NT Headers
    QTreeWidgetItem *fileHeaderItem = new QTreeWidgetItem(ntHeadersItem);
    fileHeaderItem->setText(0, "File Header");
    fileHeaderItem->setText(1, "");
    // File Header starts 4 bytes after NT Headers (after PE signature)
    fileHeaderItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset + 4, 8));
    fileHeaderItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", "0x14"));
    fileHeaderItem->setText(4, ""); // No meaning for section header
    
    if (fileHeader) {
        addPEHeaderFields(fileHeaderItem, fileHeader);
    }
    
    // Create Optional Header as child of NT Headers
    QTreeWidgetItem *optionalHeaderItem = new QTreeWidgetItem(ntHeadersItem);
    optionalHeaderItem->setText(0, LANG("UI/pe_structure_optional_header"));
    optionalHeaderItem->setText(1, "");
    // Optional Header starts after PE signature (4 bytes) + File Header (20 bytes) = 24 bytes from NT Headers start
    optionalHeaderItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset + 4 + 20, 8));
    optionalHeaderItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", "0xE0"));
    optionalHeaderItem->setText(4, ""); // No meaning for section header
    
    if (optionalHeader) {
        addOptionalHeaderFields(optionalHeaderItem, optionalHeader);
        
        // Create Data Directories as child of Optional Header
        QTreeWidgetItem *dataDirsItem = new QTreeWidgetItem(optionalHeaderItem);
        dataDirsItem->setText(0, LANG("UI/pe_structure_data_directories"));
        dataDirsItem->setText(1, "");
        // Data Directories start right after NumberOfRvaAndSizes field
        // NumberOfRvaAndSizes offset depends on PE32 vs PE32+:
        // PE32 (32-bit): NumberOfRvaAndSizes is at offset 96 (0x60) from Optional Header start, and is 4 bytes
        // PE32+ (64-bit): NumberOfRvaAndSizes is at offset 112 (0x70) from Optional Header start, and is 4 bytes
        // So Data Directories base = Optional Header start + NumberOfRvaAndSizes offset + 4
        quint16 magic = optionalHeader->Magic;
        quint32 numberOfRvaAndSizesOffset;
        if (magic == 0x10b) {
            // PE32 (32-bit)
            numberOfRvaAndSizesOffset = 92; // 0x5C
        } else {
            // PE32+ (64-bit)
            numberOfRvaAndSizesOffset = 108; // 0x6C
        }
        quint32 dataDirsOffset = ntHeadersOffset + 4 + 20 + numberOfRvaAndSizesOffset + 4; // NT Headers + PE Sig + File Header + NumberOfRvaAndSizes offset + 4
        dataDirsItem->setText(2, PEUtils::formatHexWidth(dataDirsOffset, 8));
        dataDirsItem->setText(3, LANG_PARAM("UI/pe_structure_entries_format", "count", "16"));
        dataDirsItem->setText(4, ""); // No meaning for container
        
        addDataDirectoryFields(dataDirsItem);
    }
    
    // Create Section Headers as child of NT Headers
    QTreeWidgetItem *sectionsItem = new QTreeWidgetItem(ntHeadersItem);
    sectionsItem->setText(0, "Section Headers");
    sectionsItem->setText(1, "");
    // Section Headers start after PE signature (4) + File Header (20) + Optional Header
    sectionsItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset + 4 + 20 + (fileHeader ? fileHeader->SizeOfOptionalHeader : 0), 8));
    sectionsItem->setText(3, LANG_PARAM("UI/pe_structure_entries_format", "count", PEUtils::formatHexWidth(static_cast<quint64>(m_dataModel.getSections().size()), 0)));
    sectionsItem->setText(4, ""); // No meaning for container
    
    addSectionFields(sectionsItem);
    
    treeItems.append(ntHeadersItem);
    
    return treeItems;
}

void PEParserNew::addDOSHeaderFields(QTreeWidgetItem *parent, const IMAGE_DOS_HEADER *dosHeader)
{
    // Add DOS header fields
        addTreeField(parent, "e_magic", PEUtils::formatHexWidth(dosHeader->e_magic, 4), 0, sizeof(quint16));
    addTreeField(parent, "e_cblp", PEUtils::formatHexWidth(dosHeader->e_cblp, 4), 2, sizeof(quint16));
    addTreeField(parent, "e_cp", PEUtils::formatHexWidth(dosHeader->e_cp, 4), 4, sizeof(quint16));
    addTreeField(parent, "e_crlc", PEUtils::formatHexWidth(dosHeader->e_crlc, 4), 6, sizeof(quint16));
    addTreeField(parent, "e_cparhdr", PEUtils::formatHexWidth(dosHeader->e_cparhdr, 4), 8, sizeof(quint16));
    addTreeField(parent, "e_minalloc", PEUtils::formatHexWidth(dosHeader->e_minalloc, 4), 10, sizeof(quint16));
    addTreeField(parent, "e_maxalloc", PEUtils::formatHexWidth(dosHeader->e_maxalloc, 4), 12, sizeof(quint16));
    addTreeField(parent, "e_ss", PEUtils::formatHexWidth(dosHeader->e_ss, 4), 14, sizeof(quint16));
    addTreeField(parent, "e_sp", PEUtils::formatHexWidth(dosHeader->e_sp, 4), 16, sizeof(quint16));
    addTreeField(parent, "e_csum", PEUtils::formatHexWidth(dosHeader->e_csum, 4), 18, sizeof(quint16));
    addTreeField(parent, "e_ip", PEUtils::formatHexWidth(dosHeader->e_ip, 4), 20, sizeof(quint16));
    addTreeField(parent, "e_cs", PEUtils::formatHexWidth(dosHeader->e_cs, 4), 22, sizeof(quint16));
    addTreeField(parent, "e_lfarlc", PEUtils::formatHexWidth(dosHeader->e_lfarlc, 4), 24, sizeof(quint16));
    addTreeField(parent, "e_ovno", PEUtils::formatHexWidth(dosHeader->e_ovno, 4), 26, sizeof(quint16));
        addTreeField(parent, "e_lfanew", PEUtils::formatHexWidth(dosHeader->e_lfanew, 8), 60, sizeof(quint32));
}

void PEParserNew::addPEHeaderFields(QTreeWidgetItem *parent, const IMAGE_FILE_HEADER *fileHeader)
{
    // File Header fields are relative to File Header start (parent's offset)
    // No offset needed since parent is already at File Header offset
    
    // Add File Header fields
    addTreeField(parent, "Machine", PEUtils::formatHexWidth(fileHeader->Machine, 4), 0, sizeof(quint16));
    addTreeField(parent, "NumberOfSections", PEUtils::formatHexWidth(fileHeader->NumberOfSections, 4), 2, sizeof(quint16));
    addTreeField(parent, "TimeDateStamp", PEUtils::formatHexWidth(fileHeader->TimeDateStamp, 8), 4, sizeof(quint32));
    addTreeField(parent, "PointerToSymbolTable", PEUtils::formatHexWidth(fileHeader->PointerToSymbolTable, 8), 8, sizeof(quint32));
    addTreeField(parent, "NumberOfSymbols", PEUtils::formatHexWidth(fileHeader->NumberOfSymbols, 8), 12, sizeof(quint32));
    addTreeField(parent, "SizeOfOptionalHeader", PEUtils::formatHexWidth(fileHeader->SizeOfOptionalHeader, 4), 16, sizeof(quint16));
    addTreeField(parent, "Characteristics", PEUtils::formatHexWidth(fileHeader->Characteristics, 4), 18, sizeof(quint16));
}

void PEParserNew::addOptionalHeaderFields(QTreeWidgetItem *parent, const IMAGE_OPTIONAL_HEADER *optionalHeader)
{
    // Optional Header fields are relative to Optional Header start (parent's offset)
    // No offset needed since parent is already at Optional Header offset
    
    // Add optional header fields
    addTreeField(parent, "Magic", PEUtils::formatHexWidth(optionalHeader->Magic, 4), 0, sizeof(quint16));
    addTreeField(parent, "MajorLinkerVersion", PEUtils::formatHexWidth(optionalHeader->MajorLinkerVersion, 2), 2, sizeof(quint8));
    addTreeField(parent, "MinorLinkerVersion", PEUtils::formatHexWidth(optionalHeader->MinorLinkerVersion, 2), 3, sizeof(quint8));
    addTreeField(parent, "SizeOfCode", PEUtils::formatHexWidth(optionalHeader->SizeOfCode, 8), 4, sizeof(quint32));
    addTreeField(parent, "SizeOfInitializedData", PEUtils::formatHexWidth(optionalHeader->SizeOfInitializedData, 8), 8, sizeof(quint32));
    addTreeField(parent, "SizeOfUninitializedData", PEUtils::formatHexWidth(optionalHeader->SizeOfUninitializedData, 8), 12, sizeof(quint32));
    addTreeField(parent, "AddressOfEntryPoint", PEUtils::formatHexWidth(optionalHeader->AddressOfEntryPoint, 8), 16, sizeof(quint32));
    addTreeField(parent, "BaseOfCode", PEUtils::formatHexWidth(optionalHeader->BaseOfCode, 8), 20, sizeof(quint32));
    addTreeField(parent, "ImageBase", PEUtils::formatHexWidth(optionalHeader->ImageBase, 16), 24, sizeof(quint64));
    addTreeField(parent, "SectionAlignment", PEUtils::formatHexWidth(optionalHeader->SectionAlignment, 8), 32, sizeof(quint32));
    addTreeField(parent, "FileAlignment", PEUtils::formatHexWidth(optionalHeader->FileAlignment, 8), 36, sizeof(quint32));
    addTreeField(parent, "MajorOperatingSystemVersion", PEUtils::formatHexWidth(optionalHeader->MajorOperatingSystemVersion, 4), 40, sizeof(quint16));
    addTreeField(parent, "MinorOperatingSystemVersion", PEUtils::formatHexWidth(optionalHeader->MinorOperatingSystemVersion, 4), 42, sizeof(quint16));
    addTreeField(parent, "MajorImageVersion", PEUtils::formatHexWidth(optionalHeader->MajorImageVersion, 4), 44, sizeof(quint16));
    addTreeField(parent, "MinorImageVersion", PEUtils::formatHexWidth(optionalHeader->MinorImageVersion, 4), 46, sizeof(quint16));
    addTreeField(parent, "MajorSubsystemVersion", PEUtils::formatHexWidth(optionalHeader->MajorSubsystemVersion, 4), 48, sizeof(quint16));
    addTreeField(parent, "MinorSubsystemVersion", PEUtils::formatHexWidth(optionalHeader->MinorSubsystemVersion, 4), 50, sizeof(quint16));
    addTreeField(parent, "Win32VersionValue", PEUtils::formatHexWidth(optionalHeader->Win32VersionValue, 8), 52, sizeof(quint32));
    addTreeField(parent, "SizeOfImage", PEUtils::formatHexWidth(optionalHeader->SizeOfImage, 8), 56, sizeof(quint32));
    addTreeField(parent, "SizeOfHeaders", PEUtils::formatHexWidth(optionalHeader->SizeOfHeaders, 8), 60, sizeof(quint32));
    addTreeField(parent, "CheckSum", PEUtils::formatHexWidth(optionalHeader->CheckSum, 8), 64, sizeof(quint32));
    addTreeField(parent, "Subsystem", PEUtils::formatHexWidth(optionalHeader->Subsystem, 4), 68, sizeof(quint16));
    addTreeField(parent, "DllCharacteristics", PEUtils::formatHexWidth(optionalHeader->DllCharacteristics, 4), 70, sizeof(quint16));
    addTreeField(parent, "SizeOfStackReserve", PEUtils::formatHexWidth(optionalHeader->SizeOfStackReserve, 16), 72, sizeof(quint64));
    addTreeField(parent, "SizeOfStackCommit", PEUtils::formatHexWidth(optionalHeader->SizeOfStackCommit, 16), 80, sizeof(quint64));
    addTreeField(parent, "SizeOfHeapReserve", PEUtils::formatHexWidth(optionalHeader->SizeOfHeapReserve, 16), 88, sizeof(quint64));
    addTreeField(parent, "SizeOfHeapCommit", PEUtils::formatHexWidth(optionalHeader->SizeOfHeapCommit, 16), 96, sizeof(quint64));
    addTreeField(parent, "LoaderFlags", PEUtils::formatHexWidth(optionalHeader->LoaderFlags, 8), 104, sizeof(quint32));
    addTreeField(parent, "NumberOfRvaAndSizes", PEUtils::formatHexWidth(optionalHeader->NumberOfRvaAndSizes, 8), 108, sizeof(quint32));
}

void PEParserNew::addSectionFields(QTreeWidgetItem *parent)
{
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_dataModel.getSections();
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    
    for (int i = 0; i < sections.size(); ++i) {
        const IMAGE_SECTION_HEADER *section = sections[i];
        if (section) {
            QTreeWidgetItem *sectionItem = new QTreeWidgetItem(parent);
            // Parse section name properly - handle both ASCII and non-ASCII characters
            QString sectionName;
            const char* namePtr = reinterpret_cast<const char*>(section->Name);
            
            // Check if the name is null-terminated or contains only printable characters
            bool hasValidChars = false;
            for (int j = 0; j < 8; ++j) {
                if (namePtr[j] >= 32 && namePtr[j] <= 126) { // Printable ASCII range
                    hasValidChars = true;
                    break;
                }
            }
            
            if (hasValidChars) {
                // Try to find null terminator
                int nameLength = 0;
                while (nameLength < 8 && namePtr[nameLength] != '\0' && namePtr[nameLength] >= 32) {
                    nameLength++;
                }
                sectionName = QString::fromLatin1(namePtr, nameLength);
            } else {
                // If no valid ASCII characters, show as hex
                QByteArray nameBytes(namePtr, 8);
                sectionName = QString("0x") + QString(nameBytes.toHex()).toUpper();
            }
            QMap<QString, QString> params;
            params["number"] = QString::number(i + 1);
            params["name"] = sectionName;
            sectionItem->setText(0, LANG_PARAMS("UI/pe_structure_section_format", params));
            sectionItem->setText(1, "");
            // Section header offset (where the section header structure is in the file)
            // Sections start after PE signature (4) + File Header (20) + Optional Header
            quint32 sectionHeaderOffset = (dosHeader ? dosHeader->e_lfanew : 0) + 4 + 20 + (fileHeader ? fileHeader->SizeOfOptionalHeader : 0) + (i * sizeof(IMAGE_SECTION_HEADER));
            sectionItem->setText(2, PEUtils::formatHexWidth(sectionHeaderOffset, 8));
            sectionItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", PEUtils::formatHexWidth(sizeof(IMAGE_SECTION_HEADER), 0)));
            
            // Add section details with proper file offsets
            // Section header fields are relative to sectionHeaderOffset (parent's offset)
            // IMAGE_SECTION_HEADER structure:
            // Name[8] at offset 0 (8 bytes)
            // Misc.VirtualSize at offset 8 (4 bytes)
            // VirtualAddress at offset 12 (4 bytes)
            // SizeOfRawData at offset 16 (4 bytes)
            // PointerToRawData at offset 20 (4 bytes)
            // PointerToRelocations at offset 24 (4 bytes)
            // PointerToLinenumbers at offset 28 (4 bytes)
            // NumberOfRelocations at offset 32 (2 bytes)
            // NumberOfLinenumbers at offset 34 (2 bytes)
            // Characteristics at offset 36 (4 bytes)
            
            addTreeField(sectionItem, "Name", sectionName, 0, 8);
            addTreeField(sectionItem, "VirtualSize", PEUtils::formatHexWidth(section->Misc.VirtualSize, 8), 8, sizeof(quint32));
            addTreeField(sectionItem, "VirtualAddress", PEUtils::formatHexWidth(section->VirtualAddress, 8), 12, sizeof(quint32));
            addTreeField(sectionItem, "SizeOfRawData", PEUtils::formatHexWidth(section->SizeOfRawData, 8), 16, sizeof(quint32));
            addTreeField(sectionItem, "PointerToRawData", PEUtils::formatHexWidth(section->PointerToRawData, 8), 20, sizeof(quint32));
            addTreeField(sectionItem, "PointerToRelocations", PEUtils::formatHexWidth(section->PointerToRelocations, 8), 24, sizeof(quint32));
            // Note: PointerToLineNumbers and NumberOfLineNumbers are deprecated in modern PE format
            addTreeField(sectionItem, "PointerToLineNumbers", LANG("UI/field_deprecated_pointer"), 28, sizeof(quint32));
            addTreeField(sectionItem, "NumberOfRelocations", PEUtils::formatHexWidth(section->NumberOfRelocations, 4), 32, sizeof(quint16));
            addTreeField(sectionItem, "NumberOfLineNumbers", LANG("UI/field_deprecated_count"), 34, sizeof(quint16));
            addTreeField(sectionItem, "Characteristics", PEUtils::formatHexWidth(section->Characteristics, 8), 36, sizeof(quint32));
        }
    }
}

void PEParserNew::addRichHeaderFields(QTreeWidgetItem *parent, quint32 richOffset)
{
    if (richOffset + 16 > m_fileData.size()) {
        return;
    }
    
    IMAGE_RICH_HEADER richHeader;
    if (!PEUtils::parseRichHeader(m_fileData, richOffset, richHeader)) {
        return;
    }
    
    // Add Rich Header fields - offsets are relative to richOffset (parent's offset)
    addTreeField(parent, "XorKey", PEUtils::formatHexWidth(richHeader.XorKey, 8), 0, sizeof(quint32));
    addTreeField(parent, "RichSignature", PEUtils::formatHexWidth(richHeader.RichSignature, 8), 4, sizeof(quint32));
    addTreeField(parent, "RichVersion", PEUtils::formatHexWidth(richHeader.RichVersion, 8), 8, sizeof(quint32));
    addTreeField(parent, "RichCount", PEUtils::formatHexWidth(richHeader.RichCount, 8), 12, sizeof(quint32));
    
    // Add Rich Entry fields
    QList<IMAGE_RICH_ENTRY> entries = PEUtils::parseRichEntries(m_fileData, richOffset, richHeader.RichCount);
    quint32 entryBaseOffset = 16; // 4 dwords = 16 bytes
    
    for (int i = 0; i < entries.size(); ++i) {
        const IMAGE_RICH_ENTRY &entry = entries[i];
        QString productName = PEUtils::getRichHeaderProductName(entry.ProductId);
        QString entryName = QString("Entry %1: %2").arg(i + 1).arg(productName);
        
        QTreeWidgetItem *entryItem = new QTreeWidgetItem(parent);
        entryItem->setText(0, entryName);
        QString versionMajor = QString::number((entry.ProductVersion >> 8) & 0xFF, 16).toUpper().rightJustified(2, '0');
        QString versionMinor = QString::number(entry.ProductVersion & 0xFF, 16).toUpper().rightJustified(2, '0');
        QString countHex = PEUtils::formatHexWidth(entry.ProductCount, 8);
        entryItem->setText(1, QString("v0x%1.0x%2, Count: %3").arg(versionMajor, versionMinor, countHex));
        quint32 entryOffset = entryBaseOffset + (i * 12); // Each entry is 12 bytes
        entryItem->setText(2, PEUtils::formatHexWidth(richOffset + entryOffset, 8));
        entryItem->setText(3, PEUtils::formatHexWidth(12, 0) + " bytes");
        entryItem->setText(4, ""); // No meaning for entry header
        
        // Add individual entry fields - offsets relative to entry start (entryOffset)
        addTreeField(entryItem, "ProductId", PEUtils::formatHexWidth(entry.ProductId, 4), entryOffset, sizeof(quint16));
        addTreeField(entryItem, "ProductVersion", PEUtils::formatHexWidth(entry.ProductVersion, 4), entryOffset + 2, sizeof(quint16));
        addTreeField(entryItem, "ProductCount", PEUtils::formatHexWidth(entry.ProductCount, 8), entryOffset + 4, sizeof(quint32));
        addTreeField(entryItem, "ProductTimestamp", PEUtils::formatHexWidth(entry.ProductTimestamp, 8), entryOffset + 8, sizeof(quint32));
    }
}

void PEParserNew::addDataDirectoryFields(QTreeWidgetItem *parent)
{
    // Get the Optional Header to access DataDirectory array
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!optionalHeader) {
        return;
    }
    
    // Get Data Directories base offset from parent item (already calculated correctly in getPEStructureTree)
    QString parentOffsetStr = parent->text(2);
    quint32 dataDirsBaseOffset = 0;
    if (!parentOffsetStr.isEmpty() && parentOffsetStr.startsWith("0x")) {
        bool ok;
        dataDirsBaseOffset = parentOffsetStr.toULong(&ok, 16);
        if (!ok || dataDirsBaseOffset == 0) {
            // Fallback: recalculate if parent offset is invalid
            const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
            const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
            if (dosHeader && fileHeader) {
                quint32 ntHeadersOffset = dosHeader->e_lfanew;
                quint16 magic = optionalHeader->Magic;
                quint32 numberOfRvaAndSizesOffset;
                if (magic == 0x10b) {
                    numberOfRvaAndSizesOffset = 92; // 0x5C
                } else {
                    numberOfRvaAndSizesOffset = 108; // 0x6C
                }
                dataDirsBaseOffset = ntHeadersOffset + 4 + 20 + numberOfRvaAndSizesOffset + 4;
            } else {
                return; // Cannot calculate offset
            }
        }
    } else {
        // Fallback: recalculate if no parent offset
        const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
        const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
        if (dosHeader && fileHeader) {
            quint32 ntHeadersOffset = dosHeader->e_lfanew;
            quint16 magic = optionalHeader->Magic;
            quint32 numberOfRvaAndSizesOffset;
            if (magic == 0x10b) {
                numberOfRvaAndSizesOffset = 92; // 0x5C
            } else {
                numberOfRvaAndSizesOffset = 108; // 0x6C
            }
            dataDirsBaseOffset = ntHeadersOffset + 4 + 20 + numberOfRvaAndSizesOffset + 4;
        } else {
            return; // Cannot calculate offset
        }
    }
    
    // Add data directory entries - match CFF Explorer format: show RVA and Size as separate entries
    QStringList dirNames = {LANG("UI/data_dir_export"), LANG("UI/data_dir_import"), LANG("UI/data_dir_resource"), LANG("UI/data_dir_exception"),
                           LANG("UI/data_dir_certificate"), LANG("UI/data_dir_base_relocation"), LANG("UI/data_dir_debug"), LANG("UI/data_dir_architecture"),
                           LANG("UI/data_dir_global_pointer"), LANG("UI/data_dir_tls"), LANG("UI/data_dir_load_config"), LANG("UI/data_dir_bound_import"),
                           LANG("UI/data_dir_iat"), LANG("UI/data_dir_delay_import"), LANG("UI/data_dir_com_runtime"), LANG("UI/data_dir_reserved")};
    
    // Access DataDirectory array directly from optional header structure
    // Handle both PE32 and PE32+ formats
    quint16 magic = optionalHeader->Magic;
    const IMAGE_DATA_DIRECTORY *dataDirectories = nullptr;
    if (magic == 0x10b) {
        // PE32 (32-bit) - DataDirectory is part of IMAGE_OPTIONAL_HEADER32
        const IMAGE_OPTIONAL_HEADER32 *optHeader32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalHeader);
        dataDirectories = optHeader32->DataDirectory;
            } else {
        // PE32+ (64-bit) - DataDirectory is part of IMAGE_OPTIONAL_HEADER64
        const IMAGE_OPTIONAL_HEADER64 *optHeader64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalHeader);
        dataDirectories = optHeader64->DataDirectory;
    }
    
    if (!dataDirectories) {
        return;
            }
    
    for (int i = 0; i < dirNames.size() && i < 16; ++i) {
        // Get values directly from DataDirectory array
        quint32 address = dataDirectories[i].VirtualAddress;
        quint32 size = dataDirectories[i].Size;
        
        // Calculate offsets for display (Address and Size are consecutive 4-byte fields)
        // Each Data Directory entry is 8 bytes: 4 bytes VirtualAddress + 4 bytes Size
        quint32 addressOffset = dataDirsBaseOffset + (i * 8);      // Address (RVA) is at base + (i * 8)
        quint32 sizeOffset = dataDirsBaseOffset + (i * 8) + 4;     // Size is at base + (i * 8) + 4
        
        // Verify offsets are within file bounds
        if (addressOffset + 4 > static_cast<quint32>(m_fileData.size()) || 
            sizeOffset + 4 > static_cast<quint32>(m_fileData.size())) {
            // Skip if offset is out of bounds
            continue;
        }
        
        // Verify values match what's in the file (for debugging/validation)
        // Read directly from file to ensure accuracy
        quint32 fileAddress = 0;
        quint32 fileSize = 0;
        if (addressOffset + sizeof(quint32) <= static_cast<quint32>(m_fileData.size())) {
            const quint8 *addrPtr = reinterpret_cast<const quint8*>(m_fileData.data() + addressOffset);
            fileAddress = static_cast<quint32>(addrPtr[0]) |
                         (static_cast<quint32>(addrPtr[1]) << 8) |
                         (static_cast<quint32>(addrPtr[2]) << 16) |
                         (static_cast<quint32>(addrPtr[3]) << 24);
        }
        if (sizeOffset + sizeof(quint32) <= static_cast<quint32>(m_fileData.size())) {
            const quint8 *sizePtr = reinterpret_cast<const quint8*>(m_fileData.data() + sizeOffset);
            fileSize = static_cast<quint32>(sizePtr[0]) |
                      (static_cast<quint32>(sizePtr[1]) << 8) |
                      (static_cast<quint32>(sizePtr[2]) << 16) |
                      (static_cast<quint32>(sizePtr[3]) << 24);
        }
        
        // Use values from structure (they should match file, but structure is more reliable)
        // If they don't match, use file values as fallback
        if (address != fileAddress) {
            address = fileAddress; // Use file value if mismatch
        }
        if (size != fileSize) {
            size = fileSize; // Use file value if mismatch
        }
        
        // Create directory parent item (e.g., "Export Directory")
        QTreeWidgetItem *dirItem = new QTreeWidgetItem(parent);
        dirItem->setText(0, dirNames[i]);
        dirItem->setText(1, ""); // No value for parent
        dirItem->setText(2, PEUtils::formatHexWidth(addressOffset, 8)); // Base offset
        dirItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", PEUtils::formatHexWidth(8, 0))); // 8 bytes total
        dirItem->setText(4, ""); // No meaning for directory container
        
        // Add Address child (showing RVA value in hexadecimal)
        QTreeWidgetItem *addressItem = new QTreeWidgetItem(dirItem);
        addressItem->setText(0, "Address");
        addressItem->setText(1, PEUtils::formatHexWidth(address, 8));
        addressItem->setText(2, PEUtils::formatHexWidth(addressOffset, 8));
        addressItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", PEUtils::formatHexWidth(4, 0)));
        addressItem->setText(4, ""); // No meaning for Data Directory entries
        
        // Add Size child (showing size value in hexadecimal)
        QTreeWidgetItem *sizeItem = new QTreeWidgetItem(dirItem);
        sizeItem->setText(0, "Size");
        sizeItem->setText(1, PEUtils::formatHexWidth(size, 8));
        sizeItem->setText(2, PEUtils::formatHexWidth(sizeOffset, 8));
        sizeItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", PEUtils::formatHexWidth(4, 0)));
        sizeItem->setText(4, ""); // No meaning for Data Directory entries
        
        // Import/export details now live in the dedicated tabs (imports/exports)
    }
}

void PEParserNew::addTreeField(QTreeWidgetItem *parent, const QString &name, const QString &value, quint32 offset, quint32 size)
{
    QTreeWidgetItem *fieldItem = new QTreeWidgetItem(parent);
    fieldItem->setText(0, name);
    fieldItem->setText(1, value);
    
    // Calculate absolute offset: get parent's base offset and add relative offset
    quint32 absoluteOffset = offset;
    if (parent) {
        QString parentOffsetStr = parent->text(2);
        if (!parentOffsetStr.isEmpty() && parentOffsetStr.startsWith("0x")) {
            bool ok;
            quint32 parentOffset = parentOffsetStr.toULong(&ok, 16);
            if (ok) {
                absoluteOffset = parentOffset + offset;
            }
        }
    }
    
    fieldItem->setText(2, PEUtils::formatHexWidth(absoluteOffset, 8));
    fieldItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", PEUtils::formatHexWidth(size, 0)));
    
    // Get meaning for the field
    QString meaning = getFieldMeaning(name, value);
    fieldItem->setText(4, meaning);
}

QString PEParserNew::getFieldMeaning(const QString &fieldName, const QString &value)
{
    // Handle empty values
    if (value.isEmpty()) {
        return "";
    }
    
    // Machine field - convert to architecture name
    if (fieldName == "Machine") {
        bool ok;
        quint16 machine = value.toUShort(&ok, 16);
        if (ok) {
            return PEUtils::getMachineType(machine);
        }
    }
    
    // TimeDateStamp - convert to date/time
    if (fieldName == "TimeDateStamp") {
        bool ok;
        quint32 timestamp = value.toULong(&ok, 16);
        if (ok && timestamp != 0) {
            QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
            return dateTime.toString("dddd, dd.MM.yyyy HH:mm:ss UTC");
        }
    }
    
    // Characteristics - decode flags (can be File Header or Section Header)
    if (fieldName == "Characteristics") {
        bool ok;
        // Try parsing as 16-bit first (File Header Characteristics)
        quint16 chars16 = value.toUShort(&ok, 16);
        if (ok) {
            // File characteristics are typically small values (0x0001-0xFFFF)
            // Section characteristics are typically larger (0x00000020-0xE0000000)
            // If value fits in 16-bit and is reasonable for file chars, use file characteristics
            if (chars16 <= 0xFFFF && chars16 != 0) {
                QString fileChars = PEUtils::getFileCharacteristics(chars16);
                // Check if we got meaningful flags (not just "None")
                if (!fileChars.isEmpty() && fileChars != LANG("UI/section_char_none")) {
                    return fileChars;
                }
            }
        }
        
        // Otherwise try section characteristics (32-bit)
        quint32 chars32 = value.toULong(&ok, 16);
        if (ok) {
            QString sectionChars = PEUtils::getSectionCharacteristics(chars32);
            if (!sectionChars.isEmpty()) {
                return sectionChars;
            }
        }
    }
    
    // DllCharacteristics - decode flags
    if (fieldName == "DllCharacteristics") {
        bool ok;
        quint16 chars = value.toUShort(&ok, 16);
        if (ok) {
            QString dllChars = PEUtils::getDLLCharacteristics(chars);
            // If translation failed and we got raw keys, return empty to avoid showing broken text
            if (dllChars.startsWith("UI/")) {
                return ""; // Translation keys not found, return empty
            }
            return dllChars;
        }
    }
    
    // Subsystem - convert to subsystem name
    if (fieldName == "Subsystem") {
        bool ok;
        quint16 subsystem = value.toUShort(&ok, 10);
        if (ok) {
            return PEUtils::getSubsystem(subsystem);
        }
    }
    
    // Magic - PE32 or PE32+
    if (fieldName == "Magic") {
        bool ok;
        quint16 magic = value.toUShort(&ok, 16);
        if (ok) {
            if (magic == 0x10b) return "PE32 (32-bit)";
            if (magic == 0x20b) return "PE32+ (64-bit)";
            return QString("Unknown (0x%1)").arg(magic, 4, 16, QChar('0'));
        }
    }
    
    // e_magic - DOS signature
    if (fieldName == "e_magic") {
        bool ok;
        quint16 magic = value.toUShort(&ok, 16);
        if (ok && magic == 0x5a4d) {
            return "MZ (DOS signature)";
        }
    }
    
    // Signature - PE signature
    if (fieldName == "Signature") {
        bool ok;
        quint32 signature = value.toULong(&ok, 16);
        if (ok && signature == 0x00004550) {
            return "PE\\0\\0 (PE signature)";
        }
    }
    
    // NumberOfSections - just show count
    if (fieldName == "NumberOfSections") {
        return QString("%1 section(s)").arg(value);
    }
    
    // SizeOfOptionalHeader - show decimal value
    if (fieldName == "SizeOfOptionalHeader") {
        bool ok;
        quint16 size = value.toUShort(&ok, 10);
        if (ok) {
            return QString("%1 bytes (0x%2)").arg(size).arg(size, 0, 16);
        }
    }
    
    // PointerToSymbolTable - show if zero or not
    if (fieldName == "PointerToSymbolTable") {
        bool ok;
        quint32 ptr = value.toULong(&ok, 16);
        if (ok) {
            if (ptr == 0) {
                return "No symbol table";
            }
            return QString("RVA: 0x%1").arg(ptr, 8, 16, QChar('0'));
        }
    }
    
    // NumberOfSymbols - show count
    if (fieldName == "NumberOfSymbols") {
        bool ok;
        quint32 count = value.toULong(&ok, 10);
        if (ok) {
            if (count == 0) {
                return "No symbols";
            }
            return QString("%1 symbol(s)").arg(count);
        }
    }
    
    // Rich Header fields
    if (fieldName == "RichSignature") {
        bool ok;
        quint32 sig = value.toULong(&ok, 16);
        if (ok) {
            // Check if it's "DanS" when XORed (we'd need the XOR key, but for display we show it's the signature)
            return "DanS signature (XORed)";
        }
    }
    
    if (fieldName == "RichCount") {
        bool ok;
        quint32 count = value.toULong(&ok, 10);
        if (ok) {
            return QString("%1 entry/entries").arg(count);
        }
    }
    
    // Default: return empty string if no specific meaning
    return "";
}

QString PEParserNew::findConfigFile(const QString &fileName) const
{
    QStringList possibleConfigPaths;
    
    // 1. Try relative to executable (for deployed builds) - PRIORITY 1
    QString appDir = QCoreApplication::applicationDirPath();
    possibleConfigPaths << QDir(appDir).absoluteFilePath("config/" + fileName);
    
    // 2. Try current working directory - PRIORITY 2
    possibleConfigPaths << QDir::currentPath() + "/config/" + fileName;
    
    // 3. Try relative to executable but go up to project root (for development builds) - PRIORITY 3
    QDir appDirObj(appDir);
    if (appDirObj.cdUp() && appDirObj.cdUp() && appDirObj.cdUp()) {
        possibleConfigPaths << appDirObj.absoluteFilePath("config/" + fileName);
    }
    
    // 4. Try source directory (for development builds) - PRIORITY 4
    possibleConfigPaths << QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../../../config/" + fileName);
    
    qDebug() << "Searching for config file:" << fileName;
    qDebug() << "Possible paths (in priority order):" << possibleConfigPaths;
    
    // Find the first valid config file
    for (const QString &path : possibleConfigPaths) {
        if (QFile::exists(path)) {
            qDebug() << "Found config file at:" << path;
            return path;
        }
    }
    
    qWarning() << "Config file not found in any of these locations:" << possibleConfigPaths;
    return QString();
}
