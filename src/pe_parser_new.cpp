#include "pe_parser_new.h"
#include "pe_utils.h"
#include "language_manager.h"
#include <QDebug>
#include <QFileInfo>
#include <QTreeWidgetItem>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>

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

QString PEParserNew::getFileSize() const
{
    qint64 size = m_dataModel.getFileSize();
    if (size < 1024) {
        return QString("%1 bytes").arg(size);
    } else if (size < 1024 * 1024) {
        return QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
    } else {
        return QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
    }
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
    
    m_dataModel.setDOSHeader(dosHeader);
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
    
    // Parse file header
    if (peOffset + sizeof(IMAGE_FILE_HEADER) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_pe_header_beyond"));
        return false;
    }
    
    const IMAGE_FILE_HEADER *fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_fileData.data() + peOffset
    );
    m_dataModel.setFileHeader(fileHeader);
    
    // Parse optional header
    quint32 optionalHeaderOffset = peOffset + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeaderOffset + fileHeader->SizeOfOptionalHeader > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_optional_header_beyond"));
        return false;
    }
    
    const IMAGE_OPTIONAL_HEADER *optionalHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER*>(
        m_fileData.data() + optionalHeaderOffset
    );
    
    if (!PEUtils::isValidOptionalHeaderMagic(optionalHeader->Magic)) {
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
    
    // Calculate section table offset (Microsoft PE Format compliant)
    quint32 sectionTableOffset = PEUtils::calculateSectionTableOffset(
        dosHeader->e_lfanew, 
        fileHeader->SizeOfOptionalHeader
    );
    
    if (sectionTableOffset + (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_section_table_beyond"));
        return false;
    }
    
    // Parse each section header
    for (quint16 i = 0; i < fileHeader->NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER *section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            m_fileData.data() + sectionTableOffset + (i * sizeof(IMAGE_SECTION_HEADER))
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
    
    // Calculate data directory offset (Microsoft PE Format compliant)
    quint32 dataDirectoryOffset = PEUtils::calculateDataDirectoryOffset(
        dosHeader->e_lfanew + sizeof(IMAGE_FILE_HEADER),
        fileHeader->SizeOfOptionalHeader,
        0
    );
    
    // Use the specialized data directory parser
    return m_dataDirectoryParser.parseDataDirectories(optionalHeader, dataDirectoryOffset, m_dataModel);
}

quint32 PEParserNew::rvaToFileOffset(quint32 rva)
{
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_dataModel.getSections();
    
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
    
    m_dataModel.setDOSHeader(&dosHeader);
    
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
    
    m_dataModel.setFileHeader(&fileHeader);
    
    emit parsingProgress(30, LANG("UI/progress_reading_optional_header"));
    
    // Read optional header
    IMAGE_OPTIONAL_HEADER optionalHeader;
    if (m_file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(IMAGE_OPTIONAL_HEADER)) != sizeof(IMAGE_OPTIONAL_HEADER)) {
        emit errorOccurred(LANG("UI/error_reading_optional_header"));
        return false;
    }
    
    if (!PEUtils::isValidOptionalHeaderMagic(optionalHeader.Magic)) {
        emit errorOccurred(LANG("UI/error_invalid_optional_magic"));
        return false;
    }
    
    m_dataModel.setOptionalHeader(&optionalHeader);
    
    emit parsingProgress(40, LANG("UI/progress_reading_sections"));
    
    // Read section table (typically < 1KB even for large files)
    quint32 sectionTableOffset = dosHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
    if (!m_file.seek(sectionTableOffset)) {
        emit errorOccurred(LANG("UI/error_seeking_section_table"));
        return false;
    }
    
    // Read each section header
    for (quint16 i = 0; i < fileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        if (m_file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER)) != sizeof(IMAGE_SECTION_HEADER)) {
            emit errorOccurred(LANG("UI/error_reading_section_header"));
            return false;
        }
        m_dataModel.addSection(&sectionHeader);
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
    // Load explanations from the JSON file in the binary directory
    QString appDir = QCoreApplication::applicationDirPath();
    QString explanationsPath = QDir(appDir).absoluteFilePath("config/explanations.json");
    QFile explanationsFile(explanationsPath);
    if (explanationsFile.open(QIODevice::ReadOnly)) {
        QJsonDocument doc = QJsonDocument::fromJson(explanationsFile.readAll());
        QJsonObject root = doc.object();
        
        // Search for the field in the explanations
        for (const QString &category : root.keys()) {
            QJsonObject categoryObj = root[category].toObject();
            if (categoryObj.contains(fieldName)) {
                QJsonObject fieldObj = categoryObj[fieldName].toObject();
                QString description = fieldObj["description"].toString();
                QString purpose = fieldObj["purpose"].toString();
                QString securityNotes = fieldObj["security_notes"].toString();
                
                QString explanation = QString("%1\n\nPurpose: %2\n\nSecurity Notes: %3")
                                   .arg(description)
                                   .arg(purpose)
                                   .arg(securityNotes);
                
                return explanation;
            }
        }
    }
    
    // Fallback to placeholder if field not found
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
    fieldOffsets["e_magic"] = QPair<quint32, quint32>(0, sizeof(quint16));
    fieldOffsets["e_cblp"] = QPair<quint32, quint32>(2, sizeof(quint16));
    fieldOffsets["e_cp"] = QPair<quint32, quint32>(4, sizeof(quint16));
    fieldOffsets["e_crlc"] = QPair<quint32, quint32>(6, sizeof(quint16));
    fieldOffsets["e_cparhdr"] = QPair<quint32, quint32>(8, sizeof(quint16));
    fieldOffsets["e_minalloc"] = QPair<quint32, quint32>(10, sizeof(quint16));
    fieldOffsets["e_maxalloc"] = QPair<quint32, quint32>(12, sizeof(quint16));
    fieldOffsets["e_ss"] = QPair<quint32, quint32>(14, sizeof(quint16));
    fieldOffsets["e_sp"] = QPair<quint32, quint32>(16, sizeof(quint16));
    fieldOffsets["e_csum"] = QPair<quint32, quint32>(18, sizeof(quint16));
    fieldOffsets["e_ip"] = QPair<quint32, quint32>(20, sizeof(quint16));
    fieldOffsets["e_cs"] = QPair<quint32, quint32>(22, sizeof(quint16));
    fieldOffsets["e_lfarlc"] = QPair<quint32, quint32>(24, sizeof(quint16));
    fieldOffsets["e_ovno"] = QPair<quint32, quint32>(26, sizeof(quint16));
    fieldOffsets["e_res"] = QPair<quint32, quint32>(28, sizeof(quint16) * 4);
    fieldOffsets["e_oemid"] = QPair<quint32, quint32>(36, sizeof(quint16));
    fieldOffsets["e_oeminfo"] = QPair<quint32, quint32>(38, sizeof(quint16));
    fieldOffsets["e_res2"] = QPair<quint32, quint32>(40, sizeof(quint16) * 10);
    fieldOffsets["e_lfanew"] = QPair<quint32, quint32>(60, sizeof(quint32));
    
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
    dosHeaderItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", "64"));
    
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    if (dosHeader) {
        addDOSHeaderFields(dosHeaderItem, dosHeader);
    }
    treeItems.append(dosHeaderItem);
    
    // Create PE Header section
    QTreeWidgetItem *peHeaderItem = new QTreeWidgetItem();
    peHeaderItem->setText(0, LANG("UI/pe_structure_pe_header"));
    peHeaderItem->setText(1, "");
    peHeaderItem->setText(2, QString("0x%1").arg(dosHeader ? dosHeader->e_lfanew : 0, 8, 16, QChar('0')).toUpper());
    peHeaderItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", "24"));
    
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    if (fileHeader) {
        addPEHeaderFields(peHeaderItem, fileHeader);
    }
    treeItems.append(peHeaderItem);
    
    // Create Optional Header section
    QTreeWidgetItem *optionalHeaderItem = new QTreeWidgetItem();
    optionalHeaderItem->setText(0, LANG("UI/pe_structure_optional_header"));
    optionalHeaderItem->setText(1, "");
    optionalHeaderItem->setText(2, QString("0x%1").arg((dosHeader ? dosHeader->e_lfanew : 0) + 24, 8, 16, QChar('0')).toUpper());
    optionalHeaderItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", "224"));
    
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    if (optionalHeader) {
        addOptionalHeaderFields(optionalHeaderItem, optionalHeader);
    }
    treeItems.append(optionalHeaderItem);
    
    // Create Sections section
    QTreeWidgetItem *sectionsItem = new QTreeWidgetItem();
    sectionsItem->setText(0, LANG("UI/pe_structure_sections"));
    sectionsItem->setText(1, "");
    sectionsItem->setText(2, QString("0x%1").arg((dosHeader ? dosHeader->e_lfanew : 0) + 24 + (fileHeader ? fileHeader->SizeOfOptionalHeader : 0), 8, 16, QChar('0')).toUpper());
    sectionsItem->setText(3, LANG_PARAM("UI/pe_structure_entries_format", "count", QString::number(m_dataModel.getSections().size())));
    
    addSectionFields(sectionsItem);
    treeItems.append(sectionsItem);
    
    // Create Data Directories section
    QTreeWidgetItem *dataDirsItem = new QTreeWidgetItem();
    dataDirsItem->setText(0, LANG("UI/pe_structure_data_directories"));
    dataDirsItem->setText(1, "");
    dataDirsItem->setText(2, "Variable");
    dataDirsItem->setText(3, LANG_PARAM("UI/pe_structure_entries_format", "count", "16"));
    
    addDataDirectoryFields(dataDirsItem);
    treeItems.append(dataDirsItem);
    
    return treeItems;
}

void PEParserNew::addDOSHeaderFields(QTreeWidgetItem *parent, const IMAGE_DOS_HEADER *dosHeader)
{
    // Add DOS header fields
    addTreeField(parent, "e_magic", QString("0x%1").arg(dosHeader->e_magic, 4, 16, QChar('0')).toUpper(), 0, sizeof(quint16));
    addTreeField(parent, "e_cblp", QString::number(dosHeader->e_cblp), 2, sizeof(quint16));
    addTreeField(parent, "e_cp", QString::number(dosHeader->e_cp), 4, sizeof(quint16));
    addTreeField(parent, "e_crlc", QString::number(dosHeader->e_crlc), 6, sizeof(quint16));
    addTreeField(parent, "e_cparhdr", QString::number(dosHeader->e_cparhdr), 8, sizeof(quint16));
    addTreeField(parent, "e_minalloc", QString::number(dosHeader->e_minalloc), 10, sizeof(quint16));
    addTreeField(parent, "e_maxalloc", QString::number(dosHeader->e_maxalloc), 12, sizeof(quint16));
    addTreeField(parent, "e_ss", QString::number(dosHeader->e_ss), 14, sizeof(quint16));
    addTreeField(parent, "e_sp", QString::number(dosHeader->e_sp), 16, sizeof(quint16));
    addTreeField(parent, "e_csum", QString::number(dosHeader->e_csum), 18, sizeof(quint16));
    addTreeField(parent, "e_ip", QString::number(dosHeader->e_ip), 20, sizeof(quint16));
    addTreeField(parent, "e_cs", QString::number(dosHeader->e_cs), 22, sizeof(quint16));
    addTreeField(parent, "e_lfarlc", QString::number(dosHeader->e_lfarlc), 24, sizeof(quint16));
    addTreeField(parent, "e_ovno", QString::number(dosHeader->e_ovno), 26, sizeof(quint16));
    addTreeField(parent, "e_lfanew", QString("0x%1").arg(dosHeader->e_lfanew, 8, 16, QChar('0')).toUpper(), 60, sizeof(quint32));
}

void PEParserNew::addPEHeaderFields(QTreeWidgetItem *parent, const IMAGE_FILE_HEADER *fileHeader)
{
    // Add PE header fields
    addTreeField(parent, "Machine", QString("0x%1").arg(fileHeader->Machine, 4, 16, QChar('0')).toUpper(), 0, sizeof(quint16));
    addTreeField(parent, "NumberOfSections", QString::number(fileHeader->NumberOfSections), 2, sizeof(quint16));
    addTreeField(parent, "TimeDateStamp", QString("0x%1").arg(fileHeader->TimeDateStamp, 8, 16, QChar('0')).toUpper(), 4, sizeof(quint32));
    addTreeField(parent, "PointerToSymbolTable", QString("0x%1").arg(fileHeader->PointerToSymbolTable, 8, 16, QChar('0')).toUpper(), 8, sizeof(quint32));
    addTreeField(parent, "NumberOfSymbols", QString::number(fileHeader->NumberOfSymbols), 12, sizeof(quint32));
    addTreeField(parent, "SizeOfOptionalHeader", QString::number(fileHeader->SizeOfOptionalHeader), 16, sizeof(quint16));
    addTreeField(parent, "Characteristics", QString("0x%1").arg(fileHeader->Characteristics, 4, 16, QChar('0')).toUpper(), 18, sizeof(quint16));
}

void PEParserNew::addOptionalHeaderFields(QTreeWidgetItem *parent, const IMAGE_OPTIONAL_HEADER *optionalHeader)
{
    // Add optional header fields
    addTreeField(parent, "Magic", QString("0x%1").arg(optionalHeader->Magic, 4, 16, QChar('0')).toUpper(), 0, sizeof(quint16));
    addTreeField(parent, "MajorLinkerVersion", QString::number(optionalHeader->MajorLinkerVersion), 2, sizeof(quint8));
    addTreeField(parent, "MinorLinkerVersion", QString::number(optionalHeader->MinorLinkerVersion), 3, sizeof(quint8));
    addTreeField(parent, "SizeOfCode", QString::number(optionalHeader->SizeOfCode), 4, sizeof(quint32));
    addTreeField(parent, "SizeOfInitializedData", QString::number(optionalHeader->SizeOfInitializedData), 8, sizeof(quint32));
    addTreeField(parent, "SizeOfUninitializedData", QString::number(optionalHeader->SizeOfUninitializedData), 12, sizeof(quint32));
    addTreeField(parent, "AddressOfEntryPoint", QString("0x%1").arg(optionalHeader->AddressOfEntryPoint, 8, 16, QChar('0')).toUpper(), 16, sizeof(quint32));
    addTreeField(parent, "BaseOfCode", QString("0x%1").arg(optionalHeader->BaseOfCode, 8, 16, QChar('0')).toUpper(), 20, sizeof(quint32));
    addTreeField(parent, "ImageBase", QString("0x%1").arg(optionalHeader->ImageBase, 16, 16, QChar('0')).toUpper(), 24, sizeof(quint64));
    addTreeField(parent, "SectionAlignment", QString::number(optionalHeader->SectionAlignment), 32, sizeof(quint32));
    addTreeField(parent, "FileAlignment", QString::number(optionalHeader->FileAlignment), 36, sizeof(quint32));
    addTreeField(parent, "MajorOperatingSystemVersion", QString::number(optionalHeader->MajorOperatingSystemVersion), 40, sizeof(quint16));
    addTreeField(parent, "MinorOperatingSystemVersion", QString::number(optionalHeader->MinorOperatingSystemVersion), 42, sizeof(quint16));
    addTreeField(parent, "MajorImageVersion", QString::number(optionalHeader->MajorImageVersion), 44, sizeof(quint16));
    addTreeField(parent, "MinorImageVersion", QString::number(optionalHeader->MinorImageVersion), 46, sizeof(quint16));
    addTreeField(parent, "MajorSubsystemVersion", QString::number(optionalHeader->MajorSubsystemVersion), 48, sizeof(quint16));
    addTreeField(parent, "MinorSubsystemVersion", QString::number(optionalHeader->MinorSubsystemVersion), 50, sizeof(quint16));
    addTreeField(parent, "Win32VersionValue", QString("0x%1").arg(optionalHeader->Win32VersionValue, 8, 16, QChar('0')).toUpper(), 52, sizeof(quint32));
    addTreeField(parent, "SizeOfImage", QString::number(optionalHeader->SizeOfImage), 56, sizeof(quint32));
    addTreeField(parent, "SizeOfHeaders", QString::number(optionalHeader->SizeOfHeaders), 60, sizeof(quint32));
    addTreeField(parent, "CheckSum", QString("0x%1").arg(optionalHeader->CheckSum, 8, 16, QChar('0')).toUpper(), 64, sizeof(quint32));
    addTreeField(parent, "Subsystem", QString::number(optionalHeader->Subsystem), 68, sizeof(quint16));
    addTreeField(parent, "DllCharacteristics", QString("0x%1").arg(optionalHeader->DllCharacteristics, 4, 16, QChar('0')).toUpper(), 70, sizeof(quint16));
    addTreeField(parent, "SizeOfStackReserve", QString::number(optionalHeader->SizeOfStackReserve), 72, sizeof(quint64));
    addTreeField(parent, "SizeOfStackCommit", QString::number(optionalHeader->SizeOfStackCommit), 80, sizeof(quint64));
    addTreeField(parent, "SizeOfHeapReserve", QString::number(optionalHeader->SizeOfHeapReserve), 88, sizeof(quint64));
    addTreeField(parent, "SizeOfHeapCommit", QString::number(optionalHeader->SizeOfHeapCommit), 96, sizeof(quint64));
    addTreeField(parent, "LoaderFlags", QString("0x%1").arg(optionalHeader->LoaderFlags, 8, 16, QChar('0')).toUpper(), 104, sizeof(quint32));
    addTreeField(parent, "NumberOfRvaAndSizes", QString::number(optionalHeader->NumberOfRvaAndSizes), 108, sizeof(quint32));
}

void PEParserNew::addSectionFields(QTreeWidgetItem *parent)
{
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_dataModel.getSections();
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
                sectionName = QString("0x%1").arg(QString(nameBytes.toHex()).toUpper());
            }
            QMap<QString, QString> params;
            params["number"] = QString::number(i + 1);
            params["name"] = sectionName;
            sectionItem->setText(0, LANG_PARAMS("UI/pe_structure_section_format", params));
            sectionItem->setText(1, "");
            sectionItem->setText(2, QString("0x%1").arg(section->PointerToRawData, 8, 16, QChar('0')).toUpper());
            sectionItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", QString::number(section->SizeOfRawData)));
            
            // Add section details
            addTreeField(sectionItem, "VirtualAddress", QString("0x%1").arg(section->VirtualAddress, 8, 16, QChar('0')).toUpper(), 0, sizeof(quint32));
            addTreeField(sectionItem, "SizeOfRawData", QString::number(section->SizeOfRawData), 4, sizeof(quint32));
            addTreeField(sectionItem, "PointerToRawData", QString("0x%1").arg(section->PointerToRawData, 8, 16, QChar('0')).toUpper(), 8, sizeof(quint32));
            addTreeField(sectionItem, "PointerToRelocations", QString("0x%1").arg(section->PointerToRelocations, 8, 16, QChar('0')).toUpper(), 12, sizeof(quint32));
            // Note: PointerToLineNumbers and NumberOfLineNumbers are deprecated in modern PE format
            addTreeField(sectionItem, "PointerToLineNumbers", LANG("UI/field_deprecated_pointer"), 16, sizeof(quint32));
            addTreeField(sectionItem, "NumberOfRelocations", QString::number(section->NumberOfRelocations), 20, sizeof(quint16));
            addTreeField(sectionItem, "NumberOfLineNumbers", LANG("UI/field_deprecated_count"), 22, sizeof(quint16));
            addTreeField(sectionItem, "Characteristics", QString("0x%1").arg(section->Characteristics, 8, 16, QChar('0')).toUpper(), 24, sizeof(quint32));
        }
    }
}

void PEParserNew::addDataDirectoryFields(QTreeWidgetItem *parent)
{
    // Add data directory entries
    QStringList dirNames = {LANG("UI/data_dir_export"), LANG("UI/data_dir_import"), LANG("UI/data_dir_resource"), LANG("UI/data_dir_exception"),
                           LANG("UI/data_dir_certificate"), LANG("UI/data_dir_base_relocation"), LANG("UI/data_dir_debug"), LANG("UI/data_dir_architecture"),
                           LANG("UI/data_dir_global_pointer"), LANG("UI/data_dir_tls"), LANG("UI/data_dir_load_config"), LANG("UI/data_dir_bound_import"),
                           LANG("UI/data_dir_iat"), LANG("UI/data_dir_delay_import"), LANG("UI/data_dir_com_runtime"), LANG("UI/data_dir_reserved")};
    
    for (int i = 0; i < dirNames.size(); ++i) {
        QTreeWidgetItem *dirItem = new QTreeWidgetItem(parent);
        dirItem->setText(0, dirNames[i]);
        dirItem->setText(1, "");
        dirItem->setText(2, LANG_PARAM("UI/data_directory_format", "number", QString::number(i)));
        dirItem->setText(3, LANG("UI/data_directory_size_variable"));
    }
}

void PEParserNew::addTreeField(QTreeWidgetItem *parent, const QString &name, const QString &value, quint32 offset, quint32 size)
{
    QTreeWidgetItem *fieldItem = new QTreeWidgetItem(parent);
    fieldItem->setText(0, name);
    fieldItem->setText(1, value);
    fieldItem->setText(2, QString("0x%1").arg(offset, 8, 16, QChar('0')).toUpper());
    fieldItem->setText(3, LANG_PARAM("UI/pe_structure_size_format", "size", QString::number(size)));
}
