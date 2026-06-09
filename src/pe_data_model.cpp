#include "pe_data_model.h"

PEDataModel::PEDataModel()
    : m_filePath("")
    , m_fileSize(0)
    , m_isValid(false)
    , m_dosHeader(nullptr)
    , m_fileHeader(nullptr)
    , m_optionalHeader(nullptr)
{
    // Initialize all data containers
    m_sections.clear();
    m_imports.clear();
    m_importFunctionDetails.clear();
    m_exportFunctions.clear();
    m_resourceEntries.clear();
    for (int i = 0; i < 16; ++i) {
        m_parsedDirectoryFields[i].clear();
    }
    m_dataDirectoryRecords.clear();
    m_overlayInfo = PEOverlayInfo{};
    m_entropySummary = PEEntropySummary{};
    m_pdbInfo = PEPdbInfo{};
    m_versionInfo = PEVersionInfo{};
    m_analysisMetadata = PEAnalysisMetadata{};
    m_fileMetrics = PEFileMetrics{};
    m_contentScan = PEContentScan{};
}

PEDataModel::~PEDataModel()
{
    clear();
}

// File information
void PEDataModel::setFilePath(const QString &path)
{
    m_filePath = path;
}

QString PEDataModel::getFilePath() const
{
    return m_filePath;
}

void PEDataModel::setFileSize(qint64 size)
{
    m_fileSize = size;
}

qint64 PEDataModel::getFileSize() const
{
    return m_fileSize;
}

// Header data
void PEDataModel::setDOSHeader(const IMAGE_DOS_HEADER *header)
{
    m_dosHeader = header;
}

void PEDataModel::setFileHeader(const IMAGE_FILE_HEADER *header)
{
    m_fileHeader = header;
}

void PEDataModel::setOptionalHeader(const IMAGE_OPTIONAL_HEADER *header)
{
    m_optionalHeader = header;
}

const IMAGE_DOS_HEADER* PEDataModel::getDOSHeader() const
{
    return m_dosHeader;
}

const IMAGE_FILE_HEADER* PEDataModel::getFileHeader() const
{
    return m_fileHeader;
}

const IMAGE_OPTIONAL_HEADER* PEDataModel::getOptionalHeader() const
{
    return m_optionalHeader;
}

// Sections
void PEDataModel::addSection(const IMAGE_SECTION_HEADER *section)
{
    m_sections.append(section);
}

const QList<const IMAGE_SECTION_HEADER*>& PEDataModel::getSections() const
{
    return m_sections;
}

// Imports/Exports
void PEDataModel::setImports(const QStringList &imports)
{
    m_imports = imports;
}

void PEDataModel::setImportFunctions(const QMap<QString, QList<ImportFunctionEntry>> &details)
{
    m_importFunctionDetails = details;
}

const QMap<QString, QList<PEDataModel::ImportFunctionEntry>>& PEDataModel::getImportFunctions() const
{
    return m_importFunctionDetails;
}

QStringList PEDataModel::getImports() const
{
    return m_imports;
}

void PEDataModel::setExportFunctions(const QList<ExportFunctionEntry> &functions)
{
    m_exportFunctions = functions;
}

const QList<PEDataModel::ExportFunctionEntry>& PEDataModel::getExportFunctions() const
{
    return m_exportFunctions;
}

// Resources
void PEDataModel::setResourceEntries(const QVector<PEResourceItem> &entries)
{
    m_resourceEntries = entries;
}

const QVector<PEResourceItem> &PEDataModel::getResourceEntries() const
{
    return m_resourceEntries;
}

void PEDataModel::setParsedDirectoryFields(int directoryIndex, const QVector<PEDataDirectoryField> &fields)
{
    if (directoryIndex >= 0 && directoryIndex < 16) {
        m_parsedDirectoryFields[directoryIndex] = fields;
    }
}

const QVector<PEDataDirectoryField> &PEDataModel::parsedDirectoryFields(int directoryIndex) const
{
    static const QVector<PEDataDirectoryField> kEmpty;
    if (directoryIndex >= 0 && directoryIndex < 16) {
        return m_parsedDirectoryFields[directoryIndex];
    }
    return kEmpty;
}

void PEDataModel::setDebugDirectoryEntries(const QVector<PEDebugDirectoryEntry> &entries)
{
    m_debugDirectoryEntries = entries;
}

const QVector<PEDebugDirectoryEntry> &PEDataModel::debugDirectoryEntries() const
{
    return m_debugDirectoryEntries;
}

void PEDataModel::setTlsDirectoryInfo(const PETlsDirectoryInfo &info)
{
    m_tlsDirectoryInfo = info;
}

const PETlsDirectoryInfo &PEDataModel::tlsDirectoryInfo() const
{
    return m_tlsDirectoryInfo;
}

void PEDataModel::setLoadConfigDirectoryInfo(const PELoadConfigDirectoryInfo &info)
{
    m_loadConfigDirectoryInfo = info;
}

const PELoadConfigDirectoryInfo &PEDataModel::loadConfigDirectoryInfo() const
{
    return m_loadConfigDirectoryInfo;
}

void PEDataModel::setOverlayInfo(const PEOverlayInfo &info)
{
    m_overlayInfo = info;
}

PEOverlayInfo PEDataModel::getOverlayInfo() const
{
    return m_overlayInfo;
}

void PEDataModel::setEntropySummary(const PEEntropySummary &summary)
{
    m_entropySummary = summary;
}

PEEntropySummary PEDataModel::getEntropySummary() const
{
    return m_entropySummary;
}

void PEDataModel::setPdbInfo(const PEPdbInfo &info)
{
    m_pdbInfo = info;
}

PEPdbInfo PEDataModel::getPdbInfo() const
{
    return m_pdbInfo;
}

void PEDataModel::setVersionInfo(const PEVersionInfo &info)
{
    m_versionInfo = info;
}

PEVersionInfo PEDataModel::getVersionInfo() const
{
    return m_versionInfo;
}

void PEDataModel::setAnalysisMetadata(const PEAnalysisMetadata &metadata)
{
    m_analysisMetadata = metadata;
}

PEAnalysisMetadata PEDataModel::getAnalysisMetadata() const
{
    return m_analysisMetadata;
}

void PEDataModel::setFileMetrics(const PEFileMetrics &metrics)
{
    m_fileMetrics = metrics;
}

PEFileMetrics PEDataModel::getFileMetrics() const
{
    return m_fileMetrics;
}

void PEDataModel::setContentScan(const PEContentScan &scan)
{
    m_contentScan = scan;
}

PEContentScan PEDataModel::getContentScan() const
{
    return m_contentScan;
}

void PEDataModel::setTlsCallbacksPresent(bool present)
{
    m_analysisMetadata.tlsCallbacksPresent = present;
}

void PEDataModel::setDelayImports(const QStringList &imports)
{
    m_delayImports = imports;
}

void PEDataModel::setDelayImportFunctions(const QMap<QString, QList<PEDataModel::ImportFunctionEntry>> &details)
{
    m_delayImportFunctionDetails = details;
}

QStringList PEDataModel::getDelayImports() const
{
    return m_delayImports;
}

const QMap<QString, QList<PEDataModel::ImportFunctionEntry>> &PEDataModel::getDelayImportFunctions() const
{
    return m_delayImportFunctionDetails;
}

double PEDataModel::sectionEntropy(const QString &sectionName) const
{
    for (const PESectionEntropy &se : m_entropySummary.sections) {
        if (se.sectionName.compare(sectionName, Qt::CaseInsensitive) == 0 && se.computed) {
            return se.entropy;
        }
    }
    return -1.0;
}

void PEDataModel::setDataDirectoryRecords(const QVector<PEDataDirectoryRecord> &records)
{
    m_dataDirectoryRecords = records;
}

const QVector<PEDataDirectoryRecord> &PEDataModel::getDataDirectoryRecords() const
{
    return m_dataDirectoryRecords;
}

// Validation
bool PEDataModel::isValid() const
{
    return m_isValid;
}

void PEDataModel::setValid(bool valid)
{
    m_isValid = valid;
}

// Clear all data
void PEDataModel::clear()
{
    m_filePath.clear();
    m_fileSize = 0;
    m_isValid = false;
    m_dosHeader = nullptr;
    m_fileHeader = nullptr;
    m_optionalHeader = nullptr;
    m_sections.clear();
    m_imports.clear();
    m_importFunctionDetails.clear();
    m_delayImports.clear();
    m_delayImportFunctionDetails.clear();
    m_exportFunctions.clear();
    m_resourceEntries.clear();
    for (int i = 0; i < 16; ++i) {
        m_parsedDirectoryFields[i].clear();
    }
    m_debugDirectoryEntries.clear();
    m_tlsDirectoryInfo = PETlsDirectoryInfo{};
    m_loadConfigDirectoryInfo = PELoadConfigDirectoryInfo{};
    m_dataDirectoryRecords.clear();
    m_overlayInfo = PEOverlayInfo{};
    m_entropySummary = PEEntropySummary{};
    m_pdbInfo = PEPdbInfo{};
    m_versionInfo = PEVersionInfo{};
    m_analysisMetadata = PEAnalysisMetadata{};
    m_fileMetrics = PEFileMetrics{};
    m_contentScan = PEContentScan{};
}
