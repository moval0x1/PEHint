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
    m_importDetails.clear();
    m_exports.clear();
    m_exportDetails.clear();
    m_resourceTypes.clear();
    m_resources.clear();
    m_debugInfo.clear();
    m_debugDetails.clear();
    m_tlsInfo.clear();
    m_tlsDetails.clear();
    m_loadConfigInfo.clear();
    m_loadConfigDetails.clear();
    m_exceptionInfo.clear();
    m_exceptionDetails.clear();
    m_certificateInfo.clear();
    m_certificateDetails.clear();
    m_relocationInfo.clear();
    m_relocationDetails.clear();
    m_architectureInfo.clear();
    m_architectureDetails.clear();
    m_globalPointerInfo.clear();
    m_globalPointerDetails.clear();
    m_boundImportInfo.clear();
    m_boundImportDetails.clear();
    m_iatInfo.clear();
    m_iatDetails.clear();
    m_delayImportInfo.clear();
    m_delayImportDetails.clear();
    m_comRuntimeInfo.clear();
    m_comRuntimeDetails.clear();
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

void PEDataModel::setImportDetails(const QMap<QString, QList<QString>> &details)
{
    m_importDetails = details;
}

QStringList PEDataModel::getImports() const
{
    return m_imports;
}

QMap<QString, QList<QString>> PEDataModel::getImportDetails() const
{
    return m_importDetails;
}

void PEDataModel::setExports(const QStringList &exports)
{
    m_exports = exports;
}

void PEDataModel::setExportDetails(const QStringList &details)
{
    m_exportDetails = details;
}

QStringList PEDataModel::getExports() const
{
    return m_exports;
}

QStringList PEDataModel::getExportDetails() const
{
    return m_exportDetails;
}

// Resources
void PEDataModel::setResourceTypes(const QStringList &types)
{
    m_resourceTypes = types;
}

void PEDataModel::setResources(const QMap<QString, QMap<QString, QString>> &resources)
{
    m_resources = resources;
}

QStringList PEDataModel::getResourceTypes() const
{
    return m_resourceTypes;
}

QMap<QString, QMap<QString, QString>> PEDataModel::getResources() const
{
    return m_resources;
}

// Debug info
void PEDataModel::setDebugInfo(const QStringList &info)
{
    m_debugInfo = info;
}

void PEDataModel::setDebugDetails(const QMap<QString, QString> &details)
{
    m_debugDetails = details;
}

QStringList PEDataModel::getDebugInfo() const
{
    return m_debugInfo;
}

QMap<QString, QString> PEDataModel::getDebugDetails() const
{
    return m_debugDetails;
}

// TLS info
void PEDataModel::setTLSInfo(const QStringList &info)
{
    m_tlsInfo = info;
}

void PEDataModel::setTLSDetails(const QMap<QString, QString> &details)
{
    m_tlsDetails = details;
}

QStringList PEDataModel::getTLSInfo() const
{
    return m_tlsInfo;
}

QMap<QString, QString> PEDataModel::getTLSDetails() const
{
    return m_tlsDetails;
}

// Load Configuration info
void PEDataModel::setLoadConfigInfo(const QStringList &info)
{
    m_loadConfigInfo = info;
}

void PEDataModel::setLoadConfigDetails(const QMap<QString, QString> &details)
{
    m_loadConfigDetails = details;
}

QStringList PEDataModel::getLoadConfigInfo() const
{
    return m_loadConfigInfo;
}

QMap<QString, QString> PEDataModel::getLoadConfigDetails() const
{
    return m_loadConfigDetails;
}

// Exception info
void PEDataModel::setExceptionInfo(const QStringList &info)
{
    m_exceptionInfo = info;
}

void PEDataModel::setExceptionDetails(const QMap<QString, QString> &details)
{
    m_exceptionDetails = details;
}

QStringList PEDataModel::getExceptionInfo() const
{
    return m_exceptionInfo;
}

QMap<QString, QString> PEDataModel::getExceptionDetails() const
{
    return m_exceptionDetails;
}

// Certificate info
void PEDataModel::setCertificateInfo(const QStringList &info)
{
    m_certificateInfo = info;
}

void PEDataModel::setCertificateDetails(const QMap<QString, QString> &details)
{
    m_certificateDetails = details;
}

QStringList PEDataModel::getCertificateInfo() const
{
    return m_certificateInfo;
}

QMap<QString, QString> PEDataModel::getCertificateDetails() const
{
    return m_certificateDetails;
}

// Relocation info
void PEDataModel::setRelocationInfo(const QStringList &info)
{
    m_relocationInfo = info;
}

void PEDataModel::setRelocationDetails(const QMap<QString, QString> &details)
{
    m_relocationDetails = details;
}

QStringList PEDataModel::getRelocationInfo() const
{
    return m_relocationInfo;
}

QMap<QString, QString> PEDataModel::getRelocationDetails() const
{
    return m_relocationDetails;
}

// Architecture info
void PEDataModel::setArchitectureInfo(const QStringList &info)
{
    m_architectureInfo = info;
}

void PEDataModel::setArchitectureDetails(const QMap<QString, QString> &details)
{
    m_architectureDetails = details;
}

QStringList PEDataModel::getArchitectureInfo() const
{
    return m_architectureInfo;
}

QMap<QString, QString> PEDataModel::getArchitectureDetails() const
{
    return m_architectureDetails;
}

// Global Pointer info
void PEDataModel::setGlobalPointerInfo(const QStringList &info)
{
    m_globalPointerInfo = info;
}

void PEDataModel::setGlobalPointerDetails(const QMap<QString, QString> &details)
{
    m_globalPointerDetails = details;
}

QStringList PEDataModel::getGlobalPointerInfo() const
{
    return m_globalPointerInfo;
}

QMap<QString, QString> PEDataModel::getGlobalPointerDetails() const
{
    return m_globalPointerDetails;
}

// Bound Import info
void PEDataModel::setBoundImportInfo(const QStringList &info)
{
    m_boundImportInfo = info;
}

void PEDataModel::setBoundImportDetails(const QMap<QString, QString> &details)
{
    m_boundImportDetails = details;
}

QStringList PEDataModel::getBoundImportInfo() const
{
    return m_boundImportInfo;
}

QMap<QString, QString> PEDataModel::getBoundImportDetails() const
{
    return m_boundImportDetails;
}

// IAT info
void PEDataModel::setIATInfo(const QStringList &info)
{
    m_iatInfo = info;
}

void PEDataModel::setIATDetails(const QMap<QString, QString> &details)
{
    m_iatDetails = details;
}

QStringList PEDataModel::getIATInfo() const
{
    return m_iatInfo;
}

QMap<QString, QString> PEDataModel::getIATDetails() const
{
    return m_iatDetails;
}

// Delay Import info
void PEDataModel::setDelayImportInfo(const QStringList &info)
{
    m_delayImportInfo = info;
}

void PEDataModel::setDelayImportDetails(const QMap<QString, QString> &details)
{
    m_delayImportDetails = details;
}

QStringList PEDataModel::getDelayImportInfo() const
{
    return m_delayImportInfo;
}

QMap<QString, QString> PEDataModel::getDelayImportDetails() const
{
    return m_delayImportDetails;
}

// COM+ Runtime info
void PEDataModel::setCOMRuntimeInfo(const QStringList &info)
{
    m_comRuntimeInfo = info;
}

void PEDataModel::setCOMRuntimeDetails(const QMap<QString, QString> &details)
{
    m_comRuntimeDetails = details;
}

QStringList PEDataModel::getCOMRuntimeInfo() const
{
    return m_comRuntimeInfo;
}

QMap<QString, QString> PEDataModel::getCOMRuntimeDetails() const
{
    return m_comRuntimeDetails;
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
    m_importDetails.clear();
    m_exports.clear();
    m_exportDetails.clear();
    m_resourceTypes.clear();
    m_resources.clear();
    m_debugInfo.clear();
    m_debugDetails.clear();
    
    // Clear new data fields
    m_tlsInfo.clear();
    m_tlsDetails.clear();
    m_loadConfigInfo.clear();
    m_loadConfigDetails.clear();
    m_exceptionInfo.clear();
    m_exceptionDetails.clear();
    m_certificateInfo.clear();
    m_certificateDetails.clear();
    m_relocationInfo.clear();
    m_relocationDetails.clear();
    m_architectureInfo.clear();
    m_architectureDetails.clear();
    m_globalPointerInfo.clear();
    m_globalPointerDetails.clear();
    m_boundImportInfo.clear();
    m_boundImportDetails.clear();
    m_iatInfo.clear();
    m_iatDetails.clear();
    m_delayImportInfo.clear();
    m_delayImportDetails.clear();
    m_comRuntimeInfo.clear();
    m_comRuntimeDetails.clear();
}
