#ifndef PE_DATA_MODEL_H
#define PE_DATA_MODEL_H

#include "pe_structures.h"
#include <QString>
#include <QList>
#include <QMap>

class PEDataModel
{
public:
    PEDataModel();
    ~PEDataModel();
    
    // File information
    void setFilePath(const QString &path);
    QString getFilePath() const;
    void setFileSize(qint64 size);
    qint64 getFileSize() const;
    
    // Header data
    void setDOSHeader(const IMAGE_DOS_HEADER *header);
    void setFileHeader(const IMAGE_FILE_HEADER *header);
    void setOptionalHeader(const IMAGE_OPTIONAL_HEADER *header);
    
    const IMAGE_DOS_HEADER* getDOSHeader() const;
    const IMAGE_FILE_HEADER* getFileHeader() const;
    const IMAGE_OPTIONAL_HEADER* getOptionalHeader() const;
    
    // Sections
    void addSection(const IMAGE_SECTION_HEADER *section);
    const QList<const IMAGE_SECTION_HEADER*>& getSections() const;
    
    // Imports/Exports
    void setImports(const QStringList &imports);
    void setImportDetails(const QMap<QString, QList<QString>> &details);
    QStringList getImports() const;
    QMap<QString, QList<QString>> getImportDetails() const;
    
    void setExports(const QStringList &exports);
    void setExportDetails(const QStringList &details);
    QStringList getExports() const;
    QStringList getExportDetails() const;
    
    // Resources
    void setResourceTypes(const QStringList &types);
    void setResources(const QMap<QString, QMap<QString, QString>> &resources);
    QStringList getResourceTypes() const;
    QMap<QString, QMap<QString, QString>> getResources() const;
    
    // Debug info
    void setDebugInfo(const QStringList &info);
    void setDebugDetails(const QMap<QString, QString> &details);
    QStringList getDebugInfo() const;
    QMap<QString, QString> getDebugDetails() const;
    
    // TLS info
    void setTLSInfo(const QStringList &info);
    void setTLSDetails(const QMap<QString, QString> &details);
    QStringList getTLSInfo() const;
    QMap<QString, QString> getTLSDetails() const;
    
    // Load Configuration info
    void setLoadConfigInfo(const QStringList &info);
    void setLoadConfigDetails(const QMap<QString, QString> &details);
    QStringList getLoadConfigInfo() const;
    QMap<QString, QString> getLoadConfigDetails() const;
    
    // Exception info
    void setExceptionInfo(const QStringList &info);
    void setExceptionDetails(const QMap<QString, QString> &details);
    QStringList getExceptionInfo() const;
    QMap<QString, QString> getExceptionDetails() const;
    
    // Certificate info
    void setCertificateInfo(const QStringList &info);
    void setCertificateDetails(const QMap<QString, QString> &details);
    QStringList getCertificateInfo() const;
    QMap<QString, QString> getCertificateDetails() const;
    
    // Relocation info
    void setRelocationInfo(const QStringList &info);
    void setRelocationDetails(const QMap<QString, QString> &details);
    QStringList getRelocationInfo() const;
    QMap<QString, QString> getRelocationDetails() const;
    
    // Architecture info
    void setArchitectureInfo(const QStringList &info);
    void setArchitectureDetails(const QMap<QString, QString> &details);
    QStringList getArchitectureInfo() const;
    QMap<QString, QString> getArchitectureDetails() const;
    
    // Global Pointer info
    void setGlobalPointerInfo(const QStringList &info);
    void setGlobalPointerDetails(const QMap<QString, QString> &details);
    QStringList getGlobalPointerInfo() const;
    QMap<QString, QString> getGlobalPointerDetails() const;
    
    // Bound Import info
    void setBoundImportInfo(const QStringList &info);
    void setBoundImportDetails(const QMap<QString, QString> &details);
    QStringList getBoundImportInfo() const;
    QMap<QString, QString> getBoundImportDetails() const;
    
    // IAT info
    void setIATInfo(const QStringList &info);
    void setIATDetails(const QMap<QString, QString> &details);
    QStringList getIATInfo() const;
    QMap<QString, QString> getIATDetails() const;
    
    // Delay Import info
    void setDelayImportInfo(const QStringList &info);
    void setDelayImportDetails(const QMap<QString, QString> &details);
    QStringList getDelayImportInfo() const;
    QMap<QString, QString> getDelayImportDetails() const;
    
    // COM+ Runtime info
    void setCOMRuntimeInfo(const QStringList &info);
    void setCOMRuntimeDetails(const QMap<QString, QString> &details);
    QStringList getCOMRuntimeInfo() const;
    QMap<QString, QString> getCOMRuntimeDetails() const;
    
    // Validation
    bool isValid() const;
    void setValid(bool valid);
    
    // Clear all data
    void clear();
    
private:
    // File information
    QString m_filePath;
    qint64 m_fileSize;
    bool m_isValid;
    
    // Headers
    const IMAGE_DOS_HEADER *m_dosHeader;
    const IMAGE_FILE_HEADER *m_fileHeader;
    const IMAGE_OPTIONAL_HEADER *m_optionalHeader;
    
    // Sections
    QList<const IMAGE_SECTION_HEADER*> m_sections;
    
    // Imports/Exports
    QStringList m_imports;
    QMap<QString, QList<QString>> m_importDetails;
    QStringList m_exports;
    QStringList m_exportDetails;
    
    // Resources
    QStringList m_resourceTypes;
    QMap<QString, QMap<QString, QString>> m_resources;
    
    // Debug info
    QStringList m_debugInfo;
    QMap<QString, QString> m_debugDetails;
    
    // TLS info
    QStringList m_tlsInfo;
    QMap<QString, QString> m_tlsDetails;
    
    // Load Configuration info
    QStringList m_loadConfigInfo;
    QMap<QString, QString> m_loadConfigDetails;
    
    // Exception info
    QStringList m_exceptionInfo;
    QMap<QString, QString> m_exceptionDetails;
    
    // Certificate info
    QStringList m_certificateInfo;
    QMap<QString, QString> m_certificateDetails;
    
    // Relocation info
    QStringList m_relocationInfo;
    QMap<QString, QString> m_relocationDetails;
    
    // Architecture info
    QStringList m_architectureInfo;
    QMap<QString, QString> m_architectureDetails;
    
    // Global Pointer info
    QStringList m_globalPointerInfo;
    QMap<QString, QString> m_globalPointerDetails;
    
    // Bound Import info
    QStringList m_boundImportInfo;
    QMap<QString, QString> m_boundImportDetails;
    
    // IAT info
    QStringList m_iatInfo;
    QMap<QString, QString> m_iatDetails;
    
    // Delay Import info
    QStringList m_delayImportInfo;
    QMap<QString, QString> m_delayImportDetails;
    
    // COM+ Runtime info
    QStringList m_comRuntimeInfo;
    QMap<QString, QString> m_comRuntimeDetails;
};

#endif // PE_DATA_MODEL_H
