#ifndef PE_DATA_MODEL_H
#define PE_DATA_MODEL_H

#include "pe_structures.h"
#include "pe_analysis.h"
#include "pe_data_directory_types.h"
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>

struct PEDataDirectoryField {
    QString label;
    QString value;
};

struct PEDataDirectoryRecord {
    int directoryIndex = 0;
    QString name;
    quint32 virtualAddress = 0;
    quint32 size = 0;
    QVector<PEDataDirectoryField> fields;
};

class PEDataModel
{
public:
    struct ImportFunctionEntry {
        QString name;
        bool importedByOrdinal = false;
        quint16 ordinal = 0;
        quint32 thunkRVA = 0;
        quint32 thunkOffset = 0;
    };

    struct ExportFunctionEntry {
        QString name;
        quint16 ordinal = 0;
        quint32 rva = 0;
        quint32 fileOffset = 0;
    };

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
    void setImportFunctions(const QMap<QString, QList<ImportFunctionEntry>> &details);
    QStringList getImports() const;
    const QMap<QString, QList<ImportFunctionEntry>>& getImportFunctions() const;

    void setExportFunctions(const QList<ExportFunctionEntry> &functions);
    const QList<ExportFunctionEntry>& getExportFunctions() const;
    
    // Resources
    void setResourceEntries(const QVector<PEResourceItem> &entries);
    const QVector<PEResourceItem> &getResourceEntries() const;

    /** Parsed detail rows for data directories (indices 0–15). */
    void setParsedDirectoryFields(int directoryIndex, const QVector<PEDataDirectoryField> &fields);
    const QVector<PEDataDirectoryField> &parsedDirectoryFields(int directoryIndex) const;

    void setDebugDirectoryEntries(const QVector<PEDebugDirectoryEntry> &entries);
    const QVector<PEDebugDirectoryEntry> &debugDirectoryEntries() const;
    void setTlsDirectoryInfo(const PETlsDirectoryInfo &info);
    const PETlsDirectoryInfo &tlsDirectoryInfo() const;
    void setLoadConfigDirectoryInfo(const PELoadConfigDirectoryInfo &info);
    const PELoadConfigDirectoryInfo &loadConfigDirectoryInfo() const;
    // File analysis (overlay, entropy, PDB) — filled after parse via PEAnalysis
    void setOverlayInfo(const PEOverlayInfo &info);
    PEOverlayInfo getOverlayInfo() const;
    void setEntropySummary(const PEEntropySummary &summary);
    PEEntropySummary getEntropySummary() const;
    void setPdbInfo(const PEPdbInfo &info);
    PEPdbInfo getPdbInfo() const;
    void setVersionInfo(const PEVersionInfo &info);
    PEVersionInfo getVersionInfo() const;

    void setAnalysisMetadata(const PEAnalysisMetadata &metadata);
    PEAnalysisMetadata getAnalysisMetadata() const;
    void setFileMetrics(const PEFileMetrics &metrics);
    PEFileMetrics getFileMetrics() const;
    void setContentScan(const PEContentScan &scan);
    PEContentScan getContentScan() const;
    void setTlsCallbacksPresent(bool present);

    void setDelayImports(const QStringList &imports);
    void setDelayImportFunctions(const QMap<QString, QList<ImportFunctionEntry>> &details);
    QStringList getDelayImports() const;
    const QMap<QString, QList<ImportFunctionEntry>> &getDelayImportFunctions() const;

    /** Shannon entropy for a section name from the last analysis, or -1 if unknown. */
    double sectionEntropy(const QString &sectionName) const;

    void setDataDirectoryRecords(const QVector<PEDataDirectoryRecord> &records);
    const QVector<PEDataDirectoryRecord> &getDataDirectoryRecords() const;
    
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
    QMap<QString, QList<ImportFunctionEntry>> m_importFunctionDetails;
    QList<ExportFunctionEntry> m_exportFunctions;
    
    // Resources
    QVector<PEResourceItem> m_resourceEntries;
    QVector<PEDataDirectoryField> m_parsedDirectoryFields[16];
    QVector<PEDebugDirectoryEntry> m_debugDirectoryEntries;
    PETlsDirectoryInfo m_tlsDirectoryInfo;
    PELoadConfigDirectoryInfo m_loadConfigDirectoryInfo;
    PEOverlayInfo m_overlayInfo;
    PEEntropySummary m_entropySummary;
    PEPdbInfo m_pdbInfo;
    PEVersionInfo m_versionInfo;
    PEAnalysisMetadata m_analysisMetadata;
    PEFileMetrics m_fileMetrics;
    PEContentScan m_contentScan;
    QStringList m_delayImports;
    QMap<QString, QList<ImportFunctionEntry>> m_delayImportFunctionDetails;
    QVector<PEDataDirectoryRecord> m_dataDirectoryRecords;
};

#endif // PE_DATA_MODEL_H
