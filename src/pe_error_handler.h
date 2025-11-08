/**
 * @file pe_error_handler.h
 * @brief Enhanced error handling for PEHint
 * 
 * This file provides comprehensive error handling with context,
 * recovery suggestions, and detailed error reporting.
 */

#ifndef PE_ERROR_HANDLER_H
#define PE_ERROR_HANDLER_H

#include <QString>
#include <QStringList>
#include <QMap>
#include <QException>

/**
 * @brief Error types for PE parsing operations
 */
enum class PEErrorType {
    None = 0,
    FileNotFound,
    FileAccessDenied,
    FileTooSmall,
    InvalidDOSHeader,
    InvalidPESignature,
    InvalidFileHeader,
    InvalidOptionalHeader,
    SectionTableCorrupted,
    DataDirectoryCorrupted,
    InvalidRVA,
    InvalidOffset,
    MemoryAllocationFailed,
    ParsingFailed,
    UnknownError
};

/**
 * @brief Error severity levels
 */
enum class PEErrorSeverity {
    Info,
    Warning,
    Error,
    Critical
};

/**
 * @brief Comprehensive error information structure
 */
struct PEError {
    PEErrorType type;
    PEErrorSeverity severity;
    QString message;
    QString context;
    quint32 fileOffset;
    QString expectedValue;
    QString actualValue;
    QStringList recoverySuggestions;
    QStringList relatedErrors;
    
    PEError() : type(PEErrorType::None), severity(PEErrorSeverity::Info), fileOffset(0) {}
    
    QString toString() const;
    bool isCritical() const { return severity == PEErrorSeverity::Critical; }
    bool isRecoverable() const;
    
private:
    QString getErrorTypeString(PEErrorType type) const;
};

/**
 * @brief Enhanced error handler for PE parsing operations
 * 
 * This class provides:
 * - Detailed error context
 * - Recovery suggestions
 * - Error aggregation
 * - Error reporting
 */
class PEErrorHandler
{
public:
    static PEErrorHandler& getInstance();
    
    // Error creation
    PEError createError(PEErrorType type, const QString &message, 
                       const QString &context = QString(),
                       quint32 offset = 0,
                       const QString &expected = QString(),
                       const QString &actual = QString());
    
    // Error reporting
    void reportError(const PEError &error);
    void reportWarning(const QString &message, const QString &context = QString());
    void reportInfo(const QString &message, const QString &context = QString());
    
    // Error management
    void clearErrors();
    QList<PEError> getErrors() const { return m_errors; }
    QList<PEError> getCriticalErrors() const;
    bool hasErrors() const { return !m_errors.isEmpty(); }
    bool hasCriticalErrors() const;
    
    // Error context
    void setCurrentFile(const QString &filePath);
    void setCurrentOperation(const QString &operation);
    QString getCurrentFile() const { return m_currentFile; }
    QString getCurrentOperation() const { return m_currentOperation; }
    
    // Recovery suggestions
    QStringList getRecoverySuggestions() const;
    
private:
    PEErrorHandler() = default;
    ~PEErrorHandler() = default;
    PEErrorHandler(const PEErrorHandler&) = delete;
    PEErrorHandler& operator=(const PEErrorHandler&) = delete;
    
    QList<PEError> m_errors;
    QString m_currentFile;
    QString m_currentOperation;
    
    QStringList generateRecoverySuggestions(PEErrorType type) const;
    QString getErrorTypeString(PEErrorType type) const;
    QString getSeverityString(PEErrorSeverity severity) const;
};

/**
 * @brief Exception class for PE parsing errors
 */
class PEParsingException : public QException
{
public:
    PEParsingException(const PEError &error) : m_error(error) {}
    
    const char* what() const noexcept override {
        return m_error.message.toUtf8().constData();
    }
    
    PEError getError() const { return m_error; }
    
    PEParsingException* clone() const override {
        return new PEParsingException(m_error);
    }
    
    void raise() const override {
        throw *this;
    }

private:
    PEError m_error;
};

#endif // PE_ERROR_HANDLER_H

