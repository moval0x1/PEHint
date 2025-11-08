/**
 * @file pe_error_handler.cpp
 * @brief Implementation of enhanced error handling for PEHint
 */

#include "pe_error_handler.h"
#include "language_manager.h"
#include <QDebug>
#include <QFileInfo>

PEErrorHandler& PEErrorHandler::getInstance()
{
    static PEErrorHandler instance;
    return instance;
}

PEError PEErrorHandler::createError(PEErrorType type, const QString &message,
                                   const QString &context,
                                   quint32 offset,
                                   const QString &expected,
                                   const QString &actual)
{
    PEError error;
    error.type = type;
    error.message = message;
    error.context = context.isEmpty() ? m_currentOperation : context;
    error.fileOffset = offset;
    error.expectedValue = expected;
    error.actualValue = actual;
    
    // Determine severity based on error type
    switch (type) {
        case PEErrorType::FileNotFound:
        case PEErrorType::FileAccessDenied:
        case PEErrorType::InvalidDOSHeader:
        case PEErrorType::InvalidPESignature:
        case PEErrorType::MemoryAllocationFailed:
            error.severity = PEErrorSeverity::Critical;
            break;
        case PEErrorType::FileTooSmall:
        case PEErrorType::InvalidFileHeader:
        case PEErrorType::InvalidOptionalHeader:
        case PEErrorType::SectionTableCorrupted:
            error.severity = PEErrorSeverity::Error;
            break;
        case PEErrorType::DataDirectoryCorrupted:
        case PEErrorType::InvalidRVA:
        case PEErrorType::InvalidOffset:
            error.severity = PEErrorSeverity::Warning;
            break;
        default:
            error.severity = PEErrorSeverity::Info;
            break;
    }
    
    // Generate recovery suggestions
    error.recoverySuggestions = generateRecoverySuggestions(type);
    
    return error;
}

void PEErrorHandler::reportError(const PEError &error)
{
    m_errors.append(error);
    
    QString errorMsg = QString("[%1] %2")
        .arg(getSeverityString(error.severity))
        .arg(error.toString());
    
    if (error.severity == PEErrorSeverity::Critical) {
        qCritical() << errorMsg;
    } else if (error.severity == PEErrorSeverity::Error) {
        qWarning() << errorMsg;
    } else {
        qDebug() << errorMsg;
    }
}

void PEErrorHandler::reportWarning(const QString &message, const QString &context)
{
    PEError error = createError(PEErrorType::UnknownError, message, context);
    error.severity = PEErrorSeverity::Warning;
    reportError(error);
}

void PEErrorHandler::reportInfo(const QString &message, const QString &context)
{
    PEError error = createError(PEErrorType::None, message, context);
    error.severity = PEErrorSeverity::Info;
    reportError(error);
}

void PEErrorHandler::clearErrors()
{
    m_errors.clear();
}

QList<PEError> PEErrorHandler::getCriticalErrors() const
{
    QList<PEError> critical;
    for (const PEError &error : m_errors) {
        if (error.isCritical()) {
            critical.append(error);
        }
    }
    return critical;
}

bool PEErrorHandler::hasCriticalErrors() const
{
    for (const PEError &error : m_errors) {
        if (error.isCritical()) {
            return true;
        }
    }
    return false;
}

void PEErrorHandler::setCurrentFile(const QString &filePath)
{
    m_currentFile = filePath;
}

void PEErrorHandler::setCurrentOperation(const QString &operation)
{
    m_currentOperation = operation;
}

QStringList PEErrorHandler::getRecoverySuggestions() const
{
    QStringList suggestions;
    for (const PEError &error : m_errors) {
        suggestions.append(error.recoverySuggestions);
    }
    return suggestions;
}

QStringList PEErrorHandler::generateRecoverySuggestions(PEErrorType type) const
{
    QStringList suggestions;
    
    switch (type) {
        case PEErrorType::FileNotFound:
            suggestions << "Verify the file path is correct"
                        << "Check if the file exists"
                        << "Ensure you have read permissions";
            break;
        case PEErrorType::FileAccessDenied:
            suggestions << "Check file permissions"
                        << "Run as administrator if needed"
                        << "Ensure file is not locked by another process";
            break;
        case PEErrorType::FileTooSmall:
            suggestions << "Verify the file is complete"
                        << "Check if file was corrupted during transfer"
                        << "Ensure file is a valid PE file";
            break;
        case PEErrorType::InvalidDOSHeader:
            suggestions << "File may not be a valid PE file"
                        << "Check if file is corrupted"
                        << "Verify file format";
            break;
        case PEErrorType::InvalidPESignature:
            suggestions << "File may be corrupted"
                        << "Check if file is a valid PE file"
                        << "Verify file integrity";
            break;
        case PEErrorType::SectionTableCorrupted:
            suggestions << "File may be partially corrupted"
                        << "Try parsing only headers"
                        << "Check file integrity";
            break;
        case PEErrorType::DataDirectoryCorrupted:
            suggestions << "Some data directories may be invalid"
                        << "File may still be partially readable"
                        << "Try parsing basic structure only";
            break;
        case PEErrorType::InvalidRVA:
            suggestions << "RVA may be invalid or out of bounds"
                        << "Check section alignment"
                        << "Verify PE structure integrity";
            break;
        case PEErrorType::MemoryAllocationFailed:
            suggestions << "File may be too large"
                        << "Try using streaming mode"
                        << "Free up system memory";
            break;
        default:
            break;
    }
    
    return suggestions;
}

QString PEErrorHandler::getErrorTypeString(PEErrorType type) const
{
    switch (type) {
        case PEErrorType::FileNotFound: return "File Not Found";
        case PEErrorType::FileAccessDenied: return "File Access Denied";
        case PEErrorType::FileTooSmall: return "File Too Small";
        case PEErrorType::InvalidDOSHeader: return "Invalid DOS Header";
        case PEErrorType::InvalidPESignature: return "Invalid PE Signature";
        case PEErrorType::InvalidFileHeader: return "Invalid File Header";
        case PEErrorType::InvalidOptionalHeader: return "Invalid Optional Header";
        case PEErrorType::SectionTableCorrupted: return "Section Table Corrupted";
        case PEErrorType::DataDirectoryCorrupted: return "Data Directory Corrupted";
        case PEErrorType::InvalidRVA: return "Invalid RVA";
        case PEErrorType::InvalidOffset: return "Invalid Offset";
        case PEErrorType::MemoryAllocationFailed: return "Memory Allocation Failed";
        case PEErrorType::ParsingFailed: return "Parsing Failed";
        default: return "Unknown Error";
    }
}

QString PEErrorHandler::getSeverityString(PEErrorSeverity severity) const
{
    switch (severity) {
        case PEErrorSeverity::Info: return "INFO";
        case PEErrorSeverity::Warning: return "WARNING";
        case PEErrorSeverity::Error: return "ERROR";
        case PEErrorSeverity::Critical: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

QString PEError::toString() const
{
    QString result = QString("%1: %2").arg(getErrorTypeString(type)).arg(message);
    
    if (!context.isEmpty()) {
        result += QString(" (Context: %1)").arg(context);
    }
    
    if (fileOffset > 0) {
        result += QString(" (Offset: 0x%1)").arg(fileOffset, 8, 16, QChar('0'));
    }
    
    if (!expectedValue.isEmpty() && !actualValue.isEmpty()) {
        result += QString(" (Expected: %1, Actual: %2)").arg(expectedValue, actualValue);
    }
    
    return result;
}

bool PEError::isRecoverable() const
{
    // Most errors are recoverable except critical ones
    switch (type) {
        case PEErrorType::FileNotFound:
        case PEErrorType::FileAccessDenied:
        case PEErrorType::InvalidDOSHeader:
        case PEErrorType::InvalidPESignature:
        case PEErrorType::MemoryAllocationFailed:
            return false;
        default:
            return true;
    }
}

QString PEError::getErrorTypeString(PEErrorType type) const
{
    switch (type) {
        case PEErrorType::FileNotFound: return "File Not Found";
        case PEErrorType::FileAccessDenied: return "File Access Denied";
        case PEErrorType::FileTooSmall: return "File Too Small";
        case PEErrorType::InvalidDOSHeader: return "Invalid DOS Header";
        case PEErrorType::InvalidPESignature: return "Invalid PE Signature";
        case PEErrorType::InvalidFileHeader: return "Invalid File Header";
        case PEErrorType::InvalidOptionalHeader: return "Invalid Optional Header";
        case PEErrorType::SectionTableCorrupted: return "Section Table Corrupted";
        case PEErrorType::DataDirectoryCorrupted: return "Data Directory Corrupted";
        case PEErrorType::InvalidRVA: return "Invalid RVA";
        case PEErrorType::InvalidOffset: return "Invalid Offset";
        case PEErrorType::MemoryAllocationFailed: return "Memory Allocation Failed";
        case PEErrorType::ParsingFailed: return "Parsing Failed";
        default: return "Unknown Error";
    }
}


