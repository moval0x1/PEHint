#include "crash_handler.h"
#include "version.h"

#include <QCoreApplication>
#include <QStandardPaths>
#include <QDir>
#include <QDateTime>
#include <QSysInfo>
#include <QApplication>
#include <QWidget>
#include <QStringConverter>

// Forward declare Windows types to avoid conflicts with pe_structures.h
#ifdef Q_OS_WIN
// Only include Windows headers if not already included
#ifndef _WINDOWS_
#include <windows.h>
#endif
#ifndef _DBGHELP_
#include <dbghelp.h>
#endif
#endif

#ifdef Q_OS_WIN
CrashHandler* CrashHandler::s_instance = nullptr;
#endif

CrashHandler::CrashHandler()
    : m_logFile(nullptr)
    , m_logStream(nullptr)
    , m_loggingEnabled(false)
{
#ifdef Q_OS_WIN
    s_instance = this;
#endif
}

CrashHandler::~CrashHandler()
{
    if (m_loggingEnabled && m_logFile && m_logStream) {
        logInfo("CrashHandler", "Crash handler shutting down");
        m_logStream->flush();
        m_logFile->close();
        delete m_logStream;
        delete m_logFile;
    }
}

CrashHandler& CrashHandler::getInstance()
{
    static CrashHandler instance;
    return instance;
}

void CrashHandler::initialize()
{
    // Prevent multiple initialization
    static bool isInitialized = false;
    if (isInitialized) {
        return;
    }
    
    m_loggingEnabled = true;
    
    // Create logs directory in the same directory as the executable
    QString appDir = QCoreApplication::applicationDirPath();
    QString logsDir = appDir + "/logs";
    QDir().mkpath(logsDir);
    
    // Create log file with timestamp
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    m_logFilePath = logsDir + "/pehint_crash_" + timestamp + ".log";
    
    m_logFile = new QFile(m_logFilePath);
    if (m_logFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        m_logStream = new QTextStream(m_logFile);
        // Use Qt6 compatible encoding setting
        m_logStream->setEncoding(QStringConverter::Utf8);
        
        // Write header directly to avoid recursion
        *m_logStream << "=== PEHint Crash Handler Started ===" << Qt::endl;
        *m_logStream << "Timestamp: " << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") << Qt::endl;
        *m_logStream << "Version: " << PEHINT_VERSION_MAJOR << "." << PEHINT_VERSION_MINOR << "." << PEHINT_VERSION_PATCH << Qt::endl;
        *m_logStream << "OS: " << QSysInfo::prettyProductName() << Qt::endl;
        *m_logStream << "Architecture: " << QSysInfo::currentCpuArchitecture() << Qt::endl;
        *m_logStream << "Working Directory: " << QDir::currentPath() << Qt::endl;
        *m_logStream << "Application Path: " << QCoreApplication::applicationFilePath() << Qt::endl;
        *m_logStream << "=====================================" << Qt::endl;
        m_logStream->flush();
        
        // Write initialization messages directly to avoid recursion
        QString timestamp2 = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
        *m_logStream << QString("[%1] [INFO] [CrashHandler] Crash handling system initialized successfully").arg(timestamp2) << Qt::endl;
        *m_logStream << QString("[%1] [INFO] [CrashHandler] Log file: %2").arg(timestamp2, m_logFilePath) << Qt::endl;
        m_logStream->flush();
        
        // Also output to console for immediate visibility
        qDebug() << "Crash handling system initialized successfully";
        qDebug() << "Log file:" << m_logFilePath;
    } else {
        m_loggingEnabled = false;
        qWarning() << "Failed to open crash log file:" << m_logFilePath;
    }
    
    // Setup platform-specific crash handling
    setupWindowsCrashHandling();
    setupQtCrashHandling();
    
    isInitialized = true;
}

void CrashHandler::setupWindowsCrashHandling()
{
#ifdef Q_OS_WIN
    // Set up Windows exception handler
    SetUnhandledExceptionFilter(unhandledExceptionFilter);
    
    // Set up structured exception handling
    _set_se_translator([](unsigned int code, _EXCEPTION_POINTERS* ep) {
        QString crashType;
        switch (code) {
            case EXCEPTION_ACCESS_VIOLATION: crashType = "Access Violation"; break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: crashType = "Array Bounds Exceeded"; break;
            case EXCEPTION_BREAKPOINT: crashType = "Breakpoint"; break;
            case EXCEPTION_DATATYPE_MISALIGNMENT: crashType = "Data Type Misalignment"; break;
            case EXCEPTION_FLT_DENORMAL_OPERAND: crashType = "Floating Point Denormal Operand"; break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO: crashType = "Floating Point Divide by Zero"; break;
            case EXCEPTION_FLT_INEXACT_RESULT: crashType = "Floating Point Inexact Result"; break;
            case EXCEPTION_FLT_INVALID_OPERATION: crashType = "Floating Point Invalid Operation"; break;
            case EXCEPTION_FLT_OVERFLOW: crashType = "Floating Point Overflow"; break;
            case EXCEPTION_FLT_STACK_CHECK: crashType = "Floating Point Stack Check"; break;
            case EXCEPTION_FLT_UNDERFLOW: crashType = "Floating Point Underflow"; break;
            case EXCEPTION_ILLEGAL_INSTRUCTION: crashType = "Illegal Instruction"; break;
            case EXCEPTION_IN_PAGE_ERROR: crashType = "In Page Error"; break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO: crashType = "Integer Divide by Zero"; break;
            case EXCEPTION_INT_OVERFLOW: crashType = "Integer Overflow"; break;
            case EXCEPTION_INVALID_DISPOSITION: crashType = "Invalid Disposition"; break;
            case EXCEPTION_NONCONTINUABLE_EXCEPTION: crashType = "Noncontinuable Exception"; break;
            case EXCEPTION_PRIV_INSTRUCTION: crashType = "Privileged Instruction"; break;
            case EXCEPTION_SINGLE_STEP: crashType = "Single Step"; break;
            case EXCEPTION_STACK_OVERFLOW: crashType = "Stack Overflow"; break;
            default: crashType = QString("Unknown Exception (0x%1)").arg(code, 0, 16); break;
        }
        
        QString details = QString("Exception at address: 0x%1").arg((quintptr)ep->ExceptionRecord->ExceptionAddress, 0, 16);
        
        if (s_instance && s_instance->m_loggingEnabled) {
            s_instance->logCrashInfo(crashType, details);
        }
        
        // Re-throw the exception
        throw std::runtime_error(crashType.toStdString());
    });
    
    if (m_loggingEnabled) {
        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
        *m_logStream << QString("[%1] [INFO] [CrashHandler] Windows crash handling initialized").arg(timestamp) << Qt::endl;
        m_logStream->flush();
    }
#endif
}

void CrashHandler::setupQtCrashHandling()
{
    // Setup Qt signal handlers for application termination
    if (qApp) {
        connect(qApp, &QApplication::aboutToQuit, this, [this]() {
            if (m_loggingEnabled) {
                QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
                *m_logStream << QString("[%1] [INFO] [CrashHandler] Application about to quit").arg(timestamp) << Qt::endl;
                m_logStream->flush();
            }
        });
        
        // Handle application focus changes
        connect(qApp, &QApplication::applicationStateChanged, this, [this](Qt::ApplicationState state) {
            if (!m_loggingEnabled) return;
            
            QString stateStr;
            switch (state) {
                case Qt::ApplicationActive: stateStr = "Application became active"; break;
                case Qt::ApplicationInactive: stateStr = "Application became inactive"; break;
                case Qt::ApplicationHidden: stateStr = "Application hidden"; break;
                case Qt::ApplicationSuspended: stateStr = "Application suspended"; break;
                default: stateStr = "Unknown state"; break;
            }
            
            QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
            *m_logStream << QString("[%1] [INFO] [CrashHandler] %2").arg(timestamp, stateStr) << Qt::endl;
            m_logStream->flush();
        });
    }
    
    // Handle Qt fatal errors
    qInstallMessageHandler(qtMessageHandler);
    
    if (m_loggingEnabled) {
        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
        *m_logStream << QString("[%1] [INFO] [CrashHandler] Qt crash handling initialized").arg(timestamp) << Qt::endl;
        m_logStream->flush();
    }
}

void CrashHandler::qtMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    // Prevent infinite recursion
    static bool isHandling = false;
    if (isHandling) {
        return;
    }
    
    isHandling = true;
    
    if (s_instance) {
        QString component = QString(context.category ? context.category : "Unknown");
        QString details = QString("File: %1, Line: %2, Function: %3")
                       .arg(context.file ? context.file : "Unknown")
                       .arg(context.line)
                       .arg(context.function ? context.function : "Unknown");
        
        switch (type) {
            case QtFatalMsg:
                s_instance->logCrashInfo("Qt Fatal Error", QString("Message: %1\n%2").arg(msg, details));
                break;
            case QtCriticalMsg:
                s_instance->logError(component, msg, details);
                break;
            case QtWarningMsg:
                s_instance->logWarning(component, msg, details);
                break;
            case QtInfoMsg:
                s_instance->logInfo(component, msg);
                break;
            case QtDebugMsg:
                s_instance->logDebug(component, msg);
                break;
        }
    }
    
    // Call the default handler
    static QtMessageHandler defaultHandler = qInstallMessageHandler(nullptr);
    if (defaultHandler) {
        defaultHandler(type, context, msg);
    }
    
    isHandling = false;
}

LONG WINAPI CrashHandler::unhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo)
{
    QString crashType;
    switch (exceptionInfo->ExceptionRecord->ExceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION: crashType = "Access Violation"; break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: crashType = "Array Bounds Exceeded"; break;
        case EXCEPTION_BREAKPOINT: crashType = "Breakpoint"; break;
        case EXCEPTION_DATATYPE_MISALIGNMENT: crashType = "Data Type Misalignment"; break;
        case EXCEPTION_FLT_DENORMAL_OPERAND: crashType = "Floating Point Denormal Operand"; break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: crashType = "Floating Point Divide by Zero"; break;
        case EXCEPTION_FLT_INEXACT_RESULT: crashType = "Floating Point Inexact Result"; break;
        case EXCEPTION_FLT_INVALID_OPERATION: crashType = "Floating Point Invalid Operation"; break;
        case EXCEPTION_FLT_OVERFLOW: crashType = "Floating Point Overflow"; break;
        case EXCEPTION_FLT_STACK_CHECK: crashType = "Floating Point Stack Check"; break;
        case EXCEPTION_FLT_UNDERFLOW: crashType = "Floating Point Underflow"; break;
        case EXCEPTION_ILLEGAL_INSTRUCTION: crashType = "Illegal Instruction"; break;
        case EXCEPTION_IN_PAGE_ERROR: crashType = "In Page Error"; break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO: crashType = "Integer Divide by Zero"; break;
        case EXCEPTION_INT_OVERFLOW: crashType = "Integer Overflow"; break;
        case EXCEPTION_INVALID_DISPOSITION: crashType = "Invalid Disposition"; break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: crashType = "Noncontinuable Exception"; break;
        case EXCEPTION_PRIV_INSTRUCTION: crashType = "Privileged Instruction"; break;
        case EXCEPTION_SINGLE_STEP: crashType = "Single Step"; break;
        case EXCEPTION_STACK_OVERFLOW: crashType = "Stack Overflow"; break;
        default: crashType = QString("Unknown Exception (0x%1)").arg(exceptionInfo->ExceptionRecord->ExceptionCode, 0, 16); break;
    }
    
    QString details = QString("Exception at address: 0x%1, Thread ID: %2")
                     .arg((quintptr)exceptionInfo->ExceptionRecord->ExceptionAddress, 0, 16)
                     .arg(GetCurrentThreadId());
    
    // Log the crash if we can access the instance
    if (s_instance) {
        s_instance->logCrashInfo(crashType, details);
        s_instance->createCrashDump(crashType, details);
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

void CrashHandler::logCrashInfo(const QString &crashType, const QString &details)
{
    QString crashMessage = QString("CRASH DETECTED: %1").arg(crashType);
    
    // Write to log file immediately
    if (m_loggingEnabled && m_logFile && m_logStream) {
        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
        QString logEntry = QString("[%1] [CRASH] [%2] %3\n  Details: %4")
                          .arg(timestamp, "CrashHandler", crashMessage, details);
        
        *m_logStream << logEntry << Qt::endl;
        m_logStream->flush();
        m_logFile->flush();
    }
    
    // Also write to a separate crash log file
    QString appDir = QCoreApplication::applicationDirPath();
    QString crashLogPath = appDir + "/logs/";
    QDir().mkpath(crashLogPath);
    
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    QString crashLogFile = crashLogPath + "crash_log_" + timestamp + ".txt";
    
    QFile crashFile(crashLogFile);
    if (crashFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream crashStream(&crashFile);
        crashStream << "=== PEHint Crash Report ===" << Qt::endl;
        crashStream << "Timestamp: " << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") << Qt::endl;
        crashStream << "Version: " << PEHINT_VERSION_MAJOR << "." << PEHINT_VERSION_MINOR << "." << PEHINT_VERSION_PATCH << Qt::endl;
        crashStream << "OS: " << QSysInfo::prettyProductName() << Qt::endl;
        crashStream << "Architecture: " << QSysInfo::currentCpuArchitecture() << Qt::endl;
        crashStream << "Crash Type: " << crashType << Qt::endl;
        crashStream << "Details: " << details << Qt::endl;
        crashStream << "Application Path: " << QCoreApplication::applicationFilePath() << Qt::endl;
        crashStream << "Working Directory: " << QDir::currentPath() << Qt::endl;
        crashStream << "=====================================" << Qt::endl;
        crashFile.close();
    }
    
    // Output to console for immediate visibility
    qCritical() << "[CRASH]" << crashMessage;
    qCritical() << "Details:" << details;
}

void CrashHandler::createCrashDump(const QString &crashType, const QString &details)
{
#ifdef Q_OS_WIN
    // Create a crash dump file
    QString appDir = QCoreApplication::applicationDirPath();
    QString crashDumpPath = appDir + "/crashes/";
    QDir().mkpath(crashDumpPath);
    
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    QString dumpFileName = crashDumpPath + "crash_dump_" + timestamp + ".dmp";
    
    HANDLE dumpFile = CreateFileW(
        (LPCWSTR)dumpFileName.utf16(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (dumpFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
        exceptionInfo.ThreadId = GetCurrentThreadId();
        exceptionInfo.ExceptionPointers = nullptr; // We don't have the exception pointers here
        exceptionInfo.ClientPointers = TRUE;
        
        MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            dumpFile,
            MiniDumpNormal,
            &exceptionInfo,
            nullptr,
            nullptr
        );
        
        CloseHandle(dumpFile);
        
        logInfo("CrashHandler", QString("Crash dump created: %1").arg(dumpFileName));
    }
#endif
}

void CrashHandler::logError(const QString &component, const QString &message, const QString &details)
{
    if (!m_loggingEnabled || !m_logFile || !m_logStream) {
        return;
    }
    
    writeToLog("ERROR", component, message, details);
    qCritical() << "[ERROR]" << component << ":" << message;
    if (!details.isEmpty()) {
        qCritical() << "Details:" << details;
    }
}

void CrashHandler::logWarning(const QString &component, const QString &message, const QString &details)
{
    if (!m_loggingEnabled || !m_logFile || !m_logStream) {
        return;
    }
    
    writeToLog("WARN", component, message, details);
    qWarning() << "[WARN]" << component << ":" << message;
    if (!details.isEmpty()) {
        qWarning() << "Details:" << details;
    }
}

void CrashHandler::logInfo(const QString &component, const QString &message)
{
    if (!m_loggingEnabled || !m_logFile || !m_logStream) {
        return;
    }
    
    writeToLog("INFO", component, message);
    qDebug() << "[INFO]" << component << ":" << message;
}

void CrashHandler::logDebug(const QString &component, const QString &message)
{
    if (!m_loggingEnabled || !m_logFile || !m_logStream) {
        return;
    }
    
    writeToLog("DEBUG", component, message);
    qDebug() << "[DEBUG]" << component << ":" << message;
}

QString CrashHandler::getLogFilePath() const
{
    return m_logFilePath;
}

void CrashHandler::writeToLog(const QString &level, const QString &component, const QString &message, const QString &details)
{
    if (!m_loggingEnabled || !m_logFile || !m_logStream) {
        return;
    }
    
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    QString logEntry = QString("[%1] [%2] [%3] %4")
                      .arg(timestamp, level, component, message);
    
    if (!details.isEmpty()) {
        logEntry += QString("\n  Details: %1").arg(details);
    }
    
    *m_logStream << logEntry << Qt::endl;
    m_logStream->flush();
}
