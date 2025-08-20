#ifndef CRASH_HANDLER_H
#define CRASH_HANDLER_H

#include <QObject>
#include <QString>
#include <QFile>
#include <QTextStream>

// Forward declarations for Windows types to avoid conflicts
#ifdef Q_OS_WIN
// Forward declare Windows types
struct _EXCEPTION_POINTERS;
typedef struct _EXCEPTION_POINTERS EXCEPTION_POINTERS;
typedef long LONG;
#define WINAPI __stdcall
#endif

class CrashHandler : public QObject
{
    Q_OBJECT

public:
    static CrashHandler& getInstance();
    
    // Initialize crash handling system
    void initialize();
    
    // Log crash information
    void logCrashInfo(const QString &crashType, const QString &details = "");
    
    // Get log file path
    QString getLogFilePath() const;
    
    // Manual crash logging methods
    void logError(const QString &component, const QString &message, const QString &details = "");
    void logWarning(const QString &component, const QString &message, const QString &details = "");
    void logInfo(const QString &component, const QString &message);
    void logDebug(const QString &component, const QString &message);

private:
    CrashHandler();
    ~CrashHandler();
    
    // Prevent copying
    CrashHandler(const CrashHandler&) = delete;
    CrashHandler& operator=(const CrashHandler&) = delete;
    
    // Setup Windows-specific crash handling
    void setupWindowsCrashHandling();
    
    // Setup Qt crash handling
    void setupQtCrashHandling();
    
    // Write to log file
    void writeToLog(const QString &level, const QString &component, const QString &message, const QString &details = "");
    
    // Create crash dump file
    void createCrashDump(const QString &crashType, const QString &details);
    
    // Windows exception handler
    static LONG WINAPI unhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo);
    
    // Qt message handler
    static void qtMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg);

private:
    QFile *m_logFile;
    QTextStream *m_logStream;
    QString m_logFilePath;
    bool m_loggingEnabled;
    
#ifdef Q_OS_WIN
    static CrashHandler* s_instance;
#endif
};

#endif // CRASH_HANDLER_H
