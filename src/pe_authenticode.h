#ifndef PE_AUTHENTICODE_H
#define PE_AUTHENTICODE_H

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QStringList>

enum class AuthenticodeTrustStatus {
    NotSigned,
    Valid,
    InvalidSignature,
    UntrustedRoot,
    Expired,
    Revoked,
    UnknownError,
    VerificationUnavailable
};

struct PEAuthenticodeInfo {
    bool present = false;
    QString publisher;
    QString thumbprintSha1;
    QString thumbprintSha256;
    QDateTime notBefore;
    QDateTime notAfter;
    AuthenticodeTrustStatus trustStatus = AuthenticodeTrustStatus::NotSigned;
    QString statusMessage;
    QStringList certificateSubjects;
};

/** Legacy helper — returns publisher CN only. */
QString extractAuthenticodePublisher(const QByteArray &fileData, quint32 certTableOffset, quint32 certTableSize);

/** Full Authenticode triage: publisher, cert dates, thumbprints, and trust status (WinVerifyTrust on Windows). */
PEAuthenticodeInfo analyzeAuthenticode(const QByteArray &fileData,
                                       const QString &sourceFilePath,
                                       quint32 certTableOffset,
                                       quint32 certTableSize);

QString authenticodeTrustStatusLabel(AuthenticodeTrustStatus status);

#endif // PE_AUTHENTICODE_H
