#include "pe_authenticode.h"

#include "language_manager.h"

#include <QChar>
#include <QMap>
#include <QFileInfo>

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#endif

namespace {

constexpr int kMaxPublisherChars = 120;

quint32 readLe32(const QByteArray &bytes, int offset)
{
    const auto *d = reinterpret_cast<const unsigned char *>(bytes.constData() + offset);
    return static_cast<quint32>(d[0]) | (static_cast<quint32>(d[1]) << 8)
           | (static_cast<quint32>(d[2]) << 16) | (static_cast<quint32>(d[3]) << 24);
}

QString sanitizePublisher(QString value)
{
    value = value.trimmed();
    while (!value.isEmpty() && (value.front() == QLatin1Char('"') || value.front() == QLatin1Char('\''))) {
        value.remove(0, 1);
    }
    while (!value.isEmpty() && (value.back() == QLatin1Char('"') || value.back() == QLatin1Char('\''))) {
        value.chop(1);
    }
    value = value.trimmed();
    if (value.size() > kMaxPublisherChars) {
        value = value.left(kMaxPublisherChars);
    }
    bool hasLetterOrDigit = false;
    for (const QChar ch : value) {
        if (ch.isLetterOrNumber()) {
            hasLetterOrDigit = true;
            break;
        }
    }
    if (!hasLetterOrDigit || value.size() < 2) {
        return QString();
    }
    return value;
}

QString readUntilDelimiterUtf8(const QByteArray &payload, int start)
{
    int end = start;
    while (end < payload.size()) {
        const char ch = payload.at(end);
        if (ch == '\0' || ch == '\r' || ch == '\n' || ch == ',' || ch == '/' || ch == ';') {
            break;
        }
        ++end;
    }
    return sanitizePublisher(QString::fromUtf8(payload.constData() + start, end - start));
}

QString readUntilDelimiterUtf16(const QByteArray &payload, int start)
{
    QString out;
    for (int i = start; i + 1 < payload.size(); i += 2) {
        const char16_t ch = static_cast<char16_t>(
            static_cast<unsigned char>(payload.at(i))
            | (static_cast<unsigned char>(payload.at(i + 1)) << 8));
        if (ch == 0 || ch == u'\r' || ch == u'\n' || ch == u',' || ch == u'/' || ch == u';') {
            break;
        }
        out.append(QChar(ch));
    }
    return sanitizePublisher(out);
}

QString findCnUtf8(const QByteArray &payload)
{
    int idx = payload.indexOf("CN=");
    while (idx >= 0) {
        const QString candidate = readUntilDelimiterUtf8(payload, idx + 3);
        if (!candidate.isEmpty()) {
            return candidate;
        }
        idx = payload.indexOf("CN=", idx + 3);
    }
    return QString();
}

QString findCnUtf16(const QByteArray &payload)
{
    static const QByteArray kCnUtf16("C\0N\0=\0", 6);
    int idx = payload.indexOf(kCnUtf16);
    while (idx >= 0) {
        const QString candidate = readUntilDelimiterUtf16(payload, idx + kCnUtf16.size());
        if (!candidate.isEmpty()) {
            return candidate;
        }
        idx = payload.indexOf(kCnUtf16, idx + 2);
    }
    return QString();
}

QString findCommonNameUtf16(const QByteArray &payload)
{
    static const QByteArray kCommonNameUtf16("c\0o\0m\0m\0o\0n\0N\0a\0m\0e\0", 20);
    int idx = payload.indexOf(kCommonNameUtf16);
    while (idx >= 0) {
        int cursor = idx + kCommonNameUtf16.size();
        while (cursor + 1 < payload.size()) {
            const char16_t ch = static_cast<char16_t>(
                static_cast<unsigned char>(payload.at(cursor))
                | (static_cast<unsigned char>(payload.at(cursor + 1)) << 8));
            if (ch == u'=' || ch == u':') {
                cursor += 2;
                break;
            }
            if (ch == 0 || ch == u'\r' || ch == u'\n') {
                break;
            }
            cursor += 2;
        }
        if (cursor + 1 < payload.size()) {
            const QString candidate = readUntilDelimiterUtf16(payload, cursor);
            if (!candidate.isEmpty()) {
                return candidate;
            }
        }
        idx = payload.indexOf(kCommonNameUtf16, idx + 2);
    }
    return QString();
}

QString extractPublisherFromPkcs7Payload(const QByteArray &payload)
{
    if (payload.isEmpty()) {
        return QString();
    }
    QString publisher = findCnUtf8(payload);
    if (!publisher.isEmpty()) {
        return publisher;
    }
    publisher = findCnUtf16(payload);
    if (!publisher.isEmpty()) {
        return publisher;
    }
    return findCommonNameUtf16(payload);
}

QByteArray firstPkcs7Payload(const QByteArray &fileData, quint32 certTableOffset, quint32 certTableSize)
{
    if (fileData.isEmpty() || certTableOffset == 0 || certTableSize < 8) {
        return QByteArray();
    }
    const quint64 start = certTableOffset;
    const quint64 fileSize = static_cast<quint64>(fileData.size());
    if (start >= fileSize) {
        return QByteArray();
    }
    const quint64 end = qMin(start + static_cast<quint64>(certTableSize), fileSize);
    quint64 cursor = start;
    while (cursor + 8 <= end) {
        const int certStart = static_cast<int>(cursor);
        const quint32 certLength = readLe32(fileData, certStart);
        if (certLength < 8) {
            break;
        }
        const quint64 certEnd = qMin(cursor + static_cast<quint64>(certLength), end);
        const quint64 payloadStart = cursor + 8;
        if (payloadStart < certEnd) {
            return fileData.mid(static_cast<int>(payloadStart), static_cast<int>(certEnd - payloadStart));
        }
        const quint64 advance = (static_cast<quint64>(certLength) + 7u) & ~7ull;
        if (advance == 0) {
            break;
        }
        cursor += advance;
    }
    return QByteArray();
}

#ifdef Q_OS_WIN
QString certBlobThumbprint(const PCCERT_CONTEXT cert, ALG_ID algId)
{
    if (!cert) {
        return QString();
    }
    DWORD hashLen = 0;
    if (!CryptHashCertificate(0, algId, 0, cert->pbCertEncoded, cert->cbCertEncoded, nullptr, &hashLen)
        || hashLen == 0) {
        return QString();
    }
    QByteArray hash(static_cast<int>(hashLen), Qt::Uninitialized);
    if (!CryptHashCertificate(0, algId, 0, cert->pbCertEncoded, cert->cbCertEncoded,
                              reinterpret_cast<BYTE *>(hash.data()), &hashLen)) {
        return QString();
    }
    hash.resize(static_cast<int>(hashLen));
    QString hex;
    hex.reserve(hash.size() * 2);
    for (unsigned char b : hash) {
        hex += QStringLiteral("%1").arg(b, 2, 16, QChar('0'));
    }
    return hex.toUpper();
}

QDateTime fileTimeToQDateTime(const FILETIME &ft)
{
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    if (uli.QuadPart == 0) {
        return QDateTime();
    }
    static const qint64 kEpochDiff = 11644473600000LL;
    const qint64 ms = static_cast<qint64>(uli.QuadPart / 10000) - kEpochDiff;
    return QDateTime::fromMSecsSinceEpoch(ms, Qt::UTC);
}

void enrichFromPkcs7Payload(PEAuthenticodeInfo &info, const QByteArray &payload)
{
    if (payload.isEmpty()) {
        return;
    }
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    CRYPT_DATA_BLOB blob{};
    blob.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(payload.constData()));
    blob.cbData = static_cast<DWORD>(payload.size());
    if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr, &store, &msg,
                          nullptr)) {
        return;
    }

    PCCERT_CONTEXT signer = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                                       CERT_FIND_SUBJECT_CERT, nullptr, nullptr);
    if (signer) {
        if (info.publisher.isEmpty()) {
            DWORD nameLen = CertGetNameStringW(signer, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
            if (nameLen > 1) {
                QVector<wchar_t> buf(static_cast<int>(nameLen));
                CertGetNameStringW(signer, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf.data(), nameLen);
                info.publisher = sanitizePublisher(QString::fromWCharArray(buf.data()));
            }
        }
        info.thumbprintSha1 = certBlobThumbprint(signer, CALG_SHA1);
        info.thumbprintSha256 = certBlobThumbprint(signer, CALG_SHA_256);
        info.notBefore = fileTimeToQDateTime(signer->pCertInfo->NotBefore);
        info.notAfter = fileTimeToQDateTime(signer->pCertInfo->NotAfter);
        CertFreeCertificateContext(signer);
    }

    PCCERT_CONTEXT chainCert = nullptr;
    while ((chainCert = CertEnumCertificatesInStore(store, chainCert)) != nullptr) {
        DWORD nameLen = CertGetNameStringW(chainCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
        if (nameLen > 1) {
            QVector<wchar_t> buf(static_cast<int>(nameLen));
            CertGetNameStringW(chainCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf.data(), nameLen);
            const QString subject = QString::fromWCharArray(buf.data()).trimmed();
            if (!subject.isEmpty() && !info.certificateSubjects.contains(subject)) {
                info.certificateSubjects.append(subject);
            }
        }
    }

    if (store) {
        CertCloseStore(store, 0);
    }
    if (msg) {
        CryptMsgClose(msg);
    }
}

AuthenticodeTrustStatus verifyAuthenticodeTrust(const QString &sourceFilePath, QString *detailOut)
{
    if (sourceFilePath.isEmpty() || !QFileInfo::exists(sourceFilePath)) {
        if (detailOut) {
            *detailOut = LANG("UI/authenticode_trust_need_path");
        }
        return AuthenticodeTrustStatus::UnknownError;
    }

    const std::wstring path = sourceFilePath.toStdWString();
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    const LONG status = WinVerifyTrust(nullptr, &action, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trustData);

    if (status == ERROR_SUCCESS) {
        if (detailOut) {
            *detailOut = LANG("UI/authenticode_signature_verified");
        }
        return AuthenticodeTrustStatus::Valid;
    }
    if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN) {
        if (detailOut) {
            *detailOut = LANG("UI/authenticode_no_signature");
        }
        return AuthenticodeTrustStatus::NotSigned;
    }
    if (status == CERT_E_EXPIRED) {
        if (detailOut) {
            *detailOut = LANG("UI/authenticode_cert_expired");
        }
        return AuthenticodeTrustStatus::Expired;
    }
    if (status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING) {
        if (detailOut) {
            *detailOut = LANG("UI/authenticode_chain_untrusted");
        }
        return AuthenticodeTrustStatus::UntrustedRoot;
    }
    if (status == TRUST_E_BAD_DIGEST || status == TRUST_E_CERT_SIGNATURE) {
        if (detailOut) {
            *detailOut = LANG("UI/authenticode_bad_digest");
        }
        return AuthenticodeTrustStatus::InvalidSignature;
    }
    if (status == CERT_E_REVOKED) {
        if (detailOut) {
            *detailOut = LANG("UI/authenticode_cert_revoked");
        }
        return AuthenticodeTrustStatus::Revoked;
    }
    if (detailOut) {
        QMap<QString, QString> params;
        params[QStringLiteral("code")] = QString::number(static_cast<quint32>(status), 16);
        *detailOut = LANG_PARAMS("UI/authenticode_winverify_failed", params);
    }
    return AuthenticodeTrustStatus::UnknownError;
}
#endif

} // namespace

QString extractAuthenticodePublisher(const QByteArray &fileData, quint32 certTableOffset, quint32 certTableSize)
{
    const QByteArray payload = firstPkcs7Payload(fileData, certTableOffset, certTableSize);
    return extractPublisherFromPkcs7Payload(payload);
}

PEAuthenticodeInfo analyzeAuthenticode(const QByteArray &fileData,
                                         const QString &sourceFilePath,
                                         quint32 certTableOffset,
                                         quint32 certTableSize)
{
    PEAuthenticodeInfo info;
    if (certTableOffset == 0 || certTableSize < 8) {
        info.trustStatus = AuthenticodeTrustStatus::NotSigned;
        info.statusMessage = LANG("UI/authenticode_no_cert_table");
        return info;
    }

    info.present = true;
    const QByteArray payload = firstPkcs7Payload(fileData, certTableOffset, certTableSize);
    info.publisher = extractPublisherFromPkcs7Payload(payload);

#ifdef Q_OS_WIN
    enrichFromPkcs7Payload(info, payload);
    info.trustStatus = verifyAuthenticodeTrust(sourceFilePath, &info.statusMessage);
#else
    Q_UNUSED(sourceFilePath);
    info.trustStatus = AuthenticodeTrustStatus::VerificationUnavailable;
    info.statusMessage = LANG("UI/authenticode_verify_windows_only");
#endif

    return info;
}

QString authenticodeTrustStatusLabel(AuthenticodeTrustStatus status)
{
    switch (status) {
    case AuthenticodeTrustStatus::NotSigned:
        return LANG("UI/authenticode_trust_not_signed");
    case AuthenticodeTrustStatus::Valid:
        return LANG("UI/authenticode_trust_valid");
    case AuthenticodeTrustStatus::InvalidSignature:
        return LANG("UI/authenticode_trust_invalid");
    case AuthenticodeTrustStatus::UntrustedRoot:
        return LANG("UI/authenticode_trust_untrusted_root");
    case AuthenticodeTrustStatus::Expired:
        return LANG("UI/authenticode_trust_expired");
    case AuthenticodeTrustStatus::Revoked:
        return LANG("UI/authenticode_trust_revoked");
    case AuthenticodeTrustStatus::VerificationUnavailable:
        return LANG("UI/authenticode_trust_unavailable");
    default:
        return LANG("UI/authenticode_trust_unknown");
    }
}
