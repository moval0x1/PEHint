#include "pe_authenticode.h"

#include <iostream>

bool runPeAuthenticodeSelfTests()
{
    bool ok = true;
    auto check = [&](bool condition, const char *message) {
        if (!condition) {
            std::cerr << "PEAuthenticode self-test failed: " << message << '\n';
            ok = false;
        }
    };

    // authenticodeTrustStatusLabel returns non-empty string for every enum value
    {
        const AuthenticodeTrustStatus statuses[] = {
            AuthenticodeTrustStatus::NotSigned,
            AuthenticodeTrustStatus::Valid,
            AuthenticodeTrustStatus::InvalidSignature,
            AuthenticodeTrustStatus::UntrustedRoot,
            AuthenticodeTrustStatus::Expired,
            AuthenticodeTrustStatus::Revoked,
            AuthenticodeTrustStatus::UnknownError,
            AuthenticodeTrustStatus::VerificationUnavailable,
        };
        for (const auto status : statuses) {
            const QString label = authenticodeTrustStatusLabel(status);
            check(!label.isEmpty(), "authenticodeTrustStatusLabel returns non-empty string");
        }
    }

    // extractAuthenticodePublisher with zero-size cert table returns empty string
    {
        const QByteArray empty;
        const QString publisher = extractAuthenticodePublisher(empty, 0, 0);
        check(publisher.isEmpty(), "extractAuthenticodePublisher empty data -> empty publisher");
    }

    // analyzeAuthenticode with empty file data and certTableSize=0
    // -> present=false, trustStatus=NotSigned
    {
        const QByteArray empty;
        const PEAuthenticodeInfo info = analyzeAuthenticode(empty, QString(), 0, 0);
        check(!info.present, "analyzeAuthenticode empty -> not present");
        check(info.trustStatus == AuthenticodeTrustStatus::NotSigned,
              "analyzeAuthenticode empty -> NotSigned");
        check(info.publisher.isEmpty(), "analyzeAuthenticode empty -> empty publisher");
        check(info.certificateSubjects.isEmpty(),
              "analyzeAuthenticode empty -> no cert subjects");
    }

    // analyzeAuthenticode with garbage data but non-zero certTableSize
    // -> present=true, but signature invalid or unavailable (not NotSigned)
    {
        QByteArray garbage(256, char(0xAA));
        const PEAuthenticodeInfo info = analyzeAuthenticode(garbage, QString(), 0, 64);
        check(info.present, "analyzeAuthenticode garbage with size>0 -> present=true");
        check(info.trustStatus != AuthenticodeTrustStatus::NotSigned,
              "analyzeAuthenticode garbage -> not NotSigned when certTableSize>0");
    }

    return ok;
}
