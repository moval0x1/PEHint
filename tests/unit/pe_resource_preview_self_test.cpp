#include "pe_resource_preview.h"
#include "pe_analysis.h"

#include <iostream>

bool runPeResourcePreviewSelfTests()
{
    bool ok = true;
    auto check = [&](bool condition, const char *message) {
        if (!condition) {
            std::cerr << "PEResourcePreview self-test failed: " << message << '\n';
            ok = false;
        }
    };

    // Empty item with no file data -> Empty kind
    {
        PEResourceItem item;
        const ResourcePreview preview = buildResourcePreview(QByteArray{}, item);
        check(preview.kind == ResourcePreview::Kind::Empty,
              "empty item -> Kind::Empty");
    }

    // Item with zero size but non-empty fileData -> Empty kind
    {
        PEResourceItem item;
        item.typeId = 24; // RT_MANIFEST
        item.fileOffset = 0;
        item.size = 0;
        const ResourcePreview preview = buildResourcePreview(QByteArray(64, '\0'), item);
        check(preview.kind == ResourcePreview::Kind::Empty,
              "size=0 item -> Kind::Empty");
    }

    // RT_MANIFEST (typeId=24) with valid XML text -> Kind::Html
    {
        const QByteArray manifest = QByteArray(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
            "<trustInfo><security><requestedPrivileges>"
            "<requestedExecutionLevel level=\"asInvoker\"/>"
            "</requestedPrivileges></security></trustInfo>"
            "</assembly>");

        PEResourceItem item;
        item.typeName = QStringLiteral("RT_MANIFEST");
        item.typeId = 24;
        item.fileOffset = 0;
        item.size = static_cast<quint32>(manifest.size());

        const ResourcePreview preview = buildResourcePreview(manifest, item);
        check(preview.kind == ResourcePreview::Kind::Html,
              "RT_MANIFEST -> Kind::Html");
        check(!preview.htmlContent.isEmpty(),
              "RT_MANIFEST -> non-empty htmlContent");
    }

    // RT_MANIFEST matched by typeName (case-insensitive substring)
    {
        const QByteArray manifest = QByteArray("<assembly manifestVersion=\"1.0\"/>");
        PEResourceItem item;
        item.typeName = QStringLiteral("manifest"); // lowercase substring
        item.typeId = 0;
        item.fileOffset = 0;
        item.size = static_cast<quint32>(manifest.size());

        const ResourcePreview preview = buildResourcePreview(manifest, item);
        check(preview.kind == ResourcePreview::Kind::Html,
              "typeName 'manifest' -> Kind::Html");
    }

    // Small binary blob with no recognized type -> Kind::Hex
    {
        QByteArray binary(32, '\0');
        for (int i = 0; i < binary.size(); ++i) {
            binary[i] = char(i);
        }
        PEResourceItem item;
        item.typeName = QStringLiteral("UNKNOWN_TYPE");
        item.typeId = 9999;
        item.fileOffset = 0;
        item.size = static_cast<quint32>(binary.size());

        const ResourcePreview preview = buildResourcePreview(binary, item);
        // Unknown binary content should fall through to hex preview
        check(preview.kind == ResourcePreview::Kind::Hex || preview.kind == ResourcePreview::Kind::Text,
              "unknown binary -> Kind::Hex or Kind::Text");
    }

    // RT_VERSION (typeId=16) with minimal VS_VERSION_INFO blob -> Kind::Html
    {
        // Build a minimal but structurally valid VS_FIXEDFILEINFO block inside a VS_VERSION_INFO wrapper.
        // The blob layout: wLength(u16), wValueLength(u16), wType(u16), szKey(UTF-16 "VS_VERSION_INFO\0"), pad, Value(FIXEDFILEINFO)
        QByteArray blob;
        blob.resize(0);

        // Key: "VS_VERSION_INFO" in UTF-16LE + null terminator = 16 chars * 2 = 32 bytes
        const char16_t key[] = u"VS_VERSION_INFO";
        const int keyLen = 16; // including null
        for (int i = 0; i < keyLen; ++i) {
            blob.append(char(key[i] & 0xFF));
            blob.append(char((key[i] >> 8) & 0xFF));
        }

        // Pad to DWORD boundary (current size after header fields = 6 + 32 = 38 bytes, pad 2 to reach 40)
        blob.prepend(QByteArray(6, '\0')); // placeholder for wLength/wValueLength/wType

        // Just use an intentionally short blob — the parser should gracefully produce empty/partial output
        // We only verify the kind is Html (not a crash).
        PEResourceItem item;
        item.typeName = QStringLiteral("RT_VERSION");
        item.typeId = 16;
        item.fileOffset = 0;
        item.size = static_cast<quint32>(blob.size());

        const ResourcePreview preview = buildResourcePreview(blob, item);
        check(preview.kind == ResourcePreview::Kind::Html,
              "RT_VERSION -> Kind::Html");
    }

    return ok;
}
