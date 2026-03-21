#include "pe_parser_new.h"
#include "pe_utils.h"
#include "language_manager.h"
#include <QDebug>
#include <QFileInfo>
#include <QTreeWidgetItem>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QCoreApplication>
#include <QDir>
#include <QDateTime>
#include <QtGlobal>
#include <QRegularExpression>
#include <functional>
#include <cstddef>
#include <cstring>

namespace {
constexpr int kFieldOffsetRole = Qt::UserRole + 20;
constexpr int kFieldSizeRole = Qt::UserRole + 21;

QString formatHexPreview(const QByteArray &data, int maxBytes = 72)
{
    if (data.isEmpty()) {
        return QString();
    }
    const int cap = qMin(data.size(), maxBytes);
    QString s;
    s.reserve(static_cast<int>(static_cast<size_t>(cap) * 3u));
    for (int i = 0; i < cap; ++i) {
        if (i > 0) {
            s += QLatin1Char(' ');
        }
        s += QStringLiteral("%1").arg(static_cast<quint8>(data[i]), 2, 16, QLatin1Char('0')).toUpper();
    }
    if (data.size() > maxBytes) {
        s += QStringLiteral(" …");
    }
    return s;
}

/** PE structure tree uses English only (field names / units), regardless of UI language. */
QString peTreeSizeBytesText(const QString &sizeHexToken)
{
    return QStringLiteral("%1 bytes").arg(sizeHexToken);
}

QString peTreeEntriesText(const QString &countToken)
{
    return QStringLiteral("%1 entries").arg(countToken);
}

struct FieldExplanationCaches {
    QHash<QString, QString> explanationHtmlCache;
    QHash<QString, QJsonObject> languageJsonCache;
    QHash<QString, QDateTime> languageJsonMtime;
    /// Resolved absolute path per UI language (explanations.json / explanations_pt.json); avoids hundreds of disk probes while building the tree.
    QHash<QString, QString> explanationsPathByLanguage;
};

FieldExplanationCaches &fieldExplanationCaches()
{
    static FieldExplanationCaches s;
    return s;
}

void clearFieldExplanationCachesInternal()
{
    FieldExplanationCaches &c = fieldExplanationCaches();
    c.explanationHtmlCache.clear();
    c.languageJsonCache.clear();
    c.languageJsonMtime.clear();
    c.explanationsPathByLanguage.clear();
}

/** Last-resort English when INI has no entry (must match config/language_config.ini). */
QString defaultEnglishSectionTypeInfo(const QString &sectionTypeKey)
{
    static const QHash<QString, QString> kEn = {
        {QStringLiteral("section_info_text"), QStringLiteral("This section contains the executable code of the program.")},
        {QStringLiteral("section_info_data"), QStringLiteral("This section contains initialized data that can be read and written.")},
        {QStringLiteral("section_info_rdata"), QStringLiteral("This section contains read-only initialized data, typically constants and string literals.")},
        {QStringLiteral("section_info_rsrc"), QStringLiteral("This section contains resources such as icons, bitmaps, dialogs, and version information.")},
        {QStringLiteral("section_info_reloc"), QStringLiteral("This section contains relocation information for when the executable cannot be loaded at its preferred base address.")},
        {QStringLiteral("section_info_idata"), QStringLiteral("This section contains import information, listing DLLs and functions that the executable depends on.")},
        {QStringLiteral("section_info_edata"), QStringLiteral("This section contains export information, listing functions and data that this module exports.")},
        {QStringLiteral("section_info_tls"), QStringLiteral("This section stores Thread Local Storage (TLS) templates and callbacks used during per-thread initialization.")},
        {QStringLiteral("section_info_gfids"), QStringLiteral("This section stores Control Flow Guard (CFG) function IDs used by the loader/runtime for indirect-call validation.")},
        {QStringLiteral("section_info_pdata"), QStringLiteral("This section contains runtime function table entries used for exception unwinding (especially on x64/ARM).")},
        {QStringLiteral("section_info_xdata"), QStringLiteral("This section stores unwind metadata referenced by .pdata entries.")},
        {QStringLiteral("section_info_didat"), QStringLiteral("This section contains delay-load import tables used when DLLs are resolved on first use.")},
        {QStringLiteral("section_info_crt"), QStringLiteral("This section stores C/C++ runtime initializer and terminator arrays (global constructors/destructors).")},
        {QStringLiteral("section_info_cfg"), QStringLiteral("This section stores Control Flow Guard metadata and helper tables.")},
        {QStringLiteral("section_info_sxdata"), QStringLiteral("This section contains Safe Exception Handler / structured exception metadata for some toolchains.")},
        {QStringLiteral("section_info_debug"), QStringLiteral("This section stores debug directory and symbol-related metadata.")},
        {QStringLiteral("section_info_cormeta"), QStringLiteral("This section contains CLR/.NET metadata streams in managed images.")},
        {QStringLiteral("section_info_managed"), QStringLiteral("This section contains IL/managed runtime data used by .NET executables.")},
    };
    return kEn.value(sectionTypeKey);
}

/** English labels for data-directory rows (display == explanations.json keys). */
const QStringList &dataDirectoryFieldKeys()
{
    static const QStringList keys = {
        QStringLiteral("Export Directory"),
        QStringLiteral("Import Directory"),
        QStringLiteral("Resource Directory"),
        QStringLiteral("Exception Directory"),
        QStringLiteral("Certificate Directory"),
        QStringLiteral("Base Relocation Directory"),
        QStringLiteral("Debug Directory"),
        QStringLiteral("Architecture Directory"),
        QStringLiteral("Global Pointer Directory"),
        QStringLiteral("TLS Directory"),
        QStringLiteral("Load Configuration Directory"),
        QStringLiteral("Bound Import Directory"),
        QStringLiteral("Import Address Table Directory"),
        QStringLiteral("Delay Import Directory"),
        QStringLiteral("COM+ Runtime Header Directory"),
        QStringLiteral("Reserved")
    };
    return keys;
}

quint32 readLe32(const uchar *p)
{
    return quint32(p[0]) | (quint32(p[1]) << 8) | (quint32(p[2]) << 16) | (quint32(p[3]) << 24);
}

quint16 readLe16(const uchar *p)
{
    return quint16(p[0]) | (quint16(p[1]) << 8);
}

quint64 readLe64(const uchar *p)
{
    quint64 lo = readLe32(p);
    quint64 hi = readLe32(p + 4);
    return lo | (hi << 32);
}

QString resourceTypeIdLabel(quint32 id)
{
    switch (id) {
    case 1: return QStringLiteral("RT_CURSOR");
    case 2: return QStringLiteral("RT_BITMAP");
    case 3: return QStringLiteral("RT_ICON");
    case 4: return QStringLiteral("RT_MENU");
    case 5: return QStringLiteral("RT_DIALOG");
    case 6: return QStringLiteral("RT_STRING");
    case 7: return QStringLiteral("RT_FONTDIR");
    case 8: return QStringLiteral("RT_FONT");
    case 9: return QStringLiteral("RT_ACCELERATOR");
    case 10: return QStringLiteral("RT_RCDATA");
    case 11: return QStringLiteral("RT_MESSAGETABLE");
    case 12: return QStringLiteral("RT_GROUP_CURSOR");
    case 14: return QStringLiteral("RT_GROUP_ICON");
    case 16: return QStringLiteral("RT_VERSION");
    case 24: return QStringLiteral("RT_MANIFEST");
    default: return QString();
    }
}

bool findEmbeddedManifestRva(const QByteArray &data, quint32 rootFo, quint32 absEnd, quint32 *outRva, quint32 *outSize)
{
    *outRva = 0;
    *outSize = 0;

    std::function<bool(quint32, int, bool)> walk;
    walk = [&](quint32 dirFo, int depth, bool inManifestBranch) -> bool {
        if (dirFo + 16 > absEnd || dirFo + 16 > static_cast<quint32>(data.size())) {
            return false;
        }
        const uchar *b = reinterpret_cast<const uchar *>(data.constData() + dirFo);
        const quint16 nNamed = readLe16(b + 12);
        const quint16 nId = readLe16(b + 14);
        const quint32 nEntries = quint32(nNamed) + quint32(nId);
        quint32 entryOff = 16;
        for (quint32 i = 0; i < nEntries; ++i) {
            if (dirFo + entryOff + 8 > absEnd || dirFo + entryOff + 8 > static_cast<quint32>(data.size())) {
                break;
            }
            const quint32 name = readLe32(b + entryOff);
            const quint32 otd = readLe32(b + entryOff + 4);
            entryOff += 8;
            const bool isNamed = (name & 0x80000000u) != 0;
            const quint32 id = isNamed ? 0u : name;

            if (otd & 0x80000000u) {
                const quint32 subFo = rootFo + (otd & 0x7FFFFFFFu);
                bool branch = inManifestBranch;
                if (depth == 0) {
                    if (isNamed) {
                        continue;
                    }
                    if (id != 24u) {
                        continue;
                    }
                    branch = true;
                }
                if (walk(subFo, depth + 1, branch)) {
                    return true;
                }
            } else {
                if (!inManifestBranch) {
                    continue;
                }
                if (depth < 2) {
                    continue;
                }
                const quint32 dataFo = rootFo + otd;
                if (dataFo + 16 > static_cast<quint32>(data.size())) {
                    continue;
                }
                const uchar *de = reinterpret_cast<const uchar *>(data.constData() + dataFo);
                *outRva = readLe32(de);
                *outSize = readLe32(de + 4);
                return true;
            }
        }
        return false;
    };

    return walk(rootFo, 0, false);
}

QString decodeClrImageFlags(quint32 flags)
{
    struct Bit {
        quint32 mask;
        const char *name;
    };
    static const Bit kBits[] = {
        {0x00000001u, "ILONLY"},
        {0x00000002u, "32BITREQUIRED"},
        {0x00000004u, "IL_LIBRARY"},
        {0x00000008u, "STRONGNAMESIGNED"},
        {0x00020000u, "TRACKDEBUGDATA"},
    };
    QStringList parts;
    for (const Bit &b : kBits) {
        if ((flags & b.mask) != 0) {
            parts << QString::fromLatin1(b.name);
        }
    }
    if (parts.isEmpty()) {
        return QString();
    }
    return parts.join(QStringLiteral(", "));
}

QString decodeGuardCfFlags(quint32 flags)
{
    if (flags == 0) {
        return QString();
    }
    struct Bit { quint32 mask; const char *name; };
    static const Bit kTable[] = {
        {0x00000100u, "CF_INSTRUMENTED"},
        {0x00000200u, "CFW_INSTRUMENTED"},
        {0x00000400u, "CF_FUNCTION_TABLE_PRESENT"},
        {0x00000800u, "SECURITY_COOKIE_UNUSED"},
        {0x00001000u, "PROTECT_DELAYLOAD_IAT"},
        {0x00002000u, "DELAYLOAD_IAT_IN_OWN_SECTION"},
        {0x00004000u, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"},
        {0x00008000u, "CF_ENABLE_EXPORT_SUPPRESSION"},
        {0x00010000u, "CF_LONGJUMP_TABLE_PRESENT"},
        {0x00020000u, "RF_INSTRUMENTED"},
        {0x00040000u, "RF_ENABLE"},
        {0x00080000u, "RF_STRICT"},
        {0x00100000u, "RETPOLINE_PRESENT"},
        {0x00400000u, "EH_CONTINUATION_TABLE_PRESENT"},
    };
    QStringList parts;
    quint32 known = 0;
    for (const Bit &b : kTable) {
        if (flags & b.mask) {
            parts << QString::fromLatin1(b.name);
            known |= b.mask;
        }
    }
    const quint32 rest = flags & ~known;
    if (rest != 0) {
        parts << QStringLiteral("0x%1").arg(rest, 0, 16);
    }
    return parts.join(QLatin1String(", "));
}

/** Green callout appended to JSON explanation: raw value + decoded flags for the opened PE. */
QString appendDllCharacteristicsThisImageHtml(const QString &baseHtml, quint16 dllChars)
{
    QString decoded = PEUtils::getDLLCharacteristics(dllChars);
    if (decoded.startsWith(QLatin1String("UI/"))) {
        decoded.clear();
    }
    constexpr quint16 kKnownMask = static_cast<quint16>(
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        | IMAGE_DLLCHARACTERISTICS_NO_ISOLATION | IMAGE_DLLCHARACTERISTICS_NO_SEH
        | IMAGE_DLLCHARACTERISTICS_NO_BIND | IMAGE_DLLCHARACTERISTICS_APPCONTAINER
        | IMAGE_DLLCHARACTERISTICS_WDM_DRIVER | IMAGE_DLLCHARACTERISTICS_GUARD_CF
        | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE);
    const quint16 unknownBits = dllChars & static_cast<quint16>(~kKnownMask);

    LanguageManager &lm = LanguageManager::getInstance();
    auto ui = [&lm](const QString &key, const QString &fallback) -> QString {
        const QString s = lm.getString(key, fallback);
        return (s == key) ? fallback : s;
    };
    const QString title = ui(QStringLiteral("UI/explain_dll_this_image"), QStringLiteral("This image"));
    QString html = baseHtml;
    html += QStringLiteral("<div style=\"margin-top: 10px; margin-bottom: 8px; padding: 12px; background: #f0fdf4; border-left: 4px solid #16a34a; border-radius: 6px;\">");
    html += QStringLiteral("<div style=\"font-weight: 600; color: #065f46; margin-bottom: 6px;\">%1</div>").arg(title.toHtmlEscaped());
    html += QStringLiteral("<div style=\"font-family: monospace; color: #1f2937; margin-bottom: 6px;\">0x%1</div>").arg(dllChars, 4, 16, QChar('0'));
    if (!decoded.isEmpty()) {
        html += QStringLiteral("<div style=\"color: #334155; line-height: 1.5;\">%1</div>").arg(decoded.toHtmlEscaped());
    }
    if (unknownBits != 0u) {
        const QString unkLabel = ui(QStringLiteral("UI/explain_dll_unknown_bits"), QStringLiteral("Unknown or reserved bits:"));
        html += QStringLiteral("<div style=\"margin-top: 8px; color: #b45309;\"><span style=\"font-weight: 600;\">%1</span> <span style=\"font-family: monospace;\">0x%2</span></div>")
                     .arg(unkLabel.toHtmlEscaped(), QString::number(unknownBits, 16));
    }
    html += QStringLiteral("</div>");
    return html;
}

} // namespace

static_assert(sizeof(IMAGE_COR20_HEADER) == 72, "IMAGE_COR20_HEADER size mismatch");

PEParserNew::PEParserNew(QObject *parent)
    : QObject(parent)
    , m_isValid(false)
    , m_isParsing(false)
    , m_dataDirectoryParser(m_fileData)
{
}

PEParserNew::~PEParserNew()
{
    clear();
}

bool PEParserNew::loadFile(const QString &filePath)
{
    clear();
    
    m_file.setFileName(filePath);
    if (!m_file.open(QIODevice::ReadOnly)) {
        emit errorOccurred(LANG_PARAM("UI/error_file_open_generic", "filepath", filePath));
        return false;
    }
    
    m_dataModel.setFilePath(filePath);
    m_dataModel.setFileSize(m_file.size());
    
    if (m_file.size() > LARGE_FILE_THRESHOLD) {
        emit parsingProgress(5, LANG("UI/progress_large_file_detected"));
    } else {
        emit parsingProgress(5, LANG("UI/progress_file_loaded"));
    }

    // Always load the full image into memory so structure parsing and the hex view see every byte.
    m_fileData = m_file.readAll();
    m_file.close();
    
    // Parse DOS header
    if (!parseDOSHeader()) {
        return false;
    }
    
    emit parsingProgress(15, LANG("UI/progress_dos_header"));
    
    // Parse PE headers
    if (!parsePEHeaders()) {
        return false;
    }
    
    emit parsingProgress(25, LANG("UI/progress_pe_headers"));
    
    // Parse sections
    if (!parseSections()) {
        return false;
    }
    
    emit parsingProgress(35, LANG("UI/progress_sections"));
    
    // Parse data directories (NEW: Microsoft PE Format compliant)
    if (!parseDataDirectories()) {
        return false;
    }
    
    emit parsingProgress(50, LANG("UI/progress_data_directories"));
    
    m_dataModel.setValid(true);
    m_isValid = true;
    
    // Parsing complete, but MainWindow still needs to update heavy UI widgets (tree/hex/tabs).
    // Leave headroom so 100% is only shown when the UI is actually ready.
    emit parsingProgress(85, LANG("UI/progress_complete"));
    emit parsingComplete(true);
    return true;
}

void PEParserNew::loadFileAsync(const QString &filePath)
{
    if (m_isParsing) {
        m_parsingFuture.waitForFinished();
    }
    
    m_isParsing = true;
    emit parsingProgress(0, LANG("UI/progress_async_start"));
    
    m_parsingFuture = QtConcurrent::run([this, filePath]() {
        QMutexLocker locker(&m_parsingMutex);
        
        emit parsingProgress(1, LANG("UI/progress_async_loading"));
        
        bool success = loadFile(filePath);
        m_isParsing = false;
        
        QMetaObject::invokeMethod(this, [this, success]() {
            if (success) {
                // Keep < 100 until MainWindow finishes post-parse UI updates.
                emit parsingProgress(90, LANG("UI/progress_async_complete"));
            } else {
                emit parsingProgress(100, LANG("UI/progress_async_failed"));
                // loadFile() does not emit parsingComplete(false) on early returns.
                emit parsingComplete(false);
            }
        }, Qt::QueuedConnection);
    });
}

void PEParserNew::clear()
{
    m_file.close();
    m_fileData.clear();
    m_dataModel.clear();
    m_optionalHeaderBuffer.clear();
    m_cachedSections.clear();
    m_cachedDosHeader = IMAGE_DOS_HEADER{};
    m_cachedFileHeader = IMAGE_FILE_HEADER{};
    m_isValid = false;
    m_isParsing = false;
    invalidateFieldOffsetLookup();
}

void PEParserNew::invalidateFieldOffsetLookup()
{
    m_fieldOffsetLookup.clear();
    m_fieldOffsetLookupValid = false;
}

void PEParserNew::ensureFieldOffsetLookup()
{
    if (m_fieldOffsetLookupValid) {
        return;
    }

    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    if (!dosHeader || !fileHeader || !optionalHeader) {
        m_fieldOffsetLookupValid = true;
        return;
    }

    QHash<QString, QPair<quint32, quint32>> &fieldOffsets = m_fieldOffsetLookup;

    fieldOffsets[QStringLiteral("e_magic")] = QPair<quint32, quint32>(0, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_cblp")] = QPair<quint32, quint32>(2, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_cp")] = QPair<quint32, quint32>(4, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_crlc")] = QPair<quint32, quint32>(6, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_cparhdr")] = QPair<quint32, quint32>(8, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_minalloc")] = QPair<quint32, quint32>(10, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_maxalloc")] = QPair<quint32, quint32>(12, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_ss")] = QPair<quint32, quint32>(14, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_sp")] = QPair<quint32, quint32>(16, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_csum")] = QPair<quint32, quint32>(18, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_ip")] = QPair<quint32, quint32>(20, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_cs")] = QPair<quint32, quint32>(22, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_lfarlc")] = QPair<quint32, quint32>(24, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_ovno")] = QPair<quint32, quint32>(26, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_res")] = QPair<quint32, quint32>(28, static_cast<quint32>(sizeof(quint16) * 4));
    fieldOffsets[QStringLiteral("e_oemid")] = QPair<quint32, quint32>(36, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_oeminfo")] = QPair<quint32, quint32>(38, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("e_res2")] = QPair<quint32, quint32>(40, static_cast<quint32>(sizeof(quint16) * 10));
    fieldOffsets[QStringLiteral("e_lfanew")] = QPair<quint32, quint32>(60, static_cast<quint32>(sizeof(quint32)));

    quint32 peHeaderOffset = dosHeader->e_lfanew;
    fieldOffsets[QStringLiteral("Signature")] = QPair<quint32, quint32>(peHeaderOffset, static_cast<quint32>(sizeof(quint32)));

    quint32 fileHeaderOffset = peHeaderOffset + sizeof(quint32);
    fieldOffsets[QStringLiteral("Machine")] = QPair<quint32, quint32>(fileHeaderOffset, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("NumberOfSections")] = QPair<quint32, quint32>(fileHeaderOffset + 2, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("TimeDateStamp")] = QPair<quint32, quint32>(fileHeaderOffset + 4, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("PointerToSymbolTable")] = QPair<quint32, quint32>(fileHeaderOffset + 8, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("NumberOfSymbols")] = QPair<quint32, quint32>(fileHeaderOffset + 12, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfOptionalHeader")] = QPair<quint32, quint32>(fileHeaderOffset + 16, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("Characteristics")] = QPair<quint32, quint32>(fileHeaderOffset + 18, static_cast<quint32>(sizeof(quint16)));

    quint32 optionalHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    fieldOffsets[QStringLiteral("Magic")] = QPair<quint32, quint32>(optionalHeaderOffset, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MajorLinkerVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 2, static_cast<quint32>(sizeof(quint8)));
    fieldOffsets[QStringLiteral("MinorLinkerVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 3, static_cast<quint32>(sizeof(quint8)));
    fieldOffsets[QStringLiteral("SizeOfCode")] = QPair<quint32, quint32>(optionalHeaderOffset + 4, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfInitializedData")] = QPair<quint32, quint32>(optionalHeaderOffset + 8, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfUninitializedData")] = QPair<quint32, quint32>(optionalHeaderOffset + 12, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("AddressOfEntryPoint")] = QPair<quint32, quint32>(optionalHeaderOffset + 16, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("BaseOfCode")] = QPair<quint32, quint32>(optionalHeaderOffset + 20, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("BaseOfData")] = QPair<quint32, quint32>(optionalHeaderOffset + 24, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("ImageBase")] = QPair<quint32, quint32>(optionalHeaderOffset + 28, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SectionAlignment")] = QPair<quint32, quint32>(optionalHeaderOffset + 32, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("FileAlignment")] = QPair<quint32, quint32>(optionalHeaderOffset + 36, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("MajorOperatingSystemVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 40, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MinorOperatingSystemVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 42, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MajorImageVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 44, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MinorImageVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 46, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MajorSubsystemVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 48, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("MinorSubsystemVersion")] = QPair<quint32, quint32>(optionalHeaderOffset + 50, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("Win32VersionValue")] = QPair<quint32, quint32>(optionalHeaderOffset + 52, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfImage")] = QPair<quint32, quint32>(optionalHeaderOffset + 56, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfHeaders")] = QPair<quint32, quint32>(optionalHeaderOffset + 60, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("CheckSum")] = QPair<quint32, quint32>(optionalHeaderOffset + 64, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("Subsystem")] = QPair<quint32, quint32>(optionalHeaderOffset + 68, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("DllCharacteristics")] = QPair<quint32, quint32>(optionalHeaderOffset + 70, static_cast<quint32>(sizeof(quint16)));
    fieldOffsets[QStringLiteral("SizeOfStackReserve")] = QPair<quint32, quint32>(optionalHeaderOffset + 72, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfStackCommit")] = QPair<quint32, quint32>(optionalHeaderOffset + 76, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfHeapReserve")] = QPair<quint32, quint32>(optionalHeaderOffset + 80, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("SizeOfHeapCommit")] = QPair<quint32, quint32>(optionalHeaderOffset + 84, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("LoaderFlags")] = QPair<quint32, quint32>(optionalHeaderOffset + 88, static_cast<quint32>(sizeof(quint32)));
    fieldOffsets[QStringLiteral("NumberOfRvaAndSizes")] = QPair<quint32, quint32>(optionalHeaderOffset + 92, static_cast<quint32>(sizeof(quint32)));

    fieldOffsets[QStringLiteral("DOS Header")] = QPair<quint32, quint32>(0, static_cast<quint32>(sizeof(IMAGE_DOS_HEADER)));
    fieldOffsets[QStringLiteral("PE Header")] = QPair<quint32, quint32>(peHeaderOffset, static_cast<quint32>(sizeof(quint32) + sizeof(IMAGE_FILE_HEADER)));
    fieldOffsets[QStringLiteral("File Header")] = QPair<quint32, quint32>(fileHeaderOffset, static_cast<quint32>(sizeof(IMAGE_FILE_HEADER)));
    fieldOffsets[QStringLiteral("Optional Header")] = QPair<quint32, quint32>(optionalHeaderOffset, static_cast<quint32>(fileHeader->SizeOfOptionalHeader));

    quint32 sectionsOffset = optionalHeaderOffset + fileHeader->SizeOfOptionalHeader;
    quint32 sectionsSize = fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    fieldOffsets[QStringLiteral("Sections")] = QPair<quint32, quint32>(sectionsOffset, sectionsSize);

    quint16 magic = optionalHeader->Magic;
    quint32 dataDirectoriesOffset;
    if (magic == 0x10b) {
        dataDirectoriesOffset = optionalHeaderOffset + 96;
    } else {
        dataDirectoriesOffset = optionalHeaderOffset + 112;
    }
    quint32 dataDirectoriesSize = 16 * sizeof(IMAGE_DATA_DIRECTORY);
    fieldOffsets[QStringLiteral("Data Directories")] = QPair<quint32, quint32>(dataDirectoriesOffset, dataDirectoriesSize);

    const QStringList &dirKeys = dataDirectoryFieldKeys();
    for (int i = 0; i < 16 && i < dirKeys.size(); ++i) {
        quint32 addressOffset = dataDirectoriesOffset + (i * 8);
        quint32 sizeOffset = dataDirectoriesOffset + (i * 8) + 4;
        const QString &k = dirKeys.at(i);
        fieldOffsets[k] = QPair<quint32, quint32>(addressOffset, 8);
        fieldOffsets[k + QStringLiteral(" Address")] = QPair<quint32, quint32>(addressOffset, 4);
        fieldOffsets[k + QStringLiteral(" Size")] = QPair<quint32, quint32>(sizeOffset, 4);
    }

    m_fieldOffsetLookupValid = true;
}

bool PEParserNew::isValid() const
{
    return m_isValid;
}

bool PEParserNew::isParsing() const
{
    return m_isParsing;
}

QString PEParserNew::getFilePath() const
{
    return m_dataModel.getFilePath();
}



const PEDataModel& PEParserNew::getDataModel() const
{
    return m_dataModel;
}

const QByteArray& PEParserNew::getFileData() const
{
    return m_fileData;
}

void PEParserNew::cancelParsing()
{
    if (m_isParsing) {
        m_parsingFuture.waitForFinished();
        m_isParsing = false;
    }
}

void PEParserNew::onAsyncParsingComplete()
{
    // This slot is called when async parsing completes
}

// Core parsing methods (Microsoft PE Format compliant)
bool PEParserNew::parseDOSHeader()
{
    if (m_fileData.size() < sizeof(IMAGE_DOS_HEADER)) {
        emit errorOccurred(LANG("UI/error_file_too_small"));
        return false;
    }
    
    const IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_fileData.constData());
    
    // Validate DOS magic number
    if (!PEUtils::isValidDOSMagic(dosHeader->e_magic)) {
        emit errorOccurred(LANG("UI/error_invalid_dos"));
        return false;
    }
    
    // Check if PE header exists
    if (dosHeader->e_lfanew >= m_fileData.size() || 
        dosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER)) {
        emit errorOccurred(LANG("UI/error_invalid_pe_offset"));
        return false;
    }
    
    m_cachedDosHeader = *dosHeader;
    m_dataModel.setDOSHeader(&m_cachedDosHeader);
    return true;
}

bool PEParserNew::parsePEHeaders()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    if (!dosHeader) return false;
    
    quint32 peOffset = dosHeader->e_lfanew;
    
    // Parse PE signature
    if (peOffset + sizeof(quint32) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_pe_signature_beyond"));
        return false;
    }
    
    quint32 peSignature = *reinterpret_cast<const quint32*>(m_fileData.constData() + peOffset);
    if (!PEUtils::isValidPESignature(peSignature)) {
        emit errorOccurred(LANG("UI/error_invalid_pe_signature"));
        return false;
    }
    
    // Parse file header (immediately after the PE signature)
    quint32 fileHeaderOffset = peOffset + sizeof(quint32);
    if (fileHeaderOffset + sizeof(IMAGE_FILE_HEADER) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_pe_header_beyond"));
        return false;
    }
    
    const IMAGE_FILE_HEADER *fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_fileData.constData() + fileHeaderOffset
    );
    m_cachedFileHeader = *fileHeader;
    m_dataModel.setFileHeader(&m_cachedFileHeader);
    
    // Parse optional header
    quint32 optionalHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    if (optionalHeaderOffset + fileHeader->SizeOfOptionalHeader > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_optional_header_beyond"));
        return false;
    }
    
    m_optionalHeaderBuffer.resize(static_cast<int>(fileHeader->SizeOfOptionalHeader));
    memcpy(m_optionalHeaderBuffer.data(),
           m_fileData.constData() + optionalHeaderOffset,
           static_cast<size_t>(fileHeader->SizeOfOptionalHeader));

    const IMAGE_OPTIONAL_HEADER *optionalHeader = reinterpret_cast<const IMAGE_OPTIONAL_HEADER*>(
        m_optionalHeaderBuffer.constData()
    );

    if (!PEUtils::isValidOptionalHeaderMagic(optionalHeader->Magic)) {
        qWarning() << "Unexpected optional header magic" << QString::number(optionalHeader->Magic, 16)
                   << "at offset" << QString("0x%1").arg(optionalHeaderOffset, 0, 16);
        emit errorOccurred(LANG("UI/error_invalid_optional_magic"));
        return false;
    }

    m_dataModel.setOptionalHeader(optionalHeader);
    return true;
}

bool PEParserNew::parseSections()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return false;
    }
    
    // Calculate section table offset (PE signature + file header + optional header)
    quint32 sectionTableOffset = dosHeader->e_lfanew
                               + sizeof(quint32) // PE signature
                               + sizeof(IMAGE_FILE_HEADER)
                               + fileHeader->SizeOfOptionalHeader;
    
    if (sectionTableOffset + (fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) > m_fileData.size()) {
        emit errorOccurred(LANG("UI/error_section_table_beyond"));
        return false;
    }
    
    // Copy section headers: QList stores pointers — must not point into m_fileData (QByteArray may detach
    // when shared, e.g. with HexViewer), which would invalidate those pointers.
    m_cachedSections.clear();
    const quint16 sectionCount = fileHeader->NumberOfSections;
    m_cachedSections.reserve(sectionCount);
    for (quint16 i = 0; i < sectionCount; ++i) {
        const IMAGE_SECTION_HEADER *section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            m_fileData.constData() + sectionTableOffset + (i * sizeof(IMAGE_SECTION_HEADER))
        );
        m_cachedSections.push_back(*section);
        m_dataModel.addSection(&m_cachedSections.last());
    }
    
    return true;
}

bool PEParserNew::parseDataDirectories()
{
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return false;
    }
    
    // Calculate the start of the data directories inside the optional header
    quint32 optionalHeaderOffset = dosHeader->e_lfanew
                                + sizeof(quint32) // PE signature
                                + sizeof(IMAGE_FILE_HEADER);
    
    quint16 magic = optionalHeader->Magic;
    quint32 numberOfRvaAndSizesOffset = (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 92 : 108; // 0x5C / 0x6C
    quint32 dataDirectoryOffset = optionalHeaderOffset + numberOfRvaAndSizesOffset + sizeof(quint32);
    
    // Use the specialized data directory parser
    return m_dataDirectoryParser.parseDataDirectories(optionalHeader, dataDirectoryOffset, m_dataModel);
}

quint32 PEParserNew::rvaToFileOffset(quint32 rva)
{
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_dataModel.getSections();
    
    // Find the section that contains this RVA
    for (const IMAGE_SECTION_HEADER *section : sections) {
        quint32 sectionStart = section->VirtualAddress;
        quint32 sectionSize = qMax(section->getVirtualSize(), section->SizeOfRawData);
        quint32 sectionEnd = sectionStart + sectionSize;
        
        if (rva >= sectionStart && rva < sectionEnd) {
            // Calculate file offset
            quint32 offsetInSection = rva - sectionStart;
            return section->PointerToRawData + offsetInSection;
        }
    }
    
    return 0;
}

bool PEParserNew::isLargeFile() const
{
    return m_dataModel.getFileSize() > LARGE_FILE_THRESHOLD;
}

bool PEParserNew::isVeryLargeFile() const
{
    return m_dataModel.getFileSize() > VERY_LARGE_FILE_THRESHOLD;
}

// Field explanation and offset methods (for UI compatibility)
QString PEParserNew::getFieldExplanation(const QString &fieldName)
{
    // Get current language from language manager
    QString currentLanguage = LanguageManager::getInstance().getCurrentLanguage();

    FieldExplanationCaches &fec = fieldExplanationCaches();

    // Load explanations from the language-specific JSON file (resolve path once per language per cache generation)
    QString explanationsPath;
    if (!fec.explanationsPathByLanguage.contains(currentLanguage)) {
        const QString fileName = (currentLanguage == QStringLiteral("pt")) ? QStringLiteral("explanations_pt.json")
                                                                           : QStringLiteral("explanations.json");
        fec.explanationsPathByLanguage.insert(currentLanguage, findConfigFile(fileName));
    }
    explanationsPath = fec.explanationsPathByLanguage.value(currentLanguage);
    QHash<QString, QString> &explanationHtmlCache = fec.explanationHtmlCache;
    QHash<QString, QJsonObject> &languageJsonCache = fec.languageJsonCache;
    QHash<QString, QDateTime> &languageJsonMtime = fec.languageJsonMtime;

    // Include optional-header value in cache key for fields whose explanation depends on the loaded image
    QString cacheFieldKey = fieldName;
    if (fieldName == QStringLiteral("DllCharacteristics")) {
        const IMAGE_OPTIONAL_HEADER *optHdr = m_dataModel.getOptionalHeader();
        if (optHdr) {
            cacheFieldKey += QStringLiteral("|0x") + QString::number(optHdr->DllCharacteristics, 16);
        }
    }
    const QString htmlCacheKey = explanationsPath + QStringLiteral("|") + currentLanguage + QStringLiteral("|") + cacheFieldKey;
    if (explanationHtmlCache.contains(htmlCacheKey)) {
        return explanationHtmlCache.value(htmlCacheKey);
    }

    auto cacheAndReturn = [&](const QString &value) -> QString {
        explanationHtmlCache.insert(htmlCacheKey, value);
        return value;
    };

    const QString langCacheKey = explanationsPath + QStringLiteral("|") + currentLanguage;
    QFileInfo explainInfo(explanationsPath);
    const QDateTime currentMtime = explainInfo.exists() ? explainInfo.lastModified() : QDateTime();
    if (!languageJsonCache.contains(langCacheKey) ||
        languageJsonMtime.value(langCacheKey) != currentMtime) {
        QFile explanationsFile(explanationsPath);
        if (explanationsFile.open(QIODevice::ReadOnly)) {
            QJsonDocument doc = QJsonDocument::fromJson(explanationsFile.readAll());
            QJsonObject root = doc.object();
            if (root.contains(currentLanguage)) {
                languageJsonCache.insert(langCacheKey, root[currentLanguage].toObject());
                languageJsonMtime.insert(langCacheKey, currentMtime);
            } else {
                languageJsonCache.remove(langCacheKey);
                languageJsonMtime.remove(langCacheKey);
            }
        }
    }

    if (languageJsonCache.contains(langCacheKey)) {
        QJsonObject languageObj = languageJsonCache.value(langCacheKey);
            
            // Handle section names dynamically (e.g., "Section 1: .text", "Section 2: .data")
            if (fieldName.startsWith("Section ")) {
                // Extract section name if possible
                QString sectionInfo = fieldName;
                QString sectionName;
                if (fieldName.contains(QStringLiteral(": "))) {
                    sectionName = fieldName.split(QStringLiteral(": ")).last();
                }
                sectionName.remove(QChar(0));
                sectionName = sectionName.trimmed();

                // Try to get generic "Section" explanation
                if (languageObj.contains("Section")) {
                    QJsonObject sectionObj = languageObj["Section"].toObject();
                    QString description = sectionObj["description"].toString();
                    QString purpose = sectionObj["purpose"].toString();
                    QString note = sectionObj["note"].toString();
                    QString securityNotes = sectionObj["security_notes"].toString();
                    
                    // Format the explanation with section-specific information
                    QString explanation;
                    explanation += QString("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>").arg(description);
                    
                    if (!sectionName.isEmpty() && sectionName != "0x") {
                        // Add section-specific information
                        QString sectionTypeInfo = "";
                        QString sectionTypeKey = "";
                        const QString sectionNameNorm = sectionName.trimmed().toLower();
                        if (sectionNameNorm == ".text" || sectionNameNorm == "_text") {
                            sectionTypeKey = "section_info_text";
                        } else if (sectionNameNorm == ".data" || sectionNameNorm == "_data") {
                            sectionTypeKey = "section_info_data";
                        } else if (sectionNameNorm == ".rdata" || sectionNameNorm == "_rdata" ||
                                   sectionNameNorm == "rdata" || sectionNameNorm == "._rdata") {
                            sectionTypeKey = "section_info_rdata";
                        } else if (sectionNameNorm == ".rsrc" || sectionNameNorm == "_rsrc") {
                            sectionTypeKey = "section_info_rsrc";
                        } else if (sectionNameNorm == ".reloc" || sectionNameNorm == "_reloc") {
                            sectionTypeKey = "section_info_reloc";
                        } else if (sectionNameNorm == ".idata" || sectionNameNorm == "_idata") {
                            sectionTypeKey = "section_info_idata";
                        } else if (sectionNameNorm == ".edata" || sectionNameNorm == "_edata") {
                            sectionTypeKey = "section_info_edata";
                        } else if (sectionNameNorm == ".tls" || sectionNameNorm == "_tls" ||
                                   sectionNameNorm.startsWith(".tls$") || sectionNameNorm.startsWith("_tls$")) {
                            sectionTypeKey = "section_info_tls";
                        } else if (sectionNameNorm == ".gfids" || sectionNameNorm == "_gfids") {
                            sectionTypeKey = "section_info_gfids";
                        } else if (sectionNameNorm == ".pdata" || sectionNameNorm == "_pdata") {
                            sectionTypeKey = "section_info_pdata";
                        } else if (sectionNameNorm == ".xdata" || sectionNameNorm == "_xdata") {
                            sectionTypeKey = "section_info_xdata";
                        } else if (sectionNameNorm == ".didat" || sectionNameNorm == "_didat") {
                            sectionTypeKey = "section_info_didat";
                        } else if (sectionNameNorm == ".crt" || sectionNameNorm == "_crt" ||
                                   sectionNameNorm.startsWith(".crt$") || sectionNameNorm.startsWith("_crt$")) {
                            sectionTypeKey = "section_info_crt";
                        } else if (sectionNameNorm == ".00cfg" || sectionNameNorm == ".cfg" ||
                                   sectionNameNorm == "_cfg") {
                            sectionTypeKey = "section_info_cfg";
                        } else if (sectionNameNorm == ".sxdata" || sectionNameNorm == "_sxdata") {
                            sectionTypeKey = "section_info_sxdata";
                        } else if (sectionNameNorm == ".debug" || sectionNameNorm == "_debug") {
                            sectionTypeKey = "section_info_debug";
                        } else if (sectionNameNorm == ".cormeta" || sectionNameNorm == "_cormeta") {
                            sectionTypeKey = "section_info_cormeta";
                        } else if (sectionNameNorm == ".managed" || sectionNameNorm == "_managed") {
                            sectionTypeKey = "section_info_managed";
                        }
                        
                        if (!sectionTypeKey.isEmpty()) {
                            LanguageManager &lm = LanguageManager::getInstance();
                            // getString(key, "") returns the key when missing — never use that for body text.
                            sectionTypeInfo = lm.getIniString(sectionTypeKey);
                            if (sectionTypeInfo.isEmpty()) {
                                sectionTypeInfo = lm.getIniString(QStringLiteral("UI/") + sectionTypeKey);
                            }
                            if (sectionTypeInfo.isEmpty()) {
                                sectionTypeInfo = defaultEnglishSectionTypeInfo(sectionTypeKey);
                            }
                        }
                        
                        if (!sectionTypeInfo.isEmpty()) {
                            explanation += QString("<div style='margin-bottom: 8px; padding: 8px; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 4px;'><b style='color: #1e40af;'>Section: %1</b><br>%2</div>").arg(sectionName, sectionTypeInfo);
                        }
                    }
                    
                    if (!purpose.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #1d4ed8;'>Purpose:</b> %1</div>").arg(purpose);
                    }
                    
                    if (!note.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7c3aed;'>Note:</b> %1</div>").arg(note);
                    }
                    
                    if (!securityNotes.isEmpty()) {
                        explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7f1d1d;'>Security Notes:</b> %1</div>").arg(securityNotes);
                    }
                    
                    return cacheAndReturn(explanation);
                }
            }
            
            // Check for exact field name match
            if (languageObj.contains(fieldName)) {
                QJsonObject fieldObj = languageObj[fieldName].toObject();
                QString description = fieldObj["description"].toString();
                QString purpose = fieldObj["purpose"].toString();
                QString securityNotes = fieldObj["security_notes"].toString();
                QString value = fieldObj["value"].toString();
                QString note = fieldObj["note"].toString();
                QString commonNames = fieldObj["common_names"].toString();
                
                // Format the explanation with HTML for better presentation
                QString explanation;
                
                // Main description
                explanation += QString("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>").arg(description);
                
                // Value field (if exists)
                if (!value.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #059669;'>Value:</b> <span style='font-family: monospace; background: #f3f4f6; padding: 2px 6px; border-radius: 4px;'>%1</span></div>").arg(value);
                }
                
                // Purpose field
                if (!purpose.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #1d4ed8;'>Purpose:</b> %1</div>").arg(purpose);
                }
                
                // Note field (if exists)
                if (!note.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7c3aed;'>Note:</b> %1</div>").arg(note);
                }
                
                // Common names field (if exists)
                if (!commonNames.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #dc2626;'>Common Names:</b> <span style='font-family: monospace; background: #fef2f2; padding: 2px 6px; border-radius: 4px; color: #991b1b;'>%1</span></div>").arg(commonNames);
                }
                
                // Security notes - bold and dark red
                if (!securityNotes.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7f1d1d;'>Security Notes:</b> %1</div>").arg(securityNotes);
                }

                if (fieldName == QStringLiteral("DllCharacteristics")) {
                    const IMAGE_OPTIONAL_HEADER *optExplain = m_dataModel.getOptionalHeader();
                    if (optExplain) {
                        explanation = appendDllCharacteristicsThisImageHtml(explanation, optExplain->DllCharacteristics);
                    }
                }

                return cacheAndReturn(explanation);
            }

            // Alias common tree container names to explanation keys.
            // This avoids fallback placeholder text when UI labels differ slightly
            // from JSON keys (e.g., "File Header" vs "PE Header").
            const QMap<QString, QString> explanationAliases = {
                {QStringLiteral("File Header"), QStringLiteral("PE Header")},
                {QStringLiteral("Section Headers"), QStringLiteral("Sections")},
                // Legacy JSON key used lowercase "numbers"; tree field is NumberOfLineNumbers (COFF)
                {QStringLiteral("NumberOfLineNumbers"), QStringLiteral("NumberOfLinenumbers")}
            };
            const QString aliasKey = explanationAliases.value(fieldName);
            if (!aliasKey.isEmpty() && languageObj.contains(aliasKey)) {
                QJsonObject fieldObj = languageObj[aliasKey].toObject();
                QString description = fieldObj["description"].toString();
                QString purpose = fieldObj["purpose"].toString();
                QString securityNotes = fieldObj["security_notes"].toString();
                QString note = fieldObj["note"].toString();

                QString explanation;
                explanation += QString("<div style='margin-bottom: 8px; line-height: 1.6; color: #1f2937;'>%1</div>").arg(description);
                if (!purpose.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #1d4ed8;'>Purpose:</b> %1</div>").arg(purpose);
                }
                if (!note.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7c3aed;'>Note:</b> %1</div>").arg(note);
                }
                if (!securityNotes.isEmpty()) {
                    explanation += QString("<div style='margin-bottom: 8px;'><b style='color: #7f1d1d;'>Security Notes:</b> %1</div>").arg(securityNotes);
                }
                return cacheAndReturn(explanation);
            }
    }
    
    // Fallback to placeholder if field not found in JSON
    // All explanations should be in the config JSON files
    return cacheAndReturn(LANG_PARAM("UI/field_explanation_placeholder", "fieldname", fieldName));
}

void PEParserNew::clearFieldExplanationCaches()
{
    clearFieldExplanationCachesInternal();
}

QPair<quint32, quint32> PEParserNew::getFieldOffset(const QString &fieldName)
{
    if (fieldName == QLatin1String("e_magic")) {
        return QPair<quint32, quint32>(0, static_cast<quint32>(sizeof(quint16)));
    }
    if (fieldName == QLatin1String("DOS_STUB")) {
        return QPair<quint32, quint32>(0x40, 0x40);
    }

    if (fieldName == QLatin1String("VirtualAddress") || fieldName == QLatin1String("SizeOfRawData")
        || fieldName == QLatin1String("PointerToRawData") || fieldName == QLatin1String("PointerToRelocations")
        || fieldName == QLatin1String("PointerToLineNumbers") || fieldName == QLatin1String("NumberOfRelocations")
        || fieldName == QLatin1String("NumberOfLineNumbers") || fieldName == QLatin1String("Characteristics")) {
        return QPair<quint32, quint32>(0, 0);
    }

    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    if (!dosHeader || !fileHeader || !optionalHeader) {
        return QPair<quint32, quint32>(0, 0);
    }

    ensureFieldOffsetLookup();
    const auto it = m_fieldOffsetLookup.constFind(fieldName);
    if (it != m_fieldOffsetLookup.constEnd()) {
        return it.value();
    }
    return QPair<quint32, quint32>(0, 0);
}

void PEParserNew::setLanguage(const QString &language)
{
    // Set the language for the language manager
    LanguageManager::getInstance().setLanguage(language);
    
    // Emit signal to notify UI of language change
    emit languageChanged(language);
}

QList<QTreeWidgetItem*> PEParserNew::getPEStructureTree()
{
    QList<QTreeWidgetItem*> treeItems;
    
    // Create DOS Header section
    QTreeWidgetItem *dosHeaderItem = new QTreeWidgetItem();
    dosHeaderItem->setText(0, QStringLiteral("DOS Header"));
    dosHeaderItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("DOS Header"));
    dosHeaderItem->setText(1, "");
    dosHeaderItem->setText(2, QStringLiteral("0x00000000"));
    dosHeaderItem->setText(3, peTreeSizeBytesText(QStringLiteral("0x40")));
    
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    if (dosHeader) {
        addDOSHeaderFields(dosHeaderItem, dosHeader);
    }
    treeItems.append(dosHeaderItem);

    // DOS stub: bytes after IMAGE_DOS_HEADER until min(e_lfanew, 0x80) — single tree row (offset/size columns carry location)
    if (dosHeader && dosHeader->e_lfanew > 0x40 && m_fileData.size() > 0x40) {
        const quint32 stubEnd = qMin(static_cast<quint32>(dosHeader->e_lfanew), 0x80u);
        const quint32 regionSize = (stubEnd > 0x40) ? (stubEnd - 0x40) : 0u;
        if (regionSize > 0) {
            const QByteArray stubBytes = m_fileData.mid(0x40, static_cast<int>(regionSize));
            QTreeWidgetItem *dosStubRoot = new QTreeWidgetItem();
            dosStubRoot->setText(0, QStringLiteral("DOS stub"));
            dosStubRoot->setText(1, formatHexPreview(stubBytes));
            dosStubRoot->setText(2, PEUtils::formatHexWidth(0x40, 8));
            dosStubRoot->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(regionSize, 0)));
            dosStubRoot->setText(4, getFieldMeaning(QStringLiteral("DOS_STUB"), QStringLiteral("-")));
            dosStubRoot->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("DOS_STUB"));
            dosStubRoot->setData(0, kFieldOffsetRole, static_cast<uint>(0x40));
            dosStubRoot->setData(0, kFieldSizeRole, regionSize);
            treeItems.append(dosStubRoot);
        }
    }
    
    // Create Rich Header section (if present)
    if (dosHeader) {
        quint32 richOffset;
        if (PEUtils::findRichHeaderOffset(m_fileData, *dosHeader, richOffset)) {
            quint32 richSize = PEUtils::calculateRichHeaderSize(m_fileData, richOffset);
            
            QTreeWidgetItem *richHeaderItem = new QTreeWidgetItem();
            richHeaderItem->setText(0, "Rich Header");
            richHeaderItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("Rich Header"));
            richHeaderItem->setText(1, "");
            richHeaderItem->setText(2, PEUtils::formatHexWidth(richOffset, 8));
            richHeaderItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(richSize, 0)));
            richHeaderItem->setText(4, ""); // No meaning for section header
            
            addRichHeaderFields(richHeaderItem, richOffset);
            treeItems.append(richHeaderItem);
        }
    }
    
    // Create NT Headers section (parent container for File Header, Optional Header, and Section Headers)
    quint32 ntHeadersOffset = dosHeader ? dosHeader->e_lfanew : 0;
    QTreeWidgetItem *ntHeadersItem = new QTreeWidgetItem();
    ntHeadersItem->setText(0, "NT Headers");
    ntHeadersItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("NT Headers"));
    ntHeadersItem->setText(1, "");
    ntHeadersItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset, 8));
    // NT Headers size = PE Signature (4) + File Header (20) + Optional Header + Section Headers
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    quint32 ntHeadersSize = 4 + 20 + (optionalHeader ? optionalHeader->SizeOfHeaders : 0);
    ntHeadersItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(ntHeadersSize, 0)));
    ntHeadersItem->setText(4, ""); // No meaning for container
    
    // Add PE Signature as first field of NT Headers
    if (ntHeadersOffset + 4 <= m_fileData.size()) {
        quint32 peSignature = *reinterpret_cast<const quint32*>(m_fileData.constData() + ntHeadersOffset);
        addTreeField(ntHeadersItem, "Signature", PEUtils::formatHexWidth(peSignature, 8), 0, sizeof(quint32));
    }
    
    // Create File Header as child of NT Headers
    QTreeWidgetItem *fileHeaderItem = new QTreeWidgetItem(ntHeadersItem);
    fileHeaderItem->setText(0, "File Header");
    fileHeaderItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("File Header"));
    fileHeaderItem->setText(1, "");
    // File Header starts 4 bytes after NT Headers (after PE signature)
    fileHeaderItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset + 4, 8));
    fileHeaderItem->setText(3, peTreeSizeBytesText(QStringLiteral("0x14")));
    fileHeaderItem->setText(4, ""); // No meaning for section header
    
    if (fileHeader) {
        addPEHeaderFields(fileHeaderItem, fileHeader);
    }
    
    // Create Optional Header as child of NT Headers
    QTreeWidgetItem *optionalHeaderItem = new QTreeWidgetItem(ntHeadersItem);
    optionalHeaderItem->setText(0, QStringLiteral("Optional Header"));
    optionalHeaderItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("Optional Header"));
    optionalHeaderItem->setText(1, "");
    // Optional Header starts after PE signature (4 bytes) + File Header (20 bytes) = 24 bytes from NT Headers start
    optionalHeaderItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset + 4 + 20, 8));
    optionalHeaderItem->setText(3, peTreeSizeBytesText(QStringLiteral("0xE0")));
    optionalHeaderItem->setText(4, ""); // No meaning for section header
    
    if (optionalHeader) {
        addOptionalHeaderFields(optionalHeaderItem, optionalHeader);
        
        // Create Data Directories as child of Optional Header
        QTreeWidgetItem *dataDirsItem = new QTreeWidgetItem(optionalHeaderItem);
        dataDirsItem->setText(0, QStringLiteral("Data Directories"));
        dataDirsItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("Data Directories"));
        dataDirsItem->setText(1, "");
        // Data Directories start right after NumberOfRvaAndSizes field
        // NumberOfRvaAndSizes offset depends on PE32 vs PE32+:
        // PE32 (32-bit): NumberOfRvaAndSizes is at offset 96 (0x60) from Optional Header start, and is 4 bytes
        // PE32+ (64-bit): NumberOfRvaAndSizes is at offset 112 (0x70) from Optional Header start, and is 4 bytes
        // So Data Directories base = Optional Header start + NumberOfRvaAndSizes offset + 4
        quint16 magic = optionalHeader->Magic;
        quint32 numberOfRvaAndSizesOffset;
        if (magic == 0x10b) {
            // PE32 (32-bit)
            numberOfRvaAndSizesOffset = 92; // 0x5C
        } else {
            // PE32+ (64-bit)
            numberOfRvaAndSizesOffset = 108; // 0x6C
        }
        quint32 dataDirsOffset = ntHeadersOffset + 4 + 20 + numberOfRvaAndSizesOffset + 4; // NT Headers + PE Sig + File Header + NumberOfRvaAndSizes offset + 4
        dataDirsItem->setText(2, PEUtils::formatHexWidth(dataDirsOffset, 8));
        dataDirsItem->setText(3, peTreeEntriesText(QStringLiteral("16")));
        dataDirsItem->setText(4, ""); // No meaning for container
        
        addDataDirectoryFields(dataDirsItem);
    }
    
    // Create Section Headers as child of NT Headers
    QTreeWidgetItem *sectionsItem = new QTreeWidgetItem(ntHeadersItem);
    sectionsItem->setText(0, "Section Headers");
    sectionsItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("Section Headers"));
    sectionsItem->setText(1, "");
    // Section Headers start after PE signature (4) + File Header (20) + Optional Header
    sectionsItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset + 4 + 20 + (fileHeader ? fileHeader->SizeOfOptionalHeader : 0), 8));
    sectionsItem->setText(3, peTreeEntriesText(PEUtils::formatHexWidth(static_cast<quint64>(m_dataModel.getSections().size()), 0)));
    sectionsItem->setText(4, ""); // No meaning for container
    
    addSectionFields(sectionsItem);
    
    treeItems.append(ntHeadersItem);
    
    return treeItems;
}

void PEParserNew::addDOSHeaderFields(QTreeWidgetItem *parent, const IMAGE_DOS_HEADER *dosHeader)
{
    // Add DOS header fields
        addTreeField(parent, "e_magic", PEUtils::formatHexWidth(dosHeader->e_magic, 4), 0, sizeof(quint16));
    addTreeField(parent, "e_cblp", PEUtils::formatHexWidth(dosHeader->e_cblp, 4), 2, sizeof(quint16));
    addTreeField(parent, "e_cp", PEUtils::formatHexWidth(dosHeader->e_cp, 4), 4, sizeof(quint16));
    addTreeField(parent, "e_crlc", PEUtils::formatHexWidth(dosHeader->e_crlc, 4), 6, sizeof(quint16));
    addTreeField(parent, "e_cparhdr", PEUtils::formatHexWidth(dosHeader->e_cparhdr, 4), 8, sizeof(quint16));
    addTreeField(parent, "e_minalloc", PEUtils::formatHexWidth(dosHeader->e_minalloc, 4), 10, sizeof(quint16));
    addTreeField(parent, "e_maxalloc", PEUtils::formatHexWidth(dosHeader->e_maxalloc, 4), 12, sizeof(quint16));
    addTreeField(parent, "e_ss", PEUtils::formatHexWidth(dosHeader->e_ss, 4), 14, sizeof(quint16));
    addTreeField(parent, "e_sp", PEUtils::formatHexWidth(dosHeader->e_sp, 4), 16, sizeof(quint16));
    addTreeField(parent, "e_csum", PEUtils::formatHexWidth(dosHeader->e_csum, 4), 18, sizeof(quint16));
    addTreeField(parent, "e_ip", PEUtils::formatHexWidth(dosHeader->e_ip, 4), 20, sizeof(quint16));
    addTreeField(parent, "e_cs", PEUtils::formatHexWidth(dosHeader->e_cs, 4), 22, sizeof(quint16));
    addTreeField(parent, "e_lfarlc", PEUtils::formatHexWidth(dosHeader->e_lfarlc, 4), 24, sizeof(quint16));
    addTreeField(parent, "e_ovno", PEUtils::formatHexWidth(dosHeader->e_ovno, 4), 26, sizeof(quint16));
        addTreeField(parent, "e_lfanew", PEUtils::formatHexWidth(dosHeader->e_lfanew, 8), 60, sizeof(quint32));
}

void PEParserNew::addPEHeaderFields(QTreeWidgetItem *parent, const IMAGE_FILE_HEADER *fileHeader)
{
    // File Header fields are relative to File Header start (parent's offset)
    // No offset needed since parent is already at File Header offset
    
    // Add File Header fields
    addTreeField(parent, "Machine", PEUtils::formatHexWidth(fileHeader->Machine, 4), 0, sizeof(quint16));
    addTreeField(parent, "NumberOfSections", PEUtils::formatHexWidth(fileHeader->NumberOfSections, 4), 2, sizeof(quint16));
    addTreeField(parent, "TimeDateStamp", PEUtils::formatHexWidth(fileHeader->TimeDateStamp, 8), 4, sizeof(quint32));
    addTreeField(parent, "PointerToSymbolTable", PEUtils::formatHexWidth(fileHeader->PointerToSymbolTable, 8), 8, sizeof(quint32));
    addTreeField(parent, "NumberOfSymbols", PEUtils::formatHexWidth(fileHeader->NumberOfSymbols, 8), 12, sizeof(quint32));
    addTreeField(parent, "SizeOfOptionalHeader", PEUtils::formatHexWidth(fileHeader->SizeOfOptionalHeader, 4), 16, sizeof(quint16));
    addTreeField(parent, "Characteristics", PEUtils::formatHexWidth(fileHeader->Characteristics, 4), 18, sizeof(quint16));
}

void PEParserNew::addOptionalHeaderFields(QTreeWidgetItem *parent, const IMAGE_OPTIONAL_HEADER *optionalHeader)
{
    // Optional Header fields are relative to Optional Header start (parent's offset)
    // No offset needed since parent is already at Optional Header offset
    
    // Add optional header fields
    addTreeField(parent, "Magic", PEUtils::formatHexWidth(optionalHeader->Magic, 4), 0, sizeof(quint16));
    addTreeField(parent, "MajorLinkerVersion", PEUtils::formatHexWidth(optionalHeader->MajorLinkerVersion, 2), 2, sizeof(quint8));
    addTreeField(parent, "MinorLinkerVersion", PEUtils::formatHexWidth(optionalHeader->MinorLinkerVersion, 2), 3, sizeof(quint8));
    addTreeField(parent, "SizeOfCode", PEUtils::formatHexWidth(optionalHeader->SizeOfCode, 8), 4, sizeof(quint32));
    addTreeField(parent, "SizeOfInitializedData", PEUtils::formatHexWidth(optionalHeader->SizeOfInitializedData, 8), 8, sizeof(quint32));
    addTreeField(parent, "SizeOfUninitializedData", PEUtils::formatHexWidth(optionalHeader->SizeOfUninitializedData, 8), 12, sizeof(quint32));
    addTreeField(parent, "AddressOfEntryPoint", PEUtils::formatHexWidth(optionalHeader->AddressOfEntryPoint, 8), 16, sizeof(quint32));
    addTreeField(parent, "BaseOfCode", PEUtils::formatHexWidth(optionalHeader->BaseOfCode, 8), 20, sizeof(quint32));
    addTreeField(parent, "ImageBase", PEUtils::formatHexWidth(optionalHeader->ImageBase, 16), 24, sizeof(quint64));
    addTreeField(parent, "SectionAlignment", PEUtils::formatHexWidth(optionalHeader->SectionAlignment, 8), 32, sizeof(quint32));
    addTreeField(parent, "FileAlignment", PEUtils::formatHexWidth(optionalHeader->FileAlignment, 8), 36, sizeof(quint32));
    addTreeField(parent, "MajorOperatingSystemVersion", PEUtils::formatHexWidth(optionalHeader->MajorOperatingSystemVersion, 4), 40, sizeof(quint16));
    addTreeField(parent, "MinorOperatingSystemVersion", PEUtils::formatHexWidth(optionalHeader->MinorOperatingSystemVersion, 4), 42, sizeof(quint16));
    addTreeField(parent, "MajorImageVersion", PEUtils::formatHexWidth(optionalHeader->MajorImageVersion, 4), 44, sizeof(quint16));
    addTreeField(parent, "MinorImageVersion", PEUtils::formatHexWidth(optionalHeader->MinorImageVersion, 4), 46, sizeof(quint16));
    addTreeField(parent, "MajorSubsystemVersion", PEUtils::formatHexWidth(optionalHeader->MajorSubsystemVersion, 4), 48, sizeof(quint16));
    addTreeField(parent, "MinorSubsystemVersion", PEUtils::formatHexWidth(optionalHeader->MinorSubsystemVersion, 4), 50, sizeof(quint16));
    addTreeField(parent, "Win32VersionValue", PEUtils::formatHexWidth(optionalHeader->Win32VersionValue, 8), 52, sizeof(quint32));
    addTreeField(parent, "SizeOfImage", PEUtils::formatHexWidth(optionalHeader->SizeOfImage, 8), 56, sizeof(quint32));
    addTreeField(parent, "SizeOfHeaders", PEUtils::formatHexWidth(optionalHeader->SizeOfHeaders, 8), 60, sizeof(quint32));
    addTreeField(parent, "CheckSum", PEUtils::formatHexWidth(optionalHeader->CheckSum, 8), 64, sizeof(quint32));
    addTreeField(parent, "Subsystem", PEUtils::formatHexWidth(optionalHeader->Subsystem, 4), 68, sizeof(quint16));
    addTreeField(parent, "DllCharacteristics", PEUtils::formatHexWidth(optionalHeader->DllCharacteristics, 4), 70, sizeof(quint16));
    addTreeField(parent, "SizeOfStackReserve", PEUtils::formatHexWidth(optionalHeader->SizeOfStackReserve, 16), 72, sizeof(quint64));
    addTreeField(parent, "SizeOfStackCommit", PEUtils::formatHexWidth(optionalHeader->SizeOfStackCommit, 16), 80, sizeof(quint64));
    addTreeField(parent, "SizeOfHeapReserve", PEUtils::formatHexWidth(optionalHeader->SizeOfHeapReserve, 16), 88, sizeof(quint64));
    addTreeField(parent, "SizeOfHeapCommit", PEUtils::formatHexWidth(optionalHeader->SizeOfHeapCommit, 16), 96, sizeof(quint64));
    addTreeField(parent, "LoaderFlags", PEUtils::formatHexWidth(optionalHeader->LoaderFlags, 8), 104, sizeof(quint32));
    addTreeField(parent, "NumberOfRvaAndSizes", PEUtils::formatHexWidth(optionalHeader->NumberOfRvaAndSizes, 8), 108, sizeof(quint32));
}

void PEParserNew::addSectionFields(QTreeWidgetItem *parent)
{
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_dataModel.getSections();
    const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
    
    for (int i = 0; i < sections.size(); ++i) {
        const IMAGE_SECTION_HEADER *section = sections[i];
        if (section) {
            QTreeWidgetItem *sectionItem = new QTreeWidgetItem(parent);
            // Parse section name properly - handle both ASCII and non-ASCII characters
            QString sectionName;
            const char* namePtr = reinterpret_cast<const char*>(section->Name);
            
            // Check if the name is null-terminated or contains only printable characters
            bool hasValidChars = false;
            for (int j = 0; j < 8; ++j) {
                if (namePtr[j] >= 32 && namePtr[j] <= 126) { // Printable ASCII range
                    hasValidChars = true;
                    break;
                }
            }
            
            if (hasValidChars) {
                // Try to find null terminator
                int nameLength = 0;
                while (nameLength < 8 && namePtr[nameLength] != '\0' && namePtr[nameLength] >= 32) {
                    nameLength++;
                }
                sectionName = QString::fromLatin1(namePtr, nameLength);
            } else {
                // If no valid ASCII characters, show as hex
                QByteArray nameBytes(namePtr, 8);
                sectionName = QString("0x") + QString(nameBytes.toHex()).toUpper();
            }
            const QString sectionRowLabel = QStringLiteral("Section %1: %2").arg(i + 1).arg(sectionName);
            sectionItem->setText(0, sectionRowLabel);
            sectionItem->setData(0, PEParserNew::kTreeFieldKeyRole, sectionRowLabel);
            sectionItem->setText(1, "");
            // Section header offset (where the section header structure is in the file)
            // Sections start after PE signature (4) + File Header (20) + Optional Header
            quint32 sectionHeaderOffset = (dosHeader ? dosHeader->e_lfanew : 0) + 4 + 20 + (fileHeader ? fileHeader->SizeOfOptionalHeader : 0) + (i * sizeof(IMAGE_SECTION_HEADER));
            sectionItem->setText(2, PEUtils::formatHexWidth(sectionHeaderOffset, 8));
            sectionItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(sizeof(IMAGE_SECTION_HEADER), 0)));
            
            // Add section details with proper file offsets
            // Section header fields are relative to sectionHeaderOffset (parent's offset)
            // IMAGE_SECTION_HEADER structure:
            // Name[8] at offset 0 (8 bytes)
            // Misc.VirtualSize at offset 8 (4 bytes)
            // VirtualAddress at offset 12 (4 bytes)
            // SizeOfRawData at offset 16 (4 bytes)
            // PointerToRawData at offset 20 (4 bytes)
            // PointerToRelocations at offset 24 (4 bytes)
            // PointerToLinenumbers at offset 28 (4 bytes)
            // NumberOfRelocations at offset 32 (2 bytes)
            // NumberOfLinenumbers at offset 34 (2 bytes)
            // Characteristics at offset 36 (4 bytes)
            
            addTreeField(sectionItem, "Name", sectionName, 0, 8);
            addTreeField(sectionItem, "VirtualSize", PEUtils::formatHexWidth(section->Misc.VirtualSize, 8), 8, sizeof(quint32));
            addTreeField(sectionItem, "VirtualAddress", PEUtils::formatHexWidth(section->VirtualAddress, 8), 12, sizeof(quint32));
            addTreeField(sectionItem, "SizeOfRawData", PEUtils::formatHexWidth(section->SizeOfRawData, 8), 16, sizeof(quint32));
            addTreeField(sectionItem, "PointerToRawData", PEUtils::formatHexWidth(section->PointerToRawData, 8), 20, sizeof(quint32));
            addTreeField(sectionItem, "PointerToRelocations", PEUtils::formatHexWidth(section->PointerToRelocations, 8), 24, sizeof(quint32));
            // Note: PointerToLineNumbers and NumberOfLineNumbers are deprecated in modern PE format
            addTreeField(sectionItem, "PointerToLineNumbers", QStringLiteral("(deprecated)"), 28, sizeof(quint32));
            addTreeField(sectionItem, "NumberOfRelocations", PEUtils::formatHexWidth(section->NumberOfRelocations, 4), 32, sizeof(quint16));
            addTreeField(sectionItem, "NumberOfLineNumbers", QStringLiteral("(deprecated)"), 34, sizeof(quint16));
            addTreeField(sectionItem, "Characteristics", PEUtils::formatHexWidth(section->Characteristics, 8), 36, sizeof(quint32));
        }
    }
}

void PEParserNew::addRichHeaderFields(QTreeWidgetItem *parent, quint32 richOffset)
{
    if (richOffset + 16 > m_fileData.size()) {
        return;
    }
    
    IMAGE_RICH_HEADER richHeader;
    if (!PEUtils::parseRichHeader(m_fileData, richOffset, richHeader)) {
        return;
    }
    
    // Add Rich Header fields - offsets are relative to richOffset (parent's offset)
    addTreeField(parent, "XorKey", PEUtils::formatHexWidth(richHeader.XorKey, 8), 0, sizeof(quint32));
    addTreeField(parent, "RichSignature", PEUtils::formatHexWidth(richHeader.RichSignature, 8), 4, sizeof(quint32));
    addTreeField(parent, "RichVersion", PEUtils::formatHexWidth(richHeader.RichVersion, 8), 8, sizeof(quint32));
    addTreeField(parent, "RichCount", PEUtils::formatHexWidth(richHeader.RichCount, 8), 12, sizeof(quint32));
    
    // Add Rich Entry fields
    QList<IMAGE_RICH_ENTRY> entries = PEUtils::parseRichEntries(m_fileData, richOffset, richHeader.RichCount);
    quint32 entryBaseOffset = 16; // 4 dwords = 16 bytes
    
    for (int i = 0; i < entries.size(); ++i) {
        const IMAGE_RICH_ENTRY &entry = entries[i];
        QString productName = PEUtils::getRichHeaderProductName(entry.ProductId);
        QString entryName = QString("Entry %1: %2").arg(i + 1).arg(productName);
        
        QTreeWidgetItem *entryItem = new QTreeWidgetItem(parent);
        entryItem->setText(0, entryName);
        QString versionMajor = QString::number((entry.ProductVersion >> 8) & 0xFF, 16).toUpper().rightJustified(2, '0');
        QString versionMinor = QString::number(entry.ProductVersion & 0xFF, 16).toUpper().rightJustified(2, '0');
        QString countHex = PEUtils::formatHexWidth(entry.ProductCount, 8);
        entryItem->setText(1, QString("v0x%1.0x%2, Count: %3").arg(versionMajor, versionMinor, countHex));
        quint32 entryOffset = entryBaseOffset + (i * 12); // Each entry is 12 bytes
        entryItem->setText(2, PEUtils::formatHexWidth(richOffset + entryOffset, 8));
        entryItem->setText(3, PEUtils::formatHexWidth(12, 0) + " bytes");
        entryItem->setText(4, ""); // No meaning for entry header
        
        // Add individual entry fields - offsets relative to entry item start.
        addTreeField(entryItem, "ProductId", PEUtils::formatHexWidth(entry.ProductId, 4), 0, sizeof(quint16));
        addTreeField(entryItem, "ProductVersion", PEUtils::formatHexWidth(entry.ProductVersion, 4), 2, sizeof(quint16));
        addTreeField(entryItem, "ProductCount", PEUtils::formatHexWidth(entry.ProductCount, 8), 4, sizeof(quint32));
        addTreeField(entryItem, "ProductTimestamp", PEUtils::formatHexWidth(entry.ProductTimestamp, 8), 8, sizeof(quint32));
    }
}

void PEParserNew::addDataDirectoryFields(QTreeWidgetItem *parent)
{
    // Get the Optional Header to access DataDirectory array
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_dataModel.getOptionalHeader();
    
    if (!optionalHeader) {
        return;
    }
    
    // Get Data Directories base offset from parent item (already calculated correctly in getPEStructureTree)
    QString parentOffsetStr = parent->text(2);
    quint32 dataDirsBaseOffset = 0;
    if (!parentOffsetStr.isEmpty() && parentOffsetStr.startsWith("0x")) {
        bool ok;
        dataDirsBaseOffset = parentOffsetStr.toULong(&ok, 16);
        if (!ok || dataDirsBaseOffset == 0) {
            // Fallback: recalculate if parent offset is invalid
            const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
            const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
            if (dosHeader && fileHeader) {
                quint32 ntHeadersOffset = dosHeader->e_lfanew;
                quint16 magic = optionalHeader->Magic;
                quint32 numberOfRvaAndSizesOffset;
                if (magic == 0x10b) {
                    numberOfRvaAndSizesOffset = 92; // 0x5C
                } else {
                    numberOfRvaAndSizesOffset = 108; // 0x6C
                }
                dataDirsBaseOffset = ntHeadersOffset + 4 + 20 + numberOfRvaAndSizesOffset + 4;
            } else {
                return; // Cannot calculate offset
            }
        }
    } else {
        // Fallback: recalculate if no parent offset
        const IMAGE_DOS_HEADER *dosHeader = m_dataModel.getDOSHeader();
        const IMAGE_FILE_HEADER *fileHeader = m_dataModel.getFileHeader();
        if (dosHeader && fileHeader) {
            quint32 ntHeadersOffset = dosHeader->e_lfanew;
            quint16 magic = optionalHeader->Magic;
            quint32 numberOfRvaAndSizesOffset;
            if (magic == 0x10b) {
                numberOfRvaAndSizesOffset = 92; // 0x5C
            } else {
                numberOfRvaAndSizesOffset = 108; // 0x6C
            }
            dataDirsBaseOffset = ntHeadersOffset + 4 + 20 + numberOfRvaAndSizesOffset + 4;
        } else {
            return; // Cannot calculate offset
        }
    }
    
    // Add data directory entries - match CFF Explorer format: show RVA and Size as separate entries
    const QStringList &dirNames = dataDirectoryFieldKeys();

    // Access DataDirectory array directly from optional header structure
    // Handle both PE32 and PE32+ formats
    quint16 magic = optionalHeader->Magic;
    const IMAGE_DATA_DIRECTORY *dataDirectories = nullptr;
    if (magic == 0x10b) {
        // PE32 (32-bit) - DataDirectory is part of IMAGE_OPTIONAL_HEADER32
        const IMAGE_OPTIONAL_HEADER32 *optHeader32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalHeader);
        dataDirectories = optHeader32->DataDirectory;
            } else {
        // PE32+ (64-bit) - DataDirectory is part of IMAGE_OPTIONAL_HEADER64
        const IMAGE_OPTIONAL_HEADER64 *optHeader64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalHeader);
        dataDirectories = optHeader64->DataDirectory;
    }
    
    if (!dataDirectories) {
        return;
            }
    
    for (int i = 0; i < dirNames.size() && i < 16; ++i) {
        // Get values directly from DataDirectory array
        quint32 address = dataDirectories[i].VirtualAddress;
        quint32 size = dataDirectories[i].Size;
        
        // Calculate offsets for display (Address and Size are consecutive 4-byte fields)
        // Each Data Directory entry is 8 bytes: 4 bytes VirtualAddress + 4 bytes Size
        quint32 addressOffset = dataDirsBaseOffset + (i * 8);      // Address (RVA) is at base + (i * 8)
        quint32 sizeOffset = dataDirsBaseOffset + (i * 8) + 4;     // Size is at base + (i * 8) + 4
        
        // Verify offsets are within file bounds
        if (addressOffset + 4 > static_cast<quint32>(m_fileData.size()) || 
            sizeOffset + 4 > static_cast<quint32>(m_fileData.size())) {
            // Skip if offset is out of bounds
            continue;
        }
        
        // Verify values match what's in the file (for debugging/validation)
        // Read directly from file to ensure accuracy
        quint32 fileAddress = 0;
        quint32 fileSize = 0;
        if (addressOffset + sizeof(quint32) <= static_cast<quint32>(m_fileData.size())) {
            const quint8 *addrPtr = reinterpret_cast<const quint8*>(m_fileData.constData() + addressOffset);
            fileAddress = static_cast<quint32>(addrPtr[0]) |
                         (static_cast<quint32>(addrPtr[1]) << 8) |
                         (static_cast<quint32>(addrPtr[2]) << 16) |
                         (static_cast<quint32>(addrPtr[3]) << 24);
        }
        if (sizeOffset + sizeof(quint32) <= static_cast<quint32>(m_fileData.size())) {
            const quint8 *sizePtr = reinterpret_cast<const quint8*>(m_fileData.constData() + sizeOffset);
            fileSize = static_cast<quint32>(sizePtr[0]) |
                      (static_cast<quint32>(sizePtr[1]) << 8) |
                      (static_cast<quint32>(sizePtr[2]) << 16) |
                      (static_cast<quint32>(sizePtr[3]) << 24);
        }
        
        // Use values from structure (they should match file, but structure is more reliable)
        // If they don't match, use file values as fallback
        if (address != fileAddress) {
            address = fileAddress; // Use file value if mismatch
        }
        if (size != fileSize) {
            size = fileSize; // Use file value if mismatch
        }
        
        // Create directory parent item (e.g., "Export Directory")
        QTreeWidgetItem *dirItem = new QTreeWidgetItem(parent);
        dirItem->setText(0, dirNames[i]);
        dirItem->setData(0, PEParserNew::kTreeFieldKeyRole, dirNames.at(i));
        dirItem->setText(1, ""); // No value for parent
        dirItem->setText(2, PEUtils::formatHexWidth(addressOffset, 8)); // Base offset
        dirItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(8, 0))); // 8 bytes total
        dirItem->setText(4, ""); // No meaning for directory container
        dirItem->setData(0, kFieldOffsetRole, addressOffset);
        dirItem->setData(0, kFieldSizeRole, static_cast<quint32>(8));
        
        // Add Address child (showing RVA value in hexadecimal)
        QTreeWidgetItem *addressItem = new QTreeWidgetItem(dirItem);
        addressItem->setText(0, "Address");
        addressItem->setText(1, PEUtils::formatHexWidth(address, 8));
        addressItem->setText(2, PEUtils::formatHexWidth(addressOffset, 8));
        addressItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(4, 0)));
        addressItem->setText(4, ""); // No meaning for Data Directory entries
        addressItem->setData(0, kFieldOffsetRole, addressOffset);
        addressItem->setData(0, kFieldSizeRole, static_cast<quint32>(4));
        
        // Add Size child (showing size value in hexadecimal)
        QTreeWidgetItem *sizeItem = new QTreeWidgetItem(dirItem);
        sizeItem->setText(0, "Size");
        sizeItem->setText(1, PEUtils::formatHexWidth(size, 8));
        sizeItem->setText(2, PEUtils::formatHexWidth(sizeOffset, 8));
        sizeItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(4, 0)));
        sizeItem->setText(4, ""); // No meaning for Data Directory entries
        sizeItem->setData(0, kFieldOffsetRole, sizeOffset);
        sizeItem->setData(0, kFieldSizeRole, static_cast<quint32>(4));

        if (i == 4) {
            addressItem->setText(4, QStringLiteral("File offset to certificate table (not an RVA — PE spec)"));
            sizeItem->setText(4, QStringLiteral("Total size of certificate data in the file"));
        }

        if (address != 0 && size != 0) {
            if (i == 2) {
                appendResourceDirectoryDetailTree(dirItem, address, size);
            } else if (i == 3) {
                appendExceptionDirectoryDetailTree(dirItem, address, size);
            } else if (i == 4) {
                appendCertificateDirectoryDetailTree(dirItem, address, size);
            } else if (i == 9) {
                appendTLSDirectoryDetailTree(dirItem, address, size);
            } else if (i == 10) {
                appendLoadConfigDirectoryDetailTree(dirItem, address, size);
            } else if (i == 14) {
                appendComDescriptorDetailTree(dirItem, address, size);
            }
        }

        // Import/export details now live in the dedicated tabs (imports/exports)
    }
}

void PEParserNew::addTreeField(QTreeWidgetItem *parent, const QString &name, const QString &value, quint32 offset, quint32 size,
                               const QString &jsonFieldKey)
{
    QTreeWidgetItem *fieldItem = new QTreeWidgetItem(parent);
    fieldItem->setText(0, name);
    fieldItem->setText(1, value);
    
    // Calculate absolute offset: get parent's base offset and add relative offset
    quint32 absoluteOffset = offset;
    if (parent) {
        QString parentOffsetStr = parent->text(2);
        if (!parentOffsetStr.isEmpty() && parentOffsetStr.startsWith("0x")) {
            bool ok;
            quint32 parentOffset = parentOffsetStr.toULong(&ok, 16);
            if (ok) {
                absoluteOffset = parentOffset + offset;
            }
        }
    }
    
    fieldItem->setText(2, PEUtils::formatHexWidth(absoluteOffset, 8));
    fieldItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(size, 0)));
    fieldItem->setData(0, kFieldOffsetRole, absoluteOffset);
    fieldItem->setData(0, kFieldSizeRole, size);
    if (!jsonFieldKey.isEmpty()) {
        fieldItem->setData(0, PEParserNew::kTreeFieldKeyRole, jsonFieldKey);
    }
    
    const QString meaningLookup = jsonFieldKey.isEmpty() ? name : jsonFieldKey;
    QString meaning = getFieldMeaning(meaningLookup, value);
    fieldItem->setText(4, meaning);
}

QString PEParserNew::getFieldMeaning(const QString &fieldName, const QString &value)
{
    // Blob / non-scalar regions: meaning does not depend on the Value column text
    if (fieldName == QStringLiteral("DOS_STUB")) {
        return QStringLiteral("MS-DOS 16-bit stub program (8086 real-mode machine code)");
    }

    // Handle empty values
    if (value.isEmpty()) {
        return "";
    }

    // Machine field - convert to architecture name
    if (fieldName == "Machine") {
        bool ok;
        quint16 machine = value.toUShort(&ok, 16);
        if (ok) {
            return PEUtils::getMachineType(machine);
        }
    }
    
    // TimeDateStamp - convert to date/time (optional header and load-config share this name pattern)
    if (fieldName == QStringLiteral("TimeDateStamp") || fieldName.endsWith(QStringLiteral("TimeDateStamp"))) {
        bool ok;
        quint32 timestamp = value.toULong(&ok, 16);
        if (ok && timestamp != 0) {
            QDateTime dateTime = QDateTime::fromSecsSinceEpoch(timestamp);
            return dateTime.toString("dddd, dd.MM.yyyy HH:mm:ss UTC");
        }
    }

    if (fieldName == QStringLiteral("LoadCfg GuardFlags")) {
        bool ok;
        quint32 gf = value.toULong(&ok, 16);
        if (ok) {
            QString decoded = decodeGuardCfFlags(gf);
            if (!decoded.isEmpty()) {
                return decoded;
            }
        }
    }

    if (fieldName == QStringLiteral("CLR Flags")) {
        bool ok;
        quint32 cf = value.toULong(&ok, 16);
        if (ok) {
            QString decoded = decodeClrImageFlags(cf);
            if (!decoded.isEmpty()) {
                return decoded;
            }
        }
    }

    if (fieldName == QStringLiteral("Exc RuntimeFunctionCount")) {
        bool ok;
        quint32 n = value.toULong(&ok, 10);
        if (ok && n > 0) {
            return QStringLiteral("%1 × RUNTIME_FUNCTION (12 bytes each on x64)").arg(n);
        }
    }
    
    // Characteristics - decode flags (can be File Header or Section Header)
    if (fieldName == "Characteristics") {
        bool ok;
        // Try parsing as 16-bit first (File Header Characteristics)
        quint16 chars16 = value.toUShort(&ok, 16);
        if (ok) {
            // File characteristics are typically small values (0x0001-0xFFFF)
            // Section characteristics are typically larger (0x00000020-0xE0000000)
            // If value fits in 16-bit and is reasonable for file chars, use file characteristics
            if (chars16 <= 0xFFFF && chars16 != 0) {
                QString fileChars = PEUtils::getFileCharacteristics(chars16);
                // Check if we got meaningful flags (not just "None")
                if (!fileChars.isEmpty() && fileChars != LANG("UI/section_char_none")) {
                    return fileChars;
                }
            }
        }
        
        // Otherwise try section characteristics (32-bit)
        quint32 chars32 = value.toULong(&ok, 16);
        if (ok) {
            QString sectionChars = PEUtils::getSectionCharacteristics(chars32);
            if (!sectionChars.isEmpty()) {
                return sectionChars;
            }
        }
    }
    
    // DllCharacteristics - decode flags
    if (fieldName == "DllCharacteristics") {
        bool ok;
        quint16 chars = value.toUShort(&ok, 16);
        if (ok) {
            QString dllChars = PEUtils::getDLLCharacteristics(chars);
            // If translation failed and we got raw keys, return empty to avoid showing broken text
            if (dllChars.startsWith("UI/")) {
                return ""; // Translation keys not found, return empty
            }
            return dllChars;
        }
    }
    
    // Subsystem - convert to subsystem name
    if (fieldName == "Subsystem") {
        bool ok;
        quint16 subsystem = value.toUShort(&ok, 10);
        if (ok) {
            return PEUtils::getSubsystem(subsystem);
        }
    }
    
    // Magic - PE32 or PE32+
    if (fieldName == "Magic") {
        bool ok;
        quint16 magic = value.toUShort(&ok, 16);
        if (ok) {
            if (magic == 0x10b) return "PE32 (32-bit)";
            if (magic == 0x20b) return "PE32+ (64-bit)";
            return QString("Unknown (0x%1)").arg(magic, 4, 16, QChar('0'));
        }
    }
    
    // e_magic - DOS signature
    if (fieldName == "e_magic") {
        bool ok;
        quint16 magic = value.toUShort(&ok, 16);
        if (ok && magic == 0x5a4d) {
            return "MZ (DOS signature)";
        }
    }
    
    // Signature - PE signature
    if (fieldName == "Signature") {
        bool ok;
        quint32 signature = value.toULong(&ok, 16);
        if (ok && signature == 0x00004550) {
            return "PE\\0\\0 (PE signature)";
        }
    }
    
    // NumberOfSections - just show count
    if (fieldName == "NumberOfSections") {
        return QString("%1 section(s)").arg(value);
    }
    
    // SizeOfOptionalHeader - show decimal value
    if (fieldName == "SizeOfOptionalHeader") {
        bool ok;
        quint16 size = value.toUShort(&ok, 10);
        if (ok) {
            return QString("%1 bytes (0x%2)").arg(size).arg(size, 0, 16);
        }
    }
    
    // PointerToSymbolTable - show if zero or not
    if (fieldName == "PointerToSymbolTable") {
        bool ok;
        quint32 ptr = value.toULong(&ok, 16);
        if (ok) {
            if (ptr == 0) {
                return "No symbol table";
            }
            return QString("RVA: 0x%1").arg(ptr, 8, 16, QChar('0'));
        }
    }
    
    // NumberOfSymbols - show count
    if (fieldName == "NumberOfSymbols") {
        bool ok;
        quint32 count = value.toULong(&ok, 10);
        if (ok) {
            if (count == 0) {
                return "No symbols";
            }
            return QString("%1 symbol(s)").arg(count);
        }
    }
    
    // Rich Header fields
    if (fieldName == "RichSignature") {
        bool ok;
        quint32 sig = value.toULong(&ok, 16);
        if (ok) {
            // Check if it's "DanS" when XORed (we'd need the XOR key, but for display we show it's the signature)
            return "DanS signature (XORed)";
        }
    }
    
    if (fieldName == "RichCount") {
        bool ok;
        quint32 count = value.toULong(&ok, 10);
        if (ok) {
            return QString("%1 entry/entries").arg(count);
        }
    }
    
    // Fallback: use first line of field explanation (plain text) so Meaning column is populated
    QString full = getFieldExplanation(fieldName);
    if (!full.isEmpty()) {
        full = full.replace(QRegularExpression(QStringLiteral("<[^>]*>")), QStringLiteral(" "));
        full = full.replace(QStringLiteral("&nbsp;"), QStringLiteral(" "))
                   .replace(QStringLiteral("&amp;"), QStringLiteral("&"))
                   .replace(QStringLiteral("&lt;"), QStringLiteral("<"))
                   .replace(QStringLiteral("&gt;"), QStringLiteral(">"));
        full = full.simplified();
        if (full.length() > 120)
            full = full.left(117) + QStringLiteral("...");
        if (!full.isEmpty())
            return full;
    }
    return QString();
}

void PEParserNew::appendExceptionDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = rvaToFileOffset(rva);
    if (fo == 0 || fo + regionSize > static_cast<quint32>(m_fileData.size())) {
        return;
    }

    const IMAGE_FILE_HEADER *fh = m_dataModel.getFileHeader();
    const quint16 machine = fh ? fh->Machine : 0;

    QTreeWidgetItem *body = new QTreeWidgetItem(dirItem);
    body->setText(0, QStringLiteral("Parsed directory data"));
    body->setText(1, QString());
    body->setText(2, PEUtils::formatHexWidth(fo, 8));
    body->setText(3, QString());
    body->setText(4, QStringLiteral("Values read from the mapped directory — select a row to jump in hex"));

    const uchar *base = reinterpret_cast<const uchar *>(m_fileData.constData() + fo);

    if (machine == IMAGE_FILE_MACHINE_AMD64) {
        const quint32 entryBytes = static_cast<quint32>(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
        const quint32 n = regionSize / entryBytes;
        QTreeWidgetItem *summary = new QTreeWidgetItem(body);
        summary->setText(0, QStringLiteral("Exc RuntimeFunctionCount"));
        summary->setText(1, QString::number(n));
        summary->setText(2, PEUtils::formatHexWidth(fo, 8));
        summary->setText(3, QStringLiteral("—"));
        summary->setText(4, QStringLiteral("Summary (whole table; not one field)"));

        if (regionSize >= entryBytes) {
            const auto *rf = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY *>(base);
            addTreeField(body, QStringLiteral("Exc First BeginRVA"), PEUtils::formatHexWidth(rf->BeginAddress, 8),
                         0, sizeof(quint32));
            addTreeField(body, QStringLiteral("Exc First EndRVA"), PEUtils::formatHexWidth(rf->EndAddress, 8),
                         sizeof(quint32), sizeof(quint32));
            addTreeField(body, QStringLiteral("Exc First UnwindRVA"), PEUtils::formatHexWidth(rf->UnwindInfoAddress, 8),
                         2 * sizeof(quint32), sizeof(quint32));
        }
    } else if (machine == IMAGE_FILE_MACHINE_ARM64) {
        const quint32 entryBytes = static_cast<quint32>(sizeof(IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY));
        const quint32 n = entryBytes ? regionSize / entryBytes : 0;
        QTreeWidgetItem *summary = new QTreeWidgetItem(body);
        summary->setText(0, QStringLiteral("Exc RuntimeFunctionCount"));
        summary->setText(1, QString::number(n));
        summary->setText(2, PEUtils::formatHexWidth(fo, 8));
        summary->setText(3, QStringLiteral("—"));
        summary->setText(4, QStringLiteral("ARM64 often uses packed unwind entries — treat counts as an estimate; see PE ARM64 exception data"));
    } else {
        QTreeWidgetItem *note = new QTreeWidgetItem(body);
        note->setText(0, QStringLiteral("Exc Note"));
        note->setText(1, QStringLiteral("This view expands the x64 RUNTIME_FUNCTION table. Other CPUs use different unwind/metadata layouts."));
        note->setText(2, PEUtils::formatHexWidth(fo, 8));
        note->setText(3, QStringLiteral("—"));
        note->setText(4, QString());
    }
}

void PEParserNew::appendCertificateDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 filePointer, quint32 regionSize)
{
    if (!dirItem || filePointer == 0 || regionSize == 0) {
        return;
    }
    const quint32 fileSize = static_cast<quint32>(m_fileData.size());
    if (filePointer >= fileSize) {
        return;
    }
    const quint32 available = fileSize - filePointer;
    const quint32 scanLen = qMin(regionSize, available);
    constexpr quint32 kFixedHdr = sizeof(quint32) + sizeof(quint16) + sizeof(quint16); // WIN_CERTIFICATE before bCertificate

    QTreeWidgetItem *note = new QTreeWidgetItem(dirItem);
    note->setText(0, QStringLiteral("Security directory note"));
    note->setText(1, QString());
    note->setText(2, PEUtils::formatHexWidth(filePointer, 8));
    note->setText(3, QStringLiteral("—"));
    note->setText(4, QStringLiteral(
        "Authenticode attribute certificates. The optional header value is a file offset, not an RVA. Each "
        "WIN_CERTIFICATE is padded to an 8-byte boundary."));

    const uchar *regionBase = reinterpret_cast<const uchar *>(m_fileData.constData() + filePointer);
    quint32 pos = 0;
    int certIndex = 0;
    constexpr int kMaxCerts = 64;

    while (pos + kFixedHdr <= scanLen && certIndex < kMaxCerts) {
        const quint32 absOff = filePointer + pos;
        const WIN_CERTIFICATE *hdr = reinterpret_cast<const WIN_CERTIFICATE *>(regionBase + pos);
        const quint32 dwLen = hdr->dwLength;
        if (dwLen < kFixedHdr || dwLen > scanLen - pos) {
            break;
        }

        QTreeWidgetItem *certItem = new QTreeWidgetItem(dirItem);
        const QString label = (certIndex == 0) ? QStringLiteral("WinCertificate")
                                               : QStringLiteral("WinCertificate[%1]").arg(certIndex);
        certItem->setText(0, label);
        certItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("WIN_CERTIFICATE"));
        certItem->setText(2, PEUtils::formatHexWidth(absOff, 8));
        certItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(dwLen, 0)));
        certItem->setData(0, kFieldOffsetRole, absOff);
        certItem->setData(0, kFieldSizeRole, dwLen);
        certItem->setText(4, QStringLiteral("WIN_CERTIFICATE (Authenticode)"));

        addTreeField(certItem, QStringLiteral("dwLength"), QString::number(dwLen), 0, sizeof(quint32));
        addTreeField(certItem, QStringLiteral("wRevision"), PEUtils::formatHexWidth(hdr->wRevision, 4),
                     static_cast<quint32>(sizeof(quint32)), sizeof(quint16));
        addTreeField(certItem, QStringLiteral("wCertificateType"), PEUtils::formatHexWidth(hdr->wCertificateType, 4),
                     static_cast<quint32>(sizeof(quint32) + sizeof(quint16)), sizeof(quint16));

        const quint32 payloadBytes = dwLen - kFixedHdr;
        if (payloadBytes > 0) {
            QTreeWidgetItem *pay = new QTreeWidgetItem(certItem);
            pay->setText(0, QStringLiteral("bCertificate"));
            pay->setText(1, QStringLiteral("(%1 bytes PKCS#7 / ASN.1 payload)").arg(payloadBytes));
            pay->setText(2, PEUtils::formatHexWidth(absOff + kFixedHdr, 8));
            pay->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(payloadBytes, 0)));
            pay->setData(0, kFieldOffsetRole, absOff + kFixedHdr);
            pay->setData(0, kFieldSizeRole, payloadBytes);
        }

        ++certIndex;
        quint32 step = (dwLen + 7U) & ~7U;
        if (step == 0 || pos + step > scanLen) {
            break;
        }
        pos += step;
    }
}

void PEParserNew::appendTLSDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = rvaToFileOffset(rva);
    if (fo == 0) {
        return;
    }

    const IMAGE_OPTIONAL_HEADER *opt = m_dataModel.getOptionalHeader();
    if (!opt) {
        return;
    }

    const bool pe32 = (opt->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    const quint32 need = pe32 ? static_cast<quint32>(sizeof(IMAGE_TLS_DIRECTORY32))
                              : static_cast<quint32>(sizeof(IMAGE_TLS_DIRECTORY64));
    if (fo + need > static_cast<quint32>(m_fileData.size()) || regionSize < need) {
        return;
    }

    QTreeWidgetItem *body = new QTreeWidgetItem(dirItem);
    body->setText(0, QStringLiteral("Parsed directory data"));
    body->setText(1, QString());
    body->setText(2, PEUtils::formatHexWidth(fo, 8));
    body->setText(3, QString());
    body->setText(4, QStringLiteral("Values read from the mapped directory — select a row to jump in hex"));

    const uchar *base = reinterpret_cast<const uchar *>(m_fileData.constData() + fo);

    if (pe32) {
        const auto *tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY32 *>(base);
        addTreeField(body, QStringLiteral("TLS StartOfRawData"), PEUtils::formatHexWidth(tls->StartAddressOfRawData, 8),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY32, StartAddressOfRawData)), sizeof(quint32));
        addTreeField(body, QStringLiteral("TLS EndOfRawData"), PEUtils::formatHexWidth(tls->EndAddressOfRawData, 8),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY32, EndAddressOfRawData)), sizeof(quint32));
        addTreeField(body, QStringLiteral("TLS AddressOfIndex"), PEUtils::formatHexWidth(tls->AddressOfIndex, 8),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY32, AddressOfIndex)), sizeof(quint32));
        addTreeField(body, QStringLiteral("TLS AddressOfCallBacks"), PEUtils::formatHexWidth(tls->AddressOfCallBacks, 8),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY32, AddressOfCallBacks)), sizeof(quint32));
        addTreeField(body, QStringLiteral("TLS SizeOfZeroFill"), QString::number(tls->SizeOfZeroFill),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY32, SizeOfZeroFill)), sizeof(quint32));
        addTreeField(body, QStringLiteral("TLS Characteristics"), PEUtils::formatHexWidth(tls->Characteristics, 8),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY32, Characteristics)), sizeof(quint32));
    } else {
        const auto *tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64 *>(base);
        addTreeField(body, QStringLiteral("TLS StartOfRawData"), PEUtils::formatHex(static_cast<quint64>(tls->StartAddressOfRawData)),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY64, StartAddressOfRawData)), sizeof(quint64));
        addTreeField(body, QStringLiteral("TLS EndOfRawData"), PEUtils::formatHex(static_cast<quint64>(tls->EndAddressOfRawData)),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY64, EndAddressOfRawData)), sizeof(quint64));
        addTreeField(body, QStringLiteral("TLS AddressOfIndex"), PEUtils::formatHex(static_cast<quint64>(tls->AddressOfIndex)),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY64, AddressOfIndex)), sizeof(quint64));
        addTreeField(body, QStringLiteral("TLS AddressOfCallBacks"), PEUtils::formatHex(static_cast<quint64>(tls->AddressOfCallBacks)),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY64, AddressOfCallBacks)), sizeof(quint64));
        addTreeField(body, QStringLiteral("TLS SizeOfZeroFill"), QString::number(tls->SizeOfZeroFill),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY64, SizeOfZeroFill)), sizeof(quint32));
        addTreeField(body, QStringLiteral("TLS Characteristics"), PEUtils::formatHexWidth(tls->Characteristics, 8),
                     static_cast<quint32>(offsetof(IMAGE_TLS_DIRECTORY64, Characteristics)), sizeof(quint32));
    }
}

void PEParserNew::appendLoadConfigDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = rvaToFileOffset(rva);
    if (fo == 0 || fo + 4 > static_cast<quint32>(m_fileData.size())) {
        return;
    }

    const IMAGE_OPTIONAL_HEADER *opt = m_dataModel.getOptionalHeader();
    if (!opt) {
        return;
    }

    const bool pe32 = (opt->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    const uchar *base = reinterpret_cast<const uchar *>(m_fileData.constData() + fo);

    quint32 spill = regionSize;
    {
        const quint32 reported = readLe32(base);
        if (reported != 0 && reported <= regionSize) {
            spill = reported;
        }
    }
    if (fo + spill > static_cast<quint32>(m_fileData.size())) {
        spill = static_cast<quint32>(m_fileData.size()) - fo;
    }

    QTreeWidgetItem *body = new QTreeWidgetItem(dirItem);
    body->setText(0, QStringLiteral("Parsed directory data"));
    body->setText(1, QString());
    body->setText(2, PEUtils::formatHexWidth(fo, 8));
    body->setText(3, QString());
    body->setText(4, QStringLiteral("Values read from the mapped directory — select a row to jump in hex"));

    if (pe32) {
        if (spill < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)) {
            return;
        }
        const auto *lc = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY32 *>(base);
        addTreeField(body, QStringLiteral("LoadCfg StructureSize"), PEUtils::formatHexWidth(lc->Size, 8),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, Size)), sizeof(quint32));
        addTreeField(body, QStringLiteral("LoadCfg TimeDateStamp"), PEUtils::formatHexWidth(lc->TimeDateStamp, 8),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, TimeDateStamp)), sizeof(quint32));
        addTreeField(body, QStringLiteral("LoadCfg MajorVersion"), QString::number(lc->MajorVersion),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, MajorVersion)), sizeof(quint16));
        addTreeField(body, QStringLiteral("LoadCfg MinorVersion"), QString::number(lc->MinorVersion),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, MinorVersion)), sizeof(quint16));
        addTreeField(body, QStringLiteral("LoadCfg SecurityCookie"), PEUtils::formatHexWidth(lc->SecurityCookie, 8),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie)), sizeof(quint32));
        addTreeField(body, QStringLiteral("LoadCfg SEHandlerTable"), PEUtils::formatHexWidth(lc->SEHandlerTable, 8),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerTable)), sizeof(quint32));
        addTreeField(body, QStringLiteral("LoadCfg SEHandlerCount"), QString::number(lc->SEHandlerCount),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerCount)), sizeof(quint32));

        constexpr quint32 kGuard32 = 72;
        if (spill >= kGuard32 + 20) {
            const quint32 gCheck = readLe32(base + kGuard32);
            const quint32 gDispatch = readLe32(base + kGuard32 + 4);
            const quint32 gTable = readLe32(base + kGuard32 + 8);
            const quint32 gCount = readLe32(base + kGuard32 + 12);
            const quint32 gFlags = readLe32(base + kGuard32 + 16);
            addTreeField(body, QStringLiteral("LoadCfg GuardCFCheckFunction"), PEUtils::formatHexWidth(gCheck, 8),
                         kGuard32, sizeof(quint32));
            addTreeField(body, QStringLiteral("LoadCfg GuardCFDispatchFunction"), PEUtils::formatHexWidth(gDispatch, 8),
                         kGuard32 + 4, sizeof(quint32));
            addTreeField(body, QStringLiteral("LoadCfg GuardCFFunctionTable"), PEUtils::formatHexWidth(gTable, 8),
                         kGuard32 + 8, sizeof(quint32));
            addTreeField(body, QStringLiteral("LoadCfg GuardCFFunctionCount"), PEUtils::formatHexWidth(gCount, 8),
                         kGuard32 + 12, sizeof(quint32));
            addTreeField(body, QStringLiteral("LoadCfg GuardFlags"), PEUtils::formatHexWidth(gFlags, 8),
                         kGuard32 + 16, sizeof(quint32));
        }
    } else {
        if (spill < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)) {
            return;
        }
        const auto *lc = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY64 *>(base);
        addTreeField(body, QStringLiteral("LoadCfg StructureSize"), PEUtils::formatHexWidth(lc->Size, 8),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, Size)), sizeof(quint32));
        addTreeField(body, QStringLiteral("LoadCfg TimeDateStamp"), PEUtils::formatHexWidth(lc->TimeDateStamp, 8),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, TimeDateStamp)), sizeof(quint32));
        addTreeField(body, QStringLiteral("LoadCfg MajorVersion"), QString::number(lc->MajorVersion),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, MajorVersion)), sizeof(quint16));
        addTreeField(body, QStringLiteral("LoadCfg MinorVersion"), QString::number(lc->MinorVersion),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, MinorVersion)), sizeof(quint16));
        addTreeField(body, QStringLiteral("LoadCfg SecurityCookie"), PEUtils::formatHex(static_cast<quint64>(lc->SecurityCookie)),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie)), sizeof(quint64));
        addTreeField(body, QStringLiteral("LoadCfg SEHandlerTable"), PEUtils::formatHex(static_cast<quint64>(lc->SEHandlerTable)),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SEHandlerTable)), sizeof(quint64));
        addTreeField(body, QStringLiteral("LoadCfg SEHandlerCount"), QString::number(lc->SEHandlerCount),
                     static_cast<quint32>(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SEHandlerCount)), sizeof(quint32));

        // Guard /CFG extension (IMAGE_LOAD_CONFIG_DIRECTORY64 — see Windows SDK layout)
        constexpr quint32 kGuard64 = 112;
        if (spill >= 148) {
            const quint64 gCheck = readLe64(base + kGuard64);
            const quint64 gDispatch = readLe64(base + kGuard64 + 8);
            const quint64 gTable = readLe64(base + kGuard64 + 16);
            const quint64 gCount = readLe64(base + kGuard64 + 24);
            const quint32 gFlags = readLe32(base + kGuard64 + 32);
            addTreeField(body, QStringLiteral("LoadCfg GuardCFCheckFunction"), PEUtils::formatHex(gCheck),
                         kGuard64, sizeof(quint64));
            addTreeField(body, QStringLiteral("LoadCfg GuardCFDispatchFunction"), PEUtils::formatHex(gDispatch),
                         kGuard64 + 8, sizeof(quint64));
            addTreeField(body, QStringLiteral("LoadCfg GuardCFFunctionTable"), PEUtils::formatHex(gTable),
                         kGuard64 + 16, sizeof(quint64));
            addTreeField(body, QStringLiteral("LoadCfg GuardCFFunctionCount"), PEUtils::formatHex(gCount),
                         kGuard64 + 24, sizeof(quint64));
            addTreeField(body, QStringLiteral("LoadCfg GuardFlags"), PEUtils::formatHexWidth(gFlags, 8),
                         kGuard64 + 32, sizeof(quint32));
        }
    }
}

void PEParserNew::appendResourceDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = rvaToFileOffset(rva);
    if (fo == 0 || fo + regionSize > static_cast<quint32>(m_fileData.size())) {
        return;
    }
    const quint32 absEnd = fo + regionSize;

    QTreeWidgetItem *body = new QTreeWidgetItem(dirItem);
    body->setText(0, QStringLiteral("Parsed directory data"));
    body->setText(1, QString());
    body->setText(2, PEUtils::formatHexWidth(fo, 8));
    body->setText(3, QString());
    body->setText(4, QStringLiteral("Values read from the mapped directory — select a row to jump in hex"));

    const uchar *base = reinterpret_cast<const uchar *>(m_fileData.constData() + fo);
    addTreeField(body, QStringLiteral("Res Characteristics"), PEUtils::formatHexWidth(readLe32(base), 8),
                 static_cast<quint32>(offsetof(IMAGE_RESOURCE_DIRECTORY, Characteristics)), sizeof(quint32));
    addTreeField(body, QStringLiteral("Res TimeDateStamp"), PEUtils::formatHexWidth(readLe32(base + 4), 8),
                 static_cast<quint32>(offsetof(IMAGE_RESOURCE_DIRECTORY, TimeDateStamp)), sizeof(quint32));
    addTreeField(body, QStringLiteral("Res MajorVersion"), QString::number(readLe16(base + 8)),
                 static_cast<quint32>(offsetof(IMAGE_RESOURCE_DIRECTORY, MajorVersion)), sizeof(quint16));
    addTreeField(body, QStringLiteral("Res MinorVersion"), QString::number(readLe16(base + 10)),
                 static_cast<quint32>(offsetof(IMAGE_RESOURCE_DIRECTORY, MinorVersion)), sizeof(quint16));
    const quint16 nNamed = readLe16(base + 12);
    const quint16 nId = readLe16(base + 14);
    addTreeField(body, QStringLiteral("Res NumberOfNamedEntries"), QString::number(nNamed),
                 static_cast<quint32>(offsetof(IMAGE_RESOURCE_DIRECTORY, NumberOfNamedEntries)), sizeof(quint16));
    addTreeField(body, QStringLiteral("Res NumberOfIdEntries"), QString::number(nId),
                 static_cast<quint32>(offsetof(IMAGE_RESOURCE_DIRECTORY, NumberOfIdEntries)), sizeof(quint16));

    quint32 entryOff = 16;
    for (quint32 i = 0; i < quint32(nNamed); ++i) {
        if (fo + entryOff + 8 > absEnd) {
            break;
        }
        entryOff += 8;
    }
    for (quint32 i = 0; i < quint32(nId); ++i) {
        if (fo + entryOff + 8 > absEnd) {
            break;
        }
        const quint32 nameId = readLe32(base + entryOff);
        const QString tag = resourceTypeIdLabel(nameId);
        const QString val = tag.isEmpty() ? QString::number(nameId)
                                          : QStringLiteral("%1 (%2)").arg(nameId).arg(tag);
        addTreeField(body, QStringLiteral("Res TypeId"), val, entryOff, sizeof(quint32));
        entryOff += 8;
    }

    quint32 manRva = 0;
    quint32 manSize = 0;
    if (findEmbeddedManifestRva(m_fileData, fo, absEnd, &manRva, &manSize) && manRva != 0 && manSize != 0) {
        addTreeField(body, QStringLiteral("Manifest DataRVA"), PEUtils::formatHexWidth(manRva, 8), 0, 0);
        addTreeField(body, QStringLiteral("Manifest Size"), QString::number(manSize), 0, 0);
        const quint32 mf = rvaToFileOffset(manRva);
        if (mf != 0 && mf + manSize <= static_cast<quint32>(m_fileData.size())) {
            const QByteArray slice = m_fileData.mid(static_cast<int>(mf), static_cast<int>(qMin(manSize, 512u)));
            QString clip = QString::fromUtf8(slice);
            clip.replace(QLatin1Char('\r'), QLatin1Char(' '));
            clip.replace(QLatin1Char('\n'), QLatin1Char(' '));
            clip = clip.simplified();
            if (clip.size() > 220) {
                clip = clip.left(217) + QStringLiteral("...");
            }
            addTreeField(body, QStringLiteral("Manifest Preview"), clip, 0, 0);
        }
    }
}

void PEParserNew::appendComDescriptorDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = rvaToFileOffset(rva);
    if (fo == 0 || fo + sizeof(IMAGE_COR20_HEADER) > static_cast<quint32>(m_fileData.size())) {
        return;
    }

    const uchar *base = reinterpret_cast<const uchar *>(m_fileData.constData() + fo);
    const quint32 cb = readLe32(base);
    const quint32 spill = qMin(qMax(cb, sizeof(IMAGE_COR20_HEADER)), regionSize);
    if (fo + spill > static_cast<quint32>(m_fileData.size())) {
        return;
    }

    QTreeWidgetItem *body = new QTreeWidgetItem(dirItem);
    body->setText(0, QStringLiteral("Parsed directory data"));
    body->setText(1, QString());
    body->setText(2, PEUtils::formatHexWidth(fo, 8));
    body->setText(3, QString());
    body->setText(4, QStringLiteral("Values read from the mapped directory — select a row to jump in hex"));

    if (spill < sizeof(IMAGE_COR20_HEADER)) {
        addTreeField(body, QStringLiteral("CLR cb (reported)"), PEUtils::formatHexWidth(cb, 8), 0, sizeof(quint32));
        return;
    }

    const auto *cor = reinterpret_cast<const IMAGE_COR20_HEADER *>(base);
    addTreeField(body, QStringLiteral("CLR cb"), PEUtils::formatHexWidth(cor->cb, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, cb)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR MajorRuntimeVersion"), QString::number(cor->MajorRuntimeVersion),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, MajorRuntimeVersion)), sizeof(quint16));
    addTreeField(body, QStringLiteral("CLR MinorRuntimeVersion"), QString::number(cor->MinorRuntimeVersion),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, MinorRuntimeVersion)), sizeof(quint16));
    addTreeField(body, QStringLiteral("CLR MetaData RVA"), PEUtils::formatHexWidth(cor->MetaData.VirtualAddress, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, MetaData.VirtualAddress)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR MetaData Size"), PEUtils::formatHexWidth(cor->MetaData.Size, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, MetaData.Size)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR Flags"), PEUtils::formatHexWidth(cor->Flags, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, Flags)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR EntryPointToken"), PEUtils::formatHexWidth(cor->EntryPointToken, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, EntryPointToken)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR Resources RVA"), PEUtils::formatHexWidth(cor->Resources.VirtualAddress, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, Resources.VirtualAddress)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR Resources Size"), PEUtils::formatHexWidth(cor->Resources.Size, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, Resources.Size)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR StrongNameSignature RVA"),
                 PEUtils::formatHexWidth(cor->StrongNameSignature.VirtualAddress, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, StrongNameSignature.VirtualAddress)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR StrongNameSignature Size"),
                 PEUtils::formatHexWidth(cor->StrongNameSignature.Size, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, StrongNameSignature.Size)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR CodeManagerTable RVA"),
                 PEUtils::formatHexWidth(cor->CodeManagerTable.VirtualAddress, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, CodeManagerTable.VirtualAddress)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR CodeManagerTable Size"),
                 PEUtils::formatHexWidth(cor->CodeManagerTable.Size, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, CodeManagerTable.Size)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR VTableFixups RVA"),
                 PEUtils::formatHexWidth(cor->VTableFixups.VirtualAddress, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, VTableFixups.VirtualAddress)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR VTableFixups Size"),
                 PEUtils::formatHexWidth(cor->VTableFixups.Size, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, VTableFixups.Size)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR ExportAddressTableJumps RVA"),
                 PEUtils::formatHexWidth(cor->ExportAddressTableJumps.VirtualAddress, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, ExportAddressTableJumps.VirtualAddress)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR ExportAddressTableJumps Size"),
                 PEUtils::formatHexWidth(cor->ExportAddressTableJumps.Size, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, ExportAddressTableJumps.Size)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR ManagedNativeHeader RVA"),
                 PEUtils::formatHexWidth(cor->ManagedNativeHeader.VirtualAddress, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, ManagedNativeHeader.VirtualAddress)), sizeof(quint32));
    addTreeField(body, QStringLiteral("CLR ManagedNativeHeader Size"),
                 PEUtils::formatHexWidth(cor->ManagedNativeHeader.Size, 8),
                 static_cast<quint32>(offsetof(IMAGE_COR20_HEADER, ManagedNativeHeader.Size)), sizeof(quint32));
}

QString PEParserNew::findConfigFile(const QString &fileName) const
{
    QStringList possibleConfigPaths;
    
    // 1. Try relative to executable (for deployed builds) - PRIORITY 1
    QString appDir = QCoreApplication::applicationDirPath();
    possibleConfigPaths << QDir(appDir).absoluteFilePath("config/" + fileName);
    
    // 2. Try current working directory - PRIORITY 2
    possibleConfigPaths << QDir::currentPath() + "/config/" + fileName;
    
    // 3. Try relative to executable but go up to project root (for development builds) - PRIORITY 3
    QDir appDirObj(appDir);
    if (appDirObj.cdUp() && appDirObj.cdUp() && appDirObj.cdUp()) {
        possibleConfigPaths << appDirObj.absoluteFilePath("config/" + fileName);
    }
    
    // 4. Try source directory (for development builds) - PRIORITY 4
    possibleConfigPaths << QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("../../../config/" + fileName);
    
    qDebug() << "Searching for config file:" << fileName;
    qDebug() << "Possible paths (in priority order):" << possibleConfigPaths;
    
    // Find the first valid config file
    for (const QString &path : possibleConfigPaths) {
        if (QFile::exists(path)) {
            qDebug() << "Found config file at:" << path;
            return path;
        }
    }
    
    qWarning() << "Config file not found in any of these locations:" << possibleConfigPaths;
    return QString();
}
