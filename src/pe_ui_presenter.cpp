#include "pe_ui_presenter.h"

#include "pe_parser_new.h"
#include "pe_authenticode.h"
#include "pe_ep_disasm.h"
#include "pe_utils.h"
#include "pe_tree_insight_helpers.h"
#include "language_manager.h"

#include <QTreeWidgetItem>
#include <QtGlobal>
#include <cstddef>
#include <cstring>
#include "pe_analysis.h"
#include <QRegularExpression>
#include <QSet>
#include <QVector>
#include <functional>

namespace {
constexpr int kFieldOffsetRole = Qt::UserRole + 20;
constexpr int kFieldSizeRole = Qt::UserRole + 21;

using namespace PeTreeInsight;

} // namespace

PEUIPresenter::PEUIPresenter(PEParserNew *parser)
    : m_parser(parser)
{
}

QList<QTreeWidgetItem*> PEUIPresenter::buildStructureTree()
{
    QList<QTreeWidgetItem*> treeItems;
    
    // Create DOS Header section
    QTreeWidgetItem *dosHeaderItem = new QTreeWidgetItem();
    dosHeaderItem->setText(0, QStringLiteral("DOS Header"));
    dosHeaderItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("DOS Header"));
    dosHeaderItem->setText(1, "");
    dosHeaderItem->setText(2, QStringLiteral("0x00000000"));
    dosHeaderItem->setText(3, peTreeSizeBytesText(QStringLiteral("0x40")));
    
    const IMAGE_DOS_HEADER *dosHeader = m_parser->m_dataModel.getDOSHeader();
    if (dosHeader) {
        addDOSHeaderFields(dosHeaderItem, dosHeader);
    }
    treeItems.append(dosHeaderItem);

    // DOS stub: bytes after IMAGE_DOS_HEADER until min(e_lfanew, 0x80) — single tree row (offset/size columns carry location)
    if (dosHeader && dosHeader->e_lfanew > 0x40 && m_parser->m_fileData.size() > 0x40) {
        const quint32 stubEnd = qMin(static_cast<quint32>(dosHeader->e_lfanew), 0x80u);
        const quint32 regionSize = (stubEnd > 0x40) ? (stubEnd - 0x40) : 0u;
        if (regionSize > 0) {
            const QByteArray stubBytes = m_parser->m_fileData.mid(0x40, static_cast<int>(regionSize));
            QTreeWidgetItem *dosStubRoot = new QTreeWidgetItem();
            dosStubRoot->setText(0, QStringLiteral("DOS stub"));
            dosStubRoot->setText(1, formatHexPreview(stubBytes));
            dosStubRoot->setText(2, PEUtils::formatHexWidth(0x40, 8));
            dosStubRoot->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(regionSize, 0)));
            dosStubRoot->setText(4, m_parser->getFieldMeaning(QStringLiteral("DOS_STUB"), QStringLiteral("-")));
            dosStubRoot->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("DOS_STUB"));
            dosStubRoot->setData(0, kFieldOffsetRole, static_cast<uint>(0x40));
            dosStubRoot->setData(0, kFieldSizeRole, regionSize);
            treeItems.append(dosStubRoot);
        }
    }
    
    // Create Rich Header section (if present)
    if (dosHeader) {
        quint32 richOffset;
        if (PEUtils::findRichHeaderOffset(m_parser->m_fileData, *dosHeader, richOffset)) {
            quint32 richSize = PEUtils::calculateRichHeaderSize(m_parser->m_fileData, richOffset);
            
            QTreeWidgetItem *richHeaderItem = new QTreeWidgetItem();
            richHeaderItem->setText(0, QStringLiteral("Rich Header"));
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
    ntHeadersItem->setText(0, QStringLiteral("NT Headers"));
    ntHeadersItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("NT Headers"));
    ntHeadersItem->setText(1, "");
    ntHeadersItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset, 8));
    // NT Headers size = PE Signature (4) + File Header (20) + Optional Header + Section Headers
    const IMAGE_FILE_HEADER *fileHeader = m_parser->m_dataModel.getFileHeader();
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_parser->m_dataModel.getOptionalHeader();
    quint32 ntHeadersSize = 4 + 20 + (optionalHeader ? optionalHeader->SizeOfHeaders : 0);
    ntHeadersItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(ntHeadersSize, 0)));
    ntHeadersItem->setText(4, ""); // No meaning for container
    
    // Add PE Signature as first field of NT Headers
    if (ntHeadersOffset + 4 <= m_parser->m_fileData.size()) {
        quint32 peSignature = *reinterpret_cast<const quint32*>(m_parser->m_fileData.constData() + ntHeadersOffset);
        addTreeField(ntHeadersItem, "Signature", PEUtils::formatHexWidth(peSignature, 8), 0, sizeof(quint32));
    }
    
    // Create File Header as child of NT Headers
    QTreeWidgetItem *fileHeaderItem = new QTreeWidgetItem(ntHeadersItem);
    fileHeaderItem->setText(0, QStringLiteral("File Header"));
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
    sectionsItem->setText(0, QStringLiteral("Section Headers"));
    sectionsItem->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("Section Headers"));
    sectionsItem->setText(1, "");
    // Section Headers start after PE signature (4) + File Header (20) + Optional Header
    sectionsItem->setText(2, PEUtils::formatHexWidth(ntHeadersOffset + 4 + 20 + (fileHeader ? fileHeader->SizeOfOptionalHeader : 0), 8));
    sectionsItem->setText(3, peTreeEntriesText(PEUtils::formatHexWidth(static_cast<quint64>(m_parser->m_dataModel.getSections().size()), 0)));
    sectionsItem->setText(4, ""); // No meaning for container
    
    addSectionFields(sectionsItem);
    
    treeItems.append(ntHeadersItem);

    return treeItems;
}
void PEUIPresenter::addDOSHeaderFields(QTreeWidgetItem *parent, const IMAGE_DOS_HEADER *dosHeader)
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

void PEUIPresenter::addPEHeaderFields(QTreeWidgetItem *parent, const IMAGE_FILE_HEADER *fileHeader)
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

void PEUIPresenter::addOptionalHeaderFields(QTreeWidgetItem *parent, const IMAGE_OPTIONAL_HEADER *optionalHeader)
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

void PEUIPresenter::addSectionFields(QTreeWidgetItem *parent)
{
    const QList<const IMAGE_SECTION_HEADER*> &sections = m_parser->m_dataModel.getSections();
    const IMAGE_DOS_HEADER *dosHeader = m_parser->m_dataModel.getDOSHeader();
    const IMAGE_FILE_HEADER *fileHeader = m_parser->m_dataModel.getFileHeader();
    
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

            const double secEnt = m_parser->m_dataModel.sectionEntropy(sectionName);
            if (secEnt >= 0.0) {
                const QString entStr = QStringLiteral("%1 %2").arg(QString::number(secEnt, 'f', 2),
                                                                     LANG("UI/entropy_unit"));
                addTreeField(sectionItem, LANG("UI/field_section_entropy"), entStr, section->PointerToRawData,
                             section->SizeOfRawData, QStringLiteral("Section Entropy"));
                if (QTreeWidgetItem *entItem = sectionItem->child(sectionItem->childCount() - 1)) {
                    if (secEnt >= 7.2) {
                        entItem->setText(4, uiStringWithFallback(QStringLiteral("UI/entropy_meaning_high"),
                                                                 QStringLiteral("High entropy — often packed, compressed, "
                                                                                "or encrypted content")));
                    } else if (secEnt >= 6.5) {
                        entItem->setText(4, uiStringWithFallback(QStringLiteral("UI/entropy_meaning_elevated"),
                                                                 QStringLiteral("Elevated entropy — may include compressed "
                                                                                "or mixed content")));
                    } else {
                        entItem->setText(4, uiStringWithFallback(QStringLiteral("UI/entropy_meaning_normal"),
                                                                 QStringLiteral("Typical entropy for normal code or "
                                                                                "structured data")));
                    }
                }
            }
        }
    }
}

void PEUIPresenter::addRichHeaderFields(QTreeWidgetItem *parent, quint32 richOffset)
{
    if (richOffset + 16 > m_parser->m_fileData.size()) {
        return;
    }
    
    IMAGE_RICH_HEADER richHeader;
    if (!PEUtils::parseRichHeader(m_parser->m_fileData, richOffset, richHeader)) {
        return;
    }
    
    // Add Rich Header fields - offsets are relative to richOffset (parent's offset)
    addTreeField(parent, "XorKey", PEUtils::formatHexWidth(richHeader.XorKey, 8), 0, sizeof(quint32));
    addTreeField(parent, "RichSignature", PEUtils::formatHexWidth(richHeader.RichSignature, 8), 4, sizeof(quint32));
    addTreeField(parent, "RichVersion", PEUtils::formatHexWidth(richHeader.RichVersion, 8), 8, sizeof(quint32));
    addTreeField(parent, "RichCount", PEUtils::formatHexWidth(richHeader.RichCount, 8), 12, sizeof(quint32));
    
    // Add Rich Entry fields
    QList<IMAGE_RICH_ENTRY> entries = PEUtils::parseRichEntries(m_parser->m_fileData, richOffset, richHeader.RichCount);
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

void PEUIPresenter::addDataDirectoryFields(QTreeWidgetItem *parent)
{
    // Get the Optional Header to access DataDirectory array
    const IMAGE_OPTIONAL_HEADER *optionalHeader = m_parser->m_dataModel.getOptionalHeader();
    
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
            const IMAGE_DOS_HEADER *dosHeader = m_parser->m_dataModel.getDOSHeader();
            const IMAGE_FILE_HEADER *fileHeader = m_parser->m_dataModel.getFileHeader();
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
        const IMAGE_DOS_HEADER *dosHeader = m_parser->m_dataModel.getDOSHeader();
        const IMAGE_FILE_HEADER *fileHeader = m_parser->m_dataModel.getFileHeader();
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
        if (addressOffset + 4 > static_cast<quint32>(m_parser->m_fileData.size()) || 
            sizeOffset + 4 > static_cast<quint32>(m_parser->m_fileData.size())) {
            // Skip if offset is out of bounds
            continue;
        }
        
        // Verify values match what's in the file (for debugging/validation)
        // Read directly from file to ensure accuracy
        quint32 fileAddress = 0;
        quint32 fileSize = 0;
        if (addressOffset + sizeof(quint32) <= static_cast<quint32>(m_parser->m_fileData.size())) {
            const quint8 *addrPtr = reinterpret_cast<const quint8*>(m_parser->m_fileData.constData() + addressOffset);
            fileAddress = static_cast<quint32>(addrPtr[0]) |
                         (static_cast<quint32>(addrPtr[1]) << 8) |
                         (static_cast<quint32>(addrPtr[2]) << 16) |
                         (static_cast<quint32>(addrPtr[3]) << 24);
        }
        if (sizeOffset + sizeof(quint32) <= static_cast<quint32>(m_parser->m_fileData.size())) {
            const quint8 *sizePtr = reinterpret_cast<const quint8*>(m_parser->m_fileData.constData() + sizeOffset);
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
void PEUIPresenter::addTreeField(QTreeWidgetItem *parent, const QString &name, const QString &value, quint32 offset, quint32 size,
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
    QString meaning = m_parser->getFieldMeaning(meaningLookup, value);
    fieldItem->setText(4, meaning);
}
void PEUIPresenter::appendExceptionDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = m_parser->rvaToFileOffset(rva);
    if (fo == 0 || fo + regionSize > static_cast<quint32>(m_parser->m_fileData.size())) {
        return;
    }

    const IMAGE_FILE_HEADER *fh = m_parser->m_dataModel.getFileHeader();
    const quint16 machine = fh ? fh->Machine : 0;

    QTreeWidgetItem *body = new QTreeWidgetItem(dirItem);
    body->setText(0, QStringLiteral("Parsed directory data"));
    body->setText(1, QString());
    body->setText(2, PEUtils::formatHexWidth(fo, 8));
    body->setText(3, QString());
    body->setText(4, QStringLiteral("Values read from the mapped directory — select a row to jump in hex"));

    const uchar *base = reinterpret_cast<const uchar *>(m_parser->m_fileData.constData() + fo);

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

void PEUIPresenter::appendCertificateDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 filePointer, quint32 regionSize)
{
    if (!dirItem || filePointer == 0 || regionSize == 0) {
        return;
    }
    const quint32 fileSize = static_cast<quint32>(m_parser->m_fileData.size());
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

    const uchar *regionBase = reinterpret_cast<const uchar *>(m_parser->m_fileData.constData() + filePointer);
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

void PEUIPresenter::appendTLSDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = m_parser->rvaToFileOffset(rva);
    if (fo == 0) {
        return;
    }

    const IMAGE_OPTIONAL_HEADER *opt = m_parser->m_dataModel.getOptionalHeader();
    if (!opt) {
        return;
    }

    const bool pe32 = (opt->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    const quint32 need = pe32 ? static_cast<quint32>(sizeof(IMAGE_TLS_DIRECTORY32))
                              : static_cast<quint32>(sizeof(IMAGE_TLS_DIRECTORY64));
    if (fo + need > static_cast<quint32>(m_parser->m_fileData.size()) || regionSize < need) {
        return;
    }

    QTreeWidgetItem *body = new QTreeWidgetItem(dirItem);
    body->setText(0, QStringLiteral("Parsed directory data"));
    body->setText(1, QString());
    body->setText(2, PEUtils::formatHexWidth(fo, 8));
    body->setText(3, QString());
    body->setText(4, QStringLiteral("Values read from the mapped directory — select a row to jump in hex"));

    const uchar *base = reinterpret_cast<const uchar *>(m_parser->m_fileData.constData() + fo);

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

    // Enumerate TLS callback addresses using the already-resolved list from the data model
    const PETlsDirectoryInfo &tlsInfo = m_parser->m_dataModel.tlsDirectoryInfo();
    if (tlsInfo.callbacksPresent) {
        const int ptrSize = pe32 ? 4 : 8;

        quint64 imageBase = 0;
        if (pe32) {
            imageBase = opt->ImageBase;
        } else {
            imageBase = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>(opt)->ImageBase;
        }

        quint32 cbFO = 0;
        if (imageBase != 0 && tlsInfo.addressOfCallbacks >= imageBase) {
            const quint32 cbRVA = static_cast<quint32>(tlsInfo.addressOfCallbacks - imageBase);
            cbFO = m_parser->rvaToFileOffset(cbRVA);
        }

        QTreeWidgetItem *cbNode = new QTreeWidgetItem(body);
        cbNode->setText(0, QStringLiteral("Callback Array"));
        cbNode->setText(1, cbFO != 0
            ? QStringLiteral("%1 callback(s)").arg(tlsInfo.callbackAddresses.size())
            : QStringLiteral("pointer present — unresolvable from disk image"));
        cbNode->setText(2, cbFO != 0 ? PEUtils::formatHexWidth(cbFO, 8) : QString());
        cbNode->setText(3, QString());
        cbNode->setText(4, QStringLiteral("TLS callbacks run before the entry point — common anti-debug / loader trick"));

        for (int i = 0; i < tlsInfo.callbackAddresses.size(); ++i) {
            const quint64 va    = tlsInfo.callbackAddresses[i];
            const quint64 rvaVal = (imageBase != 0 && va >= imageBase) ? va - imageBase : va;
            addTreeField(cbNode,
                         QStringLiteral("Callback[%1]").arg(i),
                         QStringLiteral("VA: %1   RVA: %2")
                             .arg(PEUtils::formatHexWidth(va, pe32 ? 8 : 16))
                             .arg(PEUtils::formatHexWidth(rvaVal, 8)),
                         static_cast<quint32>(i) * static_cast<quint32>(ptrSize),
                         static_cast<quint32>(ptrSize));
        }
    }
}

void PEUIPresenter::appendLoadConfigDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = m_parser->rvaToFileOffset(rva);
    if (fo == 0 || fo + 4 > static_cast<quint32>(m_parser->m_fileData.size())) {
        return;
    }

    const IMAGE_OPTIONAL_HEADER *opt = m_parser->m_dataModel.getOptionalHeader();
    if (!opt) {
        return;
    }

    const bool pe32 = (opt->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    const uchar *base = reinterpret_cast<const uchar *>(m_parser->m_fileData.constData() + fo);

    quint32 spill = regionSize;
    {
        const quint32 reported = readLe32(base);
        if (reported != 0 && reported <= regionSize) {
            spill = reported;
        }
    }
    if (fo + spill > static_cast<quint32>(m_parser->m_fileData.size())) {
        spill = static_cast<quint32>(m_parser->m_fileData.size()) - fo;
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

void PEUIPresenter::appendResourceDirectoryDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = m_parser->rvaToFileOffset(rva);
    if (fo == 0 || fo + regionSize > static_cast<quint32>(m_parser->m_fileData.size())) {
        return;
    }
    quint32 absEnd = fo + regionSize;
    const quint32 fileSize = static_cast<quint32>(m_parser->m_fileData.size());
    absEnd = qMin(absEnd, fileSize);
    for (const IMAGE_SECTION_HEADER *sec : m_parser->getDataModel().getSections()) {
        if (!sec || sec->SizeOfRawData == 0) {
            continue;
        }
        const quint32 rawStart = sec->PointerToRawData;
        const quint32 rawEnd = rawStart + sec->SizeOfRawData;
        if (fo >= rawStart && fo < rawEnd) {
            absEnd = qMin(absEnd, rawEnd);
            break;
        }
    }

    QTreeWidgetItem *body = new QTreeWidgetItem(dirItem);
    body->setText(0, QStringLiteral("Parsed directory data"));
    body->setText(1, QString());
    body->setText(2, PEUtils::formatHexWidth(fo, 8));
    body->setText(3, QString());
    body->setText(4, QStringLiteral("Values read from the mapped directory — select a row to jump in hex"));

    const uchar *base = reinterpret_cast<const uchar *>(m_parser->m_fileData.constData() + fo);
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

    const quint32 regionEnd = qMin(absEnd, static_cast<quint32>(m_parser->m_fileData.size()));
    const quint32 maxEntryCount = (fo + 16 < regionEnd) ? (regionEnd - fo - 16) / 8 : 0;
    const quint32 namedLimit = qMin<quint32>(nNamed, maxEntryCount);
    const quint32 idLimit = qMin<quint32>(nId, maxEntryCount > namedLimit ? maxEntryCount - namedLimit : 0);
    constexpr quint32 kMaxDisplayTypeIds = 32;
    const quint32 idShowLimit = qMin(idLimit, kMaxDisplayTypeIds);

    quint32 entryOff = 16;
    for (quint32 i = 0; i < namedLimit; ++i) {
        if (fo + entryOff + 8 > regionEnd) {
            break;
        }
        entryOff += 8;
    }
    for (quint32 i = 0; i < idShowLimit; ++i) {
        if (fo + entryOff + 8 > regionEnd) {
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
    if (findEmbeddedManifestRva(m_parser->m_fileData, fo, absEnd, &manRva, &manSize) && manRva != 0 && manSize != 0) {
        addTreeField(body, QStringLiteral("Manifest DataRVA"), PEUtils::formatHexWidth(manRva, 8), 0, 0);
        addTreeField(body, QStringLiteral("Manifest Size"), QString::number(manSize), 0, 0);
        const quint32 mf = m_parser->rvaToFileOffset(manRva);
        if (mf != 0 && mf + manSize <= static_cast<quint32>(m_parser->m_fileData.size())) {
            const QByteArray slice = m_parser->m_fileData.mid(static_cast<int>(mf), static_cast<int>(qMin(manSize, 512u)));
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

void PEUIPresenter::appendComDescriptorDetailTree(QTreeWidgetItem *dirItem, quint32 rva, quint32 regionSize)
{
    if (!dirItem || rva == 0 || regionSize == 0) {
        return;
    }
    const quint32 fo = m_parser->rvaToFileOffset(rva);
    if (fo == 0 || fo + sizeof(IMAGE_COR20_HEADER) > static_cast<quint32>(m_parser->m_fileData.size())) {
        return;
    }

    const uchar *base = reinterpret_cast<const uchar *>(m_parser->m_fileData.constData() + fo);
    const quint32 cb = readLe32(base);
    const quint32 spill = qMin(qMax(cb, sizeof(IMAGE_COR20_HEADER)), regionSize);
    if (fo + spill > static_cast<quint32>(m_parser->m_fileData.size())) {
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

void PEUIPresenter::addInsightTreeField(QTreeWidgetItem *parent, const QString &displayName, const QString &value,
                                      const QString &jsonFieldKey, quint32 fileOffset, quint32 size,
                                      bool highlightInHex, const QString &meaningOverride)
{
    QTreeWidgetItem *fieldItem = new QTreeWidgetItem(parent);
    fieldItem->setText(0, displayName);
    fieldItem->setText(1, value);
    fieldItem->setData(0, PEParserNew::kTreeFieldKeyRole, jsonFieldKey);

    if (highlightInHex && size > 0) {
        fieldItem->setText(2, PEUtils::formatHexWidth(fileOffset, 8));
        fieldItem->setText(3, peTreeSizeBytesText(PEUtils::formatHexWidth(size, 0)));
        fieldItem->setData(0, kFieldOffsetRole, fileOffset);
        fieldItem->setData(0, kFieldSizeRole, size);
    } else if (!highlightInHex && size > 0) {
        fieldItem->setText(2, LANG("UI/insight_whole_file"));
        fieldItem->setText(3, QString());
    } else {
        fieldItem->setText(2, LANG("UI/insight_no_offset"));
        fieldItem->setText(3, QString());
    }

    QString meaning = meaningOverride;
    if (meaning.isEmpty() && isFileInsightJsonKey(jsonFieldKey)) {
        meaning = insightMeaningText(jsonFieldKey);
    }
    if (meaning.isEmpty()) {
        meaning = m_parser->getFieldMeaning(jsonFieldKey, value);
    }
    fieldItem->setText(4, meaning);
}

QTreeWidgetItem *PEUIPresenter::buildFileInsightsOverview()
{
    const PEOverlayInfo overlay = m_parser->m_dataModel.getOverlayInfo();
    const PEEntropySummary entropy = m_parser->m_dataModel.getEntropySummary();
    const PEPdbInfo pdb = m_parser->m_dataModel.getPdbInfo();
    const PEVersionInfo version = m_parser->m_dataModel.getVersionInfo();
    const PEFileMetrics metrics = m_parser->m_dataModel.getFileMetrics();

    auto entropyMeaning = [](double bits) -> QString {
        if (bits < 0.0) {
            return QString();
        }
        if (bits >= 7.2) {
            return uiStringWithFallback(QStringLiteral("UI/entropy_meaning_high"),
                                        QStringLiteral("High entropy — often packed, compressed, or encrypted content"));
        }
        if (bits >= 6.5) {
            return uiStringWithFallback(QStringLiteral("UI/entropy_meaning_elevated"),
                                        QStringLiteral("Elevated entropy — may include compressed or mixed content"));
        }
        return uiStringWithFallback(QStringLiteral("UI/entropy_meaning_normal"),
                                    QStringLiteral("Typical entropy for normal code or structured data"));
    };

    QTreeWidgetItem *insights = new QTreeWidgetItem();
    insights->setText(0, LANG("UI/tree_file_insights"));
    insights->setData(0, PEParserNew::kTreeFieldKeyRole, QStringLiteral("File Insights"));
    insights->setText(1, QString());
    insights->setText(2, QString());
    insights->setText(3, QString());
    insights->setText(4, insightMeaningText(QStringLiteral("File Insights")));

    if (overlay.present && overlay.fileOffset > 0) {
        quint64 overlayBytes = overlay.size;
        if (overlayBytes == 0) {
            const qint64 tail = qMax(m_parser->m_dataModel.getFileSize(), static_cast<qint64>(m_parser->m_file.size()))
                                - static_cast<qint64>(overlay.fileOffset);
            if (tail > 0) {
                overlayBytes = static_cast<quint64>(tail);
            }
        }
        const quint32 overlaySize =
            static_cast<quint32>(qMin(overlayBytes, static_cast<quint64>(UINT32_MAX)));
        const QString offHex = PEUtils::formatHexWidth(overlay.fileOffset, 8);
        const QString endHex =
            PEUtils::formatHexWidth(overlay.fileOffset + qMax(overlaySize, 1u) - 1, 8);
        const QString overlayVal = QStringLiteral("%1 (%2) to %3")
                                       .arg(offHex, peTreeSizeBytesText(PEUtils::formatHexWidth(overlaySize, 0)),
                                            endHex);
        addInsightTreeField(insights, LANG("UI/field_overlay"), overlayVal, QStringLiteral("Overlay"),
                            overlay.fileOffset, overlaySize, overlaySize > 0,
                            insightMeaningText(QStringLiteral("Overlay")));
    } else {
        addInsightTreeField(insights, LANG("UI/field_overlay"), LANG("UI/overlay_none"), QStringLiteral("Overlay"),
                            0, 0, false);
    }

    if (entropy.fileEntropyValid) {
        const QString entStr = QStringLiteral("%1 %2").arg(QString::number(entropy.fileEntropy, 'f', 2),
                                                           LANG("UI/entropy_unit"));
        addInsightTreeField(insights, LANG("UI/field_file_entropy"), entStr, QStringLiteral("File Entropy"), 0, 0,
                            false, entropyMeaning(entropy.fileEntropy));
        if (QTreeWidgetItem *entItem = insights->child(insights->childCount() - 1)) {
            entItem->setText(2, LANG("UI/insight_whole_file"));
        }
    }

    if (metrics.hashesValid) {
        addInsightTreeField(insights, LANG("UI/field_md5"), metrics.md5Hex, QStringLiteral("MD5"), 0, 0, false,
                            insightMeaningText(QStringLiteral("MD5")));
        addInsightTreeField(insights, LANG("UI/field_sha256"), metrics.sha256Hex, QStringLiteral("SHA256"), 0, 0,
                            false, insightMeaningText(QStringLiteral("SHA256")));
        if (!metrics.imphashHex.isEmpty()) {
            addInsightTreeField(insights, LANG("UI/field_imphash"), metrics.imphashHex, QStringLiteral("ImpHash"), 0,
                                0, false, insightMeaningText(QStringLiteral("ImpHash")));
        } else {
            addInsightTreeField(insights, LANG("UI/field_imphash"), LANG("UI/imphash_none"),
                                QStringLiteral("ImpHash"), 0, 0, false, insightMeaningText(QStringLiteral("ImpHash")));
        }
    }

    if (metrics.fileRatioValid) {
        QMap<QString, QString> ratioParams;
        ratioParams.insert(QStringLiteral("ratio"), QString::number(metrics.fileRatio * 100.0, 'f', 1));
        ratioParams.insert(QStringLiteral("pe_size"),
                           PEUtils::formatFileSize(static_cast<quint64>(metrics.peLogicalSize)));
        ratioParams.insert(QStringLiteral("file_size"),
                           PEUtils::formatFileSize(static_cast<quint64>(qMax(m_parser->m_dataModel.getFileSize(),
                                                                             static_cast<qint64>(m_parser->m_fileData.size())))));
        const QString ratioVal = LANG_PARAMS(QStringLiteral("UI/file_ratio_value"), ratioParams);
        addInsightTreeField(insights, LANG("UI/field_file_ratio"), ratioVal, QStringLiteral("File Ratio"), 0, 0,
                            false, insightMeaningText(QStringLiteral("File Ratio")));
    }

    if (metrics.toolchainValid) {
        addInsightTreeField(insights, LANG("UI/field_toolchain"), metrics.toolchainSummary,
                            QStringLiteral("Toolchain"), 0, 0, false,
                            insightMeaningText(QStringLiteral("Toolchain")));
    } else if (m_parser->m_dataModel.getAnalysisMetadata().richHeaderPresent) {
        addInsightTreeField(insights, LANG("UI/field_toolchain"), LANG("UI/toolchain_rich_unknown"),
                            QStringLiteral("Toolchain"), 0, 0, false,
                            insightMeaningText(QStringLiteral("Toolchain")));
    } else {
        addInsightTreeField(insights, LANG("UI/field_toolchain"), LANG("UI/toolchain_none"), QStringLiteral("Toolchain"),
                            0, 0, false, insightMeaningText(QStringLiteral("Toolchain")));
    }

    if (metrics.triageSummaryValid) {
        if (metrics.authenticodePresent) {
            QString signedValue;
            if (metrics.authenticodeInfo.trustStatus == AuthenticodeTrustStatus::Valid) {
                signedValue = LANG("UI/signed_table_yes");
                if (!metrics.authenticodePublisher.isEmpty()) {
                    QMap<QString, QString> publisherParams;
                    publisherParams.insert(QStringLiteral("publisher"), metrics.authenticodePublisher);
                    signedValue = LanguageManager::getInstance().getString(
                        QStringLiteral("UI/signed_publisher_format"),
                        publisherParams,
                        signedValue);
                }
            } else {
                QMap<QString, QString> certParams;
                certParams.insert(QStringLiteral("size"), PEUtils::formatFileSize(metrics.certTableSize));
                signedValue = LANG_PARAMS(QStringLiteral("UI/signed_table_cert_data"), certParams);
            }
            addInsightTreeField(insights, LANG("UI/field_signed"), signedValue,
                                QStringLiteral("Signed"), 0, 0, false,
                                insightMeaningText(QStringLiteral("Signed")));
        } else {
            addInsightTreeField(insights, LANG("UI/field_signed"), LANG("UI/signed_table_no"), QStringLiteral("Signed"), 0, 0,
                                false, insightMeaningText(QStringLiteral("Signed")));
        }

        if (metrics.entryPointRva != 0) {
            const QString epVal = formatEntryPointSummary(metrics);
            const quint32 epSize = metrics.entryPointBytesHex.isEmpty()
                                       ? 1u
                                       : static_cast<quint32>(PEEpDisasm::kDefaultEpByteSample);
            addInsightTreeField(insights, LANG("UI/field_entry_point"), epVal, QStringLiteral("Entry Point"),
                                metrics.entryPointFileOffset, epSize, metrics.entryPointFileOffset > 0,
                                insightMeaningText(QStringLiteral("Entry Point")));
        } else {
            addInsightTreeField(insights, LANG("UI/field_entry_point"), LANG("UI/entry_point_none"),
                                QStringLiteral("Entry Point"), 0, 0, false,
                                insightMeaningText(QStringLiteral("Entry Point")));
        }
    }

    if (pdb.present) {
        const quint32 cvBase = pdb.codeViewFileOffset;
        const quint32 cvSize = pdb.codeViewSize;
        const quint32 pathOff = pdb.pathFileOffset;
        const quint32 pathSize = pdb.pathByteSize;
        const bool rawHighlight = cvSize > 0
                                  && static_cast<quint64>(cvBase) + cvSize
                                         <= static_cast<quint64>(m_parser->m_fileData.size());
        const bool pathHighlight = pathSize > 0
                                   && static_cast<quint64>(pathOff) + pathSize
                                          <= static_cast<quint64>(m_parser->m_fileData.size());
        const bool isRsds = pdb.format.compare(QStringLiteral("RSDS"), Qt::CaseInsensitive) == 0;

        addInsightTreeField(insights, LANG("UI/field_pdb_path"), pdb.path, QStringLiteral("PDB Path"), pathOff,
                            pathSize, pathHighlight, insightMeaningText(QStringLiteral("PDB Path")));

        if (rawHighlight) {
            addInsightTreeField(insights, LANG("UI/field_pdb_raw"), formatCodeViewRawTreeValue(pdb),
                                QStringLiteral("PDB Raw"), cvBase, cvSize, true,
                                insightMeaningText(QStringLiteral("PDB Raw")));
        }

        if (!pdb.guid.isEmpty() && isRsds) {
            const bool guidOk = rawHighlight && cvBase + 20 <= cvBase + cvSize;
            addInsightTreeField(insights, LANG("UI/field_pdb_guid"), pdb.guid, QStringLiteral("PDB GUID"),
                                guidOk ? cvBase + 4 : 0, guidOk ? 16u : 0u, guidOk,
                                insightMeaningText(QStringLiteral("PDB GUID")));
        }

        const quint32 ageOff = isRsds ? cvBase + 20 : cvBase + 8;
        const QString ageVal = QStringLiteral("%1 (%2)").arg(QString::number(pdb.age), pdb.format);
        const bool ageOk = rawHighlight && ageOff + 4 <= cvBase + cvSize;
        addInsightTreeField(insights, LANG("UI/field_pdb_age"), ageVal, QStringLiteral("PDB Age"),
                            ageOk ? ageOff : 0, ageOk ? 4u : 0u, ageOk,
                            insightMeaningText(QStringLiteral("PDB Age")));
    } else {
        addInsightTreeField(insights, LANG("UI/field_pdb_path"), LANG("UI/pdb_none"), QStringLiteral("PDB Path"), 0, 0,
                            false);
    }

    const auto addVersionField = [&](const QString &labelKey, const QString &value, const QString &treeKey,
                                   bool highlight = false) {
        if (value.isEmpty()) {
            return;
        }
        const bool canHighlight = highlight && version.versionResourceSize > 0
                                  && static_cast<quint64>(version.versionResourceOffset)
                                         + version.versionResourceSize
                                         <= static_cast<quint64>(m_parser->m_fileData.size());
        addInsightTreeField(insights, LANG(labelKey), value, treeKey,
                            canHighlight ? version.versionResourceOffset : 0u,
                            canHighlight ? version.versionResourceSize : 0u, canHighlight,
                            insightMeaningText(treeKey));
    };

    if (version.present) {
        addVersionField(QStringLiteral("UI/field_file_version"), version.fileVersion,
                        QStringLiteral("File Version"), true);
        addVersionField(QStringLiteral("UI/field_product_version"), version.productVersion,
                        QStringLiteral("Product Version"));
        addVersionField(QStringLiteral("UI/field_company_name"), version.companyName,
                        QStringLiteral("Company Name"));
        addVersionField(QStringLiteral("UI/field_product_name"), version.productName,
                        QStringLiteral("Product Name"));
    } else {
        addInsightTreeField(insights, LANG("UI/field_file_version"), LANG("UI/version_none"),
                            QStringLiteral("File Version"), 0, 0, false,
                            insightMeaningText(QStringLiteral("File Version")));
    }

    if (version.manifestPresent) {
        const QString uac = version.manifestExecutionLevel.isEmpty()
                                ? LANG("UI/version_manifest_present")
                                : version.manifestExecutionLevel;
        addInsightTreeField(insights, LANG("UI/field_manifest_uac"), uac, QStringLiteral("Manifest UAC"), 0, 0,
                            false, insightMeaningText(QStringLiteral("Manifest UAC")));
    }

    return insights;
}

