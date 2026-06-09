#include "pe_report_builder.h"

#include "language_manager.h"
#include "pe_data_model.h"
#include "pe_structures.h"
#include "pe_utils.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

QString PEReportBuilder::formatFileSize(qint64 size)
{
    if (size < 1024) {
        return LANG_PARAM("UI/size_bytes", "size", QString::number(size));
    }
    if (size < 1024 * 1024) {
        return LANG_PARAM("UI/size_kb", "size", QString::number(size / 1024.0, 'f', 1));
    }
    return LANG_PARAM("UI/size_mb", "size", QString::number(size / (1024.0 * 1024.0), 'f', 1));
}

QString PEReportBuilder::escapeXml(const QString &str)
{
    QString out;
    out.reserve(static_cast<int>(str.size() * 1.1));
    for (QChar c : str) {
        if (c == QLatin1Char('&'))
            out += QLatin1String("&amp;");
        else if (c == QLatin1Char('<'))
            out += QLatin1String("&lt;");
        else if (c == QLatin1Char('>'))
            out += QLatin1String("&gt;");
        else if (c == QLatin1Char('"'))
            out += QLatin1String("&quot;");
        else if (c == QLatin1Char('\''))
            out += QLatin1String("&apos;");
        else
            out += c;
    }
    return out;
}

QString PEReportBuilder::buildTextReport(const PEDataModel &dataModel)
{
    if (!dataModel.isValid()) {
        return QString();
    }

    QString out;
    QTextStream s(&out);
    const QString path = dataModel.getFilePath();
    const qint64 fsize = dataModel.getFileSize();
    s << "PEHint Analysis Report\n";
    s << "=====================\n\n";
    s << "File: " << path << "\n";
    s << "Size: " << formatFileSize(fsize) << " (" << fsize << " bytes)\n\n";

    const IMAGE_DOS_HEADER *dos = dataModel.getDOSHeader();
    if (dos) {
        s << "--- DOS Header ---\n";
        s << "  e_magic:     " << PEUtils::formatHexWidth(dos->e_magic, 4) << " (MZ)\n";
        s << "  e_lfanew:    " << PEUtils::formatHex(dos->e_lfanew) << "\n\n";
    }

    const IMAGE_FILE_HEADER *fh = dataModel.getFileHeader();
    if (fh) {
        s << "--- File Header ---\n";
        s << "  Machine:              " << PEUtils::formatHexWidth(fh->Machine, 4) << " ("
          << PEUtils::getMachineType(fh->Machine) << ")\n";
        s << "  NumberOfSections:     " << fh->NumberOfSections << "\n";
        s << "  Characteristics:      " << PEUtils::formatHexWidth(fh->Characteristics, 4) << " ("
          << PEUtils::getFileCharacteristics(fh->Characteristics) << ")\n\n";
    }

    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    if (opt) {
        s << "--- Optional Header ---\n";
        s << "  Magic:                 " << PEUtils::formatHexWidth(opt->Magic, 4)
          << (opt->Magic == 0x20b ? " (PE32+)" : " (PE32)") << "\n";
        s << "  AddressOfEntryPoint:   " << PEUtils::formatHex(opt->AddressOfEntryPoint) << "\n";
        s << "  Subsystem:             " << PEUtils::formatHexWidth(opt->Subsystem, 4) << " ("
          << PEUtils::getSubsystem(opt->Subsystem) << ")\n";
        s << "  SizeOfImage:           " << PEUtils::formatHex(opt->SizeOfImage) << "\n\n";
    }

    const QList<const IMAGE_SECTION_HEADER *> &sections = dataModel.getSections();
    if (!sections.isEmpty()) {
        s << "--- Sections (" << sections.size() << ") ---\n";
        for (const IMAGE_SECTION_HEADER *sec : sections) {
            const QString name = QString::fromLatin1(sec->Name, 8).trimmed();
            s << "  " << name << "  VA=" << PEUtils::formatHex(sec->VirtualAddress)
              << "  VSize=" << PEUtils::formatHex(sec->Misc.VirtualSize)
              << "  RawSize=" << PEUtils::formatHex(sec->SizeOfRawData) << "  "
              << PEUtils::getSectionCharacteristics(sec->Characteristics) << "\n";
        }
        s << "\n";
    }

    const QStringList imports = dataModel.getImports();
    if (!imports.isEmpty()) {
        s << "--- Imports ---\n";
        const auto &importDetails = dataModel.getImportFunctions();
        for (const QString &mod : imports) {
            s << "  " << mod << "\n";
            for (const PEDataModel::ImportFunctionEntry &e : importDetails.value(mod)) {
                s << "    " << (e.importedByOrdinal ? QString("#%1").arg(e.ordinal) : e.name)
                  << "  RVA=" << PEUtils::formatHex(e.thunkRVA) << "\n";
            }
        }
        s << "\n";
    }

    const QList<PEDataModel::ExportFunctionEntry> &exports = dataModel.getExportFunctions();
    if (!exports.isEmpty()) {
        s << "--- Exports ---\n";
        for (const PEDataModel::ExportFunctionEntry &e : exports) {
            s << "  " << (e.name.isEmpty() ? QString("[%1]").arg(e.ordinal) : e.name)
              << "  ordinal=" << e.ordinal << "  RVA=" << PEUtils::formatHex(e.rva) << "\n";
        }
    }
    return out;
}

QString PEReportBuilder::buildHtmlReport(const PEDataModel &dataModel)
{
    QString body = buildTextReport(dataModel);
    if (body.isEmpty()) {
        return QString();
    }
    body = body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>\n");
    return QStringLiteral(
               "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>PEHint Report</title>"
               "<style>body{font-family:Consolas,monospace;margin:1em;} pre{white-space:pre-wrap;}</style></head>"
               "<body><h1>PEHint Analysis Report</h1><pre>")
           + body + QStringLiteral("</pre></body></html>");
}

QString PEReportBuilder::buildJsonReport(const PEDataModel &dataModel)
{
    if (!dataModel.isValid()) {
        return QString();
    }

    QJsonObject root;
    root["filePath"] = dataModel.getFilePath();
    root["fileSize"] = static_cast<qint64>(dataModel.getFileSize());

    const IMAGE_DOS_HEADER *dos = dataModel.getDOSHeader();
    if (dos) {
        QJsonObject o;
        o["e_magic"] = QString(PEUtils::formatHexWidth(dos->e_magic, 4));
        o["e_lfanew"] = static_cast<int>(dos->e_lfanew);
        root["dosHeader"] = o;
    }

    const IMAGE_FILE_HEADER *fh = dataModel.getFileHeader();
    if (fh) {
        QJsonObject o;
        o["machine"] = static_cast<int>(fh->Machine);
        o["machineType"] = PEUtils::getMachineType(fh->Machine);
        o["numberOfSections"] = fh->NumberOfSections;
        o["characteristics"] = QString(PEUtils::formatHexWidth(fh->Characteristics, 4));
        root["fileHeader"] = o;
    }

    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    if (opt) {
        QJsonObject o;
        o["magic"] = static_cast<int>(opt->Magic);
        o["addressOfEntryPoint"] = QString(PEUtils::formatHex(opt->AddressOfEntryPoint));
        o["subsystem"] = static_cast<int>(opt->Subsystem);
        o["subsystemName"] = PEUtils::getSubsystem(opt->Subsystem);
        o["sizeOfImage"] = static_cast<int>(opt->SizeOfImage);
        root["optionalHeader"] = o;
    }

    QJsonArray secArr;
    for (const IMAGE_SECTION_HEADER *sec : dataModel.getSections()) {
        QJsonObject o;
        o["name"] = QString::fromLatin1(sec->Name, 8).trimmed();
        o["virtualAddress"] = QString(PEUtils::formatHex(sec->VirtualAddress));
        o["virtualSize"] = static_cast<int>(sec->Misc.VirtualSize);
        o["sizeOfRawData"] = static_cast<int>(sec->SizeOfRawData);
        secArr.append(o);
    }
    if (!secArr.isEmpty()) {
        root["sections"] = secArr;
    }

    const auto &importDetails = dataModel.getImportFunctions();
    QJsonObject importObj;
    for (const QString &mod : dataModel.getImports()) {
        QJsonArray arr;
        for (const PEDataModel::ImportFunctionEntry &e : importDetails.value(mod)) {
            arr.append(e.importedByOrdinal ? QString("#%1").arg(e.ordinal) : e.name);
        }
        importObj[mod] = arr;
    }
    if (!importObj.isEmpty()) {
        root["imports"] = importObj;
    }

    QJsonArray expArr;
    for (const PEDataModel::ExportFunctionEntry &e : dataModel.getExportFunctions()) {
        QJsonObject o;
        o["name"] = e.name.isEmpty() ? QString("[%1]").arg(e.ordinal) : e.name;
        o["ordinal"] = e.ordinal;
        o["rva"] = QString(PEUtils::formatHex(e.rva));
        expArr.append(o);
    }
    if (!expArr.isEmpty()) {
        root["exports"] = expArr;
    }

    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Indented));
}

QString PEReportBuilder::buildXmlReport(const PEDataModel &dataModel)
{
    if (!dataModel.isValid()) {
        return QString();
    }

    QString out;
    QTextStream s(&out);
    s << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PEHintReport>\n";
    s << "  <file path=\"" << escapeXml(dataModel.getFilePath()) << "\" size=\"" << dataModel.getFileSize()
      << "\" />\n";

    const IMAGE_DOS_HEADER *dos = dataModel.getDOSHeader();
    if (dos) {
        s << "  <dosHeader e_magic=\"" << PEUtils::formatHexWidth(dos->e_magic, 4) << "\" e_lfanew=\""
          << dos->e_lfanew << "\" />\n";
    }
    const IMAGE_FILE_HEADER *fh = dataModel.getFileHeader();
    if (fh) {
        s << "  <fileHeader machine=\"" << fh->Machine << "\" machineType=\""
          << escapeXml(PEUtils::getMachineType(fh->Machine)) << "\" numberOfSections=\"" << fh->NumberOfSections
          << "\" />\n";
    }
    const IMAGE_OPTIONAL_HEADER *opt = dataModel.getOptionalHeader();
    if (opt) {
        s << "  <optionalHeader magic=\"" << opt->Magic << "\" addressOfEntryPoint=\""
          << PEUtils::formatHex(opt->AddressOfEntryPoint) << "\" subsystem=\"" << opt->Subsystem
          << "\" subsystemName=\"" << escapeXml(PEUtils::getSubsystem(opt->Subsystem)) << "\" />\n";
    }
    s << "  <sections>\n";
    for (const IMAGE_SECTION_HEADER *sec : dataModel.getSections()) {
        const QString name = QString::fromLatin1(sec->Name, 8).trimmed();
        s << "    <section name=\"" << escapeXml(name) << "\" virtualAddress=\""
          << PEUtils::formatHex(sec->VirtualAddress) << "\" virtualSize=\"" << sec->Misc.VirtualSize
          << "\" sizeOfRawData=\"" << sec->SizeOfRawData << "\" />\n";
    }
    s << "  </sections>\n  <imports>\n";
    const auto &importDetails = dataModel.getImportFunctions();
    for (const QString &mod : dataModel.getImports()) {
        s << "    <module name=\"" << escapeXml(mod) << "\">\n";
        for (const PEDataModel::ImportFunctionEntry &e : importDetails.value(mod)) {
            s << "      <import>" << escapeXml(e.importedByOrdinal ? QString("#%1").arg(e.ordinal) : e.name)
              << "</import>\n";
        }
        s << "    </module>\n";
    }
    s << "  </imports>\n  <exports>\n";
    for (const PEDataModel::ExportFunctionEntry &e : dataModel.getExportFunctions()) {
        s << "    <export name=\""
          << escapeXml(e.name.isEmpty() ? QString::number(e.ordinal) : e.name) << "\" ordinal=\"" << e.ordinal
          << "\" rva=\"" << PEUtils::formatHex(e.rva) << "\" />\n";
    }
    s << "  </exports>\n</PEHintReport>\n";
    return out;
}
