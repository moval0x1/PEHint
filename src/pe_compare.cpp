#include "pe_compare.h"
#include "pe_authenticode.h"
#include "pe_data_model.h"
#include "pe_findings.h"
#include "pe_utils.h"

#include <QSet>
#include <cmath>
#include <cstring>

namespace PECompare {

namespace {

QString machineName(quint16 machine)
{
    switch (machine) {
    case 0x014C: return QStringLiteral("x86");
    case 0x8664: return QStringLiteral("x64");
    case 0xAA64: return QStringLiteral("ARM64");
    case 0x01C4: return QStringLiteral("ARM");
    default:     return QStringLiteral("0x%1").arg(machine, 4, 16, QChar('0'));
    }
}

QString subsystemName(quint16 sub)
{
    switch (sub) {
    case 2:  return QStringLiteral("GUI");
    case 3:  return QStringLiteral("Console");
    case 1:  return QStringLiteral("Native");
    default: return QString::number(sub);
    }
}

void diffField(QList<FieldDiff> &out, const QString &name,
               const QString &vA, const QString &vB)
{
    if (vA != vB) {
        out.append({name, vA, vB});
    }
}

void compareHeaders(const PEDataModel &a, const PEDataModel &b, QList<FieldDiff> &out)
{
    const IMAGE_FILE_HEADER *fhA = a.getFileHeader();
    const IMAGE_FILE_HEADER *fhB = b.getFileHeader();
    if (fhA && fhB) {
        diffField(out, QStringLiteral("Machine"),
                  machineName(fhA->Machine), machineName(fhB->Machine));
        diffField(out, QStringLiteral("NumberOfSections"),
                  QString::number(fhA->NumberOfSections), QString::number(fhB->NumberOfSections));
        diffField(out, QStringLiteral("TimeDateStamp"),
                  PEUtils::formatHex(fhA->TimeDateStamp), PEUtils::formatHex(fhB->TimeDateStamp));
        diffField(out, QStringLiteral("Characteristics"),
                  PEUtils::formatHex(fhA->Characteristics), PEUtils::formatHex(fhB->Characteristics));
    }

    const IMAGE_OPTIONAL_HEADER *ohA = a.getOptionalHeader();
    const IMAGE_OPTIONAL_HEADER *ohB = b.getOptionalHeader();
    if (ohA && ohB) {
        diffField(out, QStringLiteral("AddressOfEntryPoint"),
                  PEUtils::formatHex(ohA->AddressOfEntryPoint), PEUtils::formatHex(ohB->AddressOfEntryPoint));
        diffField(out, QStringLiteral("ImageBase"),
                  PEUtils::formatHex(ohA->ImageBase), PEUtils::formatHex(ohB->ImageBase));
        diffField(out, QStringLiteral("SizeOfImage"),
                  PEUtils::formatHex(ohA->SizeOfImage), PEUtils::formatHex(ohB->SizeOfImage));
        diffField(out, QStringLiteral("SizeOfHeaders"),
                  PEUtils::formatHex(ohA->SizeOfHeaders), PEUtils::formatHex(ohB->SizeOfHeaders));
        diffField(out, QStringLiteral("CheckSum"),
                  PEUtils::formatHex(ohA->CheckSum), PEUtils::formatHex(ohB->CheckSum));
        diffField(out, QStringLiteral("Subsystem"),
                  subsystemName(ohA->Subsystem), subsystemName(ohB->Subsystem));
        diffField(out, QStringLiteral("DllCharacteristics"),
                  PEUtils::formatHex(ohA->DllCharacteristics), PEUtils::formatHex(ohB->DllCharacteristics));
        diffField(out, QStringLiteral("SectionAlignment"),
                  PEUtils::formatHex(ohA->SectionAlignment), PEUtils::formatHex(ohB->SectionAlignment));
        diffField(out, QStringLiteral("FileAlignment"),
                  PEUtils::formatHex(ohA->FileAlignment), PEUtils::formatHex(ohB->FileAlignment));
    }
}

void compareSections(const PEDataModel &a, const PEDataModel &b, QList<SectionDiff> &out)
{
    QMap<QString, const IMAGE_SECTION_HEADER *> byNameA;
    QMap<QString, const IMAGE_SECTION_HEADER *> byNameB;

    for (const IMAGE_SECTION_HEADER *s : a.getSections()) {
        const int len = static_cast<int>(strnlen(reinterpret_cast<const char *>(s->Name), 8));
        const QString name = QString::fromLatin1(reinterpret_cast<const char *>(s->Name), len).trimmed();
        byNameA.insert(name, s);
    }
    for (const IMAGE_SECTION_HEADER *s : b.getSections()) {
        const int len = static_cast<int>(strnlen(reinterpret_cast<const char *>(s->Name), 8));
        const QString name = QString::fromLatin1(reinterpret_cast<const char *>(s->Name), len).trimmed();
        byNameB.insert(name, s);
    }

    QSet<QString> allNames;
    for (const QString &k : byNameA.keys()) allNames.insert(k);
    for (const QString &k : byNameB.keys()) allNames.insert(k);

    for (const QString &name : qAsConst(allNames)) {
        SectionDiff sd;
        sd.name = name;
        const bool inA = byNameA.contains(name);
        const bool inB = byNameB.contains(name);
        sd.onlyInA = inA && !inB;
        sd.onlyInB = !inA && inB;

        if (inA && inB) {
            const IMAGE_SECTION_HEADER *sA = byNameA[name];
            const IMAGE_SECTION_HEADER *sB = byNameB[name];
            diffField(sd.fields, QStringLiteral("VirtualSize"),
                      PEUtils::formatHex(sA->Misc.VirtualSize), PEUtils::formatHex(sB->Misc.VirtualSize));
            diffField(sd.fields, QStringLiteral("VirtualAddress"),
                      PEUtils::formatHex(sA->VirtualAddress), PEUtils::formatHex(sB->VirtualAddress));
            diffField(sd.fields, QStringLiteral("SizeOfRawData"),
                      PEUtils::formatHex(sA->SizeOfRawData), PEUtils::formatHex(sB->SizeOfRawData));
            diffField(sd.fields, QStringLiteral("Characteristics"),
                      PEUtils::formatHex(sA->Characteristics), PEUtils::formatHex(sB->Characteristics));

            // Entropy
            const double eA = a.sectionEntropy(name);
            const double eB = b.sectionEntropy(name);
            sd.entropyA = eA;
            sd.entropyB = eB;
            if (eA >= 0 && eB >= 0 && std::abs(eA - eB) > 0.1) {
                diffField(sd.fields, QStringLiteral("Entropy"),
                          QString::number(eA, 'f', 2), QString::number(eB, 'f', 2));
            }
        }

        if (sd.onlyInA || sd.onlyInB || !sd.fields.isEmpty()) {
            out.append(sd);
        }
    }
}

void compareImports(const PEDataModel &a, const PEDataModel &b, QList<ModuleDiff> &out)
{
    const auto &impsA = a.getImportFunctions();
    const auto &impsB = b.getImportFunctions();

    QSet<QString> allMods;
    for (const QString &k : impsA.keys()) allMods.insert(k.toLower());
    for (const QString &k : impsB.keys()) allMods.insert(k.toLower());

    for (const QString &modLower : qAsConst(allMods)) {
        QString keyA, keyB;
        for (const QString &k : impsA.keys()) {
            if (k.toLower() == modLower) { keyA = k; break; }
        }
        for (const QString &k : impsB.keys()) {
            if (k.toLower() == modLower) { keyB = k; break; }
        }

        ModuleDiff md;
        md.moduleName = keyA.isEmpty() ? keyB : keyA;

        QSet<QString> funcsA, funcsB;
        if (!keyA.isEmpty()) {
            for (const auto &f : impsA[keyA]) funcsA.insert(f.name);
        }
        if (!keyB.isEmpty()) {
            for (const auto &f : impsB[keyB]) funcsB.insert(f.name);
        }

        for (const QString &fn : qAsConst(funcsA)) {
            if (!funcsB.contains(fn)) md.onlyInA.append(fn);
        }
        for (const QString &fn : qAsConst(funcsB)) {
            if (!funcsA.contains(fn)) md.onlyInB.append(fn);
        }

        if (!md.onlyInA.isEmpty() || !md.onlyInB.isEmpty()
                || funcsA.isEmpty() != funcsB.isEmpty()) {
            out.append(md);
        }
    }
}

void compareExports(const PEDataModel &a, const PEDataModel &b,
                    QStringList &onlyA, QStringList &onlyB)
{
    QSet<QString> exA, exB;
    for (const auto &e : a.getExportFunctions()) {
        if (!e.name.isEmpty()) exA.insert(e.name);
    }
    for (const auto &e : b.getExportFunctions()) {
        if (!e.name.isEmpty()) exB.insert(e.name);
    }
    for (const QString &n : qAsConst(exA)) {
        if (!exB.contains(n)) onlyA.append(n);
    }
    for (const QString &n : qAsConst(exB)) {
        if (!exA.contains(n)) onlyB.append(n);
    }
    onlyA.sort();
    onlyB.sort();
}

void compareFindings(const PEDataModel &a, const PEDataModel &b,
                     QStringList &onlyA, QStringList &onlyB,
                     QMap<QString, QString> &titles)
{
    PEFindingsEngine::loadRules();
    const auto findingsA = PEFindingsEngine::evaluate(a, [](quint32) { return 0u; });
    const auto findingsB = PEFindingsEngine::evaluate(b, [](quint32) { return 0u; });

    // Collect titles from both sets
    for (const auto &f : findingsA) {
        if (!f.isPass && !titles.contains(f.ruleId))
            titles.insert(f.ruleId, f.title);
    }
    for (const auto &f : findingsB) {
        if (!f.isPass && !titles.contains(f.ruleId))
            titles.insert(f.ruleId, f.title);
    }

    QSet<QString> idsA, idsB;
    for (const auto &f : findingsA) { if (!f.isPass) idsA.insert(f.ruleId); }
    for (const auto &f : findingsB) { if (!f.isPass) idsB.insert(f.ruleId); }

    for (const QString &id : qAsConst(idsA)) {
        if (!idsB.contains(id)) onlyA.append(id);
    }
    for (const QString &id : qAsConst(idsB)) {
        if (!idsA.contains(id)) onlyB.append(id);
    }
    onlyA.sort();
    onlyB.sort();
}

void compareVersion(const PEDataModel &a, const PEDataModel &b, QList<FieldDiff> &out)
{
    const PEVersionInfo vA = a.getVersionInfo();
    const PEVersionInfo vB = b.getVersionInfo();
    if (!vA.present && !vB.present)
        return;
    const QString presA = vA.present ? QStringLiteral("present") : QStringLiteral("absent");
    const QString presB = vB.present ? QStringLiteral("present") : QStringLiteral("absent");
    diffField(out, QStringLiteral("Version resource"), presA, presB);
    if (vA.present && vB.present) {
        diffField(out, QStringLiteral("FileVersion"),       vA.fileVersion,       vB.fileVersion);
        diffField(out, QStringLiteral("ProductVersion"),    vA.productVersion,    vB.productVersion);
        diffField(out, QStringLiteral("CompanyName"),       vA.companyName,       vB.companyName);
        diffField(out, QStringLiteral("ProductName"),       vA.productName,       vB.productName);
        diffField(out, QStringLiteral("FileDescription"),   vA.fileDescription,   vB.fileDescription);
        diffField(out, QStringLiteral("OriginalFilename"),  vA.originalFilename,  vB.originalFilename);
        diffField(out, QStringLiteral("InternalName"),      vA.internalName,      vB.internalName);
    }
}

void comparePdb(const PEDataModel &a, const PEDataModel &b, QList<FieldDiff> &out)
{
    const PEPdbInfo pA = a.getPdbInfo();
    const PEPdbInfo pB = b.getPdbInfo();
    if (!pA.present && !pB.present)
        return;
    diffField(out, QStringLiteral("Debug info"),
              pA.present ? QStringLiteral("present") : QStringLiteral("absent"),
              pB.present ? QStringLiteral("present") : QStringLiteral("absent"));
    if (pA.present && pB.present) {
        diffField(out, QStringLiteral("PDB path"), pA.path, pB.path);
        diffField(out, QStringLiteral("PDB GUID"), pA.guid, pB.guid);
        diffField(out, QStringLiteral("Age"),
                  QString::number(pA.age), QString::number(pB.age));
    }
}

void compareTls(const PEDataModel &a, const PEDataModel &b, QList<FieldDiff> &out)
{
    const PETlsDirectoryInfo tA = a.tlsDirectoryInfo();
    const PETlsDirectoryInfo tB = b.tlsDirectoryInfo();
    if (!tA.present && !tB.present)
        return;
    diffField(out, QStringLiteral("TLS directory"),
              tA.present ? QStringLiteral("present") : QStringLiteral("absent"),
              tB.present ? QStringLiteral("present") : QStringLiteral("absent"));
    if (tA.present && tB.present) {
        diffField(out, QStringLiteral("Callback count"),
                  QString::number(tA.callbackAddresses.size()),
                  QString::number(tB.callbackAddresses.size()));
    }
}

void compareResources(const PEDataModel &a, const PEDataModel &b, QList<FieldDiff> &out)
{
    const QVector<PEResourceItem> &resA = a.getResourceEntries();
    const QVector<PEResourceItem> &resB = b.getResourceEntries();
    if (resA.isEmpty() && resB.isEmpty())
        return;

    diffField(out, QStringLiteral("Total resources"),
              QString::number(resA.size()), QString::number(resB.size()));

    const auto countByType = [](const QVector<PEResourceItem> &items) {
        QMap<QString, int> counts;
        for (const auto &r : items) {
            const QString key = r.typeName.isEmpty()
                ? QStringLiteral("Type %1").arg(r.typeId)
                : r.typeName;
            counts[key]++;
        }
        return counts;
    };

    const QMap<QString, int> cA = countByType(resA);
    const QMap<QString, int> cB = countByType(resB);
    QSet<QString> allTypes;
    for (const QString &k : cA.keys()) allTypes.insert(k);
    for (const QString &k : cB.keys()) allTypes.insert(k);

    for (const QString &type : qAsConst(allTypes)) {
        const int nA = cA.value(type, 0);
        const int nB = cB.value(type, 0);
        if (nA != nB) {
            diffField(out, type, QString::number(nA), QString::number(nB));
        }
    }
}

void compareSignature(const PEDataModel &a, const PEDataModel &b, QList<FieldDiff> &out)
{
    const PEFileMetrics mA = a.getFileMetrics();
    const PEFileMetrics mB = b.getFileMetrics();

    const auto sigLabel = [](const PEFileMetrics &m) -> QString {
        if (!m.authenticodePresent)
            return QStringLiteral("Not signed");
        const bool trusted = (m.authenticodeInfo.trustStatus
                              == AuthenticodeTrustStatus::Valid);
        const QString pub = m.authenticodeInfo.publisher.isEmpty()
            ? m.authenticodePublisher
            : m.authenticodeInfo.publisher;
        return trusted
            ? QStringLiteral("Signed — %1").arg(pub)
            : QStringLiteral("Cert present (untrusted) — %1").arg(pub);
    };

    diffField(out, QStringLiteral("Authenticode"), sigLabel(mA), sigLabel(mB));

    if (mA.authenticodePresent && mB.authenticodePresent) {
        diffField(out, QStringLiteral("Cert thumbprint (SHA-1)"),
                  mA.authenticodeInfo.thumbprintSha1,
                  mB.authenticodeInfo.thumbprintSha1);
    }
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

QString esc(const QString &s)
{
    QString r = s;
    r.replace(QLatin1Char('&'), QStringLiteral("&amp;"));
    r.replace(QLatin1Char('<'), QStringLiteral("&lt;"));
    r.replace(QLatin1Char('>'), QStringLiteral("&gt;"));
    return r;
}

QString formatFindingId(const QString &id, const QMap<QString, QString> &titles)
{
    // Use human-readable title when available
    if (titles.contains(id)) {
        const QString title = titles.value(id);
        // Append a small badge for flagged import IDs so origin is clear
        if (id.startsWith(QStringLiteral("flagged_import:"))) {
            return esc(title)
                + QStringLiteral("&nbsp;<span class='badge'>(import)</span>");
        }
        return esc(title);
    }

    // Fallback: format the raw ID
    QString label;
    QString badge;
    if (id.startsWith(QStringLiteral("flagged_import:malapi:"))) {
        label = id.mid(22);
        badge = QStringLiteral("malapi");
    } else if (id.startsWith(QStringLiteral("flagged_import:"))) {
        label = id.mid(15);
        badge = QStringLiteral("import");
    } else {
        label = id;
        label.replace(QLatin1Char('_'), QLatin1Char(' '));
    }
    if (!label.isEmpty())
        label[0] = label[0].toUpper();
    QString r = esc(label);
    if (!badge.isEmpty())
        r += QStringLiteral("&nbsp;<span class='badge'>(%1)</span>").arg(badge);
    return r;
}

QString itemList(const QStringList &items, const QString &cssClass)
{
    QString h = QStringLiteral("<ul>");
    for (const QString &s : items) {
        h += QStringLiteral("<li class='%1'>%2</li>").arg(cssClass, esc(s));
    }
    h += QStringLiteral("</ul>");
    return h;
}

QString findingList(const QStringList &ids, const QString &cssClass,
                    const QMap<QString, QString> &titles)
{
    QString h = QStringLiteral("<ul>");
    for (const QString &id : ids) {
        h += QStringLiteral("<li class='%1'>%2</li>")
                 .arg(cssClass, formatFindingId(id, titles));
    }
    h += QStringLiteral("</ul>");
    return h;
}

QString fieldTable(const QList<FieldDiff> &fields,
                   const QString &nameA, const QString &nameB,
                   const QString &colA, const QString &colB)
{
    QString h = QStringLiteral(
        "<table><tr><th>Field</th><th class='a'>%1</th><th class='b'>%2</th></tr>")
        .arg(esc(nameA), esc(nameB));
    for (const FieldDiff &f : fields) {
        h += QStringLiteral("<tr><td>%1</td><td class='a'>%2</td><td class='b'>%3</td></tr>")
                 .arg(esc(f.name), esc(f.valueA), esc(f.valueB));
    }
    h += QStringLiteral("</table>");
    Q_UNUSED(colA); Q_UNUSED(colB);
    return h;
}

} // namespace

// ---------------------------------------------------------------------------

int Result::totalDifferences() const
{
    int n = headerFields.size();
    for (const auto &s : sections) n += s.onlyInA ? 1 : s.onlyInB ? 1 : s.fields.size();
    for (const auto &m : imports) n += m.onlyInA.size() + m.onlyInB.size();
    n += exportsOnlyInA.size() + exportsOnlyInB.size();
    n += findingsOnlyInA.size() + findingsOnlyInB.size();
    n += versionFields.size() + pdbFields.size() + tlsFields.size()
         + resourceFields.size() + signatureFields.size();
    return n;
}

Result compare(const PEDataModel &a, const PEDataModel &b,
               const QString &pathA, const QString &pathB)
{
    Result r;
    r.filePathA = pathA;
    r.filePathB = pathB;
    compareHeaders(a, b, r.headerFields);
    compareSections(a, b, r.sections);
    compareImports(a, b, r.imports);
    compareExports(a, b, r.exportsOnlyInA, r.exportsOnlyInB);
    compareFindings(a, b, r.findingsOnlyInA, r.findingsOnlyInB, r.findingTitles);
    compareVersion(a, b, r.versionFields);
    comparePdb(a, b, r.pdbFields);
    compareTls(a, b, r.tlsFields);
    compareResources(a, b, r.resourceFields);
    compareSignature(a, b, r.signatureFields);
    return r;
}

QString toHtml(const Result &result)
{
    const QString colA = QStringLiteral("#d32f2f");
    const QString colB = QStringLiteral("#1976d2");
    const QString colSame = QStringLiteral("#555");

    QString h;
    h += QStringLiteral("<html><head><style>"
                        "body{font-family:monospace;font-size:12px;margin:8px}"
                        "h2{font-size:13px;margin:12px 0 4px;border-bottom:1px solid #ddd;padding-bottom:2px}"
                        "table{border-collapse:collapse;width:100%;margin-bottom:8px}"
                        "td,th{padding:2px 6px;border:1px solid #ccc;vertical-align:top}"
                        "th{background:#eee;font-weight:bold}"
                        "ul{margin:2px 0 6px 18px;padding:0}"
                        "li{margin:1px 0}"
                        ".a{color:%1}.b{color:%2}.same{color:%3}"
                        ".only{font-style:italic}"
                        ".badge{font-size:10px;color:#888;font-style:italic}"
                        ".mod{font-weight:bold;margin:6px 0 2px}"
                        "</style></head><body>").arg(colA, colB, colSame);

    const QString nameA = result.filePathA.isEmpty()
        ? QStringLiteral("File A")
        : result.filePathA.section(QLatin1Char('/'), -1).section(QLatin1Char('\\'), -1);
    const QString nameB = result.filePathB.isEmpty()
        ? QStringLiteral("File B")
        : result.filePathB.section(QLatin1Char('/'), -1).section(QLatin1Char('\\'), -1);
    const int total = result.totalDifferences();

    h += QStringLiteral("<p><b>%1 difference(s)</b> between "
                        "<span class='a'>%2</span> and <span class='b'>%3</span></p>")
             .arg(total).arg(esc(nameA), esc(nameB));

    // Headers
    if (!result.headerFields.isEmpty()) {
        h += QStringLiteral("<h2>Headers</h2>");
        h += fieldTable(result.headerFields, nameA, nameB, colA, colB);
    }

    // Sections
    if (!result.sections.isEmpty()) {
        h += QStringLiteral("<h2>Sections</h2>");
        for (const SectionDiff &s : result.sections) {
            if (s.onlyInA) {
                h += QStringLiteral("<p class='a only'>Section <b>%1</b> only in %2</p>")
                         .arg(esc(s.name), esc(nameA));
            } else if (s.onlyInB) {
                h += QStringLiteral("<p class='b only'>Section <b>%1</b> only in %2</p>")
                         .arg(esc(s.name), esc(nameB));
            } else if (!s.fields.isEmpty()) {
                h += QStringLiteral("<p class='mod'>%1</p>").arg(esc(s.name));
                h += fieldTable(s.fields, nameA, nameB, colA, colB);
            }
        }
    }

    // Version info
    if (!result.versionFields.isEmpty()) {
        h += QStringLiteral("<h2>Version Info</h2>");
        h += fieldTable(result.versionFields, nameA, nameB, colA, colB);
    }

    // Debug / PDB
    if (!result.pdbFields.isEmpty()) {
        h += QStringLiteral("<h2>Debug / PDB</h2>");
        h += fieldTable(result.pdbFields, nameA, nameB, colA, colB);
    }

    // TLS
    if (!result.tlsFields.isEmpty()) {
        h += QStringLiteral("<h2>TLS Callbacks</h2>");
        h += fieldTable(result.tlsFields, nameA, nameB, colA, colB);
    }

    // Resources
    if (!result.resourceFields.isEmpty()) {
        h += QStringLiteral("<h2>Resources</h2>");
        h += fieldTable(result.resourceFields, nameA, nameB, colA, colB);
    }

    // Signature
    if (!result.signatureFields.isEmpty()) {
        h += QStringLiteral("<h2>Authenticode</h2>");
        h += fieldTable(result.signatureFields, nameA, nameB, colA, colB);
    }

    // Imports
    if (!result.imports.isEmpty()) {
        h += QStringLiteral("<h2>Imports</h2>");
        for (const ModuleDiff &m : result.imports) {
            h += QStringLiteral("<p class='mod'>%1</p>").arg(esc(m.moduleName));
            if (!m.onlyInA.isEmpty()) {
                h += QStringLiteral("<p class='a only'>Only in %1:</p>").arg(esc(nameA));
                h += itemList(m.onlyInA, QStringLiteral("a"));
            }
            if (!m.onlyInB.isEmpty()) {
                h += QStringLiteral("<p class='b only'>Only in %1:</p>").arg(esc(nameB));
                h += itemList(m.onlyInB, QStringLiteral("b"));
            }
        }
    }

    // Exports
    if (!result.exportsOnlyInA.isEmpty() || !result.exportsOnlyInB.isEmpty()) {
        h += QStringLiteral("<h2>Exports</h2>");
        if (!result.exportsOnlyInA.isEmpty()) {
            h += QStringLiteral("<p class='a only'>Only in %1:</p>").arg(esc(nameA));
            h += itemList(result.exportsOnlyInA, QStringLiteral("a"));
        }
        if (!result.exportsOnlyInB.isEmpty()) {
            h += QStringLiteral("<p class='b only'>Only in %1:</p>").arg(esc(nameB));
            h += itemList(result.exportsOnlyInB, QStringLiteral("b"));
        }
    }

    // Findings
    if (!result.findingsOnlyInA.isEmpty() || !result.findingsOnlyInB.isEmpty()) {
        h += QStringLiteral("<h2>Findings</h2>");
        if (!result.findingsOnlyInA.isEmpty()) {
            h += QStringLiteral("<p class='a only'>Only in %1:</p>").arg(esc(nameA));
            h += findingList(result.findingsOnlyInA, QStringLiteral("a"), result.findingTitles);
        }
        if (!result.findingsOnlyInB.isEmpty()) {
            h += QStringLiteral("<p class='b only'>Only in %1:</p>").arg(esc(nameB));
            h += findingList(result.findingsOnlyInB, QStringLiteral("b"), result.findingTitles);
        }
    }

    if (total == 0) {
        h += QStringLiteral("<p><b>Files are identical</b> in all compared fields.</p>");
    }

    h += QStringLiteral("</body></html>");
    return h;
}

} // namespace PECompare
