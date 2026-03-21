#include "sdk_api_markdown_reader.h"

#include <QHash>
#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QLoggingCategory>
#include <QRegularExpression>
#include <QTextDocument>

namespace {

Q_LOGGING_CATEGORY(lcSdkApi, "pehint.sdk_api_docs", QtWarningMsg)

QString readFileUtf8(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return QString();
    }
    return QString::fromUtf8(f.readAll());
}

/** Extract first YAML value for key (single-line values). */
QString yamlValue(const QString &yaml, const QString &key)
{
    const QString prefix = key + QLatin1Char(':');
    for (const QString &line : yaml.split(QLatin1Char('\n'))) {
        const QString t = line.trimmed();
        if (t.startsWith(prefix)) {
            return t.mid(prefix.length()).trimmed();
        }
    }
    return QString();
}

QString extractMarkdownSection(const QString &body, const QString &startHeading, const QStringList &stopAtHeadings)
{
    const int start = body.indexOf(startHeading);
    if (start < 0) {
        return QString();
    }
    int contentStart = body.indexOf(QLatin1Char('\n'), start);
    if (contentStart < 0) {
        return QString();
    }
    ++contentStart;
    int end = body.size();
    for (const QString &h : stopAtHeadings) {
        const int p = body.indexOf(h, contentStart);
        if (p >= 0 && p < end) {
            end = p;
        }
    }
    return body.mid(contentStart, end - contentStart).trimmed();
}

/** Next "## " section at line start (Learn-style headings, not sdk-api ## -foo). */
QString extractLearnSection(const QString &body, const QString &sectionName)
{
    const QString startHeading = QStringLiteral("## ") + sectionName;
    const int start = body.indexOf(startHeading);
    if (start < 0) {
        return QString();
    }
    int contentStart = body.indexOf(QLatin1Char('\n'), start);
    if (contentStart < 0) {
        return QString();
    }
    ++contentStart;
    static const QRegularExpression nextSection(QStringLiteral(R"(\n## )"));
    const auto m = nextSection.match(body, contentStart);
    const int end = m.hasMatch() ? m.capturedStart() : body.size();
    return body.mid(contentStart, end - contentStart).trimmed();
}

bool bodyUsesSdkApiHeadings(const QString &body)
{
    return body.contains(QStringLiteral("## -parameters")) || body.contains(QStringLiteral("## -syntax"))
        || body.contains(QStringLiteral("## -description"));
}

QString alertLabel(const QString &tagUpper)
{
    static const QHash<QString, QString> labels = {
        {QStringLiteral("NOTE"), QStringLiteral("Note")},
        {QStringLiteral("TIP"), QStringLiteral("Tip")},
        {QStringLiteral("IMPORTANT"), QStringLiteral("Important")},
        {QStringLiteral("WARNING"), QStringLiteral("Warning")},
        {QStringLiteral("CAUTION"), QStringLiteral("Caution")},
    };
    return labels.value(tagUpper.toUpper(), tagUpper.toLower());
}

void normalizeLearnAlerts(QString &s)
{
    static const QRegularExpression alertBlock(QStringLiteral(R"((?:^|\n)\s*>\s*\[!(\w+)\]\s*(?:\r?\n)+)"),
        QRegularExpression::MultilineOption);
    static const QRegularExpression alertBare(QStringLiteral(R"((?:^|\n)\s*\[!(\w+)\]\s*(?:\r?\n)+)"),
        QRegularExpression::MultilineOption);
    for (;;) {
        auto m = alertBlock.match(s);
        if (m.hasMatch()) {
            const QString label = alertLabel(m.captured(1));
            s.replace(m.capturedStart(), m.capturedLength(),
                QStringLiteral("\n\n―― %1 ――\n").arg(label));
            continue;
        }
        m = alertBare.match(s);
        if (m.hasMatch()) {
            const QString label = alertLabel(m.captured(1));
            s.replace(m.capturedStart(), m.capturedLength(),
                QStringLiteral("\n\n―― %1 ――\n").arg(label));
            continue;
        }
        break;
    }
}

void stripIncludeDirectives(QString &s)
{
    s.replace(QRegularExpression(QStringLiteral(R"(\[!INCLUDE[^\]]*\])")), QString());
}

void expandMarkdownLinks(QString &s)
{
    static const QRegularExpression re(QStringLiteral(R"(\[([^\]]+)\]\(([^)]+)\))"));
    QString out;
    int last = 0;
    auto it = re.globalMatch(s);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        out += s.mid(last, m.capturedStart() - last);
        QString link = m.captured(2).trimmed();
        if (link.startsWith(QLatin1Char('/'))) {
            link = QStringLiteral("https://learn.microsoft.com/en-us") + link;
        }
        out += m.captured(1) + QStringLiteral(" (") + link + QLatin1Char(')');
        last = m.capturedEnd();
    }
    out += s.mid(last);
    s = out;
}

void expandMarkdownLinksToHtml(QString &s)
{
    static const QRegularExpression re(QStringLiteral(R"(\[([^\]]+)\]\(([^)]+)\))"));
    QString out;
    int last = 0;
    auto it = re.globalMatch(s);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        out += s.mid(last, m.capturedStart() - last);
        QString link = m.captured(2).trimmed();
        if (link.startsWith(QLatin1Char('/'))) {
            link = QStringLiteral("https://learn.microsoft.com/en-us") + link;
        }
        const QString text = m.captured(1).toHtmlEscaped();
        const QString href = link.toHtmlEscaped();
        out += QStringLiteral("<a href=\"%1\">%2</a>").arg(href, text);
        last = m.capturedEnd();
    }
    out += s.mid(last);
    s = out;
}

void fixRelativeHtmlHrefs(QString &s)
{
    s.replace(QStringLiteral("href=\"/"), QStringLiteral("href=\"https://learn.microsoft.com/en-us/"));
}

QString htmlFragmentToPlain(const QString &html)
{
    QTextDocument doc;
    doc.setHtml(QStringLiteral("<html><body>") + html + QStringLiteral("</body></html>"));
    return doc.toPlainText();
}

void resolveRelativeMarkdownLinks(QString &s)
{
    s.replace(QRegularExpression(QStringLiteral(R"(\]\((/[^)]+)\))")),
        QStringLiteral("](https://learn.microsoft.com/en-us\\1)"));
}

void preprocessMarkdownAlertsForQt(QString &s)
{
    const QRegularExpression::PatternOptions po = QRegularExpression::MultilineOption;
    s.replace(QRegularExpression(QStringLiteral(R"((?:^|\n)>\s*\[!NOTE\]\s*(?:\r?\n)+)"), po),
        QStringLiteral("\n\n> **Note:**\n> "));
    s.replace(QRegularExpression(QStringLiteral(R"((?:^|\n)\s*\[!NOTE\]\s*(?:\r?\n)+)"), po),
        QStringLiteral("\n\n> **Note:**\n"));
    s.replace(QRegularExpression(QStringLiteral(R"((?:^|\n)>\s*\[!TIP\]\s*(?:\r?\n)+)"), po),
        QStringLiteral("\n\n> **Tip:**\n> "));
    s.replace(QRegularExpression(QStringLiteral(R"((?:^|\n)>\s*\[!IMPORTANT\]\s*(?:\r?\n)+)"), po),
        QStringLiteral("\n\n> **Important:**\n> "));
    s.replace(QRegularExpression(QStringLiteral(R"((?:^|\n)>\s*\[!WARNING\]\s*(?:\r?\n)+)"), po),
        QStringLiteral("\n\n> **Warning:**\n> "));
    s.replace(QRegularExpression(QStringLiteral(R"((?:^|\n)>\s*\[!CAUTION\]\s*(?:\r?\n)+)"), po),
        QStringLiteral("\n\n> **Caution:**\n> "));
}

/**
 * Microsoft sdk-api HTML often mixes in Markdown-style **bold** and `code` inside HTML fragments.
 * QTextDocument HTML path does not interpret those; convert them before sanitize.
 */
void applyInlineMarkdownConventionsToHtml(QString &s)
{
    // Inline `code` first so ** inside backticks stays literal in <code>.
    {
        static const QRegularExpression codeRe(QStringLiteral(R"(`([^`]+)`)"));
        QString out;
        int last = 0;
        auto it = codeRe.globalMatch(s);
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            out += s.mid(last, m.capturedStart() - last);
            out += QStringLiteral("<code>") + QString(m.captured(1)).toHtmlEscaped() + QStringLiteral("</code>");
            last = m.capturedEnd();
        }
        out += s.mid(last);
        s = out;
    }
    {
        static const QRegularExpression boldRe(QStringLiteral(R"(\*\*([^*]+)\*\*)"));
        QString out;
        int last = 0;
        auto it = boldRe.globalMatch(s);
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            out += s.mid(last, m.capturedStart() - last);
            out += QStringLiteral("<strong>") + QString(m.captured(1)).toHtmlEscaped() + QStringLiteral("</strong>");
            last = m.capturedEnd();
        }
        out += s.mid(last);
        s = out;
    }
}

void sanitizeLearnHtml(QString &html)
{
    html.remove(QRegularExpression(QStringLiteral(R"(<script[^>]*>[\s\S]*?</script>)"),
        QRegularExpression::CaseInsensitiveOption));
    html.remove(QRegularExpression(QStringLiteral(R"(<style[^>]*>[\s\S]*?</style>)"),
        QRegularExpression::CaseInsensitiveOption));
    html.remove(QRegularExpression(QStringLiteral(R"(\s+on\w+\s*=\s*["'][^"']*["'])")));
    html.replace(QRegularExpression(QStringLiteral(R"(href\s*=\s*["']javascript:[^"']*["'])"), QRegularExpression::CaseInsensitiveOption),
        QStringLiteral("href=\"#\""));
    html.remove(QRegularExpression(QStringLiteral(R"(<iframe[\s\S]*?</iframe>)"), QRegularExpression::CaseInsensitiveOption));
}

void styleEmDashAlertHeaders(QString &s)
{
    static const QRegularExpression re(QStringLiteral(R"(――\s*(\w+)\s*――)"));
    s.replace(re, QStringLiteral(
        "<div style=\"border-left:4px solid #0066cc;padding:6px 10px;background:#f0f7fc;margin:8px 0;"
        "font-size:11px;\"><strong>\\1</strong></div>"));
}

QString extractQtHtmlBodyInner(const QString &fullHtml)
{
    const int bodyStart = fullHtml.indexOf(QStringLiteral("<body"), 0, Qt::CaseInsensitive);
    if (bodyStart < 0) {
        return fullHtml;
    }
    const int gt = fullHtml.indexOf(QLatin1Char('>'), bodyStart);
    if (gt < 0) {
        return fullHtml;
    }
    const int bodyEnd = fullHtml.lastIndexOf(QStringLiteral("</body>"), -1, Qt::CaseInsensitive);
    if (bodyEnd < 0) {
        return fullHtml.mid(gt + 1);
    }
    return fullHtml.mid(gt + 1, bodyEnd - gt - 1);
}

bool looksLikeEmbeddedHtml(const QString &t)
{
    if (!t.contains(QLatin1Char('<'))) {
        return false;
    }
    return t.contains(QStringLiteral("<table"), Qt::CaseInsensitive) || t.contains(QStringLiteral("<tr"), Qt::CaseInsensitive)
        || t.contains(QStringLiteral("<td"), Qt::CaseInsensitive) || t.contains(QStringLiteral("<th"), Qt::CaseInsensitive)
        || t.contains(QStringLiteral("<ul"), Qt::CaseInsensitive) || t.contains(QStringLiteral("<ol"), Qt::CaseInsensitive)
        || t.contains(QStringLiteral("<dl"), Qt::CaseInsensitive) || t.contains(QStringLiteral("<pre"), Qt::CaseInsensitive)
        || t.contains(QStringLiteral("<p>"), Qt::CaseInsensitive) || t.contains(QStringLiteral("<div"), Qt::CaseInsensitive)
        || t.contains(QStringLiteral("<br"), Qt::CaseInsensitive) || t.contains(QStringLiteral("<a "), Qt::CaseInsensitive)
        || t.contains(QStringLiteral("<i>"), Qt::CaseInsensitive) || t.contains(QStringLiteral("<b>"), Qt::CaseInsensitive)
        || t.contains(QStringLiteral("<strong>"), Qt::CaseInsensitive);
}

QString formatMicrosoftLearnPlain(const QString &s)
{
    if (s.isEmpty()) {
        return s;
    }
    QString t = s;
    normalizeLearnAlerts(t);
    stripIncludeDirectives(t);
    expandMarkdownLinks(t);

    if (t.contains(QLatin1Char('<'))) {
        fixRelativeHtmlHrefs(t);
        t = htmlFragmentToPlain(t);
        t.replace(QRegularExpression(QStringLiteral("\\n{4,}")), QStringLiteral("\n\n\n"));
    } else {
        t.replace(QRegularExpression(QStringLiteral(R"md(\[([^\]]+)\]\([^)]+\))md")), QStringLiteral("\\1"));
        t.replace(QStringLiteral("**"), QString());
        t.replace(QStringLiteral("`"), QString());
        t.replace(QRegularExpression(QStringLiteral("[ \\t]+")), QStringLiteral(" "));
        t.replace(QRegularExpression(QStringLiteral("\\n{3,}")), QStringLiteral("\n\n"));
    }

    t.replace(QRegularExpression(QStringLiteral("(?m)^>\\s*")), QString());
    return t.trimmed();
}

} // namespace

QString SdkApiMarkdownReader::microsoftLearnSourceToDisplayHtml(const QString &s)
{
    if (s.isEmpty()) {
        return s;
    }
    QString t = s;
    stripIncludeDirectives(t);
    if (t.size() > 600000) {
        t = t.left(600000) + QStringLiteral("…");
    }

    if (looksLikeEmbeddedHtml(t)) {
        normalizeLearnAlerts(t);
        expandMarkdownLinksToHtml(t);
        fixRelativeHtmlHrefs(t);
        applyInlineMarkdownConventionsToHtml(t);
        sanitizeLearnHtml(t);
        styleEmDashAlertHeaders(t);
        return QStringLiteral("<div class=\"learn-doc\">") + t + QStringLiteral("</div>");
    }

    preprocessMarkdownAlertsForQt(t);
    resolveRelativeMarkdownLinks(t);
    QTextDocument doc;
    doc.setMarkdown(t);
    QString inner = extractQtHtmlBodyInner(doc.toHtml());
    applyInlineMarkdownConventionsToHtml(inner);
    sanitizeLearnHtml(inner);
    return QStringLiteral("<div class=\"learn-doc\">") + inner + QStringLiteral("</div>");
}

SdkApiMarkdownReader &SdkApiMarkdownReader::instance()
{
    static SdkApiMarkdownReader s;
    return s;
}

void SdkApiMarkdownReader::setContentRoot(const QString &absolutePathOrEmpty)
{
    m_root = absolutePathOrEmpty;
    m_indexBuilt = false;
    m_pathsByFunctionLower.clear();
}

QString SdkApiMarkdownReader::contentRoot() const
{
    return m_root;
}

void SdkApiMarkdownReader::setConsoleDocsRoot(const QString &absolutePathOrEmpty)
{
    m_consoleDocsRoot = absolutePathOrEmpty;
    m_indexBuilt = false;
    m_pathsByFunctionLower.clear();
}

QString SdkApiMarkdownReader::consoleDocsRoot() const
{
    return m_consoleDocsRoot;
}

namespace {

QString findContentRootWalkingUp(const QString &startDir, const QStringList &tails)
{
    QDir dir(QDir(startDir).absolutePath());
    for (int depth = 0; depth < 12; ++depth) {
        for (const QString &tail : tails) {
            const QString c = dir.absoluteFilePath(tail);
            if (QDir(c).exists()) {
                return QDir(c).absolutePath();
            }
        }
        if (!dir.cdUp()) {
            break;
        }
    }
    return QString();
}

} // namespace

QString SdkApiMarkdownReader::defaultContentRoot()
{
    const QString env = qEnvironmentVariable("PEHINT_SDK_API_CONTENT");
    if (!env.isEmpty()) {
        const QDir d(env);
        if (d.exists()) {
            qCDebug(lcSdkApi) << "sdk-api content from PEHINT_SDK_API_CONTENT:" << d.absolutePath();
            return d.absolutePath();
        }
        qCWarning(lcSdkApi) << "PEHINT_SDK_API_CONTENT is set but not found:" << env;
    }

    if (QCoreApplication::instance()) {
        const QString fromExe = findContentRootWalkingUp(
            QCoreApplication::applicationDirPath(),
            {QStringLiteral("third_party/sdk-api/sdk-api-src/content"),
             QStringLiteral("third_party/sdk-api/docs/sdk-api-src/content")});
        if (!fromExe.isEmpty()) {
            qCDebug(lcSdkApi) << "sdk-api content (from exe dir walk):" << fromExe;
            return fromExe;
        }
    }
    {
        const QString fromCwd = findContentRootWalkingUp(
            QDir::currentPath(),
            {QStringLiteral("third_party/sdk-api/sdk-api-src/content"),
             QStringLiteral("third_party/sdk-api/docs/sdk-api-src/content")});
        if (!fromCwd.isEmpty()) {
            qCDebug(lcSdkApi) << "sdk-api content (from cwd walk):" << fromCwd;
            return fromCwd;
        }
    }

    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList relPaths = {
        QStringLiteral("sdk-api/docs/sdk-api-src/content"),
        QStringLiteral("sdk-api/sdk-api-src/content"),
        QStringLiteral("../third_party/sdk-api/docs/sdk-api-src/content"),
        QStringLiteral("../third_party/sdk-api/sdk-api-src/content"),
        QStringLiteral("../../third_party/sdk-api/docs/sdk-api-src/content"),
        QStringLiteral("../../third_party/sdk-api/sdk-api-src/content"),
        QStringLiteral("../../../third_party/sdk-api/docs/sdk-api-src/content"),
        QStringLiteral("../../../third_party/sdk-api/sdk-api-src/content"),
    };
    for (const QString &rel : relPaths) {
        const QString c = QDir(appDir).absoluteFilePath(rel);
        if (QDir(c).exists()) {
            qCDebug(lcSdkApi) << "sdk-api content (relative to exe):" << c;
            return QDir(c).absolutePath();
        }
    }
    qCDebug(lcSdkApi) << "sdk-api content folder not found; set PEHINT_SDK_API_CONTENT or clone under third_party/sdk-api";
    return QString();
}

QString SdkApiMarkdownReader::defaultConsoleDocsRoot()
{
    const QString env = qEnvironmentVariable("PEHINT_WINDOWS_CONSOLE_DOCS");
    if (!env.isEmpty()) {
        const QDir d(env);
        if (d.exists()) {
            qCDebug(lcSdkApi) << "Console-Docs from PEHINT_WINDOWS_CONSOLE_DOCS:" << d.absolutePath();
            return d.absolutePath();
        }
        qCWarning(lcSdkApi) << "PEHINT_WINDOWS_CONSOLE_DOCS is set but not found:" << env;
    }

    const QStringList tails = {QStringLiteral("third_party/console-docs/docs"),
                               QStringLiteral("third_party/Console-Docs/docs")};

    if (QCoreApplication::instance()) {
        const QString fromExe = findContentRootWalkingUp(QCoreApplication::applicationDirPath(), tails);
        if (!fromExe.isEmpty()) {
            qCDebug(lcSdkApi) << "Console-Docs (exe walk):" << fromExe;
            return fromExe;
        }
    }
    {
        const QString fromCwd = findContentRootWalkingUp(QDir::currentPath(), tails);
        if (!fromCwd.isEmpty()) {
            qCDebug(lcSdkApi) << "Console-Docs (cwd walk):" << fromCwd;
            return fromCwd;
        }
    }

    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList relPaths = {
        QStringLiteral("../third_party/console-docs/docs"),
        QStringLiteral("../third_party/Console-Docs/docs"),
        QStringLiteral("../../third_party/console-docs/docs"),
        QStringLiteral("../../third_party/Console-Docs/docs"),
    };
    for (const QString &rel : relPaths) {
        const QString c = QDir(appDir).absoluteFilePath(rel);
        if (QDir(c).exists()) {
            return QDir(c).absolutePath();
        }
    }
    qCDebug(lcSdkApi) << "Console-Docs folder not found; optional clone MicrosoftDocs/Console-Docs (docs/) or set PEHINT_WINDOWS_CONSOLE_DOCS";
    return QString();
}

QString SdkApiMarkdownReader::normalizeDll(const QString &dll)
{
    QString s = dll.trimmed().toLower();
    if (!s.endsWith(QStringLiteral(".dll"))) {
        s += QStringLiteral(".dll");
    }
    return s;
}

bool SdkApiMarkdownReader::yamlDllMatchesModule(const QString &yamlBlock, const QString &moduleDll)
{
    if (moduleDll.trimmed().isEmpty()) {
        return true;
    }
    const QString want = normalizeDll(moduleDll);
    const QString wantBase = want.section(QLatin1Char('.'), 0, 0);

    bool sawReqDll = false;
    for (const QString &line : yamlBlock.split(QLatin1Char('\n'))) {
        const QString t = line.trimmed();
        if (!t.startsWith(QStringLiteral("req.dll:"))) {
            continue;
        }
        sawReqDll = true;
        const QString rest = t.mid(QStringLiteral("req.dll:").length()).trimmed();
        const QString v = normalizeDll(rest);
        if (v == want) {
            return true;
        }
        const QString vBase = v.section(QLatin1Char('.'), 0, 0);
        if (!vBase.isEmpty() && vBase.compare(wantBase, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return !sawReqDll;
}

bool SdkApiMarkdownReader::yamlApiLocationMatches(const QString &yamlBlock, const QString &moduleDll)
{
    if (moduleDll.trimmed().isEmpty()) {
        return true;
    }
    const QString want = normalizeDll(moduleDll);
    const QString wantBase = want.section(QLatin1Char('.'), 0, 0);

    bool inLoc = false;
    bool sawAny = false;
    for (const QString &line : yamlBlock.split(QLatin1Char('\n'))) {
        const QString t = line.trimmed();
        if (t == QStringLiteral("api_location:")) {
            inLoc = true;
            continue;
        }
        if (inLoc) {
            if (t.startsWith(QStringLiteral("- "))) {
                sawAny = true;
                const QString item = t.mid(2).trimmed();
                const QString v = normalizeDll(item);
                if (v == want) {
                    return true;
                }
                const QString vBase = v.section(QLatin1Char('.'), 0, 0);
                if (!vBase.isEmpty() && vBase.compare(wantBase, Qt::CaseInsensitive) == 0) {
                    return true;
                }
            } else if (t.contains(QLatin1Char(':')) && !t.startsWith(QLatin1Char('-'))) {
                inLoc = false;
            }
        }
    }
    return !sawAny;
}

bool SdkApiMarkdownReader::yamlApiNameMatches(const QString &yamlBlock, const QString &functionName)
{
    const QString want = functionName.trimmed();
    if (want.isEmpty()) {
        return true;
    }
    if (!yamlBlock.contains(QStringLiteral("api_name:"))) {
        return true;
    }

    bool inNames = false;
    for (const QString &line : yamlBlock.split(QLatin1Char('\n'))) {
        const QString t = line.trimmed();
        if (t == QStringLiteral("api_name:")) {
            inNames = true;
            continue;
        }
        if (inNames) {
            if (t.startsWith(QStringLiteral("- "))) {
                const QString v = t.mid(2).trimmed();
                if (v.compare(want, Qt::CaseInsensitive) == 0) {
                    return true;
                }
            } else if (t.contains(QLatin1Char(':')) && !t.startsWith(QLatin1Char('-'))) {
                break;
            }
        }
    }
    return false;
}

bool SdkApiMarkdownReader::yamlMatchesImportDll(const QString &yamlBlock, const QString &moduleDll) const
{
    if (yamlBlock.contains(QStringLiteral("req.dll:"))) {
        return yamlDllMatchesModule(yamlBlock, moduleDll);
    }
    if (yamlBlock.contains(QStringLiteral("api_location:"))) {
        return yamlApiLocationMatches(yamlBlock, moduleDll);
    }
    return true;
}

void SdkApiMarkdownReader::indexNfFilesUnder(const QString &root) const
{
    static const QRegularExpression fileNameRe(QStringLiteral(R"fn(^nf-.+-(.+)\.md$)fn"),
        QRegularExpression::CaseInsensitiveOption);

    QDirIterator it(root, QStringList() << QStringLiteral("*.md"), QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString path = it.next();
        const QString base = QFileInfo(path).fileName();
        const auto m = fileNameRe.match(base);
        if (!m.hasMatch()) {
            continue;
        }
        const QString funcLower = m.captured(1).toLower();
        m_pathsByFunctionLower.insert(funcLower, path);
    }
}

void SdkApiMarkdownReader::indexPlainMarkdownUnder(const QString &root) const
{
    QDirIterator it(root, QStringList() << QStringLiteral("*.md"), QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString path = it.next();
        const QString base = QFileInfo(path).fileName();
        if (base.compare(QStringLiteral("index.md"), Qt::CaseInsensitive) == 0) {
            continue;
        }
        if (base.startsWith(QStringLiteral("nf-"), Qt::CaseInsensitive)) {
            continue;
        }
        const QString stem = QFileInfo(path).completeBaseName().toLower();
        if (!stem.isEmpty()) {
            m_pathsByFunctionLower.insert(stem, path);
        }
    }
}

void SdkApiMarkdownReader::ensureIndex() const
{
    if (m_indexBuilt) {
        return;
    }
    m_pathsByFunctionLower.clear();
    if (!m_root.isEmpty() && QDir(m_root).exists()) {
        indexNfFilesUnder(m_root);
    }
    if (!m_consoleDocsRoot.isEmpty() && QDir(m_consoleDocsRoot).exists()) {
        indexPlainMarkdownUnder(m_consoleDocsRoot);
    }
    m_indexBuilt = true;
    qCDebug(lcSdkApi) << "Microsoft doc index entries:" << m_pathsByFunctionLower.size()
                      << "sdkRoot=" << m_root << "consoleDocs=" << m_consoleDocsRoot;
}

QStringList SdkApiMarkdownReader::candidatePathsForFunction(const QString &functionName) const
{
    ensureIndex();
    QStringList keys;
    const QString f = functionName.toLower();
    keys.append(f);
    if (f.size() >= 2 && (f.endsWith(QLatin1Char('w')) || f.endsWith(QLatin1Char('a')))) {
        keys.append(f.left(f.size() - 1));
    }

    QStringList paths;
    for (const QString &k : keys) {
        paths.append(m_pathsByFunctionLower.values(k));
    }

    QStringList seen;
    QStringList uniq;
    for (const QString &p : paths) {
        if (!seen.contains(p)) {
            seen.append(p);
            uniq.append(p);
        }
    }
    return uniq;
}

ImportApiHint SdkApiMarkdownReader::parseMarkdownFile(const QString &absolutePath) const
{
    ImportApiHint h;
    const QString raw = readFileUtf8(absolutePath);
    if (raw.isEmpty()) {
        return h;
    }

    int fmEnd = raw.indexOf(QStringLiteral("\n---\n"), 4);
    if (!raw.startsWith(QStringLiteral("---\n")) || fmEnd < 0) {
        return h;
    }
    const QString yaml = raw.mid(4, fmEnd - 4);
    const QString body = raw.mid(fmEnd + 5);

    QString desc = yamlValue(yaml, QStringLiteral("description"));
    desc.replace(QStringLiteral("\\_"), QStringLiteral("_"));
    if (!desc.isEmpty()) {
        h.summary = microsoftLearnSourceToDisplayHtml(desc);
    }

    const bool sdkStyle = bodyUsesSdkApiHeadings(body);

    if (sdkStyle) {
        const QString descSection = extractMarkdownSection(
            body,
            QStringLiteral("## -description"),
            {QStringLiteral("## -parameters"), QStringLiteral("## -syntax"), QStringLiteral("## -returns"),
             QStringLiteral("## -remarks")});
        if (!descSection.isEmpty()) {
            const QString firstChunk = descSection.split(QStringLiteral("\n\n")).first().trimmed();
            if (!firstChunk.isEmpty()) {
                h.summary = microsoftLearnSourceToDisplayHtml(firstChunk);
            }
        }

        const QString syntaxSection = extractMarkdownSection(
            body,
            QStringLiteral("## -syntax"),
            {QStringLiteral("## -parameters"), QStringLiteral("## -description"), QStringLiteral("## -returns")});
        if (!syntaxSection.isEmpty()) {
            h.signature = microsoftLearnSourceToDisplayHtml(syntaxSection);
        }

        const QString paramsSection = extractMarkdownSection(
            body,
            QStringLiteral("## -parameters"),
            {QStringLiteral("## -returns"), QStringLiteral("## -remarks"), QStringLiteral("## -requirements"),
             QStringLiteral("## -see-also")});
        if (!paramsSection.isEmpty()) {
            static const QRegularExpression paramBlock(QStringLiteral(R"re(###\s+-param\s+([^\n]+))re"));
            QList<QRegularExpressionMatch> paramMatches;
            {
                auto it = paramBlock.globalMatch(paramsSection);
                while (it.hasNext()) {
                    paramMatches.append(it.next());
                }
            }
            for (int i = 0; i < paramMatches.size(); ++i) {
                const QRegularExpressionMatch &m = paramMatches[i];
                const QString line = m.captured(1).trimmed();
                const int blockStart = m.capturedEnd();
                const int blockEnd = (i + 1 < paramMatches.size()) ? paramMatches[i + 1].capturedStart() : paramsSection.size();
                QString block = paramsSection.mid(blockStart, blockEnd - blockStart).trimmed();
                const QString fragment = QStringLiteral("**") + line + QStringLiteral("**\n\n") + block;
                QString html = microsoftLearnSourceToDisplayHtml(fragment);
                if (html.size() > 80000) {
                    html = html.left(79997) + QStringLiteral("…");
                }
                h.parameters.append(QStringLiteral("<div class=\"param-item\">") + html + QStringLiteral("</div>"));
            }
            if (h.parameters.isEmpty()) {
                const QString fallback = microsoftLearnSourceToDisplayHtml(paramsSection);
                if (!fallback.isEmpty()) {
                    h.parameters.append(fallback);
                }
            }
        }

        const QString retSection = extractMarkdownSection(
            body,
            QStringLiteral("## -returns"),
            {QStringLiteral("## -remarks"), QStringLiteral("## -requirements"), QStringLiteral("## -see-also"),
             QStringLiteral("## -")});
        if (!retSection.isEmpty()) {
            h.returns = microsoftLearnSourceToDisplayHtml(retSection);
        }

        const QString remSection = extractMarkdownSection(
            body,
            QStringLiteral("## -remarks"),
            {QStringLiteral("## -requirements"), QStringLiteral("## -see-also"), QStringLiteral("## -")});
        if (!remSection.isEmpty()) {
            h.remarks = microsoftLearnSourceToDisplayHtml(remSection);
        }
    } else {
        // Learn-style (e.g. Console-Docs): ## Syntax, ## Parameters, …
        const QString syn = extractLearnSection(body, QStringLiteral("Syntax"));
        if (!syn.isEmpty()) {
            h.signature = microsoftLearnSourceToDisplayHtml(syn);
        }
        const QString params = extractLearnSection(body, QStringLiteral("Parameters"));
        if (!params.isEmpty()) {
            h.parameters.append(microsoftLearnSourceToDisplayHtml(params));
        }
        QString ret = extractLearnSection(body, QStringLiteral("Return value"));
        if (ret.isEmpty()) {
            ret = extractLearnSection(body, QStringLiteral("Return Value"));
        }
        if (!ret.isEmpty()) {
            h.returns = microsoftLearnSourceToDisplayHtml(ret);
        }
        const QString rem = extractLearnSection(body, QStringLiteral("Remarks"));
        if (!rem.isEmpty()) {
            h.remarks = microsoftLearnSourceToDisplayHtml(rem);
        }
    }

    h.learnUrl = learnUrlForFile(absolutePath);

    return h;
}

QString SdkApiMarkdownReader::learnUrlForFile(const QString &absolutePath) const
{
    const QString abs = QFileInfo(absolutePath).absoluteFilePath();
    if (!m_root.isEmpty()) {
        const QString sdkRoot = QDir(m_root).absolutePath();
        if (abs.startsWith(sdkRoot, Qt::CaseInsensitive)) {
            const QString rel = QDir(m_root).relativeFilePath(abs).replace(QLatin1Char('\\'), QLatin1Char('/'));
            if (!rel.isEmpty() && !rel.startsWith(QLatin1String(".."))) {
                QString p = rel;
                if (p.endsWith(QStringLiteral(".md"), Qt::CaseInsensitive)) {
                    p.chop(3);
                }
                return QStringLiteral("https://learn.microsoft.com/en-us/windows/win32/api/") + p;
            }
        }
    }
    if (!m_consoleDocsRoot.isEmpty()) {
        const QString cr = QDir(m_consoleDocsRoot).absolutePath();
        if (abs.startsWith(cr, Qt::CaseInsensitive)) {
            const QString stem = QFileInfo(abs).completeBaseName();
            return QStringLiteral("https://learn.microsoft.com/en-us/windows/console/") + stem.toLower();
        }
    }
    return QString();
}

QString SdkApiMarkdownReader::stripMarkdownForPlain(const QString &s)
{
    return formatMicrosoftLearnPlain(s);
}

ImportApiHint SdkApiMarkdownReader::hintForImport(const QString &moduleDll, const QString &functionName) const
{
    ImportApiHint empty;
    if (functionName.isEmpty()) {
        return empty;
    }
    if (m_root.isEmpty() && m_consoleDocsRoot.isEmpty()) {
        return empty;
    }

    const QStringList paths = candidatePathsForFunction(functionName);
    if (paths.isEmpty()) {
        return empty;
    }

    QStringList ordered;
    const QString sdkAbs = m_root.isEmpty() ? QString() : QDir(m_root).absolutePath();
    const QString consoleAbs = m_consoleDocsRoot.isEmpty() ? QString() : QDir(m_consoleDocsRoot).absolutePath();
    for (const QString &p : paths) {
        if (!sdkAbs.isEmpty() && p.startsWith(sdkAbs, Qt::CaseInsensitive)) {
            ordered.append(p);
        }
    }
    for (const QString &p : paths) {
        if (!ordered.contains(p)) {
            ordered.append(p);
        }
    }

    auto rankPath = [&](const QString &p) -> int {
        const QString raw = readFileUtf8(p);
        const int fmEnd = raw.indexOf(QStringLiteral("\n---\n"), 4);
        if (!raw.startsWith(QStringLiteral("---\n")) || fmEnd < 0) {
            return -1;
        }
        const QString yaml = raw.mid(4, fmEnd - 4);
        if (!yamlMatchesImportDll(yaml, moduleDll)) {
            return -1;
        }
        int score = 0;
        if (yamlApiNameMatches(yaml, functionName)) {
            score += 10;
        }
        if (!sdkAbs.isEmpty() && p.startsWith(sdkAbs, Qt::CaseInsensitive)) {
            score += 2;
        }
        return score;
    };

    QString chosen;
    int best = -1;
    for (const QString &p : ordered) {
        const int s = rankPath(p);
        if (s > best) {
            best = s;
            chosen = p;
        }
    }
    if (best < 0) {
        chosen = ordered.first();
    }

    ImportApiHint h = parseMarkdownFile(chosen);
    const QString ccLine = QStringLiteral(
        "<p style=\"margin-top:10px;color:#666;font-size:10px;\">Text from a local Microsoft documentation clone. "
        "Licensed under CC-BY; see the Documentation link for the official topic.</p>");
    if (!h.summary.isEmpty() && h.remarks.isEmpty()) {
        h.remarks = ccLine;
    } else if (!h.summary.isEmpty()) {
        h.remarks += ccLine;
    }
    return h;
}
