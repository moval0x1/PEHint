#ifndef SDK_API_MARKDOWN_READER_H
#define SDK_API_MARKDOWN_READER_H

#include <QMultiHash>
#include <QString>
#include <QStringList>

/**
 * Parsed API topic from local Microsoft Learn markdown (sdk-api nf-*.md or Console-Docs *.md).
 * Text fields (except learnUrl) contain trusted HTML fragments for the import hint panel.
 */
struct ImportApiHint {
    QString summary;
    QString signature;
    QStringList parameters;
    QString returns;
    QString remarks;
    QString learnUrl;

    bool hasContent() const
    {
        return !summary.isEmpty() || !signature.isEmpty() || !parameters.isEmpty() || !returns.isEmpty()
            || !remarks.isEmpty() || !learnUrl.isEmpty();
    }
};

/**
 * Read API topics from local clones of Microsoft documentation:
 * - MicrosoftDocs/sdk-api (docs/sdk-api-src/content): nf-*.md Win32 API reference
 * - MicrosoftDocs/Console-Docs (docs): *.md for console APIs (e.g. WriteConsoleW)
 *
 * Set PEHINT_SDK_API_CONTENT to the sdk-api "content" folder, and/or
 * PEHINT_WINDOWS_CONSOLE_DOCS to the Console-Docs "docs" folder.
 * Or place clones under third_party/ (see third_party/README.txt).
 *
 * Content is CC-BY-4.0; attribute Microsoft Learn when redistributing long excerpts.
 */
class SdkApiMarkdownReader
{
public:
    static SdkApiMarkdownReader &instance();

    /** Root containing subfolders like fileapi/, winuser/, each with nf-*.md files. */
    void setContentRoot(const QString &absolutePathOrEmpty);
    QString contentRoot() const;

    /** Root of Console-Docs "docs" folder (writeconsole.md, readconsole.md, …). */
    void setConsoleDocsRoot(const QString &absolutePathOrEmpty);
    QString consoleDocsRoot() const;

    /** Best-effort: build ImportApiHint from local markdown when repos are present. */
    ImportApiHint hintForImport(const QString &moduleDll, const QString &functionName) const;

    /** Probe common locations: env override, then third_party next to the executable (and parents for dev layouts). */
    static QString defaultContentRoot();
    static QString defaultConsoleDocsRoot();

private:
    SdkApiMarkdownReader() = default;

    void ensureIndex() const;
    void indexNfFilesUnder(const QString &root) const;
    void indexPlainMarkdownUnder(const QString &root) const;
    QStringList candidatePathsForFunction(const QString &functionName) const;
    static QString normalizeDll(const QString &dll);
    static bool yamlDllMatchesModule(const QString &yamlBlock, const QString &moduleDll);
    static bool yamlApiLocationMatches(const QString &yamlBlock, const QString &moduleDll);
    static bool yamlApiNameMatches(const QString &yamlBlock, const QString &functionName);
    bool yamlMatchesImportDll(const QString &yamlBlock, const QString &moduleDll) const;
    ImportApiHint parseMarkdownFile(const QString &absolutePath) const;
    QString learnUrlForFile(const QString &absolutePath) const;
    /** Convert a Learn markdown or HTML fragment into HTML for QTextEdit (local docs only). */
    static QString microsoftLearnSourceToDisplayHtml(const QString &s);
    static QString stripMarkdownForPlain(const QString &s);

    QString m_root;
    QString m_consoleDocsRoot;
    mutable bool m_indexBuilt = false;
    mutable QMultiHash<QString, QString> m_pathsByFunctionLower; // function key -> paths
};

#endif // SDK_API_MARKDOWN_READER_H
