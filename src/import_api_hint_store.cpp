#include "import_api_hint_store.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QVector>
namespace {

QString hintKey(const QString &dll, const QString &function)
{
    QString normalized = dll.trimmed().toLower();
    if (!normalized.isEmpty() && !normalized.endsWith(QStringLiteral(".dll"))) {
        normalized += QStringLiteral(".dll");
    }
    return normalized + QLatin1Char('|') + function.trimmed().toLower();
}

QString findBundledHintsPath()
{
    const QStringList candidates = {
        QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("config/import_api_hints.json")),
        QDir::currentPath() + QStringLiteral("/config/import_api_hints.json"),
    };
    for (const QString &path : candidates) {
        if (QFile::exists(path)) {
            return path;
        }
    }
    return QString();
}

} // namespace

ImportApiHintStore &ImportApiHintStore::instance()
{
    static ImportApiHintStore store;
    return store;
}

void ImportApiHintStore::loadFromConfig() const
{
    m_hints.clear();
    m_indexByDllFunc.clear();

    const QString path = findBundledHintsPath();
    if (path.isEmpty()) {
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (!doc.isObject()) {
        return;
    }
    const QJsonArray hints = doc.object().value(QStringLiteral("hints")).toArray();
    for (const QJsonValue &value : hints) {
        const QJsonObject obj = value.toObject();
        ImportApiHint hint;
        hint.summary = obj.value(QStringLiteral("summary")).toString();
        hint.signature = obj.value(QStringLiteral("signature")).toString();
        hint.returns = obj.value(QStringLiteral("returns")).toString();
        hint.remarks = obj.value(QStringLiteral("remarks")).toString();
        hint.learnUrl = obj.value(QStringLiteral("learnUrl")).toString();
        hint.malapiUrl = obj.value(QStringLiteral("malapiUrl")).toString();
        const QString categories = obj.value(QStringLiteral("malapiCategories")).toString();
        if (!categories.isEmpty()) {
            const QString catLine = QStringLiteral("MalAPI categories: %1").arg(categories);
            if (hint.remarks.isEmpty()) {
                hint.remarks = catLine;
            } else if (!hint.remarks.contains(QStringLiteral("MalAPI categories"))) {
                hint.remarks += QStringLiteral("<br/>") + catLine;
            }
            for (const QString &cat : categories.split(QLatin1Char(','))) {
                const QString trimmed = cat.trimmed();
                if (!trimmed.isEmpty()) {
                    hint.malapiCategories.append(trimmed);
                }
            }
        }
        const QString dll = obj.value(QStringLiteral("dll")).toString();
        const QString function = obj.value(QStringLiteral("function")).toString();
        if (!hint.hasContent() || function.isEmpty()) {
            continue;
        }
        m_hints.append(hint);
        m_indexByDllFunc.insert(hintKey(dll, function), m_hints.size() - 1);
        m_indexByDllFunc.insert(hintKey(QString(), function), m_hints.size() - 1);
    }
}

void ImportApiHintStore::ensureLoaded() const
{
    if (m_loaded) {
        return;
    }
    m_loaded = true;
    loadFromConfig();
}

ImportApiHint ImportApiHintStore::hintForImport(const QString &moduleDll, const QString &functionName) const
{
    ensureLoaded();
    ImportApiHint empty;
    if (functionName.isEmpty()) {
        return empty;
    }
    const int idx = m_indexByDllFunc.value(hintKey(moduleDll, functionName),
                                           m_indexByDllFunc.value(hintKey(QString(), functionName), -1));
    if (idx < 0 || idx >= m_hints.size()) {
        return empty;
    }
    return m_hints.at(idx);
}
