#ifndef IMPORT_API_HINT_STORE_H
#define IMPORT_API_HINT_STORE_H

#include <QHash>
#include <QVector>

#include "sdk_api_markdown_reader.h"

class ImportApiHintStore
{
public:
    static ImportApiHintStore &instance();

    void ensureLoaded() const;
    ImportApiHint hintForImport(const QString &moduleDll, const QString &functionName) const;

private:
    ImportApiHintStore() = default;
    void loadFromConfig() const;

    mutable bool m_loaded = false;
    mutable QVector<ImportApiHint> m_hints;
    mutable QHash<QString, int> m_indexByDllFunc;
};

#endif // IMPORT_API_HINT_STORE_H
