#include "orderedmap.h"

void OrderedMap::insert(const QString &key, const QString &value) {
    if (!map.contains(key)) {
        keys.append(key); // Keep track of insertion order
    }
    map[key] = value;
}

QString OrderedMap::value(const QString &key) const {
    return map.value(key);
}

QList<QString> OrderedMap::orderedKeys() const {
    return keys;
}
