#ifndef ORDEREDMAP_H
#define ORDEREDMAP_H

#include <QMap>
#include <QList>
#include <QString>

class OrderedMap {
public:
    void insert(const QString& key, const QString& value);

    QString value(const QString& key) const;

    QList<QString> orderedKeys() const;

private:
    QMap<QString, QString> map; // Stores key-value pairs
    QList<QString> keys;        // Maintains insertion order of keys
};

#endif // ORDEREDMAP_H
