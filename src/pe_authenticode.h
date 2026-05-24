#ifndef PE_AUTHENTICODE_H
#define PE_AUTHENTICODE_H

#include <QByteArray>
#include <QString>

QString extractAuthenticodePublisher(const QByteArray &fileData, quint32 certTableOffset, quint32 certTableSize);

#endif // PE_AUTHENTICODE_H
