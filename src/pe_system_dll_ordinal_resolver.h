#ifndef PE_SYSTEM_DLL_ORDINAL_RESOLVER_H
#define PE_SYSTEM_DLL_ORDINAL_RESOLVER_H

#include <QString>

/**
 * Resolve an import-by-ordinal to its export name by reading the corresponding
 * system DLL (System32 or SysWOW64) and parsing its export directory.
 * Microsoft Learn markdown does not provide ordinal→name tables.
 */
QString resolveImportOrdinalToName(const QString &dllName, quint16 ordinal, bool analyzedPeIs64Bit);

#endif
