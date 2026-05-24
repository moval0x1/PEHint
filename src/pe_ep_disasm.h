#ifndef PE_EP_DISASM_H
#define PE_EP_DISASM_H

#include <QByteArray>
#include <QStringList>

namespace PEEpDisasm {

QStringList disassembleEntryPoint(bool is64Bit, const QByteArray &bytes, int maxInstructions = 12);

} // namespace PEEpDisasm

#endif // PE_EP_DISASM_H
