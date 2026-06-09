#ifndef PE_EP_DISASM_H
#define PE_EP_DISASM_H

#include <QByteArray>
#include <QStringList>

namespace PEEpDisasm {

constexpr int kDefaultMaxInstructions = 32;
constexpr int kDefaultEpByteSample = 64;

QStringList disassembleEntryPoint(bool is64Bit,
                                  const QByteArray &bytes,
                                  int maxInstructions = kDefaultMaxInstructions,
                                  quint32 baseRva = 0);

} // namespace PEEpDisasm

#endif // PE_EP_DISASM_H
