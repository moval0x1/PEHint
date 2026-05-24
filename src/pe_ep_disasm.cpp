#include "pe_ep_disasm.h"

#include <QString>

namespace PEEpDisasm {

namespace {

bool readU8(const QByteArray &bytes, int offset, quint8 *out)
{
    if (offset < 0 || offset >= bytes.size()) {
        return false;
    }
    *out = static_cast<quint8>(bytes.at(offset));
    return true;
}

bool readU32(const QByteArray &bytes, int offset, quint32 *out)
{
    if (offset < 0 || offset + 4 > bytes.size()) {
        return false;
    }
    const auto *data = reinterpret_cast<const unsigned char *>(bytes.constData() + offset);
    *out = static_cast<quint32>(data[0]) | (static_cast<quint32>(data[1]) << 8)
           | (static_cast<quint32>(data[2]) << 16) | (static_cast<quint32>(data[3]) << 24);
    return true;
}

QString reg64(int index)
{
    static const char *kRegs[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                  "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    if (index >= 0 && index < 16) {
        return QString::fromLatin1(kRegs[index]);
    }
    return QStringLiteral("r?");
}

QString reg32(int index)
{
    static const char *kRegs[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    if (index >= 0 && index < 8) {
        return QString::fromLatin1(kRegs[index]);
    }
    return QStringLiteral("r?");
}

int decodeOne(bool is64Bit, const QByteArray &bytes, int offset, QString *lineOut, int *sizeOut)
{
    quint8 b0 = 0;
    if (!readU8(bytes, offset, &b0)) {
        return 0;
    }

    if (b0 == 0xCC) {
        *lineOut = QStringLiteral("int3");
        *sizeOut = 1;
        return 1;
    }
    if (b0 == 0xC3) {
        *lineOut = QStringLiteral("ret");
        *sizeOut = 1;
        return 1;
    }
    if (b0 == 0x90) {
        *lineOut = QStringLiteral("nop");
        *sizeOut = 1;
        return 1;
    }

    if (is64Bit) {
        if (b0 == 0x48 && offset + 3 < bytes.size()) {
            quint8 b1 = static_cast<quint8>(bytes.at(offset + 1));
            quint8 b2 = static_cast<quint8>(bytes.at(offset + 2));
            if (b1 == 0x83 && b2 == 0xEC && offset + 4 <= bytes.size()) {
                const quint8 imm = static_cast<quint8>(bytes.at(offset + 3));
                *lineOut = QStringLiteral("sub rsp, 0x%1").arg(imm, 2, 16, QChar('0'));
                *sizeOut = 4;
                return 4;
            }
            if (b1 == 0x89 && offset + 3 <= bytes.size()) {
                const int dst = (b2 >> 3) & 7;
                const int src = b2 & 7;
                *lineOut = QStringLiteral("mov %1, %2").arg(reg64(dst), reg64(src));
                *sizeOut = 3;
                return 3;
            }
            if (b1 == 0x8B && offset + 3 <= bytes.size()) {
                const int dst = (b2 >> 3) & 7;
                const int src = b2 & 7;
                *lineOut = QStringLiteral("mov %1, %2").arg(reg64(dst), reg64(src));
                *sizeOut = 3;
                return 3;
            }
            if (b1 == 0x31 && offset + 3 <= bytes.size()) {
                const int dst = (b2 >> 3) & 7;
                const int src = b2 & 7;
                *lineOut = QStringLiteral("xor %1, %2").arg(reg64(dst), reg64(src));
                *sizeOut = 3;
                return 3;
            }
            if (b1 == 0xFF && offset + 3 <= bytes.size()) {
                const int op = (b2 >> 3) & 7;
                const int reg = b2 & 7;
                if (op == 2) {
                    *lineOut = QStringLiteral("call %1").arg(reg64(reg));
                    *sizeOut = 3;
                    return 3;
                }
            }
        }
        if (b0 == 0xE8 && offset + 5 <= bytes.size()) {
            quint32 rel = 0;
            readU32(bytes, offset + 1, &rel);
            *lineOut = QStringLiteral("call +0x%1").arg(rel, 8, 16, QChar('0'));
            *sizeOut = 5;
            return 5;
        }
        if (b0 == 0xE9 && offset + 5 <= bytes.size()) {
            quint32 rel = 0;
            readU32(bytes, offset + 1, &rel);
            *lineOut = QStringLiteral("jmp +0x%1").arg(rel, 8, 16, QChar('0'));
            *sizeOut = 5;
            return 5;
        }
    } else {
        if (b0 == 0x83 && offset + 3 <= bytes.size()) {
            quint8 b1 = static_cast<quint8>(bytes.at(offset + 1));
            if ((b1 & 0xF8) == 0xE8 && offset + 3 <= bytes.size()) {
                const int reg = b1 & 7;
                const quint8 imm = static_cast<quint8>(bytes.at(offset + 2));
                *lineOut = QStringLiteral("sub %1, 0x%2").arg(reg32(reg)).arg(imm, 2, 16, QChar('0'));
                *sizeOut = 3;
                return 3;
            }
        }
        if (b0 == 0xE8 && offset + 5 <= bytes.size()) {
            quint32 rel = 0;
            readU32(bytes, offset + 1, &rel);
            *lineOut = QStringLiteral("call +0x%1").arg(rel, 8, 16, QChar('0'));
            *sizeOut = 5;
            return 5;
        }
    }

    *lineOut = QStringLiteral("db 0x%1").arg(b0, 2, 16, QChar('0'));
    *sizeOut = 1;
    return 1;
}

} // namespace

QStringList disassembleEntryPoint(bool is64Bit, const QByteArray &bytes, int maxInstructions)
{
    QStringList lines;
    int offset = 0;
    while (lines.size() < maxInstructions && offset < bytes.size()) {
        QString line;
        int size = 0;
        const int consumed = decodeOne(is64Bit, bytes, offset, &line, &size);
        if (consumed <= 0) {
            break;
        }
        lines.append(line);
        offset += consumed;
    }
    return lines;
}

} // namespace PEEpDisasm
