#include "pe_ep_disasm.h"

#include <QString>

namespace PEEpDisasm {

namespace {

constexpr int kMaxInstrBytes = 15;

// ---------------------------------------------------------------------------
// Low-level byte readers
// ---------------------------------------------------------------------------

bool readU8At(const QByteArray &bytes, int offset, quint8 *out)
{
    if (offset < 0 || offset >= bytes.size()) {
        return false;
    }
    *out = static_cast<quint8>(bytes.at(offset));
    return true;
}

bool readU16At(const QByteArray &bytes, int offset, quint16 *out)
{
    if (offset < 0 || offset + 2 > bytes.size()) {
        return false;
    }
    const auto *data = reinterpret_cast<const unsigned char *>(bytes.constData() + offset);
    *out = static_cast<quint16>(data[0]) | (static_cast<quint16>(data[1]) << 8);
    return true;
}

bool readU32At(const QByteArray &bytes, int offset, quint32 *out)
{
    if (offset < 0 || offset + 4 > bytes.size()) {
        return false;
    }
    const auto *data = reinterpret_cast<const unsigned char *>(bytes.constData() + offset);
    *out = static_cast<quint32>(data[0]) | (static_cast<quint32>(data[1]) << 8)
           | (static_cast<quint32>(data[2]) << 16) | (static_cast<quint32>(data[3]) << 24);
    return true;
}

bool readS32At(const QByteArray &bytes, int offset, qint32 *out)
{
    quint32 raw = 0;
    if (!readU32At(bytes, offset, &raw)) {
        return false;
    }
    *out = static_cast<qint32>(raw);
    return true;
}

// ---------------------------------------------------------------------------
// Register / formatting helpers
// ---------------------------------------------------------------------------

QString reg64Name(int index)
{
    static const char *kRegs[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                  "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    if (index >= 0 && index < 16) {
        return QString::fromLatin1(kRegs[index]);
    }
    return QStringLiteral("r?");
}

QString reg32Name(int index)
{
    static const char *kRegs[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    if (index >= 0 && index < 8) {
        return QString::fromLatin1(kRegs[index]);
    }
    return QStringLiteral("r?");
}

QString reg16Name(int index)
{
    static const char *kRegs[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    if (index >= 0 && index < 8) {
        return QString::fromLatin1(kRegs[index]);
    }
    return QStringLiteral("r?");
}

QString reg8Name(int index, bool high)
{
    if (high) {
        static const char *kHigh[] = {"ah", "ch", "dh", "bh"};
        if (index >= 0 && index < 4) {
            return QString::fromLatin1(kHigh[index]);
        }
        return QStringLiteral("r8?");
    }
    static const char *kLow[] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
    if (index >= 0 && index < 8) {
        return QString::fromLatin1(kLow[index]);
    }
    return QStringLiteral("r8?");
}

QString gpRegName(int index, bool is64Bit, bool rexW, bool opSize16)
{
    if (is64Bit && rexW) {
        return reg64Name(index);
    }
    if (opSize16) {
        return reg16Name(index & 7);
    }
    return reg32Name(index & 7);
}

QString formatImmHex(quint64 value, int minDigits = 1)
{
    return QStringLiteral("0x%1").arg(value, minDigits, 16, QChar('0'));
}

QString formatSignedDisp(qint64 value)
{
    if (value < 0) {
        return QStringLiteral("-0x%1").arg(static_cast<quint64>(-value), 0, 16);
    }
    return QStringLiteral("+0x%1").arg(static_cast<quint64>(value), 0, 16);
}

QString formatRelTarget(int instrStart, int instrSize, qint64 rel)
{
    const qint64 target = static_cast<qint64>(instrStart) + instrSize + rel;
    if (target < 0) {
        return QStringLiteral("-0x%1").arg(static_cast<quint64>(-target), 0, 16);
    }
    return QStringLiteral("+0x%1").arg(static_cast<quint64>(target), 0, 16);
}

QString jccMnemonic(int condition, bool shortForm)
{
    static const char *kNames[] = {"jo",   "jno",  "jb",   "jae",  "je",   "jne",  "jbe",  "ja",
                                   "js",   "jns",  "jp",   "jnp",  "jl",   "jge",  "jle",  "jg"};
    if (condition >= 0 && condition < 16) {
        Q_UNUSED(shortForm);
        return QString::fromLatin1(kNames[condition]);
    }
    return QStringLiteral("j?");
}

QString aluImmMnemonic(int op)
{
    static const char *kOps[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
    if (op >= 0 && op < 8) {
        return QString::fromLatin1(kOps[op]);
    }
    return QStringLiteral("alu");
}

QString formatHexBytes(const QByteArray &bytes)
{
    QStringList parts;
    parts.reserve(bytes.size());
    for (char byte : bytes) {
        parts.append(QStringLiteral("%1").arg(static_cast<quint8>(byte), 2, 16, QChar('0')).toUpper());
    }
    return parts.join(QLatin1Char(' '));
}

QString formatLine(quint32 baseRva, int instrStart, const QByteArray &instrBytes, const QString &text)
{
    if (baseRva == 0) {
        return text;
    }
    const quint32 addr = baseRva + static_cast<quint32>(instrStart);
    return QStringLiteral("%1: %2    %3")
        .arg(addr, 8, 16, QChar('0'))
        .arg(formatHexBytes(instrBytes))
        .arg(text);
}

// ---------------------------------------------------------------------------
// Instruction decoder
// ---------------------------------------------------------------------------

class InstructionDecoder
{
public:
    InstructionDecoder(bool is64Bit, const QByteArray &bytes, int offset)
        : m_is64Bit(is64Bit)
        , m_bytes(bytes)
        , m_start(offset)
        , m_pos(offset)
    {
    }

    bool decode(QString *textOut, int *sizeOut)
    {
        m_start = m_pos;
        m_rex = 0;
        m_hasRex = false;
        m_has66 = false;
        m_hasF2 = false;
        m_hasF3 = false;
        m_instrBytes.clear();

        if (m_pos >= m_bytes.size()) {
            return false;
        }

        consumePrefixes();

        quint8 opcode = 0;
        if (!take(&opcode)) {
            return false;
        }

        QString text;
        if (tryDecodeOpcode(opcode, &text)) {
            *textOut = text;
            *sizeOut = m_pos - m_start;
            return true;
        }

        // Fallback: single-byte db
        m_pos = m_start + 1;
        m_instrBytes = m_bytes.mid(m_start, 1);
        *textOut = QStringLiteral("db 0x%1")
                       .arg(static_cast<quint8>(m_bytes.at(m_start)), 2, 16, QChar('0'));
        *sizeOut = 1;
        return true;
    }

    QByteArray instructionBytes() const { return m_instrBytes; }
    int instructionStart() const { return m_start; }

private:
    bool m_is64Bit;
    const QByteArray &m_bytes;
    int m_start;
    int m_pos;

    quint8 m_rex = 0;
    bool m_hasRex = false;
    bool m_has66 = false;
    bool m_hasF2 = false;
    bool m_hasF3 = false;

    QByteArray m_instrBytes;

    bool rexW() const { return m_hasRex && (m_rex & 0x08); }
    bool rexR() const { return m_hasRex && (m_rex & 0x04); }
    bool rexX() const { return m_hasRex && (m_rex & 0x02); }
    bool rexB() const { return m_hasRex && (m_rex & 0x01); }

    int extendReg(int base3) const { return base3 | (rexR() ? 8 : 0); }
    int extendRm(int base3) const { return base3 | (rexB() ? 8 : 0); }

    void syncBytes()
    {
        const int len = m_pos - m_start;
        if (len > 0 && len <= kMaxInstrBytes) {
            m_instrBytes = m_bytes.mid(m_start, len);
        }
    }

    bool take(quint8 *out)
    {
        if (!readU8At(m_bytes, m_pos, out)) {
            return false;
        }
        ++m_pos;
        syncBytes();
        return true;
    }

    bool takeU16(quint16 *out)
    {
        if (!readU16At(m_bytes, m_pos, out)) {
            return false;
        }
        m_pos += 2;
        syncBytes();
        return true;
    }

    bool takeU32(quint32 *out)
    {
        if (!readU32At(m_bytes, m_pos, out)) {
            return false;
        }
        m_pos += 4;
        syncBytes();
        return true;
    }

    bool takeS32(qint32 *out)
    {
        if (!readS32At(m_bytes, m_pos, out)) {
            return false;
        }
        m_pos += 4;
        syncBytes();
        return true;
    }

    void consumePrefixes()
    {
        while (m_pos < m_bytes.size()) {
            quint8 b = static_cast<quint8>(m_bytes.at(m_pos));
            if (m_is64Bit && b >= 0x40 && b <= 0x4F) {
                m_rex = b;
                m_hasRex = true;
                ++m_pos;
                syncBytes();
                continue;
            }
            if (b == 0x66) {
                m_has66 = true;
                ++m_pos;
                syncBytes();
                continue;
            }
            if (b == 0xF2) {
                m_hasF2 = true;
                ++m_pos;
                syncBytes();
                continue;
            }
            if (b == 0xF3) {
                m_hasF3 = true;
                ++m_pos;
                syncBytes();
                continue;
            }
            break;
        }
    }

    struct ModRMResult
    {
        bool ok = false;
        int reg = 0;
        int rm = 0;
        int mod = 0;
        bool isReg = false;
        QString mem;
        int totalExtra = 0; // bytes consumed after ModRM byte position
    };

    bool decodeModRM(int modrmPos, ModRMResult *result) const
    {
        quint8 modrm = 0;
        if (!readU8At(m_bytes, modrmPos, &modrm)) {
            return false;
        }

        result->mod = (modrm >> 6) & 0x3;
        result->reg = extendReg((modrm >> 3) & 0x7);
        result->rm = extendRm(modrm & 0x7);
        result->isReg = (result->mod == 3);
        result->totalExtra = 0;

        if (result->isReg) {
            result->ok = true;
            return true;
        }

        int cursor = modrmPos + 1;

        if (result->rm == 4) {
            quint8 sib = 0;
            if (!readU8At(m_bytes, cursor, &sib)) {
                return false;
            }
            const int scale = (sib >> 6) & 0x3;
            const int index = ((sib >> 3) & 0x7) | (rexX() ? 8 : 0);
            const int base = (sib & 0x7) | (rexB() ? 8 : 0);
            ++cursor;

            if (index != 4) {
                return false; // complex indexed SIB
            }
            if (scale != 0) {
                return false;
            }

            if (base == 5 && result->mod == 0) {
                quint32 disp32 = 0;
                if (!readU32At(m_bytes, cursor, &disp32)) {
                    return false;
                }
                cursor += 4;
                result->mem = QStringLiteral("[0x%1]").arg(disp32, 0, 16);
                result->totalExtra = cursor - modrmPos - 1;
                result->ok = true;
                return true;
            }

            result->totalExtra = cursor - modrmPos - 1;
            if (result->mod == 0) {
                result->mem = QStringLiteral("[%1]").arg(gpRegName(base, m_is64Bit, false, m_has66));
            } else if (result->mod == 1) {
                quint8 disp8 = 0;
                if (!readU8At(m_bytes, cursor, &disp8)) {
                    return false;
                }
                ++cursor;
                result->totalExtra = cursor - modrmPos - 1;
                const qint8 sd = static_cast<qint8>(disp8);
                result->mem = QStringLiteral("[%1%2]")
                                  .arg(gpRegName(base, m_is64Bit, false, m_has66), formatSignedDisp(sd));
            } else if (result->mod == 2) {
                qint32 disp32 = 0;
                if (!readS32At(m_bytes, cursor, &disp32)) {
                    return false;
                }
                cursor += 4;
                result->totalExtra = cursor - modrmPos - 1;
                result->mem = QStringLiteral("[%1%2]")
                                  .arg(gpRegName(base, m_is64Bit, false, m_has66), formatSignedDisp(disp32));
            } else {
                return false;
            }
            result->ok = true;
            return true;
        }

        if (result->mod == 0 && result->rm == 5) {
            if (m_is64Bit) {
                qint32 disp32 = 0;
                if (!readS32At(m_bytes, cursor, &disp32)) {
                    return false;
                }
                cursor += 4;
                result->mem = QStringLiteral("[rip%1]").arg(formatSignedDisp(disp32));
            } else {
                quint32 disp32 = 0;
                if (!readU32At(m_bytes, cursor, &disp32)) {
                    return false;
                }
                cursor += 4;
                result->mem = QStringLiteral("[0x%1]").arg(disp32, 0, 16);
            }
            result->totalExtra = cursor - modrmPos - 1;
            result->ok = true;
            return true;
        }

        if (result->mod == 0) {
            result->mem = QStringLiteral("[%1]").arg(gpRegName(result->rm, m_is64Bit, false, m_has66));
            result->ok = true;
            return true;
        }

        if (result->mod == 1) {
            quint8 disp8 = 0;
            if (!readU8At(m_bytes, cursor, &disp8)) {
                return false;
            }
            ++cursor;
            result->totalExtra = 1;
            const qint8 sd = static_cast<qint8>(disp8);
            result->mem = QStringLiteral("[%1%2]")
                              .arg(gpRegName(result->rm, m_is64Bit, false, m_has66), formatSignedDisp(sd));
            result->ok = true;
            return true;
        }

        if (result->mod == 2) {
            qint32 disp32 = 0;
            if (!readS32At(m_bytes, cursor, &disp32)) {
                return false;
            }
            result->totalExtra = 4;
            result->mem = QStringLiteral("[%1%2]")
                              .arg(gpRegName(result->rm, m_is64Bit, false, m_has66), formatSignedDisp(disp32));
            result->ok = true;
            return true;
        }

        return false;
    }

    bool decodeModRMOperand(ModRMResult *result)
    {
        const int modrmPos = m_pos;
        quint8 modrm = 0;
        if (!take(&modrm)) {
            return false;
        }
        if (!decodeModRM(modrmPos, result)) {
            return false;
        }
        m_pos = modrmPos + 1 + result->totalExtra;
        syncBytes();
        return true;
    }

    bool tryDecodeOpcode(quint8 opcode, QString *textOut)
    {
        // Single-byte opcodes without ModRM
        if (opcode == 0xCC) {
            *textOut = QStringLiteral("int3");
            return true;
        }
        if (opcode == 0xC3) {
            *textOut = QStringLiteral("ret");
            return true;
        }
        if (opcode == 0xC2) {
            quint16 imm16 = 0;
            if (!takeU16(&imm16)) {
                return false;
            }
            *textOut = QStringLiteral("ret 0x%1").arg(imm16, 0, 16);
            return true;
        }
        if (opcode == 0x90) {
            *textOut = QStringLiteral("nop");
            return true;
        }
        if (opcode == 0xEB) {
            quint8 rel8 = 0;
            if (!take(&rel8)) {
                return false;
            }
            const qint8 sr = static_cast<qint8>(rel8);
            *textOut = QStringLiteral("jmp %1").arg(formatRelTarget(m_start, m_pos - m_start, sr));
            return true;
        }
        if (opcode >= 0x70 && opcode <= 0x7F) {
            quint8 rel8 = 0;
            if (!take(&rel8)) {
                return false;
            }
            const int cc = opcode & 0x0F;
            const qint8 sr = static_cast<qint8>(rel8);
            *textOut = QStringLiteral("%1 %2").arg(jccMnemonic(cc, true), formatRelTarget(m_start, m_pos - m_start, sr));
            return true;
        }
        if (opcode == 0xE8) {
            qint32 rel = 0;
            if (!takeS32(&rel)) {
                return false;
            }
            *textOut = QStringLiteral("call %1").arg(formatRelTarget(m_start, m_pos - m_start, rel));
            return true;
        }
        if (opcode == 0xE9) {
            qint32 rel = 0;
            if (!takeS32(&rel)) {
                return false;
            }
            *textOut = QStringLiteral("jmp %1").arg(formatRelTarget(m_start, m_pos - m_start, rel));
            return true;
        }

        // push/pop reg (50-5F)
        if (opcode >= 0x50 && opcode <= 0x5F) {
            const int reg = (opcode & 0x7) | (rexB() ? 8 : 0);
            const bool isPush = opcode < 0x58;
            if (m_is64Bit || !m_has66) {
                *textOut = QStringLiteral("%1 %2").arg(isPush ? QStringLiteral("push") : QStringLiteral("pop"),
                                                         gpRegName(reg, m_is64Bit, m_is64Bit, false));
            } else {
                *textOut = QStringLiteral("%1 %2").arg(isPush ? QStringLiteral("push") : QStringLiteral("pop"),
                                                         reg16Name(reg & 7));
            }
            return true;
        }

        // push imm8 / imm32
        if (opcode == 0x6A) {
            quint8 imm8 = 0;
            if (!take(&imm8)) {
                return false;
            }
            *textOut = QStringLiteral("push 0x%1").arg(imm8, 2, 16, QChar('0'));
            return true;
        }
        if (opcode == 0x68) {
            quint32 imm32 = 0;
            if (!takeU32(&imm32)) {
                return false;
            }
            *textOut = QStringLiteral("push 0x%1").arg(imm32, 0, 16);
            return true;
        }

        // mov reg, imm (B0-BF)
        if (opcode >= 0xB0 && opcode <= 0xBF) {
            const int regLow = opcode & 0x7;
            const bool is8Bit = (opcode & 0x08) == 0;
            if (is8Bit) {
                const int reg = regLow | (rexB() ? 8 : 0);
                quint8 imm8 = 0;
                if (!take(&imm8)) {
                    return false;
                }
                const bool high = (!m_is64Bit && !m_has66 && regLow >= 4);
                *textOut = QStringLiteral("mov %1, 0x%2").arg(reg8Name(regLow, high)).arg(imm8, 2, 16, QChar('0'));
                Q_UNUSED(reg);
            } else {
                const int reg = regLow | (rexB() ? 8 : 0);
                if (rexW()) {
                    quint32 lo = 0;
                    quint32 hi = 0;
                    if (!takeU32(&lo) || !takeU32(&hi)) {
                        return false;
                    }
                    const quint64 imm64 = (static_cast<quint64>(hi) << 32) | lo;
                    *textOut = QStringLiteral("mov %1, %2").arg(reg64Name(reg), formatImmHex(imm64));
                } else if (m_has66) {
                    quint16 imm16 = 0;
                    if (!takeU16(&imm16)) {
                        return false;
                    }
                    *textOut = QStringLiteral("mov %1, 0x%2").arg(reg16Name(regLow)).arg(imm16, 0, 16);
                } else {
                    quint32 imm32 = 0;
                    if (!takeU32(&imm32)) {
                        return false;
                    }
                    *textOut = QStringLiteral("mov %1, 0x%2").arg(gpRegName(reg, m_is64Bit, false, false)).arg(imm32, 0, 16);
                }
            }
            return true;
        }

        // Two-byte opcodes
        if (opcode == 0x0F) {
            return tryDecodeTwoByte(textOut);
        }

        // ModRM-based opcodes
        return tryDecodeModRMOpcode(opcode, textOut);
    }

    bool tryDecodeTwoByte(QString *textOut)
    {
        quint8 b1 = 0;
        if (!take(&b1)) {
            return false;
        }

        if (b1 == 0x0B) {
            *textOut = QStringLiteral("ud2");
            return true;
        }

        if (b1 == 0x1E && m_hasF3) {
            quint8 b2 = 0;
            if (!take(&b2)) {
                return false;
            }
            if (b2 == 0xFA && m_is64Bit) {
                *textOut = QStringLiteral("endbr64");
                return true;
            }
            return false;
        }

        if (b1 == 0x1F) {
            ModRMResult modrm;
            if (!decodeModRMOperand(&modrm) || !modrm.ok) {
                return false;
            }
            if (modrm.isReg) {
                *textOut = QStringLiteral("nop");
            } else {
                *textOut = QStringLiteral("nop %1").arg(modrm.mem);
            }
            return true;
        }

        if (b1 >= 0x80 && b1 <= 0x8F) {
            qint32 rel = 0;
            if (!takeS32(&rel)) {
                return false;
            }
            const int cc = b1 & 0x0F;
            *textOut = QStringLiteral("%1 %2").arg(jccMnemonic(cc, false), formatRelTarget(m_start, m_pos - m_start, rel));
            return true;
        }

        return false;
    }

    bool tryDecodeModRMOpcode(quint8 opcode, QString *textOut)
    {
        const int modrmPos = m_pos;
        quint8 modrm = 0;
        if (!take(&modrm)) {
            return false;
        }

        ModRMResult mr;
        if (!decodeModRM(modrmPos, &mr) || !mr.ok) {
            return false;
        }
        m_pos = modrmPos + 1 + mr.totalExtra;
        syncBytes();

        const int aluOp = mr.reg;

        auto regOpName = [&](int idx) { return gpRegName(idx, m_is64Bit, rexW(), m_has66); };

        // mov r/m, r  (88/89)
        if (opcode == 0x88 || opcode == 0x89) {
            if (opcode == 0x88) {
                if (mr.isReg) {
                    const bool high = (!m_is64Bit && !m_has66 && (mr.rm & 7) >= 4);
                    *textOut = QStringLiteral("mov %1, %2")
                                   .arg(reg8Name(mr.rm & 7, high), reg8Name(mr.reg & 7, (mr.reg & 7) >= 4 && !m_is64Bit));
                } else {
                    *textOut = QStringLiteral("mov %1, %2").arg(mr.mem, reg8Name(mr.reg & 7, false));
                }
            } else {
                if (mr.isReg) {
                    *textOut = QStringLiteral("mov %1, %2").arg(regOpName(mr.rm), regOpName(mr.reg));
                } else {
                    *textOut = QStringLiteral("mov %1, %2").arg(mr.mem, regOpName(mr.reg));
                }
            }
            return true;
        }

        // mov r, r/m (8A/8B)
        if (opcode == 0x8A || opcode == 0x8B) {
            if (opcode == 0x8A) {
                if (mr.isReg) {
                    const bool high = (!m_is64Bit && !m_has66 && (mr.rm & 7) >= 4);
                    *textOut = QStringLiteral("mov %1, %2")
                                   .arg(reg8Name(mr.reg & 7, (mr.reg & 7) >= 4 && !m_is64Bit), reg8Name(mr.rm & 7, high));
                } else {
                    *textOut = QStringLiteral("mov %1, %2").arg(reg8Name(mr.reg & 7, false), mr.mem);
                }
            } else {
                if (mr.isReg) {
                    *textOut = QStringLiteral("mov %1, %2").arg(regOpName(mr.reg), regOpName(mr.rm));
                } else {
                    *textOut = QStringLiteral("mov %1, %2").arg(regOpName(mr.reg), mr.mem);
                }
            }
            return true;
        }

        // lea (8D)
        if (opcode == 0x8D) {
            if (mr.isReg) {
                return false;
            }
            *textOut = QStringLiteral("lea %1, %2").arg(regOpName(mr.reg), mr.mem);
            return true;
        }

        // xor (30/31/32/33)
        if (opcode == 0x30 || opcode == 0x31 || opcode == 0x32 || opcode == 0x33) {
            const bool toMem = (opcode == 0x30 || opcode == 0x31);
            if (opcode == 0x30 || opcode == 0x32) {
                if (mr.isReg) {
                    const bool dstHigh = (!m_is64Bit && (mr.rm & 7) >= 4);
                    const bool srcHigh = (!m_is64Bit && (mr.reg & 7) >= 4);
                    if (toMem) {
                        *textOut = QStringLiteral("xor %1, %2")
                                       .arg(reg8Name(mr.rm & 7, dstHigh), reg8Name(mr.reg & 7, srcHigh));
                    } else {
                        *textOut = QStringLiteral("xor %1, %2")
                                       .arg(reg8Name(mr.reg & 7, srcHigh), reg8Name(mr.rm & 7, dstHigh));
                    }
                } else {
                    if (toMem) {
                        *textOut = QStringLiteral("xor %1, %2").arg(mr.mem, reg8Name(mr.reg & 7, false));
                    } else {
                        *textOut = QStringLiteral("xor %1, %2").arg(reg8Name(mr.reg & 7, false), mr.mem);
                    }
                }
            } else {
                if (mr.isReg) {
                    if (toMem) {
                        *textOut = QStringLiteral("xor %1, %2").arg(regOpName(mr.rm), regOpName(mr.reg));
                    } else {
                        *textOut = QStringLiteral("xor %1, %2").arg(regOpName(mr.reg), regOpName(mr.rm));
                    }
                } else {
                    if (toMem) {
                        *textOut = QStringLiteral("xor %1, %2").arg(mr.mem, regOpName(mr.reg));
                    } else {
                        *textOut = QStringLiteral("xor %1, %2").arg(regOpName(mr.reg), mr.mem);
                    }
                }
            }
            return true;
        }

        // test (84/85)
        if (opcode == 0x84 || opcode == 0x85) {
            if (opcode == 0x84) {
                if (mr.isReg) {
                    *textOut = QStringLiteral("test %1, %2")
                                   .arg(reg8Name(mr.rm & 7, false), reg8Name(mr.reg & 7, false));
                } else {
                    *textOut = QStringLiteral("test %1, %2").arg(mr.mem, reg8Name(mr.reg & 7, false));
                }
            } else {
                if (mr.isReg) {
                    *textOut = QStringLiteral("test %1, %2").arg(regOpName(mr.rm), regOpName(mr.reg));
                } else {
                    *textOut = QStringLiteral("test %1, %2").arg(mr.mem, regOpName(mr.reg));
                }
            }
            return true;
        }

        // cmp (38/39/3A/3B)
        if (opcode == 0x38 || opcode == 0x39 || opcode == 0x3A || opcode == 0x3B) {
            const bool regToRm = (opcode == 0x38 || opcode == 0x39);
            if (opcode == 0x38 || opcode == 0x3A) {
                if (mr.isReg) {
                    *textOut = QStringLiteral("cmp %1, %2")
                                   .arg(reg8Name(mr.rm & 7, false), reg8Name(mr.reg & 7, false));
                } else {
                    *textOut = regToRm
                                   ? QStringLiteral("cmp %1, %2").arg(mr.mem, reg8Name(mr.reg & 7, false))
                                   : QStringLiteral("cmp %1, %2").arg(reg8Name(mr.reg & 7, false), mr.mem);
                }
            } else {
                if (mr.isReg) {
                    *textOut = regToRm
                                   ? QStringLiteral("cmp %1, %2").arg(regOpName(mr.rm), regOpName(mr.reg))
                                   : QStringLiteral("cmp %1, %2").arg(regOpName(mr.reg), regOpName(mr.rm));
                } else {
                    *textOut = regToRm
                                   ? QStringLiteral("cmp %1, %2").arg(mr.mem, regOpName(mr.reg))
                                   : QStringLiteral("cmp %1, %2").arg(regOpName(mr.reg), mr.mem);
                }
            }
            return true;
        }

        // add/sub/... reg, r/m or r/m, reg (01/03/29/2B etc.)
        if (opcode == 0x01 || opcode == 0x03 || opcode == 0x29 || opcode == 0x2B || opcode == 0x09
            || opcode == 0x0B || opcode == 0x21 || opcode == 0x23) {
            QString op;
            bool regToRm = false;
            switch (opcode) {
            case 0x01:
                op = QStringLiteral("add");
                regToRm = true;
                break;
            case 0x03:
                op = QStringLiteral("add");
                regToRm = false;
                break;
            case 0x29:
                op = QStringLiteral("sub");
                regToRm = true;
                break;
            case 0x2B:
                op = QStringLiteral("sub");
                regToRm = false;
                break;
            case 0x09:
                op = QStringLiteral("or");
                regToRm = true;
                break;
            case 0x0B:
                op = QStringLiteral("or");
                regToRm = false;
                break;
            case 0x21:
                op = QStringLiteral("and");
                regToRm = true;
                break;
            case 0x23:
                op = QStringLiteral("and");
                regToRm = false;
                break;
            default:
                break;
            }
            if (mr.isReg) {
                if (regToRm) {
                    *textOut = QStringLiteral("%1 %2, %3").arg(op, regOpName(mr.rm), regOpName(mr.reg));
                } else {
                    *textOut = QStringLiteral("%1 %2, %3").arg(op, regOpName(mr.reg), regOpName(mr.rm));
                }
            } else {
                if (regToRm) {
                    *textOut = QStringLiteral("%1 %2, %3").arg(op, mr.mem, regOpName(mr.reg));
                } else {
                    *textOut = QStringLiteral("%1 %2, %3").arg(op, regOpName(mr.reg), mr.mem);
                }
            }
            return true;
        }

        // 83 /0-7 imm8
        if (opcode == 0x83) {
            quint8 imm8 = 0;
            if (!take(&imm8)) {
                return false;
            }
            const QString op = aluImmMnemonic(aluOp);
            if (mr.isReg) {
                *textOut = QStringLiteral("%1 %2, 0x%3").arg(op, regOpName(mr.rm)).arg(imm8, 2, 16, QChar('0'));
            } else {
                *textOut = QStringLiteral("%1 %2, 0x%3").arg(op, mr.mem).arg(imm8, 2, 16, QChar('0'));
            }
            return true;
        }

        // 81 /0-7 imm32
        if (opcode == 0x81) {
            quint32 imm32 = 0;
            if (!takeU32(&imm32)) {
                return false;
            }
            const QString op = aluImmMnemonic(aluOp);
            if (mr.isReg) {
                *textOut = QStringLiteral("%1 %2, 0x%3").arg(op, regOpName(mr.rm)).arg(imm32, 0, 16);
            } else {
                *textOut = QStringLiteral("%1 %2, 0x%3").arg(op, mr.mem).arg(imm32, 0, 16);
            }
            return true;
        }

        // FF group
        if (opcode == 0xFF) {
            const int grp = aluOp;
            if (mr.isReg) {
                switch (grp) {
                case 2:
                    *textOut = QStringLiteral("call %1").arg(regOpName(mr.rm));
                    return true;
                case 4:
                    *textOut = QStringLiteral("jmp %1").arg(regOpName(mr.rm));
                    return true;
                case 6:
                    *textOut = QStringLiteral("push %1").arg(regOpName(mr.rm));
                    return true;
                default:
                    return false;
                }
            }
            switch (grp) {
            case 2:
                *textOut = QStringLiteral("call %1").arg(mr.mem);
                return true;
            case 4:
                *textOut = QStringLiteral("jmp %1").arg(mr.mem);
                return true;
            case 6:
                *textOut = QStringLiteral("push %1").arg(mr.mem);
                return true;
            default:
                return false;
            }
        }

        return false;
    }
};

} // namespace

QStringList disassembleEntryPoint(bool is64Bit,
                                  const QByteArray &bytes,
                                  int maxInstructions,
                                  quint32 baseRva)
{
    QStringList lines;
    int offset = 0;
    while (lines.size() < maxInstructions && offset < bytes.size()) {
        InstructionDecoder decoder(is64Bit, bytes, offset);
        QString text;
        int size = 0;
        if (!decoder.decode(&text, &size) || size <= 0) {
            break;
        }
        lines.append(formatLine(baseRva, decoder.instructionStart(), decoder.instructionBytes(), text));
        offset += size;
    }
    return lines;
}

} // namespace PEEpDisasm
