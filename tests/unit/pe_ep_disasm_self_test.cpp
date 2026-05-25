#include "pe_ep_disasm.h"

#include <iostream>

bool runPeEpDisasmSelfTests()
{
    bool ok = true;
    auto check = [&](bool condition, const char *message) {
        if (!condition) {
            std::cerr << "PEEpDisasm self-test failed: " << message << '\n';
            ok = false;
        }
    };

    // Empty input yields no lines
    {
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, QByteArray{});
        check(lines.isEmpty(), "empty bytes -> empty output");
    }

    // Single-byte no-operand instructions (64-bit)
    {
        QByteArray bytes;
        bytes.append(char(0xC3)); // ret
        bytes.append(char(0x90)); // nop
        bytes.append(char(0xCC)); // int3
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 3, "ret/nop/int3 -> 3 lines");
        check(lines.at(0) == QStringLiteral("ret"), "ret decoded");
        check(lines.at(1) == QStringLiteral("nop"), "nop decoded");
        check(lines.at(2) == QStringLiteral("int3"), "int3 decoded");
    }

    // push rbp (55) in 64-bit mode
    {
        QByteArray bytes;
        bytes.append(char(0x55)); // push rbp
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "push rbp -> 1 line");
        check(lines.at(0) == QStringLiteral("push rbp"), "push rbp decoded");
    }

    // push ebp (55) in 32-bit mode
    {
        QByteArray bytes;
        bytes.append(char(0x55)); // push ebp
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(false, bytes);
        check(lines.size() == 1, "push ebp -> 1 line");
        check(lines.at(0) == QStringLiteral("push ebp"), "push ebp decoded");
    }

    // xor eax, eax (31 C0) in 64-bit mode
    {
        QByteArray bytes;
        bytes.append(char(0x31));
        bytes.append(char(0xC0)); // ModRM: mod=11, reg=eax, rm=eax
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "xor eax,eax -> 1 line");
        check(lines.at(0) == QStringLiteral("xor eax, eax"), "xor eax,eax decoded");
    }

    // xor rax, rax (REX.W 48 + 31 C0) in 64-bit mode
    {
        QByteArray bytes;
        bytes.append(char(0x48)); // REX.W
        bytes.append(char(0x31));
        bytes.append(char(0xC0));
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "xor rax,rax -> 1 line");
        check(lines.at(0) == QStringLiteral("xor rax, rax"), "xor rax,rax decoded");
    }

    // call rel32 (E8 xx xx xx xx)
    {
        QByteArray bytes;
        bytes.append(char(0xE8));
        bytes.append(char(0x00));
        bytes.append(char(0x00));
        bytes.append(char(0x00));
        bytes.append(char(0x00)); // rel32 = 0, target = 5
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "call rel32 -> 1 line");
        check(lines.at(0).startsWith(QStringLiteral("call ")), "call rel32 decoded");
    }

    // jmp short (EB xx)
    {
        QByteArray bytes;
        bytes.append(char(0xEB));
        bytes.append(char(0x00)); // rel8=0, target=2
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "jmp short -> 1 line");
        check(lines.at(0).startsWith(QStringLiteral("jmp ")), "jmp short decoded");
    }

    // je short (74 xx)
    {
        QByteArray bytes;
        bytes.append(char(0x74));
        bytes.append(char(0x02));
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "je short -> 1 line");
        check(lines.at(0).startsWith(QStringLiteral("je ")), "je short decoded");
    }

    // Unknown opcode falls back to db
    {
        QByteArray bytes;
        bytes.append(char(0x0F));
        bytes.append(char(0x0B)); // ud2
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "ud2 -> 1 line");
        check(lines.at(0) == QStringLiteral("ud2"), "ud2 decoded");
    }

    // Unrecognized byte falls back to db
    {
        QByteArray bytes;
        bytes.append(char(0xD6)); // undefined
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "unknown byte -> 1 db line");
        check(lines.at(0).startsWith(QStringLiteral("db ")), "unknown byte -> db fallback");
    }

    // maxInstructions limit
    {
        QByteArray bytes(16, char(0x90)); // 16 nops
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes, 4);
        check(lines.size() == 4, "maxInstructions=4 limits output");
    }

    // baseRva=0 omits address prefix
    {
        QByteArray bytes;
        bytes.append(char(0x90));
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes, 1, 0);
        check(lines.size() == 1 && lines.at(0) == QStringLiteral("nop"),
              "baseRva=0 -> no address prefix");
    }

    // baseRva non-zero prepends address
    {
        QByteArray bytes;
        bytes.append(char(0x90));
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes, 1, 0x1000);
        check(lines.size() == 1 && lines.at(0).contains(QStringLiteral("nop")),
              "baseRva!=0 -> line contains mnemonic");
        check(lines.at(0).startsWith(QStringLiteral("00001000")),
              "baseRva!=0 -> line starts with address");
    }

    // mov eax, imm32 (B8 xx xx xx xx)
    {
        QByteArray bytes;
        bytes.append(char(0xB8));
        bytes.append(char(0x01));
        bytes.append(char(0x00));
        bytes.append(char(0x00));
        bytes.append(char(0x00));
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(false, bytes);
        check(lines.size() == 1, "mov eax,imm32 -> 1 line");
        check(lines.at(0).startsWith(QStringLiteral("mov eax,")), "mov eax,imm32 decoded");
    }

    // sub rsp, 0x28 (48 83 EC 28) — common function prologue
    {
        QByteArray bytes;
        bytes.append(char(0x48)); // REX.W
        bytes.append(char(0x83));
        bytes.append(char(0xEC)); // ModRM: /5 (sub), rm=rsp(4), mod=11
        bytes.append(char(0x28));
        const QStringList lines = PEEpDisasm::disassembleEntryPoint(true, bytes);
        check(lines.size() == 1, "sub rsp,0x28 -> 1 line");
        check(lines.at(0).startsWith(QStringLiteral("sub ")), "sub rsp,0x28 decoded");
    }

    return ok;
}
