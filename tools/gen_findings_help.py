"""Append findings/*_help keys for rules missing beginner help."""
from pathlib import Path
import json
import re

HELP = {
    "missing_aslr": "Without ASLR, the program loads at the same address every time, which makes exploitation easier. Legitimate old tools may lack it; malware often disables it on purpose.",
    "missing_dep": "DEP (NX) marks data pages non-executable. When missing, code might run from writable memory — a common exploit technique.",
    "missing_cfg": "Control Flow Guard validates indirect calls. Without it, return-oriented programming chains are easier to use.",
    "overlay_present": "Overlay is data appended after the PE layout ends. Installers, self-extractors, and some malware use it. Inspect overlay bytes in the hex view.",
    "high_file_entropy": "High entropy often means packing, encryption, or compressed data. Compare with section entropy and imports; open the file in a disassembler if it looks suspicious.",
    "high_section_entropy": "One section with high entropy may be resources, crypto constants, or packed code. Check which section it is and whether it is marked executable.",
    "few_imports": "Very few imported DLLs can mean a tiny stub, a packer, or a self-contained binary. Compare with subsystem and section layout.",
    "no_imports": "User-mode EXEs usually import kernel32 and other system DLLs. Zero imports may indicate a packer, hand-crafted shellcode loader, or corrupt image.",
    "rwx_section": "Memory should rarely be readable, writable, and executable at once. This pattern is common in shellcode loaders and some packers.",
    "suspicious_ep": "The entry point should usually be in .text. If it sits in an odd or writable section, the file may be packed or modified. Jump to the EP in the hex view and inspect instructions.",
    "zero_timestamp": "A zero TimeDateStamp often means the linker did not record build time, or metadata was stripped. It is common in rebuilt or packed files.",
    "old_timestamp": "A very old compile date may indicate legacy software, a forged timestamp, or a deliberately backdated build.",
    "future_timestamp": "A timestamp in the future is invalid for a normal build and may indicate tampering or clock errors during linking.",
    "delay_import_present": "Delay-loaded imports resolve at first use, which can hide API usage from static import scans. Review the delay-import table.",
    "checksum_zero": "Many linkers leave CheckSum at zero. Packers and rebuilt binaries often do too; drivers and some signed builds expect a valid checksum.",
    "checksum_mismatch": "The stored checksum does not match the file contents. The image may have been modified after linking or rebuilt without updating the header.",
    "dll_no_exports": "Most DLLs export at least one symbol. An empty export table can mean a resource-only DLL, a loader stub, or an unusual build.",
    "no_rich_header": "The Rich Header records MSVC toolchain versions between the DOS and PE headers. Absence suggests non-MSVC tooling or header wiping.",
    "pdb_present": "A PDB path in the debug directory helps attribute builds and enables symbolized debugging. Malware authors sometimes leave PDB paths by mistake.",
    "debug_info_stripped": "This flag says debug info was removed at link time. You may still see CodeView/PDB records even when this flag is set.",
    "writable_code_section": "Code sections are normally read-only when loaded. Writable .text can indicate self-modifying code, unpacking stubs, or a bad linker flag.",
    "executable_data_section": "Data sections marked executable (e.g. .data with execute) are unusual and sometimes used to hide shellcode.",
    "section_raw_gt_virtual": "When raw size on disk exceeds virtual size, extra bytes may be uninitialized padding or hidden content. Compare with section entropy.",
    "gui_few_imports": "Graphical Windows programs typically import USER32/GDI32 and more. Very few imports in a GUI EXE can suggest packing or minimal launchers.",
    "tls_callbacks_present": "TLS callbacks run before the main entry point during process startup. Malware and protectors use them to unpack or anti-debug early.",
    "unsigned_executable": "No publisher signature means you cannot verify who built the file. Use hashes (MD5/SHA256) and other findings; signed is not proof of safety, but unsigned needs extra scrutiny.",
    "relocations_stripped_aslr": "ASLR needs base relocations at load time. Stripping relocs while enabling ASLR can break loading or indicate a conflicting linker setup.",
    "version_info_missing": "Version resources help identify vendor and product. Missing version info is common in tools and malware alike.",
    "manifest_require_admin": "requireAdministrator forces UAC elevation. Legitimate installers use it; malware may request admin for persistence or system changes.",
    "high_ordinal_imports": "Importing mostly by ordinal hides function names from the import table. Packers and some legitimate system DLLs do this.",
    "packer_section_name": "Section names like UPX0 or .themida match known packer/protector conventions. Treat as a hint, not proof.",
    "flagged_import": "This import matches a curated list of APIs often used in malware or suspicious tooling. Context matters — many legitimate apps use the same APIs.",
    "hardcoded_url": "URLs embedded in section data may be C2 endpoints, update servers, or debug strings. Click the finding to list matches and jump in hex.",
    "hardcoded_ip": "IPv4 strings in the file may be network endpoints or false positives (version numbers). Review matches in context.",
    "nonstandard_dos_stub": "The DOS stub usually prints 'This program cannot be run in DOS mode'. Unusual text can indicate tampering or custom stubs.",
    "duplicate_exports": "Duplicate export names break normal lookup semantics and may indicate a malformed or malicious export table.",
    "import_combo": "This import combination matches a known pattern (e.g. process injection APIs). Review the listed functions and the import tree.",
    "hardcoded_registry": "Registry paths in binary data may point to persistence keys or configuration. Click the finding to review each match.",
    "suspicious_command": "Command-line fragments (cmd.exe, powershell, schtasks, etc.) in section data can indicate droppers or scripts. Review matches in hex.",
}

rules_path = Path("config/findings.json")
rules = json.loads(rules_path.read_text(encoding="utf-8"))
rule_ids = [r["id"] for r in rules.get("rules", rules.get("findings", []))]
if not rule_ids:
    rule_ids = [r["id"] for r in rules["rules"]]

for lang_suffix in ("", "_pt"):
    ini_path = Path(f"config/language_config{lang_suffix}.ini")
    text = ini_path.read_text(encoding="utf-8")
    m = re.search(r"(\[findings\]\n)", text)
    if not m:
        raise SystemExit(f"No [findings] section in {ini_path}")

    existing = set(re.findall(r"^([a-z0-9_]+)_help=", text, re.M))
    additions = []
    for rid in rule_ids:
        if rid in existing:
            continue
        help_en = HELP.get(rid)
        if not help_en:
            print(f"WARN: no help text for {rid}")
            continue
        if lang_suffix == "_pt":
            # Keep English for now in pt file — translators can refine later; better than missing keys
            help_text = help_en
        else:
            help_text = help_en
        additions.append(f"{rid}_help={help_text}")

    if additions:
        insert_at = m.end()
        text = text[:insert_at] + "\n".join(additions) + "\n" + text[insert_at:]
        ini_path.write_text(text, encoding="utf-8")
        print(f"{ini_path.name}: added {len(additions)} help keys")
    else:
        print(f"{ini_path.name}: nothing to add")
