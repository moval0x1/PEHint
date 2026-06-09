#!/usr/bin/env python3
"""Generate config/import_api_hints.json from MalAPI.io index markdown + curated entries."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INDEX = ROOT / "tools" / "malapi_index.md"
OUTPUT = ROOT / "config" / "import_api_hints.json"
EXISTING = OUTPUT

CATEGORY_BLURBS = {
    "Enumeration": "system and environment enumeration",
    "Injection": "process injection and memory manipulation",
    "Evasion": "evasion of security controls",
    "Spying": "user activity monitoring (keylogging, screen capture)",
    "Internet": "network connectivity (C2, downloads, exfiltration)",
    "Anti-Debugging": "anti-debug and anti-analysis",
    "Ransomware": "encryption and destructive file operations",
    "Helper": "supporting APIs often abused by malware",
}

LINK_RE = re.compile(r"\[([^\]]+)\]\(/winapi/([^)]+)\)")

CURATED_LEARN_URLS = {
    "VirtualAlloc": "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc",
    "VirtualAllocEx": "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex",
    "VirtualProtect": "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect",
    "VirtualProtectEx": "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex",
    "WriteProcessMemory": "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory",
    "CreateRemoteThread": "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread",
    "LoadLibraryA": "https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya",
    "LoadLibraryW": "https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw",
    "GetProcAddress": "https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress",
    "CreateProcessW": "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw",
    "IsDebuggerPresent": "https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent",
    "NtAllocateVirtualMemory": "https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntallocatevirtualmemory",
    "NtWriteVirtualMemory": "https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntwritevirtualmemory",
    "RegCreateKeyExW": "https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw",
    "RegSetValueExW": "https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw",
    "OpenProcessToken": "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken",
    "connect": "https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect",
    "send": "https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send",
    "InternetOpenUrlW": "https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw",
    "URLDownloadToFileW": "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)",
    "SetWindowsHookExW": "https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw",
    "ShellExecuteW": "https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew",
    "CryptUnprotectData": "https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata",
    "CryptEncrypt": "https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptencrypt",
    "CreateToolhelp32Snapshot": "https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot",
}


def infer_dll(name: str) -> str:
    n = name
    if n.startswith("Nt") or n.startswith("Rtl") or n.startswith("Ldr"):
        return "ntdll.dll"
    if n.startswith("Reg") or n.startswith("Crypt") or n.startswith("OpenProcessToken") or n.startswith("AdjustToken"):
        return "advapi32.dll"
    if n.startswith("Internet") or n.startswith("Http") or n.startswith("Ftp") or n.startswith("URL"):
        return "wininet.dll"
    if n in {"connect", "send", "recv", "socket", "WSAStartup", "WSACleanup", "bind", "listen", "accept"} or n.startswith("WSA"):
        return "ws2_32.dll"
    if n.startswith("SetWindow") or n.startswith("GetWindow") or n.startswith("SendMessage") or n.startswith("GetAsyncKey") or n.startswith("SetWindowsHook"):
        return "user32.dll"
    if n.startswith("Shell"):
        return "shell32.dll"
    if n.startswith("Dns"):
        return "dnsapi.dll"
    return "kernel32.dll"


def normalize_function(raw: str) -> str:
    name = raw.strip().replace("%5F", "_")
    if name.endswith(" "):
        name = name.strip()
    return name


def parse_malapi_index(text: str) -> dict[str, set[str]]:
    lines = [ln for ln in text.splitlines() if ln.strip().startswith("|")]
    if len(lines) < 2:
        return {}
    header_cells = [c.strip() for c in lines[0].split("|")[1:-1]]
    categories = []
    for cell in header_cells:
        m = re.match(r"^([A-Za-z-]+)", cell)
        categories.append(m.group(1) if m else cell.split()[0])

    api_categories: dict[str, set[str]] = {}
    for row in lines[2:]:
        cells = [c.strip() for c in row.split("|")[1:-1]]
        for cat, cell in zip(categories, cells):
            for _, slug in LINK_RE.findall(cell):
                fn = normalize_function(slug)
                if not fn:
                    continue
                api_categories.setdefault(fn, set()).add(cat)
    return api_categories


def load_curated() -> dict[str, dict]:
    if not EXISTING.exists():
        return {}
    data = json.loads(EXISTING.read_text(encoding="utf-8"))
    out = {}
    for hint in data.get("hints", []):
        fn = hint.get("function", "")
        if fn:
            out[fn] = hint
    return out


def build_summary(name: str, cats: set[str]) -> str:
    ordered = [c for c in CATEGORY_BLURBS if c in cats]
    if not ordered:
        return f"Listed on MalAPI.io for malware triage ({name})."
    parts = [CATEGORY_BLURBS[c] for c in ordered[:3]]
    tail = ", ".join(parts)
    if len(ordered) > 3:
        tail += f" (+{len(ordered) - 3} more)"
    return f"MalAPI.io flags this API for {tail}."


def main() -> int:
    index_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INDEX
    if not index_path.exists():
        print(f"MalAPI index not found: {index_path}", file=sys.stderr)
        return 1

    text = index_path.read_text(encoding="utf-8")
    api_categories = parse_malapi_index(text)
    curated = load_curated()

    hints = []
    for fn in sorted(api_categories):
        cats = api_categories[fn]
        base = curated.get(fn, {})
        hint = {
            "function": fn,
            "dll": base.get("dll") or infer_dll(fn),
            "summary": base.get("summary") or build_summary(fn, cats),
            "malapiUrl": f"https://malapi.io/winapi/{fn}",
            "malapiCategories": ", ".join(sorted(cats)),
        }
        learn = base.get("learnUrl") or CURATED_LEARN_URLS.get(fn)
        if learn:
            hint["learnUrl"] = learn
        if base.get("remarks"):
            hint["remarks"] = base["remarks"]
        hints.append(hint)

    # Keep curated entries not present in MalAPI index
    indexed = {h["function"] for h in hints}
    for fn, base in curated.items():
        if fn in indexed:
            continue
        hints.append(base)

    hints.sort(key=lambda h: h["function"].lower())
    OUTPUT.write_text(
        json.dumps({"version": 2, "source": "malapi.io", "hints": hints}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(hints)} hints to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
