# PEHint - PE Header Learning Tool

[![Version](https://img.shields.io/badge/version-0.5.0-blue.svg)](https://github.com/moval0x1/PEHint)
[![CI](https://github.com/moval0x1/PEHint/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/moval0x1/PEHint/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![GitHub downloads](https://img.shields.io/github/downloads/moval0x1/PEHint/total?label=Downloads&logo=github)](https://github.com/moval0x1/PEHint/releases)
[![GitHub stars](https://img.shields.io/github/stars/moval0x1/PEHint?label=Stars&logo=github)](https://github.com/moval0x1/PEHint/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/moval0x1/PEHint?label=Forks&logo=github)](https://github.com/moval0x1/PEHint/network/members)

PEHint is a Windows PE file analyzer for malware triage, reverse engineering, and learning the Portable Executable format — built with C++ and Qt 6. It combines an interactive structure tree, heuristic findings, import analysis, and a CLI for batch scanning, all without leaving a single tool.

> **Full documentation is on the [Wiki](https://github.com/moval0x1/PEHint/wiki).**

## What's New

### v0.5.0
- **PE Compare** — diff two PE files side-by-side: headers, sections (with entropy), version info, PDB, TLS, resources, Authenticode, imports, exports, and findings. Swap A↔B and copy the report to clipboard.
- **Findings category filter pills** — filter the Findings tab by Hardening / Content / Metadata / Imports without losing the full list.
- **Hardening passes** — ASLR, DEP, CFG pass/fail items now always appear in the Findings tab (previously hidden when passing).
- **New findings** — `invalid_signature` (certificate directory present but Authenticode verification failed) and `clr_assembly` (.NET binaries).
- **TLS callbacks full walk** — all callback addresses listed in the TLS directory, not just the count.
- **Base relocations full walk** — all relocation blocks and their entries shown in the structure tree.
- **findings.json v6** — 41 rules, each with an explicit `category` field; fully editable without recompiling.

### v0.4.6
- Fixed a stack overflow on very large PE files (deep section recursion).
- Resource preview improvements: better icon rendering and hex fallback for unknown types.
- Clearer Signed / cert-data labels in the Authenticode panel.
- Safer crash handler — avoids re-entrancy when the signal fires during Qt shutdown.

## Screenshots

### Main Interface
![PEHint Main Interface](/resources/imgs/screenshots/file-opened.png "PEHint Main Interface")

### Imports
![Imports](/resources/imgs/screenshots/imports.png "Imports")

### Resources
![Resources](/resources/imgs/screenshots/resources.png "Resources")

### Strings
![Strings](/resources/imgs/screenshots/strings.png "Strings")

### Findings
![Findings](/resources/imgs/screenshots/findings.png "Findings")

## Greetz

Huge thanks to everyone who kicked the tires on PEHint, reported rough edges, and suggested ideas — your testing and feedback shaped what shipped.

- [P4nd3m1cb0y](https://x.com/P4nd3m1cb0y) / Imports API summary suggestion

## License

MIT License — see [LICENSE](LICENSE) for details.
