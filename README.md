# PEHint - PE Header Learning Tool

[![Version](https://img.shields.io/badge/version-0.4.6-blue.svg)](https://github.com/moval0x1/PEHint)
[![CI](https://github.com/moval0x1/PEHint/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/moval0x1/PEHint/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![GitHub downloads](https://img.shields.io/github/downloads/moval0x1/PEHint/total?label=Downloads&logo=github)](https://github.com/moval0x1/PEHint/releases)
[![GitHub stars](https://img.shields.io/github/stars/moval0x1/PEHint?label=Stars&logo=github)](https://github.com/moval0x1/PEHint/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/moval0x1/PEHint?label=Forks&logo=github)](https://github.com/moval0x1/PEHint/network/members)

## Roadmap

Planned work is tracked in [docs/ROADMAP.md](docs/ROADMAP.md) (overlay/entropy/PDB, Findings panel, delay imports, PE compare, CLI).

## Overview

PEHint is a visual PE file analyzer for analysts, reverse engineers, and students who need quick insight into Windows executables. The **Structure** tab combines an interactive PE tree, JSON-driven field explanations, and a synchronized hex view. Additional tabs cover **Imports**, **Exports**, **Delay Imports**, **Dependencies**, **Resources** (manifest, version info, icons, string tables, hex + decoded text preview), and **Strings** (filters, async extraction, export to file). The **Findings** tab runs config-driven heuristics (overlay, entropy, hardening, suspicious imports/strings, checksum, signatures, and more) with one-click navigation to the relevant tree field or hex range. Optional local clones of Microsoft documentation under `third_party/` power richer **Imports** API summaries; without them, the app still lists modules and symbols normally.

## What's new in v0.4.6

- **Stability:** Fixed stack overflow when opening large PE files with big resource sections (structure tree no longer loads full field explanations on every row at open time).
- **Resources preview:** Correct icon size labels; `RT_STRING` decoding; embedded UTF-16/ASCII text under hex dumps; improved `VS_VERSION_INFO` string parsing.
- **Findings / File summary:** Clearer **Signed** vs **certificate data only** labels when a cert table exists but Authenticode trust is not valid.
- **Crash handler:** Safer handling of stack-overflow exceptions on Windows.

## Screenshots

### Main Interface
![PEHint Main Interface](/resources/imgs/screenshots/start_opened_file.png)

### Field Explanations
![DOS Header Field Explanation](/resources/imgs/screenshots/dos_header_explanation.png)

### Imports View
![Imports Tab](/resources/imgs/screenshots/imports.png)

### Exports View
![Exports Tab](/resources/imgs/screenshots/exports.png)

### Dependencies View
![Dependencies Tab](/resources/imgs/screenshots/dependencies.png)

### Strings View
![Strings Tab](/resources/imgs/screenshots/strings.png)

## Languages

- **English** - Default language
- **Portuguese (Brazil)** - Complete Brazilian Portuguese support

## Import API hints (`third_party`)

The **Imports** tab can show curated API summaries (signature, parameters, links to Microsoft Learn) **only when** PEHint can read local Markdown from cloned Microsoft documentation repos. Nothing is bundled in the release binary—you must supply the content yourself.

**Requirement (for full import hints):** clone the repos under `third_party/` and use the folder layout and optional environment variables described in **[third_party/README.txt](third_party/README.txt)**:

- **MicrosoftDocs/sdk-api** — Win32 API reference (`nf-*.md` under the repo `content` tree); override with `PEHINT_SDK_API_CONTENT` if needed.
- **MicrosoftDocs/Console-Docs** (optional) — console APIs not covered by sdk-api; override with `PEHINT_WINDOWS_CONSOLE_DOCS`.

PEHint discovers `third_party/sdk-api` and `third_party/console-docs` next to the executable - same folder as `PEHint.exe`. Without these clones, the Imports panel still lists DLLs and symbols, but the API summary area shows a short “no summary” message instead of topic text.

## CLI

Batch triage without the GUI:

```text
PEHint --scan [--format text|json] [--min-severity high|medium|low|info] [--include-passes] [--lang en|pt] <file.exe> ...
PEHint --scan --dir <folder> [--recursive] [--watch] [--debounce-ms 500]
```

Same parse, metrics, and findings engine as the desktop app. See `PEHint --help` for all options.

## References (PE format & Windows)

- [Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — official PE/COFF specification (goes well with what PEHint shows in the tree)
- [PE Format — win.internals (0xRick)](https://0xrick.github.io/win-internals/pe1/) — approachable overview
- [Windows data types & structures (`winnt.h`)](https://learn.microsoft.com/en-us/windows/win32/api/winnt/)
- [DbgHelp API](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/) — related debugging/symbol APIs

Optional deeper reading: *"An In-Depth Look into the Win32 Portable Executable File Format"* (MSJ articles, often mirrored).

## Developer docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — modules, data flow, config
- [docs/FINDINGS_RULES.md](docs/FINDINGS_RULES.md) — findings rule reference

## Greetz

Huge thanks to everyone who kicked the tires on PEHint, reported rough edges, and suggested ideas—your testing and feedback shaped what shipped.

- [P4nd3m1cb0y](https://x.com/P4nd3m1cb0y) / Imports API summary suggestion


## License

MIT License - see [LICENSE](LICENSE) for details.

---

**PEHint v0.4.6** — Making PE header analysis accessible and educational with modern C++ and Qt 6.
