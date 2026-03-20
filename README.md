# PEHint - PE Header Learning Tool

[![Version](https://img.shields.io/badge/version-0.4.5-blue.svg)](https://github.com/moval0x1/PEHint)
[![CI](https://github.com/moval0x1/PEHint/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/moval0x1/PEHint/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)

[![GitHub stars](https://img.shields.io/github/stars/moval0x1/PEHint?label=Stars&logo=github)](https://github.com/moval0x1/PEHint/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/moval0x1/PEHint?label=Forks&logo=github)](https://github.com/moval0x1/PEHint/network/members)
[![GitHub downloads](https://img.shields.io/github/downloads/moval0x1/PEHint/total?label=Downloads&logo=github)](https://github.com/moval0x1/PEHint/releases)

## Overview

PEHint is a visual PE file analyzer designed for analysts, reverse engineers, and students who need quick insight into Windows executables. It offers an interactive PE structure tree, contextual explanations, and a synchronized hex viewer so you can move from headers to bytes without leaving the same window.

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

## References (PE format & Windows)

- [Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — official PE/COFF specification (goes well with what PEHint shows in the tree)
- [PE Format — win.internals (0xRick)](https://0xrick.github.io/win-internals/pe1/) — approachable overview
- [Windows data types & structures (`winnt.h`)](https://learn.microsoft.com/en-us/windows/win32/api/winnt/)
- [DbgHelp API](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/) — related debugging/symbol APIs

Optional deeper reading: *"An In-Depth Look into the Win32 Portable Executable File Format"* (MSJ articles, often mirrored).

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**PEHint v0.4.5** — Making PE header analysis accessible and educational with modern C++ and Qt 6.