# PEHint - PE Header Learning Tool

[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)](https://github.com/moval0x1/PEHint)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![GitHub all releases](https://img.shields.io/github/downloads/moval0x1/PEHint/total)
![GitHub release downloads](https://img.shields.io/github/downloads/moval0x1/PEHint/latest/total)


## Overview

PEHint is a visual PE file analyzer designed for analysts, reverse engineers, and students who need quick insight into Windows executables. It offers an interactive PE structure tree, contextual explanations, and a synchronized hex viewer so you can move from headers to bytes without leaving the same window.

## Key Features

- Complete header coverage: DOS header, NT headers, optional header, sections, and all 16 data directories
- Contextual explanations with security notes for high-risk fields
- Structured Imports/Exports tabs with module counts, offsets, and ordinals
- Hex viewer with offset syncing for tree selections
- Language packs (English and Portuguese) and configuration-driven explanations

## What’s New in v0.4.0

- Accurate import/export parsing for PE32 and PE32+ binaries, including ordinal handling and thunk offsets
- Dedicated Imports/Exports tabs that list modules, function counts, offsets, and ordinals
- Field explanations extended with analyst-focused notes on import/export usage patterns
- Uniform hexadecimal formatting (uppercase with 0x prefix) across the tree and hex viewer
- Drag-and-drop loading and clipboard-friendly exports of tree data
- Removal of the large-file shortcut path—64-bit samples now receive a full parse by default

## Screenshots

### Main Interface
![PEHint Main Interface](/resources/imgs/start_opened_file.png)

**What the screenshot illustrates:**
- The structure tree lists DOS, NT, and section entries with synchronized offset/size columns
- The details pane highlights the currently selected field so you can inspect offsets immediately
- The lower hex viewer shows the raw bytes for the selection, keeping tree context and hex data aligned

### Field Explanations
![DOS Header Field Explanation](/resources/imgs/dos_header_explanation.png)

**What the screenshot illustrates:**
- Selecting `DOS Header` opens the explanatory text block with description, purpose, and security notes
- The hex viewer is auto-highlighted to the header bytes referenced in the explanation
- The panel reinforces the educational flow—click, read, correlate addresses—without leaving the main window

### Imports View
![Imports Tab](/resources/imgs/imports.png)

**What the screenshot illustrates:**
- The top tree lists DLLs alongside decimal function counts so you can gauge API use at a glance
- The lower list breaks out each imported function with its thunk RVA offset and ordinal value
- Analysts can compare module usage and spot suspicious APIs without leaving the imports tab

### Exports View
![Exports Tab](/resources/imgs/exports.png)

**What the screenshot illustrates:**
- Exported symbols are shown with their resolved names (or bracketed ordinals when unnamed)
- Column layout includes RVA and ordinal for quick correlation with the export address table
- Useful for spotting ordinal-only exports, potential proxy tables, and DLL sideloading behaviour

## Languages

- **🇺🇸 English** - Default language
- **🇧🇷 Portuguese** - Complete Brazilian Portuguese support

## References
- https://0xrick.github.io/win-internals/pe1/
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/
- https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**PEHint v0.4.0** — Making PE header analysis accessible and educational with modern C++, Qt 6, and SOLID principles.
