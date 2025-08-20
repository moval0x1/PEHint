# PEHint - PE Header Learning Tool

[![Version](https://img.shields.io/badge/version-0.3.1-blue.svg)](https://github.com/moval0x1/PEHint)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)

> **Interactive PE Header Analysis Tool for Malware Analysis and Reverse Engineering Education**

## 🎯 What is PEHint?

PEHint is a **visual PE file analyzer** that makes understanding Windows executable files easy and educational. Perfect for:
- **Learning PE file format** structure and fields
- **Malware analysis** and reverse engineering education
- **Understanding Windows executables** through interactive exploration

## ✨ Key Features

- **🔍 Complete PE Analysis** - DOS Header, PE Header, Optional Header, Sections, Data Directories
- **👆 Click-to-Explain** - Click any field for detailed explanations with hex highlighting
- **🌍 Multi-language Support** - English and Portuguese with complete field documentation
- **📊 Professional Hex Viewer** - Navigate and highlight specific bytes
- **🎓 Educational Focus** - Built for learning, not just analysis

## 📸 See It in Action

### 🖼️ Main Interface
![PEHint Main Interface](/resources/imgs/start_opened_file.png)

**What you see:**
- **PE Structure Tree** (left) - Complete file structure breakdown
- **Field Details** (right) - Values, offsets, and sizes
- **Hex Viewer** (bottom) - Raw file data with highlighting

### 🔍 Field Explanations
![DOS Header Field Explanation](/resources/imgs/dos_header_explanation.png)

**Interactive Learning:**
- Click any field for instant detailed explanations
- Technical descriptions, purpose, and security insights
- Hex highlighting shows exact byte locations
- Available in English and Portuguese

## 🚀 Quick Start

### Prerequisites
- **Windows 10/11** (64-bit)
- **Visual Studio 2022** with C++ workload
- **Qt 6.8.0** (MSVC 2022 64-bit)

### Build & Run
1. **Open** project in Visual Studio 2022
2. **Select** `Qt-Debug` configuration
3. **Build** (Ctrl+Shift+B)
4. **Run** (F5)

**Alternative:** Use the provided batch files:
```bash
.\build_vs_qt.bat    # Debug build
.\build_release.bat   # Release build
```

## 📁 Project Structure

```
PEHint/
├── src/                    # Source code (SOLID architecture)
├── config/                 # Explanations and language files
├── resources/              # Icons and images
├── docs/                   # Detailed documentation
└── README.md              # This file
```

## 🌍 Languages

- **🇺🇸 English** - Default language
- **🇧🇷 Portuguese** - Complete Brazilian Portuguese support

## 🐛 Known Issues & Limitations

### Current Bugs
- **Security Analysis** - Not implemented yet (planned for v0.4.0)
- **Large File Handling** - May have memory issues with very large PE files
- **Some PE Fields** - Not all optional header fields are fully parsed
- **Import/Export Tables** - Basic parsing only, detailed analysis pending

### Future Improvements (v0.4.0+)
- **🔒 Security Analysis Engine** - Threat detection, entropy analysis, suspicious pattern identification
- **📊 Advanced Data Directory Parsing** - Detailed import/export table analysis
- **🔍 Enhanced Hex Search** - Pattern matching and advanced search capabilities
- **📈 Performance Optimization** - Better large file handling and memory management
- **🎨 UI Enhancements** - Dark mode, customizable themes, better accessibility

## 🔧 For Developers

- **SOLID Architecture** - Clean, modular design
- **Extensible** - Easy to add new PE fields
- **Configuration-based** - Externalized settings
- **Multi-language Ready** - Easy to add new languages

See [docs/](docs/) for detailed development guides.

## 📚 Learning Resources

- **Microsoft PE Format** - Official specification
- **PE File Structure** - Understanding headers and sections
- **Reverse Engineering** - Static analysis techniques

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch
3. **Follow** existing architecture patterns
4. **Submit** a pull request

## References
- https://0xrick.github.io/win-internals/pe1/
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/
- https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**PEHint v0.3.1** - Making PE Header Analysis Accessible and Educational

*Built with modern C++, Qt 6, and SOLID architecture principles*