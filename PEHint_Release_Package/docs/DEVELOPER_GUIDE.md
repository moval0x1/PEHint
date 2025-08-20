# PEHint Developer Guide

> **Essential information for developers and contributors**

## 🏗️ Architecture Overview

### SOLID Principles
- **Single Responsibility** - Each class has one clear purpose
- **Open/Closed** - Easy to extend without modifying existing code
- **Dependency Inversion** - Abstractions don't depend on details

### Key Components
- **`PEParserNew`** - Main PE parsing orchestrator
- **`PEDataModel`** - Centralized data storage
- **`LanguageManager`** - Internationalization system
- **`UIManager`** - UI setup and management

## 🔧 Development Setup

### Prerequisites
- **Visual Studio 2022** with C++ workload
- **Qt 6.8.0** (MSVC 2022 64-bit)
- **CMake** 3.16+

### Build Process
```bash
# Debug build (recommended for development)
.\build_vs_qt.bat

# Release build
.\build_release.bat
```

## 📝 Adding New Features

### New PE Fields
1. **Update** appropriate parser in `src/pe_*_parser.cpp`
2. **Add** field to `src/pe_data_model.cpp`
3. **Add** explanations to `config/explanations.json`
4. **Rebuild** project

### New Languages
1. **Create** `config/language_config_XX.ini`
2. **Translate** all strings from English
3. **Add** language code to `available_languages`
4. **Test** language switching

## 🎨 Code Standards

- **File Size** - Keep under 20KB and 500 lines
- **Comments** - Explain the "why", not the "what"
- **SOLID Principles** - Follow established patterns
- **Internationalization** - Use `LANG()` macros for all user-facing strings

## 🐛 Common Issues

### Build Problems
- **Qt not found** - Check Qt installation path
- **Missing DLLs** - Use Qt-Debug/Release configurations
- **Platform plugin error** - Ensure `platforms/qwindows.dll` is included

### Language Issues
- **Strings not loading** - Check `config/` directory paths
- **Translation missing** - Verify language file encoding (UTF-8)

## 📚 Resources

- **Qt Documentation** - [qt.io](https://doc.qt.io/)
- **PE Format** - Microsoft PE/COFF specification
- **SOLID Principles** - Clean architecture guidelines

## 🤝 Contributing

1. **Fork** repository
2. **Create** feature branch
3. **Follow** existing patterns
4. **Test** with both configurations
5. **Submit** pull request

---

**Need more details?** Check the individual documentation files in this directory.
