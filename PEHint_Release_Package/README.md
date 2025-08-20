# PEHint - PE Header Learning Tool

[![Version](https://img.shields.io/badge/version-0.4.1-blue.svg)](https://github.com/moval0x1/PEHint)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Architecture](https://img.shields.io/badge/architecture-SOLID-green.svg)](docs/REFACTORING_GUIDE.md)
[![Languages](https://img.shields.io/badge/languages-5-blue.svg)](docs/INTERNATIONALIZATION.md)

> **Interactive PE Header Analysis Tool for Malware Analysis and Reverse Engineering Education**

## 🚀 Latest Updates (v0.4.1)

### ✨ Major New Features
- **🌍 Full Internationalization System** - Complete support for English, Portuguese, Spanish, French, and German
- **🔒 Advanced Security Analysis Engine** - Configurable security rules and threat detection
- **🔍 Enhanced Hex Search** - Pattern matching with hexadecimal value search
- **🏗️ Modular SOLID Architecture** - Complete refactoring following SOLID principles
- **⚙️ Configuration Management System** - Externalized settings and language strings
- **📊 Complete PE Format Coverage** - All 16 Data Directory parsers implemented

### 🎯 UI/UX Improvements
- **👆 Click-to-Explain System** - Click on any PE field for detailed explanations (replaced hover)
- **🎨 Professional Visual Design** - Enhanced styling with hover effects and visual feedback
- **📈 Real-time Progress Tracking** - Visual feedback during file parsing
- **🔧 Advanced Hex Viewer** - Professional hex editor with search and highlighting

### 🏗️ Architecture Overhaul
- **Eliminated Monolithic Design** - Replaced single `peparser.cpp` (2000+ lines) with modular components
- **SOLID Principles Compliance** - Single Responsibility, Open/Closed, Dependency Inversion
- **File Size Optimization** - All files under 20KB and 500 lines (with meaningful comments)
- **Comprehensive Documentation** - Detailed architecture guides and internationalization docs

### 🐛 Bug Fixes
- **Fixed Qt Platform Plugin Issues** - Resolved initialization errors
- **Corrected Resource Paths** - Fixed icon and configuration file loading
- **Improved Build Reliability** - Cleaner CMake configuration with better error handling
- **Enhanced Memory Management** - Better resource cleanup and error handling

## 🎯 Features

### Core Functionality
- **📋 Interactive PE Header Analysis** - Visual exploration of complete PE file structure
- **👆 Click-based Field Explanations** - Click on any field for detailed information with precise hex highlighting
- **🔍 Advanced Hex Viewer** - Navigate, search, and highlight specific bytes with pattern matching
- **🔒 Security Analysis** - Comprehensive threat detection with configurable rules
- **📊 Complete PE Coverage** - All PE headers, sections, and 16 data directories

### Educational Features
- **🌍 Multi-language Support** - 5 languages with complete field explanations
- **📚 Comprehensive Documentation** - Detailed explanations for every PE field
- **🎓 Learning-Focused Design** - Perfect for malware analysis and reverse engineering education
- **🔍 Security Insights** - Real-world security analysis with threat indicators

### Technical Features
- **⚡ High Performance** - Optimized parsing with progress tracking
- **🏗️ Modular Architecture** - Clean, maintainable codebase following SOLID principles
- **⚙️ Configurable** - Externalized settings for security rules and UI strings
- **🔧 Extensible** - Easy to add new PE fields and analysis features

## 🚀 Quick Start

### Prerequisites
- **Windows 10/11** (64-bit)
- **Visual Studio 2022** with C++ workload
- **Qt 6.8.0** (MSVC 2022 64-bit)

### ⚠️ Important: Use Qt Configurations in Visual Studio

**Visual Studio will automatically detect the Qt configurations** from CMakePresets.json:

#### Option 1: Use Qt-Debug (Recommended for Development)
1. **Open** the project folder in Visual Studio 2022
2. **Wait for CMake configuration** to complete
3. **Select** `Qt-Debug` from the build configuration dropdown
4. **Build** the project (Ctrl+Shift+B)
5. **Debug** the application (F5)

#### Option 2: Use Qt-Release (For Production)
1. **Select** `Qt-Release` from the build configuration dropdown
2. **Build** the project (Ctrl+Shift+B)
3. **Run** the application (Ctrl+F5)

### Building from Command Line

#### Debug Build
```bash
# Using the provided batch file (RECOMMENDED)
.\build_vs_qt.bat

# Or manually with CMake preset
cmake --preset Qt-Debug
cmake --build --preset Qt-Debug
```

#### Release Build
```bash
# Using the provided batch file
.\build_release.bat

# Or manually with CMake preset
cmake --preset Qt-Release
cmake --build --preset Qt-Release
```

## 📁 Project Structure

```
PEHint/
├── src/                           # Source code (Modular SOLID Architecture)
│   ├── main.cpp                  # Application entry point
│   ├── mainwindow.cpp            # Main window implementation
│   ├── mainwindow.h              # Main window header
│   ├── pe_parser_new.cpp         # Main PE parser (replaces old peparser.cpp)
│   ├── pe_parser_new.h           # PE parser header
│   ├── pe_data_model.cpp         # PE data storage model
│   ├── pe_data_model.h           # Data model header
│   ├── pe_data_directory_parser.cpp  # Data directory parser
│   ├── pe_data_directory_parser.h    # Data directory header
│   ├── pe_import_export_parser.cpp   # Import/Export parser
│   ├── pe_import_export_parser.h     # Import/Export header
│   ├── pe_security_analyzer.cpp     # Security analysis engine
│   ├── pe_security_analyzer.h       # Security analyzer header
│   ├── language_manager.cpp         # Internationalization system
│   ├── language_manager.h           # Language manager header
│   ├── pe_ui_manager.cpp            # UI management
│   ├── pe_ui_manager.h              # UI manager header
│   ├── security_config_manager.cpp  # Configuration management
│   ├── security_config_manager.h    # Config manager header
│   ├── pe_utils.cpp                 # PE utilities
│   ├── pe_utils.h                   # Utilities header
│   ├── pe_structures.h              # PE structure definitions
│   ├── pe_ui_presenter.h            # UI presenter (MVP pattern)
│   ├── hexviewer.cpp                # Advanced hex viewer
│   ├── hexviewer.h                  # Hex viewer header
│   └── version.h                    # Version information
├── config/                        # Configuration files
│   ├── explanations.json          # Multi-language field explanations
│   ├── language_config.ini        # UI language strings
│   ├── language_config_pt.ini     # Portuguese translations
│   └── security_config.ini        # Security analysis configuration
├── resources/                     # Application resources
│   ├── imgs/                      # Icons and images
│   ├── resource.qrc               # Qt resource file
│   └── app.rc                     # Windows resource file
├── docs/                          # Documentation
│   └── INTERNATIONALIZATION.md    # Language system documentation
├── out/                           # Build output directory
│   └── build/                     # CMake build files
├── CMakeLists.txt                 # Main build configuration
├── CMakePresets.json              # Build presets (Qt-Debug, Qt-Release)
├── NEW_ARCHITECTURE_SUMMARY.md    # Architecture documentation
├── REFACTORING_GUIDE.md           # Refactoring documentation
├── VERSION_MANAGEMENT.md          # Version management guide
├── build_vs_qt.bat                # Debug build script
├── build_release.bat              # Release build script
└── README.md                      # This file
```

## 🏗️ Architecture Overview

### SOLID Principles Implementation
- **Single Responsibility**: Each class has one clear purpose
- **Open/Closed**: Easy to extend without modifying existing code
- **Dependency Inversion**: Abstractions don't depend on details

### Modular Components
- **`PEParserNew`**: Main PE parsing orchestrator
- **`PEDataModel`**: Centralized data storage
- **`PEDataDirectoryParser`**: Handles all 16 data directories
- **`PEImportExportParser`**: Specialized import/export handling
- **`PESecurityAnalyzer`**: Comprehensive security analysis
- **`LanguageManager`**: Complete internationalization system
- **`UIManager`**: UI setup and management
- **`SecurityConfigManager`**: Configuration file management

### Design Patterns Used
- **Model-View-Presenter (MVP)**: Clean separation of concerns
- **Singleton**: Language and configuration managers
- **Strategy**: Configurable security analysis rules
- **Observer**: Progress tracking and UI updates

## 🌍 Internationalization

### Supported Languages
- **🇺🇸 English** - Default language with complete coverage
- **🇧🇷 Portuguese** - Brazilian Portuguese translations
- **🇪🇸 Spanish** - Full Spanish localization
- **🇫🇷 French** - Complete French translations
- **🇩🇪 German** - German language support

### Language System Features
- **Dynamic Language Switching** - Change language at runtime
- **Comprehensive Coverage** - All UI elements and explanations
- **Extensible Design** - Easy to add new languages
- **Configuration-based** - All strings externalized to `.ini` files

See [INTERNATIONALIZATION.md](docs/INTERNATIONALIZATION.md) for detailed documentation.

## 🔒 Security Analysis

### Analysis Features
- **Entropy Analysis** - Detects packed or encrypted sections
- **Import Analysis** - Identifies suspicious API usage
- **Section Analysis** - Flags unusual section characteristics
- **Anti-Analysis Detection** - Identifies evasion techniques
- **Digital Signature Validation** - Authenticode verification
- **Risk Scoring** - Comprehensive threat assessment

### Configurable Rules
All security rules are externalized in `config/security_config.ini`:
- Suspicious API lists
- Section name patterns
- Entropy thresholds
- Risk scoring weights

## 🔧 Build Configurations

### Qt-Debug
- **Purpose**: Development and debugging
- **Generator**: Visual Studio 17 2022
- **Build Type**: Debug
- **Features**: Full debugging symbols, runtime checks
- **Use Case**: Daily development, testing, debugging

### Qt-Release
- **Purpose**: Production deployment
- **Generator**: Visual Studio 17 2022
- **Build Type**: Release
- **Features**: Optimized performance, minimal size
- **Use Case**: Final builds, distribution, performance testing

## 🎨 Customization

### Adding New PE Fields
1. **Update** the appropriate parser in `src/pe_*_parser.cpp`
2. **Add** field to `src/pe_data_model.cpp`
3. **Add** explanations to `config/explanations.json`
4. **Update** language files if needed
5. **Rebuild** the project

### Adding New Languages
1. **Create** new language config file (e.g., `language_config_es.ini`)
2. **Translate** all strings from English version
3. **Add** language code to `available_languages` in config
4. **Add** explanations to `explanations.json`
5. **Test** language switching

### Security Rule Customization
1. **Edit** `config/security_config.ini`
2. **Modify** suspicious API lists, thresholds, or patterns
3. **Restart** application to load new configuration
4. **Test** analysis with sample files

### Version Management
- **Update Version**: Edit `src/version.h` with new version numbers
- **Automatic Updates**: Version information automatically propagated to all files
- **Script Support**: Use `update_version.py` for automated version updates

## 🐛 Troubleshooting

### Common Issues

#### "No Qt platform plugin could be initialized"
- **Solution**: Use `Qt-Debug` or `Qt-Release` configuration
- **Cause**: Plugin deployment issues with complex configurations

#### Build Configuration Not Found
- **Solution**: Ensure you're using `Qt-Debug` or `Qt-Release`
- **Alternative**: Use the provided `.bat` files for command-line building

#### Language Not Loading
- **Solution**: Check `config/language_config.ini` for proper language codes
- **Verify**: Language files exist and have correct encoding (UTF-8)

#### Security Analysis Not Working
- **Solution**: Verify `config/security_config.ini` exists and is readable
- **Check**: File permissions and INI file syntax

### Getting Help
1. **Check** the build configuration (should be `Qt-Debug` or `Qt-Release`)
2. **Clean** the build directory and rebuild
3. **Verify** Qt installation path in environment variables
4. **Check** configuration files in `config/` directory
5. **Use** the provided build scripts as fallback

## 📚 Learning Resources

### PE Format Understanding
- **PE File Format**: Microsoft PE/COFF specification
- **Data Directories**: Understanding the 16 standard directories
- **Import/Export Tables**: Dynamic linking mechanisms
- **Section Headers**: Memory layout and characteristics

### Development Resources
- **Qt Development**: Qt 6 documentation and tutorials
- **CMake**: Modern CMake best practices
- **SOLID Principles**: Clean architecture guidelines
- **Internationalization**: Qt's i18n system

### Security Analysis
- **Malware Analysis**: PE-based threat detection
- **Reverse Engineering**: Static analysis techniques
- **Anti-Analysis**: Evasion technique identification
- **Digital Signatures**: Authenticode validation

## 🤝 Contributing

### Development Workflow
1. **Fork** the repository
2. **Create** a feature branch
3. **Follow** SOLID principles and existing architecture
4. **Add** appropriate tests and documentation
5. **Test** with both Qt-Debug and Qt-Release configurations
6. **Submit** a pull request

### Code Standards
- **File Size**: Keep files under 20KB and 500 lines
- **Comments**: Meaningful comments explaining the "why"
- **SOLID Principles**: Follow established architectural patterns
- **Internationalization**: Use `LANG()` macros for all user-facing strings

### Adding Features
- **New PE Fields**: Follow the modular parser pattern
- **Security Rules**: Add to configuration files, not hardcoded
- **UI Elements**: Use `UIManager` and language system
- **Documentation**: Update relevant `.md` files

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Qt Framework** for the excellent GUI framework and internationalization system
- **CMake** for the powerful and flexible build system
- **PE Format Community** for comprehensive documentation and examples
- **SOLID Principles Community** for architectural guidance
- **Open Source Contributors** for inspiration, tools, and feedback

---

**PEHint v0.4.1** - Making PE Header Analysis Accessible, Educational, and Professional

*Built with ❤️ using modern C++, Qt 6, and SOLID architecture principles*