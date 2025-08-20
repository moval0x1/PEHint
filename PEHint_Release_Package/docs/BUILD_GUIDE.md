# PEHint Build Guide

> **How to build PEHint for different purposes**

## 🚀 Quick Start

### Prerequisites
- **Qt6.8.0** installed at `C:\Qt\6.8.0\msvc2022_64`
- **Visual Studio 2022** with C++ development tools
- **CMake** 3.16 or later
- **Windows 10/11** 64-bit

### Build Commands
```bash
# Debug build (recommended for development)
.\build_vs_qt.bat

# Release build (for distribution)
.\build_release.bat
```

## 🔧 Manual Build

### 1. Configure CMake
```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="C:\Qt\6.8.0\msvc2022_64"
```

### 2. Build Project
```bash
cmake --build . --config Release
```

## 📦 Distribution Options

### Portable Release
- Run `build_release.bat`
- Zip the `release/` folder
- Users extract and run `PEHint.exe`

### Installer Package
- Run `build_release.bat` then `create_installer.bat`
- Creates `installer/` folder with installation scripts

## 🐛 Common Issues

### Qt Not Found
- **Solution**: Update Qt path in build scripts
- **Check**: Qt installation at `C:\Qt\6.8.0\msvc2022_64`

### Missing DLLs
- **Solution**: Use `build_release.bat` (copies all dependencies)
- **Essential**: `platforms/qwindows.dll` prevents "no Qt platform plugin" error

### Build Fails
- **Solution**: Ensure Visual Studio C++ tools are installed
- **Check**: CMake version compatibility

## 📁 Build Output

```
release/
├── bin/PEHint.exe          # Main application
├── Qt6*.dll               # Qt libraries
├── platforms/qwindows.dll  # Essential platform plugin
├── msvcp140.dll           # Visual C++ runtime
└── resources/              # Configuration files
```

## 🔍 Verification

After building:
1. Copy `release/` folder to clean machine
2. Run `PEHint.exe`
3. Verify all features work correctly
4. Check resources load properly

---

**Need help?** Check the main developer guide or create an issue.
