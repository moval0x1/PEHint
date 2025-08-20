# PEHint Build Guide

This guide explains how to build PEHint for different purposes.

## Prerequisites

- **Qt6.8.0** installed at `C:\Qt\6.8.0\msvc2022_64`
- **Visual Studio 2022** with C++ development tools
- **CMake** 3.16 or later
- **Windows 10/11** 64-bit

## Quick Start

### 1. Build Release Version (Recommended for Distribution)

```bash
# Run the batch script
build_release.bat

# Or use PowerShell
.\build_release.ps1
```

This will:
- Build an optimized release version
- Copy all required DLLs and dependencies
- Create a `release/` folder with everything needed
- Generate a README with instructions

### 2. Create Installer Package

```bash
# First build the release, then create installer
build_release.bat
create_installer.bat
```

This creates an `installer/` folder with:
- `install.bat` - Installation script (run as administrator)
- `uninstall.bat` - Uninstallation script
- Complete application package

## Manual Build Process

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

### 3. Copy Dependencies

The build process automatically copies Qt DLLs, but you may need to manually copy:
- `Qt6Core.dll`
- `Qt6Widgets.dll`
- `Qt6Concurrent.dll`
- `Qt6Gui.dll`
- Visual C++ Runtime DLLs

## Distribution Options

### Option 1: Portable Release
- Zip the entire `release/` folder
- Users extract and run `PEHint.exe` directly
- No installation required

### Option 2: Installer Package
- Zip the entire `installer/` folder
- Users run `install.bat` as administrator
- Creates Start Menu entries and desktop shortcuts
- Installs to Program Files

### Option 3: Single Executable
- Use tools like `windeployqt` to create a self-contained executable
- Larger file size but easier distribution

## File Structure

```
release/
├── bin/
│   ├── PEHint.exe          # Main application
│   ├── Qt6Core.dll         # Qt Core library
│   ├── Qt6Widgets.dll      # Qt Widgets library
│   ├── Qt6Concurrent.dll   # Qt Concurrent library
│   ├── Qt6Gui.dll          # Qt GUI library
│   ├── platforms/           # Qt platform plugins (ESSENTIAL)
│   │   └── qwindows.dll    # Windows platform plugin
│   ├── styles/              # Qt style plugins
│   │   └── qwindowsvistastyle.dll
│   ├── imageformats/        # Qt image format plugins
│   │   ├── qjpeg.dll
│   │   ├── qpng.dll
│   │   ├── qico.dll
│   │   └── qwebp.dll
│   ├── msvcp140.dll        # Visual C++ runtime
│   ├── vcruntime140.dll    # Visual C++ runtime
│   └── vcruntime140_1.dll  # Visual C++ runtime
├── resources/               # Application resources
│   ├── explanations.json   # Field explanations
│   └── imgs/               # Icons and images
└── README.txt              # User instructions
```

## Troubleshooting

### Common Issues

1. **Qt not found**: Update the Qt path in build scripts
2. **Build fails**: Ensure Visual Studio C++ tools are installed
3. **Missing DLLs**: Check that all Qt components are copied
4. **Runtime errors**: Verify Visual C++ runtime is included
5. **"No Qt platform plugin could be initialized"**: This error occurs when the `platforms/qwindows.dll` plugin is missing. The updated build scripts now include this essential plugin.

### Critical Dependencies

The following Qt components are **ESSENTIAL** for the application to run:
- **Qt6Core.dll** - Core functionality
- **Qt6Widgets.dll** - GUI widgets
- **Qt6Gui.dll** - Graphics and windowing
- **platforms/qwindows.dll** - Windows platform plugin (prevents "no Qt platform plugin" error)
- **Visual C++ Runtime DLLs** - Required for MSVC-compiled applications

### Verification

After building, test the release:
1. Copy `release/` folder to a clean machine
2. Run `PEHint.exe`
3. Verify all features work correctly
4. Check that resources load properly

## Performance Optimization

The release build includes:
- `/O2` optimization flags
- `/LTCG` link-time code generation
- Stripped debug information
- Optimized Qt libraries

## Security Considerations

- Release builds don't include debug symbols
- No sensitive information in release packages
- Verify all dependencies are from trusted sources

## Support

For build issues:
1. Check the prerequisites
2. Verify Qt installation path
3. Ensure Visual Studio tools are installed
4. Check CMake version compatibility

## Version Information

- **Current Version**: 0.4.1
- **Build System**: CMake
- **Qt Version**: 6.8.0
- **Compiler**: MSVC 2022
- **Target**: Windows 10/11 64-bit
