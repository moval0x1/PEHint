# Version Management in PEHint

This document explains how version numbers are managed in the PEHint project.

## Overview

PEHint now uses a centralized version management system where all version information is stored in a single file (`src/version.h`) and automatically propagated throughout the project.

## Files Involved

- **`src/version.h`** - Central version definitions (MAJOR, MINOR, PATCH)
- **`CMakeLists.txt`** - Reads version from header and configures project
- **`resources/app.rc`** - Windows resource file with version placeholders
- **`update_version.py`** - Script to update version numbers

## How It Works

1. **Version Definition**: All version numbers are defined in `src/version.h`
2. **CMake Integration**: CMake reads the version header and sets project version
3. **Resource Configuration**: CMake configures `app.rc` with actual version numbers
4. **Code Usage**: C++ code includes `version.h` and uses version macros

## Version Macros Available

```cpp
#include "version.h"

// Numeric versions
PEHINT_VERSION_MAJOR    // 0
PEHINT_VERSION_MINOR    // 4
PEHINT_VERSION_PATCH    // 1

// String versions
PEHINT_VERSION_STRING       // "0.4.1"
PEHINT_VERSION_STRING_FULL  // "v0.4.1"

// Build information
PEHINT_BUILD_DATE           // __DATE__ macro
PEHINT_BUILD_TIME           // __TIME__ macro

// Version comparison
PEHINT_VERSION_AT_LEAST(0, 4, 0)  // true
PEHINT_VERSION_EQUAL(0, 4, 1)     // true
```

## Updating Version Numbers

### Method 1: Manual Update
1. Edit `src/version.h`
2. Update the version numbers
3. Rebuild the project

### Method 2: Using the Update Script (Recommended)
```bash
# Update to version 0.4.2
python update_version.py 0.4.2

# Preview changes without making them
python update_version.py 0.4.2 --dry-run
```

## Benefits

1. **Single Source of Truth**: Version is defined in one place
2. **Automatic Propagation**: CMake automatically updates all files
3. **Consistency**: All version references stay in sync
4. **Easy Updates**: Simple script to update versions
5. **Build Integration**: Version is automatically embedded in executables

## Version Numbering Convention

- **MAJOR**: Breaking changes, major feature additions
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, minor improvements

## Example Usage in Code

```cpp
// Window title
setWindowTitle(QString("PEHint %1 - PE Header Learning Tool")
               .arg(PEHINT_VERSION_STRING_FULL));

// About dialog
QString version = QString("Version: %1").arg(PEHINT_VERSION_STRING);

// Conditional compilation
#if PEHINT_VERSION_AT_LEAST(0, 4, 0)
    // Use features available in 0.4.0+
#endif
```

## Troubleshooting

### Version Not Updating
1. Make sure you've rebuilt the project after changing `version.h`
2. Check that `version.h` is included in your source files
3. Verify CMake is reading the version correctly

### Build Errors
1. Ensure `version.h` exists in the `src/` directory
2. Check that the version format in `version.h` is correct
3. Verify CMake can parse the version numbers

## Migration from Hardcoded Versions

If you find any remaining hardcoded version numbers in the codebase:

1. Replace them with the appropriate version macro
2. Include `version.h` in the file
3. Test that the version displays correctly

Example:
```cpp
// OLD (hardcoded)
setWindowTitle("PEHint v0.4.1 - PE Header Learning Tool");

// NEW (using version header)
#include "version.h"
setWindowTitle(QString("PEHint %1 - PE Header Learning Tool")
               .arg(PEHINT_VERSION_STRING_FULL));
```
