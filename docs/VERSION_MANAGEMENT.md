# Version Management in PEHint

> **How to update version numbers in PEHint**

## 🎯 Quick Update

### Method 1: Manual Update
1. Edit `src/version.h`
2. Update version numbers
3. Rebuild project

### Method 2: Using Script (Recommended)
```bash
# Update to version 0.4.0
python update_version.py 0.4.0

# Preview changes without making them
python update_version.py 0.4.0 --dry-run
```

## 📝 Version File

### `src/version.h`
```cpp
#define PEHINT_VERSION_MAJOR 0
#define PEHINT_VERSION_MINOR 4
#define PEHINT_VERSION_PATCH 0

#define PEHINT_VERSION_STRING "0.4.0"
#define PEHINT_VERSION_STRING_FULL "v0.4.0"
```

## 🔧 How It Works

1. **Version Definition** - All numbers in `src/version.h`
2. **CMake Integration** - Automatically reads version header
3. **Resource Configuration** - Updates `app.rc` with version
4. **Code Usage** - Include `version.h` and use macros

## 📚 Available Macros

```cpp
#include "version.h"

// Numeric versions
PEHINT_VERSION_MAJOR    // 0
PEHINT_VERSION_MINOR    // 4
PEHINT_VERSION_PATCH    // 0

// String versions
PEHINT_VERSION_STRING       // "0.4.0"
PEHINT_VERSION_STRING_FULL  // "v0.4.0"

// Version comparison
PEHINT_VERSION_AT_LEAST(0, 4, 0)  // true
PEHINT_VERSION_EQUAL(0, 4, 0)     // true
```

## 🎨 Usage Examples

### Window Title
```cpp
setWindowTitle(QString("PEHint %1 - PE Header Learning Tool")
               .arg(PEHINT_VERSION_STRING_FULL));
```

### About Dialog
```cpp
QString version = QString("Version: %1").arg(PEHINT_VERSION_STRING);
```

## 🐛 Troubleshooting

### Version Not Updating
1. **Rebuild** project after changing `version.h`
2. **Check** that `version.h` is included in source files
3. **Verify** CMake is reading version correctly

### Build Errors
1. **Ensure** `version.h` exists in `src/` directory
2. **Check** version format is correct
3. **Verify** CMake can parse version numbers

## 📋 Version Convention

- **MAJOR** - Breaking changes, major features
- **MINOR** - New features, backward compatible
- **PATCH** - Bug fixes, minor improvements

---

**Need help?** Check the main developer guide or create an issue.
