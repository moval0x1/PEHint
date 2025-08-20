# PEHint Internationalization Guide

This document explains how to use the internationalization (i18n) system implemented in PEHint to support multiple languages.

## Overview

PEHint now supports multiple languages through a centralized `LanguageManager` class that provides:
- Dynamic language switching at runtime
- Configuration-based string management
- Support for Qt's built-in translation system
- Parameter substitution in strings
- Fallback to default language

## Architecture

### Language Manager (`LanguageManager`)

The `LanguageManager` class is implemented as a singleton that:
- Loads language configurations from INI files
- Manages Qt translators for runtime language switching
- Provides convenient macros for string retrieval
- Handles parameter substitution in strings

### Configuration Files

Language strings are stored in INI configuration files:
- `config/language_config.ini` - Default English language
- `config/language_config_pt.ini` - Portuguese language (example)
- Additional language files can be created following the same pattern

### String Keys

Strings are organized in sections with descriptive keys:
```ini
[UI]
window_title=PEHint {version} - PE Header Learning Tool
status_ready=Ready
button_open=Open

[Error]
file_not_found=File not found: {filepath}
```

## Usage

### 1. Basic String Retrieval

Use the `LANG()` macro to get localized strings:

```cpp
#include "language_manager.h"

// Get a simple string
QString title = LANG("UI/window_title");

// Get a string with parameter substitution
QString message = LANG_PARAM("UI/file_info", "filename", "example.exe");
```

### 2. Parameter Substitution

Strings can contain placeholders for dynamic values:

```ini
[UI]
file_info=File: {filename} | Size: {size} | Type: {type}
```

```cpp
QMap<QString, QString> params;
params["filename"] = "example.exe";
params["size"] = "1.5 MB";
params["type"] = "PE Executable";

QString info = LANG_PARAMS("UI/file_info", params);
// Result: "File: example.exe | Size: 1.5 MB | Type: PE Executable"
```

### 3. Available Macros

- `LANG(key)` - Get a localized string
- `LANG_PARAM(key, paramName, paramValue)` - Get string with single parameter
- `LANG_PARAMS(key, params)` - Get string with multiple parameters

### 4. Language Switching

Languages can be changed at runtime:

```cpp
// Switch to Portuguese
LanguageManager::getInstance().setLanguage("pt");

// Get current language
QString currentLang = LanguageManager::getInstance().getCurrentLanguage();

// Get available languages
QStringList languages = LanguageManager::getInstance().getAvailableLanguages();
```

## Adding New Languages

### 1. Create Language Configuration File

Create a new file `config/language_config_XX.ini` where `XX` is the language code:

```ini
[General]
default_language=es
available_languages=es,en,pt

[UI]
window_title=PEHint {version} - Herramienta de Aprendizaje de Encabezado PE
status_ready=Listo
button_open=Abrir
```

### 2. Update Language Manager

Add the new language to the `LanguageManager` constructor:

```cpp
LanguageManager::LanguageManager()
{
    m_languageNames["en"] = "English";
    m_languageNames["pt"] = "Português";
    m_languageNames["es"] = "Español";  // Add new language
    // ... other languages
}
```

### 3. Update Main Configuration

Add the new language to the available languages list in `config/language_config.ini`:

```ini
[General]
default_language=en
available_languages=en,pt,es,fr,de
```

## String Categories

### UI Strings
- Window titles, button labels, menu items
- Status messages, tooltips, placeholders
- Tree headers, form labels

### Error Messages
- File loading errors, parsing errors
- Validation failures, system errors

### Progress Messages
- File loading progress, parsing steps
- Async operation status

### PE-Specific Strings
- Machine types, subsystems, characteristics
- Resource types, section names
- Import/export information

## Best Practices

### 1. String Organization
- Group related strings in logical sections
- Use descriptive, hierarchical keys
- Keep keys consistent across languages

### 2. Parameter Usage
- Use placeholders for dynamic values: `{filename}`, `{size}`
- Document parameter names and expected values
- Provide meaningful default values

### 3. Translation Quality
- Ensure translations are accurate and contextually appropriate
- Consider cultural differences in terminology
- Test with native speakers when possible

### 4. Performance
- Language switching triggers UI updates
- Cache frequently used strings if needed
- Minimize string lookups in performance-critical code

## Example: Adding German Support

### 1. Create German Configuration

```ini
# config/language_config_de.ini
[General]
default_language=de
available_languages=de,en,pt,es

[UI]
window_title=PEHint {version} - PE-Header Lernwerkzeug
status_ready=Bereit
button_open=Öffnen
file_info=Datei: {filename} | Größe: {size} | Typ: PE-Ausführbare Datei

[Error]
file_not_found=Datei nicht gefunden: {filepath}
parsing_error=PE-Parsing-Fehler
```

### 2. Update Language Manager

```cpp
m_languageNames["de"] = "Deutsch";
```

### 3. Test Language Switching

```cpp
// Switch to German
LanguageManager::getInstance().setLanguage("de");

// Verify strings are updated
QString title = LANG("UI/window_title");
// Result: "PEHint 0.3.1 - PE-Header Lernwerkzeug"
```

## Troubleshooting

### Common Issues

1. **Strings not updating**: Ensure `updateUILanguage()` is called after language changes
2. **Missing translations**: Check that all keys exist in the language configuration file
3. **Parameter errors**: Verify parameter names match between string and substitution call
4. **Build errors**: Ensure `language_manager.h` and `language_manager.cpp` are in CMakeLists.txt

### Debug Information

Enable debug output to see language loading:

```cpp
// In LanguageManager::initialize()
qDebug() << "Loaded" << m_strings.size() << "strings from language configuration";
```

### Validation

Use the `hasString()` method to check if keys exist:

```cpp
if (LanguageManager::getInstance().hasString("UI/window_title")) {
    // Key exists
} else {
    // Key missing
}
```

## Future Enhancements

### Planned Features
- Qt Linguist (.ts) file support for professional translations
- Automatic language detection based on system locale
- Language-specific formatting (dates, numbers, currencies)
- RTL language support (Arabic, Hebrew)

### Integration Points
- Qt's built-in translation system
- Professional translation services
- Community translation contributions
- Automated translation quality checks

## Conclusion

The PEHint internationalization system provides a flexible, maintainable way to support multiple languages. By following the established patterns and best practices, developers can easily add new languages and maintain consistent user experience across different locales.

For questions or contributions, please refer to the main project documentation or contact the development team.
