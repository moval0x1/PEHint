# PEHint Internationalization Guide

> **How to add new languages to PEHint**

## 🌍 Quick Start

### 1. Create Language File
Create `config/language_config_XX.ini` where `XX` is the language code:

```ini
[General]
default_language=es
available_languages=es,en,pt

[UI]
window_title=PEHint {version} - Herramienta de Aprendizaje
status_ready=Listo
button_open=Abrir
```

### 2. Update Language Manager
Add to `src/language_manager.cpp`:

```cpp
m_languageNames["es"] = "Español";
```

### 3. Test
Restart application and verify language switching works.

## 📝 Language File Structure

### Required Sections
- **`[General]`** - Language configuration
- **`[UI]`** - User interface strings
- **`[Error]`** - Error messages
- **`[Progress]`** - Progress indicators

### String Format
```ini
[UI]
file_info=Archivo: {filename} | Tamaño: {size}
```

## 🔧 Parameter Substitution

### Single Parameter
```cpp
QString message = LANG_PARAM("UI/file_info", "filename", "example.exe");
```

### Multiple Parameters
```cpp
QMap<QString, QString> params;
params["filename"] = "example.exe";
params["size"] = "1.5 MB";
QString info = LANG_PARAMS("UI/file_info", params);
```

## 📚 Available Macros

- **`LANG(key)`** - Get localized string
- **`LANG_PARAM(key, paramName, paramValue)`** - Single parameter
- **`LANG_PARAMS(key, params)`** - Multiple parameters

## 🎯 Best Practices

1. **Keep keys consistent** across all languages
2. **Use descriptive names** for string keys
3. **Test thoroughly** with native speakers
4. **Maintain UTF-8 encoding** for special characters

## 🐛 Troubleshooting

### Common Issues
- **Strings not updating** - Call `updateUILanguage()` after changes
- **Missing translations** - Verify all keys exist in language file
- **Encoding problems** - Ensure UTF-8 encoding

---

**Need help?** Check the main developer guide or create an issue.
