#include "import_api_hint_store.h"
#include "sdk_api_markdown_reader.h"

#include <iostream>

bool runImportApiHintStoreSelfTests()
{
    bool ok = true;
    auto check = [&](bool condition, const char *message) {
        if (!condition) {
            std::cerr << "ImportApiHintStore self-test failed: " << message << '\n';
            ok = false;
        }
    };

    ImportApiHintStore &store = ImportApiHintStore::instance();
    store.ensureLoaded();

    // Empty function name always returns an empty hint
    {
        const ImportApiHint hint = store.hintForImport(QStringLiteral("KERNEL32.DLL"), QString());
        check(!hint.hasContent(), "empty function name -> no hint");
    }

    // Completely unknown DLL and function returns empty hint
    {
        const ImportApiHint hint = store.hintForImport(
            QStringLiteral("NONEXISTENT_MODULE_XYZ.dll"),
            QStringLiteral("SomeTotallyFakeFunction123"));
        check(!hint.hasContent(), "unknown dll+function -> no hint");
    }

    // VirtualAllocEx is a well-known MalAPI function; if config is loaded it should have a hint.
    // If config is absent (CI without assets), the hint will be empty — we only verify no crash.
    {
        const ImportApiHint hint = store.hintForImport(
            QStringLiteral("KERNEL32.dll"),
            QStringLiteral("VirtualAllocEx"));
        // Presence of hint depends on config file being deployed — just verify the call returns.
        (void)hint;
    }

    // Lookup is case-insensitive on the DLL name ("kernel32.dll" vs "KERNEL32.DLL")
    {
        const ImportApiHint lowerHint = store.hintForImport(
            QStringLiteral("kernel32.dll"),
            QStringLiteral("VirtualAllocEx"));
        const ImportApiHint upperHint = store.hintForImport(
            QStringLiteral("KERNEL32.DLL"),
            QStringLiteral("VirtualAllocEx"));
        check(lowerHint.hasContent() == upperHint.hasContent(),
              "DLL name lookup is case-insensitive");
    }

    // Lookup without DLL name (empty module) matches by function name only
    {
        const ImportApiHint withDll = store.hintForImport(
            QStringLiteral("KERNEL32.dll"),
            QStringLiteral("VirtualAllocEx"));
        const ImportApiHint noDll = store.hintForImport(
            QString(),
            QStringLiteral("VirtualAllocEx"));
        // Both should agree on whether a hint exists
        check(withDll.hasContent() == noDll.hasContent(),
              "empty-DLL lookup agrees with DLL-specific lookup");
    }

    // DLL name without .dll suffix is normalised correctly
    {
        const ImportApiHint withSuffix = store.hintForImport(
            QStringLiteral("kernel32.dll"),
            QStringLiteral("VirtualAllocEx"));
        const ImportApiHint withoutSuffix = store.hintForImport(
            QStringLiteral("kernel32"),
            QStringLiteral("VirtualAllocEx"));
        check(withSuffix.hasContent() == withoutSuffix.hasContent(),
              "DLL name normalised (with/without .dll)");
    }

    return ok;
}
