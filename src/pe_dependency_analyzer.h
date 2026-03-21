/**
 * @file pe_dependency_analyzer.h
 * @brief PE Dependency Analyzer - Analyzes DLL dependencies of PE files
 */

#ifndef PE_DEPENDENCY_ANALYZER_H
#define PE_DEPENDENCY_ANALYZER_H

#include <QString>
#include <QStringList>
#include <QList>

/**
 * @brief Single dependency entry (imported module)
 */
struct DependencyEntry {
    QString moduleName;      ///< DLL name (e.g. kernel32.dll)
    QString resolvedPath;    ///< Full path if found on system
    bool foundOnSystem = false; ///< True if DLL was located in search paths
};

/**
 * @brief Tree node for transitive dependency view
 */
struct DependencyNode {
    QString moduleName;        ///< Imported module name
    QString resolvedPath;      ///< Resolved absolute path (if found)
    bool foundOnSystem = false;
    bool cycleDetected = false;   ///< True when this edge closes a cycle
    bool truncatedByDepth = false;///< True when max recursion depth was reached
    int depth = 0;                ///< Root=0, child=1...
    QList<DependencyNode> children;
};

/**
 * @brief Result of dependency analysis
 */
struct DependencyAnalysisResult {
    QList<DependencyEntry> dependencies;
    QList<DependencyNode> dependencyTree; ///< Optional transitive dependency tree
    QStringList searchPaths;   ///< Paths that were searched
    /// True when an embedded RT_MANIFEST resource or a sidecar .manifest was read for extra paths
    bool manifestParsed = false;
};

/**
 * @brief Analyzes PE import table to list dependencies and optionally resolve paths
 */
class PEDependencyAnalyzer
{
public:
    PEDependencyAnalyzer() = default;

    /**
     * @brief Analyze dependencies from a list of import module names
     * @param importModules List of DLL names from the PE import table
     * @param peFilePath Optional path to the PE file (used to search alongside it)
     * @return Analysis result with dependency list and optional resolved paths
     */
    static DependencyAnalysisResult analyze(const QStringList &importModules,
                                           const QString &peFilePath = QString());

    /**
     * @brief Analyze dependencies recursively up to maxDepth with cycle detection
     * @param importModules Root DLL names from the PE import table
     * @param peFilePath Optional PE path (adds PE directory to search order)
     * @param maxDepth Maximum recursion depth (0 = roots only)
     * @return Analysis result including dependencyTree
     */
    static DependencyAnalysisResult analyzeTransitive(const QStringList &importModules,
                                                      const QString &peFilePath = QString(),
                                                      int maxDepth = 2);

    /**
     * @brief Check whether a DLL is found in system search paths
     * @param moduleName DLL name (e.g. kernel32.dll)
     * @param searchPaths Optional custom paths; if empty, uses default system paths
     * @return Full path if found, empty string otherwise
     */
    static QString resolveDependencyPath(const QString &moduleName,
                                         const QStringList &searchPaths = QStringList());

    /**
     * @brief Extra DLL search directories derived from an application manifest (UTF-8 XML).
     * @param manifestXmlUtf8 Full manifest text (embedded or sidecar).
     * @param exeDirectory Directory containing the PE (for privatePath probing segments).
     * @param windowsRoot Typically %SystemRoot% (e.g. C:\\Windows); WinSxS is scanned under windowsRoot\\WinSxS.
     * @return Additional directories to search after the executable directory (no duplicates).
     */
    static QStringList extraSearchPathsFromManifestXml(const QString &manifestXmlUtf8,
                                                       const QString &exeDirectory,
                                                       const QString &windowsRoot);
};

#endif // PE_DEPENDENCY_ANALYZER_H
