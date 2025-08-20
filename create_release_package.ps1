# PEHint Release Package Creator
# PowerShell Script

# Set up error logging
$LogFile = "create_release_package_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorLogFile = "create_release_package_errors_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage -ForegroundColor White }
    }
    
    # Write to log file
    $logMessage | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Write-ErrorLog {
    param([string]$Message, [string]$Details = "")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $errorMessage = "[$timestamp] ERROR: $Message"
    
    if ($Details) {
        $errorMessage += "`nDetails: $Details"
    }
    
    # Write to error log file
    $errorMessage | Out-File -FilePath $ErrorLogFile -Append -Encoding UTF8
    
    # Also write to main log
    Write-Log $Message "ERROR"
}

# Start logging
Write-Log "=== PEHint Release Package Creation Started ===" "SUCCESS"
Write-Log "Log file: $LogFile"
Write-Log "Error log file: $ErrorLogFile"
Write-Log "Script version: 2.0"
Write-Log "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Working directory: $(Get-Location)"
Write-Log "PowerShell version: $($PSVersionTable.PSVersion)"
Write-Log "OS: $([System.Environment]::OSVersion.VersionString)"
Write-Log ""

Write-Host "Creating PEHint Release Package..." -ForegroundColor Green
Write-Host "Log files: $LogFile (main), $ErrorLogFile (errors)" -ForegroundColor Cyan
Write-Host ""

# Set paths
$QtPath = "C:\Qt\6.8.0\msvc2022_64"
$BuildDir = "out\build\qt-release"
$PackageDir = "PEHint_Release_Package"

# Clean previous package
if (Test-Path $PackageDir) {
    Remove-Item -Recurse -Force $PackageDir
}
New-Item -ItemType Directory -Path $PackageDir | Out-Null

# Clean build directory to ensure fresh build
Write-Host "Cleaning build directory..." -ForegroundColor Yellow
if (Test-Path $BuildDir) {
    Remove-Item -Recurse -Force $BuildDir
    Write-Host "Build directory cleaned" -ForegroundColor Green
}

# Also clean any existing out directory to ensure complete fresh start
$outDir = "out"
if (Test-Path $outDir) {
    Write-Host "Cleaning entire out directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $outDir
    Write-Host "Out directory cleaned" -ForegroundColor Green
}

Write-Host "Building release version..." -ForegroundColor Yellow
Write-Host "Build directory: $BuildDir" -ForegroundColor Cyan
Write-Host "CMake preset: qt-release" -ForegroundColor Cyan

# Check environment variables that might affect build
Write-Host "Checking environment variables..." -ForegroundColor Cyan
$envVars = @("CMAKE_BUILD_TYPE", "CMAKE_CONFIGURATION_TYPES", "BUILD_TYPE")
foreach ($var in $envVars) {
    if (Get-Variable -Name $var -ErrorAction SilentlyContinue) {
        Write-Host "  $var = $(Get-Variable -Name $var -ValueOnly)" -ForegroundColor Gray
    } elseif (Get-ChildItem -Path "env:$var" -ErrorAction SilentlyContinue) {
        Write-Host "  $var = $env:$var" -ForegroundColor Gray
    }
}

# Configure
Write-Host "Configuring with qt-release preset..." -ForegroundColor Yellow

# Verify preset exists
$presetFile = "CMakePresets.json"
if (Test-Path $presetFile) {
    Write-Host "CMakePresets.json found" -ForegroundColor Green
    $presetContent = Get-Content $presetFile | ConvertFrom-Json
    $releasePreset = $presetContent.configurePresets | Where-Object { $_.name -eq "qt-release" }
    if ($releasePreset) {
        Write-Host "qt-release preset found with build type: $($releasePreset.cacheVariables.CMAKE_BUILD_TYPE)" -ForegroundColor Green
    } else {
        Write-Host "qt-release preset not found!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "CMakePresets.json not found!" -ForegroundColor Red
    exit 1
}

$configResult = cmake --preset qt-release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Configuration failed!" -ForegroundColor Red
    Read-Host "Press Enter to continue"
    exit 1
}

# Double-check configuration by explicitly setting build type
Write-Host "Reconfiguring to ensure Release build type..." -ForegroundColor Yellow
$reconfigResult = cmake -B $BuildDir -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Reconfiguration failed!" -ForegroundColor Red
    Read-Host "Press Enter to continue"
    exit 1
}

# For Visual Studio generator, also set configuration types
Write-Host "Setting Visual Studio configuration types..." -ForegroundColor Yellow
$vsConfigResult = cmake -B $BuildDir -DCMAKE_CONFIGURATION_TYPES=Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Visual Studio configuration failed!" -ForegroundColor Red
    Read-Host "Press Enter to continue"
    exit 1
}

# Verify the configuration
Write-Host "Verifying CMake configuration..." -ForegroundColor Yellow
$cacheFile = "$BuildDir\CMakeCache.txt"
if (Test-Path $cacheFile) {
    $buildType = Get-Content $cacheFile | Select-String "CMAKE_BUILD_TYPE:STRING="
    if ($buildType) {
        Write-Host "CMake build type: $buildType" -ForegroundColor Cyan
    }
    
    $generator = Get-Content $cacheFile | Select-String "CMAKE_GENERATOR:INTERNAL="
    if ($generator) {
        Write-Host "CMake generator: $generator" -ForegroundColor Cyan
    }
    
    # Check for any build type related variables
    $allBuildTypeVars = Get-Content $cacheFile | Select-String "CMAKE_BUILD_TYPE"
    if ($allBuildTypeVars) {
        Write-Host "All build type variables:" -ForegroundColor Cyan
        $allBuildTypeVars | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
    
    # Check for Visual Studio specific variables
    $vsVars = Get-Content $cacheFile | Select-String "CMAKE_CONFIGURATION_TYPES"
    if ($vsVars) {
        Write-Host "Visual Studio configuration types: $vsVars" -ForegroundColor Cyan
    }
    
    # Check Qt configuration
    $qtVars = Get-Content $cacheFile | Select-String "Qt6"
    if ($qtVars) {
        Write-Host "Qt6 configuration variables:" -ForegroundColor Cyan
        $qtVars | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
} else {
    Write-Host "Warning: CMakeCache.txt not found" -ForegroundColor Yellow
}

# Build
Write-Host "Building with --config Release..." -ForegroundColor Yellow
$buildResult = cmake --build --preset qt-release --config Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    Write-Host "Build output:" -ForegroundColor Red
    $buildResult | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    Read-Host "Press Enter to continue"
    exit 1
}

Write-Host "Build completed successfully" -ForegroundColor Green

# Alternative build method if the preset method doesn't work
if (-not (Test-Path "$BuildDir\bin\Release\PEHint.exe")) {
    Write-Host "Preset build didn't create Release executable, trying direct build..." -ForegroundColor Yellow
    $directBuildResult = cmake --build $BuildDir --config Release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Direct build also failed!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        exit 1
    }
}

# Check if the build actually completed
Write-Host "Checking build completion..." -ForegroundColor Yellow
$buildLogFile = "$BuildDir\CMakeFiles\CMakeOutput.log"
if (Test-Path $buildLogFile) {
    $lastBuildLine = Get-Content $buildLogFile | Select-Object -Last 10
    Write-Host "Last 10 lines of build log:" -ForegroundColor Gray
    $lastBuildLine | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

# If still no Release executable, try to force the configuration
if (-not (Test-Path "$BuildDir\bin\Release\PEHint.exe")) {
    Write-Host "Still no Release executable, trying to force Release configuration..." -ForegroundColor Yellow
    
    # Check if this is a multi-config build
    $configTypes = Get-Content $cacheFile | Select-String "CMAKE_CONFIGURATION_TYPES:INTERNAL="
    if ($configTypes -and $configTypes -match "Debug;Release") {
        Write-Host "Multi-config build detected, setting Release as default..." -ForegroundColor Cyan
        $forceConfigResult = cmake -B $BuildDir -DCMAKE_BUILD_TYPE=Release -DCMAKE_CONFIGURATION_TYPES=Release
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Configuration updated, trying build again..." -ForegroundColor Yellow
            $retryBuildResult = cmake --build $BuildDir --config Release
        }
    }
}

# Verify the build output
Write-Host "Verifying build output..." -ForegroundColor Yellow
$releaseExe = "$BuildDir\bin\Release\PEHint.exe"
$debugExe = "$BuildDir\bin\Debug\PEHint.exe"

Write-Host "Checking for existing build artifacts..." -ForegroundColor Cyan
Get-ChildItem -Path $BuildDir -Recurse -Name "*.exe" | ForEach-Object {
    Write-Host "  Found executable: $_" -ForegroundColor Gray
}

if (Test-Path $releaseExe) {
    Write-Host "✓ Release executable found at: $releaseExe" -ForegroundColor Green
    $fileInfo = Get-Item $releaseExe
    Write-Host "  File size: $($fileInfo.Length) bytes" -ForegroundColor Gray
    Write-Host "  Created: $($fileInfo.CreationTime)" -ForegroundColor Gray
} else {
    Write-Host "✗ Release executable NOT found at: $releaseExe" -ForegroundColor Red
}

if (Test-Path $debugExe) {
    Write-Host "⚠ Debug executable found at: $debugExe" -ForegroundColor Yellow
    $fileInfo = Get-Item $debugExe
    Write-Host "  File size: $($fileInfo.Length) bytes" -ForegroundColor Gray
    Write-Host "  Created: $($fileInfo.CreationTime)" -ForegroundColor Gray
} else {
    Write-Host "✓ No debug executable found (as expected)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Deploying Qt dependencies..." -ForegroundColor Yellow

# Check if the Release executable exists before deploying
if (Test-Path "$BuildDir\bin\Release\PEHint.exe") {
    Write-Host "Release executable found, deploying Qt dependencies..." -ForegroundColor Green
    # Deploy Qt dependencies
    & "$QtPath\bin\windeployqt.exe" --release --compiler-runtime --no-translations --dir "$BuildDir\bin\Release" "$BuildDir\bin\Release\PEHint.exe"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Qt deployment failed!" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        exit 1
    }
} else {
    Write-Host "Release executable not found, cannot deploy Qt dependencies!" -ForegroundColor Red
    Write-Host "Checking what executables exist:" -ForegroundColor Yellow
    Get-ChildItem -Path "$BuildDir\bin" -Recurse -Name "*.exe" | ForEach-Object {
        Write-Host "  Found: $_" -ForegroundColor Gray
    }
    Read-Host "Press Enter to continue"
    exit 1
}

Write-Host ""
Write-Host "Copying application files..." -ForegroundColor Yellow

# Verify source files exist before copying
$sourceExe = "$BuildDir\bin\Release\PEHint.exe"
$sourceDlls = "$BuildDir\bin\Release\*.dll"

if (Test-Path $sourceExe) {
    Write-Host "Copying main executable..." -ForegroundColor Green
    Copy-Item $sourceExe $PackageDir
    if (Test-Path "$PackageDir\PEHint.exe") {
        Write-Host "✓ Executable copied successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Executable copy failed!" -ForegroundColor Red
    }
} else {
    Write-Host "✗ Source executable not found: $sourceExe" -ForegroundColor Red
}

# Copy DLLs
$dllFiles = Get-ChildItem -Path "$BuildDir\bin\Release" -Filter "*.dll"
if ($dllFiles) {
    Write-Host "Copying $($dllFiles.Count) DLL files..." -ForegroundColor Green
    Copy-Item $sourceDlls $PackageDir
    $copiedDlls = Get-ChildItem -Path $PackageDir -Filter "*.dll"
    Write-Host "✓ Copied $($copiedDlls.Count) DLL files" -ForegroundColor Green
} else {
    Write-Host "⚠ No DLL files found to copy" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Copying Qt plugins and dependencies..." -ForegroundColor Yellow

# Copy Qt plugin directories
$pluginDirs = @("platforms", "iconengines", "imageformats", "styles", "generic", "networkinformation", "tls")
$copiedPlugins = 0

foreach ($dir in $pluginDirs) {
    $sourcePath = "$BuildDir\bin\Release\$dir"
    $destPath = "$PackageDir\$dir"
    
    if (Test-Path $sourcePath) {
        Write-Host "Copying $dir plugin..." -ForegroundColor Green
        Copy-Item $sourcePath $destPath -Recurse -Force
        if (Test-Path $destPath) {
            $copiedPlugins++
            Write-Host "✓ $dir plugin copied successfully" -ForegroundColor Green
        } else {
            Write-Host "✗ $dir plugin copy failed!" -ForegroundColor Red
        }
    } else {
        Write-Host "⚠ $dir plugin directory not found: $sourcePath" -ForegroundColor Yellow
    }
}

Write-Host "✓ Copied $copiedPlugins Qt plugin directories" -ForegroundColor Green

Write-Host ""
Write-Host "Copying configuration files..." -ForegroundColor Yellow

# Copy config directory
if (Test-Path "config") {
    Write-Host "Copying configuration files..." -ForegroundColor Green
    Copy-Item "config" $PackageDir -Recurse -Force
    if (Test-Path "$PackageDir\config") {
        $configFiles = Get-ChildItem -Path "$PackageDir\config" -Recurse
        Write-Host "✓ Configuration files copied successfully ($($configFiles.Count) files)" -ForegroundColor Green
    } else {
        Write-Host "✗ Configuration files copy failed!" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ Configuration directory not found: config" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Copying documentation..." -ForegroundColor Yellow

# Copy docs directory
if (Test-Path "docs") {
    Write-Host "Copying documentation files..." -ForegroundColor Green
    Copy-Item "docs" $PackageDir -Recurse -Force
    if (Test-Path "$PackageDir\docs") {
        $docFiles = Get-ChildItem -Path "$PackageDir\docs" -Recurse
        Write-Host "✓ Documentation files copied successfully ($($docFiles.Count) files)" -ForegroundColor Green
    } else {
        Write-Host "✗ Documentation files copy failed!" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ Documentation directory not found: docs" -ForegroundColor Yellow
}

# Copy README
if (Test-Path "README.md") {
    Write-Host "Copying README..." -ForegroundColor Green
    Copy-Item "README.md" $PackageDir
    if (Test-Path "$PackageDir\README.md") {
        Write-Host "✓ README copied successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ README copy failed!" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ README file not found: README.md" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Creating version info file..." -ForegroundColor Yellow

# Create version info
$versionInfo = @"
PEHint Release Package
Built on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Build Type: Release
Qt Version: 6.8.0
Compiler: MSVC 2022
"@

$versionInfo | Out-File "$PackageDir\VERSION.txt" -Encoding UTF8
if (Test-Path "$PackageDir\VERSION.txt") {
    Write-Host "✓ Version info file created successfully" -ForegroundColor Green
    $versionContent = Get-Content "$PackageDir\VERSION.txt"
    Write-Host "Version info content:" -ForegroundColor Gray
    $versionContent | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
    Write-Host "✗ Version info file creation failed!" -ForegroundColor Red
}

Write-Host ""
Write-Host "Package created successfully in: $PackageDir" -ForegroundColor Green
Write-Host ""

# Verify package integrity
Write-Host "Verifying package integrity..." -ForegroundColor Yellow
$packageFiles = Get-ChildItem $PackageDir -Recurse
$totalFiles = $packageFiles.Count
$totalSize = ($packageFiles | Measure-Object -Property Length -Sum).Sum

Write-Host "Package statistics:" -ForegroundColor Cyan
Write-Host "  Total files: $totalFiles" -ForegroundColor Gray
Write-Host "  Total size: $([math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor Gray

# Check for critical files
$criticalFiles = @("PEHint.exe", "config", "docs")
$missingFiles = @()

foreach ($file in $criticalFiles) {
    if (Test-Path "$PackageDir\$file") {
        Write-Host "✓ $file found" -ForegroundColor Green
    } else {
        Write-Host "✗ $file missing!" -ForegroundColor Red
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "⚠ Missing critical files: $($missingFiles -join ', ')" -ForegroundColor Yellow
} else {
    Write-Host "✓ All critical files present" -ForegroundColor Green
}

Write-Host ""
# Show package contents
Write-Host "Package contents:" -ForegroundColor Cyan
Get-ChildItem $PackageDir -Recurse | ForEach-Object {
    $indent = "  " * ($_.FullName.Split('\').Count - $PackageDir.Split('\').Count)
    Write-Host "$indent$($_.Name)" -ForegroundColor White
}

Write-Host ""
Read-Host "Press Enter to continue"
