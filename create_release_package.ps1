# PEHint Release Package Creator
# PowerShell Script

Write-Host "Creating PEHint Release Package..." -ForegroundColor Green
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

Write-Host "Building release version..." -ForegroundColor Yellow
# Configure
$configResult = cmake --preset qt-release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Configuration failed!" -ForegroundColor Red
    Read-Host "Press Enter to continue"
    exit 1
}

# Build
$buildResult = cmake --build --preset qt-release --config Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    Read-Host "Press Enter to continue"
    exit 1
}

Write-Host ""
Write-Host "Deploying Qt dependencies..." -ForegroundColor Yellow
# Deploy Qt dependencies
& "$QtPath\bin\windeployqt.exe" --release --compiler-runtime --no-translations --dir "$BuildDir\bin\Release" "$BuildDir\bin\Release\PEHint.exe"

Write-Host ""
Write-Host "Copying application files..." -ForegroundColor Yellow
# Copy main executable and DLLs
Copy-Item "$BuildDir\bin\Release\PEHint.exe" $PackageDir
Copy-Item "$BuildDir\bin\Release\*.dll" $PackageDir

Write-Host ""
Write-Host "Copying Qt plugins and dependencies..." -ForegroundColor Yellow
# Copy Qt plugin directories
$pluginDirs = @("platforms", "iconengines", "imageformats", "styles", "generic", "networkinformation", "tls")
foreach ($dir in $pluginDirs) {
    if (Test-Path "$BuildDir\bin\Release\$dir") {
        Copy-Item "$BuildDir\bin\Release\$dir" $PackageDir -Recurse -Force
    }
}

Write-Host ""
Write-Host "Copying configuration files..." -ForegroundColor Yellow
# Copy config directory
if (Test-Path "config") {
    Copy-Item "config" $PackageDir -Recurse -Force
}

Write-Host ""
Write-Host "Copying documentation..." -ForegroundColor Yellow
# Copy docs directory
if (Test-Path "docs") {
    Copy-Item "docs" $PackageDir -Recurse -Force
}
# Copy README
if (Test-Path "README.md") {
    Copy-Item "README.md" $PackageDir
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

Write-Host ""
Write-Host "Package created successfully in: $PackageDir" -ForegroundColor Green
Write-Host ""

# Show package contents
Write-Host "Package contents:" -ForegroundColor Cyan
Get-ChildItem $PackageDir -Recurse | ForEach-Object {
    $indent = "  " * ($_.FullName.Split('\').Count - $PackageDir.Split('\').Count)
    Write-Host "$indent$($_.Name)" -ForegroundColor White
}

Write-Host ""
Read-Host "Press Enter to continue"
