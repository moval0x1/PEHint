@echo off
setlocal enabledelayedexpansion

REM Set up error logging
set TIMESTAMP=%date:~10,4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set LOG_FILE=create_release_package_%TIMESTAMP%.log
set ERROR_LOG_FILE=create_release_package_errors_%TIMESTAMP%.log

REM Start logging
echo [%date% %time%] === PEHint Release Package Creation Started === > "%LOG_FILE%"
echo [%date% %time%] Log file: %LOG_FILE% >> "%LOG_FILE%"
echo [%date% %time%] Error log file: %ERROR_LOG_FILE% >> "%LOG_FILE%"
echo [%date% %time%] Script version: 2.0 >> "%LOG_FILE%"
echo [%date% %time%] Working directory: %CD% >> "%LOG_FILE%"
echo [%date% %time%] OS: %OS% >> "%LOG_FILE%"
echo [%date% %time%] >> "%LOG_FILE%"

echo Creating PEHint Release Package...
echo Log files: %LOG_FILE% (main), %ERROR_LOG_FILE% (errors)
echo.

REM Set Qt path
set QT_PATH=C:\Qt\6.8.0\msvc2022_64
set BUILD_DIR=out\build\qt-release
set PACKAGE_DIR=PEHint_Release_Package

REM Clean previous package
if exist "%PACKAGE_DIR%" rmdir /s /q "%PACKAGE_DIR%"
mkdir "%PACKAGE_DIR%"

REM Clean build directory to ensure fresh build
echo Cleaning build directory...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
echo Build directory cleaned

echo Building release version...
echo Build directory: %BUILD_DIR%
echo CMake preset: qt-release

cmake --preset qt-release
if errorlevel 1 (
    echo Configuration failed!
    pause
    exit /b 1
)

echo Building with --config Release...
cmake --build --preset qt-release --config Release
if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)

REM Verify the build output
echo Verifying build output...
set RELEASE_EXE=%BUILD_DIR%\bin\Release\PEHint.exe
set DEBUG_EXE=%BUILD_DIR%\bin\Debug\PEHint.exe

if exist "%RELEASE_EXE%" (
    echo ✓ Release executable found at: %RELEASE_EXE%
) else (
    echo ✗ Release executable NOT found at: %RELEASE_EXE%
)

if exist "%DEBUG_EXE%" (
    echo ⚠ Debug executable found at: %DEBUG_EXE%
) else (
    echo ✓ No debug executable found (as expected)
)

echo.
echo Deploying Qt dependencies...
"%QT_PATH%\bin\windeployqt.exe" --release --compiler-runtime --no-translations --dir "%BUILD_DIR%\bin\Release" "%BUILD_DIR%\bin\Release\PEHint.exe"

echo.
echo Copying application files...
copy "%BUILD_DIR%\bin\Release\PEHint.exe" "%PACKAGE_DIR%\"
copy "%BUILD_DIR%\bin\Release\*.dll" "%PACKAGE_DIR%\"

echo.
echo Copying Qt plugins and dependencies...
xcopy "%BUILD_DIR%\bin\Release\platforms" "%PACKAGE_DIR%\platforms\" /E /I /Y
xcopy "%BUILD_DIR%\bin\Release\iconengines" "%PACKAGE_DIR%\iconengines\" /E /I /Y
xcopy "%BUILD_DIR%\bin\Release\imageformats" "%PACKAGE_DIR%\imageformats\" /E /I /Y
xcopy "%BUILD_DIR%\bin\Release\styles" "%PACKAGE_DIR%\styles\" /E /I /Y
xcopy "%BUILD_DIR%\bin\Release\generic" "%PACKAGE_DIR%\generic\" /E /I /Y
xcopy "%BUILD_DIR%\bin\Release\networkinformation" "%PACKAGE_DIR%\networkinformation\" /E /I /Y
xcopy "%BUILD_DIR%\bin\Release\tls" "%PACKAGE_DIR%\tls\" /E /I /Y

echo.
echo Copying configuration files...
xcopy "config" "%PACKAGE_DIR%\config\" /E /I /Y

echo.
echo Copying documentation...
xcopy "docs" "%PACKAGE_DIR%\docs\" /E /I /Y
copy "README.md" "%PACKAGE_DIR%\"

echo.
echo Creating version info file...
echo PEHint Release Package > "%PACKAGE_DIR%\VERSION.txt"
echo Built on: %date% %time% >> "%PACKAGE_DIR%\VERSION.txt"
echo Build Type: Release >> "%PACKAGE_DIR%\VERSION.txt"
echo Qt Version: 6.8.0 >> "%PACKAGE_DIR%\VERSION.txt"
echo Compiler: MSVC 2022 >> "%PACKAGE_DIR%\VERSION.txt"

echo.
echo Package created successfully in: %PACKAGE_DIR%
echo.
pause
