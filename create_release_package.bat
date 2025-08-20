@echo off
echo Creating PEHint Release Package...
echo.

REM Set Qt path
set QT_PATH=C:\Qt\6.8.0\msvc2022_64
set BUILD_DIR=out\build\qt-release
set PACKAGE_DIR=PEHint_Release_Package

REM Clean previous package
if exist "%PACKAGE_DIR%" rmdir /s /q "%PACKAGE_DIR%"
mkdir "%PACKAGE_DIR%"

echo Building release version...
cmake --preset qt-release
if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)

cmake --build --preset qt-release
if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
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
