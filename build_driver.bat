@echo off
REM Build script for RegSetWatch driver
REM Requires Windows Driver Kit (WDK) to be installed

echo ====================================
echo Building RegSetWatch Driver
echo ====================================

REM Check if WDK is installed
if not exist "C:\Program Files (x86)\Windows Kits\10\bin" (
    echo ERROR: Windows Driver Kit not found
    echo Please install WDK from https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    exit /b 1
)

REM Set environment for driver build
call "C:\Program Files (x86)\Windows Kits\10\bin\SetupBuildEnv.cmd"

REM Build the driver
msbuild RegSetWatch.vcxproj /p:Configuration=Release /p:Platform=x64

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)

echo.
echo Build completed successfully!
echo Driver output: x64\Release\RegSetWatch.sys
