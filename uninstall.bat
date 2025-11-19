@echo off
REM Uninstallation script for RegSetWatch driver
REM Must be run as Administrator

echo ====================================
echo Uninstalling RegSetWatch Driver
echo ====================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    pause
    exit /b 1
)

echo.
echo [*] Stopping service...
sc stop RegSetWatch

echo [*] Deleting service...
sc delete RegSetWatch

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to delete service
    pause
    exit /b 1
)

echo.
echo [+] RegSetWatch driver uninstalled successfully!
echo.
pause
