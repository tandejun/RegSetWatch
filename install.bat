@echo off
REM Installation script for RegSetWatch driver
REM Must be run as Administrator

echo ====================================
echo Installing RegSetWatch Driver
echo ====================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    pause
    exit /b 1
)

echo.
echo [*] Stopping existing service (if running)...
sc stop RegSetWatch 2>nul

echo [*] Deleting existing service (if exists)...
sc delete RegSetWatch 2>nul

echo [*] Creating service...
sc create RegSetWatch type= kernel binPath= %~dp0RegSetWatch.sys

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to create service
    pause
    exit /b 1
)

echo [*] Starting service...
sc start RegSetWatch

if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Service created but failed to start
    echo Check if driver is properly signed
    pause
    exit /b 1
)

echo.
echo [+] RegSetWatch driver installed and started successfully!
echo.
pause
