@echo off
REM Test scenarios for RegSetWatch
REM Demonstrates both benign and malicious registry timestomping attempts

echo ====================================
echo RegSetWatch Test Scenarios
echo ====================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: Some tests may require Administrator privileges
    echo.
)

echo [*] Test 1: Benign scenario - Setting current timestamp
echo     This should NOT trigger a suspicious alert
echo.
SetRegTime.exe HKCU\Software\RegSetWatchTest\Benign benign
if %ERRORLEVEL% EQU 0 (
    echo [+] Test 1 completed
) else (
    echo [!] Test 1 failed
)
echo.
timeout /t 2 /nobreak >nul

echo [*] Test 2: Malicious scenario - Backdating timestamp to 2010
echo     This SHOULD trigger a suspicious alert
echo.
SetRegTime.exe HKCU\Software\RegSetWatchTest\Malicious
if %ERRORLEVEL% EQU 0 (
    echo [+] Test 2 completed
) else (
    echo [!] Test 2 failed
)
echo.
timeout /t 2 /nobreak >nul

echo [*] Test 3: Multiple keys with backdated timestamps
echo     This SHOULD trigger multiple suspicious alerts
echo.
SetRegTime.exe HKCU\Software\RegSetWatchTest\Malicious1
SetRegTime.exe HKCU\Software\RegSetWatchTest\Malicious2
SetRegTime.exe HKCU\Software\RegSetWatchTest\Malicious3
echo [+] Test 3 completed
echo.
timeout /t 2 /nobreak >nul

echo [*] Test 4: Retrieving alerts
echo.
RegSetWatchCtl.exe alerts
echo.

echo ====================================
echo Test scenarios completed!
echo ====================================
echo.
echo Review the alerts above to verify detection.
echo Expected results:
echo - Test 1: Should show benign operation (Suspicious: No)
echo - Test 2-3: Should show suspicious operations (Suspicious: Yes)
echo.
echo Cleanup test keys with:
echo   reg delete HKCU\Software\RegSetWatchTest /f
echo.
pause
