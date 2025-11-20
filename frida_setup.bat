@echo off

:: =======================================================
:: ELEVATION CHECK — will elevate ONCE, no infinite loops
:: =======================================================
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

echo ===========================================
echo  Frida Auto-Start Installer
echo ===========================================
echo.

:: 1. Ensure folder exists
if not exist "C:\Scripts" (
    mkdir "C:\Scripts"
)
echo [+] Scripts folder ready.

:: 2. Write startup_frida.bat
echo [+] Writing startup_frida.bat...

echo @echo off>"C:\Scripts\startup_frida.bat"
echo setlocal enabledelayedexpansion>>"C:\Scripts\startup_frida.bat"
echo.>>"C:\Scripts\startup_frida.bat"

echo cd /d "C:\Users\ICT3215\Desktop">>"C:\Scripts\startup_frida.bat"
echo.>>"C:\Scripts\startup_frida.bat"

echo start /b "" "frida-server-17.5.1-windows-x86_64.exe">>"C:\Scripts\startup_frida.bat"
echo timeout /t 2 ^>nul>>"C:\Scripts\startup_frida.bat"
echo.>>"C:\Scripts\startup_frida.bat"

echo :WAIT_LOOP>>"C:\Scripts\startup_frida.bat"
echo tasklist ^| findstr /i "frida-server" ^>nul>>"C:\Scripts\startup_frida.bat"
echo if ^!errorlevel^! neq 0 (>>"C:\Scripts\startup_frida.bat"
echo ^    timeout /t 1 ^>nul>>"C:\Scripts\startup_frida.bat"
echo ^    goto WAIT_LOOP>>"C:\Scripts\startup_frida.bat"
echo )>>"C:\Scripts\startup_frida.bat"
echo.>>"C:\Scripts\startup_frida.bat"

echo start /b "" py -3 "frida_local.py">>"C:\Scripts\startup_frida.bat"
echo endlocal>>"C:\Scripts\startup_frida.bat"
echo exit /b>>"C:\Scripts\startup_frida.bat"



echo [+] Created: C:\Scripts\startup_frida.bat
echo.

:: 3. Register scheduled task (runs on startup, hidden)
echo [+] Registering task...

schtasks /create ^
  /tn "FridaAutoStart" ^
  /tr "C:\Scripts\startup_frida.bat" ^
  /sc onlogon ^
  /rl highest ^
  /f

echo.
echo ===========================================
echo  INSTALLATION COMPLETE
echo ===========================================
pause
exit /b
