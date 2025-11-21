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

:: 2. Copy frida-server + python script to C:\Scripts
echo [+] Copying components to C:\Scripts...

copy /y "%~dp0frida-server.exe" "C:\Scripts\" >nul
copy /y "%~dp0frida_local.py" "C:\Scripts\" >nul
copy /y "%~dp0regCheck.py" "C:\Scripts\" >nul

echo [+] Copy complete.
echo.

echo [+] Copying Python to Program Files...

REM Create target folder
if not exist "C:\Program Files\Python313" (
    mkdir "C:\Program Files\Python313"
)

REM Copy entire Python installation
xcopy /e /i /h /y "%LOCALAPPDATA%\Programs\Python\Python313" "C:\Program Files\Python313" >nul

echo [+] Python copied to Program Files.

:: 2. Write startup_frida.bat
echo [+] Writing startup_frida.bat...

echo @echo off>"C:\Scripts\startup_frida.bat"
echo setlocal enabledelayedexpansion>>"C:\Scripts\startup_frida.bat"
echo.>>"C:\Scripts\startup_frida.bat"

echo cd /d "C:\Scripts">>"C:\Scripts\startup_frida.bat"
echo.>>"C:\Scripts\startup_frida.bat"

echo powershell -WindowStyle Hidden -Command "Start-Process 'C:\Scripts\frida-server.exe' -WindowStyle Hidden">>"C:\Scripts\startup_frida.bat"
echo.>>"C:\Scripts\startup_frida.bat"

echo :WAIT_LOOP>>"C:\Scripts\startup_frida.bat"
echo tasklist ^| findstr /i "frida-server" ^>nul>>"C:\Scripts\startup_frida.bat"
echo if ^!errorlevel^! neq 0 (>>"C:\Scripts\startup_frida.bat"
echo ^    timeout /t 1 ^>nul>>"C:\Scripts\startup_frida.bat"
echo ^    goto WAIT_LOOP>>"C:\Scripts\startup_frida.bat"
echo )>>"C:\Scripts\startup_frida.bat"
echo.>>"C:\Scripts\startup_frida.bat"

echo start "" "C:\Program Files\Python313\pythonw.exe" "frida_local.py">>"C:\Scripts\startup_frida.bat"
echo endlocal>>"C:\Scripts\startup_frida.bat"
echo exit /b>>"C:\Scripts\startup_frida.bat"



echo [+] Created: C:\Scripts\startup_frida.bat
echo.

echo [+] Writing startup_frida.vbs...

echo Set WshShell = CreateObject("WScript.Shell")>>"C:\Scripts\startup_frida.vbs"
echo WshShell.Run "C:\Scripts\startup_frida.bat", 0, False>>"C:\Scripts\startup_frida.vbs"

echo [+] Created: C:\Scripts\startup_frida.vbs
echo.

:: 3. Register scheduled task (runs on startup, hidden)
echo [+] Registering task...

schtasks /create ^
  /tn "FridaAutoStart" ^
  /tr "wscript.exe \"C:\Scripts\startup_frida.vbs\"" ^
  /sc onstart ^
  /ru SYSTEM ^
  /rl highest ^
  /f

echo.
echo ===========================================
echo  INSTALLATION COMPLETE
echo ===========================================
pause
exit /b
