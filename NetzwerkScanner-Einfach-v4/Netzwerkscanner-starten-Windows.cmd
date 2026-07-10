@echo off
setlocal
cd /d "%~dp0"
title Netzwerk-Scanner Reith IT

where pwsh.exe >nul 2>&1
if %errorlevel%==0 (
    pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-NetworkDevices-Pro-v4-CrossPlatform.ps1" -SimpleMode
) else (
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-NetworkDevices-Pro-v4-CrossPlatform.ps1" -SimpleMode
)

echo.
echo Scan beendet. Die Auswertung liegt auf dem Desktop.
pause
