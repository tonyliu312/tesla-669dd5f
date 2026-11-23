@echo off
setlocal
title FSD Intercept - Installer (2nd gen: ARP + 443)
cd /d "%~dp0"

echo.
echo   FSD Intercept - One-click installer
echo   Target: C:\fsd-mitm
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*

set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" echo   [exit code: %RC%]  see messages above.
echo   Press any key to close this window...
pause >nul
endlocal
