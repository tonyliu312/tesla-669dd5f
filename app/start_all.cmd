@echo off
title FSD Intercept - Start All
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_all.ps1"
echo.
echo Done. Press any key to close this window (services keep running in background).
pause >nul
