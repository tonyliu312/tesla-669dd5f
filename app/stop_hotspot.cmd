@echo off
title FSD Intercept - Stop (Hotspot mode)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop_hotspot.ps1" %*
echo.
pause >nul
