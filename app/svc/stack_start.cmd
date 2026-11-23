@echo off
rem ===========================================================================
rem  fsd-mitm resident stack launcher   (autostart entry)
rem
rem  ASCII-ONLY on purpose: a .cmd that contains UTF-8 Chinese is parsed by
rem  cmd.exe with the OEM codepage (936), which swallows bytes and produces
rem  "'...' is not recognized as an internal or external command".
rem
rem  Location-independent: every path below is absolute, so this file works
rem  from the Startup folder, from svc\, from the Desktop - anywhere.
rem
rem  Manual use:
rem      fsd-mitm-stack.cmd           start the resident stack (windowless)
rem      fsd-mitm-stack.cmd /check    verify paths only, do not start
rem
rem  Log: C:\fsd-mitm\logs\launcher.log   (UTF-8)
rem ===========================================================================
setlocal enableextensions
chcp 65001 >nul 2>nul
set "ROOT=C:\fsd-mitm"
set "PYW=%ROOT%\venv\Scripts\pythonw.exe"
set "PY=%ROOT%\venv\Scripts\python.exe"
set "ENTRY=%ROOT%\svc\stack.py"
set "LOGDIR=%ROOT%\logs"
set "LOG=%LOGDIR%\launcher.log"

if not exist "%LOGDIR%\" mkdir "%LOGDIR%" 2>nul

if /i "%~1"=="/check"   goto :check
if /i "%~1"=="--check"  goto :check
if /i "%~1"=="-check"   goto :check

call :verify
if errorlevel 1 exit /b 9

rem  already running? web board 8899 listening -> do not start a 2nd daemon
netstat -an -p tcp 2>nul | findstr /c:":8899 " | findstr /i /c:"LISTENING" >nul 2>&1
if not errorlevel 1 (
    >>"%LOG%" echo [%DATE% %TIME%] skip: stack already running on 8899
    exit /b 0
)

>>"%LOG%" echo [%DATE% %TIME%] launch "%PYW%" "%ENTRY%"
start "" /min /d "%ROOT%" "%PYW%" "%ENTRY%"
exit /b 0

:check
call :verify
exit /b %ERRORLEVEL%

:verify
set "RC=0"
if not exist "%ROOT%\"  ( echo MISSING dir     : %ROOT%  & set "RC=1" )
if not exist "%PYW%"    ( echo MISSING pythonw : %PYW%    & set "RC=1" )
if not exist "%PY%"     ( echo MISSING python  : %PY%     & set "RC=1" )
if not exist "%ENTRY%"  ( echo MISSING entry   : %ENTRY%  & set "RC=1" )
if "%RC%"=="0" (
    echo OK root     : %ROOT%
    echo OK pythonw  : %PYW%
    echo OK entry    : %ENTRY%
    echo OK log      : %LOG%
) else (
    >>"%LOG%" echo [%DATE% %TIME%] ERROR verify failed - see paths above
)
exit /b %RC%
