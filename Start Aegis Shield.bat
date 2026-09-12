@echo off
title Aegis Shield
cd /d "%~dp0"

rem Prefer the official "py" launcher; fall back to python on PATH.
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 launch_aegis_shield.py %*
    goto done
)
where python >nul 2>nul
if %errorlevel%==0 (
    python launch_aegis_shield.py %*
    goto done
)

echo.
echo Python 3.10 or newer is required.
echo Download it from https://www.python.org/downloads/
echo During setup, tick "Add python.exe to PATH", then run this file again.

:done
echo.
pause
