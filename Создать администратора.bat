@echo off
setlocal
cd /d "%~dp0"
if not exist "SecureShell.exe" goto build
if not exist ".exe-version" goto build
fc /b "APP_VERSION" ".exe-version" >nul 2>nul
if not errorlevel 1 goto setup
:build
call build_windows.bat
if errorlevel 1 (
  pause
  exit /b 1
)
:setup
start /wait "" "%~dp0SecureShell.exe" --setup-admin
