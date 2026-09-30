@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
if not exist "Вуаль-сервер.exe" goto build
if not exist ".exe-version" goto build
fc /b "APP_VERSION" ".exe-version" >nul 2>nul
if not errorlevel 1 goto launch
:build
call build_windows.bat
if errorlevel 1 (
  pause
  exit /b 1
)
:launch
"%~dp0Вуаль-сервер.exe" %*
if errorlevel 1 pause
