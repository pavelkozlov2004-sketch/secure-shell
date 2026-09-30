@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
if not exist "src\ui\login_window.py" (
  echo ERROR: Extract the entire ZIP before building.
  exit /b 1
)
if exist ".venv-build\Scripts\python.exe" goto build
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 goto use_python
py -3 -m venv .venv-build
if errorlevel 1 goto failed
goto build
:use_python
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 (
  echo ERROR: Install Python 3.10 or newer for Windows, then try again.
  exit /b 1
)
python -m venv .venv-build
if errorlevel 1 goto failed
:build
".venv-build\Scripts\python.exe" -m pip install "PyQt5>=5.15,<6" "pyinstaller>=6,<7" "cryptography>=42"
if errorlevel 1 goto failed
".venv-build\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name Вуаль --paths "%CD%\src" --add-data "%CD%\src\database\*.sql;database" --distpath dist --workpath build\windows --specpath build "%CD%\src\main.py"
if errorlevel 1 goto failed
if not exist "dist\Вуаль.exe" goto failed
copy /y "dist\Вуаль.exe" "Вуаль.exe" >nul
if errorlevel 1 goto failed
".venv-build\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --console --name Вуаль-сервер --paths "%CD%\src" --add-data "%CD%\src\database\*.sql;database" --distpath dist --workpath build\server --specpath build "%CD%\src\server_main.py"
if errorlevel 1 goto failed
if not exist "dist\Вуаль-сервер.exe" goto failed
copy /y "dist\Вуаль-сервер.exe" "Вуаль-сервер.exe" >nul
if errorlevel 1 goto failed
copy /y "APP_VERSION" ".exe-version" >nul
if errorlevel 1 goto failed
echo Build complete: %CD%\Вуаль.exe
exit /b 0
:failed
echo ERROR: Build failed. See the messages above. Check Python and internet access.
exit /b 1
