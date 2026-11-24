@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements-local.txt
if errorlevel 1 goto failed
echo Installation complete. Use the tool launcher in this folder.
pause
exit /b 0
:failed
echo Installation did not finish. Keep this message for troubleshooting.
pause
exit /b 1
