@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
if not exist ".venv\Scripts\pythonw.exe" (
    echo Please run the first-install launcher in this folder.
    pause
    exit /b 1
)
powershell -NoProfile -Command "Start-Process -FilePath '.venv\Scripts\pythonw.exe' -ArgumentList 'web_tool.py','--open' -WorkingDirectory (Get-Location).Path -WindowStyle Hidden"
exit /b
