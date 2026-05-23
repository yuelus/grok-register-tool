@echo off
setlocal

cd /d "%~dp0"

if not exist ".venv\Scripts\pythonw.exe" (
    echo [ERROR] Virtual environment not found: .venv\Scripts\pythonw.exe
    echo Please create it first:
    echo   python -m venv .venv
    echo   python -m pip install --target .venv\Lib\site-packages DrissionPage curl_cffi
    pause
    exit /b 1
)

start "" ".venv\Scripts\pythonw.exe" "grok_register_ttk.py"

endlocal
