@echo off
:: Sentinel NIDS v2.0 - 1-Click Desktop Application Launcher
:: Automatically requests Administrator rights, starts the engine, and opens the Desktop App.

title Sentinel NIDS - Starting...
cd /d "%~dp0"

:: 1. Check for Administrator Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: 2. Activate Virtual Environment & Launch Desktop App
if exist ".venv\Scripts\python.exe" (
    echo [*] Starting Sentinel NIDS Desktop Center...
    ".venv\Scripts\python.exe" -m nids.app
) else (
    echo [ERROR] Virtual environment not found! Run setup first.
    pause
)
