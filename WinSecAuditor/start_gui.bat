@echo off
REM Windows Security Auditor - GUI Launcher
REM This script launches the graphical user interface

echo.
echo ========================================
echo   Windows Security Auditor - GUI
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python 3.8+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Starting GUI application...
echo.

REM Launch the GUI
cd /d "%~dp0"
python src\gui_app.py

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to start application
    echo.
    pause
)

exit /b %errorlevel%
