@echo off
REM Windows Security Auditor - Installation Script
REM Sets up the application on Windows systems

setlocal

echo.
echo ================================================================
echo          Windows Security Auditor - Installation
echo ================================================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Not running as administrator
    echo Some features may require elevated privileges
    echo.
)

REM Check Python installation
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed!
    echo.
    echo Please install Python 3.8 or later from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo Found Python %PYTHON_VERSION%

REM Verify Python version
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
if %errorlevel% neq 0 (
    echo ERROR: Python 3.8 or later is required!
    echo Current version: %PYTHON_VERSION%
    echo.
    pause
    exit /b 1
)
echo Python version OK
echo.

REM Check pip
echo [2/5] Checking pip installation...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not installed!
    echo Installing pip...
    python -m ensurepip --default-pip
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install pip
        pause
        exit /b 1
    )
)
echo pip OK
echo.

REM Install dependencies
echo [3/5] Installing dependencies...
if exist requirements.txt (
    python -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo WARNING: Some dependencies may have failed to install
        echo The application may still work with core features
        echo.
    ) else (
        echo Dependencies installed successfully
    )
) else (
    echo No requirements.txt found - skipping dependency installation
)
echo.

REM Create output directories
echo [4/5] Creating directories...
if not exist "output" mkdir output
if not exist "reports" mkdir reports
if not exist "config" mkdir config
echo Directories created
echo.

REM Verify tkinter (for GUI)
echo [5/5] Verifying GUI support...
python -c "import tkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Tkinter (GUI library) is not available
    echo GUI application will not work
    echo CLI application will still function
    echo.
    echo To fix: Reinstall Python with "tcl/tk and IDLE" option checked
    echo.
) else (
    echo GUI support OK
)
echo.

REM Create desktop shortcuts (optional)
echo.
set /p CREATE_SHORTCUTS="Create desktop shortcuts? (Y/N): "
if /i "%CREATE_SHORTCUTS%"=="Y" (
    echo Creating shortcuts...
    
    REM Get current directory
    set CURRENT_DIR=%CD%
    
    REM Note: Creating .lnk files requires VBScript or PowerShell
    echo To create shortcuts manually:
    echo 1. Right-click on start_gui.bat
    echo 2. Select "Send to" ^> "Desktop (create shortcut)"
    echo.
)

echo.
echo ================================================================
echo              Installation Complete!
echo ================================================================
echo.
echo To start the application:
echo   GUI:  Double-click start_gui.bat
echo   CLI:  Double-click start_cli.bat or use Command Prompt
echo.
echo Documentation: README.md
echo.
echo Next steps:
echo   1. Review the README.md for usage instructions
echo   2. Run a test scan on a sample project
echo   3. Check the output reports in the 'reports' folder
echo.

pause
