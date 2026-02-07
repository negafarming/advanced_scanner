@echo off
REM Windows Security Auditor - CLI Helper
REM Quick access script for command-line interface

setlocal enabledelayedexpansion

echo.
echo ========================================
echo   Windows Security Auditor - CLI
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Change to script directory
cd /d "%~dp0"

REM Parse arguments
if "%~1"=="" (
    REM No arguments - show help
    call :show_help
    exit /b 0
)

if /i "%~1"=="scan" (
    if "%~2"=="" (
        echo ERROR: Missing target directory
        echo Usage: start_cli.bat scan "C:\path\to\project"
        pause
        exit /b 1
    )
    
    echo Scanning: %~2
    echo.
    python src\cli_app.py scan "%~2" --all --output reports
    
    if %errorlevel% equ 0 (
        echo.
        echo ========================================
        echo   Scan completed successfully!
        echo   Reports saved in: reports\
        echo ========================================
    ) else (
        echo.
        echo ========================================
        echo   Scan failed or interrupted
        echo ========================================
    )
    pause
    exit /b %errorlevel%
)

if /i "%~1"=="list" (
    python src\cli_app.py list-checks
    pause
    exit /b 0
)

if /i "%~1"=="help" (
    call :show_help
    exit /b 0
)

REM Unknown command
echo ERROR: Unknown command: %~1
call :show_help
exit /b 1

:show_help
echo Usage:
echo   start_cli.bat scan "C:\path\to\project"    - Scan a project
echo   start_cli.bat list                         - List available checks
echo   start_cli.bat help                         - Show this help
echo.
echo Examples:
echo   start_cli.bat scan "C:\Projects\MyApp"
echo   start_cli.bat scan "D:\Code\WebApp"
echo.
echo For advanced options, use Python directly:
echo   python src\cli_app.py scan --help
echo.
goto :eof
