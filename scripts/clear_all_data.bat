@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%clear_all_data.ps1"

if not exist "%PS_SCRIPT%" (
  echo Error: PowerShell script not found: "%PS_SCRIPT%"
  exit /b 1
)

if /I "%~1"=="-h" goto :usage
if /I "%~1"=="--help" goto :usage
if /I "%~1"=="/?" goto :usage

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo clear_all_data failed with exit code %RC%.
)
exit /b %RC%

:usage
echo Usage:
echo   clear_all_data.bat [-DryRun] [-NoBackup] [-DataDir "path"] [-BackupDir "path"]
echo.
echo Examples:
echo   clear_all_data.bat -DryRun
echo   clear_all_data.bat
echo   clear_all_data.bat -NoBackup
echo   clear_all_data.bat -DataDir "B:\opt\GuardianBridge\data"
exit /b 0
