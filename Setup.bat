@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0UniVPNManager.exe" (
  start "" "%~dp0UniVPNManager.exe" --setup
  exit /b 0
)
echo Please extract the complete UniVPN Manager package before running Setup.bat.
pause
exit /b 1
