@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0UniVPNManager.exe" (
  start "" "%~dp0UniVPNManager.exe"
  exit /b 0
)
if exist "%~dp0.build-venv\Scripts\pythonw.exe" (
  start "" "%~dp0.build-venv\Scripts\pythonw.exe" "%~dp0launcher.py"
  exit /b 0
)
where pythonw.exe >nul 2>&1
if not errorlevel 1 (
  start "" pythonw.exe "%~dp0launcher.py"
  exit /b 0
)
echo Please use the packaged UniVPNManager.exe or install Python 3.12 x64.
pause
exit /b 1
