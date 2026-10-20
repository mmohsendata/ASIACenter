@echo off
cd /d "%~dp0"
python backend\server.py
if errorlevel 1 (
  echo.
  echo Python is required. Install Python then run this file again.
  pause
)
