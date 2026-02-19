@echo off
REM GRC Guardian API Startup Script
REM This script ensures a clean start without Python bytecode caching issues

echo ============================================================
echo GRC Guardian API - Clean Startup
echo ============================================================
echo.

REM Set environment variable to prevent .pyc caching
set PYTHONDONTWRITEBYTECODE=1

echo [1/3] Clearing Python cache files...
REM Clear __pycache__ directories
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d" 2>nul

REM Clear .pyc files
del /s /q *.pyc 2>nul

echo [2/3] Cache cleared successfully
echo.

echo [3/3] Starting API server...
echo Server URL: http://localhost:8000
echo Dashboard: http://localhost:8000/
echo API Docs: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server
echo.

REM Start the server with reload enabled
python -m uvicorn api.app.main:app --reload --host 0.0.0.0 --port 8000
