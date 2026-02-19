@echo off
REM New Simple GRC Guardian API

echo ============================================================
echo GRC Guardian - NEW Simple API
echo ============================================================
echo.

REM Set environment
set PYTHONDONTWRITEBYTECODE=1
set PYTHONPATH=%CD%

echo Starting NEW API server...
echo URL: http://localhost:8000
echo Docs: http://localhost:8000/docs
echo.

REM Run from project root so imports work
python -m uvicorn api.simple_api:app --reload --host 0.0.0.0 --port 8000
