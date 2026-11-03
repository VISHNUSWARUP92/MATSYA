@echo off
title MATSYA - FastAPI Backend Server
echo ========================================================
echo Starting MATSYA Cyber Forensics Engine (FastAPI)
echo Endpoint: http://127.0.0.1:8000
echo API Docs: http://127.0.0.1:8000/docs
echo ========================================================
python backend/main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Backend failed to start. Ensure Python and requirements are installed:
    echo pip install -r backend/requirements.txt
    pause
)
