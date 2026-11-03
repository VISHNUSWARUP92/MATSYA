@echo off
title MATSYA - Platform Launcher
echo ========================================================
echo Launching MATSYA Cyber Forensics Platform
echo Backend:  http://127.0.0.1:8000
echo Frontend: http://localhost:5173
echo ========================================================
start "MATSYA Backend" cmd /c "run_backend.bat"
timeout /t 2 /nobreak >nul
start "MATSYA Frontend" cmd /c "run_frontend.bat"
