@echo off
title MATSYA - React Frontend
echo ========================================================
echo Starting MATSYA React Frontend (Vite)
echo Local: http://localhost:5173
echo ========================================================
npm run dev
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Frontend failed. Ensure node modules are installed:
    echo npm install
    pause
)
