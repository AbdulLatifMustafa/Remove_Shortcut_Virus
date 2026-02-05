
@echo off
title Shortcut Virus Removal Tool
color 0A

echo.
echo ========================================
echo   Shortcut Virus Removal Tool Launcher
echo ========================================
echo.

echo Starting PowerShell script...
echo.

powershell -ExecutionPolicy Bypass -NoExit -File "%~dp0Remove_Shortcut_Virus.ps1"

echo.
echo Script execution completed.
pause
