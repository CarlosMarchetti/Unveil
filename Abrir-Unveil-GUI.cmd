@echo off
cd /d "%~dp0"
python -m unveil.gui
if errorlevel 1 pause
