@echo off
rem Double-click to start Mapache. Arguments are passed through: Mapache.bat clean --simulate
cd /d "%~dp0"
python -m mapache %*
if errorlevel 1 pause
