@echo off
cd /d "%~dp0"
start "Practice Lab" cmd /k python practice_lab.py
timeout /t 2 >nul
start http://127.0.0.1:5000
python app.py