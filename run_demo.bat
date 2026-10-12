@echo off
cd /d "%~dp0"
if not exist venv (python -m venv venv)
call venv\Scripts\activate
pip install -r requirements.txt
start "WebGuard Practice Lab" cmd /k "call venv\Scripts\activate && python practice_lab.py"
timeout /t 2 >nul
start http://127.0.0.1:5000
python app.py
