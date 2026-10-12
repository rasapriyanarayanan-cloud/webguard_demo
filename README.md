# WebGuard – Ethical Hacking & Penetration Testing (Cyber Security Project)
Beginner-friendly website security assessment tool with Tamil + English explanations, fix guidance,
local practice lab, before/after comparison and PDF reports.

## Requirements
- Python 3.9+ (https://python.org) and internet for the first `pip install`

## Setup (Windows / Mac / Linux)
```
cd webguard
python -m venv venv
venv\Scripts\activate          # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
```
## Quick start
Windows: double-click `run_demo.bat`   |   Mac/Linux: `./run_demo.sh`

## Manual run
Terminal 1 (practice sites):  `python practice_lab.py`
Terminal 2 (dashboard):       `python app.py`  → open http://127.0.0.1:5000

## Demo script
1. Click **Insecure site :8001** → low score, headers missing; click **View** for Tamil/English + fix code.
2. Click **Secure site :8002** → score 100.
3. Click **Compare Lab Sites** → before/after improvement.
4. Tick consent, scan a public site you own → **Download PDF Report**.

## Files
app.py (Flask server + PDF) · scanner.py (checks) · practice_lab.py (test sites) · templates/index.html (UI)

## Ethics
Only scan sites you own or have written permission to test. Public mode blocks private/internal IPs.
This tool does one GET request and checks headers/TLS; it is not a full penetration test.
