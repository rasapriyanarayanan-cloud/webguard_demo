#!/bin/bash
cd "$(dirname "$0")"
[ -d venv ] || python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python practice_lab.py &
sleep 2
(xdg-open http://127.0.0.1:5000 || open http://127.0.0.1:5000) >/dev/null 2>&1 &
python app.py
