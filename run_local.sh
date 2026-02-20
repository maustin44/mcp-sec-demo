#!/usr/bin/env bash
set -e

cd app
npm install
npm start &
APP_PID=$!
cd ..

python3 -m venv .venv
source .venv/bin/activate
pip install -r agents/requirements.txt

python agents/catalog_agent.py
python agents/run_tools_agent.py
python agents/triage_agent.py

kill $APP_PID
echo "Done. See docs/ and reports/"