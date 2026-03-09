#!/bin/bash
set -e

cd "$(dirname "$0")/.."

if [ -f venv/bin/activate ]; then
  source venv/bin/activate
fi

export PYTHONPATH="$(pwd)/backend:$PYTHONPATH"
export FLASK_APP=backend/app.py

echo "KGUARD starting on http://127.0.0.1:1717"
echo "Press Ctrl+C to stop"
echo ""

python backend/app.py
