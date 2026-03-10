#!/usr/bin/env bash
set -e

echo "=== Sasty SAST Tool ==="

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "ERROR: Python 3 not found. Install Python 3.11+"
    exit 1
fi

# Check Node
if ! command -v node &>/dev/null; then
    echo "ERROR: Node.js not found. Install Node 20+"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/backend/.venv"

# Venv handling
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Using active venv: $VIRTUAL_ENV"
else
    if [ ! -d "$VENV_DIR" ]; then
        echo "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
    fi
    echo "Activating virtual environment..."
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
fi

# Install backend deps
echo "Installing backend dependencies..."
cd "$SCRIPT_DIR/backend"
pip install -r requirements.txt -q

# Build frontend (always rebuild to pick up any source changes)
cd "$SCRIPT_DIR/frontend"
echo "Installing frontend dependencies..."
npm install --prefer-offline --silent
echo "Building frontend..."
npm run build

# Start backend
cd "$SCRIPT_DIR/backend"
echo ""
echo "Starting Sasty on http://localhost:8000"
echo "Press Ctrl+C to stop."
echo ""
uvicorn main:app --host 0.0.0.0 --port 8000
