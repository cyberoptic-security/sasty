echo off
echo === Sasty SAST Tool ===

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.11+ from https://python.org
    pause
    exit /b 1
)

:: Check Node
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js not found. Install Node 20+ from https://nodejs.org
    pause
    exit /b 1
)

:: Venv handling
if defined VIRTUAL_ENV (
    echo Using active venv: %VIRTUAL_ENV%
) else (
    if not exist "%~dp0backend\.venv" (
        echo Creating virtual environment...
        python -m venv "%~dp0backend\.venv"
    )
    echo Activating virtual environment...
    call "%~dp0backend\.venv\Scripts\activate.bat"
)

:: Install backend deps
cd /d "%~dp0backend"
set PYTHONUNBUFFERED=1
echo Installing backend dependencies (first run may take a few minutes)...
cmd /c pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: pip install failed
    pause
    exit /b 1
)

:: Fix broken semgrep entry-point (WinError 32 during prior install can leave
:: a bare 'semgrep' script without the normal 'semgrep.exe' wrapper)
if not exist "%VIRTUAL_ENV%\Scripts\semgrep.exe" (
    echo Repairing semgrep installation...
    cmd /c pip install --force-reinstall --no-deps semgrep
)

:: Build frontend (always rebuild to pick up any source changes)
cd /d "%~dp0frontend"
echo Installing frontend dependencies...
call npm install --prefer-offline --no-audit
if errorlevel 1 (
    echo ERROR: npm install failed
    pause
    exit /b 1
)
echo Building frontend...
call npm run build
if errorlevel 1 (
    echo ERROR: Frontend build failed
    pause
    exit /b 1
)

:: Start backend (serves frontend from dist/)
cd /d "%~dp0backend"
echo.
echo Starting Sasty on http://localhost:8000
echo Press Ctrl+C to stop.
echo.
start "" http://localhost:8000
python -m uvicorn main:app --host 0.0.0.0 --port 8000
