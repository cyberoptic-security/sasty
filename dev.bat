@echo off
echo === Sasty Dev Mode ===
echo Backend: http://localhost:8000
echo Frontend: http://localhost:3000

:: Determine venv activate path
if defined VIRTUAL_ENV (
    set ACTIVATE=%VIRTUAL_ENV%\Scripts\activate.bat
) else (
    if not exist "%~dp0backend\.venv" (
        echo Creating virtual environment...
        python -m venv "%~dp0backend\.venv"
    )
    set ACTIVATE=%~dp0backend\.venv\Scripts\activate.bat
)

start cmd /k "call "%ACTIVATE%" && cd /d "%~dp0backend" && pip install -r requirements.txt -q && uvicorn main:app --reload --port 8000"

cd /d "%~dp0frontend"
start cmd /k "npm install && npm run dev"

echo.
echo Dev servers starting in separate windows.
echo Frontend proxies API to backend automatically.
