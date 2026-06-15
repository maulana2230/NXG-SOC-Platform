@echo off
echo ========================================
echo  IP Reputation Investigator - Web App
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

REM Install dependencies
echo [*] Installing dependencies...
pip install -r requirements.txt --quiet

echo.
echo [*] Starting server at http://localhost:5000
echo [*] Press Ctrl+C to stop
echo.

REM Open browser after 2 seconds
start /min cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:5000"

python app.py

pause
