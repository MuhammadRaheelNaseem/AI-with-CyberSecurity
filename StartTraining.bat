@echo off
echo ========================================
echo    Security Training Lab - Windows 11
echo ========================================
echo.

echo Step 1: Checking Python installation...
python --version
if %errorlevel% neq 0 (
    echo Error: Python not found. Please install Python 3.9+
    pause
    exit /b 1
)

echo Step 2: Checking Node.js installation...
node --version
if %errorlevel% neq 0 (
    echo Error: Node.js not found. Please install Node.js
    pause
    exit /b 1
)

echo Step 3: Activating virtual environment...
call security-env\Scripts\activate.bat

echo Step 4: Starting comprehensive training session...
cd python-scripts
python run_training.py

echo.
echo Training session completed!
pause
