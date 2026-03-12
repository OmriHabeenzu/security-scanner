@echo off
echo ========================================
echo   SecureCheck - Install Dependencies
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.8 or higher from python.org
    echo.
    pause
    exit /b 1
)

echo Python detected successfully!
echo.

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    echo.
)

REM Activate and install
call venv\Scripts\activate.bat

echo Installing/Updating dependencies...
echo This may take a few minutes...
echo.

pip install --upgrade pip
pip install python-magic-bin
pip install -r requirements.txt

echo.
echo ========================================
echo   Dependencies installed successfully!
echo ========================================
echo.
pause
