@echo off
echo ========================================
echo   SecureCheck - Starting Application
echo ========================================
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo [ERROR] Virtual environment not found!
    echo Please run "setup.bat" first to install dependencies.
    echo.
    pause
    exit /b 1
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Check if database exists
if not exist "data\security_scanner.db" (
    echo [WARNING] Database not found! Creating database...
    python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('Database created!')"
    echo.
)

echo Starting SecureCheck web application...
echo.
echo ========================================
echo   Application is running!
echo ========================================
echo.
echo Open your browser and visit:
echo http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

REM Run the application
python run.py

pause
