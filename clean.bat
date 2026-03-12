@echo off
echo ========================================
echo   SecureCheck - Clean Database
echo ========================================
echo.
echo WARNING: This will delete all data!
echo - All user accounts
echo - All scan history
echo - All reports
echo.
set /p confirm="Are you sure? (yes/no): "

if /i "%confirm%" NEQ "yes" (
    echo.
    echo Operation cancelled.
    echo.
    pause
    exit /b 0
)

echo.
echo Cleaning database...

REM Delete database file
if exist "data\security_scanner.db" (
    del /f "data\security_scanner.db"
    echo Database deleted!
)

REM Delete uploaded files
if exist "uploads\*.*" (
    del /q "uploads\*.*"
    echo Uploaded files deleted!
)

REM Delete reports
if exist "reports\*.*" (
    del /q "reports\*.*"
    echo Reports deleted!
)

REM Recreate database
call venv\Scripts\activate.bat
echo.
echo Creating fresh database...
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('Fresh database created!')"

echo.
echo ========================================
echo   Database cleaned successfully!
echo ========================================
echo.
pause
