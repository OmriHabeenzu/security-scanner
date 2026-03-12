@echo off
echo ========================================
echo   SecureCheck - Stopping Application
echo ========================================
echo.

REM Kill Python processes running Flask
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *run.py*" >nul 2>&1
if errorlevel 1 (
    echo No running SecureCheck application found.
) else (
    echo Application stopped successfully!
)

echo.
pause
