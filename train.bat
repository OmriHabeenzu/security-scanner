@echo off
echo ========================================
echo   ML Model Training - NSL-KDD Dataset
echo ========================================
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo [ERROR] Virtual environment not found!
    echo Please run setup.bat first.
    pause
    exit /b 1
)

REM Check if dataset files exist
if not exist "data\KDDTrain+.txt" (
    echo [ERROR] Training dataset not found!
    echo.
    echo Please download NSL-KDD dataset:
    echo 1. Visit: https://www.unb.ca/cic/datasets/nsl.html
    echo 2. Download KDDTrain+.txt and KDDTest+.txt
    echo 3. Place them in the 'data' folder
    echo.
    pause
    exit /b 1
)

if not exist "data\KDDTest+.txt" (
    echo [ERROR] Test dataset not found!
    echo Please place KDDTest+.txt in the 'data' folder
    echo.
    pause
    exit /b 1
)

echo [✓] Dataset files found!
echo.

REM Activate virtual environment
call venv\Scripts\activate.bat

echo Starting model training...
echo This may take 10-30 minutes depending on your computer.
echo.
echo ========================================
echo.

REM Run training script
python train_models.py

echo.
echo ========================================
echo   Training Complete!
echo ========================================
echo.
echo Trained models are saved in: ml_models/
echo - random_forest.pkl
echo - decision_tree.pkl  
echo - svm.pkl
echo - scaler.pkl
echo.
pause
