@echo off
cd /d "%~dp0"
title HeuristicScanner -- Dataset Setup

echo.
echo  =========================================================
echo     HeuristicScanner -- Dataset Setup
echo  =========================================================
echo.
echo  STEP 1 -- Add your malware samples:
echo  ---------------------------------------------------------
echo   [INSTRUCTIONS]
echo.
echo   Paste .exe / .dll malware files into:
echo.
echo   %~dp0ai\dataset\malware\
echo.
echo   ZIP files also work -- password "infected" is tried
echo   automatically. Just drop ZIPs in and they extract.
echo.
echo   Where to get malware samples:
echo     https://bazaar.abuse.ch/browse/
echo.
echo  ---------------------------------------------------------
echo.
echo  STEP 2 -- Clean samples are collected automatically from
echo  your Windows install (System32, Program Files, AppData).
echo.
echo  ---------------------------------------------------------
echo  Press any key when you have added malware files...
echo  (or press any key now to just collect clean samples)
pause >nul

echo.
echo  =========================================================
echo  [Step 1/2] Setting up dataset...
echo  =========================================================
pip install xgboost scikit-learn numpy joblib --break-system-packages -q 2>nul
python ai\download_dataset.py
if errorlevel 1 (
    echo.
    echo  [ERROR] Setup failed. See output above.
    pause
    exit /b 1
)

echo.
echo  =========================================================
echo  [Step 2/2] Training AI model...
echo  =========================================================
python ai\train.py
if errorlevel 1 (
    echo.
    echo  [ERROR] Training failed. You may need more samples.
    echo  Add more files to ai\dataset\malware\ and re-run.
    pause
    exit /b 1
)

echo.
echo  =========================================================
echo     Done! Run run.bat to start the scanner.
echo  =========================================================
echo.
pause