@echo off
title HeuristicScanner Setup
color 0B
echo.
echo  =============================================
echo   HeuristicScanner v2.0  --  First-Time Setup
echo  =============================================
echo.
cd /d "%~dp0"

:: ── Python check ─────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found.
    echo  Download from https://python.org  ^(check "Add to PATH"^)
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version') do echo  [OK] %%v

:: ── Virtual environment ───────────────────────────────────────────────────────
if not exist ai\venv (
    echo  [..] Creating virtual environment...
    python -m venv ai\venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create venv. Is Python 3.8+ installed?
        pause & exit /b 1
    )
)
echo  [OK] Virtual environment ready

:: ── Activate ──────────────────────────────────────────────────────────────────
call ai\venv\Scripts\activate.bat
if errorlevel 1 (
    echo  [ERROR] Could not activate virtual environment.
    pause & exit /b 1
)

:: ── Upgrade pip first (avoids install failures on old pip) ────────────────────
echo  [..] Upgrading pip...
python -m pip install --upgrade pip --quiet

:: ── Core packages ─────────────────────────────────────────────────────────────
echo  [..] Installing core packages...
pip install flask --quiet --upgrade
if errorlevel 1 ( echo  [ERROR] flask install failed & pause & exit /b 1 )

pip install numpy --quiet --upgrade
if errorlevel 1 ( echo  [ERROR] numpy install failed & pause & exit /b 1 )

pip install scipy --quiet --upgrade
if errorlevel 1 ( echo  [ERROR] scipy install failed & pause & exit /b 1 )

pip install scikit-learn --quiet --upgrade
if errorlevel 1 ( echo  [ERROR] scikit-learn install failed & pause & exit /b 1 )

pip install xgboost --quiet --upgrade
if errorlevel 1 ( echo  [ERROR] xgboost install failed & pause & exit /b 1 )

pip install imbalanced-learn --quiet --upgrade
if errorlevel 1 ( echo  [ERROR] imbalanced-learn install failed & pause & exit /b 1 )

pip install pefile joblib --quiet --upgrade
if errorlevel 1 ( echo  [ERROR] pefile/joblib install failed & pause & exit /b 1 )

echo  [OK] All packages installed

:: ── Verify critical imports ───────────────────────────────────────────────────
echo  [..] Verifying imports...
python -c "import flask, numpy, scipy, sklearn, xgboost, imblearn, joblib, pefile" >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] One or more packages failed to import.
    echo  Running detailed check...
    python -c "import flask"       >nul 2>&1 || echo     MISSING: flask
    python -c "import numpy"       >nul 2>&1 || echo     MISSING: numpy
    python -c "import scipy"       >nul 2>&1 || echo     MISSING: scipy
    python -c "import sklearn"     >nul 2>&1 || echo     MISSING: scikit-learn
    python -c "import xgboost"     >nul 2>&1 || echo     MISSING: xgboost
    python -c "import imblearn"    >nul 2>&1 || echo     MISSING: imbalanced-learn
    python -c "import joblib"      >nul 2>&1 || echo     MISSING: joblib
    python -c "import pefile"      >nul 2>&1 || echo     MISSING: pefile
    pause & exit /b 1
)
echo  [OK] All imports verified

:: ── Delete stale model (48-feature model is incompatible with new 72-feature extractor) ──
if exist ai\models\model.pkl (
    echo  [..] Removing old model ^(was trained on 48 features, new extractor uses 72^)...
    del /f /q ai\models\model.pkl
    echo  [OK] Old model removed -- run train.bat after setup
)
if exist ai\models\model_xgb.pkl  del /f /q ai\models\model_xgb.pkl
if exist ai\models\model_rf.pkl   del /f /q ai\models\model_rf.pkl
if exist ai\models\model_meta.json (
    :: Check if it's the old 48-feature meta and remove it too
    python -c "import json; m=json.load(open('ai/models/model_meta.json')); exit(0 if m.get('n_features',0)==72 else 1)" >nul 2>&1
    if errorlevel 1 (
        del /f /q ai\models\model_meta.json
        echo  [OK] Old model_meta.json removed
    )
)

:: ── Create required folders ───────────────────────────────────────────────────
for %%d in (
    ai\dataset\malware
    ai\dataset\clean
    ai\dataset\test\malware
    ai\dataset\test\clean
    ai\models
    ai\logs
    scanner\build
) do (
    if not exist %%d (
        mkdir %%d
        echo  [OK] Created folder: %%d
    )
)
echo  [OK] All folders ready

:: ── Summary ───────────────────────────────────────────────────────────────────
echo.
echo  =============================================
echo   Setup complete!
echo  =============================================
echo.
echo   Installed packages:
pip list | findstr /i "flask numpy scipy scikit xgboost imbalanced joblib pefile"
echo.
echo  =============================================
echo   NEXT STEPS:
echo.
echo   1. Add dataset samples:
echo      Malware : ai\dataset\malware\  ^(.exe from MalwareBazaar^)
echo      Clean   : ai\dataset\clean\    ^(copy from C:\Windows\System32^)
echo.
echo   2. Double-click train.bat  ^(trains the AI model^)
echo   3. Double-click run.bat    ^(starts the scanner^)
echo.
echo   NOTE: You MUST retrain after this setup.
echo         The old model was removed ^(feature count changed^).
echo  =============================================
echo.
pause