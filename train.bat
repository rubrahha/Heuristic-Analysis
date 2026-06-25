@echo off
title HeuristicScanner - Train AI Model
color 0B
echo.
echo  ============================================================
echo   HeuristicScanner - AI Model Training
echo   Goal: Zero False Negatives, Near-Zero False Positives
echo  ============================================================
echo.
cd /d "%~dp0"

:: ── Venv check ────────────────────────────────────────────────────────────────
if not exist ai\venv\Scripts\activate.bat (
    echo  [ERROR] Virtual environment not found.
    echo  Run setup.bat first, then come back here.
    pause & exit /b 1
)

:: ── Activate ──────────────────────────────────────────────────────────────────
call ai\venv\Scripts\activate.bat
if errorlevel 1 (
    echo  [ERROR] Could not activate virtual environment.
    echo  Try deleting ai\venv and running setup.bat again.
    pause & exit /b 1
)

:: ── Verify ALL packages before touching train.py ─────────────────────────────
:: Missing imbalanced-learn was the silent crash cause —
:: Python exits at import before printing anything, window closes instantly.
echo  [..] Checking required packages...
set MISSING_PKGS=0

python -c "import xgboost" >nul 2>&1
if errorlevel 1 (
    echo  [..] Installing xgboost...
    pip install xgboost --quiet
    python -c "import xgboost" >nul 2>&1
    if errorlevel 1 ( echo  [ERROR] xgboost install failed & set MISSING_PKGS=1 )
)

python -c "import imblearn" >nul 2>&1
if errorlevel 1 (
    echo  [..] Installing imbalanced-learn + scipy...
    pip install imbalanced-learn scipy --quiet
    python -c "import imblearn" >nul 2>&1
    if errorlevel 1 ( echo  [ERROR] imbalanced-learn install failed & set MISSING_PKGS=1 )
)

python -c "import scipy" >nul 2>&1
if errorlevel 1 (
    echo  [..] Installing scipy...
    pip install scipy --quiet
    python -c "import scipy" >nul 2>&1
    if errorlevel 1 ( echo  [ERROR] scipy install failed & set MISSING_PKGS=1 )
)

python -c "import sklearn" >nul 2>&1
if errorlevel 1 (
    echo  [..] Installing scikit-learn...
    pip install scikit-learn --quiet
    python -c "import sklearn" >nul 2>&1
    if errorlevel 1 ( echo  [ERROR] scikit-learn install failed & set MISSING_PKGS=1 )
)

python -c "import joblib" >nul 2>&1
if errorlevel 1 ( pip install joblib --quiet )

python -c "import numpy" >nul 2>&1
if errorlevel 1 ( pip install numpy --quiet )

if %MISSING_PKGS%==1 (
    echo.
    echo  [ERROR] Could not install required packages.
    echo  Check your internet connection and run setup.bat again.
    pause & exit /b 1
)
echo  [OK] All packages ready.
echo.

:: ── Stale model check ─────────────────────────────────────────────────────────
:: Old 48-feature model causes assert crash in new extractor.py (72 features).
:: Detect and remove it automatically.
if exist ai\models\model.pkl (
    python -c "import joblib; m=joblib.load('ai/models/model.pkl'); f=getattr(m,'n_features_in_',72); exit(0 if f==72 else 1)" >nul 2>&1
    if errorlevel 1 (
        echo  [..] Old model detected ^(48 features^). Removing — will retrain fresh.
        del /f /q ai\models\model.pkl >nul 2>&1
        del /f /q ai\models\model_xgb.pkl >nul 2>&1
        del /f /q ai\models\model_rf.pkl >nul 2>&1
        del /f /q ai\models\model_meta.json >nul 2>&1
        echo  [OK] Old model removed.
        echo.
    )
)

:: ── Dataset count ─────────────────────────────────────────────────────────────
cd ai
echo  [..] Counting dataset samples...

set MALWARE_COUNT=0
set CLEAN_COUNT=0
for %%f in (dataset\malware\*.exe dataset\malware\*.dll dataset\malware\*.scr dataset\malware\*.sys dataset\malware\*.ocx) do set /a MALWARE_COUNT+=1
for %%f in (dataset\clean\*.exe dataset\clean\*.dll dataset\clean\*.sys dataset\clean\*.ocx) do set /a CLEAN_COUNT+=1

echo  Malware samples : %MALWARE_COUNT%
echo  Clean samples   : %CLEAN_COUNT%
echo.

if %MALWARE_COUNT% LSS 20 (
    echo  ============================================================
    echo  [ERROR] Only %MALWARE_COUNT% malware samples found. Need 20+.
    echo.
    echo  Get samples from:
    echo    https://bazaar.abuse.ch/browse/
    echo    https://virusshare.com/
    echo  Place .exe/.dll files in: ai\dataset\malware\
    echo  ============================================================
    cd ..
    pause & exit /b 1
)

if %CLEAN_COUNT% LSS 20 (
    echo  ============================================================
    echo  [ERROR] Only %CLEAN_COUNT% clean samples found. Need 20+.
    echo.
    echo  Quick fix - run this in a new cmd window:
    echo    copy C:\Windows\System32\*.exe ai\dataset\clean\
    echo    copy C:\Windows\System32\*.dll ai\dataset\clean\
    echo  ============================================================
    cd ..
    pause & exit /b 1
)

:: ── Run training ──────────────────────────────────────────────────────────────
echo  Starting training... this may take 5-20 minutes.
echo  Do NOT close this window.
echo.
python train.py
set TRAIN_EXIT=%errorlevel%
cd ..

echo.
if %TRAIN_EXIT% NEQ 0 (
    echo  ============================================================
    echo  [ERROR] Training failed with exit code %TRAIN_EXIT%
    echo  Scroll up and read the full error message above.
    echo  ============================================================
    pause & exit /b %TRAIN_EXIT%
)

if exist ai\models\model.pkl (
    echo  ============================================================
    echo  [OK] Training complete!
    echo.
    if exist ai\models\model_meta.json (
        echo  Results:
        python -c "import json; m=json.load(open('ai/models/model_meta.json',encoding='utf-8')); print(f'    AUC      : {m.get(\"cv_auc_mean\",0):.4f}'); print(f'    Recall   : {m.get(\"cv_recall_mean\",m.get(\"val_recall\",0)):.4f}'); print(f'    Threshold: {m.get(\"detection_threshold\",0.5):.3f}'); zfn=m.get(\"zero_fn_achieved\",False); print(f'    Zero-FN  : {\"YES\" if zfn else \"No - add more samples\"}')"
    )
    echo.
    echo  Run run.bat to start the scanner.
    echo  ============================================================
) else (
    echo  ============================================================
    echo  [ERROR] model.pkl was NOT created.
    echo  Check the output above for the cause.
    echo  ============================================================
)
echo.
pause