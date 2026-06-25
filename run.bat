@echo off
title HeuristicScanner AI
color 0B
echo.
echo  =============================================
echo   HeuristicScanner AI  --  http://localhost:5000
echo  =============================================
echo.
cd /d "%~dp0"

if not exist ai\venv\Scripts\activate.bat (
    echo  [ERROR] Run setup.bat first.
    pause & exit /b 1
)

if not exist scanner\build\HeuristicScanner.exe (
    echo  [WARN] C++ scanner not built -- AI-only mode.
    echo  Run build.bat to enable full scanning.
    echo.
)
if not exist ai\models\model.pkl (
    echo  [WARN] AI model not trained.
    echo  Run train.bat after adding samples to ai\dataset\
    echo.
)

call ai\venv\Scripts\activate.bat
cd ai
echo  Starting... open http://localhost:5000 in your browser.
echo  Press Ctrl+C to stop.
echo.
python app.py
cd ..
pause
