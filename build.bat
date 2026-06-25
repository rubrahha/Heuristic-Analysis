@echo off
title HeuristicScanner - Build C++ Scanner
color 0B
setlocal enabledelayedexpansion
echo.
echo  ============================================================
echo   HeuristicScanner - Building C++ Scanner
echo  ============================================================
echo.
cd /d "%~dp0"

reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f >nul 2>&1

REM --- Find CMake ---
set CMAKE=
cmake --version >nul 2>&1
if not errorlevel 1 (
    set CMAKE=cmake
    echo  [OK] cmake found on PATH
    goto :find_ninja
)
for %%V in (18 2022 2019 2017) do (
    for %%E in (Community Professional Enterprise BuildTools) do (
        if not defined CMAKE (
            set _C=C:\Program Files\Microsoft Visual Studio\%%V\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe
            if exist "!_C!" ( set "CMAKE=!_C!" & echo  [OK] cmake in VS%%V %%E )
        )
    )
)
if not defined CMAKE (
    echo  [ERROR] cmake not found.
    echo  Get it from: https://cmake.org/download/
    pause & exit /b 1
)

REM --- Find Ninja ---
:find_ninja
set NINJA=
set USE_NINJA=0
ninja --version >nul 2>&1
if not errorlevel 1 (
    set NINJA=ninja
    set USE_NINJA=1
    echo  [OK] ninja found on PATH
    goto :find_vcvars
)
for %%V in (18 2022 2019 2017) do (
    for %%E in (Community Professional Enterprise BuildTools) do (
        if not defined NINJA (
            set _N=C:\Program Files\Microsoft Visual Studio\%%V\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe
            if exist "!_N!" ( set "NINJA=!_N!" & set USE_NINJA=1 & echo  [OK] ninja in VS%%V %%E )
        )
    )
)
if %USE_NINJA%==0 echo  [WARN] Ninja not found - using VS generator

REM --- Find MSVC ---
:find_vcvars
set VCVARS=
for %%V in (18 2022 2019 2017) do (
    for %%E in (Community Professional Enterprise BuildTools) do (
        if not defined VCVARS (
            set _V=C:\Program Files\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat
            if exist "!_V!" ( set "VCVARS=!_V!" & echo  [OK] MSVC in VS%%V %%E )
        )
    )
)
if not defined VCVARS (
    echo  [ERROR] Visual Studio C++ compiler not found.
    echo  Install VS 2019 or 2022 - Desktop development with C++ workload.
    pause & exit /b 1
)
call "%VCVARS%" >nul 2>&1
echo  [OK] MSVC ready

REM --- Build ---
set BDIR=%~dp0scanner\cmake_build
if exist "%BDIR%" rmdir /S /Q "%BDIR%"
mkdir "%BDIR%"
echo  [..] Configuring...
if %USE_NINJA%==1 (
    "%CMAKE%" -S "%~dp0scanner" -B "%BDIR%" -G "Ninja" -DCMAKE_BUILD_TYPE=Release -DCMAKE_MAKE_PROGRAM="%NINJA%"
) else (
    "%CMAKE%" -S "%~dp0scanner" -B "%BDIR%" -DCMAKE_BUILD_TYPE=Release
)
if errorlevel 1 ( echo  [ERROR] Configure failed. & pause & exit /b 1 )

echo  [..] Compiling...
"%CMAKE%" --build "%BDIR%" --config Release
if errorlevel 1 ( echo  [ERROR] Compile failed. & pause & exit /b 1 )

if not exist "%~dp0scanner\build" mkdir "%~dp0scanner\build"
set EXE_SRC=
if exist "%BDIR%\Release\HeuristicScanner.exe" set "EXE_SRC=%BDIR%\Release\HeuristicScanner.exe"
if exist "%BDIR%\HeuristicScanner.exe"         set "EXE_SRC=%BDIR%\HeuristicScanner.exe"
if exist "%~dp0scanner\build\HeuristicScanner.exe" set "EXE_SRC=%~dp0scanner\build\HeuristicScanner.exe"
if not defined EXE_SRC (
    echo  [ERROR] HeuristicScanner.exe not found.
    pause & exit /b 1
)
copy /Y "%EXE_SRC%" "%~dp0scanner\build\HeuristicScanner.exe" >nul
echo.
echo  ============================================================
echo  [OK] Build successful!
echo  ============================================================
echo.
pause 