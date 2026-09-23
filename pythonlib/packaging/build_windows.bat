@echo off
REM ============================================================================
REM  Build CamoufoxGUI.exe on Windows.
REM
REM  Run this ON a Windows machine. PyInstaller does not cross-compile: a Linux
REM  or macOS host can never produce a working .exe, so this script exists to be
REM  run where the target is.
REM
REM  Usage:
REM      packaging\build_windows.bat
REM
REM  Output:
REM      dist\CamoufoxGUI.exe        (one self-contained file)
REM
REM  Everything must run in ONE environment where camoufox[gui] is installed, or
REM  PyInstaller will bundle a different set of dependencies than you tested with.
REM ============================================================================

setlocal

REM Repository root is the parent of this script's directory.
set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%..\.."
cd /d "%REPO_ROOT%" || (
    echo ERROR: could not enter the repository root.
    exit /b 1
)

echo.
echo === Step 1/5: Python version ===
python --version || (
    echo ERROR: python not found on PATH. Install Python 3.10+ and tick
    echo        "Add python.exe to PATH" in the installer.
    exit /b 1
)

echo.
echo === Step 2/5: Build environment ===
REM Use a dedicated venv: a system-wide install mixes in packages that
REM PyInstaller will happily bundle, bloating the output and adding conflicts.
if not exist ".build-venv\Scripts\python.exe" (
    echo Creating .build-venv ...
    python -m venv .build-venv || exit /b 1
)
call ".build-venv\Scripts\activate.bat" || exit /b 1

echo.
echo === Step 3/5: Installing camoufox[gui] and PyInstaller ===
REM Installed from the git URL, not PyPI: the Audit tab lives in this fork and
REM the published package is upstream's, without it.
python -m pip install --upgrade pip --quiet
python -m pip install "camoufox[gui] @ git+https://github.com/mostakimnasim3/camoufox.git@main#subdirectory=pythonlib" || exit /b 1
python -m pip install pyinstaller || exit /b 1

echo.
echo === Step 4/5: Building ===
REM --clean discards cached analysis: a stale cache silently ships an old bundle.
python -m PyInstaller pythonlib\packaging\camoufox-gui.spec --noconfirm --clean || exit /b 1

echo.
echo === Step 5/5: Smoke test ===
REM The GUI is a windowed build, so a failure writes a log next to the exe
REM instead of printing to a console. Start it, wait, and check for that log.
if not exist "dist\CamoufoxGUI.exe" (
    echo ERROR: build produced no exe.
    exit /b 1
)

REM --self-check loads the real QML offscreen and exits with a verdict, so it is
REM a far better gate than starting the GUI and hoping. In a onefile build it
REM also exercises the extraction: the exe has to unpack itself before the check
REM can run, so a broken archive fails here.
set "QT_QPA_PLATFORM=offscreen"
del /q "dist\CamoufoxGUI-selfcheck.log" 2>nul
"dist\CamoufoxGUI.exe" --self-check
set "CHECK_RC=%ERRORLEVEL%"

if exist "dist\CamoufoxGUI-selfcheck.log" type "dist\CamoufoxGUI-selfcheck.log"

findstr /C:"self-check OK" "dist\CamoufoxGUI-selfcheck.log" >nul 2>&1
if errorlevel 1 (
    echo.
    echo FAILED: self-check did not report OK ^(exit code %CHECK_RC%^).
    echo Most often a hidden import or a data file is missing from the spec's
    echo datas/hiddenimports lists.
    exit /b 1
)

echo.
echo ===============================================================
echo  BUILD OK
echo ===============================================================
echo.
echo  Executable : %REPO_ROOT%\dist\CamoufoxGUI.exe
echo.
echo  This is a SINGLE FILE. Ship dist\CamoufoxGUI.exe on its own --
echo  it carries the Qt libraries, the QML data and the Playwright driver
echo  inside itself and unpacks them when it starts.
echo.
echo  Because it unpacks on every launch, the first window takes a few
echo  seconds longer than a folder build would. That is the cost of one file.
echo.
echo  The user still needs the browser once:
echo      1. open the app, Browsers tab, install a version, or
echo      2. run:  camoufox fetch
echo.
for %%F in ("dist\CamoufoxGUI.exe") do echo  Size       : %%~zF bytes

echo.
echo  Windows SmartScreen will warn on first run: the exe is not signed.
echo.
echo  That is expected for an unsigned build; a certificate is the only fix.

endlocal
