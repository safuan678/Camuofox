#!/usr/bin/env bash
#
# Build the Camoufox Manager GUI as a native application.
#
# Run this on the OS you are targeting. PyInstaller does not cross-compile: this
# script on macOS produces a macOS app, and on Linux a Linux binary. For a
# Windows .exe, use build_windows.bat on Windows.
#
# Usage:
#     pythonlib/packaging/build_native.sh
#
# Output:
#     dist/CamoufoxGUI          (Linux, one self-contained file)
#     dist/CamoufoxGUI.app      (macOS)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

echo "=== Step 1/5: Python ==="
python3 --version

echo
echo "=== Step 2/5: Build environment ==="
# A dedicated venv keeps unrelated system packages from being bundled, which
# would both bloat the output and risk version conflicts with PySide6.
if [ ! -x ".build-venv/bin/python" ]; then
    echo "Creating .build-venv ..."
    python3 -m venv .build-venv
fi
# shellcheck disable=SC1091
source .build-venv/bin/activate

echo
echo "=== Step 3/5: Installing camoufox[gui] and PyInstaller ==="
# From the git URL, not PyPI: the Audit tab is this fork's addition and the
# published package is upstream's.
python -m pip install --upgrade pip --quiet
python -m pip install "camoufox[gui] @ git+https://github.com/mostakimnasim3/camoufox.git@main#subdirectory=pythonlib"
python -m pip install pyinstaller

echo
echo "=== Step 4/5: Building ==="
# --clean discards cached analysis; a stale cache ships an old bundle silently.
python -m PyInstaller pythonlib/packaging/camoufox-gui.spec --noconfirm --clean

echo
echo "=== Step 5/5: Smoke test ==="
# The raw executable on Linux; inside the .app on macOS.
APP="dist/CamoufoxGUI"
if [ ! -x "$APP" ] && [ -x "dist/CamoufoxGUI.app/Contents/MacOS/CamoufoxGUI" ]; then
    APP="dist/CamoufoxGUI.app/Contents/MacOS/CamoufoxGUI"
fi
if [ ! -x "$APP" ]; then
    echo "ERROR: build produced no executable."
    exit 1
fi

# --self-check loads the real QML offscreen and exits with a verdict, so it is a
# better gate than launching the GUI and waiting to see if anything happens. In a
# onefile build it also exercises the extraction: the binary has to unpack itself
# before the check can run.
#
# Skipped on macOS, where CI and this script have no window server and the
# PySide6 wheel ships no offscreen plugin.
if [ "$(uname)" = "Darwin" ]; then
    echo "macOS: skipping --self-check (no offscreen Qt platform available)."
else
    rm -f dist/CamoufoxGUI-selfcheck.log
    QT_QPA_PLATFORM=offscreen "$APP" --self-check || true
    [ -f dist/CamoufoxGUI-selfcheck.log ] && cat dist/CamoufoxGUI-selfcheck.log

    if ! grep -q "self-check OK" dist/CamoufoxGUI-selfcheck.log 2>/dev/null; then
        echo
        echo "FAILED: self-check did not report OK."
        echo "Most often a hidden import or a data file is missing from the spec."
        exit 1
    fi
fi

rm -f dist/CamoufoxGUI-error.log

echo
echo "==============================================================="
echo " BUILD OK"
echo "==============================================================="
echo
echo " Application: $REPO_ROOT/$APP"
du -h "$APP"
echo
echo " This is a SINGLE FILE. Ship it on its own -- it carries the Qt"
echo " libraries, the QML data and the Playwright driver inside itself and"
echo " unpacks them when it starts."
echo
echo " Because it unpacks on every launch, the first window takes a few"
echo " seconds longer than a folder build would. That is the cost of one file."
echo
echo " The user still needs the browser once, via the Browsers tab or"
echo " 'camoufox fetch'."
