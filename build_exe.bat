@echo off
REM === Build TorShield.exe with Nuitka (native compile - faster, harder to reverse) ===
REM Run once: build_exe.bat   Output: TorShield.exe
REM NOTE: Nuitka needs a C compiler. If Visual Studio is not installed it
REM auto-downloads MinGW (~150 MB, one time). That is normal - let it finish.
setlocal

echo [1/2] Installing build + app dependencies...
python -m pip install --upgrade nuitka ordered-set zstandard >nul
python -m pip install -r requirements.txt >nul

echo [2/2] Compiling with Nuitka (first run downloads a C compiler; be patient)...
python -m nuitka --standalone --onefile --assume-yes-for-downloads --windows-console-mode=disable --enable-plugin=pyqt5 --include-module=win32api --include-module=win32con --include-module=win32process --include-module=win32security --include-module=win32ts --include-data-files=torshield.png=torshield.png --include-data-files=Header_Logo.png=Header_Logo.png --include-data-files=VERSION=VERSION --windows-icon-from-ico=torshield.ico --company-name=TorShield --product-name=TorShield --file-version=1.0.0 --product-version=1.0.0 --output-filename=TorShield.exe tor_vpn_gui.py

echo.
if exist TorShield.exe (
  echo Done!  -^>  %CD%\TorShield.exe
) else (
  echo Build did NOT produce TorShield.exe - check the messages above.
)
pause
