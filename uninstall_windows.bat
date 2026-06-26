@echo off
REM === TorShield uninstaller (Windows) ===
REM Restores your network and removes ALL TorShield data (the downloaded Tor,
REM tun2socks/wintun helpers, config, bridges, cache). Run as administrator.
REM (The exe itself is portable - delete TorShield.exe by hand when this finishes,
REM  or use Add/Remove Programs if you installed it with the setup installer.)
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo Stopping TorShield and restoring your network...
taskkill /F /IM TorShield.exe >nul 2>&1
taskkill /F /IM tun2socks.exe >nul 2>&1
taskkill /F /IM tor.exe       >nul 2>&1
route delete 0.0.0.0 mask 0.0.0.0 10.7.0.1 >nul 2>&1

echo Removing leftover network adapters...
powershell -NoProfile -Command "Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object {$_.FriendlyName -like '*tun2socks*'} | ForEach-Object { pnputil /remove-device $_.InstanceId 2>$null }"

echo Restoring DNS + IPv6...
powershell -NoProfile -Command "Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue; Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue }"
ipconfig /flushdns >nul

echo Deleting TorShield data (downloaded Tor, config, helpers)...
rmdir /S /Q "%APPDATA%\TorShield"      2>nul
rmdir /S /Q "%LOCALAPPDATA%\TorShield" 2>nul

echo.
echo Done. TorShield is removed and your internet is restored.
echo You can now delete TorShield.exe (and this folder) yourself.
pause
