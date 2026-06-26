@echo off
REM === TorShield: emergency internet restore ===
REM Run this if your internet is stuck after using the VPN. It undoes every change
REM TorShield can make: kills the tunnel, removes leftover adapters, resets DNS to
REM automatic, removes the Tor route, re-enables IPv6, and flushes DNS.
REM Safe to run even when everything is fine.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
echo Restoring internet (TorShield cleanup)...
taskkill /F /IM tun2socks.exe >nul 2>&1
taskkill /F /IM tor.exe        >nul 2>&1
route delete 0.0.0.0 mask 0.0.0.0 10.7.0.1 >nul 2>&1
echo Removing leftover TorShield network adapters...
powershell -NoProfile -Command "Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object {$_.FriendlyName -like '*tun2socks*'} | ForEach-Object { pnputil /remove-device $_.InstanceId 2>$null }"
powershell -NoProfile -Command "Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue; Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue }"
ipconfig /flushdns
echo.
echo Done. Your internet is restored. You can close this window.
pause
