; ── TorShield — Inno Setup installer script ────────────────────────────────────
; Builds a normal Windows installer (Program Files + Start-Menu/Desktop shortcuts
; + Add/Remove Programs entry + uninstaller) around the self-contained TorShield.exe.
;
; Prerequisites:
;   1. Build the exe first:   build_exe.bat   (produces TorShield.exe)
;   2. Install Inno Setup:    https://jrsoftware.org/isdl.php
;   3. Open this file in Inno Setup and click Build (or: iscc TorShield.iss)
;
; Output:  Output\TorShield-Setup-1.0.0.exe
;
; Note: ALL Python dependencies (PyQt5, stem, requests, pywin32, …) are already
; compiled INTO TorShield.exe — the target PC needs no Python. Tor itself and the
; tun2socks/wintun helpers are downloaded automatically on first run, so there is
; nothing else for the installer to fetch.

#define MyAppName "TorShield"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "TorShield"
#define MyAppExeName "TorShield.exe"

[Setup]
AppId={{8F2A9C41-6B7E-4D3A-9E12-TORSHIELDVPN01}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/Sa3d-99/Torshield_VPN
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=TorShield-Setup-{#MyAppVersion}
SetupIconFile=torshield.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; The VPN needs Administrator (TUN adapter + routing), and we install into Program
; Files, so require elevation for both install and the app shortcut.
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "TorShield.exe";        DestDir: "{app}"; Flags: ignoreversion
Source: "reset_internet.bat";   DestDir: "{app}"; Flags: ignoreversion
Source: "torshield.ico";        DestDir: "{app}"; Flags: ignoreversion
; README is handy to ship alongside (optional)
Source: "README.md";            DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#MyAppName}";                       Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\torshield.ico"
Name: "{group}\Restore Internet (if ever stuck)";   Filename: "{app}\reset_internet.bat"
Name: "{group}\Uninstall {#MyAppName}";             Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";                 Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\torshield.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; On uninstall, make sure routing/DNS is fully restored and nothing is left running.
Filename: "{cmd}"; Parameters: "/c taskkill /F /IM TorShield.exe & taskkill /F /IM tun2socks.exe & taskkill /F /IM tor.exe & route delete 0.0.0.0 mask 0.0.0.0 10.7.0.1 & ipconfig /flushdns"; Flags: runhidden; RunOnceId: "TorShieldCleanup"
