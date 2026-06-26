# 🛡️ TorShield — System-Wide Tor VPN Client

<p align="center">
  <img src="torshield.png" alt="TorShield Logo" width="180"/>
</p>

A GUI-based Tor VPN client for **Linux and Windows** that routes **all system
traffic** through the Tor network — every app, every browser, every connection —
with a single click. No per-app configuration required.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Tor](https://img.shields.io/badge/Powered%20by-Tor-purple?logo=tor-browser)

---

## Features

| Feature | Description |
|---|---|
| **System-wide routing** | iptables transparent proxy — all TCP traffic routed through Tor, no per-app setup |
| **DNS leak prevention** | All DNS queries routed through Tor's DNSPort (5353) — no ISP DNS leaks |
| **QUIC / HTTP3 blocking** | Rejects UDP 443/80 to prevent Chrome from bypassing Tor via HTTP/3 |
| **Connection flushing** | `conntrack -F` clears stale sessions when routing is enabled |
| **Exit node selection** | Choose a specific country for your exit node (19 countries + random) |
| **New Identity** | Sends `SIGNAL NEWNYM` to Tor for a fresh circuit and IP |
| **Live circuit tracker** | Real-time 3-hop display: Entry Guard → Middle Relay → Exit Node, with IPs |
| **Connection test** | Verifies your Tor exit IP via SOCKS5 with a randomised User-Agent |
| **Auto privilege elevation** | Requests root via `pkexec`, falls back to `sudo`, then runs unprivileged — never crashes if `pkexec` is missing |
| **Fully automatic connection** | Tries direct → Snowflake → obfs4 and uses whichever bootstraps, with a live progress bar. No modes to pick. |
| **Auto-fetched bridges** | obfs4 bridges are fetched automatically from Tor's BridgeDB (the captcha-free moat API) — nothing to paste or configure |
| **Auto system-wide routing** | On connect (as root), ALL traffic is routed through Tor immediately — no extra switch to flip; restored on disconnect |
| **Standalone binary** | PyInstaller build included — run without a Python install |

---

## Requirements

| Requirement | Details |
|---|---|
| **OS** | Linux (Ubuntu 22.04 LTS or newer recommended) |
| **Python** | 3.10 or higher |
| **Root access** | Required for iptables system-wide routing |
| **Tor** | Installed via `apt` — managed by TorShield, do **not** run the system service |

---

## Quick Install (Recommended)

The included installer handles all dependencies, configures torrc, creates a
launcher command, and adds a desktop entry in one shot:

```bash
chmod +x install.sh
./install.sh
```

> Do **not** run the installer with `sudo`. It will prompt for your password when needed.

The installer also copies `torshield.png` to `~/.local/share/icons/` so the app
icon appears in the application menu and desktop shortcut. Make sure
`torshield.png` is in the same directory as `install.sh` before running.

After installation, launch TorShield from:
- **Terminal:** `torshield`
- **App menu / Desktop:** TorShield shortcut

To uninstall:
```bash
torshield-uninstall
```

---

## Windows

TorShield runs on Windows too — the same Fluent GUI and a **full system-wide VPN**
that routes **every app** through Tor (like the Linux build). **No Tor Browser
required.**

```powershell
# 1. Install the Python dependencies (one-time):
python setup_windows.py

# 2. Launch — accept the UAC (Administrator) prompt when it appears:
python tor_vpn_gui.py
```

**Tor itself is downloaded automatically** on first run (the official Tor Expert
Bundle, ~22 MB, into `%APPDATA%\TorShield`) — you don't need Tor Browser or a
manual `tor.exe`. Then just pick a country and click **Connect**.

### How Windows routing works

- **Full VPN — default, needs Administrator.** A **Wintun** virtual adapter +
  **tun2socks** push *all* apps' traffic into Tor, with **DNS resolved through
  Tor** (no DNS leak), **IPv6 leak protection**, and Tor's own relay traffic
  routed *around* the tunnel so it never loops. The helper binaries
  (`wintun.dll`, `tun2socks.exe`) download automatically on first connect. Accept
  the UAC prompt when the app launches.
- **Proxy fallback — no Administrator.** If you decline UAC, TorShield falls back
  to the per-user Windows system proxy (HTTP) pointed at Tor. This covers browsers
  and proxy-aware apps and **can never disconnect your machine**.

### Windows notes

- Elevation uses the **UAC prompt** (instead of pkexec/sudo); the console window
  is hidden automatically (no black `cmd` window).
- Config and Tor live in `%APPDATA%\TorShield\`.
- **Exit country** really works: changing it rebuilds your circuits through that
  country. A country with no Tor exit automatically falls back to the best
  available exit so you stay online.
- **Self-healing:** routing, DNS, and IPv6 are restored automatically on
  disconnect / when you close the app, and any leftover state from a crash is
  auto-repaired on the next launch. If your internet is ever stuck, run
  **`reset_internet.bat`** (right-click → *Run as administrator*) to restore it
  instantly.
- After connecting, if a browser still shows your real location, fully close and
  reopen it once (browsers cache DNS internally for ~1 minute).

---

## Manual Installation (Linux)

### 1 — Install system packages

```bash
sudo apt update
sudo apt install tor obfs4proxy snowflake-client conntrack python3-pip python3-pyqt5 python3-pyqt5.qtx11extras -y
```

### 2 — Disable the system Tor service

TorShield manages the Tor daemon itself — the system service must be off to
avoid port conflicts on 9050/9051:

```bash
sudo systemctl stop tor
sudo systemctl disable tor
```

### 3 — Configure torrc

`install.sh` does this for you: it generates `/etc/tor/torrc` from
`torrc.template`, substituting the real `tor`, `snowflake-client`, and
`obfs4proxy` paths it detects on your machine, then validates it with
`tor --verify-config`. To do it by hand:

```bash
sed -e "s|__USER__|$USER|g" \
    -e "s|__SNOWFLAKE_CLIENT__|$(command -v snowflake-client)|g" \
    -e "s|__OBFS4PROXY__|$(command -v obfs4proxy)|g" \
    torrc.template | sudo tee /etc/tor/torrc > /dev/null
```

The template already includes all required settings:

```
SocksPort 9050
ControlPort 9051
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```

> **On a censored network? (Egypt, Iran, China, etc.)**  
> Nothing to do — it's automatic. TorShield tries direct, then Snowflake, then
> obfs4. Snowflake (default, `front=foursquare.com`) works reliably in Egypt,
> and obfs4 bridges are **fetched automatically** from Tor's BridgeDB and cached
> at `~/.local/share/torshield/obfs4_bridges.txt`. Use the **Refresh bridges**
> button in the app to pull a fresh set on demand.

### 4 — Install Python dependencies

```bash
pip install -r requirements.txt
# installs PyQt5, PyQt-Fluent-Widgets, stem, requests, PySocks, fake-useragent, Pillow
```

### 5 — Run TorShield

```bash
python3 tor_vpn_gui.py
```

TorShield will automatically request root privileges via `pkexec`. You can also
run it directly:

```bash
sudo python3 tor_vpn_gui.py
```

---

## Usage

1. **Click Connect** — TorShield starts Tor and connects automatically
   (Direct → Snowflake → obfs4), showing live bootstrap progress
2. **System-wide routing turns on automatically** once connected — every step
   (conntrack flush, TCP/DNS redirect, QUIC block) is printed in the terminal.
   There is no switch to flip.
3. **Wait** for circuits to appear in the right panel (~30–120 seconds)
4. Click **Test** to verify your Tor exit IP
5. Use the **country dropdown** to pin your exit node to a specific country
6. Click **New Identity** to rotate to a fresh circuit and IP
7. Click **Disconnect** — Tor stops, routing is restored, all rules removed
8. If a new version is published, an **Update available** dialog appears at
   launch — choose **Update now** or **Maybe later**

---

## How System-Wide Routing Works

When the routing switch is turned **ON**, TorShield applies the following
iptables rules:

```
DNS (UDP 53)              ──────────► Tor DNSPort :5353
                                       (prevents DNS leaks)

All TCP traffic           ──────────► Tor TransPort :9040
                                       (transparent proxy)

UDP 443 / UDP 80 (QUIC)   ──────────► REJECT
                                       (forces HTTPS over TCP)

Loopback (127.x.x.x)      ──────────► ACCEPT (unchanged)
Tor process itself         ──────────► ACCEPT (prevents routing loop)
```

When routing is turned **OFF** or the app exits, all rules are flushed and
traffic returns to normal.

---

## Building a Standalone Binary (Optional)

The resulting exe **bundles every Python dependency** (PyQt5, stem, requests,
pywin32, …) — the target PC needs **no Python and no pip**. Tor and the
tun2socks/wintun helpers are **downloaded automatically on first run** into
`%APPDATA%\TorShield`, so the exe stays small and self-contained.

### Windows — Nuitka (recommended: faster + harder to reverse-engineer)

Nuitka compiles the Python to native C, so the exe is faster and much harder to
decompile than a PyInstaller bundle. One command:

```powershell
build_exe.bat
# output: TorShield.exe  (single file, no console)
```

### Windows — PyInstaller (alternative)

```powershell
pip install pyinstaller
pyinstaller TorShield.spec --distpath .
# output: TorShield.exe  (in the project folder, ready for the installer)
```

Either way, just double-click the exe — it requests Administrator via UAC and
sets itself up automatically. Nothing else to install.

### Make it a real installed program (Start Menu + uninstaller)

A ready-to-use **[Inno Setup](https://jrsoftware.org/isdl.php)** script
(`TorShield.iss`) is included — it turns the exe into a proper Windows installer
(Program Files install, Start-Menu + Desktop shortcuts, Add/Remove Programs entry,
uninstaller that also restores routing).

```powershell
# 1. Build the exe:
build_exe.bat
# 2. Install Inno Setup, then compile the installer:
iscc TorShield.iss
# output: Output\TorShield-Setup-1.0.0.exe
```

Ship that one `TorShield-Setup-1.0.0.exe` — users run it, click through the wizard,
and get TorShield in their Start Menu. **No Python, no dependencies to install** —
everything is inside the exe, and Tor downloads itself on first launch.

### Linux

```bash
pip install pyinstaller
pyinstaller --onefile --windowed tor_vpn_gui.py
# output: dist/tor_vpn_gui   (still needs Tor installed via apt)
```

---

## Security Notes

- Ports `9050`, `9051`, and `9040` are bound to `127.0.0.1` — not reachable from outside your machine
- Always **disable routing before disconnecting** to prevent a momentary traffic gap
- Logging into personal accounts (Google, Facebook, etc.) while on Tor de-anonymises you
- Chrome has a unique fingerprint — use Firefox for stronger anonymity on Tor
- Install the **WebRTC Network Limiter** extension in Chrome to block WebRTC IP leaks
- For high-stakes anonymity requirements, use **Tails OS** instead

---

## Troubleshooting

| Problem | Fix |
|---|---|
| App doesn't start / no GUI | `sudo apt install python3-pyqt5 python3-pyqt5.qtx11extras` then `pip install PyQt-Fluent-Widgets` |
| Stuck at "Connecting" | Ensure `ControlPort 9051` is uncommented in `torrc` |
| Tor stuck at 5% bootstrap | Your network is blocking Tor — add bridges to `torrc` |
| Connection test times out | Wait until circuits appear in the right panel first |
| `Missing dependencies for SOCKS support` | `pip install PySocks` |
| Port already in use | `sudo systemctl stop tor` |
| Traffic not going through Tor | Confirm the routing toggle is ON, not just connected |
| `/tmp` permission errors | `sudo chmod 1777 /tmp` |

---

## Project Structure

```
torshield/
├── tor_vpn_gui.py       # Main application — Fluent GUI (view layer)
├── torshield_core.py    # Backend — Tor manager, bridges, detection, routing API
├── win_routing.py       # Windows-only — TUN VPN (tun2socks) + system-proxy fallback
├── setup_windows.py     # Windows one-time setup (installs Python deps)
├── reset_internet.bat   # Windows emergency: restore internet if ever stuck
├── uninstall_windows.bat# Windows uninstaller: restore network + remove all data
├── build_exe.bat        # Windows — build TorShield.exe with Nuitka (one command)
├── TorShield.spec       # Windows — PyInstaller spec (alternative build)
├── TorShield.iss        # Windows — Inno Setup script → TorShield-Setup.exe installer
├── torshield.ico        # Windows exe / installer icon
├── torrc.template       # Tor configuration template (Linux: copy to /etc/tor/torrc)
├── requirements.txt     # Python dependencies
├── install.sh           # Linux one-shot installer (recommended)
├── uninstall.sh         # Linux uninstaller
├── torshield.png        # App icon — copied to ~/.local/share/icons/ by installer
├── INSTALL.md           # Detailed manual installation guide
├── CHANGELOG.md         # Version history
├── LICENSE              # MIT License
└── README.md            # This file
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

TorShield is a privacy tool intended for legal use. Use it responsibly and in
accordance with the laws of your country. The Tor network is widely used by
journalists, researchers, activists, and privacy-conscious individuals worldwide.
