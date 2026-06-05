# 🛡️ TorShield — System-Wide Tor VPN Client

<p align="center">
  <img src="torshield.png" alt="TorShield Logo" width="180"/>
</p>

A GUI-based Tor VPN client for Linux that routes **all system traffic** through
the Tor network — every app, every browser, every connection — with a single
toggle switch. No per-app configuration required.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux)
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
| **Auto privilege elevation** | Uses `pkexec` to request root — no need to launch from a terminal |
| **Bridge support** | Works with obfs4 and Snowflake bridges for censored networks |
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

## Manual Installation

### 1 — Install system packages

```bash
sudo apt update
sudo apt install tor obfs4proxy snowflake-client conntrack python3-pip python3-tk -y
```

### 2 — Disable the system Tor service

TorShield manages the Tor daemon itself — the system service must be off to
avoid port conflicts on 9050/9051:

```bash
sudo systemctl stop tor
sudo systemctl disable tor
```

### 3 — Configure torrc

```bash
sudo cp torrc.template /etc/tor/torrc
sudo nano /etc/tor/torrc
```

The template already includes all required settings:

```
SocksPort 9050
ControlPort 9051
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
```

> **On a censored network? (Egypt, Iran, China, etc.)**  
> Uncomment the bridge section at the bottom of `torrc` and fill in your bridges.  
> Get fresh bridges at https://bridges.torproject.org — choose **obfs4** or **Snowflake**.  
> For Egypt, Snowflake with `front=foursquare.com` is known to work reliably.

### 4 — Install Python dependencies

```bash
pip install -r requirements.txt
# or
pip install customtkinter stem requests PySocks fake-useragent
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

1. **Click ▶ Connect** — TorShield starts the Tor daemon in the background
2. **Wait** for circuits to appear in the right panel (~30–120 seconds)
3. **Toggle "Route ALL traffic through Tor"** — all system traffic is now anonymised
4. The header displays **🌐 ALL TRAFFIC → TOR** to confirm routing is active
5. Click **🔍 Test** to verify your Tor exit IP
6. Use the **country dropdown** to pin your exit node to a specific country
7. Click **🔄 New Identity** to rotate to a fresh circuit and IP
8. **Toggle routing OFF before disconnecting** to avoid a momentary traffic gap
9. Click **■ Disconnect** — Tor stops and all iptables rules are removed

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

A prebuilt binary is included in `dist/tor_vpn_gui`. To rebuild it yourself:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed tor_vpn_gui.py
# output: dist/tor_vpn_gui
```

> The binary still requires Tor to be installed on the target system.

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
| App doesn't start / no GUI | `sudo apt install python3-tk` |
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
├── tor_vpn_gui.py       # Main application — all logic and GUI in one file
├── torrc.template       # Tor configuration template (copy to /etc/tor/torrc)
├── requirements.txt     # Python dependencies
├── install.sh           # One-shot installer (recommended)
├── uninstall.sh         # Uninstaller
├── torshield.png        # App icon — copied to ~/.local/share/icons/ by installer
├── tor_vpn_gui.spec     # PyInstaller build spec
├── dist/tor_vpn_gui     # Prebuilt standalone binary
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
