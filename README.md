# 🛡 TorShield — System-Wide Tor VPN Client

A modern, GUI-based Tor VPN client for Linux that routes **all system traffic**
through the Tor network — every app, every browser, every connection, with a
single toggle switch. No per-app configuration required.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)
![Tor](https://img.shields.io/badge/Powered%20by-Tor-purple?logo=tor-browser)

---

## Screenshots

> Connect → toggle the routing switch → every app on your machine uses Tor automatically.

---

## Features

| Feature | Description |
|---|---|
| **System-wide routing** | iptables transparent proxy — all TCP traffic goes through Tor, no per-app setup |
| **QUIC blocking** | Blocks UDP 443/80 to prevent Chrome's HTTP/3 from bypassing Tor |
| **DNS leak prevention** | All DNS queries routed through Tor's DNSPort (no ISP DNS leaks) |
| **Connection flushing** | `conntrack -F` clears old sessions when routing is enabled |
| **Exit node selection** | Choose a specific country for your exit node (20 countries) |
| **New Identity** | Send `SIGNAL NEWNYM` to get a fresh Tor circuit and IP |
| **Live circuit tracker** | Real-time display of all 3 hops (Entry Guard → Middle → Exit) with IPs |
| **Connection test** | Fetch your Tor exit IP via SOCKS5 with randomised User-Agent |
| **Auto privilege elevation** | Uses `pkexec` to request root — no need to run from terminal |
| **Bridge support** | Works with obfs4 and Snowflake bridges for censored networks |

---

## Requirements

- **OS:** Linux (Ubuntu 22.04+ recommended)
- **Python:** 3.10 or higher
- **Root access:** Required for iptables system-wide routing
- **Tor:** Installed via `apt`

---

## Installation

### 1 — Install Tor and pluggable transports

```bash
sudo apt update
sudo apt install tor obfs4proxy snowflake-client conntrack -y
```

### 2 — Stop the system Tor service (TorShield manages Tor itself)

```bash
sudo systemctl stop tor
sudo systemctl disable tor
```

### 3 — Configure torrc

Copy the included template and edit it:

```bash
sudo cp torrc.template /etc/tor/torrc
sudo nano /etc/tor/torrc
```

Minimum required settings (already in the template):
```
SocksPort 9050
ControlPort 9051
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
```

> **Censored network? (e.g. Egypt, Iran, China)**
> Uncomment and fill in the bridge section at the bottom of torrc.
> Get fresh bridges at https://bridges.torproject.org — choose **obfs4** or **Snowflake**.
> For Egypt specifically, Snowflake with `front=foursquare.com` is known to work.

### 4 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### 5 — Run TorShield

```bash
python3 tor_vpn_gui.py
```

The app will automatically request root privileges via `pkexec` if not already running as root.

Alternatively, run directly with sudo:
```bash
sudo python3 tor_vpn_gui.py
```

---

## Usage

1. **Click ▶ Connect** — TorShield starts the Tor daemon in the background
2. **Wait** for circuits to appear in the right panel (~30–120 seconds depending on your network)
3. **Toggle "Route ALL traffic through Tor"** — all system traffic is now anonymised
4. The header shows **🌐 ALL TRAFFIC → TOR** when active
5. Click **🔍 Test** to verify your Tor exit IP
6. Use the **country dropdown** to select a specific exit node country
7. Click **🔄 New Identity** to get a fresh IP
8. **Toggle routing OFF** before disconnecting to restore normal traffic
9. Click **■ Disconnect** — Tor stops and all iptables rules are removed

---

## How System-Wide Routing Works

When the routing switch is turned **ON**, TorShield applies these iptables rules:

```
DNS (UDP 53)  ──────────────────────────► Tor DNSPort :5353
                                           (prevents DNS leaks)

All TCP traffic ────────────────────────► Tor TransPort :9040
                                           (transparent proxy)

UDP 443 / UDP 80 (QUIC) ───────────────► REJECT
                                           (forces HTTPS fallback to TCP)

Loopback (127.x.x.x) ──────────────────► ACCEPT (unchanged)
Tor process itself ─────────────────────► ACCEPT (prevents routing loop)
```

When routing is turned **OFF** or the app closes, all rules are flushed and
traffic returns to normal direct routing.

---

## Security Notes

- Ports 9050, 9051, 9040 are bound to `127.0.0.1` — not accessible from outside your machine
- Always disable system routing **before** disconnecting to avoid a traffic gap
- Logging into personal accounts (Google, Facebook) while on Tor reveals your identity
- Chrome has a unique fingerprint — consider using Firefox with Tor for better anonymity
- Install the **WebRTC Network Limiter** Chrome extension to prevent WebRTC IP leaks
- For high-stakes anonymity, use **Tails OS** instead

---

## Troubleshooting

| Problem | Fix |
|---|---|
| App doesn't start / no GUI | Run `sudo apt install python3-tk` |
| Stuck at "Connecting" | Check torrc has `ControlPort 9051` uncommented |
| Tor stuck at 5% bootstrap | Your network blocks Tor — add bridges to torrc |
| Connection test times out | Wait for circuits to appear in the right panel first |
| `Missing dependencies for SOCKS support` | Run `pip install PySocks` |
| Port already in use | Run `sudo systemctl stop tor` |
| Traffic not going through Tor | Make sure the routing switch is ON, not just connected |

---

## Project Structure

```
torshield/
├── tor_vpn_gui.py      # Main application — all logic and GUI in one file
├── torrc.template      # Tor configuration template (copy to /etc/tor/torrc)
├── requirements.txt    # Python dependencies
├── INSTALL.md          # Detailed installation guide
├── LICENSE             # MIT License
└── README.md           # This file
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

TorShield is a tool for privacy and anonymity. Use it responsibly and in
accordance with the laws of your country. The Tor network is a legitimate
privacy tool used by journalists, researchers, activists, and privacy-conscious
individuals worldwide.
