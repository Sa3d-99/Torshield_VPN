# TorShield — Detailed Installation Guide

## Ubuntu / Debian (Tested on Ubuntu 22.04 LTS)

### Step 1 — System packages

```bash
sudo apt update
sudo apt install tor obfs4proxy snowflake-client conntrack python3-pip python3-tk -y
```

### Step 2 — Disable the system Tor service

TorShield manages the Tor process itself. The system service must be stopped
to avoid port conflicts on 9050/9051.

```bash
sudo systemctl stop tor
sudo systemctl disable tor
```

To re-enable the system service later (if you uninstall TorShield):
```bash
sudo systemctl enable tor
sudo systemctl start tor
```

### Step 3 — Configure /etc/tor/torrc

```bash
sudo cp torrc.template /etc/tor/torrc
sudo nano /etc/tor/torrc
```

**Required lines** (uncomment if commented out):
```
SocksPort 9050
ControlPort 9051
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
```

**For censored networks**, add bridges at the bottom. Get fresh ones from
https://bridges.torproject.org — select Snowflake for best results.

### Step 4 — Python dependencies

```bash
pip install -r requirements.txt
# or
pip install customtkinter stem requests PySocks fake-useragent
```

### Step 5 — Run

```bash
python3 tor_vpn_gui.py
```

The app requests root via `pkexec` automatically.
If pkexec fails, use:
```bash
sudo python3 tor_vpn_gui.py
```

---

## Fix /tmp permissions (if you previously ran chmod 777 /tmp by mistake)

```bash
sudo chmod 1777 /tmp
```

---

## Verify ports are safe (bound to localhost only)

After connecting, run:
```bash
ss -tlnp | grep -E "9050|9051|9040|5353"
```

All entries should show `127.0.0.1:PORT` — not `0.0.0.0:PORT`.

---

## Building a standalone executable (optional)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed tor_vpn_gui.py
```

The binary will be in `dist/tor_vpn_gui`.
Note: the binary still requires Tor to be installed on the target system.
