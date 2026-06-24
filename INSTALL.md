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

You normally do **not** do this by hand — `install.sh` generates
`/etc/tor/torrc` from `torrc.template`, substituting the real binary paths it
detected on your machine. If you want to do it manually:

```bash
# Replace the placeholders with paths from `which`:
sed -e "s|__USER__|$USER|g" \
    -e "s|__SNOWFLAKE_CLIENT__|$(command -v snowflake-client)|g" \
    -e "s|__OBFS4PROXY__|$(command -v obfs4proxy)|g" \
    torrc.template | sudo tee /etc/tor/torrc > /dev/null
sudo tor --verify-config -f /etc/tor/torrc   # should print "Configuration was valid"
```

**Required lines** (already in the template):
```
SocksPort 9050
ControlPort 9051
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```

**Bridges / censored networks:** fully automatic — there is no mode to pick.
The template enables Snowflake by default and declares both the `snowflake` and
`obfs4` transports. When you press **Connect**, TorShield tries, in order:

1. **Direct** — fastest, on uncensored networks.
2. **Snowflake** — disguises Tor as a video call (works reliably in Egypt/Iran).
3. **obfs4** — using bridges it **fetches automatically** from Tor's BridgeDB
   (the captcha-free moat API) and caches at
   `~/.local/share/torshield/obfs4_bridges.txt`.

`install.sh` pre-fetches the obfs4 bridges during setup; the app also refreshes
them in the background on launch and via the **Refresh bridges** button. You
never paste bridges by hand.

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
