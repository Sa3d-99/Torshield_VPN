#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TorShield — One-Shot Installer  (Ubuntu / Debian / Mint / Pop!_OS)
#
# Usage:
#   chmod +x install.sh
#   ./install.sh          ← do NOT run with sudo
#
# To uninstall later:
#   torshield-uninstall
#
# Goal of v2.1: install identically on ANY Debian-family laptop. Tor and its
# pluggable-transport helpers live in different places on different distros, so
# this installer DETECTS them and bakes the real paths into /etc/tor/torrc.
# A missing helper is commented out instead of left to crash Tor on startup.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()   { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()     { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header() { echo -e "\n${BOLD}${CYAN}━━━  $*  ━━━${NC}\n"; }

# ── Banner ────────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
echo "  ╔════════════════════════════════════════╗"
echo "  ║   🛡  TorShield — System-Wide Tor VPN  ║"
echo "  ║        Installer v2.1                  ║"
echo "  ╚════════════════════════════════════════╝"
echo -e "${NC}"

# ── Must NOT run as root ──────────────────────────────────────────────────────
if [ "${EUID}" -eq 0 ]; then
    error "Do not run this installer with sudo.\nRun as your normal user: ./install.sh\nThe script asks for your password only when needed."
fi

# Make sure we run from the project folder (so the source files are present).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Variables ─────────────────────────────────────────────────────────────────
REAL_USER="$USER"
REAL_HOME="$HOME"
INSTALL_DIR="$REAL_HOME/.local/share/torshield"
BIN_LINK="/usr/local/bin/torshield"
UNINSTALL_BIN="/usr/local/bin/torshield-uninstall"
DESKTOP_FILE="$REAL_HOME/.local/share/applications/torshield.desktop"
TORRC_PATH="/etc/tor/torrc"
TORRC_TEMPLATE="$SCRIPT_DIR/torrc.template"
LAUNCHER="$INSTALL_DIR/launch.sh"
CONF_FILE="$INSTALL_DIR/torshield.conf"

# ── Step 1 — System packages ──────────────────────────────────────────────────
header "Step 1 — System packages"

info "Updating package lists…"
sudo apt-get update -qq || warn "apt-get update reported a problem — continuing."

# The GUI uses PyQt5 + PyQt-Fluent-Widgets. On Linux, qfluentwidgets also needs
# python3-pyqt5.qtx11extras (QX11Info) or it fails to import. tor runs the daemon;
# conntrack flushes leaks. Pluggable transports are best-effort + detected later.
CORE_PACKAGES=(tor conntrack python3 python3-pip python3-pyqt5 python3-pyqt5.qtx11extras)
OPTIONAL_PACKAGES=(obfs4proxy snowflake-client fonts-noto-color-emoji)

for pkg in "${CORE_PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        ok "$pkg — already installed"
    else
        info "Installing $pkg…"
        sudo apt-get install -y -qq "$pkg" || error "Failed to install required package: $pkg"
        ok "$pkg — installed"
    fi
done

for pkg in "${OPTIONAL_PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        ok "$pkg — already installed"
    else
        info "Installing $pkg (optional bridge transport)…"
        if sudo apt-get install -y -qq "$pkg"; then
            ok "$pkg — installed"
        else
            warn "$pkg not available from apt — TorShield will work without it."
        fi
    fi
done

# ── Step 2 — Detect Tor + transport binaries ─────────────────────────────────
header "Step 2 — Detecting binaries on this machine"

find_bin() {
    # $1 = command name, rest = extra candidate absolute paths
    local name="$1"; shift
    local p
    p="$(command -v "$name" 2>/dev/null || true)"
    if [ -n "$p" ]; then echo "$p"; return 0; fi
    for p in "$@"; do
        if [ -x "$p" ]; then echo "$p"; return 0; fi
    done
    echo ""
}

TOR_EXE="$(find_bin tor /usr/sbin/tor /usr/bin/tor /usr/local/bin/tor)"
[ -n "$TOR_EXE" ] || error "Tor binary not found even after install. Try: sudo apt-get install tor"
ok "tor              → $TOR_EXE"

SNOWFLAKE_CLIENT="$(find_bin snowflake-client /usr/bin/snowflake-client /usr/local/bin/snowflake-client)"
if [ -n "$SNOWFLAKE_CLIENT" ]; then
    ok "snowflake-client → $SNOWFLAKE_CLIENT"
else
    warn "snowflake-client not found — Snowflake bridge mode will be disabled."
fi

OBFS4PROXY="$(find_bin obfs4proxy /usr/bin/obfs4proxy /usr/lib/tor/obfs4proxy /usr/local/bin/obfs4proxy)"
if [ -n "$OBFS4PROXY" ]; then
    ok "obfs4proxy       → $OBFS4PROXY"
else
    warn "obfs4proxy not found — obfs4 bridge mode will be disabled."
fi

# ── Step 3 — Stop system Tor service ─────────────────────────────────────────
header "Step 3 — Disabling system Tor service"
info "TorShield manages Tor itself — the system service must be stopped."

if systemctl is-active --quiet tor 2>/dev/null; then
    sudo systemctl stop tor && ok "Tor service stopped"
else
    ok "Tor service was not running"
fi

if systemctl is-enabled --quiet tor 2>/dev/null; then
    sudo systemctl disable tor 2>/dev/null && ok "Tor service disabled (won't auto-start on boot)"
else
    ok "Tor service was already disabled"
fi

# ── Step 4 — Generate /etc/tor/torrc from the template ───────────────────────
header "Step 4 — Generating /etc/tor/torrc"

[ -f "$TORRC_TEMPLATE" ] || error "torrc.template not found next to install.sh."

# Back up any existing torrc before replacing it.
if [ -f "$TORRC_PATH" ]; then
    BACKUP="${TORRC_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
    sudo cp "$TORRC_PATH" "$BACKUP"
    ok "Existing torrc backed up → $BACKUP"
fi

TMP_TORRC="$(mktemp)"
trap 'rm -f "$TMP_TORRC"' EXIT
cp "$TORRC_TEMPLATE" "$TMP_TORRC"

# Substitute the real username and detected binary paths.
sed -i "s|__USER__|${REAL_USER}|g" "$TMP_TORRC"

if [ -n "$SNOWFLAKE_CLIENT" ]; then
    sed -i "s|__SNOWFLAKE_CLIENT__|${SNOWFLAKE_CLIENT}|g" "$TMP_TORRC"
else
    # No snowflake binary → comment out its plugin + bridge so Tor can still start.
    sed -i '/__SNOWFLAKE_CLIENT__/ s|^|# (disabled: snowflake-client not installed) |' "$TMP_TORRC"
    sed -i '/^Bridge snowflake /     s|^|# (disabled: snowflake-client not installed) |' "$TMP_TORRC"
fi

if [ -n "$OBFS4PROXY" ]; then
    sed -i "s|__OBFS4PROXY__|${OBFS4PROXY}|g" "$TMP_TORRC"
else
    sed -i '/__OBFS4PROXY__/ s|^|# (disabled: obfs4proxy not installed) |' "$TMP_TORRC"
fi

# If neither transport is available, fall back to a direct (no-bridge) config so
# the user still gets a working Tor instead of one that can never bootstrap.
if [ -z "$SNOWFLAKE_CLIENT" ] && [ -z "$OBFS4PROXY" ]; then
    sed -i 's|^UseBridges 1|UseBridges 0|' "$TMP_TORRC"
    warn "No bridge transports installed — torrc set to DIRECT mode."
fi

sudo install -o root -g root -m 644 "$TMP_TORRC" "$TORRC_PATH"
ok "Wrote $TORRC_PATH (ports, cookie auth, bridges, detected paths)"

# Validate the generated config so a bad torrc never reaches the GUI.
if sudo "$TOR_EXE" --verify-config -f "$TORRC_PATH" >/dev/null 2>&1; then
    ok "torrc passed 'tor --verify-config'"
else
    warn "tor --verify-config reported issues — re-run after checking $TORRC_PATH"
fi

# ── Step 5 — Fix Tor data-directory permissions ──────────────────────────────
header "Step 5 — Fixing Tor data directory permissions"

if [ -d /var/lib/tor ]; then
    sudo chown debian-tor:debian-tor /var/lib/tor
    sudo chmod 750 /var/lib/tor
    ok "/var/lib/tor  ownership=debian-tor:debian-tor  permissions=750"
fi
if [ -d /run/tor ]; then
    sudo chown debian-tor:debian-tor /run/tor
    sudo chmod 750 /run/tor
    ok "/run/tor  ownership=debian-tor:debian-tor  permissions=750"
fi

# ── Step 6 — Add user to debian-tor group ────────────────────────────────────
header "Step 6 — Tor group membership"

if getent group debian-tor > /dev/null 2>&1; then
    if id -nG "$REAL_USER" | grep -qw "debian-tor"; then
        ok "$REAL_USER is already in the debian-tor group"
    else
        sudo usermod -a -G debian-tor "$REAL_USER"
        ok "Added $REAL_USER to the debian-tor group"
        warn "GROUP CHANGE needs a re-login, or run now:  newgrp debian-tor"
    fi
else
    warn "debian-tor group not found — Tor may not be installed correctly."
fi

# ── Step 7 — Python packages (pinned, reproducible) ──────────────────────────
header "Step 7 — Python packages"

PIP_FLAGS=(--quiet --upgrade)
# Newer pip on Debian needs this to install outside a venv.
if pip install --help 2>/dev/null | grep -q -- "--break-system-packages"; then
    PIP_FLAGS+=(--break-system-packages)
fi

pip install "${PIP_FLAGS[@]}" pip
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    pip install "${PIP_FLAGS[@]}" -r "$SCRIPT_DIR/requirements.txt"
    ok "Python packages installed from requirements.txt (pinned versions)"
else
    pip install "${PIP_FLAGS[@]}" customtkinter stem requests PySocks fake-useragent pillow
    ok "Python packages installed"
fi

# ── Step 8 — Copy TorShield files ────────────────────────────────────────────
header "Step 8 — Installing TorShield files"

mkdir -p "$INSTALL_DIR"

if [ -f "tor_vpn_gui.py" ]; then
    cp "tor_vpn_gui.py" "$INSTALL_DIR/"
    ok "tor_vpn_gui.py copied to $INSTALL_DIR/"
else
    error "tor_vpn_gui.py not found! Run install.sh from inside the project folder."
fi

# The GUI imports torshield_core (backend engine) and reads VERSION for updates.
for extra in torshield_core.py VERSION; do
    if [ -f "$extra" ]; then
        cp "$extra" "$INSTALL_DIR/"
        ok "$extra copied"
    else
        warn "$extra not found — the app may not start without it."
    fi
done

# Persist the detected paths so the GUI uses the exact same binaries we set up.
cat > "$CONF_FILE" << CONF
# TorShield — machine configuration written by install.sh
# The GUI reads this so it always uses the binaries detected at install time.
TOR_EXE=$TOR_EXE
TORRC_PATH=$TORRC_PATH
SNOWFLAKE_CLIENT=$SNOWFLAKE_CLIENT
OBFS4PROXY=$OBFS4PROXY
CONF
ok "Saved machine config → $CONF_FILE"

# Copy logos into the app dir as-is (used by the in-app header).
for img in Header_Logo.png torshield.png; do
    if [ -f "$img" ]; then
        cp "$img" "$INSTALL_DIR/"
        ok "$img copied"
    fi
done

# Generate a SQUARE app/launcher icon so the taskbar does not stretch a wide
# logo into a square slot. We pad the source to a square canvas (keeping aspect
# ratio) and install it into the hicolor theme at several sizes, plus the
# legacy ~/.local/share/icons/torshield.png the desktop file references.
ICON_SRC=""
for cand in Header_Logo.png torshield.png; do
    [ -f "$cand" ] && { ICON_SRC="$cand"; break; }
done

if [ -n "$ICON_SRC" ]; then
    if python3 - "$ICON_SRC" "$HOME" <<'PYICON'
import sys, os
try:
    from PIL import Image
except Exception:
    sys.exit(1)
src, home = sys.argv[1], sys.argv[2]
img = Image.open(src).convert("RGBA")
w, h = img.size
if w != h:                       # pad short side → square (no distortion)
    side = max(w, h)
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(img, ((side - w) // 2, (side - h) // 2), img)
    img = canvas
# Legacy path referenced by torshield.desktop (Icon=torshield)
legacy = os.path.join(home, ".local/share/icons")
os.makedirs(legacy, exist_ok=True)
img.resize((256, 256), Image.LANCZOS).save(os.path.join(legacy, "torshield.png"))
# Proper hicolor theme sizes for crisp rendering everywhere
for s in (16, 24, 32, 48, 64, 128, 256):
    d = os.path.join(home, f".local/share/icons/hicolor/{s}x{s}/apps")
    os.makedirs(d, exist_ok=True)
    img.resize((s, s), Image.LANCZOS).save(os.path.join(d, "torshield.png"))
print("ok")
PYICON
    then
        ok "Square app icon generated (taskbar/launcher, no stretching)"
        gtk-update-icon-cache -q -t -f "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
    else
        warn "Could not generate square icon (Pillow?) — copying source as-is."
        mkdir -p "$HOME/.local/share/icons"
        cp "$ICON_SRC" "$HOME/.local/share/icons/torshield.png"
    fi
fi

# ── Step 8b — Fetch bridges automatically from Tor ────────────────────────────
header "Step 8b — Fetching bridges from Tor"

# Pull fresh obfs4 AND snowflake bridges from Tor's captcha-free BridgeDB (moat)
# — the same service Tor Browser uses. Nothing is hardcoded or entered by hand.
# Non-fatal if the network blocks it: the app retries the fetch itself on launch
# and falls back to the built-in Snowflake line.
fetch_kind() {
    # $1 = transport kind (obfs4|snowflake), $2 = output file
    python3 - "$1" "$2" <<'PYFETCH'
import sys, datetime
try:
    import requests
except Exception:
    sys.exit(1)
kind, outfile = sys.argv[1], sys.argv[2]
H = {"Content-Type": "application/vnd.api+json"}
lines = []
for url, key in (("https://bridges.torproject.org/moat/circumvention/settings", "settings"),
                 ("https://bridges.torproject.org/moat/circumvention/builtin", "builtin")):
    try:
        r = requests.post(url, json={} if key == "settings" else None, headers=H, timeout=25)
        if not r.ok:
            continue
        data = r.json()
        if key == "settings":
            for s in data.get("settings", []):
                b = s.get("bridges", {})
                if b.get("type") == kind:
                    lines += b.get("bridge_strings", [])
        else:
            lines += data.get(kind, [])
    except Exception:
        pass
seen, out = set(), []
for l in lines:
    l = l.strip()
    if l and not l.lower().startswith("bridge "):
        l = "Bridge " + l
    if l and l not in seen:
        seen.add(l); out.append(l)
if not out:
    sys.exit(2)
with open(outfile, "w", encoding="utf-8") as fh:
    fh.write(f"# {kind} bridges fetched automatically from Tor BridgeDB (moat)\n")
    fh.write(f"# generated {datetime.datetime.now().isoformat(timespec='seconds')}\n")
    fh.write("\n".join(out) + "\n")
print(len(out))
PYFETCH
}

if [ -n "$OBFS4PROXY" ]; then
    info "Requesting obfs4 bridges from bridges.torproject.org…"
    if fetch_kind obfs4 "$INSTALL_DIR/obfs4_bridges.txt"; then
        ok "Saved $(grep -c '^Bridge ' "$INSTALL_DIR/obfs4_bridges.txt" 2>/dev/null || echo some) obfs4 bridges"
    else
        warn "Could not fetch obfs4 now — the app will retry on launch."
    fi
else
    info "obfs4proxy not installed — skipping obfs4."
fi

if [ -n "$SNOWFLAKE_CLIENT" ]; then
    info "Requesting snowflake bridges from bridges.torproject.org…"
    if fetch_kind snowflake "$INSTALL_DIR/snowflake_bridges.txt"; then
        ok "Saved $(grep -c '^Bridge ' "$INSTALL_DIR/snowflake_bridges.txt" 2>/dev/null || echo some) snowflake bridges"
    else
        warn "Could not fetch snowflake now — the built-in line will be used."
    fi
else
    info "snowflake-client not installed — skipping snowflake."
fi

# ── Step 9 — Launcher script (auto privilege elevation) ──────────────────────
header "Step 9 — Creating launcher"

cat > "$LAUNCHER" << LAUNCHER_SCRIPT
#!/bin/bash
# TorShield launcher — grabs the root privileges the app needs, automatically.
export DISPLAY=\${DISPLAY:-:0}
export XAUTHORITY=\${XAUTHORITY:-\$HOME/.Xauthority}

GUI="$INSTALL_DIR/tor_vpn_gui.py"

# Already root → just run.
if [ "\$EUID" -eq 0 ]; then
    exec python3 "\$GUI" "\$@"
fi

# Prefer pkexec (graphical password prompt). Fall back to sudo, then to running
# unprivileged (the app still opens; only system-wide routing is disabled).
if command -v pkexec >/dev/null 2>&1; then
    exec pkexec env \\
        DISPLAY="\$DISPLAY" \\
        XAUTHORITY="\$XAUTHORITY" \\
        WAYLAND_DISPLAY="\${WAYLAND_DISPLAY:-}" \\
        HOME="\$HOME" \\
        PATH="\$PATH" \\
        python3 "\$GUI" "\$@" && exit 0
fi

if command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
    exec sudo -E python3 "\$GUI" "\$@"
fi

echo "Could not elevate privileges — opening without system-wide routing."
exec python3 "\$GUI" "\$@"
LAUNCHER_SCRIPT

chmod +x "$LAUNCHER"
ok "Launcher created at $LAUNCHER"

# ── Step 10 — Terminal command ────────────────────────────────────────────────
header "Step 10 — Terminal command"

sudo ln -sf "$LAUNCHER" "$BIN_LINK"
ok "Run TorShield from any terminal: torshield"

# ── Step 11 — Desktop shortcut ────────────────────────────────────────────────
header "Step 11 — Desktop shortcut"

mkdir -p "$REAL_HOME/.local/share/applications"

cat > "$DESKTOP_FILE" << DESKTOP
[Desktop Entry]
Name=TorShield
Comment=System-Wide Tor VPN Client
Exec=$LAUNCHER
Icon=torshield
Terminal=false
Type=Application
Categories=Network;Security;
Keywords=tor;vpn;privacy;anonymity;
StartupNotify=true
DESKTOP

chmod +x "$DESKTOP_FILE"
ok "Added to Applications menu"

if [ -d "$REAL_HOME/Desktop" ]; then
    cp "$DESKTOP_FILE" "$REAL_HOME/Desktop/TorShield.desktop"
    chmod +x "$REAL_HOME/Desktop/TorShield.desktop"
    ok "Desktop icon created"
fi

# ── Step 12 — Install uninstaller ────────────────────────────────────────────
header "Step 12 — Installing uninstaller"

if [ -f "uninstall.sh" ]; then
    sudo cp "uninstall.sh" "$UNINSTALL_BIN"
    sudo chmod +x "$UNINSTALL_BIN"
    ok "Uninstaller available as: torshield-uninstall"
else
    warn "uninstall.sh not found — skipping"
fi

# ── Step 13 — Safety checks ───────────────────────────────────────────────────
header "Step 13 — Safety checks"

TMP_PERMS=$(stat -c "%a" /tmp)
if [ "$TMP_PERMS" != "1777" ]; then
    warn "/tmp permissions wrong ($TMP_PERMS) — fixing…"
    sudo chmod 1777 /tmp
    ok "/tmp permissions restored to 1777"
else
    ok "/tmp permissions are correct (1777)"
fi

for PORT in 9050 9051 9040; do
    if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
        warn "Port $PORT is in use — something may conflict with Tor"
    else
        ok "Port $PORT is free"
    fi
done

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  ✔  TorShield installed successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${YELLOW}⚠  First time only — apply your new group membership:${NC}"
echo -e "  ${BOLD}Option A (recommended):${NC}  Log out and log back in"
echo -e "  ${BOLD}Option B (right now):${NC}     run  ${CYAN}newgrp debian-tor${NC}"
echo ""
echo -e "  How to launch:"
echo -e "  ${BOLD}•${NC} Terminal:  ${CYAN}torshield${NC}"
echo -e "  ${BOLD}•${NC} App menu:  search for ${CYAN}TorShield${NC}"
if [ -d "$REAL_HOME/Desktop" ]; then
echo -e "  ${BOLD}•${NC} Desktop:   double-click ${CYAN}TorShield${NC}"
fi
echo ""
echo -e "  Connection mode is ${BOLD}Auto${NC} by default: direct first, then Snowflake/obfs4."
echo -e "  To uninstall:  ${CYAN}torshield-uninstall${NC}"
echo ""
