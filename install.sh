#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TorShield — One-Shot Installer  (Ubuntu 22.04 / Debian)
#
# Usage:
#   chmod +x install.sh
#   ./install.sh          ← do NOT run with sudo
#
# To uninstall later:
#   torshield-uninstall
# ─────────────────────────────────────────────────────────────────────────────

set -e

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
echo "  ║        Installer v2.0                  ║"
echo "  ╚════════════════════════════════════════╝"
echo -e "${NC}"

# ── Must NOT run as root ──────────────────────────────────────────────────────
if [ "$EUID" -eq 0 ]; then
    error "Do not run this installer with sudo.\nRun as your normal user: ./install.sh\nThe script asks for your password only when needed."
fi

# ── Variables ─────────────────────────────────────────────────────────────────
REAL_USER="$USER"
REAL_HOME="$HOME"
INSTALL_DIR="$REAL_HOME/.local/share/torshield"
BIN_LINK="/usr/local/bin/torshield"
UNINSTALL_BIN="/usr/local/bin/torshield-uninstall"
DESKTOP_FILE="$REAL_HOME/.local/share/applications/torshield.desktop"
TORRC_PATH="/etc/tor/torrc"
LAUNCHER="$INSTALL_DIR/launch.sh"

# ── Step 1 — System packages ──────────────────────────────────────────────────
header "Step 1 — System packages"

info "Updating package lists…"
sudo apt-get update -qq

PACKAGES=(tor obfs4proxy snowflake-client conntrack python3 python3-pip python3-tk git)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        ok "$pkg — already installed"
    else
        info "Installing $pkg…"
        sudo apt-get install -y -qq "$pkg"
        ok "$pkg — installed"
    fi
done

# ── Step 2 — Stop system Tor service ─────────────────────────────────────────
header "Step 2 — Disabling system Tor service"
info "TorShield manages Tor itself — the system service must be stopped."

if systemctl is-active --quiet tor 2>/dev/null; then
    sudo systemctl stop tor
    ok "Tor service stopped"
else
    ok "Tor service was not running"
fi

if systemctl is-enabled --quiet tor 2>/dev/null; then
    sudo systemctl disable tor
    ok "Tor service disabled (won't auto-start on boot)"
else
    ok "Tor service was already disabled"
fi

# ── Step 3 — Configure /etc/tor/torrc ────────────────────────────────────────
header "Step 3 — Configuring /etc/tor/torrc"

# Only adds lines that are missing — safe to run multiple times.
# CookieAuthentication is REQUIRED for stem (Python) to connect to ControlPort.
# Snowflake bridges are included by default so it works on censored networks
# (Egypt, Iran, etc.) without any manual configuration.
#
# NOTE: The snowflake log path uses /home/$REAL_USER so it works for any
# username — not hardcoded to a specific user like /home/jimmy.

REQUIRED_LINES=(
    "SocksPort 9050"
    "ControlPort 9051"
    "TransPort 9040"
    "DNSPort 5353"
    "AutomapHostsOnResolve 1"
    "CookieAuthentication 1"
    "CookieAuthFileGroupReadable 1"
    "UseBridges 1"
    "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client -log /home/$REAL_USER/snowflake.log -url https://snowflake-broker.torproject.net/ -front foursquare.com -ice stun:stun.l.google.com:19302,stun:stun.antisip.com:3478"
    "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ front=foursquare.com"
)

if [ ! -f "$TORRC_PATH" ]; then
    sudo touch "$TORRC_PATH"
    ok "Created empty $TORRC_PATH"
fi

BACKUP="${TORRC_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
sudo cp "$TORRC_PATH" "$BACKUP"
ok "torrc backed up → $BACKUP"

if ! sudo grep -q "# TorShield required settings" "$TORRC_PATH"; then
    echo "" | sudo tee -a "$TORRC_PATH" > /dev/null
    echo "# ── TorShield required settings ─────────────────────────────────────────────" | sudo tee -a "$TORRC_PATH" > /dev/null
fi

ADDED=0
for line in "${REQUIRED_LINES[@]}"; do
    setting=$(echo "$line" | awk '{print $1}')
    if sudo grep -qE "^${setting}\s" "$TORRC_PATH" 2>/dev/null; then
        ok "$line — already present"
    else
        echo "$line" | sudo tee -a "$TORRC_PATH" > /dev/null
        ok "$line — added"
        ADDED=$((ADDED + 1))
    fi
done

if [ "$ADDED" -eq 0 ]; then
    info "torrc already had all required settings — nothing changed."
fi

# ── Step 4 — Fix /var/lib/tor permissions ────────────────────────────────────
header "Step 4 — Fixing Tor data directory permissions"

# Ubuntu 22.04: Tor writes its cookie to /run/tor/control.authcookie
# Older installs: /var/lib/tor/control_auth_cookie
# Both must be accessible by users in the debian-tor group.

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

# ── Step 5 — Add user to debian-tor group ────────────────────────────────────
header "Step 5 — Tor group membership"

# FIX: The correct command is:  usermod -a -G debian-tor $USER
#      NOT:                      usermod -a -G $USER debian-tor   ← this is backwards
#
# The user must be IN the debian-tor group to read the cookie file.
# Without this, stem cannot authenticate and circuits never appear.

if getent group debian-tor > /dev/null 2>&1; then
    if id -nG "$REAL_USER" | grep -qw "debian-tor"; then
        ok "$REAL_USER is already in the debian-tor group"
    else
        sudo usermod -a -G debian-tor "$REAL_USER"
        ok "Added $REAL_USER to the debian-tor group"
        warn "────────────────────────────────────────────────────────"
        warn "GROUP CHANGE requires you to log out and back in."
        warn "OR apply it right now in this terminal by running:"
        warn "  newgrp debian-tor"
        warn "────────────────────────────────────────────────────────"
    fi
else
    warn "debian-tor group not found — Tor may not be installed correctly."
fi

# ── Step 6 — Python packages ──────────────────────────────────────────────────
header "Step 6 — Python packages"

pip install --quiet --upgrade pip --break-system-packages
pip install --quiet customtkinter stem requests PySocks fake-useragent pillow --break-system-packages
ok "Python packages installed"

# ── Step 7 — Copy TorShield files ────────────────────────────────────────────
header "Step 7 — Installing TorShield files"

mkdir -p "$INSTALL_DIR"

if [ -f "tor_vpn_gui.py" ]; then
    cp "tor_vpn_gui.py" "$INSTALL_DIR/"
    ok "tor_vpn_gui.py copied to $INSTALL_DIR/"
else
    error "tor_vpn_gui.py not found! Run install.sh from inside the project folder."
fi

# Copy logo if present
for img in Header_Logo.png torshield.png; do
    if [ -f "$img" ]; then
        cp "$img" "$INSTALL_DIR/"
        mkdir -p "$HOME/.local/share/icons"
        cp "$img" "$HOME/.local/share/icons/$img"
        ok "$img copied"
    fi
done

# ── Step 8 — Launcher script ──────────────────────────────────────────────────
header "Step 8 — Creating launcher"

cat > "$LAUNCHER" << LAUNCHER_SCRIPT
#!/bin/bash
# TorShield launcher — handles privilege elevation automatically
export DISPLAY=\${DISPLAY:-:0}
export XAUTHORITY=\${XAUTHORITY:-\$HOME/.Xauthority}

if [ "\$EUID" -ne 0 ]; then
    exec pkexec env \\
        DISPLAY="\$DISPLAY" \\
        XAUTHORITY="\$XAUTHORITY" \\
        HOME="\$HOME" \\
        PATH="\$PATH" \\
        python3 "$INSTALL_DIR/tor_vpn_gui.py" "\$@"
else
    exec python3 "$INSTALL_DIR/tor_vpn_gui.py" "\$@"
fi
LAUNCHER_SCRIPT

chmod +x "$LAUNCHER"
ok "Launcher created at $LAUNCHER"

# ── Step 9 — Terminal command ─────────────────────────────────────────────────
header "Step 9 — Terminal command"

sudo ln -sf "$LAUNCHER" "$BIN_LINK"
ok "Run TorShield from any terminal: torshield"

# ── Step 10 — Desktop shortcut ────────────────────────────────────────────────
header "Step 10 — Desktop shortcut"

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

# ── Step 11 — Install uninstaller ────────────────────────────────────────────
header "Step 11 — Installing uninstaller"

if [ -f "uninstall.sh" ]; then
    sudo cp "uninstall.sh" "$UNINSTALL_BIN"
    sudo chmod +x "$UNINSTALL_BIN"
    ok "Uninstaller available as: torshield-uninstall"
else
    warn "uninstall.sh not found — skipping"
fi

# ── Step 12 — Safety checks ───────────────────────────────────────────────────
header "Step 12 — Safety checks"

# /tmp permissions
TMP_PERMS=$(stat -c "%a" /tmp)
if [ "$TMP_PERMS" != "1777" ]; then
    warn "/tmp permissions wrong ($TMP_PERMS) — fixing…"
    sudo chmod 1777 /tmp
    ok "/tmp permissions restored to 1777"
else
    ok "/tmp permissions are correct (1777)"
fi

# Ports
for PORT in 9050 9051 9040; do
    if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
        warn "Port $PORT is in use — something may conflict with Tor"
    else
        ok "Port $PORT is free"
    fi
done

# Verify cookie file exists after restart
info "Starting Tor once to generate cookie file…"
sudo systemctl start tor 2>/dev/null || true
sleep 3

COOKIE_FOUND=0
for cookie in /run/tor/control.authcookie /var/lib/tor/control_auth_cookie; do
    if [ -f "$cookie" ]; then
        ok "Cookie file found: $cookie"
        COOKIE_FOUND=1
        break
    fi
done

if [ "$COOKIE_FOUND" -eq 0 ]; then
    warn "Cookie file not found yet — Tor may still be starting."
    warn "Run: sudo systemctl start tor  then wait 10 seconds."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  ✔  TorShield installed successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${YELLOW}⚠  IMPORTANT — do ONE of these before launching:${NC}"
echo -e "  ${BOLD}Option A (recommended):${NC}  Log out and log back in"
echo -e "  ${BOLD}Option B (right now):${NC}     Run in this terminal:"
echo -e "                            ${CYAN}newgrp debian-tor${NC}"
echo ""
echo -e "  How to launch:"
echo -e "  ${BOLD}•${NC} Terminal:  ${CYAN}torshield${NC}"
echo -e "  ${BOLD}•${NC} App menu:  Search for ${CYAN}TorShield${NC}"
if [ -d "$REAL_HOME/Desktop" ]; then
echo -e "  ${BOLD}•${NC} Desktop:   Double-click ${CYAN}TorShield${NC} icon"
fi
echo ""
echo -e "  To uninstall:  ${CYAN}torshield-uninstall${NC}"
echo ""
echo -e "  ${YELLOW}⚠  On a censored network (Egypt etc.)?${NC}"
echo -e "  Get Snowflake bridges at: ${CYAN}https://bridges.torproject.org${NC}"
echo ""
