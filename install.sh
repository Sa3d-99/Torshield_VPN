#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TorShield — One-Shot Installer
#
# This script installs all dependencies and clones TorShield from GitHub.
# The source code lives in your GitHub repo — this script does NOT contain it.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
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
echo "  ║        Installer v1.0                  ║"
echo "  ╚════════════════════════════════════════╝"
echo -e "${NC}"

# ── Must NOT run as root ──────────────────────────────────────────────────────
if [ "$EUID" -eq 0 ]; then
    error "Do not run this installer with sudo.\nRun as your normal user: ./install.sh\nThe script will ask for sudo password when needed."
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

# Only adds the lines TorShield needs — never removes existing content.
# If the line already exists it is skipped, so this is safe to run multiple times.

REQUIRED_LINES=(
    "SocksPort 9050"
    "ControlPort 9051"
    "TransPort 9040"
    "DNSPort 5353"
    "AutomapHostsOnResolve 1"
)

# Create torrc if it doesn't exist yet
if [ ! -f "$TORRC_PATH" ]; then
    sudo touch "$TORRC_PATH"
    ok "Created empty $TORRC_PATH"
fi

# Back up the current torrc once
BACKUP="${TORRC_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
sudo cp "$TORRC_PATH" "$BACKUP"
ok "torrc backed up → $BACKUP"

# Add a section header so the user can find TorShield's lines easily
if ! sudo grep -q "# TorShield required settings" "$TORRC_PATH"; then
    echo "" | sudo tee -a "$TORRC_PATH" > /dev/null
    echo "# ── TorShield required settings ─────────────────────────────────────────────" | sudo tee -a "$TORRC_PATH" > /dev/null
fi

ADDED=0
for line in "${REQUIRED_LINES[@]}"; do
    # Check if the exact line (or an uncommented version) already exists
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

# ── Step 4 — Python packages ──────────────────────────────────────────────────
header "Step 4 — Python packages"

pip install --quiet --upgrade pip
pip install --quiet customtkinter stem requests PySocks fake-useragent
ok "Python packages installed"

# ── Step 5 — Copying TorShield files locally ─────────────────────────────────
header "Step 5 — Installing TorShield files"

mkdir -p "$INSTALL_DIR"

# confirm tor_vpn_gui.py exists in the current directory before copying
if [ -f "tor_vpn_gui.py" ]; then
    info "Copying app files to $INSTALL_DIR …"
    cp "tor_vpn_gui.py" "$INSTALL_DIR/"
    ok "TorShield installed locally"
else
    error "tor_vpn_gui.py not found! Make sure you run install.sh from inside the downloaded folder."
fi

# ── Step 6 — Launcher script ──────────────────────────────────────────────────
header "Step 6 — Creating launcher"

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
ok "Launcher created"

# ── Step 7 — Terminal command ─────────────────────────────────────────────────
header "Step 7 — Terminal command"

sudo ln -sf "$LAUNCHER" "$BIN_LINK"
ok "Run TorShield from any terminal by typing: torshield"

# ── Step 8 — Desktop shortcut ─────────────────────────────────────────────────
header "Step 8 — Desktop shortcut"

mkdir -p "$REAL_HOME/.local/share/applications"

cat > "$DESKTOP_FILE" << DESKTOP
[Desktop Entry]
Name=TorShield
Comment=System-Wide Tor VPN Client
Exec=$LAUNCHER
Icon=network-vpn
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

## ── Step 9 — Install uninstaller as a system command ─────────────────────────
header "Step 9 — Installing uninstaller"

if [ -f "uninstall.sh" ]; then
    sudo cp "uninstall.sh" "$UNINSTALL_BIN"
    sudo chmod +x "$UNINSTALL_BIN"
    ok "Uninstaller available as: torshield-uninstall"
else
    warn "uninstall.sh not found! Make sure it is in the same folder."
fi

# ── Step 10 — Safety checks ───────────────────────────────────────────────────
header "Step 10 — Safety checks"

# Fix /tmp permissions if wrong
TMP_PERMS=$(stat -c "%a" /tmp)
if [ "$TMP_PERMS" != "1777" ]; then
    warn "/tmp permissions are wrong ($TMP_PERMS) — fixing…"
    sudo chmod 1777 /tmp
    ok "/tmp permissions restored to 1777"
else
    ok "/tmp permissions are correct (1777)"
fi

# Check ports are free
for PORT in 9050 9051 9040; do
    if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
        warn "Port $PORT is already in use — something may conflict with Tor"
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
echo -e "  How to launch:"
echo -e "  ${BOLD}•${NC} Terminal:     ${CYAN}torshield${NC}"
echo -e "  ${BOLD}•${NC} App menu:     Search for ${CYAN}TorShield${NC}"
if [ -d "$REAL_HOME/Desktop" ]; then
echo -e "  ${BOLD}•${NC} Desktop:      Double-click ${CYAN}TorShield${NC} icon"
fi
echo ""
echo -e "  To uninstall:  ${CYAN}torshield-uninstall${NC}"
echo ""
echo -e "  ${YELLOW}⚠  Censored network (Egypt etc.)?${NC}"
echo -e "  Add bridges to /etc/tor/torrc"
echo -e "  Get them at: ${CYAN}https://bridges.torproject.org${NC}"
echo ""
