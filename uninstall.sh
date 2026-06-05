#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TorShield — Uninstaller
#
# Usage:
#   chmod +x uninstall.sh
#   ./uninstall.sh
# ─────────────────────────────────────────────────────────────────────────────

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }

# ── Paths (must match install.sh) ─────────────────────────────────────────────
REAL_HOME="$HOME"
INSTALL_DIR="$REAL_HOME/.local/share/torshield"
BIN_LINK="/usr/local/bin/torshield"
UNINSTALL_BIN="/usr/local/bin/torshield-uninstall"
DESKTOP_FILE="$REAL_HOME/.local/share/applications/torshield.desktop"
DESKTOP_ICON="$REAL_HOME/Desktop/TorShield.desktop"
TORRC_PATH="/etc/tor/torrc"

# ── Banner ────────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${RED}"
echo "  ╔════════════════════════════════════════╗"
echo "  ║   🛡  TorShield — Uninstaller          ║"
echo "  ╚════════════════════════════════════════╝"
echo -e "${NC}"

# ── Confirm ───────────────────────────────────────────────────────────────────
read -rp "  Are you sure you want to uninstall TorShield? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "\n  Cancelled — nothing was removed.\n"
    exit 0
fi

echo ""

# ── 1 — Clear iptables rules (in case routing was left active) ────────────────
info "Clearing iptables rules…"
sudo iptables -F OUTPUT 2>/dev/null || true
sudo iptables -t nat -F OUTPUT 2>/dev/null || true
ok "iptables rules cleared"

# ── 2 — Remove terminal commands ─────────────────────────────────────────────
info "Removing terminal commands…"
sudo rm -f "$BIN_LINK"
sudo rm -f "$UNINSTALL_BIN"
ok "Commands removed  (torshield, torshield-uninstall)"

# ── 3 — Remove desktop shortcuts ─────────────────────────────────────────────
info "Removing desktop shortcuts…"
rm -f "$DESKTOP_FILE"
rm -f "$DESKTOP_ICON"
ok "Desktop shortcuts removed"

# ── 4 — Remove TorShield lines from torrc (keeps your bridges & custom config) 
info "Cleaning /etc/tor/torrc…"
if [ -f "$TORRC_PATH" ]; then
    # Remove only the block that install.sh added — everything else stays
    sudo sed -i '/# ── TorShield required settings/,/^AutomapHostsOnResolve.*/d' "$TORRC_PATH" 2>/dev/null || true
    ok "TorShield lines removed from torrc — your bridges are untouched"
else
    warn "torrc not found — skipping"
fi

# ── 5 — Remove app files ──────────────────────────────────────────────────────
info "Removing app files from $INSTALL_DIR …"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    ok "App files removed"
else
    warn "Install directory not found — already removed?"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  ✔  TorShield has been completely removed.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  System packages (tor, obfs4proxy, etc.) were ${BOLD}NOT${NC} removed."
echo -e "  To remove them too:"
echo -e "  ${CYAN}sudo apt remove tor obfs4proxy snowflake-client conntrack${NC}"
echo ""
