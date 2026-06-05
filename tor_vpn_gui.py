"""
TorShield - VPN-like Tor Network Client with System-Wide Traffic Routing
========================================================================
Routes ALL system traffic (every app, browser, etc.) through Tor using
iptables transparent proxying. No need to configure individual apps.

Dependencies:
    pip install customtkinter stem requests fake-useragent

Setup:
    1. Set TOR_EXE_PATH and TORRC_PATH below
    2. Run with sudo (required for iptables):
         sudo python3 tor_vpn_gui.py

torrc minimum requirements:
    SocksPort 9050
    ControlPort 9051
    TransPort 9040
    DNSPort 5353
    AutomapHostsOnResolve 1
"""

# ─────────────────────────────────────────────────────────────────────────────
# USER CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
TOR_EXE_PATH     = "/usr/sbin/tor"
TORRC_PATH       = "/etc/tor/torrc"
CONTROL_PASSWORD = ""

SOCKS_PORT  = 9050
TRANS_PORT  = 9040   # TransPort — used for system-wide iptables routing
DNS_PORT    = 5353   # DNSPort   — Tor handles DNS to prevent leaks
CONTROL_PORT = 9051
CONTROL_HOST = "127.0.0.1"

# ─────────────────────────────────────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys
import time
import socket
import threading
import subprocess
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from typing import Optional

try:
    import customtkinter as ctk
except ImportError:
    sys.exit("Missing: pip install customtkinter")

try:
    import requests
except ImportError:
    sys.exit("Missing: pip install requests")

try:
    from stem import Signal
    from stem.control import Controller
except ImportError:
    sys.exit("Missing: pip install stem")

try:
    from fake_useragent import UserAgent
    _UA_AVAILABLE = True
except ImportError:
    _UA_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Suppress stdout/stderr if not already set (e.g. when run with sudo)
# ─────────────────────────────────────────────────────────────────────────────

if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')


# ─────────────────────────────────────────────────────────────────────────────
# Root check and elevation
# ─────────────────────────────────────────────────────────────────────────────
def ensure_root():
    if os.geteuid() != 0:
        # 1. Preserve necessary environment variables for GUI display when elevating
        display = os.environ.get('DISPLAY', ':0')
        xauth = os.environ.get('XAUTHORITY', '')
        wayland = os.environ.get('WAYLAND_DISPLAY', '')

        # 2.form the pkexec command with the necessary environment variables
        cmd = ['pkexec', 'env', f'DISPLAY={display}']
        if xauth:
            cmd.append(f'XAUTHORITY={xauth}')
        if wayland:
            cmd.append(f'WAYLAND_DISPLAY={wayland}')
        
        # 3. append the current Python executable and script arguments
        cmd.append(sys.executable)
        cmd.extend(sys.argv[1:])
        
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            print("Failed to elevate privileges. Please run with sudo or ensure pkexec is configured correctly.")
        sys.exit()

# call this at the very start to re-launch with root if not already
ensure_root()

# ─────────────────────────────────────────────────────────────────────────────
# Country codes
# ─────────────────────────────────────────────────────────────────────────────
COUNTRY_CODES: dict[str, str] = {
    "Random (Any)":   "",
    "United States":  "{us}",
    "United Kingdom": "{gb}",
    "Germany":        "{de}",
    "France":         "{fr}",
    "Netherlands":    "{nl}",
    "Sweden":         "{se}",
    "Switzerland":    "{ch}",
    "Canada":         "{ca}",
    "Australia":      "{au}",
    "Japan":          "{jp}",
    "Singapore":      "{sg}",
    "Brazil":         "{br}",
    "Romania":        "{ro}",
    "Czech Republic": "{cz}",
    "Norway":         "{no}",
    "Finland":        "{fi}",
    "Austria":        "{at}",
    "Poland":         "{pl}",
    "Luxembourg":     "{lu}",
}

# ─────────────────────────────────────────────────────────────────────────────
# Theme
# ─────────────────────────────────────────────────────────────────────────────
THEME = {
    "bg":           "#0D0D12",
    "panel":        "#13131C",
    "card":         "#1A1A28",
    "border":       "#2A2A40",
    "accent":       "#7B2FFF",
    "accent_hover": "#9B5FFF",
    "success":      "#00D68F",
    "warning":      "#FFB547",
    "danger":       "#FF3860",
    "text":         "#E8E8F0",
    "subtext":      "#8888AA",
    "log_bg":       "#0A0A10",
    "connected":    "#00D68F",
    "disconnected": "#FF3860",
}

def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# System-wide iptables routing
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd: list[str]) -> bool:
    """Run a shell command, return True on success."""
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def enable_system_routing() -> tuple[bool, str]:
    """
    Redirect ALL system TCP traffic and DNS through Tor using iptables.
    This affects every app on the machine — Chrome, curl, Discord, etc.

    Requires root (sudo). Called automatically when Connect is clicked.

    How it works:
      1. Old connections are flushed via conntrack to prevent leaks from
         existing sessions that were established before Tor was active.
      2. QUIC (UDP 443/80) is blocked — Chrome uses QUIC by default which
         bypasses TCP and cannot be tunnelled through Tor, so we reject it
         to force fallback to normal HTTPS TCP which Tor can handle.
      3. DNS queries (UDP port 53) → Tor's DNSPort (5353) so hostnames
         are resolved anonymously through Tor, preventing DNS leaks.
      4. All TCP connections → Tor's TransPort (9040) transparent proxy,
         which forwards them through the Tor circuit.
      5. Tor's own traffic is exempted so it can reach the network.
      6. Loopback (127.x.x.x) is exempted so local services still work.
    """
    try:
        # Flush all existing tracked connections so any pre-Tor sessions
        # cannot continue leaking real IP traffic after routing is enabled.
        # Wrapped in try/except — conntrack may not be installed on all systems.
        try:
            subprocess.run(
                ["conntrack", "-F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass  # conntrack not installed — safe to ignore

        # Get the UID that the tor process runs as
        result = subprocess.run(
            ["id", "-u", "debian-tor"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            tor_uid = result.stdout.strip()
        else:
            # Fall back: find UID from running tor process
            ps = subprocess.run(
                ["pgrep", "-u", "debian-tor", "tor"],
                capture_output=True, text=True
            )
            # If running as root (our case), skip uid exemption
            tor_uid = None

        # Flush existing rules first for a clean slate
        _run(["iptables", "-F", "OUTPUT"])
        _run(["iptables", "-t", "nat", "-F", "OUTPUT"])

        # Allow loopback traffic (127.x.x.x) — local services must work
        _run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        _run(["iptables", "-t", "nat", "-A", "OUTPUT",
              "-o", "lo", "-j", "RETURN"])

        # Exempt Tor's own process from redirection (prevent routing loop)
        if tor_uid:
            _run(["iptables", "-t", "nat", "-A", "OUTPUT",
                  "-m", "owner", "--uid-owner", tor_uid, "-j", "RETURN"])
            _run(["iptables", "-A", "OUTPUT",
                  "-m", "owner", "--uid-owner", tor_uid, "-j", "ACCEPT"])

        # Redirect DNS (UDP port 53) → Tor DNSPort to prevent DNS leaks
        _run(["iptables", "-t", "nat", "-A", "OUTPUT",
              "-p", "udp", "--dport", "53",
              "-j", "REDIRECT", "--to-ports", str(DNS_PORT)])

        # Redirect all TCP traffic → Tor TransPort (transparent proxy)
        _run(["iptables", "-t", "nat", "-A", "OUTPUT",
              "-p", "tcp", "--syn",
              "-j", "REDIRECT", "--to-ports", str(TRANS_PORT)])

        # Block QUIC (UDP on ports 443 and 80).
        # QUIC is a UDP-based protocol used by Chrome/HTTP3 that bypasses
        # TCP and cannot be routed through Tor's transparent proxy.
        # Rejecting it forces browsers to fall back to TCP HTTPS, which
        # Tor can handle correctly — preventing silent UDP leaks.
        _run(["iptables", "-A", "OUTPUT",
              "-p", "udp", "--dport", "443", "-j", "REJECT"])
        _run(["iptables", "-A", "OUTPUT",
              "-p", "udp", "--dport", "80",  "-j", "REJECT"])

        return True, "System-wide routing enabled — all traffic through Tor"

    except Exception as exc:
        return False, f"iptables error: {exc}"


def disable_system_routing() -> tuple[bool, str]:
    """
    Remove iptables rules and restore normal direct internet routing.
    Called automatically when Disconnect is clicked.

    Explicitly deletes the QUIC REJECT rules with -D before flushing,
    ensuring they are cleanly removed even if the flush order matters.
    """
    try:
        # Explicitly delete the QUIC block rules added during enable.
        # Using -D (delete) targets these specific rules precisely.
        _run(["iptables", "-D", "OUTPUT",
              "-p", "udp", "--dport", "443", "-j", "REJECT"])
        _run(["iptables", "-D", "OUTPUT",
              "-p", "udp", "--dport", "80",  "-j", "REJECT"])

        # Flush remaining OUTPUT and NAT rules to restore normal routing
        _run(["iptables", "-F", "OUTPUT"])
        _run(["iptables", "-t", "nat", "-F", "OUTPUT"])
        return True, "System routing restored — traffic is direct again"
    except Exception as exc:
        return False, f"Failed to restore routing: {exc}"


def check_root() -> bool:
    """Return True if running as root (required for iptables)."""
    return os.geteuid() == 0


# ─────────────────────────────────────────────────────────────────────────────
# Tor Manager
# ─────────────────────────────────────────────────────────────────────────────

class TorManager:
    def __init__(self) -> None:
        self._process:    Optional[subprocess.Popen] = None
        self._controller: Optional[Controller]       = None
        self._monitoring  = False

    def start_tor(self) -> bool:
        if not os.path.isfile(TOR_EXE_PATH):
            raise FileNotFoundError(
                f"tor not found at:\n{TOR_EXE_PATH}\n\nEdit TOR_EXE_PATH."
            )
        if not os.path.isfile(TORRC_PATH):
            raise FileNotFoundError(
                f"torrc not found at:\n{TORRC_PATH}\n\nEdit TORRC_PATH."
            )
        self._process = subprocess.Popen(
            [TOR_EXE_PATH, "-f", TORRC_PATH],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True

    def stop_tor(self) -> None:
        self._monitoring = False
        self._disconnect_controller()
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process = None

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def connect_controller(self, max_retries: int = 30,
                           delay: float = 2.0) -> None:
        for attempt in range(max_retries):
            try:
                ctrl = Controller.from_port(
                    address=CONTROL_HOST, port=CONTROL_PORT
                )
                if CONTROL_PASSWORD:
                    ctrl.authenticate(password=CONTROL_PASSWORD)
                else:
                    ctrl.authenticate()
                self._controller = ctrl
                return
            except Exception:
                if attempt < max_retries - 1:
                    time.sleep(delay)
        raise ConnectionError(
            f"Could not connect to ControlPort {CONTROL_HOST}:{CONTROL_PORT}."
        )

    def _disconnect_controller(self) -> None:
        if self._controller:
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None

    @property
    def controller(self) -> Optional[Controller]:
        return self._controller

    def set_exit_node(self, country_code: str) -> None:
        if not self._controller:
            raise RuntimeError("Controller not connected.")
        if country_code:
            self._controller.set_conf("ExitNodes", country_code)
            self._controller.set_conf("StrictNodes", "1")
        else:
            self._controller.reset_conf("ExitNodes")
            self._controller.reset_conf("StrictNodes")

    def new_identity(self) -> None:
        if not self._controller:
            raise RuntimeError("Controller not connected.")
        self._controller.signal(Signal.NEWNYM)

    def get_circuits(self) -> list[dict]:
        if not self._controller:
            return []
        circuits = []
        try:
            for circ in self._controller.get_circuits():
                if circ.status.casefold() != "built":
                    continue
                path_info = []
                for fp, nickname in circ.path:
                    try:
                        ns = self._controller.get_network_status(fp, None)
                        ip = ns.address if ns else fp
                    except Exception:
                        ip = fp
                    path_info.append((fp, nickname or fp[:8], ip))
                if path_info:
                    circuits.append({"id": circ.id, "path": path_info})
        except Exception:
            pass
        return circuits

    def start_circuit_monitoring(self, callback,
                                  interval: float = 5.0) -> None:
        self._monitoring = True
        def _loop():
            while self._monitoring:
                try:
                    callback(self.get_circuits())
                except Exception:
                    pass
                time.sleep(interval)
        threading.Thread(target=_loop, daemon=True).start()

    def stop_circuit_monitoring(self) -> None:
        self._monitoring = False


# ─────────────────────────────────────────────────────────────────────────────
# Connection test
# ─────────────────────────────────────────────────────────────────────────────

def get_tor_public_ip() -> str:
    proxies = {
        "http":  f"socks5h://127.0.0.1:{SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{SOCKS_PORT}",
    }
    headers = {}
    if _UA_AVAILABLE:
        try:
            headers["User-Agent"] = UserAgent().random
        except Exception:
            pass
    if not headers.get("User-Agent"):
        headers["User-Agent"] = (
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) "
            "Gecko/20100101 Firefox/115.0"
        )
    endpoints = [
        "https://api.ipify.org?format=json",
        "https://api64.ipify.org?format=json",
        "https://httpbin.org/ip",
        "https://ifconfig.me/ip",
    ]
    last_error = ""
    for url in endpoints:
        try:
            resp = requests.get(url, proxies=proxies,
                                headers=headers, timeout=60)
            resp.raise_for_status()
            try:
                data = resp.json()
                return data.get("ip") or data.get("origin", "Unknown")
            except ValueError:
                return resp.text.strip()
        except Exception as exc:
            last_error = str(exc)
    raise ConnectionError(
        f"All IP-echo endpoints failed.\nLast error: {last_error}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────

class TorShieldApp(ctk.CTk):

    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("TorShield  ·  System-Wide Tor VPN")
        self.geometry("980x700")
        self.minsize(860, 620)
        self.configure(fg_color=THEME["bg"])

        self._tor    = TorManager()
        self._status = "disconnected"
        self._system_routing_active = False
        self._after_id: Optional[str] = None

        self._build_ui()

        # Warn if not running as root
        if not check_root():
            self._log(
                "⚠  Not running as root — system-wide routing will be "
                "disabled. Run with: sudo python3 tor_vpn_gui.py",
                "warn"
            )
        else:
            self._log("Running as root — system-wide routing available.", "ok")

        self._log(f"Tor binary : {TOR_EXE_PATH}")
        self._log(f"torrc path : {TORRC_PATH}")

        if not os.path.isfile(TOR_EXE_PATH):
            self._log(f"tor not found at {TOR_EXE_PATH}", "error")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # Header
        header = ctk.CTkFrame(self, fg_color=THEME["panel"],
                               corner_radius=0, height=64)
        header.pack(fill="x", pady=(0, 2))
        header.pack_propagate(False)

        ctk.CTkLabel(
            header, text="🛡  TorShield",
            font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
            text_color=THEME["accent"],
        ).pack(side="left", padx=24)

        ctk.CTkLabel(
            header, text="System-Wide Tor VPN",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=THEME["subtext"],
        ).pack(side="left", padx=4)

        self._status_badge = ctk.CTkLabel(
            header, text="● DISCONNECTED",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=THEME["disconnected"],
        )
        self._status_badge.pack(side="right", padx=24)

        # Routing indicator badge
        self._routing_badge = ctk.CTkLabel(
            header, text="",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=THEME["subtext"],
        )
        self._routing_badge.pack(side="right", padx=8)

        # Body
        body = ctk.CTkFrame(self, fg_color=THEME["bg"])
        body.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        body.columnconfigure(0, weight=0, minsize=300)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color=THEME["panel"], corner_radius=12)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)

        right = ctk.CTkFrame(body, fg_color=THEME["panel"], corner_radius=12)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        self._build_left(left)
        self._build_right(right)

    def _section(self, parent, text: str) -> None:
        ctk.CTkLabel(
            parent, text=text.upper(),
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=THEME["subtext"],
        ).pack(anchor="w", padx=18, pady=(14, 2))

    def _divider(self, parent) -> None:
        ctk.CTkFrame(parent, height=1,
                     fg_color=THEME["border"]).pack(fill="x", padx=14, pady=5)

    def _build_left(self, parent) -> None:
        # ── Connect / Disconnect ──────────────────────────────────────────────
        self._section(parent, "Connection")

        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 4))
        row.columnconfigure((0, 1), weight=1)

        self._connect_btn = ctk.CTkButton(
            row, text="▶  Connect",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=THEME["accent"], hover_color=THEME["accent_hover"],
            height=42, corner_radius=8, command=self._on_connect,
        )
        self._connect_btn.grid(row=0, column=0, padx=(0, 4), sticky="ew")

        self._disconnect_btn = ctk.CTkButton(
            row, text="■  Disconnect",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=THEME["card"], hover_color=THEME["danger"],
            height=42, corner_radius=8, state="disabled",
            command=self._on_disconnect,
        )
        self._disconnect_btn.grid(row=0, column=1, padx=(4, 0), sticky="ew")

        # ── System-wide routing toggle ────────────────────────────────────────
        self._divider(parent)
        self._section(parent, "System-Wide Traffic Routing")

        # Info box
        info = ctk.CTkFrame(parent, fg_color=THEME["card"], corner_radius=8)
        info.pack(fill="x", padx=14, pady=(0, 6))
        ctk.CTkLabel(
            info,
            text=(
                "When ON — ALL apps use Tor automatically.\n"
                "Chrome, Firefox, curl, every app on this machine.\n"
                "No per-app configuration needed."
            ),
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=THEME["subtext"],
            justify="left",
        ).pack(padx=10, pady=8, anchor="w")

        self._routing_switch = ctk.CTkSwitch(
            parent,
            text="Route ALL traffic through Tor",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=THEME["text"],
            progress_color=THEME["success"],
            button_color=THEME["accent"],
            button_hover_color=THEME["accent_hover"],
            command=self._on_routing_toggle,
            state="disabled",
        )
        self._routing_switch.pack(padx=18, pady=(0, 8), anchor="w")

        if not check_root():
            ctk.CTkLabel(
                parent,
                text="⚠  Requires: sudo python3 tor_vpn_gui.py",
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=THEME["warning"],
            ).pack(anchor="w", padx=18, pady=(0, 4))

        # ── Country selector ──────────────────────────────────────────────────
        self._divider(parent)
        self._section(parent, "Exit Node Country")

        self._country_var = ctk.StringVar(value="Random (Any)")
        self._country_menu = ctk.CTkOptionMenu(
            parent,
            values=list(COUNTRY_CODES.keys()),
            variable=self._country_var,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=THEME["card"],
            button_color=THEME["accent"],
            button_hover_color=THEME["accent_hover"],
            dropdown_fg_color=THEME["card"],
            text_color=THEME["text"],
            height=36, corner_radius=8,
            command=self._on_country_change,
        )
        self._country_menu.pack(fill="x", padx=14, pady=(0, 4))

        # ── New Identity ──────────────────────────────────────────────────────
        self._divider(parent)
        self._section(parent, "Identity")

        self._newid_btn = ctk.CTkButton(
            parent, text="🔄  New Identity  (new circuit / IP)",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=THEME["card"], hover_color=THEME["warning"],
            text_color=THEME["warning"], height=38, corner_radius=8,
            state="disabled", command=self._on_new_identity,
        )
        self._newid_btn.pack(fill="x", padx=14, pady=(0, 4))

        # ── Test button ───────────────────────────────────────────────────────
        self._divider(parent)
        self._section(parent, "Connection Test")

        self._test_btn = ctk.CTkButton(
            parent, text="🔍  Test — Fetch Tor Exit IP",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=THEME["card"], hover_color=THEME["success"],
            text_color=THEME["success"], height=38, corner_radius=8,
            state="disabled", command=self._on_test_connection,
        )
        self._test_btn.pack(fill="x", padx=14, pady=(0, 4))

        # ── IP display ────────────────────────────────────────────────────────
        self._divider(parent)
        self._section(parent, "Public IP via Tor")

        ip_frame = ctk.CTkFrame(parent, fg_color=THEME["card"],
                                corner_radius=8)
        ip_frame.pack(fill="x", padx=14, pady=(0, 6))

        self._ip_label = ctk.CTkLabel(
            ip_frame, text="—",
            font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
            text_color=THEME["success"],
        )
        self._ip_label.pack(padx=12, pady=10)

        # ── Uptime ────────────────────────────────────────────────────────────
        self._divider(parent)
        self._uptime_label = ctk.CTkLabel(
            parent, text="Uptime: —",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=THEME["subtext"],
        )
        self._uptime_label.pack(anchor="w", padx=18, pady=(0, 10))
        self._connect_time: Optional[float] = None

    def _build_right(self, parent) -> None:
        # Circuit tracker
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=14, pady=(14, 2))

        ctk.CTkLabel(
            hdr, text="ACTIVE TOR CIRCUITS  (3-HOP PATH)",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=THEME["subtext"],
        ).pack(side="left")

        self._circ_ts = ctk.CTkLabel(
            hdr, text="",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=THEME["subtext"],
        )
        self._circ_ts.pack(side="right")

        self._circuit_box = ctk.CTkTextbox(
            parent,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=THEME["log_bg"], text_color=THEME["text"],
            corner_radius=8, wrap="word", height=190,
            activate_scrollbars=True, state="disabled",
        )
        self._circuit_box.pack(fill="x", padx=14, pady=(0, 4))

        ctk.CTkFrame(parent, height=1,
                     fg_color=THEME["border"]).pack(fill="x", padx=14, pady=5)

        log_hdr = ctk.CTkFrame(parent, fg_color="transparent")
        log_hdr.pack(fill="x", padx=14, pady=(0, 2))

        ctk.CTkLabel(
            log_hdr, text="ACTIVITY LOG",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=THEME["subtext"],
        ).pack(side="left")

        ctk.CTkButton(
            log_hdr, text="Clear",
            font=ctk.CTkFont(family="Consolas", size=9),
            width=50, height=20,
            fg_color=THEME["border"], hover_color=THEME["card"],
            text_color=THEME["subtext"], corner_radius=4,
            command=self._clear_log,
        ).pack(side="right")

        self._log_box = ctk.CTkTextbox(
            parent,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=THEME["log_bg"], text_color=THEME["text"],
            corner_radius=8, wrap="word",
            activate_scrollbars=True, state="disabled",
        )
        self._log_box.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, message: str, level: str = "info") -> None:
        prefix = {"info": "  ", "ok": "✔ ", "warn": "⚠ ",
                  "error": "✖ "}.get(level, "  ")
        line = f"[{ts()}] {prefix}{message}\n"
        def _append():
            self._log_box.configure(state="normal")
            self._log_box.insert("end", line)
            self._log_box.configure(state="disabled")
            self._log_box.see("end")
        self.after(0, _append)

    def _clear_log(self) -> None:
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")

    # ── Status ────────────────────────────────────────────────────────────────

    def _set_status(self, status: str) -> None:
        self._status = status
        if status == "connected":
            self._status_badge.configure(
                text="● CONNECTED", text_color=THEME["connected"])
            self._connect_btn.configure(state="disabled")
            self._disconnect_btn.configure(state="normal")
            self._newid_btn.configure(state="normal")
            self._test_btn.configure(state="normal")
            if check_root():
                self._routing_switch.configure(state="normal")
            self._connect_time = time.time()
            self._update_uptime()
        elif status == "connecting":
            self._status_badge.configure(
                text="◌ CONNECTING…", text_color=THEME["warning"])
            for b in [self._connect_btn, self._disconnect_btn,
                      self._newid_btn, self._test_btn]:
                b.configure(state="disabled")
            self._routing_switch.configure(state="disabled")
        else:
            self._status_badge.configure(
                text="● DISCONNECTED", text_color=THEME["disconnected"])
            self._connect_btn.configure(state="normal")
            self._disconnect_btn.configure(state="disabled")
            self._newid_btn.configure(state="disabled")
            self._test_btn.configure(state="disabled")
            self._routing_switch.configure(state="disabled")
            self._connect_time = None
            if self._after_id:
                self.after_cancel(self._after_id)
            self._uptime_label.configure(text="Uptime: —")
            self._ip_label.configure(text="—")

    def _update_uptime(self) -> None:
        if self._connect_time and self._status == "connected":
            elapsed = int(time.time() - self._connect_time)
            h, rem = divmod(elapsed, 3600)
            m, s   = divmod(rem, 60)
            self._uptime_label.configure(
                text=f"Uptime: {h:02d}:{m:02d}:{s:02d}")
            self._after_id = self.after(1000, self._update_uptime)

    # ── Circuit display ───────────────────────────────────────────────────────

    def _update_circuit_display(self, circuits: list[dict]) -> None:
        def _render():
            self._circuit_box.configure(state="normal")
            self._circuit_box.delete("1.0", "end")
            if not circuits:
                self._circuit_box.insert(
                    "end", "  No built circuits detected yet…\n")
            else:
                for circ in circuits:
                    self._circuit_box.insert(
                        "end", f"  Circuit #{circ['id']}\n")
                    labels = ["Entry Guard  ", "Middle Relay ", "Exit Node    "]
                    icons  = ["🟢", "🟡", "🔴"]
                    for idx, (fp, nick, ip) in enumerate(circ["path"]):
                        lbl  = labels[idx] if idx < 3 else f"Hop {idx+1}     "
                        icon = icons[idx]  if idx < 3 else "⚪"
                        self._circuit_box.insert(
                            "end",
                            f"    {icon} {lbl} │  {ip:<18}  ({nick})\n"
                        )
                    self._circuit_box.insert("end", "\n")
            self._circuit_box.configure(state="disabled")
            self._circ_ts.configure(text=f"last updated {ts()}")
        self.after(0, _render)

    # ── Button handlers ───────────────────────────────────────────────────────

    def _on_connect(self) -> None:
        self._set_status("connecting")
        self._log("Starting Tor daemon…")

        def _worker():
            try:
                self._tor.start_tor()
                self._log("Tor process launched. Waiting for ControlPort…")
                self._tor.connect_controller(max_retries=30, delay=2.0)
                self._log("Controller connected on port 9051.", "ok")

                country_code = COUNTRY_CODES.get(self._country_var.get(), "")
                if country_code:
                    self._tor.set_exit_node(country_code)
                    self._log(
                        f"Exit node set to: {self._country_var.get()}", "ok")

                self._tor.start_circuit_monitoring(
                    callback=self._update_circuit_display, interval=5.0)

                self.after(0, lambda: self._set_status("connected"))
                self._log(
                    "Connected! Tor is running. Enable the routing switch "
                    "to route ALL system traffic through Tor.", "ok")

            except FileNotFoundError as exc:
                self.after(0, lambda: self._set_status("disconnected"))
                self._log(str(exc), "error")
                self.after(0, lambda: messagebox.showerror(
                    "File Not Found", str(exc)))
            except Exception as exc:
                self.after(0, lambda: self._set_status("disconnected"))
                self._log(f"Error: {exc}", "error")

        threading.Thread(target=_worker, daemon=True).start()

    def _on_disconnect(self) -> None:
        # Always disable system routing before stopping Tor
        if self._system_routing_active:
            self._log("Disabling system-wide routing…")
            ok, msg = disable_system_routing()
            self._system_routing_active = False
            self._log(msg, "ok" if ok else "error")
            self.after(0, lambda: self._routing_switch.deselect())
            self.after(0, lambda: self._routing_badge.configure(text=""))

        self._log("Disconnecting…")
        self._tor.stop_circuit_monitoring()

        def _worker():
            self._tor.stop_tor()
            self.after(0, lambda: self._set_status("disconnected"))
            self.after(0, lambda: self._update_circuit_display([]))
            self._log("Tor stopped. All circuits closed.", "ok")

        threading.Thread(target=_worker, daemon=True).start()

    def _on_routing_toggle(self) -> None:
        """
        Toggle system-wide iptables routing on/off.
        When ON  → ALL traffic from every app goes through Tor.
        When OFF → traffic returns to normal direct routing.
        """
        if self._routing_switch.get():
            # Switch turned ON
            self._log("Enabling system-wide traffic routing via iptables…")

            def _enable():
                ok, msg = enable_system_routing()
                self._system_routing_active = ok
                self._log(msg, "ok" if ok else "error")
                if ok:
                    self.after(0, lambda: self._routing_badge.configure(
                        text="🌐 ALL TRAFFIC → TOR",
                        text_color=THEME["success"]
                    ))
                    self._log(
                        "Every app on this machine now uses Tor. "
                        "Open any browser — it will show the Tor IP.", "ok")
                else:
                    self.after(0, lambda: self._routing_switch.deselect())

            threading.Thread(target=_enable, daemon=True).start()
        else:
            # Switch turned OFF
            self._log("Disabling system-wide routing…")

            def _disable():
                ok, msg = disable_system_routing()
                self._system_routing_active = False
                self._log(msg, "ok" if ok else "error")
                self.after(0, lambda: self._routing_badge.configure(text=""))

            threading.Thread(target=_disable, daemon=True).start()

    def _on_country_change(self, selection: str) -> None:
        country_code = COUNTRY_CODES.get(selection, "")
        if self._status != "connected":
            self._log(f"Exit node queued: {selection}")
            return

        def _worker():
            try:
                self._tor.set_exit_node(country_code)
                self._log(
                    f"Exit node changed to: {selection}" if country_code
                    else "Exit node restriction removed (Random).", "ok")
                time.sleep(0.5)
                self._tor.new_identity()
                self._log("New circuit requested.", "info")
            except Exception as exc:
                self._log(f"Failed to change exit node: {exc}", "error")

        threading.Thread(target=_worker, daemon=True).start()

    def _on_new_identity(self) -> None:
        self._log("Requesting new identity (NEWNYM)…")
        def _worker():
            try:
                self._tor.new_identity()
                self._log(
                    "New identity requested. Circuit rebuilding shortly "
                    "(10-second rate limit may apply).", "ok")
            except Exception as exc:
                self._log(f"New identity failed: {exc}", "error")
        threading.Thread(target=_worker, daemon=True).start()

    def _on_test_connection(self) -> None:
        self._log("Testing connection through Tor SOCKS5 proxy…")
        self._ip_label.configure(text="…", text_color=THEME["warning"])
        self._test_btn.configure(state="disabled")

        def _worker():
            try:
                ip = get_tor_public_ip()
                self.after(0, lambda: self._ip_label.configure(
                    text=ip, text_color=THEME["success"]))
                self._log(f"Public IP via Tor: {ip}", "ok")
                if _UA_AVAILABLE:
                    self._log("Randomised User-Agent applied.", "ok")
            except Exception as exc:
                self.after(0, lambda: self._ip_label.configure(
                    text="Error", text_color=THEME["danger"]))
                self._log(f"Connection test failed: {exc}", "error")
            finally:
                self.after(0, lambda: self._test_btn.configure(state="normal"))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_close(self) -> None:
        if self._status in ("connected", "connecting"):
            if messagebox.askyesno(
                "Quit TorShield",
                "Tor is running. Stop Tor and restore normal routing?"
            ):
                if self._system_routing_active:
                    disable_system_routing()
                self._tor.stop_tor()
                self.destroy()
        else:
            if self._system_routing_active:
                disable_system_routing()
            self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = TorShieldApp()
    app.mainloop()
