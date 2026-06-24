"""
TorShield - VPN-like Tor Network Client with System-Wide Traffic Routing
========================================================================
Routes ALL system traffic (every app, browser, etc.) through Tor using
iptables transparent proxying. No need to configure individual apps.

Highlights (v2.1):
  • Portable: Tor + transport binaries are auto-detected (or read from the
    install-time config) so it runs the same on any Debian-family laptop.
  • Resilient connect: an "Auto" mode tries a DIRECT connection first and
    automatically falls back to Snowflake / obfs4 bridges if Tor cannot
    bootstrap — the main fix for "it won't connect on my friend's machine".
  • Safe elevation: if pkexec is missing it degrades gracefully instead of
    crashing on launch.
  • Refreshed UI: slate-dark theme, monospace terminal log, live 3-hop
    circuit visualisation.

Dependencies:  pip install -r requirements.txt
Setup:         run install.sh once, then type: torshield
"""

# ─────────────────────────────────────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────────────────────────────────────
import os
import re
import sys
import time
import shutil
import socket
import threading
import subprocess
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Suppress stdout/stderr if not set (e.g. when run with pkexec/sudo)
# ─────────────────────────────────────────────────────────────────────────────
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")


def _die(msg: str) -> None:
    """Show a friendly error instead of a raw traceback, then exit."""
    try:
        import tkinter.messagebox as mb
        r = tk.Tk(); r.withdraw()
        mb.showerror("TorShield — missing dependency", msg)
        r.destroy()
    except Exception:
        pass
    sys.exit(msg)


try:
    import customtkinter as ctk
except ImportError:
    _die("Missing dependency: customtkinter\n\nInstall with:\n  pip install -r requirements.txt")

try:
    import requests
except ImportError:
    _die("Missing dependency: requests\n\nInstall with:\n  pip install -r requirements.txt")

try:
    from stem import Signal
    from stem.control import Controller
except ImportError:
    _die("Missing dependency: stem\n\nInstall with:\n  pip install -r requirements.txt")

try:
    from fake_useragent import UserAgent
    _UA_AVAILABLE = True
except ImportError:
    _UA_AVAILABLE = False

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Machine configuration — written by install.sh, with safe auto-detection
# fallbacks so the app still works when run straight from the source folder.
# ─────────────────────────────────────────────────────────────────────────────
def _detect_bin(name: str, *candidates: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return ""


def _load_conf() -> dict:
    """Read torshield.conf (KEY=VALUE) from the install dir or alongside this file."""
    conf: dict[str, str] = {}
    candidates = [
        os.path.expanduser("~/.local/share/torshield/torshield.conf"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "torshield.conf"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    for raw in fh:
                        raw = raw.strip()
                        if not raw or raw.startswith("#") or "=" not in raw:
                            continue
                        k, _, v = raw.partition("=")
                        conf[k.strip()] = v.strip()
                break
            except Exception:
                pass
    return conf


_CONF = _load_conf()

TOR_EXE_PATH     = _CONF.get("TOR_EXE") or _detect_bin(
    "tor", "/usr/sbin/tor", "/usr/bin/tor", "/usr/local/bin/tor") or "/usr/sbin/tor"
TORRC_PATH       = _CONF.get("TORRC_PATH") or "/etc/tor/torrc"
SNOWFLAKE_CLIENT = _CONF.get("SNOWFLAKE_CLIENT") or _detect_bin(
    "snowflake-client", "/usr/bin/snowflake-client")
OBFS4PROXY       = _CONF.get("OBFS4PROXY") or _detect_bin(
    "obfs4proxy", "/usr/bin/obfs4proxy", "/usr/lib/tor/obfs4proxy")

CONTROL_PASSWORD = ""          # Leave empty — cookie auth is used automatically

SOCKS_PORT   = 9050
TRANS_PORT   = 9040
DNS_PORT     = 5353
CONTROL_PORT = 9051
CONTROL_HOST = "127.0.0.1"

# Where the user's own obfs4 bridges live (added via the app / bridges.torproject.org)
OBFS4_BRIDGES_FILE = os.path.expanduser("~/.local/share/torshield/obfs4_bridges.txt")

# The standard Snowflake bridge line (the IP is a placeholder — the broker
# rendezvouses real peers, so no fresh certificate is ever needed).
SNOWFLAKE_BRIDGE_LINE = (
    "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "url=https://snowflake-broker.torproject.net/ front=foursquare.com"
)

_BRIDGE_HEAD = "# >>> TORSHIELD MANAGED BRIDGES — DO NOT EDIT BY HAND <<<"
_BRIDGE_TAIL = "# <<< TORSHIELD MANAGED BRIDGES END >>>"


# ─────────────────────────────────────────────────────────────────────────────
# Root check and graceful elevation via pkexec → sudo → unprivileged
# ─────────────────────────────────────────────────────────────────────────────
def ensure_root() -> None:
    if os.geteuid() == 0:
        return

    display = os.environ.get("DISPLAY", ":0")
    xauth   = os.environ.get("XAUTHORITY", "")
    wayland = os.environ.get("WAYLAND_DISPLAY", "")

    if shutil.which("pkexec"):
        cmd = ["pkexec", "env", f"DISPLAY={display}"]
        if xauth:
            cmd.append(f"XAUTHORITY={xauth}")
        if wayland:
            cmd.append(f"WAYLAND_DISPLAY={wayland}")
        cmd += [sys.executable] + sys.argv[1:]
        try:
            subprocess.check_call(cmd)
            sys.exit()          # the elevated child ran the GUI
        except FileNotFoundError:
            pass                # pkexec vanished mid-call — try the next option
        except subprocess.CalledProcessError:
            # User cancelled the password prompt, or polkit refused. Fall back to
            # opening the app unprivileged rather than crashing.
            return

    # No pkexec (or it failed). The app will open unprivileged: it still works,
    # only system-wide iptables routing is unavailable.
    return


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
# Theme  (slate-dark + Tor-purple accent, green = secure — per ui-ux-pro-max)
# ─────────────────────────────────────────────────────────────────────────────
THEME = {
    "bg":           "#020617",   # slate-950 base
    "panel":        "#0B1120",   # deep panel
    "card":         "#0F172A",   # slate-900 card
    "card_alt":     "#1E293B",   # slate-800 raised
    "border":       "#1E293B",
    "accent":       "#A855F7",   # Tor purple
    "accent_hover": "#C084FC",
    "success":      "#22C55E",
    "warning":      "#F59E0B",
    "danger":       "#EF4444",
    "info":         "#38BDF8",
    "text":         "#F8FAFC",
    "subtext":      "#94A3B8",
    "muted":        "#64748B",
    "log_bg":       "#010409",
    "connected":    "#22C55E",
    "disconnected": "#EF4444",
    "entry":        "#22C55E",   # circuit hop colours
    "middle":       "#F59E0B",
    "exit":         "#EF4444",
}

# Font families — first available is used (set after the root window exists).
_MONO_CANDIDATES = ["Fira Code", "JetBrains Mono", "DejaVu Sans Mono",
                    "Consolas", "Liberation Mono", "monospace"]
_UI_CANDIDATES   = ["Fira Sans", "Inter", "Ubuntu", "Cantarell",
                    "DejaVu Sans", "sans-serif"]
MONO_FAMILY = "monospace"
UI_FAMILY   = "sans-serif"


def _pick_family(candidates: list[str], default: str) -> str:
    try:
        available = set(tkfont.families())
        for fam in candidates:
            if fam in available:
                return fam
    except Exception:
        pass
    return default


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# torrc bridge management (writes the managed block between the markers)
# ─────────────────────────────────────────────────────────────────────────────
def load_obfs4_bridges() -> list[str]:
    """Return user-supplied obfs4 'Bridge obfs4 ...' lines, if any."""
    lines: list[str] = []
    if os.path.isfile(OBFS4_BRIDGES_FILE):
        try:
            with open(OBFS4_BRIDGES_FILE, encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    if not raw.lower().startswith("bridge "):
                        raw = "Bridge " + raw
                    lines.append(raw)
        except Exception:
            pass
    return lines


def build_bridge_block(mode: str) -> str:
    """Build the managed bridge block for a concrete mode (not 'Auto')."""
    body: list[str] = [_BRIDGE_HEAD, f"# mode: {mode}"]
    if mode == "Direct":
        body.append("UseBridges 0")
    elif mode == "Snowflake":
        body.append("UseBridges 1")
        if SNOWFLAKE_CLIENT:
            body.append(SNOWFLAKE_BRIDGE_LINE)
    elif mode == "obfs4":
        body.append("UseBridges 1")
        body.extend(load_obfs4_bridges())
    body.append(_BRIDGE_TAIL)
    return "\n".join(body) + "\n"


def apply_bridge_mode(mode: str) -> None:
    """Rewrite the managed block of /etc/tor/torrc for `mode`. Needs root."""
    block = build_bridge_block(mode)
    try:
        with open(TORRC_PATH, encoding="utf-8") as fh:
            content = fh.read()
    except Exception as exc:
        raise RuntimeError(f"Cannot read {TORRC_PATH}: {exc}")

    pattern = re.compile(
        re.escape(_BRIDGE_HEAD) + r".*?" + re.escape(_BRIDGE_TAIL),
        re.DOTALL,
    )
    if pattern.search(content):
        content = pattern.sub(block.rstrip("\n"), content)
    else:
        content = content.rstrip("\n") + "\n\n" + block

    try:
        with open(TORRC_PATH, "w", encoding="utf-8") as fh:
            fh.write(content)
    except Exception as exc:
        raise RuntimeError(f"Cannot write {TORRC_PATH} (need root): {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# System-wide iptables routing
# ─────────────────────────────────────────────────────────────────────────────
def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def enable_system_routing() -> tuple[bool, str]:
    """Redirect ALL system TCP traffic and DNS through Tor using iptables."""
    try:
        try:
            subprocess.run(["conntrack", "-F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass   # conntrack not installed — safe to ignore

        result = subprocess.run(["id", "-u", "debian-tor"],
                                capture_output=True, text=True)
        tor_uid = result.stdout.strip() if result.returncode == 0 else None

        _run(["iptables", "-F", "OUTPUT"])
        _run(["iptables", "-t", "nat", "-F", "OUTPUT"])
        _run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        _run(["iptables", "-t", "nat", "-A", "OUTPUT", "-o", "lo", "-j", "RETURN"])

        if tor_uid:
            _run(["iptables", "-t", "nat", "-A", "OUTPUT",
                  "-m", "owner", "--uid-owner", tor_uid, "-j", "RETURN"])
            _run(["iptables", "-A", "OUTPUT",
                  "-m", "owner", "--uid-owner", tor_uid, "-j", "ACCEPT"])

        _run(["iptables", "-t", "nat", "-A", "OUTPUT",
              "-p", "udp", "--dport", "53",
              "-j", "REDIRECT", "--to-ports", str(DNS_PORT)])
        _run(["iptables", "-t", "nat", "-A", "OUTPUT",
              "-p", "tcp", "--syn",
              "-j", "REDIRECT", "--to-ports", str(TRANS_PORT)])

        _run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"])
        _run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "80",  "-j", "REJECT"])

        return True, "System-wide routing enabled — all traffic through Tor"
    except Exception as exc:
        return False, f"iptables error: {exc}"


def disable_system_routing() -> tuple[bool, str]:
    """Remove iptables rules and restore normal direct internet routing."""
    try:
        _run(["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"])
        _run(["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "80",  "-j", "REJECT"])
        _run(["iptables", "-F", "OUTPUT"])
        _run(["iptables", "-t", "nat", "-F", "OUTPUT"])
        return True, "System routing restored — traffic is direct again"
    except Exception as exc:
        return False, f"Failed to restore routing: {exc}"


def check_root() -> bool:
    return os.geteuid() == 0


# ─────────────────────────────────────────────────────────────────────────────
# Cookie file locations
# ─────────────────────────────────────────────────────────────────────────────
_COOKIE_PATHS = [
    "/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
    "/var/run/tor/control.authcookie",
]


# ─────────────────────────────────────────────────────────────────────────────
# Tor Manager
# ─────────────────────────────────────────────────────────────────────────────
class TorManager:

    def __init__(self) -> None:
        self._process:      Optional[subprocess.Popen] = None
        self._controller:   Optional[Controller]       = None
        self._monitoring    = False
        self._user_data_dir: Optional[str]             = None

    # ── Start / stop Tor ────────────────────────────────────────────────────

    def start_tor(self) -> bool:
        if not os.path.isfile(TOR_EXE_PATH):
            raise FileNotFoundError(
                f"Tor binary not found: {TOR_EXE_PATH}\n"
                "Run: sudo apt-get install tor"
            )
        if not os.path.isfile(TORRC_PATH):
            raise FileNotFoundError(
                f"torrc not found: {TORRC_PATH}\nRun install.sh to set it up."
            )

        extra_args: list[str] = []
        if not os.access("/var/lib/tor", os.W_OK):
            self._user_data_dir = os.path.expanduser(
                "~/.local/share/torshield/tor-data")
            os.makedirs(self._user_data_dir, mode=0o700, exist_ok=True)
            extra_args = ["--DataDirectory", self._user_data_dir]

        cmd = [TOR_EXE_PATH, "-f", TORRC_PATH] + extra_args
        self._process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        try:
            self._process.wait(timeout=3)
            stderr_out = ""
            if self._process.stderr:
                stderr_out = self._process.stderr.read().decode(
                    "utf-8", errors="replace")
            raise RuntimeError(
                "Tor exited immediately after launch.\n\n"
                "Common causes:\n"
                "  • /etc/tor/torrc has a syntax error\n"
                "  • a pluggable-transport binary is missing\n"
                "  • DataDirectory not writable\n"
                "  • Port 9050/9051/9040 already in use\n\n"
                f"Tor output:\n{stderr_out[-800:] if stderr_out else '(none)'}"
            )
        except subprocess.TimeoutExpired:
            pass   # still running after 3 s — good
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

    # ── Controller ──────────────────────────────────────────────────────────

    def connect_controller(self, max_retries: int = 30,
                            delay: float = 2.0) -> None:
        cookie_paths = list(_COOKIE_PATHS)
        if self._user_data_dir:
            cookie_paths.insert(
                0, os.path.join(self._user_data_dir, "control_auth_cookie"))

        last_error: Exception = ConnectionError("No attempt made yet")
        for attempt in range(max_retries):
            try:
                ctrl = Controller.from_port(address=CONTROL_HOST, port=CONTROL_PORT)
                authenticated = False

                if CONTROL_PASSWORD and not authenticated:
                    try:
                        ctrl.authenticate(password=CONTROL_PASSWORD)
                        authenticated = True
                    except Exception:
                        pass

                if not authenticated:
                    for cookie_path in cookie_paths:
                        if os.path.isfile(cookie_path):
                            try:
                                with open(cookie_path, "rb") as f:
                                    ctrl.authenticate(f.read())
                                authenticated = True
                                break
                            except Exception:
                                continue

                if not authenticated:
                    ctrl.authenticate()

                self._controller = ctrl
                return
            except Exception as exc:
                last_error = exc
                if attempt < max_retries - 1:
                    time.sleep(delay)

        found = [p for p in cookie_paths if os.path.isfile(p)]
        if not found:
            hint = (
                "\n\nNo cookie file found. Fix:\n"
                "  sudo systemctl restart tor\n"
                "  sudo usermod -a -G debian-tor $USER\n"
                "  newgrp debian-tor    (or log out and back in)"
            )
        else:
            hint = (
                f"\n\nCookie found at: {found[0]}\n"
                "But read failed — confirm your user is in the debian-tor group:\n"
                "  sudo usermod -a -G debian-tor $USER  &&  newgrp debian-tor"
            )
        raise ConnectionError(
            f"Could not connect to ControlPort {CONTROL_HOST}:{CONTROL_PORT}\n"
            f"Last error: {last_error}{hint}")

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

    # ── Bootstrap progress (used by Auto mode) ──────────────────────────────

    def bootstrap_progress(self) -> int:
        """Return Tor bootstrap percentage (0-100), or -1 if unavailable."""
        if not self._controller:
            return -1
        try:
            line = self._controller.get_info("status/bootstrap-phase")
            m = re.search(r"PROGRESS=(\d+)", line)
            return int(m.group(1)) if m else 0
        except Exception:
            return -1

    def wait_for_bootstrap(self, timeout: float, on_progress=None) -> bool:
        """Poll bootstrap until 100% or `timeout` seconds elapse."""
        deadline = time.time() + timeout
        last = -1
        while time.time() < deadline:
            pct = self.bootstrap_progress()
            if pct != last and on_progress and pct >= 0:
                on_progress(pct)
                last = pct
            if pct >= 100:
                return True
            time.sleep(1.0)
        return self.bootstrap_progress() >= 100

    # ── Exit node / identity / circuits ─────────────────────────────────────

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

    def start_circuit_monitoring(self, callback, interval: float = 5.0) -> None:
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
            "Gecko/20100101 Firefox/115.0")
    endpoints = [
        "https://api.ipify.org?format=json",
        "https://api64.ipify.org?format=json",
        "https://httpbin.org/ip",
        "https://ifconfig.me/ip",
    ]
    last_error = ""
    for url in endpoints:
        try:
            resp = requests.get(url, proxies=proxies, headers=headers, timeout=60)
            resp.raise_for_status()
            try:
                data = resp.json()
                return data.get("ip") or data.get("origin", "Unknown")
            except ValueError:
                return resp.text.strip()
        except Exception as exc:
            last_error = str(exc)
    raise ConnectionError(f"All IP-echo endpoints failed.\nLast error: {last_error}")


# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────
class TorShieldApp(ctk.CTk):

    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        global MONO_FAMILY, UI_FAMILY
        MONO_FAMILY = _pick_family(_MONO_CANDIDATES, "monospace")
        UI_FAMILY   = _pick_family(_UI_CANDIDATES, "sans-serif")

        self.title("TorShield  ·  System-Wide Tor VPN")
        self.geometry("1040x740")
        self.minsize(900, 660)
        self.configure(fg_color=THEME["bg"])

        self._tor    = TorManager()
        self._status = "disconnected"
        self._system_routing_active = False
        self._after_id: Optional[str] = None
        self._connect_time: Optional[float] = None

        self._bridge_mode = ctk.StringVar(value="Auto")

        self._logo_image = None
        if _PIL_AVAILABLE:
            _logo_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "Header_Logo.png")
            if os.path.isfile(_logo_path):
                try:
                    _pil = Image.open(_logo_path).resize((38, 38), Image.LANCZOS)
                    self._logo_image = ctk.CTkImage(
                        light_image=_pil, dark_image=_pil, size=(38, 38))
                except Exception:
                    self._logo_image = None

        self._build_ui()
        self._print_environment()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Fonts ────────────────────────────────────────────────────────────────
    def _mono(self, size: int, weight: str = "normal") -> ctk.CTkFont:
        return ctk.CTkFont(family=MONO_FAMILY, size=size, weight=weight)

    def _ui(self, size: int, weight: str = "normal") -> ctk.CTkFont:
        return ctk.CTkFont(family=UI_FAMILY, size=size, weight=weight)

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        self._build_header()

        body = ctk.CTkFrame(self, fg_color=THEME["bg"])
        body.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        body.columnconfigure(0, weight=0, minsize=320)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = ctk.CTkScrollableFrame(
            body, fg_color=THEME["panel"], corner_radius=14,
            scrollbar_button_color=THEME["card_alt"],
            scrollbar_button_hover_color=THEME["accent"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)

        right = ctk.CTkFrame(body, fg_color=THEME["panel"], corner_radius=14)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        self._build_left(left)
        self._build_right(right)

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=THEME["panel"],
                              corner_radius=0, height=68)
        header.pack(fill="x", pady=(0, 2))
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text="  TorShield" if self._logo_image else "🛡  TorShield",
            image=self._logo_image, compound="left",
            font=self._ui(23, "bold"), text_color=THEME["text"],
        ).pack(side="left", padx=24)

        ctk.CTkLabel(
            header, text="System-Wide Tor VPN",
            font=self._mono(11), text_color=THEME["subtext"],
        ).pack(side="left", padx=2, pady=(6, 0))

        self._status_badge = ctk.CTkLabel(
            header, text="●  DISCONNECTED",
            font=self._mono(12, "bold"), text_color=THEME["disconnected"],
        )
        self._status_badge.pack(side="right", padx=24)

        self._routing_badge = ctk.CTkLabel(
            header, text="", font=self._mono(10),
            text_color=THEME["subtext"])
        self._routing_badge.pack(side="right", padx=8)

    def _section(self, parent, text: str) -> None:
        ctk.CTkLabel(
            parent, text=text.upper(), font=self._mono(9, "bold"),
            text_color=THEME["muted"],
        ).pack(anchor="w", padx=18, pady=(16, 4))

    def _divider(self, parent) -> None:
        ctk.CTkFrame(parent, height=1, fg_color=THEME["border"]).pack(
            fill="x", padx=14, pady=6)

    def _card(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color=THEME["card"], corner_radius=10)
        f.pack(fill="x", padx=14, pady=(0, 6))
        return f

    # ── Left column — controls ───────────────────────────────────────────────
    def _build_left(self, parent) -> None:
        self._section(parent, "Connection")

        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 4))
        row.columnconfigure((0, 1), weight=1)

        self._connect_btn = ctk.CTkButton(
            row, text="▶  Connect", font=self._ui(13, "bold"),
            fg_color=THEME["accent"], hover_color=THEME["accent_hover"],
            text_color="#0B0614", height=44, corner_radius=9,
            command=self._on_connect)
        self._connect_btn.grid(row=0, column=0, padx=(0, 4), sticky="ew")

        self._disconnect_btn = ctk.CTkButton(
            row, text="■  Disconnect", font=self._ui(13, "bold"),
            fg_color=THEME["card_alt"], hover_color=THEME["danger"],
            height=44, corner_radius=9, state="disabled",
            command=self._on_disconnect)
        self._disconnect_btn.grid(row=0, column=1, padx=(4, 0), sticky="ew")

        # Bootstrap progress bar
        self._progress = ctk.CTkProgressBar(
            parent, height=6, corner_radius=3,
            fg_color=THEME["card_alt"], progress_color=THEME["accent"])
        self._progress.set(0)
        self._progress.pack(fill="x", padx=16, pady=(8, 0))
        self._progress_label = ctk.CTkLabel(
            parent, text="idle", font=self._mono(9),
            text_color=THEME["muted"])
        self._progress_label.pack(anchor="w", padx=18, pady=(2, 0))

        self._divider(parent)
        self._section(parent, "Connection Mode (bridges)")

        info = self._card(parent)
        ctk.CTkLabel(
            info,
            text=("Auto tries a direct connection first, then falls\n"
                  "back to Snowflake / obfs4 bridges if blocked.\n"
                  "Best choice on a censored network."),
            font=self._mono(10), text_color=THEME["subtext"],
            justify="left").pack(padx=10, pady=8, anchor="w")

        modes = ["Auto", "Snowflake", "obfs4", "Direct"]
        self._mode_menu = ctk.CTkSegmentedButton(
            parent, values=modes, variable=self._bridge_mode,
            font=self._mono(11, "bold"),
            selected_color=THEME["accent"],
            selected_hover_color=THEME["accent_hover"],
            unselected_color=THEME["card"],
            unselected_hover_color=THEME["card_alt"],
            fg_color=THEME["card"], text_color=THEME["text"],
            command=self._on_mode_change)
        self._mode_menu.pack(fill="x", padx=14, pady=(0, 4))

        self._mode_hint = ctk.CTkLabel(
            parent, text="", font=self._mono(9), text_color=THEME["muted"],
            justify="left", wraplength=270)
        self._mode_hint.pack(anchor="w", padx=18, pady=(0, 4))
        self._refresh_mode_hint()

        self._divider(parent)
        self._section(parent, "System-Wide Traffic Routing")

        info2 = self._card(parent)
        ctk.CTkLabel(
            info2,
            text=("When ON — every app (Chrome, curl, Discord…)\n"
                  "uses Tor automatically. No per-app setup."),
            font=self._mono(10), text_color=THEME["subtext"],
            justify="left").pack(padx=10, pady=8, anchor="w")

        self._routing_switch = ctk.CTkSwitch(
            parent, text="Route ALL traffic through Tor",
            font=self._mono(12, "bold"), text_color=THEME["text"],
            progress_color=THEME["success"], button_color=THEME["accent"],
            button_hover_color=THEME["accent_hover"],
            command=self._on_routing_toggle, state="disabled")
        self._routing_switch.pack(padx=18, pady=(0, 8), anchor="w")

        if not check_root():
            ctk.CTkLabel(
                parent, text="⚠  Routing needs root (pkexec/sudo)",
                font=self._mono(9), text_color=THEME["warning"],
            ).pack(anchor="w", padx=18, pady=(0, 4))

        self._divider(parent)
        self._section(parent, "Exit Node Country")

        self._country_var = ctk.StringVar(value="Random (Any)")
        self._country_menu = ctk.CTkOptionMenu(
            parent, values=list(COUNTRY_CODES.keys()), variable=self._country_var,
            font=self._mono(12), fg_color=THEME["card"],
            button_color=THEME["accent"], button_hover_color=THEME["accent_hover"],
            dropdown_fg_color=THEME["card"], text_color=THEME["text"],
            height=38, corner_radius=9, command=self._on_country_change)
        self._country_menu.pack(fill="x", padx=14, pady=(0, 4))

        self._divider(parent)
        self._section(parent, "Identity & Test")

        self._newid_btn = ctk.CTkButton(
            parent, text="🔄  New Identity  (new circuit / IP)",
            font=self._mono(12, "bold"), fg_color=THEME["card"],
            hover_color=THEME["warning"], text_color=THEME["warning"],
            height=38, corner_radius=9, state="disabled",
            command=self._on_new_identity)
        self._newid_btn.pack(fill="x", padx=14, pady=(0, 4))

        self._test_btn = ctk.CTkButton(
            parent, text="🔍  Test — Fetch Tor Exit IP",
            font=self._mono(12, "bold"), fg_color=THEME["card"],
            hover_color=THEME["success"], text_color=THEME["success"],
            height=38, corner_radius=9, state="disabled",
            command=self._on_test_connection)
        self._test_btn.pack(fill="x", padx=14, pady=(0, 4))

        self._divider(parent)
        self._section(parent, "Public IP via Tor")

        ipf = self._card(parent)
        self._ip_label = ctk.CTkLabel(
            ipf, text="—", font=self._mono(20, "bold"),
            text_color=THEME["success"])
        self._ip_label.pack(padx=12, pady=10)

        self._uptime_label = ctk.CTkLabel(
            parent, text="Uptime: —", font=self._mono(10),
            text_color=THEME["subtext"])
        self._uptime_label.pack(anchor="w", padx=18, pady=(2, 12))

    # ── Right column — circuits + terminal log ───────────────────────────────
    def _build_right(self, parent) -> None:
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=14, pady=(14, 2))
        ctk.CTkLabel(
            hdr, text="ACTIVE TOR CIRCUITS  ·  3-HOP PATH",
            font=self._mono(9, "bold"), text_color=THEME["muted"],
        ).pack(side="left")
        self._circ_ts = ctk.CTkLabel(
            hdr, text="", font=self._mono(9), text_color=THEME["muted"])
        self._circ_ts.pack(side="right")

        self._circuit_box = ctk.CTkTextbox(
            parent, font=self._mono(11), fg_color=THEME["log_bg"],
            text_color=THEME["text"], corner_radius=10, wrap="none",
            height=210, activate_scrollbars=True, state="disabled")
        self._circuit_box.pack(fill="x", padx=14, pady=(0, 4))
        self._config_tags(self._circuit_box)

        ctk.CTkFrame(parent, height=1, fg_color=THEME["border"]).pack(
            fill="x", padx=14, pady=6)

        log_hdr = ctk.CTkFrame(parent, fg_color="transparent")
        log_hdr.pack(fill="x", padx=14, pady=(0, 2))
        ctk.CTkLabel(
            log_hdr, text="ACTIVITY LOG  ·  TERMINAL",
            font=self._mono(9, "bold"), text_color=THEME["muted"],
        ).pack(side="left")
        ctk.CTkButton(
            log_hdr, text="Clear", font=self._mono(9), width=54, height=22,
            fg_color=THEME["card_alt"], hover_color=THEME["card"],
            text_color=THEME["subtext"], corner_radius=5,
            command=self._clear_log).pack(side="right")

        self._log_box = ctk.CTkTextbox(
            parent, font=self._mono(11), fg_color=THEME["log_bg"],
            text_color=THEME["text"], corner_radius=10, wrap="word",
            activate_scrollbars=True, state="disabled")
        self._log_box.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self._config_tags(self._log_box)

    def _config_tags(self, box: ctk.CTkTextbox) -> None:
        """Configure colour tags on the underlying tkinter Text widget."""
        try:
            t = box._textbox  # CTkTextbox wraps a tkinter.Text
            t.tag_config("ok",    foreground=THEME["success"])
            t.tag_config("warn",  foreground=THEME["warning"])
            t.tag_config("error", foreground=THEME["danger"])
            t.tag_config("info",  foreground=THEME["subtext"])
            t.tag_config("accent", foreground=THEME["accent"])
            t.tag_config("dim",   foreground=THEME["muted"])
            t.tag_config("entry", foreground=THEME["entry"])
            t.tag_config("middle", foreground=THEME["middle"])
            t.tag_config("exit",  foreground=THEME["exit"])
        except Exception:
            pass

    # ── Logging ───────────────────────────────────────────────────────────────
    def _log(self, message: str, level: str = "info") -> None:
        symbol = {"info": "•", "ok": "✔", "warn": "⚠", "error": "✖"}.get(level, "•")
        def _append():
            try:
                t = self._log_box._textbox
                self._log_box.configure(state="normal")
                t.insert("end", f"[{ts()}] ", "dim")
                t.insert("end", f"{symbol} ", level if level != "info" else "info")
                t.insert("end", f"{message}\n", level)
                self._log_box.configure(state="disabled")
                self._log_box.see("end")
            except Exception:
                # Fallback if tag access fails
                self._log_box.configure(state="normal")
                self._log_box.insert("end", f"[{ts()}] {symbol} {message}\n")
                self._log_box.configure(state="disabled")
                self._log_box.see("end")
        self.after(0, _append)

    def _clear_log(self) -> None:
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")

    def _print_environment(self) -> None:
        if check_root():
            self._log("Running as root — system-wide routing available.", "ok")
        else:
            self._log("Not root — routing disabled. Launch via the "
                      "'torshield' command for full features.", "warn")
        self._log(f"Tor binary : {TOR_EXE_PATH}", "dim")
        self._log(f"torrc      : {TORRC_PATH}", "dim")
        self._log(f"Snowflake  : {SNOWFLAKE_CLIENT or 'not installed'}",
                  "dim" if SNOWFLAKE_CLIENT else "warn")
        self._log(f"obfs4proxy : {OBFS4PROXY or 'not installed'}",
                  "dim" if OBFS4PROXY else "warn")
        if not os.path.isfile(TOR_EXE_PATH):
            self._log(f"Tor not found at {TOR_EXE_PATH}", "error")
        found = [p for p in _COOKIE_PATHS if os.path.isfile(p)]
        if found:
            self._log(f"Cookie file: {found[0]}", "ok")
        else:
            self._log("Cookie file not present yet — appears after Tor starts.",
                      "warn")

    # ── Progress helpers ─────────────────────────────────────────────────────
    def _set_progress(self, pct: int, label: str) -> None:
        def _u():
            self._progress.set(max(0, min(pct, 100)) / 100)
            self._progress_label.configure(text=label)
        self.after(0, _u)

    # ── Status ────────────────────────────────────────────────────────────────
    def _set_status(self, status: str) -> None:
        self._status = status
        if status == "connected":
            self._status_badge.configure(text="●  CONNECTED",
                                         text_color=THEME["connected"])
            self._connect_btn.configure(state="disabled")
            self._disconnect_btn.configure(state="normal")
            self._newid_btn.configure(state="normal")
            self._test_btn.configure(state="normal")
            self._mode_menu.configure(state="disabled")
            if check_root():
                self._routing_switch.configure(state="normal")
            self._connect_time = time.time()
            self._update_uptime()
            self._set_progress(100, "bootstrapped · 100%")
        elif status == "connecting":
            self._status_badge.configure(text="◌  CONNECTING…",
                                         text_color=THEME["warning"])
            for b in (self._connect_btn, self._disconnect_btn,
                      self._newid_btn, self._test_btn):
                b.configure(state="disabled")
            self._routing_switch.configure(state="disabled")
            self._mode_menu.configure(state="disabled")
        else:
            self._status_badge.configure(text="●  DISCONNECTED",
                                         text_color=THEME["disconnected"])
            self._connect_btn.configure(state="normal")
            self._disconnect_btn.configure(state="disabled")
            self._newid_btn.configure(state="disabled")
            self._test_btn.configure(state="disabled")
            self._routing_switch.configure(state="disabled")
            self._mode_menu.configure(state="normal")
            self._connect_time = None
            if self._after_id:
                self.after_cancel(self._after_id)
            self._uptime_label.configure(text="Uptime: —")
            self._ip_label.configure(text="—")
            self._set_progress(0, "idle")

    def _update_uptime(self) -> None:
        if self._connect_time and self._status == "connected":
            elapsed = int(time.time() - self._connect_time)
            h, rem = divmod(elapsed, 3600)
            m, s = divmod(rem, 60)
            self._uptime_label.configure(text=f"Uptime: {h:02d}:{m:02d}:{s:02d}")
            self._after_id = self.after(1000, self._update_uptime)

    # ── Mode hint ────────────────────────────────────────────────────────────
    def _refresh_mode_hint(self) -> None:
        mode = self._bridge_mode.get()
        if mode == "Snowflake" and not SNOWFLAKE_CLIENT:
            txt, col = "snowflake-client not installed — install it or use Auto.", THEME["warning"]
        elif mode == "obfs4" and not load_obfs4_bridges():
            txt, col = ("No obfs4 bridges saved. Add lines to\n"
                        f"{OBFS4_BRIDGES_FILE}"), THEME["warning"]
        else:
            txt, col = {
                "Auto":      "Direct → Snowflake → obfs4, automatically.",
                "Snowflake": "Disguises Tor as a video call (good for Egypt/Iran).",
                "obfs4":     "Uses your saved obfs4 bridges.",
                "Direct":    "No bridges — only on uncensored networks.",
            }.get(mode, ""), THEME["muted"]
        self._mode_hint.configure(text=txt, text_color=col)

    def _on_mode_change(self, _value=None) -> None:
        self._refresh_mode_hint()
        self._log(f"Connection mode set to: {self._bridge_mode.get()}", "info")

    # ── Circuit display ──────────────────────────────────────────────────────
    def _update_circuit_display(self, circuits: list[dict]) -> None:
        def _render():
            box = self._circuit_box
            t = box._textbox
            box.configure(state="normal")
            box.delete("1.0", "end")
            if not circuits:
                t.insert("end", "  Building circuits…\n", "dim")
            else:
                roles = [("entry", "🟢", "Entry Guard "),
                         ("middle", "🟡", "Middle Relay"),
                         ("exit", "🔴", "Exit Node   ")]
                for circ in circuits:
                    t.insert("end", f"  ╭─ Circuit #{circ['id']}\n", "accent")
                    n = len(circ["path"])
                    for idx, (fp, nick, ip) in enumerate(circ["path"]):
                        connector = "  │  " if idx < n - 1 else "  ╰─ "
                        if idx < 3:
                            tag, icon, label = roles[idx]
                        else:
                            tag, icon, label = "dim", "⚪", f"Hop {idx+1}    "
                        t.insert("end", connector, "dim")
                        t.insert("end", f"{icon} {label} ", tag)
                        t.insert("end", f"{ip:<16} ", "info")
                        t.insert("end", f"({nick})\n", "dim")
                    t.insert("end", "\n")
            box.configure(state="disabled")
            self._circ_ts.configure(text=f"updated {ts()}")
        self.after(0, _render)

    # ── Connection strategy ──────────────────────────────────────────────────
    def _build_mode_sequence(self) -> list[str]:
        """Return the ordered list of concrete modes to attempt."""
        mode = self._bridge_mode.get()
        if mode != "Auto":
            return [mode]
        seq = ["Direct"]
        if SNOWFLAKE_CLIENT:
            seq.append("Snowflake")
        if OBFS4PROXY and load_obfs4_bridges():
            seq.append("obfs4")
        return seq

    def _attempt_mode(self, mode: str, timeout: float) -> bool:
        """Configure torrc for `mode`, (re)start Tor, wait for bootstrap."""
        self._log(f"Trying connection mode: {mode}…", "accent")
        self._set_progress(0, f"{mode}: starting Tor…")

        if check_root():
            try:
                apply_bridge_mode(mode)
            except Exception as exc:
                self._log(f"Could not write torrc for {mode}: {exc}", "error")
                return False

        self._tor.stop_tor()
        try:
            self._tor.start_tor()
        except Exception as exc:
            self._log(f"{mode}: Tor failed to start — {exc}", "error")
            return False

        try:
            self._tor.connect_controller(max_retries=12, delay=1.5)
        except Exception as exc:
            self._log(f"{mode}: control port not ready — {exc}", "warn")
            return False

        def _prog(pct):
            self._set_progress(pct, f"{mode}: bootstrapping… {pct}%")
        ok = self._tor.wait_for_bootstrap(timeout=timeout, on_progress=_prog)
        if ok:
            self._log(f"{mode}: bootstrapped successfully.", "ok")
        else:
            pct = self._tor.bootstrap_progress()
            self._log(f"{mode}: stalled at {max(pct,0)}% after {int(timeout)}s.", "warn")
        return ok

    def _on_connect(self) -> None:
        self._set_status("connecting")
        seq = self._build_mode_sequence()
        self._log(f"Connecting (plan: {' → '.join(seq)})", "info")

        timeouts = {"Direct": 25.0, "Snowflake": 75.0, "obfs4": 60.0}

        def _worker():
            connected_mode = None
            for mode in seq:
                if self._attempt_mode(mode, timeouts.get(mode, 60.0)):
                    connected_mode = mode
                    break
            if not connected_mode:
                self._tor.stop_tor()
                self.after(0, lambda: self._set_status("disconnected"))
                self._log("Could not bootstrap with any mode. "
                          "Check your network or add fresh bridges.", "error")
                self.after(0, lambda: messagebox.showerror(
                    "Connection failed",
                    "Tor could not connect in any mode "
                    f"({', '.join(seq)}).\n\nIf you are on a censored network, "
                    "make sure snowflake-client is installed, or add obfs4 "
                    "bridges from https://bridges.torproject.org"))
                return

            try:
                country_code = COUNTRY_CODES.get(self._country_var.get(), "")
                if country_code:
                    self._tor.set_exit_node(country_code)
                    self._log(f"Exit node set to: {self._country_var.get()}", "ok")
                self._tor.start_circuit_monitoring(
                    callback=self._update_circuit_display, interval=5.0)
                self.after(0, lambda: self._set_status("connected"))
                self._log(f"Connected via {connected_mode}! Enable the routing "
                          "switch to send ALL traffic through Tor.", "ok")
            except Exception as exc:
                self.after(0, lambda: self._set_status("disconnected"))
                self._log(f"Post-connect error: {exc}", "error")

        threading.Thread(target=_worker, daemon=True).start()

    def _on_disconnect(self) -> None:
        if self._system_routing_active:
            self._log("Disabling system-wide routing…")
            ok, msg = disable_system_routing()
            self._system_routing_active = False
            self._log(msg, "ok" if ok else "error")
            self.after(0, self._routing_switch.deselect)
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
        if self._routing_switch.get():
            self._log("Enabling system-wide routing via iptables…")
            def _enable():
                ok, msg = enable_system_routing()
                self._system_routing_active = ok
                self._log(msg, "ok" if ok else "error")
                if ok:
                    self.after(0, lambda: self._routing_badge.configure(
                        text="🌐 ALL TRAFFIC → TOR", text_color=THEME["success"]))
                    self._log("Every app on this machine now uses Tor.", "ok")
                else:
                    self.after(0, self._routing_switch.deselect)
            threading.Thread(target=_enable, daemon=True).start()
        else:
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
                self._log(f"Exit node changed to: {selection}" if country_code
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
                self._log("New identity requested. Circuit rebuilding shortly "
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
                "Tor is running. Stop Tor and restore normal routing?"):
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
    try:
        app = TorShieldApp()
        app.mainloop()
    except Exception as exc:
        _die(f"TorShield failed to start:\n\n{exc}")
