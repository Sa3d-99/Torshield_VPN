"""
torshield_core — framework-agnostic backend for TorShield.

Everything here is pure Python (no GUI toolkit): binary detection, machine
config, automatic bridge fetching from Tor's BridgeDB (moat), the Tor process
manager, system-wide iptables routing, the connection test, and the GitHub
auto-update checker. The PyQt-Fluent GUI in tor_vpn_gui.py imports from here.
"""

import os
import re
import sys
import time
import json
import shutil
import tarfile
import tempfile
import threading
import subprocess
import urllib.request
from datetime import datetime
from typing import Optional, Callable

try:
    import requests
    _REQUESTS = True
except Exception:
    _REQUESTS = False

try:
    from stem import Signal
    from stem.control import Controller
    _STEM = True
except Exception:
    _STEM = False

try:
    from fake_useragent import UserAgent
    _UA_AVAILABLE = True
except Exception:
    _UA_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Version + GitHub auto-update
# ─────────────────────────────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))


def _read_version() -> str:
    for path in (os.path.join(HERE, "VERSION"),
                 os.path.expanduser("~/.local/share/torshield/VERSION")):
        try:
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    v = fh.read().strip()
                    if v:
                        return v
        except Exception:
            pass
    return "0.0.0"


__version__ = _read_version()

GITHUB_OWNER  = "Sa3d-99"
GITHUB_REPO   = "Torshield_VPN"
GITHUB_BRANCH = "main"
REPO_RAW_VERSION_URL = (
    f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/"
    f"{GITHUB_BRANCH}/VERSION")
REPO_TARBALL_URL = (
    f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/archive/refs/heads/"
    f"{GITHUB_BRANCH}.tar.gz")
INSTALL_DIR = os.path.expanduser("~/.local/share/torshield")


def _parse_version(v: str) -> tuple:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums) if nums else (0,)


def fetch_remote_version(timeout: float = 8.0) -> str:
    """Read the VERSION file from the GitHub repo. '' on failure."""
    try:
        req = urllib.request.Request(
            REPO_RAW_VERSION_URL, headers={"User-Agent": "TorShield-Updater"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace").strip()
    except Exception:
        return ""


def check_for_update(timeout: float = 8.0) -> dict:
    """
    Compare the bundled version with the one published on GitHub.
    Returns {'available': bool, 'current': str, 'remote': str}.
    """
    remote = fetch_remote_version(timeout)
    current = __version__
    available = bool(remote) and _parse_version(remote) > _parse_version(current)
    return {"available": available, "current": current, "remote": remote}


def perform_update(log: Optional[Callable[[str, str], None]] = None) -> bool:
    """
    Download the latest source from GitHub and copy the updated app files into
    the install dir. Code-only update — no sudo, no full reinstall. The caller
    should restart the app afterwards (see restart_app).
    """
    def _log(msg, lvl="info"):
        if log:
            log(msg, lvl)

    if not os.path.isdir(INSTALL_DIR):
        _log("Install dir not found — run install.sh first.", "error")
        return False
    try:
        _log("Downloading latest version from GitHub…", "info")
        tmp = tempfile.mkdtemp(prefix="torshield-update-")
        tarball = os.path.join(tmp, "src.tar.gz")
        req = urllib.request.Request(
            REPO_TARBALL_URL, headers={"User-Agent": "TorShield-Updater"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(tarball, "wb") as fh:
            shutil.copyfileobj(resp, fh)

        _log("Extracting update…", "info")
        with tarfile.open(tarball) as tf:
            tf.extractall(tmp)

        roots = [os.path.join(tmp, d) for d in os.listdir(tmp)
                 if os.path.isdir(os.path.join(tmp, d)) and d != "__MACOSX"]
        if not roots:
            _log("Update archive was empty.", "error")
            return False
        src_root = roots[0]

        copied = 0
        for name in ("tor_vpn_gui.py", "torshield_core.py", "VERSION",
                     "torrc.template", "install.sh", "uninstall.sh",
                     "requirements.txt", "Header_Logo.png", "torshield.png"):
            src = os.path.join(src_root, name)
            if os.path.isfile(src):
                try:
                    shutil.copy2(src, os.path.join(INSTALL_DIR, name))
                    copied += 1
                except Exception as exc:
                    _log(f"Could not update {name}: {exc}", "warn")
        shutil.rmtree(tmp, ignore_errors=True)

        if copied:
            _log(f"Updated {copied} files. Restarting…", "ok")
            return True
        _log("Nothing was updated.", "warn")
        return False
    except Exception as exc:
        _log(f"Update failed: {exc}", "error")
        return False


def restart_app() -> None:
    """Re-exec the running app so the freshly downloaded code takes effect."""
    try:
        gui = os.path.join(INSTALL_DIR, "tor_vpn_gui.py")
        if not os.path.isfile(gui):
            gui = os.path.join(HERE, "tor_vpn_gui.py")
        os.execv(sys.executable, [sys.executable, gui] + sys.argv[1:])
    except Exception:
        sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# Machine configuration (written by install.sh) + auto-detection fallback
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
    conf: dict = {}
    for path in (os.path.join(INSTALL_DIR, "torshield.conf"),
                 os.path.join(HERE, "torshield.conf")):
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

CONTROL_PASSWORD = ""
SOCKS_PORT   = 9050
TRANS_PORT   = 9040
DNS_PORT     = 5353
CONTROL_PORT = 9051
CONTROL_HOST = "127.0.0.1"

OBFS4_BRIDGES_FILE     = os.path.join(INSTALL_DIR, "obfs4_bridges.txt")
SNOWFLAKE_BRIDGES_FILE = os.path.join(INSTALL_DIR, "snowflake_bridges.txt")

MOAT_SETTINGS_URL = "https://bridges.torproject.org/moat/circumvention/settings"
MOAT_BUILTIN_URL  = "https://bridges.torproject.org/moat/circumvention/builtin"
BRIDGE_MAX_AGE = 60 * 60 * 24 * 3   # 3 days

SNOWFLAKE_BRIDGE_LINE = (
    "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
    "url=https://snowflake-broker.torproject.net/ front=foursquare.com")

_BRIDGE_HEAD = "# >>> TORSHIELD MANAGED BRIDGES — DO NOT EDIT BY HAND <<<"
_BRIDGE_TAIL = "# <<< TORSHIELD MANAGED BRIDGES END >>>"

_COOKIE_PATHS = [
    "/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
    "/var/run/tor/control.authcookie",
]

COUNTRY_CODES: dict = {
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


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def check_root() -> bool:
    return os.geteuid() == 0


# ─────────────────────────────────────────────────────────────────────────────
# Privilege elevation (pkexec → sudo → unprivileged)
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
        cmd += [sys.executable] + sys.argv
        try:
            subprocess.check_call(cmd)
            sys.exit()
        except FileNotFoundError:
            pass
        except subprocess.CalledProcessError:
            return
    return


# ─────────────────────────────────────────────────────────────────────────────
# Automatic bridge fetching (obfs4 + snowflake) from Tor BridgeDB
# ─────────────────────────────────────────────────────────────────────────────
_BRIDGE_FILES = {"obfs4": OBFS4_BRIDGES_FILE, "snowflake": SNOWFLAKE_BRIDGES_FILE}


def _norm_bridge(line: str) -> str:
    line = line.strip()
    if line and not line.lower().startswith("bridge "):
        line = "Bridge " + line
    return line


def _load_bridges(kind: str) -> list:
    path = _BRIDGE_FILES[kind]
    lines = []
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if raw and not raw.startswith("#"):
                        lines.append(_norm_bridge(raw))
        except Exception:
            pass
    return lines


def load_obfs4_bridges() -> list:
    return _load_bridges("obfs4")


def load_snowflake_bridges() -> list:
    lines = _load_bridges("snowflake")
    return lines if lines else [SNOWFLAKE_BRIDGE_LINE]


def _file_stale(path: str) -> bool:
    if not os.path.isfile(path):
        return True
    try:
        return (time.time() - os.path.getmtime(path)) > BRIDGE_MAX_AGE
    except Exception:
        return True


def bridges_are_stale() -> bool:
    return (_file_stale(OBFS4_BRIDGES_FILE) or not _load_bridges("obfs4")
            or _file_stale(SNOWFLAKE_BRIDGES_FILE))


def fetch_bridges(kind: str, country: str = "", timeout: float = 20.0) -> list:
    if not _REQUESTS:
        return []
    headers = {"Content-Type": "application/vnd.api+json"}
    collected = []
    try:
        payload = {"country": country} if country else {}
        resp = requests.post(MOAT_SETTINGS_URL, json=payload,
                             headers=headers, timeout=timeout)
        if resp.ok:
            for setting in resp.json().get("settings", []):
                br = setting.get("bridges", {})
                if br.get("type") == kind:
                    for s in br.get("bridge_strings", []):
                        collected.append(_norm_bridge(s))
    except Exception:
        pass
    try:
        resp = requests.post(MOAT_BUILTIN_URL, headers=headers, timeout=timeout)
        if resp.ok:
            for s in resp.json().get(kind, []):
                collected.append(_norm_bridge(s))
    except Exception:
        pass
    seen, out = set(), []
    for line in collected:
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def save_bridges(kind: str, lines: list) -> bool:
    if not lines:
        return False
    path = _BRIDGE_FILES[kind]
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        header = (f"# {kind} bridges fetched automatically from Tor BridgeDB (moat)\n"
                  f"# generated {datetime.now().isoformat(timespec='seconds')}\n"
                  "# do not edit — TorShield refreshes this automatically\n")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(header)
            fh.write("\n".join(lines) + "\n")
        return True
    except Exception:
        return False


def refresh_all_bridges(country: str = "", force: bool = False) -> dict:
    result = {}
    for kind in ("obfs4", "snowflake"):
        path = _BRIDGE_FILES[kind]
        if not force and not _file_stale(path) and _load_bridges(kind):
            result[kind] = len(_load_bridges(kind))
            continue
        lines = fetch_bridges(kind, country)
        if lines and save_bridges(kind, lines):
            result[kind] = len(lines)
        else:
            result[kind] = len(_load_bridges(kind))
    return result


def build_bridge_block(mode: str) -> str:
    body = [_BRIDGE_HEAD, f"# mode: {mode}"]
    if mode == "Direct":
        body.append("UseBridges 0")
    elif mode == "Snowflake":
        body.append("UseBridges 1")
        if SNOWFLAKE_CLIENT:
            body.extend(load_snowflake_bridges())
    elif mode == "obfs4":
        body.append("UseBridges 1")
        body.extend(load_obfs4_bridges())
    body.append(_BRIDGE_TAIL)
    return "\n".join(body) + "\n"


def apply_bridge_mode(mode: str) -> None:
    block = build_bridge_block(mode)
    try:
        with open(TORRC_PATH, encoding="utf-8") as fh:
            content = fh.read()
    except Exception as exc:
        raise RuntimeError(f"Cannot read {TORRC_PATH}: {exc}")
    pattern = re.compile(re.escape(_BRIDGE_HEAD) + r".*?" + re.escape(_BRIDGE_TAIL),
                         re.DOTALL)
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
def _run(cmd: list) -> bool:
    try:
        subprocess.run(cmd, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def enable_system_routing() -> tuple:
    try:
        try:
            subprocess.run(["conntrack", "-F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
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
        _run(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53",
              "-j", "REDIRECT", "--to-ports", str(DNS_PORT)])
        _run(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn",
              "-j", "REDIRECT", "--to-ports", str(TRANS_PORT)])
        _run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"])
        _run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "80",  "-j", "REJECT"])
        return True, "System-wide routing enabled — all traffic through Tor"
    except Exception as exc:
        return False, f"iptables error: {exc}"


def disable_system_routing() -> tuple:
    try:
        _run(["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"])
        _run(["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "80",  "-j", "REJECT"])
        _run(["iptables", "-F", "OUTPUT"])
        _run(["iptables", "-t", "nat", "-F", "OUTPUT"])
        return True, "System routing restored — traffic is direct again"
    except Exception as exc:
        return False, f"Failed to restore routing: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Tor Manager
# ─────────────────────────────────────────────────────────────────────────────
class TorManager:
    def __init__(self) -> None:
        self._process: Optional[subprocess.Popen] = None
        self._controller = None
        self._monitoring = False
        self._user_data_dir: Optional[str] = None

    def start_tor(self) -> bool:
        if not os.path.isfile(TOR_EXE_PATH):
            raise FileNotFoundError(
                f"Tor binary not found: {TOR_EXE_PATH}\nRun: sudo apt-get install tor")
        if not os.path.isfile(TORRC_PATH):
            raise FileNotFoundError(
                f"torrc not found: {TORRC_PATH}\nRun install.sh to set it up.")
        extra_args = []
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
                stderr_out = self._process.stderr.read().decode("utf-8", "replace")
            raise RuntimeError(
                "Tor exited immediately after launch.\n\n"
                "Common causes:\n"
                "  • /etc/tor/torrc has a syntax error\n"
                "  • a pluggable-transport binary is missing\n"
                "  • DataDirectory not writable\n"
                "  • Port 9050/9051/9040 already in use\n\n"
                f"Tor output:\n{stderr_out[-800:] if stderr_out else '(none)'}")
        except subprocess.TimeoutExpired:
            pass
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

    def connect_controller(self, max_retries: int = 30, delay: float = 2.0,
                           should_continue=None) -> None:
        cookie_paths = list(_COOKIE_PATHS)
        if self._user_data_dir:
            cookie_paths.insert(
                0, os.path.join(self._user_data_dir, "control_auth_cookie"))
        last_error = ConnectionError("No attempt made yet")
        for attempt in range(max_retries):
            if should_continue is not None and not should_continue():
                raise ConnectionError("cancelled")
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
        raise ConnectionError(
            f"Could not connect to ControlPort {CONTROL_HOST}:{CONTROL_PORT}\n"
            f"Last error: {last_error}\n\n"
            "Fix: sudo usermod -a -G debian-tor $USER && newgrp debian-tor")

    def _disconnect_controller(self) -> None:
        if self._controller:
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None

    @property
    def controller(self):
        return self._controller

    def bootstrap_progress(self) -> int:
        if not self._controller:
            return -1
        try:
            line = self._controller.get_info("status/bootstrap-phase")
            m = re.search(r"PROGRESS=(\d+)", line)
            return int(m.group(1)) if m else 0
        except Exception:
            return -1

    def wait_for_bootstrap(self, timeout: float, on_progress=None,
                           should_continue=None) -> bool:
        """
        Poll bootstrap until 100% or timeout. If `should_continue` is given and
        returns False, abort early (used to cancel a connection in progress).
        """
        deadline = time.time() + timeout
        last = -1
        while time.time() < deadline:
            if should_continue is not None and not should_continue():
                return False
            pct = self.bootstrap_progress()
            if pct != last and on_progress and pct >= 0:
                on_progress(pct)
                last = pct
            if pct >= 100:
                return True
            time.sleep(0.5)
        return self.bootstrap_progress() >= 100

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

    def get_circuits(self) -> list:
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
                    # Look up the relay's country from Tor's GeoIP database.
                    country = "??"
                    try:
                        cc = self._controller.get_info(f"ip-to-country/{ip}")
                        if cc and cc not in ("??", "!!"):
                            country = cc.upper()
                    except Exception:
                        pass
                    path_info.append((fp, nickname or fp[:8], ip, country))
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
