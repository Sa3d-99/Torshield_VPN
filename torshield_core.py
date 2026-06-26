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
# Platform awareness (Linux + Windows)
# ─────────────────────────────────────────────────────────────────────────────
import platform

IS_WINDOWS = os.name == "nt"
IS_LINUX   = (os.name == "posix") and (platform.system() == "Linux")
EXE = ".exe" if IS_WINDOWS else ""


def app_data_dir() -> str:
    """Per-user app directory for config, torrc, data — OS appropriate."""
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "TorShield")
    return os.path.expanduser("~/.local/share/torshield")


# When frozen by PyInstaller, bundled data (logos, VERSION) lives in the temporary
# extraction dir (sys._MEIPASS); from source it's the script's folder.
if getattr(sys, "frozen", False):
    HERE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
else:
    HERE = os.path.dirname(os.path.abspath(__file__))


def _read_version() -> str:
    for path in (os.path.join(HERE, "VERSION"),
                 os.path.join(app_data_dir(), "VERSION")):
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
# On Linux this is exactly the old path (~/.local/share/torshield) — unchanged.
# On Windows it becomes %APPDATA%\TorShield.
INSTALL_DIR = app_data_dir()


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
        for name in ("tor_vpn_gui.py", "torshield_core.py", "win_routing.py",
                     "setup_windows.py", "VERSION", "torrc.template",
                     "install.sh", "uninstall.sh", "requirements.txt",
                     "Header_Logo.png", "torshield.png"):
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

# GeoIP databases — only used on Windows (Linux's tor finds the system geoip on
# its own, so these stay empty there and the Linux torrc/launch are unchanged).
GEOIP_FILE = ""
GEOIP6_FILE = ""

if IS_WINDOWS:
    # Locate Tor at runtime instead of hard-coding a path, so the app works on any
    # machine wherever Tor Browser happens to be installed. We probe a "Tor"
    # directory (…\Browser\TorBrowser\Tor) under common roots — every fixed drive,
    # the user's Desktop/Downloads/home, Program Files and LocalAppData — and
    # accept either the spaced "Tor Browser" or an underscored "Tor_browser" name.
    _pf = os.environ.get("ProgramFiles", r"C:\Program Files")

    def _win_tor_dirs():
        sub = os.path.join("Browser", "TorBrowser", "Tor")
        names = ("Tor Browser", "Tor_browser", "tor-browser", "TorBrowser")
        home = os.path.expanduser("~")
        bases = [home,
                 os.path.join(home, "Desktop"),
                 os.path.join(home, "Downloads"),
                 os.environ.get("LOCALAPPDATA", ""),
                 os.environ.get("ProgramFiles", ""),
                 os.environ.get("ProgramFiles(x86)", "")]
        import string
        for letter in string.ascii_uppercase:
            root = letter + ":\\"
            if os.path.isdir(root):
                bases.append(root)
        seen = set()
        for base in bases:
            if not base:
                continue
            for name in names:
                d = os.path.join(base, name, sub)
                if d not in seen:
                    seen.add(d)
                    yield d

    def _find_in_tor_browser(rel):
        for d in _win_tor_dirs():
            p = os.path.join(d, rel)
            if os.path.isfile(p):
                return p
        return ""

    # Where ensure_tor_installed() drops the downloaded Tor Expert Bundle. The
    # tarball keeps its own  tor/  and  data/  folders, so after extraction we get
    # TEB_DIR/tor/tor.exe, TEB_DIR/tor/pluggable_transports/lyrebird.exe and
    # TEB_DIR/data/geoip.  INSTALL_DIR (%APPDATA%\TorShield) is space-free & writable.
    TEB_DIR = os.path.join(INSTALL_DIR, "tor")
    _eb_tor      = os.path.join(TEB_DIR, "tor", "tor.exe")
    _eb_lyrebird = os.path.join(TEB_DIR, "tor", "pluggable_transports", "lyrebird.exe")

    def _find_geoip_near(tor_exe):
        """Locate the geoip / geoip6 databases that ship with a tor.exe. Expert
        Bundle keeps them in  ../data , Tor Browser in  ../Data/Tor ."""
        if not tor_exe:
            return "", ""
        d = os.path.dirname(tor_exe)
        for g, g6 in (
            (os.path.join(d, "..", "data", "geoip"),
             os.path.join(d, "..", "data", "geoip6")),         # Expert Bundle
            (os.path.join(d, "..", "Data", "Tor", "geoip"),
             os.path.join(d, "..", "Data", "Tor", "geoip6")),  # Tor Browser
            (os.path.join(d, "geoip"), os.path.join(d, "geoip6")),
            (os.path.join(TEB_DIR, "data", "geoip"),
             os.path.join(TEB_DIR, "data", "geoip6")),
        ):
            if os.path.isfile(g):
                return (os.path.normpath(g),
                        os.path.normpath(g6) if os.path.isfile(g6) else "")
        return "", ""

    def _resolve_windows_bins():
        """(Re)detect Tor + transports + geoip and publish them as module globals.
        Called at import and again after ensure_tor_installed() downloads Tor."""
        global TOR_EXE_PATH, TORRC_PATH, SNOWFLAKE_CLIENT, OBFS4PROXY
        global GEOIP_FILE, GEOIP6_FILE
        _tb_tor = _find_in_tor_browser("tor.exe")
        # Tor Browser ships lyrebird, which provides BOTH the obfs4 and snowflake
        # transports (replacing the old separate obfs4proxy / snowflake-client).
        _tb_lyrebird = _find_in_tor_browser(
            os.path.join("PluggableTransports", "lyrebird.exe"))

        # Order: a "tor\" folder bundled next to the app wins (portable installs),
        # then our downloaded Expert Bundle, then a detected Tor Browser, then a
        # Tor Expert Bundle installed in Program Files.
        _win_tor = [os.path.join(HERE, "tor", "tor.exe"), _eb_tor]
        if _tb_tor:
            _win_tor.append(_tb_tor)
        _win_tor.append(os.path.join(_pf, "Tor", "tor.exe"))

        _win_sf = [os.path.join(HERE, "tor", "snowflake-client.exe"), _eb_lyrebird]
        _win_ob = [os.path.join(HERE, "tor", "obfs4proxy.exe"), _eb_lyrebird]
        if _tb_lyrebird:
            _win_sf.append(_tb_lyrebird)
            _win_ob.append(_tb_lyrebird)
        _win_sf.append(os.path.join(_pf, "Tor", "snowflake-client.exe"))
        _win_ob.append(os.path.join(_pf, "Tor", "obfs4proxy.exe"))

        TOR_EXE_PATH     = _CONF.get("TOR_EXE") or _detect_bin("tor", *_win_tor) or "tor.exe"
        TORRC_PATH       = _CONF.get("TORRC_PATH") or os.path.join(INSTALL_DIR, "torrc")
        SNOWFLAKE_CLIENT = _CONF.get("SNOWFLAKE_CLIENT") or _detect_bin("snowflake-client", *_win_sf)
        OBFS4PROXY       = _CONF.get("OBFS4PROXY") or _detect_bin("obfs4proxy", *_win_ob)
        g, g6 = _find_geoip_near(TOR_EXE_PATH)
        GEOIP_FILE  = _CONF.get("GEOIP_FILE")  or g
        GEOIP6_FILE = _CONF.get("GEOIP6_FILE") or g6

    _resolve_windows_bins()
else:
    # ── Linux: unchanged ──
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
# Tor's built-in HTTP CONNECT proxy. Browsers honor an HTTP/HTTPS system proxy far
# more reliably than a SOCKS one, so on Windows we point the system proxy here and
# Tor tunnels it onward. Only used on Windows (see _win_tor_extra_args).
HTTP_TUNNEL_PORT = 9080
# Tor's DNS resolver port (Windows). The TUN VPN forwards DNS here so names resolve
# through Tor with no leak; harmless in proxy mode.
TOR_DNS_PORT = 9053

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
    """Admin/root check — Windows uses IsUserAnAdmin, Linux uses geteuid()."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


# ─────────────────────────────────────────────────────────────────────────────
# Privilege elevation — Windows UAC (runas) / Linux pkexec → sudo → unprivileged
# ─────────────────────────────────────────────────────────────────────────────
def ensure_root() -> None:
    if IS_WINDOWS:
        # The TUN VPN (route every app) needs administrator rights to create the
        # virtual adapter and edit the routing table, so elevate via UAC. If the
        # user declines, the app still runs and falls back to the per-user system
        # proxy (which is SID-aware and works whether elevated or not).
        if check_root():
            return
        try:
            import ctypes
            # Built exe (PyInstaller/Nuitka): sys.executable IS the app, so pass only
            # argv[1:]. From source: sys.executable is python(w), so pass script+args.
            _is_exe = getattr(sys, "frozen", False) or "__compiled__" in globals()
            rest = sys.argv[1:] if _is_exe else sys.argv
            params = " ".join(f'"{a}"' for a in rest)
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1)
            if rc > 32:          # success → the elevated instance takes over
                sys.exit()
        except Exception:
            pass
        return                   # declined → keep running, proxy fallback applies

    if check_root():
        return

    # ── Linux: unchanged (pkexec → sudo handled by the launcher) ──
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


# ─────────────────────────────────────────────────────────────────────────────
# Windows: self-contained Tor install (no Tor Browser required)
# ─────────────────────────────────────────────────────────────────────────────
# A baked-in fallback used only if the live version lookup fails. Kept current-ish.
TEB_FALLBACK_VERSION = "15.0.16"


def _teb_latest_version() -> str:
    """Latest Tor Browser / Expert-Bundle version, or the baked-in fallback."""
    if _REQUESTS:
        try:
            r = requests.get(
                "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json",
                timeout=20)
            v = (r.json() or {}).get("version")
            if v:
                return str(v)
        except Exception:
            pass
    return TEB_FALLBACK_VERSION


def _teb_url(version: str) -> str:
    return ("https://archive.torproject.org/tor-package-archive/torbrowser/"
            f"{version}/tor-expert-bundle-windows-x86_64-{version}.tar.gz")


def ensure_tor_installed(log: Optional[Callable] = None, force: bool = False) -> str:
    """
    Windows only: guarantee a usable tor.exe (plus lyrebird transports and the
    geoip databases) without requiring Tor Browser, by downloading the official
    Tor Expert Bundle into %APPDATA%\\TorShield\\tor on first run.

    No-op on Linux, and a no-op on Windows when Tor is already present (bundled
    next to the app, a previous download, Tor Browser, or a Program Files Expert
    Bundle). Returns the resolved tor.exe path. `log(msg)` receives progress.
    """
    def _say(msg):
        if log:
            try:
                log(msg)
            except Exception:
                pass

    if not IS_WINDOWS:
        return TOR_EXE_PATH
    if not force and (os.path.isfile(TOR_EXE_PATH) or shutil.which(TOR_EXE_PATH)):
        return TOR_EXE_PATH
    if not _REQUESTS:
        _say("Cannot download Tor: the 'requests' package is missing.")
        return TOR_EXE_PATH

    version = _teb_latest_version()
    url = _teb_url(version)
    os.makedirs(TEB_DIR, exist_ok=True)
    tmp = os.path.join(tempfile.gettempdir(), f"tor-expert-bundle-{version}.tar.gz")
    _say(f"Downloading Tor {version} (~22 MB)… one-time setup.")
    try:
        with requests.get(url, stream=True, timeout=300) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", 0) or 0)
            done = next_mark = 0
            with open(tmp, "wb") as fh:
                for chunk in r.iter_content(chunk_size=262144):
                    if not chunk:
                        continue
                    fh.write(chunk)
                    done += len(chunk)
                    if total and done >= next_mark:
                        _say(f"  …{done * 100 // total}%")
                        next_mark += total // 10
        _say("Extracting Tor…")
        with tarfile.open(tmp) as tf:
            members = [m for m in tf.getmembers()
                       if m.name.startswith(("tor/", "data/"))]
            try:
                tf.extractall(TEB_DIR, members=members, filter="data")
            except TypeError:        # Python < 3.12 has no 'filter' kwarg
                tf.extractall(TEB_DIR, members=members)
    except Exception as exc:
        _say(f"Tor download failed: {exc}")
        return TOR_EXE_PATH
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

    _resolve_windows_bins()          # re-detect now that the files exist
    _say(f"Tor ready: {TOR_EXE_PATH}")
    return TOR_EXE_PATH


def _pt_exec_path(path: str) -> str:
    """
    Windows-only: make a pluggable-transport binary usable from a torrc
    ClientTransportPlugin 'exec' line. Tor splits that line on whitespace and
    keeps quotes literally, so a binary whose path contains a space (e.g. Tor
    Browser under 'F:\\Tor browser\\...') can never launch — tor only sees
    '"F:\\Tor'. When the path has a space we copy the (standalone) PT binary into
    the space-free INSTALL_DIR and return that copy. No-op on Linux and for
    already space-free paths.
    """
    if not IS_WINDOWS or not path or " " not in path:
        return path
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        dst = os.path.join(INSTALL_DIR, os.path.basename(path))
        if (not os.path.isfile(dst)
                or os.path.getsize(dst) != os.path.getsize(path)):
            shutil.copy2(path, dst)
        if " " not in dst:
            return dst
    except Exception:
        pass
    return path


def _win_tor_extra_args() -> list:
    """
    Windows-only extra tor command-line args: the pluggable-transport plugins and
    the geoip databases. Passing them here (instead of in the torrc) keeps the
    paths current and lets tor's argv parser receive each value as one token, so
    geoip paths with spaces are fine. Transport exec paths still go through
    _pt_exec_path so they are space-free (tor's PT sub-parser splits on spaces).
    Returns [] on Linux.
    """
    if not IS_WINDOWS:
        return []
    # An HTTP CONNECT proxy that tunnels through Tor — the Windows system proxy
    # points browsers at this (HTTP proxies are honored far more reliably than
    # SOCKS), so traffic actually exits via Tor and the IP changes.
    args = ["--HTTPTunnelPort", str(HTTP_TUNNEL_PORT),
            "--DNSPort", f"127.0.0.1:{TOR_DNS_PORT}"]
    if SNOWFLAKE_CLIENT:
        # lyrebird provides snowflake and reads url/front/ice from the bridge line.
        args += ["--ClientTransportPlugin",
                 f"snowflake exec {_pt_exec_path(SNOWFLAKE_CLIENT)}"]
    if OBFS4PROXY:
        args += ["--ClientTransportPlugin",
                 f"obfs4 exec {_pt_exec_path(OBFS4PROXY)}"]
    if GEOIP_FILE:
        args += ["--GeoIPFile", GEOIP_FILE]
        if GEOIP6_FILE:
            args += ["--GeoIPv6File", GEOIP6_FILE]
    return args


def ensure_torrc() -> None:
    """
    Generate a default torrc at TORRC_PATH if it doesn't exist. Used on Windows
    (no install.sh). On Linux the installer writes /etc/tor/torrc, so this is a
    no-op there unless the file is somehow missing.
    """
    if os.path.isfile(TORRC_PATH):
        return
    try:
        os.makedirs(os.path.dirname(TORRC_PATH) or ".", exist_ok=True)
    except Exception:
        pass
    lines = [
        "# TorShield torrc — auto-generated",
        f"SocksPort {SOCKS_PORT}",
        f"ControlPort {CONTROL_PORT}",
        "CookieAuthentication 1",
    ]
    if not IS_WINDOWS:
        # TransPort/DNSPort transparent proxying is Linux-only.
        lines += [f"TransPort {TRANS_PORT}", f"DNSPort {DNS_PORT}",
                  "AutomapHostsOnResolve 1", "CookieAuthFileGroupReadable 1"]
    # On Windows the ClientTransportPlugin lines (and GeoIPFile) are passed on the
    # tor command line instead — see TorManager.start_tor / _win_tor_extra_args —
    # so the exec paths stay current even if Tor is re-detected or re-downloaded.
    # Linux keeps writing them into the torrc exactly as before.
    if not IS_WINDOWS:
        if SNOWFLAKE_CLIENT:
            lines.append(
                f'ClientTransportPlugin snowflake exec "{SNOWFLAKE_CLIENT}" '
                "-url https://snowflake-broker.torproject.net/ -front foursquare.com "
                "-ice stun:stun.l.google.com:19302,stun:stun.antisip.com:3478")
        if OBFS4PROXY:
            lines.append(f'ClientTransportPlugin obfs4 exec "{OBFS4PROXY}"')
    lines.append(build_bridge_block("Direct").rstrip("\n"))
    try:
        with open(TORRC_PATH, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception:
        pass


def apply_bridge_mode(mode: str) -> None:
    block = build_bridge_block(mode)
    # On Windows the torrc is app-generated (no install.sh) — create it first.
    if IS_WINDOWS and not os.path.isfile(TORRC_PATH):
        ensure_torrc()
    try:
        with open(TORRC_PATH, encoding="utf-8") as fh:
            content = fh.read()
    except Exception as exc:
        raise RuntimeError(f"Cannot read {TORRC_PATH}: {exc}")
    if IS_WINDOWS:
        # Transports + geoip now go on tor's command line (see _win_tor_extra_args),
        # so strip any ClientTransportPlugin/GeoIP* lines an older torrc may still
        # carry — otherwise tor errors with "transport already registered".
        content = "\n".join(
            ln for ln in content.splitlines()
            if not ln.lstrip().startswith(
                ("ClientTransportPlugin", "GeoIPFile", "GeoIPv6File")))
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


def enable_system_routing(tor_pid=None, log=None) -> tuple:
    # Windows: full TUN VPN (all apps) with a system-proxy fallback (win_routing).
    # tor_pid lets it route Tor's own traffic around the tunnel. Linux ignores the
    # extra arguments and behaves exactly as before.
    if IS_WINDOWS:
        try:
            import win_routing
            return win_routing.enable(SOCKS_PORT, tor_pid=tor_pid,
                                      http_port=HTTP_TUNNEL_PORT,
                                      tor_dns_port=TOR_DNS_PORT, log=log)
        except Exception as exc:
            return False, f"Windows routing error: {exc}"

    # ── Linux: unchanged (iptables transparent proxy) ──
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


def cleanup_stale_routing(kill_tor: bool = False) -> None:
    """Windows: quietly repair leftover TUN/DNS state from a previous crash (same as
    reset_internet.bat, automatic) — at startup (self-heal) and before each connect
    (clean slate). `kill_tor` also frees a stray tor.exe holding the ports. No-op on
    Linux."""
    if IS_WINDOWS:
        try:
            import win_routing
            win_routing.cleanup_stale(kill_tor=kill_tor)
        except Exception:
            pass


def flush_dns() -> None:
    """Windows: flush the OS DNS cache so a just-changed exit country takes effect
    immediately (old lookups were resolved through the previous exit). No-op on Linux."""
    if IS_WINDOWS:
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception:
            pass


def routing_mode():
    """Active Windows routing mode: 'tun', 'proxy', or None. Always None on Linux."""
    if IS_WINDOWS:
        try:
            import win_routing
            return win_routing._state.get("mode")
        except Exception:
            return None
    return None


def open_secure_browser() -> tuple:
    """Windows: open a browser window hard-wired to Tor (proxy + no-QUIC, isolated
    profile) — the most reliable way to actually browse through Tor. No-op elsewhere."""
    if IS_WINDOWS:
        try:
            import win_routing
            return win_routing.open_secure_browser(HTTP_TUNNEL_PORT)
        except Exception as exc:
            return False, f"Could not open secure browser: {exc}"
    return False, "Secure-browser launch is Windows-only."


def disable_system_routing() -> tuple:
    if IS_WINDOWS:
        try:
            import win_routing
            return win_routing.disable()
        except Exception as exc:
            return False, f"Windows routing restore error: {exc}"

    # ── Linux: unchanged ──
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

    def tor_pid(self):
        """PID of the running tor.exe (or None) — used to exclude Tor's own
        traffic from Windows system-wide routing."""
        p = self._process
        return p.pid if (p and p.poll() is None) else None

    def start_tor(self) -> bool:
        if not os.path.isfile(TOR_EXE_PATH) and not shutil.which(TOR_EXE_PATH):
            hint = ("Install the Tor Expert Bundle and put tor.exe in a 'tor' folder "
                    "next to the app." if IS_WINDOWS else "Run: sudo apt-get install tor")
            raise FileNotFoundError(f"Tor binary not found: {TOR_EXE_PATH}\n{hint}")
        # Windows has no install.sh, so generate a torrc on first run if missing.
        if not os.path.isfile(TORRC_PATH):
            if IS_WINDOWS:
                ensure_torrc()
            if not os.path.isfile(TORRC_PATH):
                raise FileNotFoundError(
                    f"torrc not found: {TORRC_PATH}\n"
                    + ("(could not auto-generate it)" if IS_WINDOWS
                       else "Run install.sh to set it up."))

        # Always run Tor with its own writable DataDirectory + a real log file.
        self._user_data_dir = os.path.join(INSTALL_DIR, "tor-data")
        try:
            os.makedirs(self._user_data_dir, exist_ok=True)
            if not IS_WINDOWS:
                os.chmod(self._user_data_dir, 0o700)
        except Exception:
            self._user_data_dir = tempfile.mkdtemp(prefix="torshield-tor-")
        self._log_path = os.path.join(self._user_data_dir, "tor.log")
        cmd = [TOR_EXE_PATH, "-f", TORRC_PATH,
               "--DataDirectory", self._user_data_dir,
               "--Log", "notice stdout"]
        # Windows: pluggable transports + geoip databases via argv (Linux returns []).
        cmd += _win_tor_extra_args()

        # Send Tor's combined output to a file (so a full pipe can never block
        # Tor, and we can read the real error on immediate exit).
        self._log_fh = open(self._log_path, "w+b")
        # On Windows, don't pop up a console window for tor.exe.
        _popen_kw = {}
        if IS_WINDOWS:
            _popen_kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._process = subprocess.Popen(
            cmd, stdout=self._log_fh, stderr=subprocess.STDOUT, **_popen_kw)
        try:
            self._process.wait(timeout=3)
            out = ""
            try:
                self._log_fh.flush()
                with open(self._log_path, "r", encoding="utf-8", errors="replace") as f:
                    out = f.read().strip()
            except Exception:
                pass
            raise RuntimeError(
                "Tor exited immediately after launch.\n\n"
                "Common causes:\n"
                "  • another Tor is already running (sudo systemctl stop tor)\n"
                "  • port 9050/9051/9040 already in use\n"
                "  • a pluggable-transport binary is missing\n"
                "  • /etc/tor/torrc has a syntax error\n\n"
                f"Tor said:\n{out[-1000:] if out else '(no output captured)'}")
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
        fh = getattr(self, "_log_fh", None)
        if fh:
            try:
                fh.close()
            except Exception:
                pass
            self._log_fh = None

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
                           should_continue=None, stall_after=None) -> bool:
        """
        Poll bootstrap until 100% or timeout. If `should_continue` is given and
        returns False, abort early (used to cancel a connection in progress).

        `stall_after` (seconds) is an optional early-out: if the bootstrap makes
        no forward progress for that long, give up so the caller can try the next
        connection mode instead of burning the whole timeout. Left as None (the
        default) the behaviour is exactly as before — Linux passes nothing.
        """
        deadline = time.time() + timeout
        last = -1
        last_change = time.time()
        while time.time() < deadline:
            if should_continue is not None and not should_continue():
                return False
            pct = self.bootstrap_progress()
            if pct != last and pct >= 0:
                if on_progress:
                    on_progress(pct)
                last = pct
                last_change = time.time()
            if pct >= 100:
                return True
            if stall_after is not None and time.time() - last_change > stall_after:
                return False
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
        # Circuits built before this point keep their OLD (random) exit, so traffic
        # would still leave via the wrong country (e.g. show Netherlands when France
        # was picked). Close them so Tor rebuilds every circuit through the new exit.
        try:
            for circ in self._controller.get_circuits():
                try:
                    self._controller.close_circuit(circ.id)
                except Exception:
                    pass
        except Exception:
            pass

    def exit_country_ok(self, country_code: str, timeout: float = 20.0) -> bool:
        """Wait until at least one BUILT circuit actually exits in `country_code`
        (e.g. '{fr}' → 'fr'). Lets the caller know the chosen country is usable."""
        if not self._controller or not country_code:
            return True
        want = country_code.strip("{}").lower()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                for circ in self._controller.get_circuits():
                    if circ.status.casefold() != "built" or not circ.path:
                        continue
                    fp = circ.path[-1][0]
                    try:
                        cc = self._controller.get_info(f"ip-to-country/"
                                + self._controller.get_network_status(fp).address)
                        if cc and cc.lower() == want:
                            return True
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(1.0)
        return False

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
