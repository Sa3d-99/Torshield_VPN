"""
win_routing — Windows "route every app through Tor" (TUN VPN) with a proxy fallback.

⚠️  WINDOWS-ONLY · never imported on Linux (torshield_core guards the import with
`if IS_WINDOWS:`), so the Linux iptables routing is untouched.

Primary mode — TUN VPN (all apps, like Linux):
  A virtual network adapter (Wintun) is created and tun2socks forwards every IP
  packet into Tor's SOCKS5 listener (127.0.0.1:<socks_port>). The default route is
  pointed at the TUN, so ALL programs go through Tor — not just proxy-aware ones.
    • Tor's own traffic to its relays must NOT go back into the TUN (that would
      loop), so we add /32 host routes for the IPs tor.exe is connected to, via the
      real gateway, refreshed continuously as circuits change.
    • DNS is resolved through Tor: a tiny local forwarder on 127.0.0.1:53 hands
      queries to Tor's DNSPort, and the TUN adapter's DNS is set to 127.0.0.1.
  Needs administrator rights (adapter + routing table). Helper binaries (wintun.dll
  and tun2socks.exe) are downloaded once into %LOCALAPPDATA%\\TorShield\\tun2socks.

Fallback mode — system proxy:
  If the TUN can't start (no admin, download failed, driver issue) we fall back to
  the per-user system proxy pointed at Tor's HTTP tunnel. Covers browsers and
  proxy-aware apps and can never disconnect the machine.

disable() always fully restores connectivity (removes our routes / proxy).
"""

import os
import time
import socket
import struct
import threading
import subprocess

try:
    import winreg
except Exception:          # pragma: no cover
    winreg = None

try:
    import requests
except Exception:
    requests = None

# ── TUN parameters ───────────────────────────────────────────────────────────
TUN_DEVICE = "torshield"
TUN_ADDR   = "10.7.0.2"
TUN_MASK   = "255.255.255.0"
TUN_GW     = "10.7.0.1"
WINTUN_URL   = "https://www.wintun.net/builds/wintun-0.14.1.zip"
TUN2SOCKS_URL = ("https://github.com/xjasonlyu/tun2socks/releases/download/"
                 "v2.6.0/tun2socks-windows-amd64.zip")

_CREATE_NO_WINDOW = 0x08000000

_state = {
    "mode": None,           # "tun" | "proxy" | None
    "running": False,
    # tun
    "proc": None,           # tun2socks process
    "adapter": None,        # actual Wintun adapter name
    "phys_gw": None,
    "host_routes": set(),   # guard IPs we routed via the physical gateway
    "dns_adapters": [],     # adapters whose DNS/IPv6 we changed (to restore)
    "dns_sock": None,
    "threads_run": False,
    "socks_port": 9050,
    "tor_pid": None,
    "tor_dns_port": 9053,
    # proxy fallback
    "prev_enable": None,
    "prev_server": None,
    "proxy_root": None,
    "proxy_subkey": None,
}


def _appdir():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "TorShield", "tun2socks")


def _run(cmd):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           creationflags=_CREATE_NO_WINDOW)
        return r.returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Helper-binary download (wintun.dll + tun2socks.exe)
# ─────────────────────────────────────────────────────────────────────────────
def _ensure_tun_binaries(log=None):
    def say(m):
        if log:
            try: log(m)
            except Exception: pass
    d = _appdir()
    exe = os.path.join(d, "tun2socks.exe")
    dll = os.path.join(d, "wintun.dll")
    if os.path.isfile(exe) and os.path.isfile(dll):
        return exe
    if requests is None:
        return None
    import zipfile, io
    try:
        os.makedirs(d, exist_ok=True)
        if not os.path.isfile(dll):
            say("Downloading Wintun driver…")
            z = zipfile.ZipFile(io.BytesIO(requests.get(WINTUN_URL, timeout=120).content))
            for n in z.namelist():
                if n.lower().endswith("amd64/wintun.dll"):
                    with z.open(n) as src, open(dll, "wb") as dst:
                        dst.write(src.read())
                    break
        if not os.path.isfile(exe):
            say("Downloading tun2socks…")
            z = zipfile.ZipFile(io.BytesIO(requests.get(TUN2SOCKS_URL, timeout=180).content))
            for n in z.namelist():
                if n.lower().endswith(".exe"):
                    with z.open(n) as src, open(exe, "wb") as dst:
                        dst.write(src.read())
                    break
    except Exception as exc:
        say(f"TUN binary download failed: {exc}")
        return None
    return exe if (os.path.isfile(exe) and os.path.isfile(dll)) else None


# ─────────────────────────────────────────────────────────────────────────────
# Routing-table helpers
# ─────────────────────────────────────────────────────────────────────────────
def _default_route():
    """(gateway_ip, interface_ip) of the active IPv4 default route, or (None,None)."""
    try:
        out = subprocess.run(["route", "print", "-4"], capture_output=True,
                             text=True, creationflags=_CREATE_NO_WINDOW).stdout
    except Exception:
        return None, None
    best = None
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
            gw, iface = p[2], p[3]
            try:
                metric = int(p[4])
            except ValueError:
                continue
            if gw.lower() == "on-link":
                continue
            if best is None or metric < best[0]:
                best = (metric, gw, iface)
    if best:
        return best[1], best[2]
    return None, None


def _tcp_table():
    """All IPv4 TCP rows as (state, local_port, remote_ip, remote_port, pid)."""
    rows = []
    try:
        import ctypes
        from ctypes import wintypes
        iphlpapi = ctypes.windll.iphlpapi
        fn = iphlpapi.GetExtendedTcpTable
        fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                       wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
        fn.restype = wintypes.DWORD
        size = wintypes.DWORD(0)
        fn(None, ctypes.byref(size), False, 2, 5, 0)   # AF_INET, OWNER_PID_ALL
        buf = ctypes.create_string_buffer(size.value)
        if fn(buf, ctypes.byref(size), False, 2, 5, 0) != 0:
            return rows
        raw = buf.raw
        n = struct.unpack("<I", raw[:4])[0]
        off = 4
        for _ in range(n):
            row = raw[off:off + 24]; off += 24
            if len(row) < 24:
                break
            state = struct.unpack("<I", row[0:4])[0]
            lport = struct.unpack(">H", row[8:10])[0]
            raddr = socket.inet_ntoa(row[12:16])
            rport = struct.unpack(">H", row[16:18])[0]
            pid = struct.unpack("<I", row[20:24])[0]
            rows.append((state, lport, raddr, rport, pid))
    except Exception:
        pass
    return rows


def _pid_remote_ips(pid):
    """Remote IPv4 addresses tor.exe is connected to (the relays to exclude)."""
    ips = set()
    if not pid:
        return ips
    for state, lport, raddr, rport, owner in _tcp_table():
        if owner == pid and raddr not in ("0.0.0.0", "127.0.0.1"):
            ips.add(raddr)
    return ips


def _wintun_adapter_name():
    """Wait (inside ONE PowerShell call, so it's fast) for the Wintun adapter
    tun2socks created and return its Windows name, or None."""
    try:
        # tun2socks names the Wintun adapter "tun2socks Tunnel" (description) with
        # the alias = our device name. Match the description and take the Up one.
        ps = ("for($i=0;$i -lt 30;$i++){"
              "$a=Get-NetAdapter|?{$_.InterfaceDescription -like '*tun2socks*' "
              "-and $_.Status -eq 'Up'}|select -First 1 -Exp Name; "
              "if($a){$a; break}; Start-Sleep -m 300}")
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True,
                             creationflags=_CREATE_NO_WINDOW).stdout.strip()
        # If multiple names came back, take the last line.
        out = out.splitlines()[-1].strip() if out else ""
        return out or None
    except Exception:
        return None


def _active_adapters():
    """Names of connected adapters (so we can force their DNS / disable IPv6)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}"
             " | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, creationflags=_CREATE_NO_WINDOW).stdout
        return [l.strip() for l in out.splitlines() if l.strip()]
    except Exception:
        return []


def _force_ipv4_dns(enable):
    """Fast: point every connected adapter's IPv4 DNS at our local Tor-DNS
    forwarder (127.0.0.1), or hand it back to DHCP. Also overrides IPv6 DNS to ::1
    so the router's fe80::1 resolver (which Tor can't reach over UDP) isn't used."""
    if enable:
        _state["dns_adapters"] = _active_adapters()
    for name in _state.get("dns_adapters", []):
        if enable:
            _run(["netsh", "interface", "ipv4", "set", "dnsservers",
                  f"name={name}", "static", "127.0.0.1", "primary"])
            _run(["netsh", "interface", "ipv6", "set", "dnsservers",
                  f"name={name}", "static", "::1", "primary"])
        else:
            _run(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "dhcp"])
            _run(["netsh", "interface", "ipv6", "set", "dnsservers", f"name={name}", "dhcp"])
    _run(["ipconfig", "/flushdns"])


def _remove_tun_adapters():
    """Remove orphaned Wintun adapters tun2socks left behind. A forceful kill does
    NOT clean them up, so without this they pile up as 'torshield 1', 'torshield 2',
    … and a stale one can grab the default route and break the internet."""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | "
             "Where-Object {$_.FriendlyName -like '*tun2socks*'} | "
             "ForEach-Object { pnputil /remove-device $_.InstanceId 2>$null }"],
            capture_output=True, text=True,
            creationflags=_CREATE_NO_WINDOW, timeout=60)
    except Exception:
        pass


def _add_host_route(ip, gw):
    return _run(["route", "add", ip, "mask", "255.255.255.255", gw, "metric", "1"])


def _del_host_route(ip):
    _run(["route", "delete", ip])


# ─────────────────────────────────────────────────────────────────────────────
# Background threads: keep Tor's relays routed around the TUN; DNS through Tor
# ─────────────────────────────────────────────────────────────────────────────
def _route_refresh_loop():
    while _state["threads_run"]:
        gw = _state["phys_gw"]
        if gw:
            for ip in _pid_remote_ips(_state["tor_pid"]):
                if ip not in _state["host_routes"]:
                    if _add_host_route(ip, gw):
                        _state["host_routes"].add(ip)
        time.sleep(2.0)


def _dns_forwarder_loop(family=socket.AF_INET, bind_addr=("127.0.0.1", 53)):
    try:
        srv = socket.socket(family, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Windows: stop recvfrom() from raising WSAECONNRESET (10054) after a reply
        # provokes an ICMP "port unreachable". Without this the loop dies on the
        # first already-closed client and every later DNS query times out.
        try:
            srv.ioctl(getattr(socket, "SIO_UDP_CONNRESET", 0x9800000C), False)
        except Exception:
            pass
        srv.bind(bind_addr)
        srv.settimeout(1.0)
    except Exception:
        return            # something already owns :53 — DNS-through-Tor unavailable
    _state.setdefault("dns_socks", []).append(srv)
    _state["dns_sock"] = srv
    tor_dns = ("127.0.0.1", _state["tor_dns_port"])
    while _state["threads_run"]:
        try:
            data, addr = srv.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            continue          # spurious 10054 etc. — keep serving, don't die
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(5.0)
            up.sendto(data, tor_dns)
            resp, _ = up.recvfrom(4096)
            srv.sendto(resp, addr)
            up.close()
        except Exception:
            pass
    try:
        srv.close()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# TUN VPN enable / disable
# ─────────────────────────────────────────────────────────────────────────────
def _tun_enable(socks_port, tor_pid, tor_dns_port, log=None):
    def say(m):
        if log:
            try: log(m)
            except Exception: pass

    exe = _ensure_tun_binaries(log)
    if not exe:
        return False, "TUN helper binaries unavailable."
    gw, _iface = _default_route()
    if not gw:
        return False, "Could not find the default gateway."
    _state["phys_gw"] = gw
    _state["socks_port"] = socks_port
    _state["tor_pid"] = tor_pid
    _state["tor_dns_port"] = tor_dns_port

    # Pre-route Tor's existing relay connections around the TUN (avoid the loop).
    _state["host_routes"] = set()
    for ip in _pid_remote_ips(tor_pid):
        if _add_host_route(ip, gw):
            _state["host_routes"].add(ip)

    # Kill any leftover tun2socks from a previous crashed run and REMOVE its
    # orphaned adapter, so we don't accumulate torshield/torshield 1/… clones (a
    # stale one can grab the route and break the internet).
    _run(["taskkill", "/F", "/IM", "tun2socks.exe"])
    time.sleep(0.6)
    _remove_tun_adapters()

    # Start tun2socks (cwd = its dir so it finds wintun.dll). Log its output so
    # failures are visible instead of silent.
    say("Starting TUN adapter (tun2socks)…")
    logpath = os.path.join(os.path.dirname(exe), "tun2socks.log")
    try:
        logfh = open(logpath, "w", encoding="utf-8", errors="replace")
    except Exception:
        logfh = subprocess.DEVNULL
    try:
        proc = subprocess.Popen(
            [exe, "-device", f"tun://{TUN_DEVICE}",
             "-proxy", f"socks5://127.0.0.1:{socks_port}", "-loglevel", "info"],
            cwd=os.path.dirname(exe),
            stdout=logfh, stderr=subprocess.STDOUT,
            creationflags=_CREATE_NO_WINDOW)
    except Exception as exc:
        return False, f"tun2socks failed to start: {exc}"
    _state["proc"] = proc

    # Wait (inside one PowerShell poll) for the "tun2socks Tunnel" adapter.
    time.sleep(1.0)
    if proc.poll() is not None:
        tail = ""
        try:
            with open(logpath, encoding="utf-8", errors="replace") as f:
                tail = f.read().strip()[-300:]
        except Exception:
            pass
        return False, "tun2socks exited (driver/permissions). " + (tail or "")
    adapter = _wintun_adapter_name()
    if not adapter:
        return False, "TUN adapter did not come up (see tun2socks.log)."
    say(f"TUN adapter: {adapter}")
    _state["adapter"] = adapter

    if not _run(["netsh", "interface", "ip", "set", "address",
                 f"name={adapter}", "static", TUN_ADDR, TUN_MASK]):
        return False, f"Could not assign IP to TUN adapter '{adapter}'."
    # Make the TUN the lowest-metric interface so its default route wins.
    _run(["netsh", "interface", "ip", "set", "interface", f"{adapter}", "metric=1"])

    # Start the DNS-through-Tor forwarders (IPv4 + IPv6 loopback) BEFORE redirecting
    # traffic, so name resolution works the instant the default route flips. The
    # IPv6 one answers ::1 queries Windows makes for AAAA records.
    _state["threads_run"] = True
    _state["dns_socks"] = []
    threading.Thread(target=lambda: _dns_forwarder_loop(
        socket.AF_INET, ("127.0.0.1", 53)), daemon=True).start()
    threading.Thread(target=lambda: _dns_forwarder_loop(
        socket.AF_INET6, ("::1", 53)), daemon=True).start()
    time.sleep(0.5)
    # Force all DNS to 127.0.0.1 (our forwarder → Tor's DNS). Fast.
    say("Forcing DNS through Tor…")
    _force_ipv4_dns(True)

    # Send everything through the TUN (lower metric than the physical default).
    _run(["route", "add", "0.0.0.0", "mask", "0.0.0.0", TUN_GW, "metric", "1"])
    say("Default route now points at the Tor TUN — all apps go through Tor.")

    threading.Thread(target=_route_refresh_loop, daemon=True).start()
    # NOTE: we no longer reset the IPv6 binding (that briefly disrupted the adapter
    # and broke DNS during the race). Both IPv4 and IPv6 DNS are redirected to the
    # local Tor forwarder above, so there is no DNS leak; IPv6 *traffic* has no TUN
    # route and simply fails over to IPv4 (Tor).
    _state["mode"] = "tun"
    _state["running"] = True
    return True, "All apps now route through Tor (TUN VPN, DNS via Tor)."


def _tun_disable():
    _state["threads_run"] = False
    # Restore DNS FIRST so connectivity returns even if later steps fail.
    try:
        _force_ipv4_dns(False)
    except Exception:
        pass
    _state["dns_adapters"] = []
    for s in _state.get("dns_socks", []):
        try:
            s.close()
        except Exception:
            pass
    _state["dns_socks"] = []
    _run(["route", "delete", "0.0.0.0", "mask", "0.0.0.0", TUN_GW])
    for ip in list(_state["host_routes"]):
        _del_host_route(ip)
    _state["host_routes"] = set()
    s = _state.get("dns_sock")
    if s:
        try: s.close()
        except Exception: pass
        _state["dns_sock"] = None
    p = _state.get("proc")
    if p and p.poll() is None:
        try:
            p.terminate(); p.wait(timeout=5)
        except Exception:
            try: p.kill()
            except Exception: pass
    _state["proc"] = None
    _remove_tun_adapters()        # delete the Wintun adapter so it can't linger


# ─────────────────────────────────────────────────────────────────────────────
# System-proxy fallback (per-user, SID-aware so it works elevated too)
# ─────────────────────────────────────────────────────────────────────────────
_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _interactive_user_sid():
    try:
        import win32api, win32con, win32process, win32security
    except Exception:
        return None
    try:
        for pid in win32process.EnumProcesses():
            try:
                h = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                    False, pid)
                if win32process.GetModuleFileNameEx(h, 0).lower().endswith("explorer.exe"):
                    tok = win32security.OpenProcessToken(h, win32con.TOKEN_QUERY)
                    sid, _ = win32security.GetTokenInformation(tok, win32security.TokenUser)
                    return win32security.ConvertSidToStringSid(sid)
            except Exception:
                continue
    except Exception:
        pass
    return None


def _open_settings_key():
    sid = _interactive_user_sid()
    if sid:
        sub = sid + "\\" + _INTERNET_SETTINGS
        try:
            return (winreg.OpenKey(winreg.HKEY_USERS, sub, 0,
                                   winreg.KEY_READ | winreg.KEY_WRITE),
                    winreg.HKEY_USERS, sub)
        except OSError:
            pass
    return (winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS, 0,
                           winreg.KEY_READ | winreg.KEY_WRITE),
            winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS)


def _refresh_wininet():
    try:
        import ctypes
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0)
        w.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


def _proxy_enable(http_port, socks_port):
    if winreg is None:
        return False, "Registry unavailable."
    proxy = (f"http=127.0.0.1:{http_port};https=127.0.0.1:{http_port}"
             if http_port else f"socks=127.0.0.1:{socks_port}")
    try:
        key, root, sub = _open_settings_key()
        try: _state["prev_enable"] = winreg.QueryValueEx(key, "ProxyEnable")[0]
        except FileNotFoundError: _state["prev_enable"] = 0
        try: _state["prev_server"] = winreg.QueryValueEx(key, "ProxyServer")[0]
        except FileNotFoundError: _state["prev_server"] = ""
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        _state["proxy_root"], _state["proxy_subkey"] = root, sub
    except Exception as exc:
        return False, f"Could not set system proxy: {exc}"
    _refresh_wininet()
    _state["mode"] = "proxy"
    _state["running"] = True
    return (True, "Routing via Windows system proxy (browsers/proxy-aware apps). "
                  "Restart the browser if it was open.")


def _proxy_disable():
    if winreg is None:
        return True, "Nothing to restore."
    try:
        root = _state.get("proxy_root") or winreg.HKEY_CURRENT_USER
        sub = _state.get("proxy_subkey") or _INTERNET_SETTINGS
        key = winreg.OpenKey(root, sub, 0, winreg.KEY_READ | winreg.KEY_WRITE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD,
                          int(_state["prev_enable"] or 0))
        if _state["prev_server"]:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, _state["prev_server"])
        else:
            try: winreg.DeleteValue(key, "ProxyServer")
            except FileNotFoundError: pass
        winreg.CloseKey(key)
    except Exception as exc:
        return False, f"Could not restore system proxy: {exc}"
    _refresh_wininet()
    return True, "System proxy restored."


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────
def enable(socks_port: int = 9050, tor_pid=None, http_port=None,
           tor_dns_port: int = 9053, log=None) -> tuple:
    if _state["running"]:
        return True, "Routing already active."
    # Try the full TUN VPN first (needs admin); fall back to the system proxy.
    is_admin = False
    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    if is_admin:
        ok, msg = _tun_enable(socks_port, tor_pid, tor_dns_port, log=log)
        if ok:
            return True, msg
        # TUN failed — clean up any partial state, then fall back.
        _tun_disable()
        if log:
            try: log(f"TUN VPN unavailable ({msg}) — using system proxy instead.")
            except Exception: pass
    elif log:
        try: log("Not elevated — using system proxy (run as admin for all-apps VPN).")
        except Exception: pass
    return _proxy_enable(http_port, socks_port)


def cleanup_stale(kill_tor: bool = False) -> None:
    """
    Quietly undo any leftover TUN state from a previous crashed/force-closed run:
    a stray tun2socks holding an adapter, the Tor default route, and adapters whose
    DNS is still pinned to our local forwarder (127.0.0.1 / ::1) — exactly what
    reset_internet.bat does, but automatic. Run at startup (self-heal) and again
    right before each connect (clean slate). `kill_tor` also frees a stray tor.exe
    holding the ports (used pre-connect; not at startup, to avoid killing an
    unrelated Tor like Tor Browser). No-op while routing is active.
    """
    if _state.get("running"):
        return
    try:
        _run(["taskkill", "/F", "/IM", "tun2socks.exe"])
        if kill_tor:
            _run(["taskkill", "/F", "/IM", "tor.exe"])
        _remove_tun_adapters()    # delete any piled-up torshield adapters
        _run(["route", "delete", "0.0.0.0", "mask", "0.0.0.0", TUN_GW])
        # Reset only adapters still pinned to OUR forwarder (don't disturb real DNS),
        # and re-enable IPv6 in case an older build disabled it.
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-DnsClientServerAddress | "
             "Where-Object {$_.ServerAddresses -contains '127.0.0.1' "
             "-or $_.ServerAddresses -contains '::1'} | "
             "ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex "
             "$_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue };"
             "Get-NetAdapter | ForEach-Object { Enable-NetAdapterBinding -Name "
             "$_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue }"],
            capture_output=True, text=True, creationflags=_CREATE_NO_WINDOW)
        _run(["ipconfig", "/flushdns"])
    except Exception:
        pass


def disable() -> tuple:
    mode = _state.get("mode")
    try:
        if mode == "tun":
            _tun_disable()
            result = (True, "TUN VPN stopped — traffic is direct again.")
        elif mode == "proxy":
            result = _proxy_disable()
        else:
            result = (True, "Routing was not active.")
    finally:
        _state["mode"] = None
        _state["running"] = False
        _state["prev_enable"] = None
        _state["prev_server"] = None
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Secure-browser launch (used by the proxy fallback path)
# ─────────────────────────────────────────────────────────────────────────────
def _find_browser():
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    lad = os.environ.get("LOCALAPPDATA", "")
    for path, name in [
        (os.path.join(pf,    r"Google\Chrome\Application\chrome.exe"), "Chrome"),
        (os.path.join(pfx86, r"Google\Chrome\Application\chrome.exe"), "Chrome"),
        (os.path.join(lad,   r"Google\Chrome\Application\chrome.exe"), "Chrome"),
        (os.path.join(pfx86, r"Microsoft\Edge\Application\msedge.exe"), "Edge"),
        (os.path.join(pf,    r"Microsoft\Edge\Application\msedge.exe"), "Edge"),
    ]:
        if path and os.path.isfile(path):
            return path, name
    return None, None


def open_secure_browser(http_port: int = 9080,
                        url: str = "https://check.torproject.org/") -> tuple:
    """Restart the user's browser through Tor (used only in proxy-fallback mode;
    in TUN mode every app already routes through Tor, so this isn't needed)."""
    exe, name = _find_browser()
    if not exe:
        return False, f"No Chrome/Edge found. Set the proxy to HTTP 127.0.0.1:{http_port}."
    image = os.path.basename(exe)
    try:
        subprocess.run(["taskkill", "/F", "/IM", image],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       creationflags=_CREATE_NO_WINDOW)
        time.sleep(1.5)
    except Exception:
        pass
    try:
        subprocess.Popen([exe, "--disable-quic",
                          "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                          "--new-window", url],
                         close_fds=True, creationflags=_CREATE_NO_WINDOW)
    except Exception as exc:
        return False, f"Could not relaunch {name}: {exc}"
    return True, f"{name} restarted through Tor."
