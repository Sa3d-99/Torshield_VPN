"""
win_routing — Windows "route all TCP through Tor" via WinDivert.

⚠️  WINDOWS-ONLY · EXPERIMENTAL
This module is never imported on Linux (torshield_core only imports it inside an
`if IS_WINDOWS:` branch). It implements the transparent-proxy equivalent of the
Linux iptables TransPort routing, using the WinDivert kernel driver through the
`pydivert` Python bindings:

  1. A local SOCKS bridge listens on 127.0.0.1:BRIDGE_PORT. For every connection
     it receives, it looks up the *original* destination (saved by the diverter)
     and relays the stream to Tor's SOCKS5 proxy (127.0.0.1:<socks_port>) using
     socks5h, so DNS is resolved through Tor as well.
  2. A WinDivert thread intercepts outbound TCP, rewrites the destination to the
     local bridge (remembering the real destination keyed by the source port),
     and rewrites the return traffic back so applications are unaware.

Requirements on the target machine (handled by the Windows setup):
  • pip install pydivert
  • pip install PySocks   (already a TorShield dependency)
  • Administrator privileges (WinDivert loads a kernel driver)

This needs testing/iteration on real Windows — packet-level NAT on loopback is
fiddly. enable()/disable() never raise; they return (ok, message) like the Linux
functions so the GUI can show the result either way.
"""

import socket
import struct
import threading

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 9061          # local transparent-proxy bridge port

_state = {
    "running": False,
    "divert": None,
    "bridge": None,
    "threads": [],
    "nat": {},              # src_port -> (orig_dst_ip, orig_dst_port)
    "socks_port": 9050,
}


# ─────────────────────────────────────────────────────────────────────────────
# SOCKS bridge: accept redirected connections, relay to Tor with original dest
# ─────────────────────────────────────────────────────────────────────────────
def _relay(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


def _handle_client(client, addr):
    try:
        import socks   # PySocks
    except Exception:
        client.close()
        return
    src_port = addr[1]
    dest = _state["nat"].get(src_port)
    if not dest:
        client.close()
        return
    dst_ip, dst_port = dest
    try:
        upstream = socks.socksocket()
        upstream.set_proxy(socks.SOCKS5, "127.0.0.1", _state["socks_port"],
                           rdns=True)
        upstream.connect((dst_ip, dst_port))
    except Exception:
        client.close()
        return
    threading.Thread(target=_relay, args=(client, upstream), daemon=True).start()
    threading.Thread(target=_relay, args=(upstream, client), daemon=True).start()


def _bridge_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BRIDGE_HOST, BRIDGE_PORT))
    srv.listen(128)
    _state["bridge"] = srv
    while _state["running"]:
        try:
            client, addr = srv.accept()
        except Exception:
            break
        threading.Thread(target=_handle_client, args=(client, addr),
                         daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# WinDivert diverter: redirect outbound TCP to the bridge, rewrite returns
# ─────────────────────────────────────────────────────────────────────────────
def _divert_loop():
    import pydivert  # type: ignore  # Windows-only dep, imported lazily at runtime
    nat = _state["nat"]
    # Capture outbound TCP and the loopback return path from the bridge.
    flt = (f"tcp and "
           f"((outbound and ip.DstAddr != 127.0.0.1) or "
           f" (ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == {BRIDGE_PORT}))")
    try:
        w = pydivert.WinDivert(flt)
        w.open()
    except Exception:
        return
    _state["divert"] = w
    bridge_ip = struct.unpack(">I", socket.inet_aton(BRIDGE_HOST))[0]  # noqa: F841
    while _state["running"]:
        try:
            packet = w.recv()
        except Exception:
            break
        try:
            if packet.is_outbound and packet.dst_addr != "127.0.0.1":
                # App → remote: remember original destination, send to bridge.
                nat[packet.src_port] = (packet.dst_addr, packet.dst_port)
                packet.dst_addr = BRIDGE_HOST
                packet.dst_port = BRIDGE_PORT
            elif packet.src_addr == "127.0.0.1" and packet.src_port == BRIDGE_PORT:
                # Bridge → app: rewrite source back to the original destination.
                orig = nat.get(packet.dst_port)
                if orig:
                    packet.src_addr = orig[0]
                    packet.src_port = orig[1]
            w.send(packet)        # pydivert recomputes checksums on send
        except Exception:
            try:
                w.send(packet)
            except Exception:
                pass
    try:
        w.close()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Public API (mirrors the Linux enable/disable_system_routing signatures)
# ─────────────────────────────────────────────────────────────────────────────
def enable(socks_port: int = 9050) -> tuple:
    if _state["running"]:
        return True, "System-wide routing already active (WinDivert)"
    try:
        import pydivert  # type: ignore  # noqa: F401  (Windows-only)
    except Exception:
        return (False,
                "WinDivert/pydivert not installed. Run: pip install pydivert")
    _state["socks_port"] = socks_port
    _state["nat"] = {}
    _state["running"] = True
    t1 = threading.Thread(target=_bridge_server, daemon=True)
    t2 = threading.Thread(target=_divert_loop, daemon=True)
    t1.start()
    t2.start()
    _state["threads"] = [t1, t2]
    return True, "System-wide routing enabled — all TCP through Tor (WinDivert)"


def disable() -> tuple:
    _state["running"] = False
    w = _state.get("divert")
    if w:
        try:
            w.close()
        except Exception:
            pass
    srv = _state.get("bridge")
    if srv:
        try:
            srv.close()
        except Exception:
            pass
    _state["divert"] = None
    _state["bridge"] = None
    _state["nat"] = {}
    return True, "System routing restored — traffic is direct again"
