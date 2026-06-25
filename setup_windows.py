"""
setup_windows.py — one-shot Windows setup for TorShield.

Windows has no install.sh, so run this once from the project folder:

    python setup_windows.py

It installs the Python dependencies, generates the torrc, pre-fetches bridges,
and checks for tor.exe. It does NOT touch a Linux system in any way.

Tor itself: download the Tor Expert Bundle from
    https://www.torproject.org/download/tor/
and place tor.exe (plus snowflake-client.exe / obfs4proxy.exe if you want
bridges) in a folder named  tor\\  next to this script. The app also looks in
common Tor Browser / "C:\\Program Files\\Tor" locations.
"""

import os
import sys
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def _pip(*args):
    subprocess.check_call([sys.executable, "-m", "pip", "install", *args])


def main():
    if os.name != "nt":
        print("This setup is for Windows. On Linux use ./install.sh instead.")
        return

    print("== TorShield — Windows setup ==\n")

    # 1. Python dependencies (the Windows PyQt5 wheel bundles everything needed).
    print("[1/4] Installing Python packages…")
    req = os.path.join(HERE, "requirements.txt")
    try:
        if os.path.isfile(req):
            _pip("--upgrade", "-r", req)
        else:
            _pip("--upgrade", "PyQt5", "PyQt-Fluent-Widgets", "stem", "requests",
                 "PySocks", "fake-useragent", "Pillow", "pydivert")
        print("      OK\n")
    except Exception as exc:
        print(f"      pip problem: {exc}\n      Try: python -m pip install -r requirements.txt\n")

    # 2. Pull in the backend and generate the torrc + fetch bridges.
    sys.path.insert(0, HERE)
    try:
        import torshield_core as core
    except Exception as exc:
        print(f"[!] Could not import torshield_core: {exc}")
        return

    print("[2/4] Locating Tor…")
    if os.path.isfile(core.TOR_EXE_PATH) or _which(core.TOR_EXE_PATH):
        print(f"      Found: {core.TOR_EXE_PATH}\n")
    else:
        print("      tor.exe NOT found. Download the Tor Expert Bundle from")
        print("      https://www.torproject.org/download/tor/ and put tor.exe")
        print(f"      in:  {os.path.join(HERE, 'tor')}\\\n")

    print("[3/4] Generating torrc…")
    try:
        core.ensure_torrc()
        print(f"      Wrote: {core.TORRC_PATH}\n")
    except Exception as exc:
        print(f"      Could not write torrc: {exc}\n")

    print("[4/4] Fetching bridges from Tor BridgeDB…")
    try:
        counts = core.refresh_all_bridges(force=True)
        print(f"      obfs4={counts.get('obfs4', 0)}  snowflake={counts.get('snowflake', 0)}\n")
    except Exception as exc:
        print(f"      Could not fetch bridges now: {exc}\n")

    print("== Done ==")
    print("Launch the app with (right-click → Run as administrator for routing):")
    print(f"    python {os.path.join(HERE, 'tor_vpn_gui.py')}")


def _which(name):
    from shutil import which
    return which(name)


if __name__ == "__main__":
    main()
