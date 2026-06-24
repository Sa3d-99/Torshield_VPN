# Changelog

All notable changes to TorShield are documented here.

---

## [2.1.0] — 2026-06-24

### Added
- **Fully automatic connection** — tries a direct Tor connection first, then
  automatically falls back to Snowflake and obfs4 bridges if Tor cannot
  bootstrap. No connection mode to choose. Live bootstrap progress bar.
- **Automatic bridge fetching** — obfs4 bridges are pulled from Tor's BridgeDB
  via the captcha-free moat API (the same one Tor Browser uses), at install
  time and refreshed in the app. Nothing is hardcoded or pasted by hand.
  A **Refresh bridges** button fetches a fresh set on demand.
- Cached obfs4 bridges at `~/.local/share/torshield/obfs4_bridges.txt`.
- **Automatic system-wide routing** — when you connect (as root), ALL traffic is
  routed through Tor immediately. The switch remains as an optional override to
  temporarily go direct, and routing is restored on disconnect/close.
- Machine config (`torshield.conf`) written by the installer so the GUI always
  uses the exact Tor/transport binaries detected at install time.

### Changed
- **Portability:** `tor`, `snowflake-client`, and `obfs4proxy` paths are now
  auto-detected instead of hardcoded — fixes "crashes / won't connect" on other
  laptops where binaries live in different locations.
- `/etc/tor/torrc` is now **generated from `torrc.template`** (with the real
  per-machine paths substituted) instead of appended line-by-line, and is
  validated with `tor --verify-config` during install.
- A missing pluggable-transport binary is commented out automatically so Tor
  can still start (previously it would fail to launch).
- Refreshed UI — slate-dark theme, monospace terminal-style activity log with
  colour-coded levels, and a clearer 3-hop circuit visualisation.
- Pinned Python dependencies in `requirements.txt` for reproducible installs.

### Fixed
- App no longer crashes on launch when `pkexec` is missing — it falls back to
  `sudo`, then to running unprivileged (routing disabled) with a clear notice.

---

## [1.0.0] — 2026-06-04

### Added
- Initial release
- System-wide iptables transparent proxy routing (all TCP traffic through Tor)
- DNS leak prevention via Tor's DNSPort (5353)
- QUIC/HTTP3 blocking (UDP 443/80) to prevent Chrome bypass
- `conntrack -F` connection flushing on routing enable
- Auto root elevation via `pkexec` — no manual sudo required
- Exit node country selection (20 countries)
- New Identity button (SIGNAL NEWNYM)
- Live circuit tracker — shows Entry Guard, Middle Relay, Exit Node IPs
- Connection test via SOCKS5 proxy with randomised User-Agent
- Uptime counter
- Activity log with clear button
- Snowflake and obfs4 bridge support for censored networks
- Graceful shutdown — restores iptables rules on close
