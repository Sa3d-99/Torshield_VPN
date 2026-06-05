# Changelog

All notable changes to TorShield are documented here.

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
