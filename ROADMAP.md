# Roadmap

Prosvet's goal: the most trustworthy, understandable way for an ordinary person to see *how* their
network is censored — and open data about it. Items move as research and contributions arrive.
*Дорожная карта; пункты отсортированы по приоритету.*

## v0.1 — first public release ✅

- Probes: DNS (system/NSDI/DoH/DoT), TCP, TLS with real/no/random SNI, HTTP with wire-level stall
  detection, QUIC v1/v2, ECH, DNS interception
- Classifier with confidence and evidence; whitelist-mode check; 3× repetitions with majority voting
- TUI, CLI, local dashboard, Markdown/HTML/JSON reports, RU/EN
- Anonymous submissions, public heatmap on GitHub Pages, issue-to-PR flow
- Releases for Windows/Linux/macOS/FreeBSD/OpenWrt, Docker, deb/rpm/apk

## v0.2 — accuracy

- [ ] Scoop bucket, winget manifest and Homebrew cask (configured in `.goreleaser.yaml`, enabled once the `PACKAGES_TOKEN` secret exists)
- [ ] Validate thresholds of the 16–20 KB freeze per operator with submitted `stall_kb` data
- [ ] IPv6 measurements alongside IPv4
- [ ] Packet-level freeze detection (count of packets, not only bytes) where the OS allows it
- [ ] HTTP/2 and HTTP/3 page fetches (currently HTTP/1.1 over TLS + QUIC handshake)
- [ ] Per-ISP DNS stub fingerprints learned from submissions (with review)
- [ ] Optional import of Citizen Lab test lists as an extra category

## v0.3 — reach

- [ ] OpenWrt package (`.ipk`/`apk`) and a LuCI status page
- [ ] Android build (Termux) instructions and a minimal UI wrapper
- [ ] Scheduled measurements (`prosvet watch`) with local history and change notifications
- [ ] More languages (uk, kk, be, fa, tr) — strings are already in `locales/`

## v0.4 — the map

- [ ] Regional choropleth view next to the heatmap
- [ ] Per-provider pages with history and methods used
- [ ] RSS/Atom feed of status changes ("X started being blocked on Y")
- [ ] Data exports (CSV/Parquet) published with every build

## Research backlog

- [ ] How whitelist mode is enforced (IP vs SNI) per mobile operator
- [ ] Prevalence of plain-DNS DNAT to the NSDI
- [ ] FaceTime / VoIP blocking method (signalling vs media)
- [ ] Stability of QUIC v2 passthrough

## Explicitly out of scope

Circumvention of any kind (proxies, tunnels, VPN, DPI desynchronisation, "working SNI" search),
user tracking, telemetry, and a central server that could be blocked or subpoenaed.
