<div align="center">

<img src="docs/assets/logo.svg" width="96" height="96" alt="Prosvet logo">

# Prosvet

**Network diagnostics & censorship measurement.**
Find out *what* is blocked or throttled on your network — and *how*.

[![CI](https://github.com/Derposd/prosvet/actions/workflows/ci.yml/badge.svg)](https://github.com/Derposd/prosvet/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Derposd/prosvet?color=7C9CFF)](https://github.com/Derposd/prosvet/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/Derposd/prosvet)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-3FB950)](LICENSE)
[![Map](https://img.shields.io/badge/public%20map-live-F0883E)](https://derposd.github.io/prosvet/)

**English** · [Русский](README.ru.md)

<img src="docs/assets/demo.gif" alt="prosvet demo: status table and interactive TUI" width="880">

</div>

---

## Why

"Telegram doesn't work" can mean very different things. Your provider may remove the name from DNS,
drop the server's IP address, cut the TLS handshake when it sees the site name (DPI by SNI), freeze
every connection to foreign hosting after the first ~16 KB, filter QUIC, or switch your mobile
connection to a *whitelist* where only approved domestic services work.

Each of these needs a different explanation — and they are changing week to week
(see the [research notes](docs/research.md)). Prosvet runs a set of differential tests for every
service and tells you, in plain language, which method is used, how sure it is and why.

- **One static binary** for Windows, Linux, macOS and OpenWrt routers. No dependencies, no account.
- **Measurement only.** No proxies, tunnels or VPN code — Prosvet explains, it does not route traffic.
- **Private by default.** Everything runs locally; nothing is sent anywhere unless you run `prosvet submit`.
- **Open data.** Anonymous results feed a [public map](https://derposd.github.io/prosvet/) of
  service × provider, built by GitHub Actions — no server, no trackers.

## Quick start

```bash
# 1. download the binary for your OS from Releases (or: scoop / brew / winget / docker, see below)
# 2. run the interactive TUI
prosvet
# 3. or a one-shot scan with a report
prosvet scan && prosvet report --format html -o report.html
```

Want to see every verdict without touching the real network? `prosvet demo` runs against a
simulated censored network on localhost.

## Features

| | |
|---|---|
| **DNS** | System resolver vs national DNS (NSDI) vs DNS-over-HTTPS; detects removed records, stub/bogon answers, substituted addresses, blocked DoH/DoT and transparent DNS interception |
| **TCP / IP** | Connect to every address; drop vs reject; tells "this CDN node is blocked" from DNS tampering |
| **TLS / SNI** | Handshake with the real name, **without SNI** and with a **random SNI** — the differential test that separates DPI-by-name from IP blocking and from generic TLS resets |
| **Certificates** | Flags certificates from the Russian state CA on foreign sites (MITM); tolerates private PKI (e.g. Signal) |
| **HTTP** | Block-page fingerprints of Russian ISPs; mid-stream resets |
| **Throttling** | Detects the "16–20 KB" freeze by counting bytes **on the wire**, and rate limiting against a domestic baseline |
| **QUIC / ECH** | QUIC v1/v2 with real vs random SNI (fresh UDP port per try), Encrypted Client Hello |
| **Whitelist mode** | `prosvet whitelist` — are only allow-listed domestic services reachable? DNS, IP or DPI level? |
| **Reliability** | Every test runs 3× with majority voting; confidence levels; evidence for every conclusion |
| **Network** | ASN, provider, coarse region (federal subject), mobile vs fixed, VPN/proxy warning — your IP is never stored |
| **Interfaces** | TUI (bubbletea), plain CLI, local web dashboard (`prosvet serve`, 127.0.0.1 only) |
| **Reports** | Terminal, JSON, Markdown, self-contained HTML (no scripts) |
| **Languages** | Russian and English, auto-detected; every string lives in [`locales/`](locales) |
| **Targets** | 60+ services in editable YAML ([`targets/`](targets)), with sources for every expectation |

## Example output

```text
Prosvet · network diagnostics & censorship measurement
⚠ DEMO — simulated network, not real measurements
● Demo Telecom (AS64500) · Moscow · fixed line

MESSENGERS
  ● Messenger A  Blocked    DPI blocking by server name (SNI) — TCP RST injected · high confidence
  ● Messenger B  Blocked    DNS tampering — removed from the national DNS (NSDI) · high confidence
  ● Messenger C  Works

VIDEO
  ● Video A      Throttled  Throttling: transfer freezes — freeze after ~16–20 KB · high confidence
  ● Video B      Throttled  Throttling: low speed · medium confidence

SOCIAL NETWORKS
  ● Social A     Blocked    ISP block page — ru.rostelecom.warning · high confidence
  ● Social B     Blocked    DNS tampering — stub address returned · high confidence
  ● Social C     Blocked    Blocked by IP address — connection rejected · medium confidence
  ● Secure site  Blocked    TLS interception (MITM) — certificate from the Russian state CA · high confidence

DNS
  ● DNS queries to public resolvers are intercepted on the path (answers do not come from 198.51.100.8).
  ● Your system resolver tampers with: messenger-b.demo, social-b.demo.

4 work · 2 throttled · 0 partially blocked · 6 blocked
```

Every verdict comes with an explanation and evidence, e.g. *"TLS handshake with the real server name
failed: reset. Seen in 3 of 3 attempts. The same server answered a handshake with SNI variant
'random'."*

## How it works

For each endpoint of each service:

1. **DNS** — system resolver ×3, the national DNS (NSDI) and DoH with fallbacks (Cloudflare → Quad9 → AdGuard → Google).
2. **TCP + TLS** ×3 with the real SNI; the HTTP request reuses the same connection and reads up to 64 KB with stall detection.
3. On a failed handshake: **no-SNI** and **random-SNI** handshakes ×3 to the same IP.
4. **Throttling**: a large file from the same provider, bytes counted at the TCP level; speed compared with a domestic mirror.
5. **QUIC** (random SNI first — a filtered flow is blackholed for minutes) and **ECH** where configured.
6. The **classifier** combines the signals ([rules](docs/research.md#7-методология-prosvet-вывод-из-ресёрча)) — the
   `expect` field from public sources is shown next to the result but never used to decide it.

| Verdict | Signature |
|---|---|
| DNS tampering | system resolver: NXDOMAIN / stub / bogon, while DoH returns a working address |
| IP block | TCP fails to every address while control hosts work |
| DPI by SNI | TCP works; TLS with the real name fails; no-SNI or random-SNI handshake succeeds |
| TLS reset | handshake reset regardless of the name |
| Throttling: freeze | transfer stalls after ~12–36 KB on the wire, no RST |
| Throttling: rate | < 25 % of the domestic baseline and < 1 Mbit/s |
| TLS interception | foreign site with a certificate chaining to the Russian state CA |
| QUIC by SNI | real-SNI QUIC unanswered while random-SNI QUIC answers |

## Install

| Method | Command |
|---|---|
| Binary | download from [Releases](https://github.com/Derposd/prosvet/releases), verify `checksums.txt`, run |
| Scoop (Windows) | `scoop bucket add prosvet https://github.com/Derposd/scoop-bucket && scoop install prosvet` |
| winget (Windows) | `winget install Prosvet.prosvet` |
| Homebrew (macOS/Linux) | `brew install --cask Derposd/tap/prosvet` |
| Docker | `docker run --rm -it --network host ghcr.io/derposd/prosvet` |
| Debian/Ubuntu, Fedora, Alpine | `.deb`, `.rpm`, `.apk` packages on the Releases page |
| Go | `go install github.com/Derposd/prosvet/cmd/prosvet@latest` |
| OpenWrt router | copy `prosvet_*_linux_mipsle_softfloat` (or `mips_softfloat`, `armv7`, `arm64`) to `/tmp`, `chmod +x`, run `./prosvet scan --yes` |

## Commands

| Command | What it does |
|---|---|
| `prosvet` | interactive TUI |
| `prosvet scan` | scan default categories (`--target telegram`, `--category messengers`, `--all` for opt-in) |
| `prosvet whitelist` | whitelist-mode check |
| `prosvet report --format html\|md\|json` | render the last report (`-o file`) |
| `prosvet serve` | local web dashboard on `127.0.0.1:8787` (`--open`) |
| `prosvet submit` | prepare an anonymous result file for the public map |
| `prosvet targets` | list services and categories |
| `prosvet demo` | run against a simulated censored network (`--tui`) |

Useful flags: `--lang ru|en`, `--brief`, `--verbose`, `--timeout-scale 2` for slow mobile networks,
`--targets-dir ./my-targets` for your own lists, `--asn`/`--region`/`--conn` to skip online network detection.

## Public map

[**derposd.github.io/prosvet**](https://derposd.github.io/prosvet/) shows the latest status of
every service per provider, region and connection type, a daily timeline and the history of when
blocking started. It is a static site rebuilt by GitHub Actions from [`results/`](results).

To contribute data: `prosvet scan`, `prosvet submit`, then open a pull request with the file or paste
it into the [issue form](https://github.com/Derposd/prosvet/issues/new?template=submit-results.yml).

## Privacy

- No telemetry, no analytics, no update checks. All measurements run on your machine.
- Your public IP is used in memory to look up the ASN and region (RIPEstat) and is **never stored** —
  use `--offline-netinfo --asn N` to skip even that.
- The last report is kept in your user cache directory; `prosvet submit` shows you **exactly** what
  would be shared (no IP, no time of day, no device data) and writes a file — publishing is up to you.
- The probes ignore `HTTP(S)_PROXY` and warn when a VPN seems active, because results would describe
  the VPN exit instead of your provider.

Details: [PRIVACY.md](PRIVACY.md).

## FAQ

**Is this a VPN or a way around blocks?** No. Prosvet contains no proxy, tunnel or VPN code. It
measures and explains, like a thermometer.

**Is it legal to run in Russia?** Checking whether a site opens is ordinary network diagnostics.
Prosvet does not access blocked content beyond a handshake and the first bytes of a public page.
The opt-in `media` category asks for confirmation because your provider can see the connections.

**Why does it test each thing three times?** Filtering equipment is overloaded and inconsistent;
single measurements produce false positives. The result is decided by majority and the confidence
is lowered when attempts disagree.

**Why not just use OONI Probe?** OONI is excellent and inspired this project. Prosvet focuses on
what OONI's web test does not cover in one flow: SNI-vs-IP disambiguation, the 16–20 KB freeze,
whitelist mode, DNS interception, plain-language verdicts — and works without any backend.
See the [gap analysis](docs/research.md#6-существующие-инструменты-и-пробелы).

**Does it work outside Russia?** Yes — the probes and the classifier are generic; the default
target lists and some fingerprints are Russia-specific. Bring your own `targets/*.yaml`.

**Can I run it on a router?** Yes: static binaries for OpenWrt (mips/mipsle softfloat, armv7, arm64)
are UPX-compressed. Measuring from the router shows what the whole household gets.

## Contributing

New targets, fingerprints, translations and code are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md),
the [roadmap](ROADMAP.md) and [good first issues](docs/first-issues.md).
Security reports: [SECURITY.md](SECURITY.md).

## Acknowledgments

The methodology builds on public research by [OONI](https://ooni.org), the Censored Planet team
(*TSPU: Russia's Decentralized Censorship System*, IMC 2022), the FOCI 2026 study of QUIC SNI
censorship, net4people, Mediazona and many others — full list in [docs/research.md](docs/research.md#12-источники).

## License

Code: [MIT](LICENSE). Result data in `results/`: [CC0 1.0](results/README.md#license--лицензия).
