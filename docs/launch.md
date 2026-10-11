# Launch checklist and plan / Чек-лист публикации и план запуска

## 1. Before the first push

- [ ] Decide the GitHub owner. The code uses `ordinarysim/prosvet` in `go.mod`, `internal/brand/brand.go`,
      README badges, `.goreleaser.yaml`, issue templates and `results/README.md`. If the owner differs:
      `grep -rl "ordinarysim" . | xargs sed -i 's/ordinarysim/<owner>/g'` and `go mod tidy`.
- [ ] Review `docs/research.md` once more (sources are dated 2026-10-10).
- [ ] Run `go test ./... && golangci-lint run ./...` and `go run ./cmd/prosvet demo`.
- [ ] Run a real scan on 2–3 networks (home, mobile, a friend in another region); sanity-check verdicts.

## 2. Repository settings

```bash
gh repo create ordinarysim/prosvet --public --source . --push \
  --description "Network diagnostics & censorship measurement: find out what is blocked or throttled on your network and how (DNS, IP, SNI, TLS, QUIC, 16 KB throttling, whitelists)"
gh repo edit ordinarysim/prosvet --homepage https://ordinarysim.github.io/prosvet/ \
  --add-topic network-diagnostics --add-topic censorship --add-topic dpi --add-topic dns \
  --add-topic tls --add-topic cli --add-topic tui --add-topic golang \
  --add-topic censorship-measurement --add-topic ooni --add-topic quic --add-topic russia
gh label create results --color F0883E --description "Measurement submission"
gh label create targets --color 7C9CFF --description "Target lists"
gh label create blocking-report --color F85149 --description "New or unusual blocking method"
gh label create "good first issue" --color 3FB950 --force
```

- [ ] Settings → General → **Social preview**: upload `docs/assets/social-preview.png` (1280×640).
- [ ] Settings → Pages → **Source: GitHub Actions**; run the "Map" workflow once (`gh workflow run Map`).
- [ ] Settings → Security → enable **Private vulnerability reporting**, Dependabot alerts, secret scanning.
- [ ] Settings → Features → enable **Discussions** (linked from the issue chooser).
- [ ] Settings → Actions → General → allow GitHub Actions to **create pull requests** (issue-to-PR flow).
- [ ] Branch protection for `main`: require CI (`test`, `test-32bit`, `lint`, `docs`, `cross-build`).
- [ ] Create the 10 issues from `docs/first-issues.md` with the `good first issue` label.

## 3. Packaging

- [ ] Create repos `ordinarysim/homebrew-tap`, `ordinarysim/scoop-bucket` (empty, public) and fork
      `microsoft/winget-pkgs` to `ordinarysim/winget-pkgs`.
- [ ] Create a fine-grained token with *Contents: write* and *Pull requests: write* on those three repos,
      save it as the `PACKAGES_TOKEN` secret.
- [ ] `git tag v0.1.0 && git push --tags` → the Release workflow builds everything as a **draft** release;
      check assets (`checksums.txt`, OpenWrt binaries are UPX-compressed), then publish.
- [ ] Check `ghcr.io/ordinarysim/prosvet` is public (Packages → settings → visibility).
- [ ] Test install paths: Releases binary, `scoop install`, `brew install --cask`, `docker run`, `go install`.
- [ ] The winget PR is opened as a draft; mark it ready after the first manual validation.

## 4. Seed data for the map

- [ ] Collect 10–20 real submissions from volunteers in different regions/operators before announcing,
      so the map is not empty on day one. Never publish sample data on the live map.

## 5. Launch plan

Timing: Tuesday–Thursday, morning Moscow time for Russian venues, ~16:00 UTC for HN/Reddit.
Prepare a 30-second GIF (`docs/assets/demo.gif`) and two screenshots (TUI and map).

| Day | Where | Angle |
|---|---|---|
| D0 | **Хабр** (hubs: Информационная безопасность, Сетевые технологии, Go, Open source) | Long technical article: «Как устроены блокировки в 2026: DNS, SNI, 16 КБ и белые списки — и как это измерить». Methodology, real (anonymised) findings, the classifier, the testnet simulator, privacy design. Avoid any "how to get around" content. |
| D0 | Telegram channels on networks/infosec/Go (e.g. channels of ntc.party community, Go-сообщество, профильные админские каналы) | Short post + GIF + link to Habr. Ask admins in advance. |
| D1 | **Hacker News — Show HN** | "Show HN: Prosvet – measure how your network is censored (DNS, SNI, 16KB throttling)". First comment: what is new vs OONI, simulated-censor testnet, privacy, no circumvention code. Stay in the thread for 3–4 hours. |
| D1 | **r/golang** | Engineering angle: single static binary for OpenWrt mips, bubbletea TUI, simulated censored network for integration tests, wire-level byte counting. |
| D2 | **r/selfhosted** | Router/OpenWrt angle and the serverless map (GitHub Actions + Pages, data in git). |
| D2–D3 | r/netsec, r/russia (English), lobste.rs (`networking`, `go` tags), OONI community Slack/forum, net4people (as a measurement tool) | Methodology and open data; invite measurements. |
| D7 | Habr follow-up / blog post | First map insights from community data (per-operator 16–20 KB thresholds, whitelist prevalence). |

Messaging rules: say "network diagnostics & censorship measurement"; never promise access to blocked
services; emphasise privacy (no telemetry, IP never stored, opt-in submissions) and reproducibility
(`prosvet demo`, open methodology, sources).

After launch: answer issues within 24 h, merge first community PRs quickly, publish v0.1.1 with fixes
within a week, keep `docs/research.md` updated as the situation changes.
