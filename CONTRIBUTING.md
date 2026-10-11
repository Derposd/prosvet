# Contributing to Prosvet

Thank you for helping! Prosvet is useful only if its targets, fingerprints and classifier keep up
with reality, so every contribution counts. *Русская версия — ниже.*

## Ground rules

- **Measurement only.** Prosvet must never contain proxy, tunnel, VPN, DPI-desync or similar code,
  nor instructions for accessing blocked resources. Pull requests that add such functionality are
  closed. The wording is "network diagnostics & censorship measurement".
- **Privacy first.** No telemetry, no new network calls without a clear reason documented in
  `PRIVACY.md`, never store or print the user's IP.
- **Sources.** Any statement about blocking (`expect`, `since`, docs) needs a source in
  `docs/research.md`.
- Be kind: see the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to help

| You want to… | Do this |
|---|---|
| Add or fix a target | edit `targets/*.yaml` (schema in [targets/README.md](targets/README.md)), run `go test ./internal/catalog/` |
| Add a block-page or DNS-stub fingerprint | edit `internal/fingerprint/fingerprints.yaml`, include evidence in the PR |
| Report a new blocking method | open a “Blocking report” issue with the JSON report (`prosvet scan -f json`) |
| Contribute measurements | `prosvet scan` + `prosvet submit`, then a PR or the issue form ([results/README.md](results/README.md)) |
| Translate | copy `locales/en.yaml` to `locales/<lang>.yaml`; the test suite checks that keys and placeholders match |
| Write code | pick an issue from [docs/first-issues.md](docs/first-issues.md) or the [roadmap](ROADMAP.md) |

## Development

```bash
git clone https://github.com/Derposd/prosvet && cd prosvet
go test ./...            # unit + integration tests (simulated censored network on localhost)
go test -short ./...     # skip the slower integration tests
golangci-lint run ./...  # v2, config in .golangci.yml
go run ./cmd/prosvet demo
go run ./cmd/prosvet-map -results results -out site -sample   # public map with sample data
```

Requirements: Go (see `go.mod`), golangci-lint v2. Optional: GoReleaser v2, vhs (for the GIF),
`go run ./tools/assets` regenerates the logo and social preview.

### Code map

| Package | Purpose |
|---|---|
| `internal/probe` | DNS (system/UDP/DoT/DoH), TCP, TLS with SNI variants, HTTP with stall detection, QUIC, ECH |
| `internal/engine` | orchestration, repetitions and majority voting, baseline, DNS matrix, whitelist check |
| `internal/classify` | rules that turn measurements into verdicts with evidence |
| `internal/testnet` | the censor simulator used by tests and `prosvet demo` |
| `internal/report` | view model, terminal/Markdown/HTML/JSON renderers |
| `internal/tui`, `internal/serve` | interactive TUI and local dashboard |
| `internal/submit`, `internal/mapgen` | anonymous submissions, validation, public map |
| `internal/netinfo` | ASN, provider, region, connection type, VPN heuristics |
| `locales/`, `targets/` | all user-facing strings and target lists |

### Adding a verdict or rule

1. Add the measurement to `internal/model` / `internal/probe`.
2. Add the rule in `internal/classify` with a table test in `classify_test.go`.
3. Reproduce the behaviour in `internal/testnet` (a middlebox action) and add an integration case
   in `internal/engine/engine_test.go`.
4. Add `kind.*` / `ev.*` strings to **both** locale files.

### Commits and PRs

- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `targets:`, `docs:`, `test:`, `ci:`, `chore:`.
- Tests and the linter must pass; new behaviour needs tests.
- Keep PRs focused; describe how you verified the change (ideally on a real network, with a redacted report).

---

## Участие (RU)

- **Только измерения.** В проекте не должно быть кода прокси, туннелей, VPN, десинхронизации DPI и
  инструкций по доступу к заблокированным ресурсам — такие PR закрываются.
- **Приватность.** Никакой телеметрии; новые сетевые обращения — только с описанием в `PRIVACY.md`.
- **Источники.** Любое утверждение о блокировке подкрепляется источником в `docs/research.md`.

Как помочь: добавить цель (`targets/*.yaml`), отпечаток заглушки (`internal/fingerprint/fingerprints.yaml`),
сообщить о новом методе блокировки (issue «Сообщение о блокировке»), прислать измерения
(`prosvet scan` + `prosvet submit`), перевести интерфейс (`locales/`), взять задачу из
[docs/first-issues.md](docs/first-issues.md).

Разработка: `go test ./...`, `golangci-lint run ./...`, `go run ./cmd/prosvet demo`.
Коммиты — в формате Conventional Commits.
