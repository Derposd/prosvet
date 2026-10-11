## What and why / Что и зачем

<!-- One or two sentences. Link the issue: Closes #123 -->

## How it was verified / Как проверено

<!-- Tests, `prosvet demo`, a real-network run (attach a redacted report), screenshots for UI changes. -->

## Checklist

- [ ] `go test ./...` and `golangci-lint run ./...` pass
- [ ] New user-facing strings are in **both** `locales/en.yaml` and `locales/ru.yaml`
- [ ] Claims about blocking (`expect`, docs) have a source in `docs/research.md`
- [ ] No circumvention functionality, no telemetry, no new network calls without a note in `PRIVACY.md`
- [ ] Commit messages follow Conventional Commits
