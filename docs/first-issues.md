# Good first issues / Задачи для новичков

Ten self-contained tasks for a first contribution. Each lists where to look and how to know you
are done. Open an issue (or comment on the existing one) before starting, so work is not duplicated.

Десять небольших задач для первого вклада. В каждой — где смотреть и критерий готовности.

---

### 1. Localise Cobra's built-in help strings
Cobra prints "Usage:", "Available Commands", "Flags:" in English even with `--lang ru`.
*Where:* `internal/cli/root.go` (`SetUsageTemplate`, `SetHelpTemplate`), `locales/*.yaml`.
*Done when:* `prosvet --help --lang ru` has no English headings; strings live in the locale files.

### 2. `prosvet targets --json`
Machine-readable list of targets and categories for scripts.
*Where:* `internal/cli/commands.go` (`targetsCmd`).
*Done when:* valid JSON with id, name, category, endpoints; a test parses it.

### 3. Add `--only-problems` to terminal and Markdown reports
The HTML report has a "show only problems" filter; the terminal and Markdown outputs do not.
*Where:* `internal/report/terminal.go`, `internal/report/markdown.go`, a flag in `internal/cli`.
*Done when:* working targets are hidden with the flag; tests cover both renderers.

### 4. Ukrainian / Kazakh / Belarusian translation
*Where:* copy `locales/en.yaml` to `locales/uk.yaml` (or `kk`, `be`).
*Done when:* `go test ./internal/i18n/` passes (keys and placeholders must match).

### 5. More block-page fingerprints
Collect redirect hosts or page phrases of regional Russian ISPs (with an OONI measurement or a
report as evidence).
*Where:* `internal/fingerprint/fingerprints.yaml`.
*Done when:* new entries with unique ids, `go test ./internal/fingerprint/` passes, evidence linked in the PR.

### 6. Show elapsed time and ETA in the TUI progress screen
*Where:* `internal/tui/tui.go` (`viewProgress`).
*Done when:* the progress screen shows elapsed time and a rough remaining-time estimate.

### 7. Copy the result file to the clipboard in `prosvet submit`
Make pasting into the issue form one step (OSC 52 escape sequence works in most terminals without
extra dependencies).
*Where:* `internal/cli/interactive.go` (`submitCmd`).
*Done when:* `--copy` puts the JSON into the clipboard; documented in the README.

### 8. Keyboard help overlay in the TUI (`?`)
*Where:* `internal/tui` (consider `bubbles/help` and `bubbles/key`).
*Done when:* `?` toggles a help panel listing all keys on every screen; strings in `locales/`.

### 9. Map: link to a cell
Allow sharing a link like `…/prosvet/#t=telegram&r=12389|RU-MOW|fixed` that opens the service panel.
*Where:* `internal/mapgen/site/app.js`.
*Done when:* opening the URL selects filters and opens the panel; works without reload on hash change.

### 10. Validate `targets/*.yaml` with a JSON Schema for editors
A schema enables autocompletion in VS Code (YAML extension) for contributors.
*Where:* new `targets/schema.json`, a `# yaml-language-server: $schema=schema.json` line in each file,
a test that every target file validates.
*Done when:* editors show completion; CI fails on schema violations.
