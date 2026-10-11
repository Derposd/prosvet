# Prosvet targets

These files list the targets Prosvet checks. You can edit them without rebuilding the binary. Pass your own directory with `--targets <dir>`.

## Schema (v1)

```yaml
version: 1
category: messengers            # unique category id (used by --category)
title: { ru: "Мессенджеры", en: "Messengers" }
default: true                   # included in a plain `prosvet scan`; false = opt-in
order: 10                       # display order of categories (lower first)
targets:
  - id: telegram                # unique id (used by --target)
    name: Telegram
    expect: blocked             # prior from docs/research.md: ok|throttled|partial|blocked|unknown
                                # display only, never used by the classifier
    since: "2026-02-10"         # optional, date the restriction was first reported
    refs: [S1, S2]              # source ids from docs/research.md §12
    notes: { ru: "...", en: "..." }
    throttle_url: https://...   # optional: resource well over 34 KB, used for the 16–20 KB freeze test
    endpoints:
      - host: web.telegram.org  # hostname endpoint; default tests: dns, tcp, tls(real/none/random SNI), http
        port: 443               # default 443
        path: /                 # default /
        quic: true              # also run the QUIC v1 probe (default false)
        http80: true            # also fetch plain http://host/ and match blockpage fingerprints
      - addr: 149.154.167.51:443  # raw IP endpoint; default tests: tcp
        tests: [tcp, tls_nosni]
        note: MTProto DC2
```

Optional target fields:

| Field | Meaning |
|---|---|
| `role: control` | Expected to work. Used to tell "this service is blocked" apart from "the network is down". |
| `role: baseline` | Domestic speed reference for the throttling test. Never classified as blocked. |
| `verified: false` | The `throttle_url` was not reachable when the list was compiled. The scan runs it but marks the result. |

Optional endpoint fields:

| Field | Meaning |
|---|---|
| `tests` | Overrides the default test set. Values: `dns`, `tcp`, `tls`, `tls_nosni`, `http`, `quic`, `ech`. |
| `quic_versions` | QUIC versions to probe, e.g. `[1, 2]`. Default `[1]`. |

Category fields: `consent: {ru, en}` is a prompt the user must accept before an opt-in category runs. `media.yaml` uses it.

Other files use `kind:` instead of `targets:`. `dns.yaml` has `kind: resolvers` and `whitelist.yaml` has `kind: whitelist`. Their formats are documented in comments at the top of each file.

## Rules

- No circumvention endpoints: no proxies, VPN servers or "whitelisted SNI" lists.
- Use stable, public hostnames, and say in `note` why each endpoint was chosen.
- Every `expect` value must be backed by a source in `docs/research.md`.
