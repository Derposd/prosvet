# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability
reporting: **Security → Report a vulnerability** on the repository page. You will get an answer
within 7 days. If the issue affects users' privacy (e.g. a way for a web page to trigger scans
through the local dashboard, or a way for a submission to leak an IP address), it is treated as
high priority.

Сообщения об уязвимостях — только приватно: вкладка **Security → Report a vulnerability**.

## Supported versions

Only the latest release receives fixes.

## Scope and design notes

- **Probes deliberately skip TLS verification** (`InsecureSkipVerify`) so that handshakes with
  censored or impersonated servers can be observed. Certificates are verified manually and the
  result is recorded as evidence. No user data is ever sent over these connections — only a fixed
  `GET /` with a `prosvet/<version>` User-Agent.
- **The local dashboard** binds to loopback only, checks the `Host` header (DNS rebinding),
  requires a per-process random token for state-changing requests (CSRF), sets a strict CSP and
  serves no third-party code.
- **Result submissions** are untrusted input. The validator (`internal/submit`) allows only known
  fields, bounded values and rejects anything that looks like an IP address. The issue-to-PR
  workflow handles the issue body only through an environment variable and runs the validator from
  `main`, never from the submission.
- **Releases** are built by GoReleaser in GitHub Actions; `checksums.txt` is published with every
  release.

## Out of scope

Prosvet does not provide anonymity or censorship circumvention, and makes no claims about protecting
you from your network operator: the operator can see which services you test.
