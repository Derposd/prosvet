# Results / Результаты

Anonymous measurements submitted by Prosvet users. GitHub Actions aggregates them into the
[public map](https://derposd.github.io/prosvet/) (`cmd/prosvet-map`, `.github/workflows/pages.yml`).

Анонимные измерения пользователей Prosvet. GitHub Actions собирает из них
[публичную карту](https://derposd.github.io/prosvet/).

## How to add yours / Как добавить свои

```bash
prosvet scan
prosvet submit          # shows the file and writes results/AS<asn>/<date>-<id>.json
```

Then either open a pull request with the new file, **or** paste its content into the
[“Submit results” issue form](https://github.com/Derposd/prosvet/issues/new?template=submit-results.yml) —
a bot validates it and opens the pull request for you.

Затем откройте pull request с новым файлом **или** вставьте его содержимое в
[форму «Отправить результаты»](https://github.com/Derposd/prosvet/issues/new?template=submit-results.yml) —
бот проверит файл и сам откроет pull request.

## Format / Формат

`prosvet.submission/v1`, one file per measurement, path `AS<asn>/<YYYY-MM-DD>-<6 hex>.json`:

```json
{
  "schema": "prosvet.submission/v1",
  "tool": { "name": "prosvet", "version": "0.1.0" },
  "date": "2026-10-11",
  "network": { "asn": 12389, "isp": "PJSC Rostelecom", "country": "RU", "region": "RU-MOW", "conn": "fixed" },
  "results": [
    { "target": "telegram", "category": "messengers", "status": "blocked", "kind": "ip_block", "subtype": "drop", "confidence": "high" },
    { "target": "cloudflare", "category": "infra", "status": "throttled", "kind": "throttle_freeze", "subtype": "16-20kb", "confidence": "high", "stall_kb": 16.5 }
  ]
}
```

What is **never** included: IP addresses, time of day, device or OS details, hostnames,
raw DNS answers, timings. The validator (`internal/submit`) rejects files with unknown fields
or anything that looks like an IP address, and CI only accepts *new* files under `results/`.

В файле **никогда** нет IP-адресов, точного времени, данных устройства и ОС, сырых ответов DNS
и таймингов. Валидатор отклоняет файлы с неизвестными полями и всем, что похоже на IP-адрес.

## License / Лицензия

The data in this directory is dedicated to the public domain under
[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/).
Данные в этом каталоге передаются в общественное достояние по лицензии CC0 1.0.
