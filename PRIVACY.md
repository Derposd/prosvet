# Privacy / Приватность

Prosvet is built so that using it does not create new risks for you. This document lists exactly
what the program does with data. *Русская версия — ниже.*

## Summary

| | |
|---|---|
| Telemetry, analytics, crash reports, update checks | **none** |
| Accounts, cookies, identifiers | **none** |
| Data sent to the Prosvet authors | **none** — there is no Prosvet server |
| Your IP address | used in memory for an ASN/region lookup, **never stored or printed** |
| What leaves your computer | only the network measurements themselves and the lookups listed below |
| Publishing results | only if *you* run `prosvet submit` and *you* open a PR / issue |

## Network connections Prosvet makes

1. **The services under test** (from `targets/*.yaml`): DNS lookups, TCP/TLS handshakes, one HTTP GET
   (at most 64 KB, 256 KB for throttling files), QUIC handshakes. Your provider can see these
   connections, as with any website visit. The opt-in `media` category asks for confirmation first.
2. **DNS resolvers** (from `targets/dns.yaml`): the national DNS (NSDI), Cloudflare, Google, Quad9,
   AdGuard, Yandex — to compare answers.
3. **Network detection** (skip with `--offline-netinfo`):
   - an "echo" service returns your public IP: `yandex.ru/internet/api/v0/ip`, RIPEstat
     `whats-my-ip` or `cloudflare.com/cdn-cgi/trace` (first that works);
   - [RIPEstat](https://stat.ripe.net) (RIPE NCC) maps the IP to ASN, holder name and approximate
     location. The IP is held in memory only for these requests.
   - The location is reduced to a **federal subject** (e.g. `RU-TA`); city and coordinates are discarded.

Prosvet ignores `HTTP_PROXY`/`HTTPS_PROXY`: measurements always use the direct path.

## Data stored on your computer

- `<user cache dir>/prosvet/last-report.json` — the last report (contains the tested server addresses,
  verdicts, ASN, provider, region; **not** your IP). Delete it any time.
- `<user config dir>/prosvet/consent` — a timestamp that you accepted the first-run notice.
- Files you export explicitly (`report -o`, TUI export, `submit`).

## What `prosvet submit` shares

`prosvet submit` prints the file **before** writing it and asks for confirmation. It contains:
schema and tool version, the **date** (no time), ASN, provider name, country, region code,
connection type (mobile/fixed/unknown) and per-target verdicts (status, method, confidence,
for the 16–20 KB freeze the stall size in KB). It never contains IP addresses, device or OS data,
hostnames, raw DNS answers or timings. The validator rejects files that contain anything resembling
an IP address. Submitting is refused when a VPN seems active or the report is from `prosvet demo`.

Published result files are public and licensed CC0. An ASN plus region and date is coarse, but in a
small town with one provider it can narrow down who measured. Submit only if you are comfortable with that.

## The local dashboard

`prosvet serve` listens on 127.0.0.1 only, rejects requests with a foreign `Host` header, requires a
random per-run token for actions and sets a strict Content-Security-Policy. It loads no external
resources.

## The public map

The map is a static GitHub Pages site with no cookies, no analytics and no external resources.
GitHub may log visits to github.io as described in GitHub's privacy statement.

---

# Приватность (RU)

| | |
|---|---|
| Телеметрия, аналитика, отчёты об ошибках, проверка обновлений | **нет** |
| Аккаунты, cookies, идентификаторы | **нет** |
| Данные, отправляемые авторам Prosvet | **никакие** — сервера Prosvet не существует |
| Ваш IP-адрес | используется в памяти для определения ASN/региона, **нигде не сохраняется и не выводится** |
| Публикация результатов | только если *вы* запустите `prosvet submit` и *вы* откроете PR/issue |

**Какие подключения делает Prosvet:** к проверяемым сервисам (DNS, TCP/TLS, один HTTP-запрос до 64 КБ,
QUIC) — провайдер видит их, как и любое посещение сайта; к DNS-резолверам для сравнения ответов;
для определения сети (отключается `--offline-netinfo`) — к эхо-сервису (Яндекс, RIPEstat или Cloudflare)
и к RIPEstat за ASN и примерным местоположением, которое огрубляется до субъекта РФ.
Переменные `HTTP(S)_PROXY` игнорируются.

**Что хранится на компьютере:** последний отчёт (`<кэш>/prosvet/last-report.json`, без вашего IP),
отметка о согласии и файлы, которые вы экспортировали сами.

**Что публикует `prosvet submit`:** дату (без времени), ASN, провайдера, страну, код региона, тип
подключения и вердикты по сервисам. Никаких IP, данных устройства, сырых ответов DNS и таймингов.
Перед записью файл показывается целиком. Файл с чем-то похожим на IP-адрес не пройдёт проверку.
Отправка отклоняется, если включён VPN или отчёт получен в `prosvet demo`.
Опубликованные данные открыты (CC0); сочетание ASN, региона и даты грубое, но в маленьком городе
с одним провайдером может сузить круг. Отправляйте, только если вас это устраивает.
