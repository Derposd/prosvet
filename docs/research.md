# Prosvet — исследование: блокировки и замедления интернета в России

> Состояние на **10 октября 2026**. Самые свежие публикации, которые удалось найти, датированы концом сентября 2026.
> Документ живой: правки и новые источники принимаются через PR (см. `CONTRIBUTING.md`).

## TL;DR (English)

- **Russia's filtering is decentralized in hardware but centrally controlled.** TSPU DPI boxes sit inline at every ISP and are run by Roskomnadzor [S9, S20]. Blocking methods therefore differ by ISP and change from week to week. Any single measurement is noisy, so repeated, multi-signal tests are mandatory.
- **2026 brought a step change.** WhatsApp and YouTube were removed from the National DNS (NSDI) in February 2026. Telegram was throttled from February and ~95% blocked by April. VPN protocols are now blocked by behavioural fingerprinting. DoH/DoT to Google/Cloudflare started failing in August 2026, and plain UDP/53 to 1.1.1.1/8.8.8.8 is reportedly DNAT'ed to the NSDI resolver [S6, S10, S4, S27, S30].
- **The "16 KB curtain" is the signature throttling method.** Since June 2025, TLS/QUIC flows to foreign hosting and CDN ranges (Cloudflare, Hetzner, DigitalOcean, OVH, …) freeze silently after ~16–20 KB. No RST is sent, and SNI/CIDR allowlists exempt some flows [S15, S16, S17].
- **Mobile "whitelists" are a new censorship regime.** During mobile shutdowns only 500+ approved domestic services work. This was active in 60–70+ regions in 2026 [S38–S41, S46].
- **The gap Prosvet fills.** OONI is the gold standard, but its web test does not detect the 16 KB freeze, the whitelist regime, DNS interception or SNI-vs-IP disambiguation in one flow, and OONI Explorer itself is blocked in Russia [S58, S61]. Community DPI checkers exist [S18, S19], but they target technical users and circumvention operators. They have no plain-language verdicts, no reports and no public ASN×service map. Prosvet is **measurement-only** and has no circumvention code.

---

## Содержание

1. [Как делался ресёрч и насколько ему верить](#1-как-делался-ресёрч-и-насколько-ему-верить)
2. [Ключевые выводы](#2-ключевые-выводы)
3. [Хронология 2024–2026](#3-хронология-20242026)
4. [Статус сервисов](#4-статус-сервисов-на-октябрь-2026)
5. [Методы блокировки и как их распознать](#5-методы-блокировки-и-как-их-распознать)
6. [Существующие инструменты и пробелы](#6-существующие-инструменты-и-пробелы)
7. [Методология Prosvet (вывод из ресёрча)](#7-методология-prosvet-вывод-из-ресёрча)
8. [Границы проекта: чего мы не делаем](#8-границы-проекта-чего-мы-не-делаем)
9. [Риски для пользователей и этика измерений](#9-риски-для-пользователей-и-этика-измерений)
10. [Цели проверки](#10-цели-проверки)
11. [Открытые вопросы](#11-открытые-вопросы)
12. [Источники](#12-источники)

---

## 1. Как делался ресёрч и насколько ему верить

- Источники делятся на три класса. В таблицах класс помечен так:
  - **A**: рецензируемые работы и официальные данные (IMC, FOCI, спецификации OONI, блог Cloudflare);
  - **B**: профильные СМИ с собственной проверкой (Медиазона, Meduza, The Moscow Times, Вёрстка, Risky Business, The Record);
  - **C**: вторичные агрегаторы, форумы и блоги VPN-вендоров. Используются только как сигнал, у вендоров есть коммерческий интерес.
- Если источники расходятся (даты, полнота блокировки), это указано явно.
- Ни одно утверждение здесь не заменяет измерение. Prosvet нужен как раз затем, чтобы проверять эти утверждения на конкретной сети.
- Конечные точки для замеров скорости проверены на существование HTTP-запросами 10.10.2026, но не из российской сети. Hetzner и DigitalOcean из среды сборки не ответили. В `targets/infra.yaml` они помечены `verified: false`.

## 2. Ключевые выводы

1. **ТСПУ — главный инструмент.** DPI-оборудование стоит у каждого оператора, им управляет РКН [S9]. Оно in-path и stateful, умеет блокировать по SNI, IP и QUIC [S20]. Около 70% из более чем миллиона обследованных адресов находились не дальше двух хопов от ТСПУ [S20].
2. **Реализация неоднородна.** Каждый провайдер внедряет блокировки по-своему [S22]. Мощности ТСПУ иногда не хватает, и заблокированное «просвечивает» [S9]. Отсюда требование измерять повторно и голосовать по большинству.
3. **DNS стал инструментом блокировки федерального уровня.** Записи удаляют из НСДИ, и резолверы провайдеров отдают NXDOMAIN. Так в феврале 2026 исчезли YouTube, WhatsApp, Facebook и ряд СМИ [S9, S11, S32].
4. **Шифрованный DNS под ударом.** С 26.08.2026 у части операторов DoT (1.1.1.1:853) и DoH (dns.google) сбрасываются после ClientHello [S27–S29]. Есть сообщение (один источник), что открытый UDP/53 к 1.1.1.1 и 8.8.8.8 перехватывается и подменяется ответами НСДИ (DNAT на 195.208.5.1) [S30].
5. **«Занавес 16 КБ».** С 9 июня 2025 соединения к Cloudflare, а также к Hetzner, DigitalOcean, OVH и другим зарубежным хостингам замирают после ~16 КБ (~25 пакетов). RST не приходит, клиент ждёт таймаута. Затронуты HTTP/1.1, HTTP/2 и HTTP/3 [S15–S17].
6. **QUIC фильтруется по SNI.** У QUIC v1 разбирается Initial-пакет, поток с запрещённым SNI отбрасывается и «чёрная дыра» держится 420 секунд с продлением. QUIC v2 на момент исследования проходил [S23].
7. **Мессенджеры.** Signal, Viber и Discord заблокированы в 2024 году. В 2025 добавились Snapchat и FaceTime, в феврале 2026 WhatsApp. Telegram замедляют с февраля 2026 и почти полностью блокируют с апреля [S1–S8, S49, S51].
8. **Белые списки на мобильном интернете.** Действует режим «запрещено всё, кроме разрешённого». В списке больше 500 отечественных сервисов, у операторов могут быть свои расширения. По разным оценкам, в марте 2026 режим работал в 68–71 регионе [S38–S41].
9. **VPN-протоколы распознают по поведению.** Ловят размеры пакетов, тайминги и рукопожатия, а не только адреса. Волны блокировок прошли 4 августа, 7–8 сентября и 22–25 сентября 2026 [S34–S36, S72, S73].
10. **Появился государственный корневой сертификат.** В августе 2026 семь крупных банков перешли на сертификаты НУЦ Минцифры [S56, S57]. Для измерителя это означает: «сертификат не проверяется» на `.ru`-домене ещё не признак MITM. А тот же корень на зарубежном домене — сильный признак перехвата.

## 3. Хронология 2024–2026

| Дата | Событие | Класс | Источник |
|---|---|---|---|
| 2016-11 | LinkedIn заблокирован | A/B | [S77] |
| 2021-03-10 | Замедление Twitter по SNI до 130–150 кбит/с (первое массовое замедление) | A | [S21] |
| 2022-03-04 | Twitter: замедление сменилось блокировкой (RST после ClientHello); заблокирован Facebook | A | [S22] |
| 2022-03-14 | Instagram заблокирован | A/B | [S22] |
| 2022-03 | Начало блокировки HTTP/3 (QUIC) | A/C | [S24] |
| 2022-05 … 2023-07 | ТСПУ массово переходят на SNI-фильтрацию QUIC | A | [S23] |
| 2024-07-11 | Начало замедления YouTube (сначала Ростелеком и Tele2) | B | [S13] |
| 2024-08 | Signal заблокирован | B/C | [S52, S78] |
| 2024-09 | Заблокирован OONI Explorer | A | [S61] |
| 2024-10-08 | Discord заблокирован | B | [S51] |
| 2024-11-06 | Блокировка сайтов Cloudflare с ECH (внешний SNI `cloudflare-ech.com` + расширение ECH) | B | [S25, S26, S76] |
| 2024-12 | Viber заблокирован | B/C | [S52, S78] |
| 2025-05 | Первые региональные отключения мобильного интернета (40+ регионов перед 9 мая) | B | [S43] |
| 2025-06-09 | «Занавес 16 КБ» для Cloudflare и зарубежных хостингов | A | [S15, S16] |
| 2025-06…08 | Взрывной рост шатдаунов: 655 (июнь) → 2099 (июль/август) | B | [S44, S45] |
| 2025-08 | Ограничены звонки в WhatsApp и Telegram | B | [S9] |
| 2025-09-05 | Первая редакция «белого списка» Минцифры | B | [S38, S39] |
| 2025-10 | Telegram и WhatsApp ограничены в 34 регионах; запрет регистрации новых пользователей; Snapchat заблокирован (объявлено 04.12) | B | [S8, S49] |
| 2025-11 (конец) | Общенациональное замедление WhatsApp | B | [S9] |
| 2025-12-03/04 | Заблокированы Roblox и Snapchat, ограничен FaceTime | B | [S49, S67, S68] |
| 2026-01 | Ограничен доступ к 439 VPN-сервисам (469 на 26.02) | B/C | [S37] |
| 2026-02-10 | Ужесточение ограничений Telegram; youtube.com исчез из DNS, подконтрольного РКН | B | [S2, S11] |
| 2026-02-11/12 | WhatsApp удалён из НСДИ; YouTube «полностью заблокирован» (по Wikipedia) | B | [S6, S7, S10] |
| 2026-02 | Деградация Steam, Xbox, Epic, Origin и PlayStation (доступность −5…−11%) | B | [S53] |
| 2026-03-06 | Шатдаун мобильного интернета в центре Москвы (~3 недели) | B | [S47, S48] |
| 2026-03-12 | Белые списки активированы в 68–71 регионе | B/C | [S38] |
| 2026-03-23 | Заблокирован archive.today | B | [S66] |
| 2026-03…04 | Telegram: ~80% блокировки в середине марта, ~95% в апреле | B/C | [S4, S5] |
| 2026-04-23 | Крупное расширение белого списка; позже он превысил 500 сервисов | B/C | [S41] |
| 2026-06-10 | Roblox разблокирован (чат по-прежнему ограничен) | B | [S50] |
| 2026-07 | Шатдауны регулярно в 60+ регионах; в Центральной России без ограничений прошло 30,5% мобильных сессий | B/C | [S40, S46] |
| 2026-07-08 | Сбои Battle.net (ошибка 30008) | C | [S54] |
| 2026-07-27 | РКН угрожает замедлить сервисы Google | B | [S55] |
| 2026-08-03 | Сайты семи банков перешли на сертификаты НУЦ Минцифры | B | [S56, S57] |
| 2026-08-04 | Массовая волна блокировок VPN, затронуты подсети хостеров | C | [S35, S73] |
| 2026-08-26 | DoH/DoT к Google/Cloudflare сбрасываются (Ростелеком, Дом.ру, Таттелеком, SkyNet) | B | [S27–S29] |
| 2026-08-28 | Сообщение о DNAT открытого DNS (1.1.1.1/8.8.8.8 → НСДИ) | C | [S30] |
| 2026-09-22…29 | Волна блокировок VPN после выборов в Госдуму | B | [S34] |

## 4. Статус сервисов на октябрь 2026

Легенда статуса: **blocked**: заблокирован; **throttled**: замедлен; **partial**: частично или у части провайдеров; **ok**: работает; **unknown**: данных нет.
Колонка «Наблюдаемый метод» показывает, что видели исследователи. Prosvet перепроверяет это на сети пользователя.

| Сервис | Статус | С | Наблюдаемый метод | Уверенность | Источники |
|---|---|---|---|---|---|
| Telegram | blocked (≈95%) | 2026-02-10 | DPI по протоколу и SNI; звонки с 2025-08 | высокая | S1–S5 |
| WhatsApp | blocked | 2026-02-12 | удаление из НСДИ (NXDOMAIN) + DPI; звонки с 2025-08 | высокая | S6–S9 |
| YouTube | blocked/throttled | 2024-07 / 2026-02-10 | замедление (GGC, SNI), затем удаление из НСДИ; аномалии 52–54% соединений в мар–мае 2026 | высокая (факт), средняя (полнота) | S10–S14 |
| Instagram | blocked | 2022-03-14 | SNI/IP | высокая | S22 |
| Facebook | blocked | 2022-03-04 | SNI/IP; удаление из НСДИ 2026-02 | высокая | S9, S22 |
| X / Twitter | blocked | 2022-03-04 | RST после ClientHello (ранее замедление по SNI) | высокая | S21, S22 |
| LinkedIn | blocked | 2016-11 | реестр | высокая | S77 |
| Discord | blocked | 2024-10-08 | реестр, DPI | высокая | S51, S71 |
| Signal | blocked | 2024-08 | реестр, DPI | высокая | S52, S78 |
| Viber | blocked | 2024-12 | реестр | высокая | S52, S78 |
| Snapchat | blocked | 2025-10 | «централизованное управление сетью» (ТСПУ) | высокая | S49, S75 |
| FaceTime | blocked | 2025-12-04 | на уровне сети, метод не описан | средняя | S67, S68 |
| Roblox | ok (чат ограничен) | 2026-06-10 разблок. | — | высокая | S50 |
| Google (поиск, Gmail, Play) | partial/unknown | — | подтверждённой блокировки нет; угроза замедления (07.2026); DoH dns.google сбрасывается | средняя | S27, S55 |
| Steam / Xbox / Epic / EA / PSN | partial | 2026-02 | падение доступности на 5–11%, фильтрация ТСПУ предполагается | средняя | S53 |
| Battle.net | partial | 2026-07-08 | ошибка 30008, причина не подтверждена | низкая | S54 |
| Cloudflare и зарубежные хостинги | throttled | 2025-06-09 | заморозка после ~16 КБ; ECH-блок с 2024-11; блоки подсетей в волнах 08–09.2026 | высокая | S15–S17, S25, S35 |
| QUIC / HTTP3 | partial/blocked | 2022 | SNI-фильтрация QUIC v1, «чёрная дыра» на 420 с | высокая | S23, S24 |
| DoH/DoT (Google, Cloudflare) | partial | 2026-08-26 | RST после ClientHello (SNI `dns.google`, порт 853) | средняя | S27–S29, S31 |
| Открытый DNS UDP/53 к 1.1.1.1/8.8.8.8 | partial | 2026-08-26 | DNAT на НСДИ (195.208.5.1) | низкая (1 источник) | S30 |
| VPN: OpenVPN, IKEv2, L2TP, WireGuard (без обфускации) | blocked | 2025–2026 | поведенческие сигнатуры ТСПУ + блок подсетей | средняя (вендоры) | S34–S37 |
| archive.today | blocked | 2026-03-23 | реестр | высокая | S66 |
| OONI Explorer | blocked | 2024-09 | реестр | высокая | S61 |
| Max, Госуслуги, Яндекс, VK | ok (белый список) | — | — | высокая | S38–S41 |

## 5. Методы блокировки и как их распознать

Для каждого метода указаны механизм, сигнатура в измерениях и способ отличить его от похожих.

### 5.1 DNS

| Вариант | Механизм | Сигнатура | Чем отличить |
|---|---|---|---|
| Удаление из НСДИ | Операторы обязаны брать данные из НСДИ; запись удалена | Системный резолвер: **NXDOMAIN**/пусто; DoH к зарубежному резолверу: нормальные IP | Подключение к IP из DoH с реальным SNI даёт валидный сертификат, значит, на уровне IP домен жив [S9, S11, S32] |
| Подмена на заглушку | Резолвер провайдера отдаёт IP страницы-заглушки | Системный ответ ≠ DoH; IP из известного списка заглушек (Ростелеком 95.167.13.50/51, ЭР-Телеком 5.3.3.17 и др.) | TLS к подменённому IP с реальным SNI не проходит валидацию; совпадение с отпечатком [S62] |
| Перехват UDP/53 (DNAT) | ТСПУ перенаправляют запросы к 1.1.1.1/8.8.8.8 на НСДИ | Ответ «от 1.1.1.1» совпадает с НСДИ (NXDOMAIN на youtube.com); `whoami.cloudflare CH TXT` даёт пусто или неверный формат; `o-o.myaddr.l.google.com TXT` не возвращает адрес из сети Google | Сравнить UDP/53 с DoH к тому же провайдеру [S30] |
| Блок DoH/DoT | RST после ClientHello по SNI (`dns.google`) или по порту 853 | TCP ок → TLS RST; тот же IP с другим SNI проходит | Тест SNI-переключения (см. 5.3) [S27–S29, S31] |

> Публичные резолверы НСДИ: `195.208.4.1`, `195.208.5.1` [S33]. Prosvet использует их как **эталон «официального» ответа** и сравнивает с ним системный резолвер и DoH. Так видно, чем вызвано NXDOMAIN: федеральным удалением или самодеятельностью провайдера.

### 5.2 Блокировка по IP

- Механизм: блэкхол (drop) или отказ (RST/ICMP) на адреса или целые подсети. В августе–сентябре 2026 блокировали подсети крупных хостеров целиком [S35, S73].
- Сигнатура: TCP-коннект к **всем** IP цели (взятым из DoH) заканчивается таймаутом или RST, при этом контрольные хосты на том же порту доступны.
- Отличие от DPI: в DPI-случае TCP-рукопожатие проходит, ломается TLS.

### 5.3 DPI по SNI (TLS)

- Механизм: ТСПУ читает SNI в ClientHello. Реакция: инжекция RST (наиболее частая), молчаливый drop или замораживание [S20, S22].
- Сигнатура: TCP ок; TLS с реальным SNI → RST, EOF или таймаут; к **тому же IP** TLS **без SNI** или со **случайным SNI** → ServerHello (ошибка имени в сертификате ожидаема и допустима).
- Это главный дифференциальный тест Prosvet. Он однозначно разделяет «блок по IP» и «блок по SNI». Аналог есть в экспериментальном `sniblocking` OONI [S60], но в веб-тест OONI он не встроен.

### 5.4 TLS reset и ECH

- **TLS reset**: RST на рукопожатии **независимо от SNI**. Это блок по IP:порту или по протокольной сигнатуре.
- **ECH**: с 06.11.2024 блокируется ClientHello, у которого одновременно внешний SNI `cloudflare-ech.com` и расширение ECH. Если выполнено только одно из двух условий, соединение проходит [S25, S26]. Go 1.23+ поддерживает ECH на клиенте, так что тест реализуем без сторонних библиотек.

### 5.5 Замедление

Нужно различать два принципиально разных механизма.

| Тип | Механизм | Сигнатура | Источник |
|---|---|---|---|
| **Ограничение скорости** | Отбрасывание пакетов сверх порога для потоков с определённым SNI (Twitter 2021: 130–150 кбит/с; YouTube 2024: трафик ~20–30% от базы) | Загрузка идёт, но скорость намного ниже, чем у отечественного эталона на той же сети | S13, S14, S21 |
| **«TCP 16–20» (заморозка)** | После ~16–20 КБ от сервера к клиенту (≈25 пакетов) пакеты перестают приходить; RST нет; цель — зарубежные хостинги и CDN; исключения по SNI- и CIDR-белым спискам; порог зависит от провайдера; затронуты TLS 1.2/1.3 и QUIC | TLS ок, HTTP начал отдавать тело, приём **замирает** в окне 14–34 КБ, соединение висит до таймаута; повторяется на нескольких хостах одного хостера | S15–S17, S19, S69 |

Важно:
- Cloudflare называет среди операторов и **фиксированные** сети (Ростелеком, МГТС), так что «16–20» не только мобильная история [S15].
- Для детекта нужен ресурс заметно больше 34 КБ: главная telegram.org весит ~20 КБ и для этого теста не годится. Поэтому у целей задаётся `throttle_url` с заведомо большим файлом.
- Эталон скорости берётся с отечественного зеркала (`mirror.yandex.ru`, `mirror.selectel.ru`). Иначе «медленный канал» не отличить от «замедления».

### 5.6 QUIC / HTTP/3

- С 2022 года QUIC блокируется у ряда крупных провайдеров. С 2023 фильтрация в основном по SNI из Initial-пакета QUIC v1 [S23, S24].
- После срабатывания поток отбрасывается **420 секунд**, и каждый новый пакет продлевает таймер [S23]. Следствия для методики:
  1. QUIC-тесты идут **после** TCP-тестов;
  2. каждая попытка уходит с нового UDP-порта;
  3. проба со случайным SNI делается **до** пробы с реальным SNI к тому же адресу.
- QUIC v2 (RFC 9369) на момент исследования проходил [S23]. Prosvet фиксирует версию как параметр измерения, и это значимый для классификации признак.

### 5.7 VPN-протоколы

- ТСПУ оценивает поведенческие признаки: размеры пакетов, тайминги, рукопожатия, keepalive. После превышения порога блокируется IP сервера [S36].
- OpenVPN, IKEv2, L2TP и «голый» WireGuard массово не работают, блокируются и подсети хостеров [S34–S37].
- **Prosvet это не тестирует** (см. раздел 8): нет нейтральных эндпоинтов, а сам тест неизбежно превращается в подбор работающих конфигураций. Информация оставлена для контекста.

### 5.8 Белые списки (мобильный интернет)

- Режим «запрещено всё, кроме разрешённого». Операторы пропускают трафик только к IP и доменам из перечня [S38]. Минцифры отрицает применение к проводному интернету (23.03.2026) [S38].
- Перечня одним файлом нет: Минцифры публикует его частями [S41]. В нём больше 500 сервисов, и все их вычислительные ресурсы обязаны находиться в РФ [S41]. МТС, Билайн, МегаФон и Tele2 ведут свои расширенные списки [S41].
- Признаки режима: отечественные сервисы открываются, зарубежные контрольные хосты разных ASN недоступны **все сразу**, независимо от категории. Иногда разрешённые ресурсы требуют CAPTCHA [S38].
- Белый список отличается от полного шатдауна тем, что при шатдауне не работает и отечественное.

### 5.9 Шатдауны

- 11 903 отключения с мая по декабрь 2025 [S45]. В июле 2026 шатдауны регулярно шли в 60+ регионах [S46]. Отключения обычно частичные: в одном районе города есть связь, в другом нет [S45].
- С февраля 2026 операторы обязаны отключать связь по требованию ФСБ [S9, S38].
- Для Prosvet это отдельный вердикт «нет связности» (не работает ничего, включая отечественное), а не блокировка конкретного сервиса.

### 5.10 Перехват TLS и государственный корень

- НУЦ Минцифры (Russian Trusted Root CA) не входит в хранилища доверия браузеров и ОС. У корня нет ограничений по именам [S56, S57].
- Правило классификатора:
  - сертификат зарубежного домена, выпущенный этим корнем или любым неизвестным УЦ, означает **перехват TLS (MITM)** с высокой уверенностью;
  - сертификат этого корня на `.ru/.su/.рф` фиксируется как «отечественный УЦ», без признака блокировки.

### 5.11 Страницы-заглушки (HTTP)

- На порту 80 провайдеры отвечают редиректом на заглушку (`warning.rt.ru`, `blocked.mgts.ru`, `t2blocked.com`, `fz139.ttk.ru` и десятки других). Тело заглушки часто содержит «Доступ к сайту ограничен…» [S62].
- В базе OONI `blocking-fingerprints` 192 HTTP- и 27 DNS-отпечатков для RU, **но у репозитория нет лицензии**. Копировать её в MIT-проект нельзя. Prosvet ведёт собственный файл отпечатков: факты (домены, IP), найденные независимо, со ссылкой на OONI как на источник идеи. Параллельно стоит запросить у OONI разрешение.

### 5.12 Мешающие факторы при измерении

- **VPN и прокси у пользователя.** Результат отражает выходной узел, а не провайдера. В среде сборки этого отчёта весь трафик шёл через локальный прокси (`remote_ip=127.0.0.1`). Prosvet обязан **игнорировать `HTTP(S)_PROXY`** и предупреждать, если маршрут по умолчанию идёт через `tun/wg/utun/ppp`.
- **Средства противодействия DPI на машине** (локальные «десинхронизаторы»). Они искажают результат [S19], поэтому Prosvet предупреждает о такой возможности.
- **Перегрузка ТСПУ.** Блокировка иногда «просвечивает» [S9], поэтому нужны три повтора и итог по большинству.

## 6. Существующие инструменты и пробелы

| Инструмент | Что умеет | Чего не хватает для задачи |
|---|---|---|
| **OONI Probe** [S58–S60] | Эталонная методология: Web Connectivity (DNS/TCP/TLS/HTTP со сравнением с test helper), отдельные тесты Telegram, WhatsApp, Signal, Facebook Messenger, экспериментальные `sniblocking`, `echcheck`, `quicping`, `tlsmiddlebox` | Нет детекта «16–20» и режима белых списков; вердикты сводятся к `dns / tcp_ip / http-failure / http-diff` без разделения SNI и IP в одном прогоне; нужен доступ к бэкенду OONI; OONI Explorer заблокирован в РФ [S61] |
| **hyperion-cs/dpi-checkers** [S18] | Go-CLI DPI-CH, браузерный чекер TCP 16–20, поиск белых подсетей, поиск белых доменов | Ориентирован на технических пользователей и операторов средств доступа; нет понятных вердиктов, отчётов и агрегированной карты |
| **Runnin4ik/dpi-detector** [S19] | Python: DNS-подмена, перехват UDP/53, блок DoH/DoT, TCP 16–20, классификация ошибок | Ориентирован на подбор «белых» SNI; нет HTML/JSON-отчётов, публичной карты, режима белых списков, сборок под роутер |
| **Censored Planet, IODA, Cloudflare Radar** | Удалённые измерения и метрики связности на уровне страны и ASN | Не видят «последнюю милю» конкретного пользователя и мобильные белые списки |
| **«На связи»** [S44] | Учёт шатдаунов по жалобам и официальным сообщениям | Это не инструмент измерения |

**Что Prosvet добавляет, не дублируя OONI:**

1. Один статический бинарник с понятными вердиктами на RU/EN для нетехнических пользователей.
2. Дифференциальный TLS-тест (реальный SNI / без SNI / случайный SNI) для каждой цели, в одном потоке с DNS, TCP, HTTP и QUIC.
3. Детект заморозки «16–20» и ограничения скорости относительно отечественного эталона.
4. Вердикт «режим белых списков» против «шатдауна» против «нормальной сети».
5. Обнаружение перехвата DNS (DNAT на НСДИ) и сравнение «системный / НСДИ / DoH».
6. Обнаружение MITM по цепочке сертификата.
7. Работу без сервера: публичная карта ASN×сервис собирается из PR и Issue в git, данные версионируются и проверяемы.
8. Сборки под OpenWrt, чтобы измерять с роутера.

**Чего не делаем, чтобы не дублировать:** собственный глобальный список тестов (в будущем можно импортировать `citizenlab/test-lists`) и собственный бэкенд сравнения (control). Вместо test helper используются DoH, НСДИ и валидация сертификата.

## 7. Методология Prosvet (вывод из ресёрча)

### 7.1 Шаги для одной цели

Каждый шаг выполняется **3 раза** на новых соединениях, итог определяется по большинству. Таймауты по умолчанию указаны в скобках.

1. **DNS:**
   - системный резолвер;
   - НСДИ (UDP);
   - DoH к двум-трём провайдерам с откатом: Cloudflare → Quad9 → AdGuard → Google (часть может быть заблокирована, это само по себе результат);
   - сравнение: NXDOMAIN, известная заглушка, bogon, расхождение множеств IP. Консистентность проверяется валидацией TLS к IP, без базы ASN. (3 с)
2. **TCP:** connect к IP из системного DNS и к IP из DoH; итог: ok / timeout / RST / unreachable. (5 с)
3. **TLS ×3 варианта:** реальный SNI, без SNI, случайный SNI `<rand>.invalid`. Для каждого: ok, RST, EOF или таймаут, версия TLS, цепочка и издатель сертификата. (6 с)
4. **HTTP:**
   - GET по TLS с чтением до 256 КБ;
   - фиксируются статус, байты, время до первого байта и паузы приёма;
   - опционально plain HTTP на :80 со сверкой с отпечатками заглушек. (8 с до первого байта, 6 с паузы)
5. **Замедление:**
   - загрузка `throttle_url` до 256 КБ;
   - признак заморозки: приём встал в окне 14–34 КБ дольше 6 с без RST, при `Content-Length` больше полученного;
   - признак ограничения скорости: меньше 25% от отечественного эталона и меньше 1 Мбит/с.
6. **QUIC (в конце):** QUIC v1 Initial со случайным SNI, затем с реальным; каждая проба с нового порта; опционально QUIC v2.

### 7.2 Классификатор (порядок правил)

| # | Условие (по большинству из 3 повторов) | Вердикт | Уверенность |
|---|---|---|---|
| 0 | Обнаружен VPN или прокси на маршруте по умолчанию | предупреждение, вердикты помечаются «через VPN» | — |
| 1 | Не работают и отечественные, и зарубежные контрольные хосты | `no_connectivity` (шатдаун или авария) | высокая |
| 2 | Системный DNS: NXDOMAIN, заглушка или bogon, а DoH даёт IP с валидным TLS | `dns` (подмена или удаление; подтип `nsdi_removed`, если НСДИ тоже NXDOMAIN) | высокая |
| 3 | TCP к **всем** IP: таймаут или RST; контрольные хосты доступны | `ip_block` (подтип drop/reject) | высокая при ≥2 IP |
| 4 | TCP ок; TLS с реальным SNI падает; без SNI или со случайным SNI проходит | `sni_dpi` (подтип reset/drop) | высокая |
| 5 | TCP ок; TLS падает с RST во всех трёх вариантах | `tls_reset` | средняя |
| 6 | TLS ок, но сертификат от неизвестного УЦ или от НУЦ на не-`.ru` домене | `tls_mitm` | высокая |
| 7 | HTTP :80 совпал с отпечатком заглушки | `blockpage` | высокая |
| 8 | Заморозка в окне 14–34 КБ (≥2 из 3) | `throttle_freeze` («16–20») | высокая |
| 9 | Скорость меньше 25% эталона и меньше 1 Мбит/с | `throttle_rate` | средняя |
| 10 | Всё обрывается по таймауту без устойчивой сигнатуры | `timeout` (сервер или сеть) | низкая |
| 11 | Всё ок | `ok` | высокая |
| Q | QUIC: реальный SNI без ответа, случайный с ответом | `quic_sni` | высокая |
| Q | QUIC: нет ответа ни на что, при этом TCP и TLS ок | `quic_blocked` (UDP целиком) | средняя |

- Уверенность понижается на ступень при 2/3 вместо 3/3 и при одной конечной точке на цель.
- Уверенность повышается, если одна сигнатура повторилась на нескольких хостах цели.
- Поле `expect` из `targets/*.yaml` (априорный статус по открытым источникам) **не участвует в классификации**. Оно только показывается рядом с результатом, чтобы не подтверждать ожидания.

### 7.3 Режим белых списков

- **D**: 15–20 отечественных сервисов из перечня Минцифры, минимум 6 разных компаний и ASN.
- **F**: 12 зарубежных контрольных хостов, которые обычно **не заблокированы**: Google, Wikimedia, GitHub, Microsoft, Apple, Amazon, Mozilla, Python (Fastly), IETF, Debian, Cloudflare. Учитывается только TLS-рукопожатие и первые байты, поэтому заморозка «16–20» на результат не влияет.
- Вычисляются `rD` и `rF`, доли успешных проверок в каждой группе:

| Условие | Вердикт |
|---|---|
| `rD ≥ 0.7` и `rF ≤ 0.15` | **белый список активен**; уверенность высокая при `rF = 0` |
| `rD < 0.3` и `rF < 0.3` | **нет связности** |
| `rD ≥ 0.7` и `rF ≥ 0.7` | **обычная сеть** |
| иначе | **деградация** с объяснением |

- Уточнение: на каком уровне падают зарубежные хосты: TCP (белый список по IP), TLS (по SNI) или DNS.
- Сертификаты НУЦ у отечественных сервисов (банки) считаются нормой.

### 7.4 Определение сети

- **Публичный IP** берётся только в памяти: отечественный эхо-сервис (`yandex.ru/internet/api/v0/ip`), затем зарубежный (`www.cloudflare.com/cdn-cgi/trace`).
- **ASN и оператор**: RIPEstat Data API (`network-info`, `as-overview`), запасной вариант — офлайн-таблица (iptoasn, PDDL) или ручной `--asn`.
- **Регион**: грубая геолокация (GeoLite через RIPEstat) до субъекта РФ. Город и координаты не сохраняются.
- **Тип подключения**: эвристика по ASN (мобильные AS операторов), типу интерфейса ОС (WWAN, rmnet, wwan0) и CGNAT-адресу (100.64/10); `--conn mobile|fixed` переопределяет.
- **IP нигде не сохраняется и не выводится**, хранятся только ASN, оператор, регион и тип подключения (см. `PRIVACY.md`).

### 7.5 Нагрузка и деликатность

- Полный прогон по умолчанию укладывается в ~600 коротких соединений, чтение ограничено 256 КБ на запрос.
- Параллелизм 8–16 потоков, пауза между повторами со случайным разбросом.
- User-Agent честный: `prosvet/<версия>`.

## 8. Границы проекта: чего мы не делаем

- **В проекте нет кода прокси, туннелей, VPN, десинхронизации DPI, фрагментации ClientHello и подбора «разрешённых» SNI или подсетей.** Prosvet только измеряет и объясняет.
- **VPN-протоколы не тестируются** (см. 5.7).
- Справка по вердиктам ссылается только на нейтральную публичную документацию: описания методов в OONI, RFC, Wikipedia, исследования IMC/FOCI.
- Правовой контекст:
  - с 01.03.2024 запрещена реклама средств доступа к заблокированным ресурсам [S64];
  - с 01.09.2025 действуют штрафы за умышленный поиск «экстремистских материалов», в том числе через VPN, и повышенные штрафы за рекламу VPN [S63].

  Поэтому формулировки проекта: «network diagnostics & censorship measurement», «диагностика сети и измерение цензуры».

## 9. Риски для пользователей и этика измерений

- Модель информированного согласия по образцу OONI. При первом запуске показывается короткое предупреждение: провайдер может видеть, что вы проверяете доступность сервисов.
- Категория `media` (независимые СМИ, справочные ресурсы) **выключена по умолчанию** и включается только явно (`--category media`).
- Отправка результатов только по явной команде `prosvet submit`, которая готовит файл без IP. Публикует его сам пользователь, через PR или Issue.
- В отчёте нет локальных адресов, имён хоста, MAC, SSID и сырых DNS-ответов системного резолвера (в них могут оказаться внутренние имена).

## 10. Цели проверки

Списки лежат в `targets/*.yaml` и редактируются без пересборки, схема описана в [`targets/README.md`](../targets/README.md).

| Файл | Что внутри | По умолчанию |
|---|---|---|
| `messengers.yaml` | Telegram (вкл. адреса DC), WhatsApp, Signal, Viber, Discord, Snapchat, Max (контроль) | да |
| `social.yaml` | Instagram, Facebook, X, LinkedIn, Threads, TikTok, Reddit | да |
| `video.yaml` | YouTube (вкл. googlevideo), Twitch, Vimeo | да |
| `google.yaml` | Поиск, Gmail, Play, API/шрифты, Диск, FCM push (5228) | да |
| `gaming.yaml` | Steam, Epic, Battle.net, Xbox, PlayStation, EA, Roblox (регрессионный контроль), Riot | да |
| `infra.yaml` | CDN и хостинги для «16–20»: Cloudflare, Hetzner, DigitalOcean, OVH, Vultr, Akamai/Linode, AWS, Fastly, Google, GitHub; отечественные эталоны скорости | да |
| `protocols.yaml` | QUIC (Cloudflare, Google, YouTube, Яндекс как контроль), ECH | да |
| `dns.yaml` | Резолверы (система, НСДИ, Google, Cloudflare, Quad9, AdGuard, Яндекс) и пробы перехвата | да |
| `whitelist.yaml` | Наборы D (отечественные) и F (зарубежный контроль) для `prosvet whitelist` | для `whitelist` |
| `media.yaml` | Независимые СМИ и справочные ресурсы | **нет (opt-in)** |

## 11. Открытые вопросы

1. Байтовый или пакетный порог у «16–20» и одинаков ли он у мобильных и фиксированных операторов. Ответ дадут сырые данные `bytes_before_stall` и `packets_before_stall` из `results/`.
2. Насколько распространён DNAT открытого UDP/53 на НСДИ (подтверждён одним источником) [S30].
3. Как устроен белый список на уровне сети (IP или SNI) у разных операторов, по данным с реальных SIM-карт.
4. Метод блокировки FaceTime: сигнальные хосты Apple или медиапоток. Пока не тестируется, нужны предложения в Issues.
5. Состояние Google-сервисов после угрозы замедления (07.2026).
6. Устойчивость прохождения QUIC v2 в 2026 году.

## 12. Источники

Класс источника: A — рецензируемые или официальные данные, B — профильные СМИ, C — вторичные.

- **S1** (B) Wikipedia — Blocking of Telegram in Russia. https://en.wikipedia.org/wiki/Blocking_of_Telegram_in_Russia
- **S2** (B) The Moscow Times, 2026-02-10 — Roskomnadzor Tightens Restrictions on Telegram. https://www.themoscowtimes.com/2026/02/10/roskomnadzor-tightens-restrictions-on-telegram-as-users-report-disruptions-a91907
- **S3** (B) CPJ, 2026-02 — Russia's Telegram throttling. https://cpj.org/2026/02/cpj-russias-telegram-throttling-another-step-toward-total-information-control/
- **S4** (B) Kyiv Post — Russia Introduces Full Telegram Ban Nationwide. https://www.kyivpost.com/post/73690
- **S5** (C) Russiable — Telegram in Russia 2026. https://russiable.com/telegram-russia/
- **S6** (B) The Moscow Times, 2026-02-12 — WhatsApp Accuses Russian Government of Trying to 'Fully Block' Platform. https://www.themoscowtimes.com/2026/02/12/whatsapp-accuses-russian-government-of-trying-to-fully-block-platform-a91928
- **S7** (B) CNBC, 2026-02-12 — Russia blocks WhatsApp. https://www.cnbc.com/2026/02/12/russia-whatsapp-meta-max.html
- **S8** (B) The Moscow Times, 2025-10-22 — Telegram and WhatsApp Access Restricted in 34 Russian Regions. https://www.themoscowtimes.com/2025/10/22/telegram-and-whatsapp-access-restricted-in-34-russian-regions-monitor-a90903
- **S9** (B) Медиазона (EN), 2026-04-07 — Russia's internet censorship in 2026. https://en.zona.media/article/2026/04/07/russian_internet_censorship_2026
- **S10** (B) Wikipedia — Blocking of YouTube in Russia. https://en.wikipedia.org/wiki/Blocking_of_YouTube_in_Russia
- **S11** (B) Вёрстка — YouTube «выключили» через DNS. https://verstka.media/youtube-vyklyuchili-cherez-dns-roskomnadzor-primenil-radikalnyj-sposob-blokirovki
- **S12** (B) Вёрстка — Замедление YouTube ослабло до минимальных значений за полтора года. https://verstka.media/zamedlenie-youtube-v-rossii-oslablo-do-minimalnyh-znachenij-za-poltora-goda
- **S13** (B) Meduza, 2024-07-12 — Traffic speeds reveal targeted throttling of YouTube. https://meduza.io/en/feature/2024/07/12/traffic-speeds-reveal-that-russia-s-youtube-slowdown-is-targeted-throttling-not-google-global-cache-equipment-failure
- **S14** (A) RIPE 89, M. Klimarev — Throttling YouTube in Russia. https://ripe89.ripe.net/presentations/44-Throttling-YouTube-in-Russia_v2.pdf
- **S15** (A) Cloudflare Blog — Russian Internet users are unable to access the open Internet. https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/
- **S16** (B) Медиазона (EN), 2025-06-19 — The 16-kilobyte curtain. https://en.zona.media/article/2025/06/19/cloudflare
- **S17** (C) net4people/bbs #490 — TCP 16-20 freeze. https://github.com/net4people/bbs/issues/490
- **S18** (C) hyperion-cs/dpi-checkers. https://github.com/hyperion-cs/dpi-checkers
- **S19** (C) Runnin4ik/dpi-detector. https://github.com/Runnin4ik/dpi-detector
- **S20** (A) Xue et al., IMC 2022 — TSPU: Russia's Decentralized Censorship System. https://doi.org/10.1145/3517745.3561461 (PDF: https://par.nsf.gov/servlets/purl/10379650)
- **S21** (A) Xue et al., IMC 2021 — Throttling Twitter. https://censorbib.nymity.ch/pdf/Xue2021a.pdf
- **S22** (A) OONI, 2022 — New blocks emerge in Russia amid war in Ukraine. https://ooni.org/post/2022-russia-blocks-amid-ru-ua-conflict/
- **S23** (A) FOCI 2026 — On Russia's Early Introduction of QUIC SNI Censorship. https://www.petsymposium.org/foci/2026/foci-2026-0010.php
- **S24** (A) OONI, 2022 — A Quick Look at QUIC Censorship. https://ooni.org/post/2022-quick-look-quic-censorship/
- **S25** (B) Risky Business — Russia blocks Cloudflare ECH connections. https://news.risky.biz/risky-biz-news-russia-blocks-cloudflare-ech-connections/
- **S26** (B) The Record — Russia blocks thousands of websites that use Cloudflare service. https://therecord.media/russia-blocks-thousands-of-websites-that-use-cloudflare-service
- **S27** (B) Risky Bulletin, 2026-08-26 — Russia starts blocking DoH and DoT. https://news.risky.biz/risky-bulletin-russia-starts-blocking-doh-and-dot/
- **S28** (B) Anti-Malware.ru, 2026-08-26 — Российские провайдеры начали глушить защищённые DNS. https://www.anti-malware.ru/news/2026-08-26-111332/51193
- **S29** (C) Comss.ru — В России начали блокировать защищённый DNS. https://www.comss.ru/page.php?id=21721
- **S30** (C) Techora, 2026-08-28 — ТСПУ перенаправляют DNS-запросы к Cloudflare и Google на НСДИ. https://techora.ru/news/rossiyskie-tspu-napravlyayut-otkrytye-dns-zaprosy-2026-08-28
- **S31** (C) net4people/bbs #81 — Blocking of DNS, DoH, DoT servers in Russia. https://github.com/net4people/bbs/issues/81
- **S32** (B) The Insider — YouTube, Instagram, WhatsApp Web disappear from state DNS. https://theins.press/en/news/289338
- **S33** (C) Хабр — НСДИ: публичные резолверы. https://habr.com/ru/articles/562722/
- **S34** (B) Meduza, 2026-09-29 — Russia steps up VPN blocking after parliamentary elections. https://meduza.io/en/news/2026/09/29/russia-steps-up-vpn-blocking-after-parliamentary-elections-ten-services-report-tighter-restrictions-in-a-single-week
- **S35** (B) TechRadar — Russia blocks over 20 popular VPNs. https://www.techradar.com/vpn/vpn-privacy-security/the-largest-in-history-russia-blocks-over-20-popular-vpns-in-major-internet-crackdown
- **S36** (C) TechNadu — AmneziaWG 3.0 responds to Russia's intensifying VPN blocking. https://www.technadu.com/amneziawg-3-0-responds-to-russias-intensifying-vpn-blocking/633890/
- **S37** (C) www1.ru, 2026-01-22 — Roskomnadzor restricted access to 439 VPN services. https://www1.ru/en/news/2026/01/22/roskomnadzor-ogranicil-dostup-k-439-vpn-servisam-v-rossii.html
- **S38** (B) Википедия — «Белые списки» сайтов в России. https://ru.wikipedia.org/wiki/%C2%AB%D0%91%D0%B5%D0%BB%D1%8B%D0%B5_%D1%81%D0%BF%D0%B8%D1%81%D0%BA%D0%B8%C2%BB_%D1%81%D0%B0%D0%B9%D1%82%D0%BE%D0%B2_%D0%B2_%D0%A0%D0%BE%D1%81%D1%81%D0%B8%D0%B8
- **S39** (C) TAdviser — Белый список цифровых платформ. https://www.tadviser.ru/index.php/%D0%A1%D1%82%D0%B0%D1%82%D1%8C%D1%8F:%D0%91%D0%B5%D0%BB%D1%8B%D0%B9_%D1%81%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D1%86%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D1%8B%D1%85_%D0%BF%D0%BB%D0%B0%D1%82%D1%84%D0%BE%D1%80%D0%BC,_%D0%B4%D0%BE%D1%81%D1%82%D1%83%D0%BF%D0%BD%D1%8B%D1%85_%D0%B2_%D0%A0%D0%BE%D1%81%D1%81%D0%B8%D0%B8_%D0%B2_%D0%BF%D0%B5%D1%80%D0%B8%D0%BE%D0%B4%D1%8B_%D0%BE%D1%82%D0%BA%D0%BB%D1%8E%D1%87%D0%B5%D0%BD%D0%B8%D0%B9_%D0%BC%D0%BE%D0%B1%D0%B8%D0%BB%D1%8C%D0%BD%D0%BE%D0%B3%D0%BE_%D0%B8%D0%BD%D1%82%D0%B5%D1%80%D0%BD%D0%B5%D1%82%D0%B0
- **S40** (B) SecurityLab — Мобильный интернет в России сжался до «белого списка». https://www.securitylab.ru/news/575700.php
- **S41** (C) Techora, 2026-05-26 — Минцифры расширило белый список до 500. https://techora.ru/news/mintsifry-rasshirilo-belyy-spisok-do-500-2026-05-26
- **S42** (B) Фонтанка, 2026-02-04 — Минцифры расширило «белый список». https://www.fontanka.ru/2026/02/04/76248140/
- **S43** (B) Wikipedia — Wartime internet restrictions in Russia (2025–present). https://en.wikipedia.org/wiki/Wartime_internet_restrictions_in_Russia_(2025%E2%80%93present)
- **S44** (B) Meduza, 2025-07-01 — «На связи»: в июне 655 отключений. https://meduza.io/news/2025/07/01/na-svyazi-v-rossii-v-iyune-655-raz-otklyuchali-mobilnyy-internet
- **S45** (B) The Moscow Times (RU), 2025-12-31 — Почти 12 тысяч отключений в 2025 году. https://ru.themoscowtimes.com/2025/12/31/v-rossiiskih-regionah-pochti-12-tisyach-raz-otklyuchali-internet-v-2025-godu-a184027
- **S46** (B) The Moscow Times (RU), 2026-07-23 — Рухнуло потребление мобильного интернета. https://ru.themoscowtimes.com/2026/07/23/v-rossii-ruhnulo-potreblenie-mobilnogo-interneta-iz-za-massovih-otklyuchenii-svyazi-a201521
- **S47** (B) Chatham House, 2026-03 — Moscow internet blackouts. https://www.chathamhouse.org/2026/03/moscow-internet-blackouts-kremlin-tightens-its-grip-russias-digital-space
- **S48** (B) The Moscow Times, 2026-03-13 — A week of mobile internet shutdowns in Moscow. https://www.themoscowtimes.com/2026/03/13/in-moscow-a-week-of-mobile-internet-shutdowns-makes-life-a-real-pain-a92207
- **S49** (B) Meduza, 2025-12-04 — Russia blocks Snapchat, along with Roblox and FaceTime. https://meduza.io/en/news/2025/12/04/russia-blocks-snapchat-along-with-roblox-and-facetime
- **S50** (B) The Moscow Times, 2026-06-10 — Russia backs down on Roblox ban. https://www.themoscowtimes.com/2026/06/10/russia-backs-down-on-roblox-ban-after-childrens-complaints-a92976
- **S51** (B) RFE/RL — Russia blocks Discord. https://www.rferl.org/a/roskomnadzor-blocks-discord-tech-russia-ukraine/33152178.html
- **S52** (C) Express — Foreign messengers in Russia 2026. https://express.ms/en/blog/obzory/kakie-inostrannye-messendzhery-rabotayut-v-rossii/
- **S53** (B) The Moscow Times (RU), 2026-05-25 — Власти стали блокировать крупнейшие сайты с компьютерными играми. https://ru.themoscowtimes.com/2026/05/25/rossiiskie-vlasti-stali-blokirovat-krupneishie-saiti-s-kompyuternimi-igrami-a196186
- **S54** (C) iXBT Games, 2026-07-15 — Russians lost access to Battle.net. https://ixbt.games/en/news/2026/07/15/rossiiane-lisilis-dostupa-k-battlenet-diablo-iv-i-drugim-igram-blizzard.html
- **S55** (B) The Moscow Times, 2026-07-27 — Russia gives Google 24-hour ultimatum. https://www.themoscowtimes.com/2026/07/27/russia-gives-google-24-hour-ultimatum-to-remove-banned-content
- **S56** (B) Новая газета Европа, 2026-08-03 — Сайты семи банков перешли на сертификаты Минцифры. https://novayagazeta.eu/articles/2026/08/03/saity-semi-bankov-pereshli-na-nebezopasnye-sertifikaty-mintsifry-news
- **S57** (B) The Moscow Times (RU), 2026-08-04 — Сайты крупнейших банков перешли на сертификаты Минцифры. https://ru.themoscowtimes.com/2026/08/04/saiti-krupneishih-rossiiskih-bankov-pereshli-na-sertifikati-mintsifri-pozvolyayuschie-rasshifrovivat-trafik-polzovatelei-a202560
- **S58** (A) OONI spec — ts-017 Web Connectivity. https://github.com/ooni/spec/blob/master/nettests/ts-017-web-connectivity.md
- **S59** (A) OONI — Web Connectivity nettest. https://ooni.org/nettest/web-connectivity/
- **S60** (A) OONI probe-cli — experiments. https://github.com/ooni/probe-cli/tree/master/internal/experiment
- **S61** (A) OONI, 2024 — Russia blocked OONI Explorer. https://ooni.org/post/2024-russia-blocked-ooni-explorer
- **S62** (A) OONI — blocking-fingerprints (без лицензии). https://github.com/ooni/blocking-fingerprints
- **S63** (B) Meduza, 2025-07-31 — Putin signs law penalizing online searches for "extremist" content. https://meduza.io/en/news/2025/07/31/putin-signs-law-penalizing-online-searches-for-content-deemed-extremist-by-russian-authorities
- **S64** (B) Kyiv Post — Russia implements ban on VPN advertisement. https://www.kyivpost.com/post/28993
- **S65** (B) Human Rights Watch, 2025-07-30 — Disrupted, Throttled, and Blocked. https://www.hrw.org/report/2025/07/30/disrupted-throttled-and-blocked/state-censorship-control-and-increasing-isolation
- **S66** (B) TechCrunch, 2026-03-23 — Russian authorities block archive.today. https://techcrunch.com/2026/03/23/russian-authorities-block-paywall-removal-site-archive-today/
- **S67** (B) heise — Roblox, FaceTime and Snapchat blocked in Russia. https://www.heise.de/en/news/After-threat-against-WhatsApp-Roblox-FaceTime-and-Snapchat-blocked-in-Russia-11103420.html
- **S68** (B) MacRumors, 2025-12-04 — Russia blocks FaceTime. https://www.macrumors.com/2025/12/04/russia-blocks-facetime/
- **S69** (C) Lantern corpus — summary of hyperion-cs 2025 report (автоизвлечение LLM, требует проверки). https://corpus.lantern.io/papers/2025-hyperion-cs-censor-has-new/
- **S70** (B) Новая газета Европа, 2026-05-05 — Минимум в 21 регионе отключат связь перед 9 мая. https://novayagazeta.eu/articles/2026/05/05/minimum-v-21-regione-rossii-otkliuchat-sviaz-v-preddverii-9-maia-vyiasnila-novaia-evropa-news
- **S71** (B) Новая газета Европа, 2024-10-09 — Russia blocks Discord. https://novayagazeta.eu/articles/2024/10/09/russia-blocks-popular-messaging-app-discord-for-breaking-anti-terror-laws-en-news
- **S72** (C, вендор) Le VPN — Russia VPN blocking wave, September 2026. https://www.le-vpn.com/russia-vpn-blocking-wave-september-2026/
- **S73** (C, вендор) vpnon — Mass VPN outages in Russia, August 2026. https://vpnon.io/en/blog/mass-vpn-outages-russia-august-2026
- **S74** (A) Справочные сервисы, используемые в методологии: RIPEstat Data API https://stat.ripe.net/docs/data_api · iptoasn https://iptoasn.com/ · Cloudflare Radar https://radar.cloudflare.com/ · IODA https://ioda.inetintel.cc.gatech.edu/ · Censored Planet https://censoredplanet.org/
- **S75** (B) Al Jazeera, 2025-12-05 — Russia blocks Snapchat, FaceTime. https://www.aljazeera.com/news/2025/12/5/russia-continues-tech-crackdown-by-blocking-snapchat-facetime-access
- **S76** (B) Meduza, 2024-11-08 — Russia's internet censor demands a break from Cloudflare. https://meduza.io/en/news/2024/11/08/russia-s-internet-censor-demands-a-break-from-cloudflare-after-the-american-company-enabled-new-privacy-tools-last-month
- **S77** (B) Wikipedia — List of websites blocked in Russia. https://en.wikipedia.org/wiki/List_of_websites_blocked_in_Russia
- **S78** (B) Wikipedia — Internet censorship in Russia. https://en.wikipedia.org/wiki/Internet_censorship_in_Russia
