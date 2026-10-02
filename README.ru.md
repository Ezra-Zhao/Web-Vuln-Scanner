# Web-Vuln-Scanner

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Español](README.es.md) | [Português](README.pt.md) | **[Русский](README.ru.md)**

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Status: scaffold](https://img.shields.io/badge/status-scaffold_v0.1-orange)


Лёгкий Python-сканер веб-уязвимостей с приоритетом этики — практический учебный проект в рамках магистратуры по кибербезопасности (WGU, в процессе обучения).

Сканирует цель, которой вы владеете (или которую явно разрешено тестировать), выполняет набор независимых проверок уязвимостей и формирует отчёт в консоль + JSON.

> **Статус проекта: каркас v0.1 (честная редакция).**
> Четыре проверки реализованы и проверены на встроенном уязвимом демо-приложении: отражённый XSS, SQLi на основе ошибок, отсутствующие security-заголовки и поиск чувствительных файлов/каталогов. Хранимый XSS, булев/слепой SQLi по времени, CSRF и тестирование аутентификации **не** реализованы — они помечены как TODO, а не заявлены как готовые функции.

---

## ⚖️ Только авторизованное использование

Этот инструмент **откажется запускаться**, если вы не:

1. Явно передать `--target` (без значений по умолчанию, без «сканирования интернета»), **и**
2. Ввести `SCAN` в запросе подтверждения области, подтвердив, что цель принадлежит вам или у вас есть явное письменное разрешение на её тестирование, **и**
3. (Необязательно, но рекомендуется) передать `--allowlist allowlist.txt`, чтобы сканировались только заранее одобренные хосты.

Инструмент предназначен для систем, которыми вы владеете, намеренно уязвимых тренировочных приложений (DVWA, OWASP Juice Shop) и встроенного сервера `./demo`. Сканирование чужих систем без разрешения незаконно в большинстве юрисдикций — не делайте этого.

---

## Проверки

| Check | What it does | Severity |
|---|---|---|
| `reflected-xss` | Injects a unique token into URL params and form fields; flags unescaped reflection | High |
| `error-based-sqli` | Injects quote-based payloads; matches DB error signatures (SQLite/MySQL/PostgreSQL/MSSQL/Oracle) | High |
| `security-headers` | Flags missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; notes `Server` version disclosure | Low–Medium |
| `sensitive-files` | Probes for `/.git/HEAD`, `/.env`, `/admin`, `/robots.txt`, backups, etc. | Info–High |

Каждая проверка — независимый модуль в `scanner/checks/`; добавление новой — это один файл + одна строка в `cli.py`.

### Планы развития (TODO, пока не реализовано)

- Детекция хранимого XSS (нужно наблюдение за персистентным состоянием)
- Булев и временной слепой SQLi
- Проверка наличия CSRF-токена
- Обработка аутентификации/сессий для сканирования после входа
- Детекция soft-404 для поиска чувствительных файлов

---

## Архитектура

```
scanner/
├── cli.py          # argparse entrypoint; wires scope → crawl → checks → report
├── scope.py        # ethics guardrail: explicit target + confirmation (+ allowlist)
├── crawler.py      # same-host crawler: pages, links, forms, URLs with params
├── checks/
│   ├── base.py     # Finding dataclass + BaseCheck interface
│   ├── xss.py      # reflected XSS
│   ├── sqli.py     # error-based SQLi
│   ├── headers.py  # security headers
│   └── sensitive_files.py
└── report.py       # console table + JSON report

demo/
└── vulnerable_app.py  # intentionally vulnerable Flask app (local training target)

tests/              # pytest: checks verified against the demo app
```

---

## Быстрый старт (2 минуты, без Docker)

Терминал 1 — запуск намеренно уязвимого демо-сервера:

```bash
cd Web-Vuln-Scanner
.venv/bin/python demo/vulnerable_app.py
# → работает на http://127.0.0.1:5000 (только localhost)
```

Терминал 2 — сканируем:

```bash
.venv/bin/python -m scanner.cli --target http://127.0.0.1:5000
# введите SCAN в запросе подтверждения
```

Ожидаемый результат: отражённый XSS на `/search`, SQLi на основе ошибок на `/user`, отсутствующие security-заголовки и чувствительные пути (`/admin`, `/.git/HEAD`, `/robots.txt`). JSON-отчёт записывается в `scan_report.json`.

Запуск тестов:

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## Технологии

Python 3.11+, `requests`, `beautifulsoup4`, `flask` (только для демо), `pytest`.

## Лицензия

MIT — см. [LICENSE](LICENSE).
