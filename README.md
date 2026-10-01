# Web-Vuln-Scanner

A lightweight, ethics-first web vulnerability scanner in Python — built as a hands-on
learning project alongside a Master's in Cybersecurity (WGU, in progress).

It crawls a target you own (or are explicitly authorized to test), runs a set of
independent vulnerability checks, and produces a console + JSON report.

> **Project status: scaffold v0.1 (honest edition).**
> Four checks are implemented and verified against the bundled vulnerable demo app:
> reflected XSS, error-based SQLi, missing security headers, and sensitive file/dir
> probing. Stored XSS, boolean/time-based blind SQLi, CSRF, and auth testing are
> **not** implemented — they are marked as TODOs, not claimed features.

---

## ⚖️ Authorized use only

This tool will **refuse to run** unless you:

1. Pass an explicit `--target` (no defaults, no "scan the internet"), **and**
2. Type `SCAN` at the scope-confirmation prompt, confirming you own the target or
   have explicit written authorization to test it, **and**
3. (Optional but recommended) pass `--allowlist allowlist.txt` so only
   pre-approved hosts can ever be scanned.

It is intended for systems you own, intentionally vulnerable training apps
(DVWA, OWASP Juice Shop), and the bundled `./demo` server. Scanning systems
without authorization is illegal in most jurisdictions — don't.

---

## Checks

| Check | What it does | Severity |
|---|---|---|
| `reflected-xss` | Injects a unique token into URL params and form fields; flags unescaped reflection | High |
| `error-based-sqli` | Injects quote-based payloads; matches DB error signatures (SQLite/MySQL/PostgreSQL/MSSQL/Oracle) | High |
| `security-headers` | Flags missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; notes `Server` version disclosure | Low–Medium |
| `sensitive-files` | Probes for `/.git/HEAD`, `/.env`, `/admin`, `/robots.txt`, backups, etc. | Info–High |

Each check is an independent module under `scanner/checks/` — adding a new one is
a single file + one line in `cli.py`.

### Roadmap (TODO, not yet implemented)

- Stored XSS detection (needs persistent state observation)
- Boolean-based and time-based blind SQLi
- CSRF token presence check
- Authentication / session handling for logged-in scans
- Soft-404 detection for the sensitive-file prober

---

## Architecture

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

## Quickstart (2 minutes, no Docker)

Terminal 1 — start the intentionally vulnerable demo server:

```bash
cd Web-Vuln-Scanner
.venv/bin/python demo/vulnerable_app.py
# → running on http://127.0.0.1:5000  (binds localhost only)
```

Terminal 2 — scan it:

```bash
.venv/bin/python -m scanner.cli --target http://127.0.0.1:5000
# type SCAN at the confirmation prompt
```

Expected: reflected XSS on `/search`, error-based SQLi on `/user`, missing security
headers, and sensitive paths (`/admin`, `/.git/HEAD`, `/robots.txt`). A JSON report
is written to `scan_report.json`.

Run the tests:

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## Tech

Python 3.11+, `requests`, `beautifulsoup4`, `flask` (demo only), `pytest`.

## License

MIT — see [LICENSE](LICENSE).
