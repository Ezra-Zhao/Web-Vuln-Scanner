# Web-Vuln-Scanner

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | **[Español](README.es.md)** | [Português](README.pt.md) | [Русский](README.ru.md)

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Status: scaffold](https://img.shields.io/badge/status-scaffold_v0.1-orange)


Un escáner de vulnerabilidades web ligero, en Python y con la ética en primer lugar — construido como proyecto práctico de aprendizaje durante una Maestría en Ciberseguridad (WGU, en curso).

Rastrea un objetivo que te pertenece (o que estás explícitamente autorizado a probar), ejecuta un conjunto de comprobaciones de vulnerabilidades independientes y produce un informe en consola + JSON.

> **Estado del proyecto: andamiaje v0.1 (edición honesta).**
> Cuatro comprobaciones están implementadas y verificadas contra la app demo vulnerable incluida: XSS reflejado, SQLi basado en errores, cabeceras de seguridad faltantes y sondeo de archivos/directorios sensibles. XSS almacenado, SQLi ciego booleano/basado en tiempo, CSRF y pruebas de autenticación **no** están implementados — están marcados como TODO, no como funciones existentes.

---

## ⚖️ Solo uso autorizado

Esta herramienta **se negará a ejecutarse** a menos que:

1. Pasar un `--target` explícito (sin valores por defecto, sin "escanear internet"), **y**
2. Escribir `SCAN` en el prompt de confirmación de alcance, confirmando que el objetivo te pertenece o que tienes autorización escrita explícita para probarlo, **y**
3. (Opcional pero recomendado) pasar `--allowlist allowlist.txt` para que solo hosts preaprobados puedan ser escaneados.

Está pensado para sistemas que te pertenecen, apps de entrenamiento intencionalmente vulnerables (DVWA, OWASP Juice Shop) y el servidor `./demo` incluido. Escanear sistemas sin autorización es ilegal en la mayoría de las jurisdicciones — no lo hagas.

---

## Comprobaciones

| Check | What it does | Severity |
|---|---|---|
| `reflected-xss` | Injects a unique token into URL params and form fields; flags unescaped reflection | High |
| `error-based-sqli` | Injects quote-based payloads; matches DB error signatures (SQLite/MySQL/PostgreSQL/MSSQL/Oracle) | High |
| `security-headers` | Flags missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; notes `Server` version disclosure | Low–Medium |
| `sensitive-files` | Probes for `/.git/HEAD`, `/.env`, `/admin`, `/robots.txt`, backups, etc. | Info–High |

Cada comprobación es un módulo independiente en `scanner/checks/` — añadir una nueva es un solo archivo + una línea en `cli.py`.

### Hoja de ruta (TODO, aún no implementado)

- Detección de XSS almacenado (requiere observar estado persistente)
- SQLi ciego booleano y basado en tiempo
- Comprobación de presencia de token CSRF
- Manejo de autenticación/sesión para escaneos con sesión iniciada
- Detección de soft-404 para el sondeador de archivos sensibles

---

## Arquitectura

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

## Inicio rápido (2 minutos, sin Docker)

Terminal 1: iniciar el servidor demo intencionalmente vulnerable:

```bash
cd Web-Vuln-Scanner
.venv/bin/python demo/vulnerable_app.py
# → corriendo en http://127.0.0.1:5000 (solo escucha en localhost)
```

Terminal 2: escanearlo:

```bash
.venv/bin/python -m scanner.cli --target http://127.0.0.1:5000
# escribe SCAN en el prompt de confirmación
```

Esperado: XSS reflejado en `/search`, SQLi basado en errores en `/user`, cabeceras de seguridad faltantes y rutas sensibles (`/admin`, `/.git/HEAD`, `/robots.txt`). El informe JSON se escribe en `scan_report.json`.

Ejecutar las pruebas:

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## Tecnologías

Python 3.11+, `requests`, `beautifulsoup4`, `flask` (solo demo), `pytest`.

## Licencia

MIT — ver [LICENSE](LICENSE).
