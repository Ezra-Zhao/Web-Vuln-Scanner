# Web-Vuln-Scanner

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Español](README.es.md) | **[Português](README.pt.md)** | [Русский](README.ru.md)

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Status: scaffold](https://img.shields.io/badge/status-scaffold_v0.1-orange)


Um scanner de vulnerabilidades web leve, em Python e com ética em primeiro lugar — construído como projeto prático de aprendizado durante um Mestrado em Cibersegurança (WGU, em andamento).

Rastreia um alvo que você possui (ou está explicitamente autorizado a testar), executa um conjunto de verificações de vulnerabilidades independentes e produz um relatório em console + JSON.

> **Estado do projeto: esqueleto v0.1 (edição honesta).**
> Quatro verificações estão implementadas e validadas contra o app demo vulnerável incluído: XSS refletido, SQLi baseado em erros, cabeçalhos de segurança ausentes e sondagem de arquivos/diretórios sensíveis. XSS armazenado, SQLi cego booleano/baseado em tempo, CSRF e testes de autenticação **não** estão implementados — estão marcados como TODO, não como recursos existentes.

---

## ⚖️ Somente uso autorizado

Esta ferramenta **se recusará a executar** a menos que:

1. Passar um `--target` explícito (sem padrões, sem "escanear a internet"), **e**
2. Digitar `SCAN` no prompt de confirmação de escopo, confirmando que o alvo pertence a você ou que você tem autorização escrita explícita para testá-lo, **e**
3. (Opcional, mas recomendado) passar `--allowlist allowlist.txt` para que apenas hosts pré-aprovados possam ser escaneados.

Destina-se a sistemas que você possui, apps de treinamento intencionalmente vulneráveis (DVWA, OWASP Juice Shop) e o servidor `./demo` incluído. Escanear sistemas sem autorização é ilegal na maioria das jurisdições — não faça isso.

---

## Verificações

| Check | What it does | Severity |
|---|---|---|
| `reflected-xss` | Injects a unique token into URL params and form fields; flags unescaped reflection | High |
| `error-based-sqli` | Injects quote-based payloads; matches DB error signatures (SQLite/MySQL/PostgreSQL/MSSQL/Oracle) | High |
| `security-headers` | Flags missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; notes `Server` version disclosure | Low–Medium |
| `sensitive-files` | Probes for `/.git/HEAD`, `/.env`, `/admin`, `/robots.txt`, backups, etc. | Info–High |

Cada verificação é um módulo independente em `scanner/checks/` — adicionar uma nova é um único arquivo + uma linha em `cli.py`.

### Roteiro (TODO, ainda não implementado)

- Detecção de XSS armazenado (requer observação de estado persistente)
- SQLi cego booleano e baseado em tempo
- Verificação de presença de token CSRF
- Tratamento de autenticação/sessão para varreduras autenticadas
- Detecção de soft-404 para o sondador de arquivos sensíveis

---

## Arquitetura

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

## Início rápido (2 minutos, sem Docker)

Terminal 1: iniciar o servidor demo intencionalmente vulnerável:

```bash
cd Web-Vuln-Scanner
.venv/bin/python demo/vulnerable_app.py
# → rodando em http://127.0.0.1:5000 (vincula apenas ao localhost)
```

Terminal 2: escaneá-lo:

```bash
.venv/bin/python -m scanner.cli --target http://127.0.0.1:5000
# digite SCAN no prompt de confirmação
```

Esperado: XSS refletido em `/search`, SQLi baseado em erros em `/user`, cabeçalhos de segurança ausentes e caminhos sensíveis (`/admin`, `/.git/HEAD`, `/robots.txt`). O relatório JSON é gravado em `scan_report.json`.

Executar os testes:

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## Tecnologias

Python 3.11+, `requests`, `beautifulsoup4`, `flask` (apenas demo), `pytest`.

## Licença

MIT — ver [LICENSE](LICENSE).
