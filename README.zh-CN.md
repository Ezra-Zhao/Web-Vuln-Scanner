# Web-Vuln-Scanner

[English](README.md) | **[简体中文](README.zh-CN.md)** | [日本語](README.ja.md) | [한국어](README.ko.md) | [Español](README.es.md) | [Português](README.pt.md) | [Русский](README.ru.md)

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Status: scaffold](https://img.shields.io/badge/status-scaffold_v0.1-orange)


一个轻量、伦理优先的 Python Web 漏洞扫描器——作为网络安全硕士（WGU，在读）学习期间的动手实践项目。

它爬取你拥有（或被明确授权测试）的目标，运行一组独立的漏洞检查，并生成控制台＋JSON 报告。

> **项目状态：脚手架 v0.1（诚实版）。**
> 四项检查已实现，并已用内置的脆弱演示应用验证：反射型 XSS、基于报错的 SQLi、缺失的安全响应头、敏感文件／目录探测。存储型 XSS、布尔／时间盲注 SQLi、CSRF、认证测试**尚未**实现——它们标为 TODO，不是已宣称的功能。

---

## ⚖️ 仅限授权使用

除非满足以下条件，否则本工具将**拒绝运行**：

1. 显式传入 `--target`（无默认值，不存在“扫描全网”这种选项），**并且**
2. 在范围确认提示中输入 `SCAN`，确认你拥有该目标或已获得测试它的明确书面授权，**并且**
3. （可选但推荐）传入 `--allowlist allowlist.txt`，确保只有预先批准的主机才会被扫描。

它适用于你拥有的系统、故意做脆弱的训练应用（DVWA、OWASP Juice Shop）以及内置的 `./demo` 服务器。在大多数司法管辖区，未经授权扫描他人系统是违法的——不要这么做。

---

## 检查项

| Check | What it does | Severity |
|---|---|---|
| `reflected-xss` | Injects a unique token into URL params and form fields; flags unescaped reflection | High |
| `error-based-sqli` | Injects quote-based payloads; matches DB error signatures (SQLite/MySQL/PostgreSQL/MSSQL/Oracle) | High |
| `security-headers` | Flags missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; notes `Server` version disclosure | Low–Medium |
| `sensitive-files` | Probes for `/.git/HEAD`, `/.env`, `/admin`, `/robots.txt`, backups, etc. | Info–High |

每项检查都是 `scanner/checks/` 下的独立模块——新增一项只需一个文件＋在 `cli.py` 里加一行。

### 路线图（TODO，尚未实现）

- 存储型 XSS 检测（需要对持久化状态做观察）
- 布尔型和时间型盲注 SQLi
- CSRF token 存在性检查
- 登录后扫描的认证／会话处理
- 敏感文件探测器的 soft-404 识别

---

## 架构

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

## 快速上手（2 分钟，无需 Docker）

终端 1——启动故意做脆弱的演示服务器：

```bash
cd Web-Vuln-Scanner
.venv/bin/python demo/vulnerable_app.py
# → 运行在 http://127.0.0.1:5000（仅绑定本机）
```

终端 2——扫描它：

```bash
.venv/bin/python -m scanner.cli --target http://127.0.0.1:5000
# 在确认提示中输入 SCAN
```

预期结果：`/search` 上的反射型 XSS、`/user` 上的报错型 SQLi、缺失的安全响应头、敏感路径（`/admin`、`/.git/HEAD`、`/robots.txt`）。JSON 报告写入 `scan_report.json`。

运行测试：

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## 技术栈

Python 3.11+、`requests`、`beautifulsoup4`、`flask`（仅演示用）、`pytest`。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
