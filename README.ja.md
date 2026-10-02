# Web-Vuln-Scanner

[English](README.md) | [简体中文](README.zh-CN.md) | **[日本語](README.ja.md)** | [한국어](README.ko.md) | [Español](README.es.md) | [Português](README.pt.md) | [Русский](README.ru.md)

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Status: scaffold](https://img.shields.io/badge/status-scaffold_v0.1-orange)


軽量で倫理ファーストな Python 製 Web 脆弱性スキャナ——サイバーセキュリティ修士課程（WGU、在学中）のハンズオン学習プロジェクトとして構築。

所有者である（または明示的にテストを許可された）ターゲットをクロールし、一連の独立した脆弱性チェックを実行して、コンソール＋JSON レポートを生成します。

> **プロジェクト状態：スカフォールド v0.1（正直エディション）。**
> 4 つのチェックが実装済みで、同梱の脆弱性デモアプリで検証済みです：反射型 XSS、エラーベース SQLi、セキュリティヘッダの欠落、センシティブなファイル／ディレクトリの探索。保存型 XSS、真偽値／時間ベースのブラインド SQLi、CSRF、認証テストは**未実装**です——TODO として明示されており、実装済み機能ではありません。

---

## ⚖️ 許可された利用のみ

以下の条件を満たさない限り、このツールは**実行を拒否**します：

1. `--target` を明示的に渡す（デフォルトなし、「インターネット全体をスキャン」は存在しない）、**かつ**
2. スコープ確認プロンプトで `SCAN` と入力し、ターゲットの所有者であること、またはテストの明示的な書面による許可を得ていることを確認する、**かつ**
3. （任意だが推奨）`--allowlist allowlist.txt` を渡し、事前承認されたホストのみがスキャンされるようにする。

本ツールは、所有するシステム、意図的に脆弱に作られた訓練用アプリ（DVWA、OWASP Juice Shop）、および同梱の `./demo` サーバーを対象としています。許可なく他者のシステムをスキャンすることは、ほとんどの法域で違法です——やめましょう。

---

## チェック項目

| Check | What it does | Severity |
|---|---|---|
| `reflected-xss` | Injects a unique token into URL params and form fields; flags unescaped reflection | High |
| `error-based-sqli` | Injects quote-based payloads; matches DB error signatures (SQLite/MySQL/PostgreSQL/MSSQL/Oracle) | High |
| `security-headers` | Flags missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; notes `Server` version disclosure | Low–Medium |
| `sensitive-files` | Probes for `/.git/HEAD`, `/.env`, `/admin`, `/robots.txt`, backups, etc. | Info–High |

各チェックは `scanner/checks/` 配下の独立モジュールです——新しいチェックの追加は、1 ファイル＋`cli.py` への 1 行追加だけです。

### ロードマップ（TODO、未実装）

- 保存型 XSS の検出（永続化された状態の観測が必要）
- 真偽値ベースおよび時間ベースのブラインド SQLi
- CSRF トークンの存在チェック
- ログイン後スキャンのための認証／セッション処理
- センシティブファイル探索用の soft-404 検出

---

## アーキテクチャ

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

## クイックスタート（2 分、Docker 不要）

ターミナル 1——意図的に脆弱なデモサーバーを起動：

```bash
cd Web-Vuln-Scanner
.venv/bin/python demo/vulnerable_app.py
# → http://127.0.0.1:5000 で起動（localhost のみにバインド）
```

ターミナル 2——スキャン実行：

```bash
.venv/bin/python -m scanner.cli --target http://127.0.0.1:5000
# 確認プロンプトで SCAN と入力
```

期待される結果：`/search` での反射型 XSS、`/user` でのエラーベース SQLi、セキュリティヘッダの欠落、センシティブなパス（`/admin`、`/.git/HEAD`、`/robots.txt`）。JSON レポートは `scan_report.json` に出力されます。

テストの実行：

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## 技術スタック

Python 3.11+、`requests`、`beautifulsoup4`、`flask`（デモのみ）、`pytest`。

## ライセンス

MIT —— [LICENSE](LICENSE) を参照。
