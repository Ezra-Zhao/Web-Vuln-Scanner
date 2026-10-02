# Web-Vuln-Scanner

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | **[한국어](README.ko.md)** | [Español](README.es.md) | [Português](README.pt.md) | [Русский](README.ru.md)

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Status: scaffold](https://img.shields.io/badge/status-scaffold_v0.1-orange)


가볍고 윤리를 우선하는 Python 웹 취약점 스캐너 — 사이버보안 석사 과정(WGU, 재학 중)의 실습 학습 프로젝트로 제작.

소유하고 있거나(명시적으로 테스트가 허가된) 타깃을 크롤링하고, 일련의 독립적인 취약점 검사를 실행한 뒤 콘솔 + JSON 리포트를 생성합니다.

> **프로젝트 상태: 스캐폴드 v0.1(정직 에디션).**
> 4가지 검사가 구현되어 내장된 취약한 데모 앱으로 검증되었습니다: 반사형 XSS, 에러 기반 SQLi, 누락된 보안 헤더, 민감한 파일/디렉터리 탐색. 저장형 XSS, 불리언/시간 기반 블라인드 SQLi, CSRF, 인증 테스트는 **미구현**입니다 — TODO로 표시되어 있을 뿐 구현된 기능이 아닙니다.

---

## ⚖️ 허가된 사용만

다음 조건을 충족하지 않으면 이 도구는 **실행을 거부**합니다:

1. 명시적으로 `--target`을 전달한다(기본값 없음, "인터넷 전체 스캔" 같은 옵션 없음), **그리고**
2. 범위 확인 프롬프트에 `SCAN`을 입력하여 타깃의 소유자이거나 테스트에 대한 명시적 서면 허가를 받았음을 확인한다, **그리고**
3. (선택 사항이지만 권장) `--allowlist allowlist.txt`를 전달하여 사전 승인된 호스트만 스캔되도록 한다.

이 도구는 소유한 시스템, 의도적으로 취약하게 만든 훈련용 앱(DVWA, OWASP Juice Shop), 그리고 내장된 `./demo` 서버를 대상으로 합니다. 허가 없이 타인의 시스템을 스캔하는 것은 대부분의 관할권에서 불법입니다 — 하지 마세요.

---

## 검사 항목

| Check | What it does | Severity |
|---|---|---|
| `reflected-xss` | Injects a unique token into URL params and form fields; flags unescaped reflection | High |
| `error-based-sqli` | Injects quote-based payloads; matches DB error signatures (SQLite/MySQL/PostgreSQL/MSSQL/Oracle) | High |
| `security-headers` | Flags missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`; notes `Server` version disclosure | Low–Medium |
| `sensitive-files` | Probes for `/.git/HEAD`, `/.env`, `/admin`, `/robots.txt`, backups, etc. | Info–High |

각 검사는 `scanner/checks/` 아래의 독립 모듈입니다 — 새 검사를 추가하려면 파일 하나와 `cli.py`의 한 줄이면 됩니다.

### 로드맵(TODO, 미구현)

- 저장형 XSS 탐지(영속 상태 관찰 필요)
- 불리언 기반 및 시간 기반 블라인드 SQLi
- CSRF 토큰 존재 여부 검사
- 로그인 후 스캔을 위한 인증/세션 처리
- 민감 파일 탐색기용 soft-404 탐지

---

## 아키텍처

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

## 빠른 시작(2분, Docker 불필요)

터미널 1 — 의도적으로 취약한 데모 서버 시작:

```bash
cd Web-Vuln-Scanner
.venv/bin/python demo/vulnerable_app.py
# → http://127.0.0.1:5000 에서 실행(localhost에만 바인드)
```

터미널 2 — 스캔 실행:

```bash
.venv/bin/python -m scanner.cli --target http://127.0.0.1:5000
# 확인 프롬프트에 SCAN 입력
```

예상 결과: `/search`의 반사형 XSS, `/user`의 에러 기반 SQLi, 누락된 보안 헤더, 민감한 경로(`/admin`, `/.git/HEAD`, `/robots.txt`). JSON 리포트는 `scan_report.json`에 기록됩니다.

테스트 실행:

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## 기술 스택

Python 3.11+, `requests`, `beautifulsoup4`, `flask`(데모 전용), `pytest`.

## 라이선스

MIT — [LICENSE](LICENSE) 참조.
