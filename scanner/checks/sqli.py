"""Error-based SQL injection detection.

Appends quote-based payloads to URL parameters and form fields, then matches
database error signatures in the response body.

Limitations (honest): error-based only. Boolean-based blind and time-based blind
SQLi are NOT covered -- see TODOs below.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

from .base import BaseCheck, Finding

# (label, [regexes]) -- matched against response bodies
ERROR_SIGNATURES: list[tuple[str, list[str]]] = [
    ("SQLite", [r"SQLite", r"sqlite3", r"syntax error", r"unrecognized token"]),
    ("MySQL/MariaDB", [r"MySQL", r"You have an error in your SQL syntax", r"mysql_fetch", r"MariaDB"]),
    ("PostgreSQL", [r"PostgreSQL", r"PG::", r"pg_query\(\)", r"unterminated quoted string"]),
    ("MSSQL", [r"Microsoft OLE DB", r"SQL Server", r"ODBC SQL Server Driver"]),
    ("Oracle", [r"ORA-\d{5}", r"Oracle error"]),
    ("Generic SQL", [r"SQL syntax", r"database error", r"DB Error", r"\bJDBC\b"]),
]

PAYLOADS = ["'", '"', "' OR '1'='1", '" OR "1"="1']


def _match_db_error(text: str) -> str | None:
    for label, patterns in ERROR_SIGNATURES:
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return label
    return None


class ErrorBasedSQLiCheck(BaseCheck):
    name = "error-based-sqli"
    description = "Injects quote payloads; flags database error signatures in responses."

    def _test(self, session: requests.Session, url: str, params: dict) -> list[Finding]:
        findings: list[Finding] = []
        for key in params:
            for payload in PAYLOADS:
                probe = dict(params)
                probe[key] = str(params[key]) + payload
                try:
                    resp = session.get(url, params=probe, timeout=10)
                except requests.RequestException:
                    continue
                db = _match_db_error(resp.text)
                if db:
                    findings.append(
                        Finding(
                            check=self.name,
                            severity="high",
                            title=f"Possible SQL injection via parameter '{key}' ({db} error disclosed)",
                            url=resp.url,
                            detail=(
                                f"Payload {payload!r} triggered a {db} error message. "
                                "Error disclosure + injectable parameter = likely SQLi."
                            ),
                            evidence=payload,
                        )
                    )
                    break  # one finding per parameter is enough
        return findings

    def run(self, session: requests.Session, target) -> list[Finding]:
        findings: list[Finding] = []
        for url in target.urls_with_params:
            parts = urlparse(url)
            base = urlunparse(parts._replace(query=""))
            params = dict(parse_qsl(parts.query))
            findings.extend(self._test(session, base, params))
        for form in target.forms:
            if not form.inputs or form.method != "get":
                continue
            # GET forms submit as query params; POST-form SQLi probing is a TODO
            params = {name: "1" for name in form.inputs}
            findings.extend(self._test(session, form.action, params))
        return findings


# TODO(ezra): boolean-based blind SQLi -- compare TRUE vs FALSE payload responses
#   (e.g. "' AND '1'='1" vs "' AND '1'='2") for content/length differences.
# TODO(ezra): time-based blind SQLi -- payloads like "'; SELECT pg_sleep(5)--"
#   with response-time measurement. Needs per-DB payload sets + timing stats.
# TODO(ezra): probe POST form fields too (currently GET only).
