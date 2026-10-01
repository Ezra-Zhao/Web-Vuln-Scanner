"""Reflected XSS detection.

Injects a unique token into URL parameters and form fields, then checks whether
the exact payload is reflected unescaped in the response body.

Limitations (honest): reflected only. Stored XSS (payload persisted and rendered
later, e.g. in comment boards) is NOT covered -- see TODO below.
"""
from __future__ import annotations

import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

from .base import BaseCheck, Finding


def _payload(token: str) -> str:
    return f'\"><svg/onload=alert(\'{token}\')>'


class ReflectedXSSCheck(BaseCheck):
    name = "reflected-xss"
    description = "Injects a unique token into parameters/forms; flags unescaped reflection."

    def _check_url(self, session: requests.Session, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parts = urlparse(url)
        params = parse_qsl(parts.query)
        if not params:
            return findings
        for key, _ in params:
            token = "xss" + uuid.uuid4().hex[:8]
            payload = _payload(token)
            new_qs = urlencode([(k, payload if k == key else v) for k, v in params])
            test_url = urlunparse(parts._replace(query=new_qs))
            try:
                resp = session.get(test_url, timeout=10)
            except requests.RequestException:
                continue
            # token present AND the raw payload (with < > ") present => unescaped reflection
            if token in resp.text and payload in resp.text:
                findings.append(
                    Finding(
                        check=self.name,
                        severity="high",
                        title=f"Reflected XSS via parameter '{key}'",
                        url=test_url,
                        detail=f"Injected payload was reflected unescaped in the response body.",
                        evidence=payload,
                    )
                )
        return findings

    def _check_forms(self, session: requests.Session, target) -> list[Finding]:
        findings: list[Finding] = []
        for form in target.forms:
            if not form.inputs:
                continue
            for field in form.inputs:
                token = "xss" + uuid.uuid4().hex[:8]
                payload = _payload(token)
                data = {name: (payload if name == field else "test") for name in form.inputs}
                try:
                    if form.method == "post":
                        resp = session.post(form.action, data=data, timeout=10)
                    else:
                        resp = session.get(form.action, params=data, timeout=10)
                except requests.RequestException:
                    continue
                if token in resp.text and payload in resp.text:
                    findings.append(
                        Finding(
                            check=self.name,
                            severity="high",
                            title=f"Reflected XSS via form field '{field}'",
                            url=form.action,
                            detail=f"Form at {form.action} reflected the injected payload unescaped.",
                            evidence=payload,
                        )
                    )
        return findings

    def run(self, session: requests.Session, target) -> list[Finding]:
        findings: list[Finding] = []
        for url in target.urls_with_params:
            findings.extend(self._check_url(session, url))
        findings.extend(self._check_forms(session, target))
        return findings


# TODO(ezra): stored XSS -- submit payload, then revisit the page (and related
# pages) later to see if it renders. Needs a small state store of submitted
# payloads + a second crawl pass. Do not claim coverage until implemented.
