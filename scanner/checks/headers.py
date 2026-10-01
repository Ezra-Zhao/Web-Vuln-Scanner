"""Security response-header check.

Flags missing hardening headers on the target's base page and notes version
disclosure via the Server header.
"""
from __future__ import annotations

import requests

from .base import BaseCheck, Finding

# header -> severity when missing
EXPECTED_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "medium",
    "X-Frame-Options": "low",
    "X-Content-Type-Options": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "info",
}

WHY = {
    "Content-Security-Policy": "primary mitigation for XSS; without it, injected scripts run unrestricted",
    "X-Frame-Options": "page can be framed by attacker sites (clickjacking)",
    "X-Content-Type-Options": "allows MIME-sniffing attacks",
    "Referrer-Policy": "full URLs (possibly with tokens) may leak via Referer",
    "Permissions-Policy": "browser features (camera, mic, geolocation) not restricted",
}


class SecurityHeadersCheck(BaseCheck):
    name = "security-headers"
    description = "Flags missing security response headers on the base page."

    def run(self, session: requests.Session, target) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = session.get(target.base_url, timeout=10)
        except requests.RequestException:
            return findings
        present = {k.lower() for k in resp.headers}
        for header, severity in EXPECTED_HEADERS.items():
            if header.lower() not in present:
                findings.append(
                    Finding(
                        check=self.name,
                        severity=severity,
                        title=f"Missing security header: {header}",
                        url=target.base_url,
                        detail=f"{header} not set. {WHY.get(header, '')}",
                    )
                )
        # HSTS is only meaningful over HTTPS; note its absence as info there.
        if target.base_url.startswith("https://") and "strict-transport-security" not in present:
            findings.append(
                Finding(
                    check=self.name,
                    severity="medium",
                    title="Missing security header: Strict-Transport-Security",
                    url=target.base_url,
                    detail="HSTS not set on an HTTPS site; users are exposed to SSL-stripping on first visit.",
                )
            )
        server = resp.headers.get("Server")
        if server:
            findings.append(
                Finding(
                    check=self.name,
                    severity="info",
                    title=f"Server header discloses: {server}",
                    url=target.base_url,
                    detail="Version disclosure helps attackers fingerprint the stack. Consider minimizing it.",
                    evidence=server,
                )
            )
        return findings
