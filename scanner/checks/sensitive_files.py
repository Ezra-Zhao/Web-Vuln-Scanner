"""Sensitive file / directory probing.

Requests a list of well-known sensitive paths and reports the ones that return
HTTP 200. Findings are informational-to-high depending on what was exposed.

Limitations (honest): a 200 does not prove sensitive content -- some apps return
200 with a generic page ("soft 404"). Content verification is a TODO.
"""
from __future__ import annotations

import requests

from .base import BaseCheck, Finding

# (path, severity, note)
PROBES: list[tuple[str, str, str]] = [
    ("robots.txt", "info", "may reveal hidden paths (also useful for defenders)"),
    (".git/HEAD", "high", "exposed .git allows source-code reconstruction"),
    (".env", "high", "often contains secrets / credentials"),
    (".htaccess", "medium", "may leak access-control configuration"),
    (".DS_Store", "low", "may leak directory listings"),
    ("admin", "medium", "admin interface reachable"),
    ("admin/", "medium", "admin interface reachable"),
    ("backup.zip", "medium", "backup archives often contain source or DB dumps"),
    ("db.sqlite", "high", "database file directly downloadable"),
    ("database.sql", "high", "database dump directly downloadable"),
    ("phpinfo.php", "medium", "discloses full server configuration"),
    ("server-status", "medium", "may disclose request / worker details"),
    (".svn/entries", "medium", "exposed SVN metadata leaks paths"),
    ("actuator/health", "low", "Spring Boot actuator exposed"),
]


class SensitiveFilesCheck(BaseCheck):
    name = "sensitive-files"
    description = "Probes well-known sensitive paths; reports HTTP 200 hits."

    def run(self, session: requests.Session, target) -> list[Finding]:
        findings: list[Finding] = []
        base = target.base_url
        for path, severity, note in PROBES:
            url = f"{base}/{path}"
            try:
                resp = session.get(url, timeout=10, allow_redirects=False)
            except requests.RequestException:
                continue
            if resp.status_code == 200 and len(resp.content) > 0:
                findings.append(
                    Finding(
                        check=self.name,
                        severity=severity,
                        title=f"Accessible sensitive path: /{path}",
                        url=url,
                        detail=f"GET /{path} returned 200. {note}",
                        evidence=f"HTTP 200, {len(resp.content)} bytes",
                    )
                )
        return findings


# TODO(ezra): soft-404 detection -- fetch a random non-existent path first and
#   compare body similarity, so generic "200 with error page" responses are not
#   reported as exposed files.
# TODO(ezra): content sniffing -- e.g. confirm /.git/HEAD body starts with "ref:",
#   .env body contains KEY=VALUE lines, before raising severity to high.
