"""Ethics guardrail: the scanner only runs against explicitly authorized targets.

Rules enforced here (and covered by tests/test_scope.py):
  1. --target is required and must be an explicit http(s) URL. There is no
     default target and no "scan the internet" mode.
  2. The operator must confirm the scan (interactive prompt in cli.py, or
     --yes for scripted runs against lab targets). Unconfirmed scans raise.
  3. If an --allowlist file is given, the target host must be listed in it.
"""
from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a scan is not explicitly authorized."""


def normalize_target(raw: str) -> str:
    target = (raw or "").strip()
    if not target.startswith(("http://", "https://")):
        raise ScopeError(
            "Target must be an explicit http(s) URL, e.g. "
            "--target http://127.0.0.1:5000"
        )
    parsed = urlparse(target)
    if not parsed.hostname:
        raise ScopeError(f"Could not parse a host from target: {target!r}")
    return target.rstrip("/")


def load_allowlist(path: str) -> set[str]:
    hosts: set[str] = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                # allow plain hosts or full URLs in the file
                hosts.add(urlparse(line).hostname or line)
    return hosts


def authorize(target: str, allowlist_path: str | None = None, confirmed: bool = False) -> str:
    """Validate the scan target. Returns the normalized target URL.

    Raises ScopeError unless the operator explicitly confirmed authorization.
    """
    url = normalize_target(target)
    if allowlist_path:
        allowed = load_allowlist(allowlist_path)
        host = urlparse(url).hostname
        if host not in allowed:
            raise ScopeError(
                f"Target host {host!r} is not in allowlist {allowlist_path}. "
                "Refusing to scan."
            )
    if not confirmed:
        raise ScopeError(
            "Scan not confirmed. Confirm that you own this target or have "
            "explicit written authorization to test it."
        )
    return url
