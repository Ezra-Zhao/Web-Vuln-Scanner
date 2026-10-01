"""Shared types for vulnerability checks."""
from __future__ import annotations

from dataclasses import dataclass, asdict

import requests


@dataclass
class Finding:
    check: str        # check name, e.g. "reflected-xss"
    severity: str     # critical / high / medium / low / info
    title: str
    url: str
    detail: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class BaseCheck:
    """Interface every check implements. Keep checks independent and single-purpose."""

    name = "base"
    description = ""

    def run(self, session: requests.Session, target) -> list[Finding]:
        """Run against a CrawlResult. Return findings (possibly empty)."""
        raise NotImplementedError
