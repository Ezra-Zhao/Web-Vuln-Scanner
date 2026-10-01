"""Console + JSON reporting for scan findings."""
from __future__ import annotations

import json
from collections import Counter

from .checks.base import Finding

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def print_report(findings: list[Finding], target: str) -> None:
    print(f"\n=== Scan report: {target} ===")
    print(f"Total findings: {len(findings)}")
    if findings:
        counts = Counter(f.severity for f in findings)
        print("By severity:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))))
    print("-" * 60)
    for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
        print(f"[{f.severity.upper():8}] {f.check} :: {f.title}")
        print(f"           URL: {f.url}")
        print(f"           {f.detail}")
        if f.evidence:
            ev = f.evidence if len(f.evidence) <= 200 else f.evidence[:200] + "..."
            print(f"           evidence: {ev}")
    print("-" * 60)


def save_json(findings: list[Finding], target: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(
            {"target": target, "findings": [f.to_dict() for f in findings]},
            fh,
            indent=2,
        )
    print(f"JSON report written to {path}")
