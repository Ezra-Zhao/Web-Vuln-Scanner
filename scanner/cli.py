"""CLI entrypoint: scope confirmation -> crawl -> checks -> report.

Ethics: the scan refuses to start unless the operator explicitly confirms they
are authorized to test the target (interactive prompt, or --yes for lab use),
and the target host must be in --allowlist when one is provided.
"""
from __future__ import annotations

import argparse
import sys

import requests

from .scope import authorize, ScopeError
from .crawler import crawl
from .report import print_report, save_json
from .checks.xss import ReflectedXSSCheck
from .checks.sqli import ErrorBasedSQLiCheck
from .checks.headers import SecurityHeadersCheck
from .checks.sensitive_files import SensitiveFilesCheck

CHECKS = [
    ReflectedXSSCheck(),
    ErrorBasedSQLiCheck(),
    SecurityHeadersCheck(),
    SensitiveFilesCheck(),
]

CONFIRM_WORD = "SCAN"


def _confirm_interactive(target: str) -> bool:
    print("=" * 60)
    print("AUTHORIZATION CHECK")
    print("=" * 60)
    print(f"You are about to scan: {target}")
    print()
    print("Only scan systems you OWN or have EXPLICIT WRITTEN authorization")
    print("to test (your own apps, lab targets, DVWA / Juice Shop, etc.).")
    print("Unauthorized scanning is illegal in most jurisdictions.")
    print()
    answer = input(f'Type {CONFIRM_WORD} to confirm you are authorized (anything else aborts): ')
    return answer.strip() == CONFIRM_WORD


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Web-Vuln-Scanner: ethics-first web vulnerability scanner."
    )
    parser.add_argument("--target", required=True, help="Explicit target URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--allowlist", default=None, help="File with allowed hosts (one per line)")
    parser.add_argument("--max-pages", type=int, default=20, help="Crawl page limit (default 20)")
    parser.add_argument("--output", default="scan_report.json", help="JSON report path")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive prompt. Only use for lab targets you own. "
             "You are still asserting authorization by passing this flag.",
    )
    args = parser.parse_args(argv)

    confirmed = args.yes or _confirm_interactive(args.target)
    try:
        target = authorize(args.target, allowlist_path=args.allowlist, confirmed=confirmed)
    except ScopeError as e:
        print(f"Refusing to scan: {e}", file=sys.stderr)
        return 2

    session = requests.Session()
    session.headers["User-Agent"] = "Web-Vuln-Scanner/0.1 (security learning project)"

    print(f"Crawling {target} (max {args.max_pages} pages)...")
    crawled = crawl(session, target, max_pages=args.max_pages)
    print(f"Crawled {len(crawled.pages)} pages, {len(crawled.forms)} forms, "
          f"{len(crawled.urls_with_params)} parameterized URLs.")

    findings = []
    for check in CHECKS:
        print(f"Running check: {check.name} ...")
        try:
            findings.extend(check.run(session, crawled))
        except Exception as e:  # a check must never kill the whole scan
            print(f"  [warn] check {check.name} failed: {e}", file=sys.stderr)

    print_report(findings, target)
    save_json(findings, target, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
