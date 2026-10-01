import requests

from scanner.checks.headers import SecurityHeadersCheck
from scanner.crawler import crawl


def test_missing_headers_flagged(demo_base_url):
    session = requests.Session()
    crawled = crawl(session, demo_base_url)
    findings = SecurityHeadersCheck().run(session, crawled)
    missing = {f.title for f in findings}
    assert "Missing security header: Content-Security-Policy" in missing
    assert "Missing security header: X-Frame-Options" in missing
    assert "Missing security header: X-Content-Type-Options" in missing
