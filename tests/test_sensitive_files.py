import requests

from scanner.checks.sensitive_files import SensitiveFilesCheck
from scanner.crawler import crawl


def test_sensitive_paths_found(demo_base_url):
    session = requests.Session()
    crawled = crawl(session, demo_base_url)
    findings = SensitiveFilesCheck().run(session, crawled)
    urls = {f.url for f in findings}
    assert any(u.endswith("/admin") for u in urls), f"/admin not found: {urls}"
    assert any(u.endswith("/.git/HEAD") for u in urls), f"/.git/HEAD not found: {urls}"
    assert any(u.endswith("/robots.txt") for u in urls), f"/robots.txt not found: {urls}"
    git = [f for f in findings if f.url.endswith("/.git/HEAD")]
    assert git and git[0].severity == "high"
