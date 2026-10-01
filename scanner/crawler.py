"""Simple same-host web crawler: collects pages, links, forms, and parameterized URLs."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup


@dataclass
class Form:
    action: str
    method: str  # "get" or "post"
    inputs: list[str]


@dataclass
class Page:
    url: str
    status: int
    html: str


@dataclass
class CrawlResult:
    base_url: str
    pages: list[Page] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    urls_with_params: list[str] = field(default_factory=list)


def _same_host(base: str, url: str) -> bool:
    return urlparse(base).netloc == urlparse(url).netloc


def crawl(session: requests.Session, base_url: str, max_pages: int = 20) -> CrawlResult:
    result = CrawlResult(base_url=base_url.rstrip("/"))
    seen: set[str] = set()
    queue: list[str] = [result.base_url]

    while queue and len(result.pages) < max_pages:
        url = urldefrag(queue.pop(0))[0]
        if url in seen or not _same_host(result.base_url, url):
            continue
        seen.add(url)
        try:
            resp = session.get(url, timeout=10)
        except requests.RequestException:
            continue
        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue
        result.pages.append(Page(url=url, status=resp.status_code, html=resp.text))
        if urlparse(url).query:
            result.urls_with_params.append(url)

        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            if not _same_host(result.base_url, action):
                continue
            inputs = [
                i.get("name")
                for i in form.find_all(["input", "textarea", "select"])
                if i.get("name")
            ]
            result.forms.append(
                Form(action=action, method=(form.get("method") or "get").lower(), inputs=inputs)
            )
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if _same_host(result.base_url, link) and link not in seen:
                queue.append(link)

    return result
