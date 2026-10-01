"""Ethics guardrail tests: the scanner must refuse unauthorized scans."""
import pytest

from scanner.scope import ScopeError, authorize, normalize_target


def test_target_scheme_required():
    with pytest.raises(ScopeError):
        normalize_target("example.com")
    with pytest.raises(ScopeError):
        normalize_target("")


def test_unconfirmed_scan_refused():
    with pytest.raises(ScopeError):
        authorize("http://127.0.0.1:5000", confirmed=False)


def test_confirmed_scan_allowed():
    assert authorize("http://127.0.0.1:5000/", confirmed=True) == "http://127.0.0.1:5000"


def test_allowlist_blocks_unlisted_host(tmp_path):
    allow = tmp_path / "allow.txt"
    allow.write_text("127.0.0.1\n")
    with pytest.raises(ScopeError):
        authorize("http://192.168.1.1:5000", allowlist_path=str(allow), confirmed=True)


def test_allowlist_permits_listed_host(tmp_path):
    allow = tmp_path / "allow.txt"
    allow.write_text("# lab targets\n127.0.0.1\n")
    url = authorize("http://127.0.0.1:5000", allowlist_path=str(allow), confirmed=True)
    assert url == "http://127.0.0.1:5000"
