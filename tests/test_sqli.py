import requests

from scanner.checks.sqli import ErrorBasedSQLiCheck, _match_db_error
from scanner.crawler import crawl


def test_error_signatures_match():
    assert _match_db_error("sqlite3.OperationalError: near \"'\": syntax error") == "SQLite"
    assert _match_db_error("You have an error in your SQL syntax near '1'") == "MySQL/MariaDB"
    assert _match_db_error('ERROR: unterminated quoted string at or near "\'"') == "PostgreSQL"
    assert _match_db_error("Hello, world") is None


def test_sqli_detected_on_user_endpoint(demo_base_url):
    session = requests.Session()
    crawled = crawl(session, demo_base_url + "/user?id=1")
    findings = ErrorBasedSQLiCheck().run(session, crawled)
    assert any(
        f.check == "error-based-sqli" and f.severity == "high" for f in findings
    ), f"expected SQLi finding, got: {findings}"
