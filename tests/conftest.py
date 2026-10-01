"""Test fixtures: spin up the intentionally vulnerable demo app on localhost."""
import os
import sys
import threading
import time

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo.vulnerable_app import app  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

DEMO_PORT = 5055


@pytest.fixture(scope="session")
def demo_base_url():
    server = make_server("127.0.0.1", DEMO_PORT, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{DEMO_PORT}"
    for _ in range(100):
        try:
            requests.get(base + "/", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    yield base
    server.shutdown()
