"""INTENTIONALLY VULNERABLE demo app -- for local security training ONLY.

Planted vulnerabilities (do NOT copy these patterns into real code):
  1. Reflected XSS on  /search?q=   (user input rendered unescaped)
  2. SQL injection on /user?id=    (string-formatted SQL + verbose DB errors)
  3. No security headers at all
  4. Sensitive paths: /admin, /robots.txt, /.git/HEAD

Binds to 127.0.0.1 only. Never expose this to a network.
Run:  python demo/vulnerable_app.py   (or: .venv/bin/python demo/vulnerable_app.py)
"""
from __future__ import annotations

import sqlite3

from flask import Flask, Response, request

app = Flask(__name__)

# In-memory demo database (shared connection is fine for a local training app).
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
DB.executemany(
    "INSERT INTO users (id, name, email) VALUES (?, ?, ?)",
    [(1, "alice", "alice@example.com"), (2, "bob", "bob@example.com")],
)


@app.get("/")
def index():
    return """
    <h1>Vuln Demo Shop</h1>
    <ul>
      <li><a href="/search?q=phone">Search</a></li>
      <li><a href="/user?id=1">User profile</a></li>
      <li><a href="/admin">Admin</a></li>
    </ul>
    <form action="/search" method="get">
      <input name="q" placeholder="search..."><button>Go</button>
    </form>
    """


@app.get("/search")
def search():
    q = request.args.get("q", "")
    # VULN 1: reflected XSS -- raw user input interpolated into HTML.
    return f"<h1>Search results for: {q}</h1><p>No products found.</p>"


@app.get("/user")
def user():
    uid = request.args.get("id", "1")
    # VULN 2: SQL injection -- query built with string formatting.
    try:
        cur = DB.execute(f"SELECT id, name, email FROM users WHERE id = {uid}")
        rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001 - intentional verbose error for training
        # VULN 2b: verbose database errors make error-based SQLi trivially detectable,
        # exactly like misconfigured production apps.
        return f"<h1>Database error</h1><pre>{e}</pre>", 500
    if not rows:
        return "<h1>User not found</h1>", 404
    items = "".join(f"<li>#{r[0]} {r[1]} &lt;{r[2]}&gt;</li>" for r in rows)
    return f"<h1>Users</h1><ul>{items}</ul>"


@app.get("/admin")
def admin():
    # VULN 4a: sensitive functionality with no authentication.
    return "<h1>Admin panel</h1><p>TODO: add authentication</p>"


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\n", mimetype="text/plain")


@app.get("/.git/HEAD")
def git_head():
    # VULN 4b: exposed VCS metadata.
    return Response("ref: refs/heads/main\n", mimetype="text/plain")


if __name__ == "__main__":
    print("WARNING: intentionally vulnerable training app -- listening on 127.0.0.1:5000 only")
    app.run(host="127.0.0.1", port=5000)
