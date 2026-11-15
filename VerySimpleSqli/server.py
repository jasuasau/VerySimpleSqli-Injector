#!/usr/bin/env python3
# vuln_app.py — intentionally vulnerable SQLi test app (LOOPBACK ONLY)
from flask import Flask, request, g
import sqlite3

DB_PATH = "test.db"
DB_USER = "admin"
DB_PASS = "S3cr3tP@ss"

app = Flask(__name__)

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = None
    return db

@app.teardown_appcontext
def close_db(_exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

@app.route("/")
def index():
    uid = request.args.get("id")
    if uid is not None:
        db = get_db()
        # VULNERABLE: numeric injection, 3 columns (id, username, email)
        q = f"SELECT id, username, email FROM users WHERE id={uid}"
        try:
            rows = db.execute(q).fetchall()
        except sqlite3.OperationalError as e:
            return f"<h2>SQL error</h2><pre>{e}</pre>", 500
        if rows:
            return f"<pre>{rows}</pre>"
        return "<pre>not found</pre>", 404
    # normal homepage when no id param
    return """<h2>Vulnerable Corp Portal</h2>
<form action="/login" method="post">
  <input name="username" placeholder="username"><br>
  <input name="password" type="password" placeholder="password"><br>
  <button>Login</button>
</form>
<p>Users search: <a href="/search?name=a">/search?name=a</a></p>
<p>Comments: <a href="/comments">/comments</a></p>"""

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    db = get_db()
    # VULNERABLE: string concatenation
    q = f"SELECT id, username, email, role FROM users WHERE username='{u}' AND password='{p}'"
    try:
        rows = db.execute(q).fetchall()
    except sqlite3.OperationalError as e:
        return f"<h2>SQL error</h2><pre>{e}</pre>", 500
    if rows:
        return f"<h2>Welcome</h2><pre>{rows}</pre>"
    return "<h2>Login failed</h2>", 401

@app.route("/search")
def search():
    name = request.args.get("name", "")
    db = get_db()
    # VULNERABLE: users table = 4 columns (id, username, email, role)
    q = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{name}%'"
    try:
        rows = db.execute(q).fetchall()
    except sqlite3.OperationalError as e:
        return f"<h2>SQL error</h2><pre>{e}</pre>", 500
    return f"<pre>{rows}</pre>"

@app.route("/comments")
def comments():
    db = get_db()
    rows = db.execute("SELECT id, author, comment, created FROM comments ORDER BY id").fetchall()
    out = "\n".join(f"{r[0]} | {r[1]}: {r[2]} ({r[3]})" for r in rows)
    return f"<pre>{out}</pre>"

@app.route("/products")
def products():
    db = get_db()
    rows = db.execute("SELECT id, name, price FROM products").fetchall()
    return f"<pre>{rows}</pre>"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS comments")
    c.execute("DROP TABLE IF EXISTS products")
    c.execute("DROP TABLE IF EXISTS api_keys")
    c.execute("DROP TABLE IF EXISTS payments")

    # 4 columns: id, username, email, role (password kept out of default SELECT,
    # but pullable via UNION: ' UNION SELECT 1, username||':'||password, role, 4 FROM users--)
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)")
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?)", [
        (1, "admin",   "S3cr3tP@ss",      "admin@vulncorp.local",  "admin"),
        (2, "alice",   "password123",     "alice@vulncorp.local",  "user"),
        (3, "bob",     "hunter2",         "bob@vulncorp.local",    "user"),
        (4, "svc_backup", "Backup#2024!", "svc@vulncorp.local",    "service"),
        (5, "dev_test","devdev123",       "dev@vulncorp.local",    "developer"),
    ])

    c.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, comment TEXT, created TEXT)")
    c.executemany("INSERT INTO comments VALUES (?,?,?,?)", [
        (1, "alice", "Anyone know why prod is down?", "2026-11-10"),
        (2, "admin", "Restarting the DB, creds are on the wiki", "2026-11-10"),
        (3, "bob",   "nice security team lol", "2026-11-11"),
    ])

    c.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    c.executemany("INSERT INTO products VALUES (?,?,?)", [
        (1, "Laptop", 999.99), (2, "Mouse", 19.99), (3, "Keyboard", 49.99),
    ])

    # Juicy dump targets
    c.execute("CREATE TABLE api_keys (id INTEGER PRIMARY KEY, owner TEXT, service TEXT, key TEXT)")
    c.executemany("INSERT INTO api_keys VALUES (?,?,?,?)", [
        (1, "admin", "aws",  "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        (2, "admin", "slack", "xoxb-123456789012-FAKE-TOKEN-EXAMPLE"),
        (3, "svc_backup", "stripe", "sk_test_FAKEKEY1234567890"),
        (4, "dev_test", "github", "ghp_FAKEPATtokenEXAMPLE000000000"),
    ])

    c.execute("CREATE TABLE payments (id INTEGER PRIMARY KEY, user_id INTEGER, card TEXT, cvv TEXT, expiry TEXT, balance REAL)")
    c.executemany("INSERT INTO payments VALUES (?,?,?,?,?,?)", [
        (1, 2, "4111111111111111", "123", "12/27", 5400.50),
        (2, 3, "5500005555555559", "456", "06/28", 120.00),
        (3, 5, "378282246310005",  "7890", "01/26", 99999.99),
    ])

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    # Loopback only — not reachable from other hosts
    app.run(host="127.0.0.1", port=5000, debug=False)
