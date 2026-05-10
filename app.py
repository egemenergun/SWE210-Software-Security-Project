import os
import sqlite3
from datetime import datetime
from functools import wraps

from cryptography.fernet import Fernet
from flask import Flask, g, redirect, render_template_string, request, session, url_for
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash


# -----------------------------
# Application setup (Flask)
# -----------------------------
app = Flask(__name__)

# Use an environment variable in real deployments.
# For a classroom demo, this default keeps the app runnable out of the box.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# Store the SQLite database in the project folder by default.
DATABASE_PATH = os.environ.get(
    "SQLITE_PATH",
    os.path.join(os.path.dirname(__file__), "security_project.db"),
)


# -----------------------------
# Database helpers (SQLite)
# -----------------------------
def get_db():
    """Return a SQLite connection stored in Flask's request context."""
    if "db" not in g:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    """Close the SQLite connection after each request."""
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    """
    Create required tables and ensure the Fernet key exists in the DB.
    We do this once at startup.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Users table stores roles and password hashes.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')) DEFAULT 'user',
            created_at TEXT NOT NULL
        );
        """
    )

    # Sensitive data table stores encrypted values per user.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sensitive_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            encrypted_value BLOB NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )

    # App config table stores the Fernet key so encrypted data can be decrypted later.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )

    # Ensure we have a persistent Fernet key.
    row = cur.execute(
        "SELECT value FROM app_config WHERE key = ?",
        ("fernet_key",),
    ).fetchone()

    if row is None:
        # If the environment provides a key, use it; otherwise generate one.
        # This keeps encryption stable across restarts as long as the DB is kept.
        env_key = os.environ.get("FERNET_KEY")
        key = env_key.encode("utf-8") if env_key else Fernet.generate_key()
        cur.execute(
            "INSERT INTO app_config (key, value) VALUES (?, ?)",
            ("fernet_key", key.decode("utf-8")),
        )

    conn.commit()
    conn.close()


def load_fernet_key():
    """Load the Fernet key from SQLite and return it as bytes."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    row = cur.execute(
        "SELECT value FROM app_config WHERE key = ?",
        ("fernet_key",),
    ).fetchone()
    conn.close()

    if row is None:
        # This should not happen if init_db() ran successfully.
        raise RuntimeError("Missing Fernet key in database.")

    return row["value"].encode("utf-8")


def get_fernet():
    """Create a Fernet instance for encryption/decryption."""
    return Fernet(load_fernet_key())


def encrypt_sensitive(plaintext: str) -> bytes:
    """Encrypt sensitive text using Fernet."""
    token = get_fernet().encrypt(plaintext.encode("utf-8"))
    return token


def decrypt_sensitive(token: bytes) -> str:
    """Decrypt encrypted sensitive text using Fernet."""
    plaintext = get_fernet().decrypt(token).decode("utf-8")
    return plaintext


@app.before_request
def ensure_db():
    """Make sure tables exist before handling requests (once per process)."""
    global _DB_INITIALIZED
    if not _DB_INITIALIZED:
        init_db()
        _DB_INITIALIZED = True


_DB_INITIALIZED = False


# -----------------------------
# Security helpers (RBAC + sessions)
# -----------------------------
def get_current_user():
    """Return the current user row or None if the user is not logged in."""
    user_id = session.get("user_id")
    if not user_id:
        return None

    db = get_db()
    return db.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def login_required(view_func):
    """Protect routes so only logged-in users can access them."""

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


def admin_required(view_func):
    """Protect routes so only admins can access them."""

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or user["role"] != "admin":
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)

    return wrapper


# -----------------------------
# HTML templates (single-file)
# -----------------------------
BASE_STYLE = """
body { font-family: Arial, sans-serif; margin: 40px; }
.card { max-width: 720px; padding: 20px; border: 1px solid #ddd; border-radius: 10px; }
input, button, textarea { width: 100%; padding: 10px; margin-top: 8px; }
button { width: auto; padding: 10px 14px; margin-top: 12px; }
.row { display: flex; gap: 16px; align-items: flex-start; }
.half { flex: 1; }
.muted { color: #666; }
.error { color: #b00020; }
"""


def render_page(title: str, body_html: str):
    """Render a page with a simple consistent layout."""
    return render_template_string(
        """
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8"/>
          <title>{{ title }}</title>
          <style>{{ style }}</style>
        </head>
        <body>
          <div class="card">
            <h2>{{ title }}</h2>
            {{ body|safe }}
          </div>
        </body>
        </html>
        """,
        title=title,
        style=BASE_STYLE,
        body=body_html,
    )


# -----------------------------
# Authentication routes
# -----------------------------
@app.route("/")
def index():
    """Redirect users to the right start page."""
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Create a new user account.
    Passwords are hashed with werkzeug.security before storing them in SQLite.
    """
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            message = "Please provide both username and password."
        elif len(username) < 3:
            message = "Username must be at least 3 characters."
        elif len(password) < 8:
            message = "Password must be at least 8 characters."
        else:
            db = get_db()

            # The first registered user becomes admin automatically.
            # This makes it easy to test /admin during a project demo.
            user_count = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            role = "admin" if user_count == 0 else "user"

            password_hash = generate_password_hash(password)
            try:
                db.execute(
                    """
                    INSERT INTO users (username, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, password_hash, role, datetime.utcnow().isoformat()),
                )
                db.commit()
                message = "Account created. You can log in now."
            except sqlite3.IntegrityError:
                message = "That username is already taken."

    form_html = f"""
    <p class="muted">Create your account. The first account will be an admin.</p>
    {"<p class='error'>" + message + "</p>" if message and "Account created" not in message else ("<p>" + message + "</p>" if message else "")}
    <form method="post">
      <label>Username</label>
      <input name="username" required minlength="3" autocomplete="username"/>
      <label>Password</label>
      <input name="password" type="password" required minlength="8" autocomplete="new-password"/>
      <button type="submit">Register</button>
    </form>
    <p class="muted">Already have an account? <a href="{url_for('login')}">Log in</a></p>
    """
    return render_page("Register", form_html)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log in an existing user and store their session in a secure cookie."""
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            message = "Invalid username or password."
        else:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

    form_html = f"""
    <p class="muted">Log in to access your dashboard.</p>
    {"<p class='error'>" + message + "</p>" if message else ""}
    <form method="post">
      <label>Username</label>
      <input name="username" required autocomplete="username"/>
      <label>Password</label>
      <input name="password" type="password" required autocomplete="current-password"/>
      <button type="submit">Log in</button>
    </form>
    <p class="muted">No account? <a href="{url_for('register')}">Register</a></p>
    """
    return render_page("Login", form_html)


@app.route("/logout")
def logout():
    """Clear the session to log the user out."""
    session.clear()
    return redirect(url_for("login"))


# -----------------------------
# Protected routes (RBAC)
# -----------------------------
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    """
    Show a logged-in user's dashboard.
    The page encrypts data before storing it, then decrypts it for display.
    """
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    message = ""

    if request.method == "POST":
        sensitive_plaintext = request.form.get("sensitive_data", "").strip()
        if not sensitive_plaintext:
            message = "Please enter the sensitive data you want to store."
        else:
            encrypted = encrypt_sensitive(sensitive_plaintext)
            db = get_db()
            db.execute(
                """
                INSERT INTO sensitive_data (user_id, encrypted_value, created_at)
                VALUES (?, ?, ?)
                """,
                (user["id"], encrypted, datetime.utcnow().isoformat()),
            )
            db.commit()
            message = "Saved encrypted data. It will be decrypted for display below."

    # Load the most recent encrypted value for the current user.
    db = get_db()
    latest = db.execute(
        """
        SELECT encrypted_value, created_at
        FROM sensitive_data
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (user["id"],),
    ).fetchone()

    decrypted_value = None
    created_at = None
    if latest is not None:
        encrypted_blob = latest["encrypted_value"]
        decrypted_value = decrypt_sensitive(encrypted_blob)
        created_at = latest["created_at"]

    body_html = f"""
    <div class="row">
      <div class="half">
        <p class="muted">Your role: <strong>{escape(user['role'])}</strong></p>
        <p class="muted">This dashboard demonstrates encryption at rest using <code>cryptography.fernet</code>.</p>
      </div>
      <div class="half">
        <p class="muted" style="text-align:right"><a href="{url_for('logout')}">Log out</a></p>
      </div>
    </div>

    {"<p class='error'>" + message + "</p>" if message and 'Please' in message else ("<p>" + message + "</p>" if message else "")}

    <h3>Store sensitive data (encrypted in DB)</h3>
    <form method="post">
      <label>Sensitive data text</label>
      <textarea name="sensitive_data" rows="4" placeholder="Type a secret message..."></textarea>
      <button type="submit">Save encrypted value</button>
    </form>

    <h3>Display (decrypted when rendering)</h3>
    {f"<p class='muted'>Last stored at: {created_at}</p>" if created_at else "<p class='muted'>No sensitive data stored yet.</p>"}
    {f"<pre>{escape(decrypted_value)}</pre>" if decrypted_value is not None else ""}
    """

    if user["role"] == "admin":
        # Admins get a quick link, but access is still enforced by /admin checks.
        body_html += f"""
        <p class="muted"><a href="{url_for('admin_panel')}">Go to admin panel</a></p>
        """

    return render_page("Dashboard", body_html)


@app.route("/admin", methods=["GET"])
@login_required
@admin_required
def admin_panel():
    """
    Admin-only route.
    Only users with the admin role can reach this page.
    """
    db = get_db()
    users = db.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id ASC"
    ).fetchall()

    total_secrets = db.execute("SELECT COUNT(*) AS c FROM sensitive_data").fetchone()["c"]

    rows_html = ""
    for u in users:
        rows_html += (
            "<tr>"
            f"<td>{u['id']}</td>"
            f"<td>{escape(u['username'])}</td>"
            f"<td>{escape(u['role'])}</td>"
            f"<td>{escape(u['created_at'])}</td>"
            "</tr>"
        )

    body_html = f"""
    <p class="muted">You have admin access.</p>
    <p class="muted">Total encrypted sensitive records in the DB: <strong>{total_secrets}</strong></p>
    <p class="muted" style="text-align:right"><a href="{url_for('logout')}">Log out</a></p>

    <h3>Registered users</h3>
    <table style="width:100%; border-collapse:collapse" border="1" cellpadding="6">
      <thead>
        <tr><th>ID</th><th>Username</th><th>Role</th><th>Created At</th></tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>

    <p class="muted">RBAC note: this page is restricted to <code>admin</code> role only.</p>
    """
    return render_page("Admin Panel", body_html)


if __name__ == "__main__":
    # Initialize the DB before the first request so the app starts cleanly.
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)

