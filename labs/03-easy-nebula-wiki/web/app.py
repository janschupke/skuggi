"""Nebula Wiki — DELIBERATELY VULNERABLE Flask practice target."""

import os
import time

import psycopg2
import redis
from flask import (
    Flask,
    jsonify,
    render_template_string,
    request,
    session,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev")

PG = {
    "host": os.environ.get("PG_HOST", "postgres"),
    "dbname": "wiki",
    "user": "wiki",
    "password": os.environ.get("PG_PASS", "wiki-db-pass"),
}
CACHE = redis.Redis(
    host=os.environ.get("REDIS_HOST", "redis"), port=6379, decode_responses=True
)


def pg():
    return psycopg2.connect(**PG)


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/")
def index():
    with pg() as conn, conn.cursor() as cur:
        cur.execute("SELECT slug, title FROM pages ORDER BY slug")
        rows = cur.fetchall()
    links = "".join(f'<li><a href="/page/{s}">{t}</a></li>' for s, t in rows)
    return (
        "<h1>Nebula Wiki</h1><p>Internal knowledge base.</p>"
        f"<ul>{links}</ul>"
        '<p>Try the <a href="/preview">markdown preview</a>.</p>'
    )


@app.get("/page/<slug>")
def page(slug):
    with pg() as conn, conn.cursor() as cur:
        cur.execute("SELECT title, body FROM pages WHERE slug = %s", (slug,))
        row = cur.fetchone()
    if not row:
        return "not found", 404
    title, body = row
    return f"<h1>{title}</h1><pre>{body}</pre>"


# VULN (SSTI -> RCE): the preview renders user input as a Jinja template.
@app.route("/preview", methods=["GET", "POST"])
def preview():
    content = request.values.get("content", "")
    if not content:
        return (
            '<form method="post"><textarea name="content" rows="6" cols="60">'
            "Hello {{ 1+1 }}</textarea><br><button>Preview</button></form>"
        )
    return render_template_string(content)


# VULN (info leak): a debug route left enabled dumps the app config, including
# the Flask SECRET_KEY — enough to forge an admin session cookie.
@app.get("/debug")
def debug():
    return jsonify({k: str(v) for k, v in app.config.items()})


# Requires an admin session. Forge the cookie with the leaked SECRET_KEY.
@app.get("/admin")
def admin():
    if session.get("role") != "admin":
        return "forbidden — admin session required", 403
    with pg() as conn, conn.cursor() as cur:
        cur.execute("SELECT name, email, dept, salary FROM employees ORDER BY name")
        rows = cur.fetchall()
    body = "".join(
        f"<tr><td>{n}</td><td>{e}</td><td>{d}</td><td>{s}</td></tr>"
        for n, e, d, s in rows
    )
    return f"<h1>Employee export</h1><table>{body}</table>"


def _seed_cache():
    """Warm the Redis cache the way the app does at boot (idempotent)."""
    for _ in range(30):
        try:
            CACHE.set(
                "secret:smtp",
                "SMTP relay: mailer@nebula.example / N3bula-Mail-2024!",
            )
            CACHE.set("cache:pages_last_built", "2026-09-01T00:00:00Z")
            return
        except redis.RedisError:
            time.sleep(1)


if __name__ == "__main__":
    _seed_cache()
    app.run(host="0.0.0.0", port=5000)  # noqa: S104,S201 - lab target
