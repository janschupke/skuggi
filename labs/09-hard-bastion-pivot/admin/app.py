"""Bastion internal admin — internal-only crown-jewels service."""

import json

from flask import Flask

app = Flask(__name__)
with open("/app/crown.json", encoding="utf-8") as fh:
    CROWN = json.load(fh)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/")
def home():
    return "<h1>Bastion Internal Admin</h1><p>Ledger export at /db.</p>"


@app.get("/db")
def db():
    return CROWN


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)  # noqa: S104
