"""Bastion DMZ portal — DELIBERATELY VULNERABLE practice target.

It restores a client 'session' cookie by unpickling it (insecure
deserialization -> RCE). This host is the ONLY route onto the internal network.
"""

import base64
import pickle  # noqa: S403 - the vulnerability is the point

from flask import Flask, request

app = Flask(__name__)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/")
def home():
    cookie = request.cookies.get("session")
    if not cookie:
        return (
            "<h1>Bastion Portal</h1><p>No session. A returning user sends a "
            "base64 <code>session</code> cookie that we restore.</p>"
        )
    try:
        obj = pickle.loads(base64.b64decode(cookie))  # noqa: S301 - VULN
    except Exception as e:  # noqa: BLE001
        return f"session error: {e}", 400
    return f"Session restored: {obj!r}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # noqa: S104
