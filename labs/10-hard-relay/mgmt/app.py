"""RELAY management console — DELIBERATELY VULNERABLE practice target.

Serves a legacy client download WITHOUT authentication (which leaks the RELAY
service credentials and documents the protocol), and an /admin area behind HTTP
basic auth whose password lives in the relay config the traversal leaks.
"""

import json

from flask import Flask, Response, request

app = Flask(__name__)
ADMIN = ("relay-admin", "M4nage-R3lay-2026")

with open("/app/records.json", encoding="utf-8") as fh:
    RECORDS = json.load(fh)

CLIENT = """#!/usr/bin/env python3
# Legacy RELAY client (internal tooling). Speaks the RELAY/1.0 line protocol.
#
#   BANNER : "RELAY/1.0 ready"
#   HELO <name>
#   AUTH <user> <pass>        # service account below
#   LIST                      # spool contents (after AUTH)
#   FETCH <path>              # returns a spool file (after AUTH)
#   QUIT
#
# Service credentials (do not commit... again):
RELAY_HOST = "relay.control.lab"
RELAY_PORT = 7000
RELAY_USER = "svc-relay"
RELAY_PASS = "R3lay-svc-9x"
"""


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/")
def index():
    return (
        "<h1>RELAY management console</h1>"
        '<p>Download the <a href="/relay-client.py">legacy client</a>. '
        "Admin area at /admin.</p>"
    )


# VULN: no auth on the client download — leaks the RELAY service credentials.
@app.get("/relay-client.py")
def client():
    return Response(CLIENT, mimetype="text/x-python")


@app.get("/admin")
def admin():
    a = request.authorization
    if not a or a.username != ADMIN[0] or a.password != ADMIN[1]:
        return Response(
            "authentication required", 401, {"WWW-Authenticate": "Basic realm=relay"}
        )
    return RECORDS


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)  # noqa: S104
