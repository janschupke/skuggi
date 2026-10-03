"""Minimal, intentionally-vulnerable SSRF target (build-free, stdlib only).

Two HTTP servers in one container:

* ``:8080`` (PUBLISHED to loopback) exposes ``/`` (health) and ``/fetch?url=``,
  which fetches any URL server-side and returns the body -- a classic SSRF.
* ``:9000`` (NOT published) serves ``/secret``, an "internal metadata" endpoint
  reachable only from inside the container.

The boundary is the point: the host cannot reach ``:9000`` directly, but a
``/fetch`` of ``http://127.0.0.1:9000/secret`` makes the app cross it and hand
the secret back. Loopback-only, offline, no image build.
"""

from __future__ import annotations

import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SECRET = "SSRF-SECRET-a1b2c3d4-internal-only"  # the oracle the e2e test asserts


class _Internal(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = SECRET if self.path == "/secret" else "internal"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_: object) -> None:  # silence
        return


class _Edge(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if parsed.path == "/fetch":
            url = (parse_qs(parsed.query).get("url") or [""])[0]
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310
                    data = resp.read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)
            except Exception as exc:  # noqa: BLE001
                self.send_response(502)
                self.end_headers()
                self.wfile.write(f"fetch failed: {exc}".encode())
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_: object) -> None:
        return


def _serve(port: int, handler: type[BaseHTTPRequestHandler]) -> None:
    ThreadingHTTPServer(("0.0.0.0", port), handler).serve_forever()  # noqa: S104


if __name__ == "__main__":
    threading.Thread(target=_serve, args=(9000, _Internal), daemon=True).start()
    _serve(8080, _Edge)
