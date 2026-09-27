"""RELAY — a bespoke line-based TCP spool service (DELIBERATELY VULNERABLE).

No scanner has a signature for this protocol; you fingerprint the banner and
reverse the verbs. FETCH joins its argument onto the spool dir with no
sanitisation, so a path traversal reads files outside the spool — including the
management console's credentials in ../config/relay.conf.
"""

import os
import socketserver

SPOOL = "/srv/relay/spool"
CREDS = ("svc-relay", "R3lay-svc-9x")


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        authed = False
        self.wfile.write(b"RELAY/1.0 ready\r\n")
        for raw in self.rfile:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split(" ")
            cmd = parts[0].upper()
            if cmd == "HELO":
                self.wfile.write(b"250 hello\r\n")
            elif cmd == "AUTH":
                if len(parts) >= 3 and (parts[1], parts[2]) == CREDS:
                    authed = True
                    self.wfile.write(b"200 authorized\r\n")
                else:
                    self.wfile.write(b"403 denied\r\n")
            elif cmd == "LIST":
                if not authed:
                    self.wfile.write(b"401 auth required\r\n")
                    continue
                names = " ".join(sorted(os.listdir(SPOOL)))
                self.wfile.write(f"250 {names}\r\n".encode())
            elif cmd == "FETCH":
                if not authed:
                    self.wfile.write(b"401 auth required\r\n")
                    continue
                if len(parts) < 2:
                    self.wfile.write(b"500 usage: FETCH <path>\r\n")
                    continue
                path = os.path.join(SPOOL, parts[1])  # VULN: no sanitisation
                try:
                    with open(path, "rb") as fh:
                        data = fh.read()
                    self.wfile.write(f"250 {len(data)} bytes\r\n".encode())
                    self.wfile.write(data + b"\r\n")
                except OSError as exc:
                    self.wfile.write(f"550 {exc}\r\n".encode())
            elif cmd == "QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"502 unknown command\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", 7000), Handler).serve_forever()  # noqa: S104
