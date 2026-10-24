"""Container-only logging HTTP proxy. Denies by default, forwards only with explicit opt-in.

Never logs headers or bodies. The server container is attached only to an internal Docker
network; this sidecar is the sole container attached to an additional network with egress.
"""

from __future__ import annotations

import json
import os
import select
import socket
import socketserver
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit


class Proxy(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_CONNECT(self) -> None:
        self.forward(True)

    def do_GET(self) -> None:
        self.forward(False)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_GET

    def forward(self, tunnel: bool) -> None:
        target = urlsplit("//" + self.path if tunnel else self.path)
        host = target.hostname
        try:
            port = target.port or (443 if tunnel else 80)
        except ValueError:
            self.send_error(400)
            return
        print(
            json.dumps(
                {
                    "time": __import__("time").time(),
                    "target": f"{host}:{port}",
                    "allowed": os.environ.get("ALLOW_NETWORK") == "1",
                }
            ),
            flush=True,
        )
        if os.environ.get("ALLOW_NETWORK") != "1":
            self.send_error(403, "MCPiranha default-deny egress")
            return
        if not host or target.scheme not in ("", "http"):
            self.send_error(400)
            return
        try:
            with socket.create_connection((host, port), timeout=5) as upstream:
                if tunnel:
                    self.send_response(200)
                    self.end_headers()
                else:
                    path = target.path or "/"
                    if target.query:
                        path += "?" + target.query
                    upstream.sendall(f"{self.command} {path} HTTP/1.0\r\n".encode())
                    for key, value in self.headers.items():
                        if key.lower() not in (
                            "proxy-authorization",
                            "proxy-connection",
                            "connection",
                        ):
                            upstream.sendall(f"{key}: {value}\r\n".encode())
                    upstream.sendall(b"Connection: close\r\n\r\n")
                    # Reject unbounded/chunked request bodies; callers get an explicit error.
                    remaining = int(self.headers.get("Content-Length", "0"))
                    if remaining > 1_048_576 or self.headers.get("Transfer-Encoding"):
                        return
                    while remaining:
                        block = self.rfile.read(min(remaining, 65536))
                        if not block:
                            return
                        upstream.sendall(block)
                        remaining -= len(block)
                peers = [self.connection, upstream]
                for _ in range(1024):
                    ready, _, _ = select.select(peers, [], [], 10)
                    if not ready:
                        break
                    for peer in ready:
                        data = peer.recv(65536)
                        if not data:
                            return
                        (upstream if peer is self.connection else self.connection).sendall(data)
        except (OSError, ValueError):
            self.close_connection = True


if __name__ == "__main__":

    class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

    with Server(("0.0.0.0", 8080), Proxy) as server:
        server.serve_forever()
