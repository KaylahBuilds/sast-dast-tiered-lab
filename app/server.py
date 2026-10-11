"""Local-only HTTP training fixture. Contains deliberate vulnerabilities.

Run from the repository root: python -m app.server --port 8080
Only 127.0.0.1 is permitted. Never expose through a proxy, tunnel, public bind,
port-forward, container publication, or shared host. Local processes/users can
still access it. This standard-library HTTP server is not production software.
"""

import argparse
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sqlite3
from urllib.parse import parse_qs, urlsplit

from app.lookup import SIMULATED_TENANT, make_database, safe_lookup, vulnerable_lookup


LOOPBACK_HOST = "127.0.0.1"
MAX_TARGET_LENGTH = 2048
LAB_WARNING = "Educational vulnerable fixture; synthetic data; do not deploy"


class LabHTTPServer(HTTPServer):
    """Single-request-at-a-time fixture; each lookup gets a fresh database."""

    def get_request(self):
        client_socket, address = super().get_request()
        client_socket.settimeout(2)
        return client_socket, address


class LabHandler(BaseHTTPRequestHandler):
    server_version = "TieredSecurityLab/0.1"
    sys_version = ""

    def log_message(self, format, *args):
        # Do not copy request query strings into logs, even in this fake lab.
        return

    def send_json(self, status: int, payload: dict, *, allow: str | None = None):
        encoded = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Lab-Warning", LAB_WARNING)
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def do_GET(self):
        try:
            if len(self.path) > MAX_TARGET_LENGTH:
                self.send_json(414, {"error": "Request target is too long"})
                return
            target = urlsplit(self.path)
            if target.scheme or target.netloc or target.fragment:
                raise ValueError("Use a local origin-form request target")
            query = parse_qs(
                target.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=4,
                errors="strict",
            )
            if target.path in ("/", "/health"):
                if query:
                    raise ValueError("This endpoint accepts no query parameters")
                self.send_json(200, {
                    "status": "ok",
                    "purpose": LAB_WARNING,
                    "authentication": "none; tenant-alpha is a fixed simulated context",
                    "endpoints": ["/vulnerable/lookup?email=...", "/safe/lookup?email=..."],
                })
                return
            if target.path not in ("/vulnerable/lookup", "/safe/lookup"):
                self.send_json(404, {"error": "Unknown educational endpoint"})
                return
            if set(query) != {"email"} or len(query["email"]) != 1:
                raise ValueError("Supply exactly one email parameter and no other fields")
            if self.headers.get("X-Tenant-ID") is not None:
                raise ValueError("Tenant headers cannot override the fixed simulated context")
            email = query["email"][0]
            mode = "vulnerable" if target.path == "/vulnerable/lookup" else "safe"
            with closing(make_database()) as connection:
                if mode == "vulnerable":
                    rows = vulnerable_lookup(connection, email)
                else:
                    rows = safe_lookup(
                        connection, email, authorized_tenant_id=SIMULATED_TENANT
                    )
            self.send_json(200, {
                "mode": mode,
                "rows": rows,
                "simulated_tenant": SIMULATED_TENANT,
                "warning": LAB_WARNING,
            })
        except (ValueError, UnicodeError):
            self.send_json(400, {"error": "Invalid lookup request; see the lab interface"})
        except sqlite3.Error:
            self.send_json(400, {"error": "The deliberate SQL fixture rejected this query"})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.send_json(405, {"error": "Only GET and HEAD are supported"}, allow="GET, HEAD")

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


def create_server(*, host: str = LOOPBACK_HOST, port: int = 8080) -> LabHTTPServer:
    """Fail closed on non-loopback binding. Port 0 is for ephemeral local tests."""
    if host != LOOPBACK_HOST:
        raise ValueError("This vulnerable fixture may bind only to literal 127.0.0.1")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("Port must be an integer from 0 through 65535")
    return LabHTTPServer((host, port), LabHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=LAB_WARNING)
    parser.add_argument("--port", type=int, default=8080, help="Local port; default 8080")
    args = parser.parse_args(argv)
    try:
        server = create_server(port=args.port)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(f"{LAB_WARNING}\nListening at http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
