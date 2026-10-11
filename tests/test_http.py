"""Offline HTTP protocol tests using the real handler and in-memory byte streams.

These do not establish live TCP connectivity, browser behavior, or a DAST scan.
The server factory binding check is separate and opens no client connection.
"""

from http.client import HTTPResponse
from io import BytesIO
import json
from types import SimpleNamespace
import unittest
from urllib.parse import urlencode

from app.lookup import MAX_EMAIL_LENGTH
from app.server import LabHandler, MAX_TARGET_LENGTH, create_server


class MemoryTransport:
    """Minimal socket-shaped transport for stdlib handler/response parsing."""

    def __init__(self, incoming: bytes):
        self.incoming = BytesIO(incoming)
        self.outgoing = BytesIO()

    def makefile(self, mode, *args):
        if mode != "rb":
            raise AssertionError("Only the handler's binary read stream is expected")
        return self.incoming

    def sendall(self, payload):
        self.outgoing.write(payload)


class OfflineHTTPTests(unittest.TestCase):

    def request(self, path, *, method="GET", headers=None):
        header_lines = ["Host: 127.0.0.1", "Connection: close"]
        header_lines.extend(f"{name}: {value}" for name, value in (headers or {}).items())
        wire_request = (f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(header_lines) + "\r\n\r\n").encode("ascii")
        transport = MemoryTransport(wire_request)
        server = SimpleNamespace(server_address=("127.0.0.1", 8080))
        LabHandler(transport, ("127.0.0.1", 12345), server)
        response = HTTPResponse(MemoryTransport(transport.outgoing.getvalue()), method=method)
        response.begin()
        body = response.read()
        return response.status, dict(response.getheaders()), json.loads(body) if body else None

    def lookup(self, mode, email, **kwargs):
        return self.request(f"/{mode}/lookup?" + urlencode({"email": email}), **kwargs)

    def test_server_binds_only_ipv4_loopback(self):
        server = create_server(port=0)
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
        finally:
            server.server_close()
        for host in ("0.0.0.0", "::", "localhost", "example.test", "192.0.2.1"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                create_server(host=host, port=0)

    def test_invalid_ports_are_rejected_before_binding(self):
        for port in (-1, 65536, "8080", True, None):
            with self.subTest(port=port), self.assertRaises(ValueError):
                create_server(port=port)

    def test_health_labels_the_demo_and_does_not_claim_authentication(self):
        status, headers, body = self.request("/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("Educational", body["purpose"])
        self.assertIn("none", body["authentication"])

    def test_ordinary_lookup_works_over_http_on_both_paths(self):
        for mode in ("vulnerable", "safe"):
            with self.subTest(mode=mode):
                status, _, body = self.lookup(mode, "alice@example.test")
                self.assertEqual(status, 200)
                self.assertEqual([row["id"] for row in body["rows"]], [1])

    def test_http_injection_distinguishes_vulnerable_and_fixed_paths(self):
        status, _, vulnerable = self.lookup("vulnerable", "' OR 1=1 --")
        self.assertEqual(status, 200)
        self.assertEqual(len(vulnerable["rows"]), 3)
        status, _, safe = self.lookup("safe", "' OR 1=1 --")
        self.assertEqual(status, 200)
        self.assertEqual(safe["rows"], [])

    def test_safe_http_context_prevents_cross_tenant_lookup(self):
        status, _, body = self.lookup("safe", "bob@example.test")
        self.assertEqual(status, 200)
        self.assertEqual(body["simulated_tenant"], "tenant-alpha")
        self.assertEqual(body["rows"], [])
        status, _, vulnerable = self.lookup("vulnerable", "bob@example.test")
        self.assertEqual(status, 200)
        self.assertEqual([row["tenant_id"] for row in vulnerable["rows"]], ["tenant-beta"])

    def test_querystring_cannot_assign_tenant_ownership(self):
        path = "/safe/lookup?" + urlencode({"email": "bob@example.test", "tenant_id": "tenant-beta"})
        self.assertEqual(self.request(path)[0], 400)

    def test_tenant_header_cannot_override_simulated_context(self):
        self.assertEqual(self.lookup(
            "safe", "bob@example.test", headers={"X-Tenant-ID": "tenant-beta"}
        )[0], 400)
        # Other client-controlled identity-looking values never establish identity.
        status, _, body = self.lookup(
            "safe", "bob@example.test", headers={"Authorization": "Bearer FAKE-LOCAL-EXAMPLE"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["rows"], [])

    def test_missing_duplicate_blank_and_extra_parameters_are_rejected(self):
        for query in ("", "email=", "email=a&email=b", "email=a&extra=b", "email", "a=1&b=2&c=3&d=4&e=5"):
            with self.subTest(query=query):
                self.assertEqual(self.request("/safe/lookup?" + query)[0], 400)

    def test_overlong_and_control_character_values_are_rejected(self):
        for email in ("x" * (MAX_EMAIL_LENGTH + 1), "alice\x00@example.test", "a\nb"):
            with self.subTest(email=email):
                self.assertEqual(self.lookup("safe", email)[0], 400)

    def test_invalid_unicode_query_is_rejected(self):
        self.assertEqual(self.request("/safe/lookup?email=%FF")[0], 400)

    def test_oversized_request_target_is_rejected(self):
        path = "/safe/lookup?email=" + "x" * MAX_TARGET_LENGTH
        self.assertEqual(self.request(path)[0], 414)

    def test_absolute_request_target_is_rejected(self):
        self.assertEqual(self.request("http://example.test/safe/lookup?email=a")[0], 400)

    def test_malformed_vulnerable_sql_does_not_break_next_request(self):
        self.assertEqual(self.lookup("vulnerable", "'")[0], 400)
        status, _, body = self.lookup("safe", "alice@example.test")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["rows"]), 1)

    def test_unknown_routes_and_unsupported_methods_are_explicit(self):
        self.assertEqual(self.request("/not-a-route")[0], 404)
        status, headers, _ = self.request("/safe/lookup", method="POST")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET, HEAD")

    def test_head_returns_headers_without_a_body(self):
        status, headers, body = self.request("/health", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assertIsNone(body)


if __name__ == "__main__":
    unittest.main()
