"""Opt-in loopback integration tests; no arbitrary host or target is accepted.

Default discovery skips these tests. In an environment permitting local sockets,
set RUN_LOCAL_HTTP_TESTS=1 and run python -m unittest discover -s tests -v.
This starts only our own 127.0.0.1 server on an ephemeral port and removes it
afterward. It is application integration evidence, not an external DAST scan.
"""

from http.client import HTTPConnection
import json
import os
from threading import Thread
import unittest
from urllib.parse import urlencode

from app.server import create_server


@unittest.skipUnless(
    os.environ.get("RUN_LOCAL_HTTP_TESTS") == "1",
    "Opt in with RUN_LOCAL_HTTP_TESTS=1 where loopback TCP is permitted",
)
class LiveLoopbackHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(port=0)
        cls.thread = Thread(
            target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        # unittest runs class cleanups even if startup or a test fails.
        cls.addClassCleanup(cls.close_server)
        cls.thread.start()

    @classmethod
    def close_server(cls):
        try:
            if cls.thread.is_alive():
                cls.server.shutdown()
        finally:
            cls.server.server_close()
            if cls.thread.ident is not None:
                cls.thread.join(timeout=2)
        if cls.thread.is_alive():
            raise AssertionError("The self-created loopback server did not stop")

    def request(self, path):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def lookup(self, mode, email):
        return self.request(f"/{mode}/lookup?" + urlencode({"email": email}))

    def test_health_and_ordinary_query_over_real_loopback(self):
        status, body = self.request("/health")
        self.assertEqual(status, 200)
        self.assertIn("Educational", body["purpose"])
        for mode in ("vulnerable", "safe"):
            with self.subTest(mode=mode):
                status, body = self.lookup(mode, "alice@example.test")
                self.assertEqual(status, 200)
                self.assertEqual([row["id"] for row in body["rows"]], [1])

    def test_injection_distinguishes_unsafe_and_fixed_over_real_loopback(self):
        status, unsafe = self.lookup("vulnerable", "' OR 1=1 --")
        self.assertEqual(status, 200)
        self.assertEqual({row["id"] for row in unsafe["rows"]}, {1, 2, 3})
        status, fixed = self.lookup("safe", "' OR 1=1 --")
        self.assertEqual(status, 200)
        self.assertEqual(fixed["rows"], [])

    def test_cross_tenant_lookup_uses_fixed_server_context_over_real_loopback(self):
        status, unsafe = self.lookup("vulnerable", "bob@example.test")
        self.assertEqual(status, 200)
        self.assertEqual([row["tenant_id"] for row in unsafe["rows"]], ["tenant-beta"])
        status, fixed = self.lookup("safe", "bob@example.test")
        self.assertEqual(status, 200)
        self.assertEqual(fixed["simulated_tenant"], "tenant-alpha")
        self.assertEqual(fixed["rows"], [])

    def test_tenant_query_cannot_override_context_over_real_loopback(self):
        path = "/safe/lookup?" + urlencode({
            "email": "bob@example.test", "tenant_id": "tenant-beta"
        })
        self.assertEqual(self.request(path)[0], 400)


if __name__ == "__main__":
    unittest.main()
