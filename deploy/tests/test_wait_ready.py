import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer


class StartupTransportTests(unittest.TestCase):
    def run_wait(self, health_status, daemon):
        paths = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                self.send_response(health_status if self.path == '/healthz' else 503)
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = os.environ.copy()
        address = '127.0.0.1:' + str(server.server_port)
        env['BROWSERD_EGRESS_CONTROL_URL'] = 'http://' + address
        env['BROWSERD_BIND'] = address
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parents[1] / 'wait_ready.py'),
                 daemon, '--timeout', '0.4'], env=env,
                capture_output=True, text=True, timeout=3,
            )
            return result.returncode, paths
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_egress_transport_starts_while_effect_readiness_is_unavailable(self):
        status, paths = self.run_wait(204, 'egress')
        self.assertEqual(status, 0)
        self.assertEqual(paths, ['/healthz'])

    def test_gateway_admin_transport_starts_before_safety_initialization(self):
        status, paths = self.run_wait(200, 'gateway')
        self.assertEqual(status, 0)
        self.assertEqual(paths, ['/healthz'])

    def test_failed_health_never_qualifies_startup(self):
        status, paths = self.run_wait(503, 'egress')
        self.assertEqual(status, 1)
        self.assertGreater(len(paths), 0)
        self.assertTrue(all(path == '/healthz' for path in paths))


if __name__ == '__main__':
    unittest.main()
