import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = Path(__file__).resolve().parents[2]
# The Rust routers whose liveness route the startup waiter must probe.
ROUTERS = {
    'egress': ROOT / 'bins/browser-egressd/src/main.rs',
    'gateway': ROOT / 'crates/browserd-http/src/lib.rs',
}


class StartupTransportTests(unittest.TestCase):
    def run_wait(self, responses, daemon):
        paths = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                self.send_response(responses.get(self.path, 404))
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
        status, paths = self.run_wait({'/healthz': 204, '/readyz': 503}, 'egress')
        self.assertEqual(status, 0)
        self.assertEqual(paths, ['/healthz'])

    def test_gateway_admin_transport_starts_before_safety_initialization(self):
        status, paths = self.run_wait({'/health/live': 200, '/health/ready': 503}, 'gateway')
        self.assertEqual(status, 0)
        self.assertEqual(paths, ['/health/live'])

    def test_failed_health_never_qualifies_startup(self):
        for daemon, path in (('egress', '/healthz'), ('gateway', '/health/live')):
            with self.subTest(daemon=daemon):
                status, paths = self.run_wait({path: 503}, daemon)
                self.assertEqual(status, 1)
                self.assertGreater(len(paths), 0)
                self.assertTrue(all(probed == path for probed in paths))

    @unittest.skipUnless(all(path.is_file() for path in ROUTERS.values()), 'Rust router sources are absent')
    def test_startup_probes_a_liveness_route_the_daemon_serves(self):
        for daemon, router in ROUTERS.items():
            with self.subTest(daemon=daemon):
                routes = set(re.findall(r'\.route\(\s*"([^"]+)"', router.read_text()))
                _status, paths = self.run_wait({}, daemon)
                self.assertGreater(len(paths), 0)
                self.assertLessEqual(set(paths), routes)
                self.assertTrue(set(paths).isdisjoint({'/readyz', '/health/ready'}))


if __name__ == '__main__':
    unittest.main()
