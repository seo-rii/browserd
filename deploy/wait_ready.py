#!/usr/bin/env python3
"""Order transport startup; effect readiness and kernel qualification remain separate."""
import argparse
import os
import socket
import time
from urllib.request import build_opener, ProxyHandler

# Transport liveness routes: egress control serves /healthz (bins/browser-egressd) and
# the gateway serves /health/live (crates/browserd-http). Readiness (/readyz and
# /health/ready) reports effect admission separately and must not gate startup.
LIVENESS_PATHS = {"egress": "/healthz", "gateway": "/health/live"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("daemon", choices=("egress", "sandbox", "worker", "gateway"))
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    http = build_opener(ProxyHandler({}))
    while time.monotonic() < deadline:
        try:
            if args.daemon in {"sandbox", "worker"}:
                variable = "BROWSERD_SANDBOX_SOCKET" if args.daemon == "sandbox" else "BROWSERD_WORKER_SOCKET"
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(min(1, max(0.01, deadline - time.monotonic())))
                    probe.connect(os.environ[variable])
                return 0
            base = os.environ["BROWSERD_EGRESS_CONTROL_URL"] if args.daemon == "egress" else "http://" + os.environ["BROWSERD_BIND"]
            # The admin Initialize endpoint must remain reachable before safety admission is ready.
            with http.open(base.rstrip("/") + LIVENESS_PATHS[args.daemon], timeout=1) as response:
                if 200 <= response.status < 300:
                    return 0
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    print(f"{args.daemon} did not become reachable before the startup deadline")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
