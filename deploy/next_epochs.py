#!/usr/bin/env python3
"""Print next-incarnation bindings while ALL four browserd daemons are stopped.

Read-only: does not allocate, reset, or write epoch state. If any daemon start consumes an
epoch and fails, stop the stack and calculate again before retrying. Sandboxd deliberately
uses the same durable daemon-epoch record format as egressd. Never delete epoch files to retry.
"""
import argparse
from pathlib import Path
import re


def next_epoch(path: Path, *, daemon: bool) -> int:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("epoch state path must not contain symlinks")
    try:
        if not path.is_file() or path.stat().st_size > 64:
            if not path.exists():
                return 1
            raise ValueError("epoch state must be a bounded regular file")
        text = path.read_text()
    except FileNotFoundError:
        return 1
    pattern = r"browserd-egressd-daemon-epoch-v1\n([1-9][0-9]*)\n" if daemon else r"([0-9]+)\n?"
    match = re.fullmatch(pattern, text)
    if not match:
        raise ValueError("epoch state has the wrong durable record format")
    previous = int(match.group(1))
    if previous >= 2**64 - 1:
        raise ValueError("epoch space is exhausted")
    return previous + 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-state", type=Path, required=True)
    parser.add_argument("--egress-state", type=Path, required=True)
    parser.add_argument("--sandbox-state", type=Path, required=True)
    args = parser.parse_args()
    worker = next_epoch(args.worker_state, daemon=False)
    egress = next_epoch(args.egress_state, daemon=True)
    sandbox = next_epoch(args.sandbox_state, daemon=True)
    print(f"BROWSERD_WORKER_EPOCH={worker}")
    print(f"BROWSER_EGRESS_WORKER_EPOCH={worker}")
    print(f"BROWSERD_EGRESS_DAEMON_EPOCH={egress}")
    print(f"BROWSERD_SANDBOXD_EPOCH={sandbox}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
