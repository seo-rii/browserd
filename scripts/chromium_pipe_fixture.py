#!/usr/bin/env python3
"""Test-only stdio bridge to sandbox-enabled Chromium's private CDP pipes.

This bypasses production artifact/sandbox qualification solely for local functional
tests. It never disables Chromium's own sandbox or exposes a debugging TCP port.
"""

import os
import json
import re
from pathlib import Path
import subprocess
import sys
import threading


def main() -> int:
    if len(sys.argv) == 8 and sys.argv[1] == "--exec":
        binary, profile, command_fd, event_fd, user_agent, locale = sys.argv[2:]
        os.dup2(int(command_fd), 3, inheritable=True)
        os.dup2(int(event_fd), 4, inheritable=True)
        for fd in (int(command_fd), int(event_fd)):
            if fd > 4:
                os.close(fd)
        arguments = [binary, "--headless", "--remote-debugging-pipe",
                         "--no-startup-window", "--no-first-run", "--no-default-browser-check",
                         "--disable-background-networking", "--disable-component-update",
                         "--disable-extensions", "--disable-component-extensions-with-background-pages",
                         "--disable-features=PreloadTopChromeWebUI,WebUIOmniboxPopup,WebUIOmniboxAimPopup",
                         "--site-per-process", "--disable-dev-shm-usage",
                         f"--user-data-dir={profile}"]
        if user_agent:
            if len(user_agent.encode()) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in user_agent):
                raise ValueError("invalid test user agent")
            arguments.append(f"--user-agent={user_agent}")
        if locale:
            if len(locale) > 64 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*", locale):
                raise ValueError("invalid test locale")
            arguments.extend([f"--lang={locale}", f"--accept-lang={locale}"])
        os.execv(binary, arguments)
    if len(sys.argv) not in (4, 5, 6):
        raise ValueError("expected Chromium executable, private profile, and private event evidence file")
    binary = Path(sys.argv[1]).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Chromium must be an executable file")
    evidence = os.open(sys.argv[3], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    command_read, command_write = os.pipe()
    event_read, event_write = os.pipe()
    child = subprocess.Popen(
        [sys.executable, __file__, "--exec", str(binary), sys.argv[2],
         str(command_read), str(event_write), sys.argv[4] if len(sys.argv) >= 5 else "",
         sys.argv[5] if len(sys.argv) == 6 else ""],
        pass_fds=(command_read, event_write), stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
    os.close(command_read)
    os.close(event_write)

    def copy(source: int, destination: int, trace: bool = False) -> None:
        frames = bytearray()
        evidence_bytes = 0
        diagnostics = os.environ.get("BROWSERD_TEST_CDP_DIAGNOSTICS") == "1"
        diagnostic_count = 0
        try:
            while data := os.read(source, 64 * 1024):
                if trace or diagnostics:
                    frames.extend(data)
                    if len(frames) > 4 * 1024 * 1024:
                        raise OSError("bounded CDP evidence frame exceeded")
                    while (end := frames.find(0)) >= 0:
                        frame = json.loads(frames[:end])
                        del frames[:end + 1]
                        if diagnostics and diagnostic_count < 128:
                            record = {"direction": "event" if trace else "command",
                                      "id": frame.get("id"), "method": frame.get("method"),
                                      "has_session": "sessionId" in frame}
                            if "error" in frame:
                                record["error"] = str(frame["error"])[:256]
                            if frame.get("method") == "Target.attachedToTarget":
                                record["kind"] = frame["params"]["targetInfo"].get("type")
                                record["paused"] = frame["params"].get("waitingForDebugger")
                                internal_url = frame["params"]["targetInfo"].get("url", "")
                                if internal_url.startswith(("chrome://", "chrome-untrusted://")):
                                    record["internal_ui"] = internal_url[:256]
                            print("CDP_FIXTURE " + json.dumps(record), file=sys.stderr, flush=True)
                            diagnostic_count += 1
                        if trace and frame.get("method") == "Target.attachedToTarget":
                            # Only target kinds and opaque IDs; never persist document/input data.
                            info = frame.get("params", {}).get("targetInfo", {})
                            encoded = (json.dumps({"attached_target_kind": info.get("type"),
                                                   "target_id": info.get("targetId")}) + "\n").encode()
                            evidence_bytes += len(encoded)
                            if evidence_bytes > 1024 * 1024:
                                raise OSError("bounded CDP evidence exceeded")
                            os.write(evidence, encoded)
                remaining = memoryview(data)
                while remaining:
                    written = os.write(destination, remaining)
                    remaining = remaining[written:]
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                os.close(destination)
            except OSError:
                pass

    incoming = threading.Thread(target=copy, args=(0, command_write), daemon=True)
    outgoing = threading.Thread(target=copy, args=(event_read, 1, True), daemon=True)
    incoming.start()
    outgoing.start()
    try:
        return child.wait(timeout=180)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
