#!/usr/bin/env python3
"""Probe raw target emulation with sandbox-enabled Chromium, without qualification.

The browserd owner is deliberately bypassed. Results describe CDP compatibility,
not an approved browser artifact, production admission, or an outer sandbox gate.
Targets attach paused. Service-worker option availability is measured after
resume and explicitly marked unqualified for a startup emulation barrier.
Exit 0 means observations completed; it does not mean every profile matched.
"""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

from chromium_emulation_matrix_fixture import EmulationFixture, SNAPSHOT


PROFILE = {
    "locale": "ko-KR",
    "timezone": "Asia/Seoul",
    "user_agent": "browserd-emulation-matrix/1.0",
    "viewport": [820, 640, 1.25],
}


class Cdp:
    def __init__(self, binary: Path, directory: Path, environment_timezone: str = "UTC",
                 launch_locale: str | None = None, accept_language: str | None = None,
                 environment_locale: str | None = None) -> None:
        chromium_environment = os.environ.copy()
        chromium_environment["TZ"] = environment_timezone
        if environment_locale:
            chromium_environment["LANG"] = environment_locale
            chromium_environment["LC_ALL"] = environment_locale
        command_read, command_write = os.pipe()
        event_read, event_write = os.pipe()
        arguments = ["--headless", "--remote-debugging-pipe", "--no-startup-window",
                     "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
                     "--disable-component-update", "--disable-extensions",
                     "--disable-component-extensions-with-background-pages",
                     "--disable-features=PreloadTopChromeWebUI,WebUIOmniboxPopup,WebUIOmniboxAimPopup",
                     "--site-per-process", "--disable-dev-shm-usage", f"--user-data-dir={directory / 'profile'}"]
        if launch_locale:
            arguments.append(f"--lang={launch_locale}")
        if accept_language:
            arguments.append(f"--accept-lang={accept_language}")
        self.process = subprocess.Popen(
            [sys.executable, __file__, "--exec", str(binary), str(command_read),
             str(event_write), json.dumps(arguments)],
            pass_fds=(command_read, event_write), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, env=chromium_environment,
        )
        os.close(command_read)
        os.close(event_write)
        self.command_stream = os.fdopen(command_write, "wb", buffering=0)
        self.event_stream = os.fdopen(event_read, "rb", buffering=0)
        self.next_id = 0
        self.write_lock = threading.Lock()
        self.dispatch_thread = threading.get_ident()
        self.condition = threading.Condition()
        self.responses: dict[int, dict] = {}
        self.response_sizes: dict[int, int] = {}
        self.events: deque[tuple[dict, int]] = deque()
        self.queued_bytes = 0
        self.reader_error: str | None = None
        self.ended = False
        self.handling_event = False
        self.event_handler = lambda event: None
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        frames = bytearray()
        try:
            while chunk := os.read(self.event_stream.fileno(), 65536):
                frames.extend(chunk)
                if len(frames) > 4 * 1024 * 1024:
                    raise ValueError("bounded CDP frame exceeded")
                while (end := frames.find(0)) >= 0:
                    frame_size = end + 1
                    message = json.loads(frames[:end])
                    del frames[:end + 1]
                    with self.condition:
                        if self.queued_bytes + frame_size > 8 * 1024 * 1024:
                            raise ValueError("bounded CDP queue bytes exceeded")
                        if "id" in message:
                            if len(self.responses) >= 256:
                                raise ValueError("bounded CDP response queue exceeded")
                            self.responses[message["id"]] = message
                            self.response_sizes[message["id"]] = frame_size
                        else:
                            if len(self.events) >= 2048:
                                raise ValueError("bounded CDP event queue exceeded")
                            self.events.append((message, frame_size))
                        self.queued_bytes += frame_size
                        self.condition.notify_all()
        except (OSError, ValueError) as error:
            self.reader_error = str(error)[:512]
        finally:
            with self.condition:
                self.ended = True
                self.condition.notify_all()

    def pump(self) -> None:
        if self.handling_event:
            return
        while True:
            with self.condition:
                if not self.events:
                    return
                event, frame_size = self.events.popleft()
                self.queued_bytes -= frame_size
            self.handling_event = True
            try:
                self.event_handler(event)
            finally:
                self.handling_event = False

    def command(self, method: str, params: dict | None = None,
                session: str | None = None, timeout: float = 10) -> dict:
        with self.write_lock:
            self.next_id += 1
            command_id = self.next_id
            message = {"id": command_id, "method": method, "params": params or {}}
            if session:
                message["sessionId"] = session
            self.command_stream.write(json.dumps(message).encode() + b"\0")
        deadline = time.monotonic() + timeout
        while True:
            if threading.get_ident() == self.dispatch_thread:
                self.pump()
            with self.condition:
                if command_id in self.responses:
                    self.queued_bytes -= self.response_sizes.pop(command_id)
                    return self.responses.pop(command_id)
                if self.ended:
                    raise RuntimeError(self.reader_error or "Chromium CDP pipe closed")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"CDP {method} exceeded deadline")
                self.condition.wait(timeout=min(remaining, 0.05))

    def checked(self, method: str, params: dict | None = None,
                session: str | None = None) -> dict:
        response = self.command(method, params, session)
        if "error" in response:
            raise RuntimeError(f"{method}: {response['error']}")
        return response.get("result", {})

    def close(self) -> None:
        self.event_handler = lambda event: None
        try:
            self.command("Browser.close", timeout=3)
        except (RuntimeError, OSError, TimeoutError):
            pass
        self.command_stream.close()
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        with self.condition:
            self.ended = True
            self.condition.notify_all()
        self.reader.join(timeout=3)
        self.event_stream.close()


class Probe:
    def __init__(self, cdp: Cdp, policy: str) -> None:
        self.cdp = cdp
        self.policy = policy
        self.targets: dict[str, dict] = {}
        self.attachments: list[dict] = []
        self.page_session: str | None = None
        self.page_bootstrapped = threading.Event()
        self.bootstrap_threads: list[threading.Thread] = []
        cdp.event_handler = self.event

    def event(self, event: dict) -> None:
        if event.get("method") == "Target.detachedFromTarget":
            record = self.targets.get(event.get("params", {}).get("sessionId"))
            if record is not None:
                record["detached"] = True
            return
        if event.get("method") != "Target.attachedToTarget":
            return
        params = event["params"]
        info = params["targetInfo"]
        session = params["sessionId"]
        if session in self.targets:
            return
        if len(self.targets) >= 128:
            raise RuntimeError("bounded target/bootstrap-thread count exceeded")
        record = {
            "kind": info["type"], "target_id": info["targetId"],
            "session_id": session, "url": info.get("url", ""),
            "paused": params.get("waitingForDebugger"), "commands": {},
        }
        self.targets[session] = record
        self.attachments.append(record)
        print(json.dumps({"attached": record["kind"], "url": record["url"],
                          "paused": record["paused"]}), flush=True)
        kind = record["kind"]
        if kind == "page" and self.page_session is None:
            self.page_session = session
        thread = threading.Thread(target=self.bootstrap, args=(record,), daemon=True)
        self.bootstrap_threads.append(thread)
        try:
            thread.start()
        except RuntimeError as error:
            record["bootstrap_error"] = str(error)[:512]
            raise

    def bootstrap(self, record: dict) -> None:
        try:
            self._bootstrap(record)
            record["bootstrap_complete"] = True
        except (OSError, RuntimeError, TimeoutError) as error:
            record["bootstrap_error"] = str(error)
        finally:
            if record["session_id"] == self.page_session:
                self.page_bootstrapped.set()

    def _bootstrap(self, record: dict) -> None:
        kind = record["kind"]
        session = record["session_id"]
        # Service-worker Runtime.enable waits for renderer initialization while
        # the startup pause is held. Do not make that observational command a
        # prerequisite for installing options or releasing the startup pause.
        if kind in ("page", "iframe"):
            for method, arguments in [
                ("Runtime.enable", {}),
                ("Network.enable", {}),
                ("Page.enable", {}),
                ("Target.setAutoAttach", {"autoAttach": True,
                                          "waitForDebuggerOnStart": True, "flatten": True}),
            ]:
                record["commands"][method] = self.outcome(method, arguments, session)
            if kind == "iframe":
                record["before_override_readback"] = self.paused_readback(session)
        apply_options = (kind == "page" and self.policy != "baseline") or self.policy == "per-target"
        option_commands = [
                ("Emulation.setDeviceMetricsOverride", {
                    "width": PROFILE["viewport"][0], "height": PROFILE["viewport"][1],
                    "deviceScaleFactor": PROFILE["viewport"][2], "mobile": False}),
                ("Emulation.setLocaleOverride", {"locale": PROFILE["locale"]}),
                ("Emulation.setTimezoneOverride", {"timezoneId": PROFILE["timezone"]}),
                ("Emulation.setUserAgentOverride", {
                    "userAgent": PROFILE["user_agent"], "acceptLanguage": PROFILE["locale"]}),
            ]
        # A service worker is attached before its renderer's protocol handler is
        # initialized. Probe its domains after resume and label the result so it
        # cannot be confused with an acknowledged startup emulation barrier.
        if apply_options and kind != "service_worker":
            record["option_installation"] = "before_resume"
            for method, arguments in option_commands:
                record["commands"][method] = self.outcome(method, arguments, session)
        if kind == "iframe":
            record["before_resume_readback"] = self.paused_readback(session)
        record["commands"]["Runtime.runIfWaitingForDebugger"] = self.outcome(
            "Runtime.runIfWaitingForDebugger", {}, session)
        if kind not in ("page", "iframe"):
            record["commands"]["Runtime.enable"] = self.outcome("Runtime.enable", {}, session)
            if apply_options and kind == "service_worker":
                record["option_installation"] = "after_resume_unqualified"
                for method, arguments in option_commands:
                    record["commands"][method] = self.outcome(method, arguments, session)
            for method, arguments in [("Network.enable", {}), ("Page.enable", {})]:
                record["commands"][method] = self.outcome(method, arguments, session)
            record["after_resume_readback"] = self.cdp.checked("Runtime.evaluate", {
                "expression": f"(async () => ({{snapshot:({SNAPSHOT})(), request:await fetch('/echo?kind=after-bootstrap').then(r=>r.json())}}))()",
                "returnByValue": True, "awaitPromise": True,
            }, session).get("result", {}).get("value")

    def outcome(self, method: str, arguments: dict, session: str) -> dict:
        response = self.cdp.command(method, arguments, session)
        return {"error": response["error"]} if "error" in response else {"ok": True}

    def paused_readback(self, session: str) -> dict:
        try:
            response = self.cdp.command("Runtime.evaluate", {
                "expression": f"({SNAPSHOT})()", "returnByValue": True,
            }, session, timeout=2)
            return response.get("result", response)
        except TimeoutError as error:
            return {"timeout": str(error)}

    def evaluate(self, expression: str) -> object:
        assert self.page_session
        result = self.cdp.checked("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True,
        }, self.page_session)
        if "exceptionDetails" in result:
            raise RuntimeError(str(result["exceptionDetails"]))
        return result.get("result", {}).get("value")

    def wait_samples(self, expected: set[str], timeout: float = 20,
                     phase: str | None = None) -> dict:
        deadline = time.monotonic() + timeout
        last = {}
        while time.monotonic() < deadline:
            self.cdp.pump()
            last = self.evaluate("({samples:window.samples||{}, errors:window.errors||[], ready:document.readyState, phase:typeof phase==='string'?phase:null})")
            bootstrapped = all(record.get("bootstrap_complete") or record.get("bootstrap_error")
                               for record in self.attachments)
            if expected <= set(last["samples"]) and bootstrapped and (phase is None or last["phase"] == phase):
                return last
            with self.cdp.condition:
                self.cdp.condition.wait(timeout=0.05)
        return {**last, "missing": sorted(expected - set(last["samples"])), "wait_timeout": True}


def run_scenario(binary: Path, policy: str, include_workers: bool = True,
                 environment_timezone: str = "UTC", launch_locale: str | None = None,
                 accept_language: str | None = None, environment_locale: str | None = None,
                 worker_kind: str | None = None) -> dict:
    scenario = {"policy": policy, "worker_kind": worker_kind, "targets": [],
                "observations": {}, "requests": [], "cleanup": {}}
    fixture = EmulationFixture(include_workers, worker_kind)
    scenario["requests"] = fixture.records
    try:
        fixture.start()
        with tempfile.TemporaryDirectory(prefix="browserd-emulation-matrix-") as temporary:
            cdp = Cdp(binary, Path(temporary), environment_timezone, launch_locale,
                      accept_language, environment_locale)
            cleanup = {"chromium_pid": cdp.process.pid}
            scenario["cleanup"] = cleanup
            probe = None
            try:
                version = cdp.checked("Browser.getVersion")
                scenario["version"] = version
                print(json.dumps({"policy": policy, "version": version}), flush=True)
                probe = Probe(cdp, policy)
                scenario["targets"] = probe.attachments
                cdp.checked("Target.setAutoAttach", {
                    "autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True,
                })
                context = cdp.checked("Target.createBrowserContext")["browserContextId"]
                target = cdp.checked("Target.createTarget", {
                    "url": "about:blank", "browserContextId": context,
                })["targetId"]
                deadline = time.monotonic() + 5
                while not probe.page_bootstrapped.is_set() and time.monotonic() < deadline:
                    cdp.pump()
                    with cdp.condition:
                        cdp.condition.wait(timeout=0.05)
                if not probe.page_bootstrapped.is_set():
                    raise TimeoutError("page did not complete paused bootstrap")
                if "bootstrap_error" in probe.targets[probe.page_session]:
                    raise RuntimeError(probe.targets[probe.page_session]["bootstrap_error"])
                expected = {"page", "iframe"}
                if include_workers:
                    expected |= {worker_kind} if worker_kind else {"worker", "shared_worker", "service_worker"}
                observations = scenario["observations"]
                for phase, host in [("initial", "127.0.0.1"), ("renderer-swap", "127.0.0.2")]:
                    scenario["active_phase"] = phase
                    # A phase-specific query ensures workers are recreated and observed.
                    cdp.checked("Page.navigate", {
                        "url": f"http://{host}:{fixture.port}/page?phase={phase}",
                    }, probe.page_session)
                    observations[phase] = probe.wait_samples(expected, phase=phase)
                    if phase == "initial":
                        probe.evaluate("delete samples.iframe; document.getElementById('child').src += '&reload=1'; true")
                        observations["iframe-reload"] = probe.wait_samples(expected, phase=phase)
                        probe.evaluate("const peer=document.createElement('iframe'); peer.id='peer'; peer.src=document.getElementById('child').src+'&id=iframe2'; document.body.append(peer); true")
                        observations["two-iframes"] = probe.wait_samples(expected | {"iframe2"}, phase=phase)
                        peer_session = None
                        for session, record in list(probe.targets.items()):
                            if record["kind"] != "iframe" or record.get("detached"):
                                continue
                            location = cdp.checked("Runtime.evaluate", {
                                "expression": "location.href", "returnByValue": True,
                            }, session).get("result", {}).get("value", "")
                            if "id=iframe2" in location:
                                peer_session = session
                        probe.evaluate("document.getElementById('child').remove(); true")
                        if peer_session:
                            observations["first-iframe-owner-removed"] = {
                                "peer_readback": cdp.checked("Runtime.evaluate", {
                                    "expression": f"({SNAPSHOT})()", "returnByValue": True,
                                }, peer_session).get("result", {}).get("value"),
                            }
                cdp.checked("Target.closeTarget", {"targetId": target})
                cdp.checked("Target.disposeBrowserContext", {"browserContextId": context})
                scenario.pop("active_phase", None)
            except Exception as error:
                scenario["error"] = {"type": type(error).__name__, "message": str(error)[:1024]}
            finally:
                try:
                    cdp.close()
                except Exception as error:
                    scenario["cleanup_error"] = str(error)[:1024]
                finally:
                    cleanup["chromium_exit_code"] = cdp.process.returncode
                    cleanup["reader_thread_joined"] = not cdp.reader.is_alive()
                    if probe is not None:
                        for thread in probe.bootstrap_threads:
                            if thread.ident is not None:
                                thread.join(timeout=2)
                        cleanup["bootstrap_threads"] = len(probe.bootstrap_threads)
                        cleanup["bootstrap_threads_joined"] = all(
                            not thread.is_alive() for thread in probe.bootstrap_threads)
                    if (cdp.process.returncode is None or cdp.reader.is_alive()
                        or not cleanup.get("bootstrap_threads_joined", True)):
                        scenario["cleanup_error"] = "browser or probe threads did not finish cleanup"
    finally:
        try:
            fixture.close()
        except Exception as error:
            scenario["cleanup_error"] = str(error)[:1024]
        scenario["cleanup"]["fixture_server_threads_joined"] = all(
            not thread.is_alive() for thread in fixture.threads)
        if fixture.limit_error:
            scenario["fixture_error"] = fixture.limit_error
    return scenario


def main() -> int:
    if len(sys.argv) == 6 and sys.argv[1] == "--exec":
        binary, command_read, event_write, arguments = sys.argv[2:]
        os.dup2(int(command_read), 3, inheritable=True)
        os.dup2(int(event_write), 4, inheritable=True)
        for descriptor in (int(command_read), int(event_write)):
            if descriptor > 4:
                os.close(descriptor)
        os.execv(binary, [binary, *json.loads(arguments)])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--skip-workers", action="store_true",
                        help="Isolate page/OOPIF ownership and paused readback probes")
    parser.add_argument("--worker-kind", choices=("worker", "shared_worker", "service_worker"),
                        help="Isolate one worker kind so unavailable domains cannot hide other probes")
    parser.add_argument("--policies", nargs="+", choices=("baseline", "parent-only", "per-target"),
                        default=["baseline", "parent-only", "per-target"])
    parser.add_argument("--environment-timezone", default="UTC")
    parser.add_argument("--environment-locale")
    parser.add_argument("--launch-locale")
    parser.add_argument("--launch-accept-language")
    args = parser.parse_args()
    binary = args.chromium.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Chromium must be an executable file")
    with binary.open("rb") as source:
        binary_digest = hashlib.file_digest(source, "sha256").hexdigest()
    report = {
        "qualification": "raw CDP local functional compatibility only; Chromium sandbox enabled; artifact is not approved",
        "exit_zero_means": "observations completed; does not establish profile correctness",
        "binary": {"path": str(binary), "sha256": binary_digest, "approved": False},
        "profile": PROFILE,
        "chromium_environment": {"TZ": args.environment_timezone,
                                 "LANG/LC_ALL": args.environment_locale},
        "launch_flags": {"lang": args.launch_locale, "accept_lang": args.launch_accept_language},
        "include_workers": not args.skip_workers,
        "scenarios": [],
    }
    for policy in args.policies:
        try:
            scenario = run_scenario(binary, policy, not args.skip_workers,
                                    args.environment_timezone, args.launch_locale,
                                    args.launch_accept_language, args.environment_locale,
                                    args.worker_kind)
        except Exception as error:
            scenario = {"policy": policy, "observations": {}, "error": {
                "type": type(error).__name__, "message": str(error)[:1024]}}
        report["scenarios"].append(scenario)
    encoded = json.dumps(report, indent=2) + "\n"
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write(encoded)
    missing = [
        {"policy": scenario["policy"], "phase": phase, "missing": data["missing"],
         "wait_timeout": data.get("wait_timeout", False)}
        for scenario in report["scenarios"] for phase, data in scenario["observations"].items()
        if data.get("missing") or data.get("wait_timeout")
    ]
    print(json.dumps({"output": str(args.output), "missing": missing}), flush=True)
    failed = any(
        scenario.get("error") or scenario.get("cleanup_error") or scenario.get("fixture_error")
        or any(target.get("bootstrap_error") for target in scenario.get("targets", []))
        for scenario in report["scenarios"])
    return 1 if missing or failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
