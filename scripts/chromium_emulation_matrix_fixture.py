"""Loopback-only fixtures for the raw CDP emulation compatibility probe."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib.parse import parse_qs, urlsplit


SNAPSHOT = """() => ({
    locale: Intl.DateTimeFormat().resolvedOptions().locale,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    languages: [...navigator.languages],
    user_agent: navigator.userAgent,
    viewport: typeof innerWidth === 'number' ? [innerWidth, innerHeight, devicePixelRatio] : null
})"""


class EmulationFixture:
    def __init__(self, include_workers: bool = True, worker_kind: str | None = None) -> None:
        self.include_workers = include_workers
        self.worker_kind = worker_kind
        self.records: list[dict] = []
        self.lock = threading.Lock()
        self.limit_error: str | None = None
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                pass

            def do_GET(self) -> None:
                self.connection.settimeout(5)
                parsed = urlsplit(self.path)
                phase = parse_qs(parsed.query).get("phase", ["initial"])[0]
                with fixture.lock:
                    if len(fixture.records) >= 2048 or len(self.path) > 4096:
                        fixture.limit_error = "bounded fixture request records or path exceeded"
                        self.send_error(503)
                        return
                    fixture.records.append({
                        "path": self.path,
                        "host": self.headers.get("Host"),
                        "user_agent": self.headers.get("User-Agent"),
                        "accept_language": self.headers.get("Accept-Language"),
                    })
                mime = "text/html"
                if parsed.path == "/echo":
                    mime = "application/json"
                    body = json.dumps({
                        "user_agent": self.headers.get("User-Agent"),
                        "accept_language": self.headers.get("Accept-Language"),
                    })
                elif parsed.path == "/page":
                    body = fixture.page(phase, self.headers.get("Host", "").split(":")[0])
                elif parsed.path == "/child":
                    child_id = parse_qs(parsed.query).get("id", ["iframe"])[0]
                    body = fixture.child(phase, child_id)
                elif parsed.path == "/dedicated.js":
                    mime = "application/javascript"
                    body = fixture.dedicated()
                elif parsed.path == "/shared.js":
                    mime = "application/javascript"
                    body = fixture.shared()
                elif parsed.path == "/service.js":
                    mime = "application/javascript"
                    body = fixture.service()
                else:
                    body = "<!doctype html><title>probe idle</title>"
                data = body.encode()
                if len(data) > 64 * 1024:
                    fixture.limit_error = "bounded fixture response exceeded"
                    self.send_error(503)
                    return
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

        class Server(ThreadingHTTPServer):
            daemon_threads = False
            request_queue_size = 16

            def __init__(self, address, handler) -> None:
                self.request_slots = threading.BoundedSemaphore(16)
                super().__init__(address, handler)

            def process_request(self, request, client_address) -> None:
                request.settimeout(5)
                if not self.request_slots.acquire(blocking=False):
                    fixture.limit_error = "bounded fixture active requests exceeded"
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except Exception:
                    self.request_slots.release()
                    raise

            def process_request_thread(self, request, client_address) -> None:
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self.request_slots.release()

        self.server = Server(("127.0.0.1", 0), Handler)
        try:
            self.other_server = Server(("127.0.0.2", self.server.server_port), Handler)
        except Exception:
            self.server.server_close()
            raise
        self.threads = [threading.Thread(target=server.serve_forever, daemon=True)
                        for server in (self.server, self.other_server)]

    @property
    def port(self) -> int:
        return self.server.server_port

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        for server, thread in zip((self.server, self.other_server), self.threads):
            if thread.is_alive():
                server.shutdown()
            server.server_close()
        for thread in self.threads:
            if thread.ident is not None:
                thread.join(timeout=5)

    def page(self, phase: str, host: str) -> str:
        child_host = "127.0.0.2" if host == "127.0.0.1" else "127.0.0.1"
        return f"""<!doctype html><title>emulation matrix</title><script>
const snapshot = {SNAPSHOT};
const phase = {json.dumps(phase)};
window.samples = {{}};
window.errors = [];
const record = (kind, value) => samples[kind] = value;
window.addEventListener('message', event => {{
    const kind = event.data?.kind;
    if (kind?.startsWith('iframe')) {{
        const frame = document.getElementById(kind === 'iframe2' ? 'peer' : 'child');
        if (frame && frame.src === event.data.href) record(kind, event.data);
    }}
}});
(async () => {{
    const first = snapshot();
    record('page', {{kind:'page', first, current:snapshot(),
        request:await fetch('/echo?kind=page&phase='+phase).then(r=>r.json())}});
    if (!{str(self.include_workers).lower()}) return;
    if ({str(self.worker_kind in (None, 'worker')).lower()}) {{
    const dedicated = new Worker('/dedicated.js?phase='+phase);
    window.dedicated = dedicated;
    dedicated.onmessage = event => record('worker', event.data);
    dedicated.onerror = event => errors.push('dedicated: '+event.message);
    }}
    if ({str(self.worker_kind in (None, 'shared_worker')).lower()}) {{
    const shared = new SharedWorker('/shared.js?phase='+phase);
    window.shared = shared;
    shared.port.onmessage = event => record('shared_worker', event.data);
    shared.port.start();
    }}
    if ({str(self.worker_kind in (None, 'service_worker')).lower()}) try {{
        const registration = await navigator.serviceWorker.register('/service.js?phase='+phase);
        window.registration = registration;
        await navigator.serviceWorker.ready;
        const channel = new MessageChannel();
        channel.port1.onmessage = event => record('service_worker', event.data);
        registration.active.postMessage({{phase}}, [channel.port2]);
    }} catch (error) {{ errors.push('service: '+error); }}
}})().catch(error => errors.push(String(error)));
</script><iframe id="child" src="http://{child_host}:{self.port}/child?phase={phase}"></iframe>"""

    @staticmethod
    def child(phase: str, child_id: str) -> str:
        return f"""<!doctype html><title>cross origin child</title><script>
const snapshot = {SNAPSHOT};
const first = snapshot();
(async () => parent.postMessage({{kind:{json.dumps(child_id)}, href:location.href, first, current:snapshot(),
    request:await fetch('/echo?kind=iframe&phase='+{json.dumps(phase)}).then(r=>r.json())}}, '*'))();
</script>"""

    @staticmethod
    def dedicated() -> str:
        return f"""const snapshot = {SNAPSHOT};
const first = snapshot();
(async () => postMessage({{kind:'worker', first, current:snapshot(),
    request:await fetch('/echo?kind=worker').then(r=>r.json())}}))();"""

    @staticmethod
    def shared() -> str:
        return f"""const snapshot = {SNAPSHOT};
const first = snapshot();
onconnect = async event => {{ const port = event.ports[0]; port.start();
    port.postMessage({{kind:'shared_worker', first, current:snapshot(),
        request:await fetch('/echo?kind=shared_worker').then(r=>r.json())}});
}};"""

    @staticmethod
    def service() -> str:
        return f"""const snapshot = {SNAPSHOT};
const first = snapshot();
addEventListener('install', event => event.waitUntil(skipWaiting()));
addEventListener('activate', event => event.waitUntil(clients.claim()));
addEventListener('message', event => event.waitUntil((async () => {{
    event.ports[0].postMessage({{kind:'service_worker', first, current:snapshot(),
        request:await fetch('/echo?kind=service_worker').then(r=>r.json())}});
}})()));"""
