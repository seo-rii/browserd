import json
from copy import deepcopy
from pathlib import Path
import unittest
from urllib.parse import parse_qs, urlsplit

from browserd import (
    ArtifactListPage,
    BrowserdClient,
    BrowserdError,
    DispatchUncertainError,
    EventGapError,
    Response,
)


class ScriptedTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, dict(headers), body, timeout))
        next_value = self.responses.pop(0)
        if isinstance(next_value, Exception):
            raise next_value
        return next_value


def response(status, body, headers=None):
    return Response(status=status, headers=headers or {}, body=json.dumps(body).encode())


FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "fixtures/http_contract.json").read_text())


def wire(name, changes=None, trace_id=None):
    value = deepcopy(FIXTURE["responses"][name])
    wrapper = next((key for key in ("operation", "session", "page", "ownership", "artifact", "approval") if key in value["data"]), None)
    target = value["data"][wrapper] if wrapper else value["data"]
    target.update(changes or {})
    value["trace_id"] = trace_id or FIXTURE["ids"]["trace"]
    return value


class ClientTests(unittest.TestCase):
    def test_query_all_preserves_frame_paths_without_adding_legacy_fields(self):
        transport = ScriptedTransport([
            response(200, wire("action_queued", {"action_id": "act-query", "status": "succeeded"}))
            for _ in range(3)
        ])
        client = BrowserdClient("https://api.example", transport=transport)
        for action in [
            {"type": "query_all", "selector": "input"},
            {"type": "query_all", "selector": "input", "frame_path": []},
            {"type": "query_all", "selector": "input", "frame_path": ["iframe#outer", "iframe#inner"]},
        ]:
            body = {
                "page_id": "page-1", "if_session_incarnation": 1,
                "execution_timeout_ms": 30_000, "action": action,
            }
            client.create_action("session-1", body)
            self.assertEqual(json.loads(transport.calls[-1][3]), body)
        self.assertNotIn("frame_path", json.loads(transport.calls[0][3])["action"])

    def test_public_routes_headers_and_escaping(self):
        responses = [response(200, wire(name)) for name in ["operation_queued", "operation_queued", "operation_queued", "sessions", "session", "session", "ownership", "ownership", "pages", "page", "page_deleted", "page", "action_queued", "action_queued", "action_queued", "action_queued", "event_page", "viewer_ticket", "artifact", "artifact", "artifact_download", "approvals", "approval", "approval"]]
        transport = ScriptedTransport(responses)
        client = BrowserdClient("https://api.example/", token="secret", transport=transport)
        client.create_session({}, idempotency_key="idem-session", wait_ms=500)
        client.get_operation("op/a")
        client.cancel_operation("op/a")
        client.list_sessions(lifecycle="ready", limit=50, page_token="next token")
        client.get_session("ses/a")
        client.close_session("ses/a")
        client.reconnect_session(
            "ses/a", {"token": "reconnect-token", "binding": "client-1"}
        )
        client.transfer_session(
            "ses/a", {"new_worker_id": "worker-1", "new_worker_epoch": 2}
        )
        client.list_pages("ses/a")
        client.create_page("ses/a", {"url": "about:blank"})
        client.close_page("ses/a", "pg/a")
        client.activate_page("ses/a", "pg/a")
        client.create_action(
            "ses/a",
            {"action": {"type": "navigate"}},
            idempotency_key="idem-action",
        )
        client.get_action("ses/a", "act/a")
        client.cancel_action("ses/a", "act/a")
        client.resolve_action(
            "ses/a",
            "act/a",
            {"resolution": "abandoned", "basis": "caller_choice"},
        )
        client.list_events(cursor="cur/a", limit=25)
        client.create_viewer_ticket("ses/a", {"scope": "viewer:read"})
        client.create_artifact_upload("ses/a", {"filename": "file.txt"})
        client.get_artifact("ses/a", "art/a")
        client.create_artifact_download_token("ses/a", "art/a")
        client.list_approvals(
            state="pending",
            session_id="ses/a",
            limit=20,
            page_token="next page",
        )
        client.get_approval("apr/a")
        client.decide_approval("apr/a", {"decision": "approve"})
        paths = [
            (method, __import__("urllib.parse").parse.urlsplit(url).path)
            for method, url, *_ in transport.calls
        ]
        self.assertEqual(
            paths,
            [
                ("POST", "/v1/sessions"),
                ("GET", "/v1/operations/op%2Fa"),
                ("DELETE", "/v1/operations/op%2Fa"),
                ("GET", "/v1/sessions"),
                ("GET", "/v1/sessions/ses%2Fa"),
                ("DELETE", "/v1/sessions/ses%2Fa"),
                ("POST", "/v1/sessions/ses%2Fa/reconnect"),
                ("POST", "/v1/sessions/ses%2Fa/transfer"),
                ("GET", "/v1/sessions/ses%2Fa/pages"),
                ("POST", "/v1/sessions/ses%2Fa/pages"),
                ("DELETE", "/v1/sessions/ses%2Fa/pages/pg%2Fa"),
                ("POST", "/v1/sessions/ses%2Fa/pages/pg%2Fa/activate"),
                ("POST", "/v1/sessions/ses%2Fa/actions"),
                ("GET", "/v1/sessions/ses%2Fa/actions/act%2Fa"),
                ("DELETE", "/v1/sessions/ses%2Fa/actions/act%2Fa"),
                ("POST", "/v1/sessions/ses%2Fa/actions/act%2Fa/resolve"),
                ("GET", "/v1/events"),
                ("POST", "/v1/sessions/ses%2Fa/viewer-ticket"),
                ("POST", "/v1/sessions/ses%2Fa/artifacts/uploads"),
                ("GET", "/v1/sessions/ses%2Fa/artifacts/art%2Fa"),
                ("POST", "/v1/sessions/ses%2Fa/artifacts/art%2Fa/download"),
                ("GET", "/v1/approvals"),
                ("GET", "/v1/approvals/apr%2Fa"),
                ("POST", "/v1/approvals/apr%2Fa/decision"),
            ],
        )
        headers = transport.calls[0][2]
        self.assertEqual(headers["Authorization"], "Bearer secret")
        self.assertEqual(headers["Idempotency-Key"], "idem-session")
        self.assertEqual(headers["Prefer"], "wait=500")
        self.assertTrue(headers["X-Request-Id"])
        approval_query = __import__("urllib.parse").parse.urlsplit(
            transport.calls[21][1]
        ).query
        approval_parameters = __import__("urllib.parse").parse.parse_qs(approval_query)
        self.assertEqual(approval_parameters["limit"], ["20"])
        self.assertEqual(approval_parameters["page_token"], ["next page"])
        for bodiless in (11, 20):
            self.assertIsNone(transport.calls[bodiless][3])
            self.assertNotIn("Content-Type", transport.calls[bodiless][2])
        self.assertNotIn("Idempotency-Key", transport.calls[15][2])
        self.assertEqual(
            client.viewer_websocket_url("ses/a"),
            "wss://api.example/v1/sessions/ses%2Fa/viewer",
        )

        read = ScriptedTransport([response(200, wire("session", {"id": "ses-1"}))])
        BrowserdClient("https://api.example", transport=read).get_session(
            "ses-1", request_id="req-read"
        )
        self.assertEqual(read.calls[0][2]["X-Request-Id"], "req-read")

    def test_base_url_validation_and_viewer_url_secret_isolation(self):
        for base_url in (
            "/relative",
            "ftp://api.example",
            "https://user:password@api.example",
            "https://api.example?tenant=other",
            "https://api.example#fragment",
        ):
            with self.subTest(base_url=base_url):
                with self.assertRaises(ValueError):
                    BrowserdClient(base_url)
        client = BrowserdClient(
            "https://api.example/proxy/", token="secret-token"
        )
        viewer = __import__("urllib.parse").parse.urlsplit(
            client.viewer_websocket_url("ses/../other")
        )
        self.assertEqual(
            viewer.geturl(),
            "wss://api.example/proxy/v1/sessions/ses%2F..%2Fother/viewer",
        )
        self.assertIsNone(viewer.username)
        self.assertIsNone(viewer.password)
        self.assertEqual(viewer.query, "")
        self.assertEqual(viewer.fragment, "")
        self.assertNotIn("secret-token", viewer.geturl())

    def test_typed_error_envelope(self):
        transport = ScriptedTransport(
            [
                response(
                    409,
                    {
                        "error": {
                            "code": "idempotency_conflict",
                            "message": "different",
                            "retryable": False,
                            "details": {},
                            "trace_id": "trace-1",
                        }
                    },
                    {"X-Request-Id": "server-req"},
                )
            ]
        )
        client = BrowserdClient("https://api.example", transport=transport)
        with self.assertRaises(BrowserdError) as raised:
            client.get_session("ses-1")
        self.assertEqual(raised.exception.code, "idempotency_conflict")
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(raised.exception.trace_id, "trace-1")
        self.assertEqual(raised.exception.request_id, "server-req")

    def test_mutating_transport_uncertainty_and_outcome_unknown_are_never_replayed(self):
        uncertain = ScriptedTransport([OSError("reset"), response(200, {"status": "succeeded"})])
        client = BrowserdClient("https://api.example", transport=uncertain, max_retries=3)
        with self.assertRaises(DispatchUncertainError) as raised:
            client.create_action("ses-1", {"action": {"type": "click"}}, idempotency_key="idem-1")
        self.assertEqual(raised.exception.idempotency_key, "idem-1")
        self.assertEqual(len(uncertain.calls), 1)

        unknown = ScriptedTransport(
            [
                response(
                    200,
                    wire("action_unknown", {"action_id": "act-1"}),
                )
            ]
        )
        value = BrowserdClient(
            "https://api.example", transport=unknown, max_retries=3
        ).create_action("ses-1", {"action": {"type": "click"}})
        self.assertTrue(BrowserdClient.is_outcome_unknown(value))
        self.assertEqual(value["action_id"], "act-1")
        self.assertEqual(len(unknown.calls), 1)

    def test_download_token_transport_uncertainty_is_never_replayed(self):
        transport = ScriptedTransport(
            [OSError("reset"), response(200, {"token": "bad-replay"})]
        )
        client = BrowserdClient(
            "https://api.example", transport=transport, max_retries=3
        )
        with self.assertRaises(DispatchUncertainError) as raised:
            client.create_artifact_download_token(
                "ses/a", "art/a", request_id="req-download"
            )
        self.assertEqual(raised.exception.request_id, "req-download")
        self.assertEqual(len(transport.calls), 1)

    def test_artifact_metadata_read_is_replay_safe(self):
        artifact = {"id": "art-1", "state": "available", "display_filename": "첨부 문서.txt"}
        transport = ScriptedTransport(
            [
                OSError("reset"),
                response(
                    200, {"data": {"artifact": artifact}, "trace_id": "trace-artifact"}
                ),
            ]
        )
        client = BrowserdClient(
            "https://api.example",
            transport=transport,
            max_retries=1,
            sleep=lambda _: None,
        )
        self.assertEqual(
            client.get_artifact("ses-1", "art-1"), {**artifact, "trace_id": "trace-artifact"}
        )
        self.assertEqual(len(transport.calls), 2)

    def test_artifact_pages_decode_http_envelope_and_encode_cursor(self):
        first: ArtifactListPage = {
            "artifacts": [
                {"id": "art-1", "state": "available", "size_bytes": 0,
                 "content_type": "application/octet-stream", "display_filename": "한" * 85},
                {"id": "art-2", "state": "available", "display_filename": None},
                {"id": "art-3", "state": "available"},
            ],
            "next_cursor": "art/a?&after=other +한글",
        }
        last: ArtifactListPage = {"artifacts": [], "next_cursor": None}
        transport = ScriptedTransport([
            response(200, {"data": first, "trace_id": "trace-1"}),
            response(200, {"data": last, "trace_id": "trace-2"}),
        ])
        client = BrowserdClient("https://api.example/proxy/", transport=transport)
        page = client.list_artifacts("ses/a?&한글", request_id="req-list")
        self.assertEqual(page, {**first, "trace_id": "trace-1"})
        self.assertEqual(client.list_artifacts(
            "ses/a?&한글", after=page["next_cursor"], limit=100,
        ), {**last, "trace_id": "trace-2"})
        initial = urlsplit(transport.calls[0][1])
        self.assertEqual(initial.path,
                         "/proxy/v1/sessions/ses%2Fa%3F%26%ED%95%9C%EA%B8%80/artifacts")
        self.assertEqual(parse_qs(initial.query), {"limit": ["50"]})
        next_page = urlsplit(transport.calls[1][1])
        self.assertEqual(parse_qs(next_page.query),
                         {"after": [first["next_cursor"]], "limit": ["100"]})
        self.assertEqual(next_page.fragment, "")
        for method, _, headers, body, _ in transport.calls:
            self.assertEqual(method, "GET")
            self.assertIsNone(body)
            self.assertNotIn("Idempotency-Key", headers)
        self.assertEqual(transport.calls[0][2]["X-Request-Id"], "req-list")

    def test_invalid_artifact_limits_and_dot_identifiers_never_reach_transport(self):
        transport = ScriptedTransport([])
        client = BrowserdClient("https://api.example", transport=transport)
        for limit in (0, 101, -1, 1.5, float("nan"), float("inf"), True, "50", None):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                client.list_artifacts("ses-1", limit=limit)
        for session_id in ("", ".", ".."):
            with self.subTest(session_id=session_id), self.assertRaises(ValueError):
                client.list_artifacts(session_id)
        self.assertEqual(transport.calls, [])

    def test_artifact_listing_retries_read_with_same_pagination_and_request_identity(self):
        page: ArtifactListPage = {"artifacts": [], "next_cursor": None}
        transport = ScriptedTransport([
            OSError("reset"), response(200, {"data": page, "trace_id": "trace-list"}),
        ])
        client = BrowserdClient("https://api.example", transport=transport,
                                max_retries=1, sleep=lambda _: None)
        self.assertEqual(client.list_artifacts(
            "ses-1", after="art-1", limit=1, request_id="req-list",
        ), {**page, "trace_id": "trace-list"})
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(transport.calls[0][1], transport.calls[1][1])
        for _, _, headers, _, _ in transport.calls:
            self.assertEqual(headers["X-Request-Id"], "req-list")
            self.assertNotIn("Idempotency-Key", headers)

    def test_retries_only_reads_and_explicit_pre_dispatch_errors(self):
        read = ScriptedTransport(
            [
                response(
                    503,
                    {
                        "error": {
                            "code": "worker_unavailable",
                            "message": "retry",
                            "retryable": True,
                            "details": {},
                            "trace_id": "t",
                        }
                    },
                ),
                response(200, wire("session", {"id": "ses-1"})),
            ]
        )
        client = BrowserdClient(
            "https://api.example",
            transport=read,
            max_retries=1,
            sleep=lambda _: None,
        )
        self.assertEqual(client.get_session("ses-1")["id"], "ses-1")
        self.assertEqual(len(read.calls), 2)
        action = ScriptedTransport(
            [
                response(
                    503,
                    {
                        "error": {
                            "code": "action_admission_timeout",
                            "message": "not dispatched",
                            "retryable": True,
                            "details": {},
                            "trace_id": "t",
                        }
                    },
                ),
                response(202, wire("action_queued", {"action_id": "act-1"})),
            ]
        )
        client = BrowserdClient(
            "https://api.example",
            transport=action,
            max_retries=1,
            sleep=lambda _: None,
        )
        client.create_action("ses-1", {"action": {"type": "screenshot"}})
        self.assertEqual(len(action.calls), 2)
        self.assertEqual(
            action.calls[0][2]["Idempotency-Key"],
            action.calls[1][2]["Idempotency-Key"],
        )

    def test_status_only_routing_failure_is_not_treated_as_pre_dispatch(self):
        transport = ScriptedTransport(
            [
                response(
                    503,
                    {
                        "error": {
                            "code": "worker_unavailable",
                            "message": "query action status",
                            "retryable": True,
                            "details": {},
                            "trace_id": "t-status",
                        }
                    },
                ),
                response(200, {"action_id": "act-2", "status": "succeeded"}),
            ]
        )
        client = BrowserdClient(
            "https://api.example",
            transport=transport,
            max_retries=2,
            sleep=lambda _: None,
        )
        with self.assertRaises(BrowserdError) as raised:
            client.create_action("ses-1", {"action": {"type": "click"}})
        self.assertEqual(raised.exception.code, "worker_unavailable")
        self.assertEqual(len(transport.calls), 1)

    def test_undecodable_mutating_response_is_dispatch_uncertain(self):
        transport = ScriptedTransport([Response(200, {}, b"not-json")])
        client = BrowserdClient("https://api.example", transport=transport)
        with self.assertRaises(DispatchUncertainError) as raised:
            client.create_action(
                "ses-1",
                {"action": {"type": "click"}},
                request_id="req-bad",
            )
        self.assertEqual(raised.exception.request_id, "req-bad")
        self.assertEqual(len(transport.calls), 1)

    def test_operation_poll_and_event_resume(self):
        operations = ScriptedTransport(
            [
                response(200, wire("operation_queued", {"id": "op-1", "state": "creating"})),
                response(200, wire("operation_succeeded", {"id": "op-1"})),
            ]
        )
        client = BrowserdClient("https://api.example", transport=operations, sleep=lambda _: None)
        self.assertEqual(
            client.wait_for_operation("op-1", interval=0, max_polls=2)["state"],
            "succeeded",
        )
        events = ScriptedTransport(
            [
                response(
                    200,
                    wire("event_page", {"events": [{**FIXTURE["responses"]["event_page"]["data"]["events"][0], "event_id": "ev-1"}], "next_cursor": "cur-2"}),
                ),
                response(
                    200,
                    wire("event_page", {"events": [{**FIXTURE["responses"]["event_page"]["data"]["events"][0], "event_id": "ev-2"}], "next_cursor": "cur-3"}),
                ),
            ]
        )
        client = BrowserdClient("https://api.example", transport=events, sleep=lambda _: None)
        self.assertEqual(
            [
                event["event_id"]
                for event in client.iter_events(
                    cursor="cur-1", interval=0, max_polls=2
                )
            ],
            ["ev-1", "ev-2"],
        )
        self.assertIn("cursor=cur-2", events.calls[1][1])

    def test_event_resume_surfaces_retention_gap(self):
        events = ScriptedTransport(
            [
                response(
                    200,
                    wire("event_gap", {"next_cursor": "cur-latest"}),
                )
            ]
        )
        client = BrowserdClient("https://api.example", transport=events)
        with self.assertRaises(EventGapError) as raised:
            list(client.iter_events(cursor="cur-expired", max_polls=1))
        self.assertEqual(raised.exception.latest_cursor, "cur-latest")


if __name__ == "__main__":
    unittest.main()
