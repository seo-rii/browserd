import copy
import json
from pathlib import Path
import unittest

from browserd import BrowserdClient, DispatchUncertainError, EventGapError, Response, TransportError

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "fixtures/http_contract.json").read_text())


def body(name):
    return copy.deepcopy(FIXTURE["responses"][name])


def client_for(responses):
    calls = []
    values = list(responses)

    def transport(method, url, headers, payload, timeout):
        calls.append(url)
        if not values:
            raise AssertionError("invalid response must stop polling")
        return Response(200, {}, json.dumps(values.pop(0)).encode())

    return BrowserdClient("https://api.example", transport=transport, max_retries=0, sleep=lambda _: None), calls


class HttpContractTests(unittest.TestCase):
    def test_operation_envelope_preserves_states_and_session_failure_resources(self):
        for terminal in ["operation_succeeded", "operation_failed", "operation_timed_out"]:
            with self.subTest(terminal=terminal):
                client, _ = client_for([body("operation_queued"), body(terminal)])
                self.assertEqual(client.wait_for_operation("op", max_polls=2), {**body(terminal)["data"]["operation"], "trace_id": FIXTURE["ids"]["trace"]})

    def test_action_events_and_retention_gap_use_the_real_http_shape(self):
        client, _ = client_for([body("action_queued"), body("action_unknown")])
        self.assertEqual(client.wait_for_action("ses", "act", max_polls=2)["status"], "outcome_unknown")
        client, calls = client_for([body("event_page"), {"data": {"events": [], "gap": False, "next_cursor": FIXTURE["ids"]["event"]}, "trace_id": FIXTURE["ids"]["trace"]}])
        self.assertEqual(list(client.iter_events(cursor="old", max_polls=2)), body("event_page")["data"]["events"])
        self.assertIn("cursor=" + FIXTURE["ids"]["event"], calls[1])
        client, _ = client_for([body("event_gap")])
        with self.assertRaises(EventGapError) as error:
            list(client.iter_events(max_polls=1))
        self.assertEqual(error.exception.latest_cursor, FIXTURE["ids"]["event"])

    def test_all_methods_unwrap_envelope_and_endpoint_resource_once(self):
        methods = [
            ("operation_succeeded", lambda c: c.create_session({}), "operation"),
            ("operation_succeeded", lambda c: c.get_operation("op"), "operation"),
            ("operation_succeeded", lambda c: c.cancel_operation("op"), "operation"),
            ("sessions", lambda c: c.list_sessions(), None),
            ("session", lambda c: c.get_session("ses"), "session"),
            ("session", lambda c: c.close_session("ses"), "session"),
            ("ownership", lambda c: c.reconnect_session("ses", {}), "ownership"),
            ("ownership", lambda c: c.transfer_session("ses", {}), "ownership"),
            ("pages", lambda c: c.list_pages("ses"), None),
            ("page", lambda c: c.create_page("ses"), "page"),
            ("page_deleted", lambda c: c.close_page("ses", "pg"), "page"),
            ("page", lambda c: c.activate_page("ses", "pg"), "page"),
            ("action_unknown", lambda c: c.create_action("ses", {"action": {"type": "click"}}), None),
            ("action_unknown", lambda c: c.get_action("ses", "act"), None),
            ("action_unknown", lambda c: c.cancel_action("ses", "act"), None),
            ("action_unknown", lambda c: c.resolve_action("ses", "act", {}), None),
            ("event_page", lambda c: c.list_events(), None),
            ("viewer_ticket", lambda c: c.create_viewer_ticket("ses", {}), None),
            ("artifact", lambda c: c.create_artifact_upload("ses", {}), "artifact"),
            ("artifact", lambda c: c.get_artifact("ses", "art"), "artifact"),
            ("artifacts", lambda c: c.list_artifacts("ses"), None),
            ("artifact_download", lambda c: c.create_artifact_download_token("ses", "art"), None),
            ("approvals", lambda c: c.list_approvals(), None),
            ("approval", lambda c: c.get_approval("apr"), "approval"),
            ("approval", lambda c: c.decide_approval("apr", {}), "approval"),
        ]
        for name, call, wrapper in methods:
            with self.subTest(name=name):
                response = body(name)
                client, _ = client_for([response])
                self.assertEqual(call(client), {**(response["data"][wrapper] if wrapper else response["data"]), "trace_id": response["trace_id"]})
                client, calls = client_for([{"data": {}, "trace_id": FIXTURE["ids"]["trace"]}])
                with self.assertRaises((TransportError, DispatchUncertainError)):
                    call(client)
                self.assertEqual(len(calls), 1)
        for name in ["operation_succeeded", "action_unknown", "session", "pages", "event_page"]:
            invalid = body(name)
            if name == "operation_succeeded":
                invalid["data"]["operation"]["state"] = "bogus"
            elif name == "action_unknown":
                invalid["data"]["status"] = "bogus"
            elif name == "session":
                invalid["data"]["session"]["incarnation"] = "3"
            elif name == "pages":
                invalid["data"]["pages"][0]["document_epoch"] = -1
            else:
                invalid["data"]["gap"] = "true"
            client, _ = client_for([invalid])
            call = {"operation_succeeded": lambda: client.get_operation("op"),
                    "action_unknown": lambda: client.get_action("ses", "act"),
                    "session": lambda: client.get_session("ses"),
                    "pages": lambda: client.list_pages("ses"),
                    "event_page": lambda: client.list_events()}[name]
            with self.subTest(name=name), self.assertRaises(TransportError):
                call()

    def test_invalid_success_fails_once_without_polling_or_replaying_mutation(self):
        for invalid in [None, [], {}, {"data": {}}, {"data": [], "trace_id": FIXTURE["ids"]["trace"]}, {"data": {"operation": {"id": "op", "state": "timedout"}}, "trace_id": FIXTURE["ids"]["trace"]}]:
            with self.subTest(invalid=invalid):
                client, calls = client_for([invalid])
                with self.assertRaises(TransportError):
                    client.wait_for_operation("op", max_polls=10)
                self.assertEqual(len(calls), 1)
        client, calls = client_for([{"data": {}, "trace_id": FIXTURE["ids"]["trace"]}])
        with self.assertRaises(DispatchUncertainError):
            client.create_session({})
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
