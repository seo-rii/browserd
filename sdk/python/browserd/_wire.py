"""Validate the HTTP success envelope before returning a public resource."""

from datetime import datetime
from typing import Any, Callable

OPERATION_STATES = {"accepted", "queued", "reserving", "creating", "succeeded", "failed", "timed_out", "cancelled"}
ACTION_STATES = {"accepted", "queued", "pending_approval", "ready_to_dispatch", "may_have_executed", "succeeded", "failed_known", "cancelled_before_dispatch", "cancelled_confirmed", "outcome_unknown"}
SESSION_STATES = {"creating", "ready", "closing", "closed", "failed"}
ISOLATIONS = {"shared_context", "tenant_dedicated_shard", "dedicated_process", "dedicated_worker"}
ARTIFACT_STATES = {"uploading", "stored", "scanning", "available", "quarantined", "rejected", "generating", "finalizing", "failed", "deleting", "deleted"}
EVENT_KINDS = {"operation.state_changed", "session.lifecycle_changed", "session.execution_changed", "action.state_changed", "action.approval_required", "approval.decided", "browser.control.changed", "download.completed", "artifact.state_changed"}


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("invalid browserd success response")


def obj(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict))
    return value


def string(value: Any) -> None:
    require(isinstance(value, str) and bool(value))


def integer(value: Any, minimum: int = 0) -> None:
    require(type(value) is int and value >= minimum)


def state(value: Any, states: set[str]) -> None:
    require(isinstance(value, str) and value in states)


def cursor(value: Any) -> None:
    if value is not None:
        string(value)


def array(value: Any, check: Callable[[Any], None]) -> None:
    require(isinstance(value, list))
    for item in value:
        check(item)


def session(value: Any) -> None:
    value = obj(value)
    string(value.get("id"))
    state(value.get("state"), SESSION_STATES)
    state(value.get("lifecycle"), SESSION_STATES)
    require(value["state"] == value["lifecycle"])
    integer(value.get("incarnation"), 1)
    state(value.get("requested_isolation"), ISOLATIONS)
    state(value.get("effective_isolation"), ISOLATIONS)
    require(all(isinstance(v, str) for v in obj(value.get("metadata")).values()))


def operation(value: Any) -> None:
    value = obj(value)
    string(value.get("id"))
    string(value.get("poll_url"))
    state(value.get("state"), OPERATION_STATES)
    require("session" in value and "failure" in value)
    if value["session"] is not None:
        session(value["session"])
    if value["failure"] is not None:
        failure = obj(value["failure"])
        string(failure.get("code"))
        require(isinstance(failure.get("message"), str) and type(failure.get("retryable")) is bool)
        require(all(isinstance(v, str) for v in obj(failure.get("details")).values()))
    require(value["state"] != "succeeded" or (value["session"] is not None and value["failure"] is None))
    require(value["state"] == "succeeded" or value["session"] is None)


def page(value: Any) -> None:
    value = obj(value)
    string(value.get("id"))
    string(value.get("session_id"))
    require(type(value.get("active")) is bool)
    integer(value.get("target_incarnation"), 1)
    integer(value.get("document_epoch"), 1)
    integer(value.get("url_revision"))


def action(value: Any) -> None:
    value = obj(value)
    string(value.get("action_id"))
    state(value.get("status"), ACTION_STATES)
    integer(value.get("session_sequence"), 1)
    if value["status"] == "outcome_unknown":
        require(value.get("retryable") is False)


def artifact(value: Any) -> None:
    value = obj(value)
    string(value.get("id"))
    state(value.get("state"), ARTIFACT_STATES)
    if value.get("size_bytes") is not None:
        integer(value["size_bytes"])
    for field in ("content_type", "display_filename"):
        if value.get(field) is not None:
            require(isinstance(value[field], str))


def approval(value: Any) -> None:
    value = obj(value)
    for field in ("id", "session_id", "action_id"):
        string(value.get(field))
    state(value.get("state"), {"pending", "approved", "denied", "expired"})
    obj(value.get("summary"))


def event(value: Any) -> None:
    value = obj(value)
    string(value.get("event_id"))
    state(value.get("kind"), EVENT_KINDS)
    string(value.get("created_at"))
    require(datetime.fromisoformat(value["created_at"].replace("Z", "+00:00")).tzinfo is not None)
    resource = obj(value.get("resource"))
    state(resource.get("type"), {"operation", "session", "action", "approval", "artifact"})
    string(resource.get("id"))
    integer(value.get("aggregate_revision"))
    if "session_id" in value:
        string(value["session_id"])
    if "summary" in value:
        summary = obj(value["summary"])
        states = {"operation": OPERATION_STATES, "session_lifecycle": SESSION_STATES,
                  "session_execution": {"idle", "running", "pending_approval", "reconciliation_required"},
                  "action": ACTION_STATES, "approval": {"approved", "denied", "expired"},
                  "control": {"agent", "human"}, "download": {"completed"}, "artifact": ARTIFACT_STATES}
        string(summary.get("type"))
        if summary["type"] == "approval_required":
            string(summary.get("approval_id"))
        else:
            require(summary["type"] in states)
            state(summary.get("state"), states[summary["type"]])
        if "action_id" in summary:
            string(summary["action_id"])
        if "resolution" in summary:
            state(summary["resolution"], {"confirmed_executed", "confirmed_not_executed", "abandoned"})


def decode_success(value: Any, method: str, path: str) -> dict[str, Any]:
    envelope = obj(value)
    string(envelope.get("trace_id"))
    data = obj(envelope.get("data"))
    parts = path.split("?", 1)[0].strip("/").split("/")
    result = data
    if parts[1] == "operations" or (len(parts) == 2 and parts[1] == "sessions" and method == "POST"):
        result = obj(data.get("operation"))
        operation(result)
    elif parts[1] == "events":
        array(data.get("events"), event)
        require(type(data.get("gap")) is bool and "next_cursor" in data)
        cursor(data["next_cursor"])
    elif parts[1] == "approvals":
        if len(parts) == 2:
            array(data.get("approvals"), approval)
            require("next_page_token" in data)
            cursor(data["next_page_token"])
        else:
            result = obj(data.get("approval"))
            approval(result)
    elif parts[1] == "sessions":
        if len(parts) == 2:
            array(data.get("sessions"), session)
            require("next_page_token" in data)
            cursor(data["next_page_token"])
        elif len(parts) == 3:
            result = obj(data.get("session"))
            session(result)
        elif parts[3] in {"reconnect", "transfer"}:
            result = obj(data.get("ownership"))
            string(result.get("worker_id"))
            for field in ("worker_epoch", "placement_version", "session_incarnation"):
                integer(result.get(field), 1)
        elif parts[3] == "pages":
            if len(parts) == 4 and method == "GET":
                array(data.get("pages"), page)
            else:
                result = obj(data.get("page"))
                if method == "DELETE":
                    string(result.get("id"))
                    require(result.get("deleted") is True)
                else:
                    page(result)
        elif parts[3] == "actions":
            action(result)
        elif parts[3] == "viewer-ticket":
            require(data.get("ticket_issued") is True)
        elif parts[3] == "artifacts":
            if len(parts) == 4:
                array(data.get("artifacts"), artifact)
                require("next_cursor" in data)
                cursor(data["next_cursor"])
            elif len(parts) == 6 and parts[5] == "download":
                string(data.get("download_token"))
            else:
                result = obj(data.get("artifact"))
                artifact(result)
        else:
            require(False)
    else:
        require(False)
    return {**result, "trace_id": envelope["trace_id"]}
