"""Dependency-free browserd v1 public API client."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Literal, Mapping, Protocol, TypedDict, cast
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

JsonObject = dict[str, Any]
ActionType = Literal[
    "navigate", "reload", "go_back", "go_forward", "click", "double_click", "hover",
    "fill", "fill_secret", "type_text", "press_key", "scroll", "select_option",
    "set_files", "focus", "blur", "check", "uncheck", "handle_dialog", "snapshot",
    "get_text", "get_html", "get_url", "get_title", "get_attribute", "get_properties",
    "get_computed_style", "query_all", "extract_table", "new_page", "close_page",
    "activate_page", "wait_for", "evaluate", "screenshot", "pdf", "scrape", "checkpoint",
]
ActionStatus = Literal[
    "accepted",
    "queued",
    "pending_approval",
    "ready_to_dispatch",
    "may_have_executed",
    "succeeded",
    "failed_known",
    "cancelled_before_dispatch",
    "cancelled_confirmed",
    "outcome_unknown",
]


class Action(TypedDict, total=False):
    type: ActionType


class ActionRequest(TypedDict, total=False):
    action: Action
    page_id: str
    if_session_incarnation: int
    execution_timeout_ms: int


class ActionResponse(TypedDict, total=False):
    action_id: str
    status: ActionStatus
    trace_id: str
    retryable: Literal[False]


class Operation(TypedDict, total=False):
    id: str
    state: str
    poll_url: str
    session_id: str


class Event(TypedDict, total=False):
    event_id: str
    type: str


class ArtifactMetadata(TypedDict, total=False):
    artifact_id: str
    state: str
    size_bytes: int
    content_type: str


class ArtifactDownloadToken(TypedDict, total=False):
    token: str
    expires_at: str


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> Response: ...


class BrowserdError(Exception):
    def __init__(
        self,
        *,
        status: int,
        code: str,
        message: str,
        retryable: bool,
        details: Mapping[str, Any],
        trace_id: str | None,
        request_id: str | None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.retryable = retryable
        self.details = dict(details)
        self.trace_id = trace_id
        self.request_id = request_id


class DispatchUncertainError(Exception):
    def __init__(self, request_id: str, idempotency_key: str | None, cause: BaseException) -> None:
        super().__init__(
            "The mutating request may have been dispatched; it was not automatically replayed."
        )
        self.request_id = request_id
        self.idempotency_key = idempotency_key
        self.__cause__ = cause


class TransportError(Exception):
    def __init__(self, request_id: str, cause: BaseException) -> None:
        super().__init__("browserd transport failed")
        self.request_id = request_id
        self.__cause__ = cause


class EventGapError(Exception):
    def __init__(self, latest_cursor: str | None) -> None:
        super().__init__(
            "The event cursor is outside the retention window; poll resource state before resuming."
        )
        self.latest_cursor = latest_cursor


ReplayMode = Literal["read", "pre-dispatch", "unsafe"]
Sleep = Callable[[float], None]

_PRE_DISPATCH_CODES = frozenset(
    {
        "action_admission_timeout",
        "queue_timeout",
        "global_capacity_exceeded",
        "tenant_quota_exceeded",
        "rate_limited",
        "audit_unavailable",
        "browser_start_failed",
        "context_create_failed",
    }
)
_TERMINAL_OPERATIONS = frozenset({"succeeded", "failed", "timed_out", "cancelled"})
_TERMINAL_ACTIONS = frozenset(
    {
        "succeeded",
        "failed_known",
        "cancelled_before_dispatch",
        "cancelled_confirmed",
        "outcome_unknown",
    }
)


def _urllib_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: float,
) -> Response:
    request = Request(url, data=body, headers=dict(headers), method=method)
    try:
        with urlopen(request, timeout=timeout) as opened:
            return Response(
                status=opened.status,
                headers=dict(opened.headers.items()),
                body=opened.read(),
            )
    except HTTPError as error:
        return Response(
            status=error.code,
            headers=dict(error.headers.items()) if error.headers else {},
            body=error.read(),
        )


class BrowserdClient:
    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        transport: Transport | None = None,
        timeout: float = 30.0,
        max_retries: int = 2,
        retry_base: float = 0.1,
        sleep: Sleep = time.sleep,
    ) -> None:
        try:
            parsed_base_url = urlsplit(base_url)
            _ = parsed_base_url.port
        except ValueError as cause:
            raise ValueError("base_url must be an absolute HTTP(S) URL") from cause
        if (
            parsed_base_url.scheme not in {"http", "https"}
            or not parsed_base_url.hostname
            or parsed_base_url.username is not None
            or parsed_base_url.password is not None
            or "?" in base_url
            or "#" in base_url
        ):
            raise ValueError(
                "base_url must be HTTP(S) and contain no credentials, query, or fragment"
            )
        self.base_url = urlunsplit(
            (
                parsed_base_url.scheme,
                parsed_base_url.netloc,
                parsed_base_url.path.rstrip("/"),
                "",
                "",
            )
        )
        self.token = token
        self.transport = transport or _urllib_transport
        self.timeout = max(0.001, timeout)
        self.max_retries = max(0, max_retries)
        self.retry_base = max(0.0, retry_base)
        self.sleep = sleep

    def create_session(
        self,
        body: Mapping[str, Any],
        *,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        wait_ms: int | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            "/v1/sessions",
            body=body,
            replay="pre-dispatch",
            request_id=request_id,
            idempotency_key=idempotency_key,
            wait_ms=wait_ms,
        )

    def get_operation(
        self, operation_id: str, *, request_id: str | None = None
    ) -> Operation:
        return cast(
            Operation,
            self._request(
                "GET",
                f"/v1/operations/{self._segment(operation_id)}",
                replay="read",
                request_id=request_id,
            ),
        )

    def cancel_operation(
        self, operation_id: str, *, request_id: str | None = None
    ) -> JsonObject:
        return self._request(
            "DELETE",
            f"/v1/operations/{self._segment(operation_id)}",
            replay="read",
            request_id=request_id,
        )

    def list_sessions(
        self,
        *,
        lifecycle: str | None = None,
        isolation: str | None = None,
        metadata_key: str | None = None,
        limit: int | None = None,
        page_token: str | None = None,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "GET",
            self._query(
                "/v1/sessions",
                lifecycle=lifecycle,
                isolation=isolation,
                metadata_key=metadata_key,
                limit=limit,
                page_token=page_token,
            ),
            replay="read",
            request_id=request_id,
        )

    def get_session(
        self, session_id: str, *, request_id: str | None = None
    ) -> JsonObject:
        return self._request(
            "GET",
            f"/v1/sessions/{self._segment(session_id)}",
            replay="read",
            request_id=request_id,
        )

    def close_session(
        self, session_id: str, *, request_id: str | None = None
    ) -> JsonObject:
        return self._request(
            "DELETE",
            f"/v1/sessions/{self._segment(session_id)}",
            replay="read",
            request_id=request_id,
        )

    def reconnect_session(
        self,
        session_id: str,
        body: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            f"/v1/sessions/{self._segment(session_id)}/reconnect",
            body=body,
            replay="unsafe",
            request_id=request_id,
        )

    def transfer_session(
        self,
        session_id: str,
        body: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            f"/v1/sessions/{self._segment(session_id)}/transfer",
            body=body,
            replay="unsafe",
            request_id=request_id,
        )

    def list_pages(
        self, session_id: str, *, request_id: str | None = None
    ) -> JsonObject:
        return self._request(
            "GET",
            f"/v1/sessions/{self._segment(session_id)}/pages",
            replay="read",
            request_id=request_id,
        )

    def create_page(
        self,
        session_id: str,
        body: Mapping[str, Any] | None = None,
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            f"/v1/sessions/{self._segment(session_id)}/pages",
            body=body or {},
            replay="unsafe",
            request_id=request_id,
        )

    def close_page(
        self,
        session_id: str,
        page_id: str,
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "DELETE",
            f"/v1/sessions/{self._segment(session_id)}/pages/"
            f"{self._segment(page_id)}",
            replay="read",
            request_id=request_id,
        )

    def activate_page(
        self,
        session_id: str,
        page_id: str,
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            f"/v1/sessions/{self._segment(session_id)}/pages/"
            f"{self._segment(page_id)}/activate",
            body={},
            replay="unsafe",
            request_id=request_id,
        )

    def create_action(
        self,
        session_id: str,
        body: Mapping[str, Any],
        *,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        wait_ms: int | None = None,
    ) -> ActionResponse:
        return cast(
            ActionResponse,
            self._request(
                "POST",
                f"/v1/sessions/{self._segment(session_id)}/actions",
                body=body,
                replay="pre-dispatch",
                request_id=request_id,
                idempotency_key=idempotency_key,
                wait_ms=wait_ms,
            ),
        )

    def get_action(
        self,
        session_id: str,
        action_id: str,
        *,
        request_id: str | None = None,
    ) -> ActionResponse:
        return cast(
            ActionResponse,
            self._request(
                "GET",
                f"/v1/sessions/{self._segment(session_id)}/actions/"
                f"{self._segment(action_id)}",
                replay="read",
                request_id=request_id,
            ),
        )

    def cancel_action(
        self,
        session_id: str,
        action_id: str,
        *,
        request_id: str | None = None,
    ) -> ActionResponse:
        return cast(
            ActionResponse,
            self._request(
                "DELETE",
                f"/v1/sessions/{self._segment(session_id)}/actions/"
                f"{self._segment(action_id)}",
                replay="read",
                request_id=request_id,
            ),
        )

    def resolve_action(
        self,
        session_id: str,
        action_id: str,
        body: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            f"/v1/sessions/{self._segment(session_id)}/actions/"
            f"{self._segment(action_id)}/resolve",
            body=body,
            replay="read",
            request_id=request_id,
        )

    def list_events(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "GET",
            self._query("/v1/events", cursor=cursor, limit=limit),
            replay="read",
            request_id=request_id,
        )

    def create_viewer_ticket(
        self,
        session_id: str,
        body: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            f"/v1/sessions/{self._segment(session_id)}/viewer-ticket",
            body=body,
            replay="unsafe",
            request_id=request_id,
        )

    def viewer_websocket_url(self, session_id: str) -> str:
        parts = urlsplit(f"{self.base_url}/v1/sessions/{self._segment(session_id)}/viewer")
        scheme = "wss" if parts.scheme == "https" else "ws"
        return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))

    def create_artifact_upload(
        self,
        session_id: str,
        body: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            f"/v1/sessions/{self._segment(session_id)}/artifacts/uploads",
            body=body,
            replay="unsafe",
            request_id=request_id,
        )

    def get_artifact(
        self,
        session_id: str,
        artifact_id: str,
        *,
        request_id: str | None = None,
    ) -> ArtifactMetadata:
        return cast(
            ArtifactMetadata,
            self._request(
                "GET",
                f"/v1/sessions/{self._segment(session_id)}/artifacts/"
                f"{self._segment(artifact_id)}",
                replay="read",
                request_id=request_id,
            ),
        )

    def create_artifact_download_token(
        self,
        session_id: str,
        artifact_id: str,
        *,
        request_id: str | None = None,
    ) -> ArtifactDownloadToken:
        return cast(
            ArtifactDownloadToken,
            self._request(
                "POST",
                f"/v1/sessions/{self._segment(session_id)}/artifacts/"
                f"{self._segment(artifact_id)}/download",
                replay="unsafe",
                request_id=request_id,
            ),
        )

    def list_approvals(
        self,
        *,
        state: str | None = None,
        session_id: str | None = None,
        limit: int | None = None,
        page_token: str | None = None,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "GET",
            self._query(
                "/v1/approvals",
                state=state,
                session_id=session_id,
                limit=limit,
                page_token=page_token,
            ),
            replay="read",
            request_id=request_id,
        )

    def get_approval(
        self, approval_id: str, *, request_id: str | None = None
    ) -> JsonObject:
        return self._request(
            "GET",
            f"/v1/approvals/{self._segment(approval_id)}",
            replay="read",
            request_id=request_id,
        )

    def decide_approval(
        self,
        approval_id: str,
        body: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        return self._request(
            "POST",
            f"/v1/approvals/{self._segment(approval_id)}/decision",
            body=body,
            replay="unsafe",
            request_id=request_id,
        )

    def wait_for_operation(
        self,
        operation_id: str,
        *,
        interval: float = 0.25,
        max_polls: int | None = None,
    ) -> Operation:
        polls = 0
        while max_polls is None or polls < max_polls:
            operation = self.get_operation(operation_id)
            polls += 1
            if operation.get("state") in _TERMINAL_OPERATIONS:
                return operation
            if max_polls is None or polls < max_polls:
                self.sleep(max(0.0, interval))
        raise TimeoutError("operation polling limit reached")

    def wait_for_action(
        self,
        session_id: str,
        action_id: str,
        *,
        interval: float = 0.25,
        max_polls: int | None = None,
    ) -> ActionResponse:
        polls = 0
        while max_polls is None or polls < max_polls:
            action = self.get_action(session_id, action_id)
            polls += 1
            if action.get("status") in _TERMINAL_ACTIONS:
                return action
            if max_polls is None or polls < max_polls:
                self.sleep(max(0.0, interval))
        raise TimeoutError("action polling limit reached")

    def iter_events(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        interval: float = 0.25,
        max_polls: int | None = None,
    ) -> Iterator[Event]:
        polls = 0
        while max_polls is None or polls < max_polls:
            page = self.list_events(cursor=cursor, limit=limit)
            polls += 1
            if page.get("gap") is True:
                raise EventGapError(
                    cast(
                        str | None,
                        page.get("latest_cursor")
                        or page.get("next_cursor")
                        or page.get("cursor"),
                    )
                )
            for event in page.get("events", []):
                yield cast(Event, event)
            cursor = cast(
                str | None,
                page.get("next_cursor")
                or page.get("latest_cursor")
                or page.get("cursor")
                or cursor,
            )
            if max_polls is None or polls < max_polls:
                self.sleep(max(0.0, interval))

    @staticmethod
    def is_outcome_unknown(value: Mapping[str, Any]) -> bool:
        return value.get("status") == "outcome_unknown"

    @staticmethod
    def _segment(value: str) -> str:
        return quote(value, safe="")

    @staticmethod
    def _query(path: str, **values: str | int | None) -> str:
        encoded = urlencode({key: value for key, value in values.items() if value is not None})
        return f"{path}?{encoded}" if encoded else path

    def _request(
        self,
        method: str,
        path: str,
        *,
        replay: ReplayMode,
        body: Mapping[str, Any] | None = None,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        wait_ms: int | None = None,
    ) -> JsonObject:
        request_id = request_id or str(uuid.uuid4())
        if replay == "pre-dispatch":
            idempotency_key = idempotency_key or str(uuid.uuid4())
        headers: dict[str, str] = {
            "Accept": "application/json",
            "X-Request-Id": request_id,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(dict(body), separators=(",", ":")).encode()
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if wait_ms is not None:
            headers["Prefer"] = f"wait={max(0, int(wait_ms))}"

        attempt = 0
        while True:
            try:
                response = self.transport(
                    method,
                    f"{self.base_url}{path}",
                    headers,
                    payload,
                    self.timeout,
                )
            except Exception as cause:
                if replay == "read" and attempt < self.max_retries:
                    self.sleep(self.retry_base * (2**attempt))
                    attempt += 1
                    continue
                if replay != "read":
                    raise DispatchUncertainError(request_id, idempotency_key, cause) from cause
                raise TransportError(request_id, cause) from cause

            try:
                decoded: JsonObject = json.loads(response.body) if response.body else {}
            except (UnicodeDecodeError, ValueError) as cause:
                if replay != "read":
                    raise DispatchUncertainError(
                        request_id, idempotency_key, cause
                    ) from cause
                raise TransportError(request_id, cause) from cause
            if 200 <= response.status < 300:
                return decoded
            raw = decoded.get("error")
            envelope = raw if isinstance(raw, dict) else {}
            error = BrowserdError(
                status=response.status,
                code=str(envelope.get("code", "internal")),
                message=str(
                    envelope.get("message", f"browserd returned HTTP {response.status}")
                ),
                retryable=envelope.get("retryable") is True,
                details=envelope.get("details")
                if isinstance(envelope.get("details"), dict)
                else {},
                trace_id=cast(str | None, envelope.get("trace_id")),
                request_id=self._header(response.headers, "x-request-id") or request_id,
            )
            replay_safe = replay == "read" or (
                replay == "pre-dispatch" and error.code in _PRE_DISPATCH_CODES
            )
            if error.retryable and replay_safe and attempt < self.max_retries:
                self.sleep(self.retry_base * (2**attempt))
                attempt += 1
                continue
            raise error

    @staticmethod
    def _header(headers: Mapping[str, str], name: str) -> str | None:
        lowered = name.lower()
        for key, value in headers.items():
            if key.lower() == lowered:
                return value
        return None


__all__ = [
    "ArtifactDownloadToken",
    "ArtifactMetadata",
    "ActionResponse",
    "Action",
    "ActionRequest",
    "BrowserdClient",
    "BrowserdError",
    "DispatchUncertainError",
    "EventGapError",
    "Event",
    "Operation",
    "Response",
    "Transport",
    "TransportError",
]
