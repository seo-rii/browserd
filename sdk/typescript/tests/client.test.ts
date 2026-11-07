import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  BrowserdClient,
  BrowserdError,
  DispatchUncertainError,
  EventGapError,
  type ArtifactListPage,
  type FetchLike,
} from "../src/index.ts";

type Call = { url: string; init: RequestInit };

const fixture = JSON.parse(readFileSync(new URL("../../fixtures/http_contract.json", import.meta.url), "utf8"));
function wire(name: string, changes: Record<string, unknown> = {}, traceId = fixture.ids.trace): unknown {
  const response = structuredClone(fixture.responses[name]);
  const wrapper = ["operation", "session", "page", "ownership", "artifact", "approval"].find((key) => Object.hasOwn(response.data, key));
  Object.assign(wrapper ? response.data[wrapper] : response.data, changes);
  response.trace_id = traceId;
  return response;
}

function jsonResponse(status: number, body: unknown, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function scripted(responses: Array<Response | Error>): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    if (!next) throw new Error("unexpected request");
    return next;
  };
  return { fetch, calls };
}

test("query_all forwards frame paths without adding one to legacy actions", async () => {
  const transport = scripted(Array.from({ length: 3 }, () => jsonResponse(200, wire("action_queued", {
    action_id: "act-query", status: "succeeded",
  }))));
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: transport.fetch });
  for (const action of [
    { type: "query_all" as const, selector: "input" },
    { type: "query_all" as const, selector: "input", frame_path: [] },
    { type: "query_all" as const, selector: "input", frame_path: ["iframe#outer", "iframe#inner"] },
  ]) {
    const body = { page_id: "page-1", if_session_incarnation: 1, execution_timeout_ms: 30_000, action };
    await client.createAction("session-1", body);
    assert.deepEqual(JSON.parse(String(transport.calls.at(-1)?.init.body)), body);
  }
  assert.equal(Object.hasOwn(JSON.parse(String(transport.calls[0].init.body)).action, "frame_path"), false);
});

test("matches every API public route with escaped identifiers and bounded query parameters", async () => {
  const responses = ["operation_queued", "operation_queued", "operation_queued", "sessions", "session", "session", "ownership", "ownership", "pages", "page", "page_deleted", "page", "action_queued", "action_queued", "action_queued", "action_queued", "event_page", "viewer_ticket", "artifact", "artifact", "artifact_download", "approvals", "approval", "approval"].map((name) => jsonResponse(200, wire(name)));
  const transport = scripted(responses);
  const client = new BrowserdClient({ baseUrl: "https://api.example/", token: "secret", fetch: transport.fetch });

  await client.createSession({ isolation: "shared_context" }, { idempotencyKey: "idem-session", waitMs: 500 });
  await client.getOperation("op/a");
  await client.cancelOperation("op/a");
  await client.listSessions({ lifecycle: "ready", limit: 50, pageToken: "next token" });
  await client.getSession("ses/a");
  await client.closeSession("ses/a");
  await client.reconnectSession("ses/a", { token: "reconnect-token", binding: "client-1" });
  await client.transferSession("ses/a", { new_worker_id: "worker-1", new_worker_epoch: 2 });
  await client.listPages("ses/a");
  await client.createPage("ses/a", { url: "about:blank" });
  await client.closePage("ses/a", "pg/a");
  await client.activatePage("ses/a", "pg/a");
  await client.createAction("ses/a", { action: { type: "navigate", url: "https://example.com" } }, { idempotencyKey: "idem-action", waitMs: 30_000 });
  await client.getAction("ses/a", "act/a");
  await client.cancelAction("ses/a", "act/a");
  await client.resolveAction("ses/a", "act/a", { resolution: "abandoned", basis: "caller_choice" });
  await client.listEvents({ cursor: "cur/a", limit: 25 });
  await client.createViewerTicket("ses/a", { scope: "viewer:read" });
  await client.createArtifactUpload("ses/a", { filename: "file.txt", content_type: "text/plain" });
  await client.getArtifact("ses/a", "art/a");
  await client.createArtifactDownloadToken("ses/a", "art/a");
  await client.listApprovals({ state: "pending", sessionId: "ses/a", limit: 20, pageToken: "next page" });
  await client.getApproval("apr/a");
  await client.decideApproval("apr/a", { decision: "approve", reason: "verified" });

  assert.deepEqual(transport.calls.map((call) => [call.init.method, new URL(call.url).pathname]), [
    ["POST", "/v1/sessions"], ["GET", "/v1/operations/op%2Fa"], ["DELETE", "/v1/operations/op%2Fa"],
    ["GET", "/v1/sessions"], ["GET", "/v1/sessions/ses%2Fa"], ["DELETE", "/v1/sessions/ses%2Fa"],
    ["POST", "/v1/sessions/ses%2Fa/reconnect"], ["POST", "/v1/sessions/ses%2Fa/transfer"],
    ["GET", "/v1/sessions/ses%2Fa/pages"], ["POST", "/v1/sessions/ses%2Fa/pages"],
    ["DELETE", "/v1/sessions/ses%2Fa/pages/pg%2Fa"], ["POST", "/v1/sessions/ses%2Fa/pages/pg%2Fa/activate"],
    ["POST", "/v1/sessions/ses%2Fa/actions"], ["GET", "/v1/sessions/ses%2Fa/actions/act%2Fa"],
    ["DELETE", "/v1/sessions/ses%2Fa/actions/act%2Fa"],
    ["POST", "/v1/sessions/ses%2Fa/actions/act%2Fa/resolve"], ["GET", "/v1/events"],
    ["POST", "/v1/sessions/ses%2Fa/viewer-ticket"], ["POST", "/v1/sessions/ses%2Fa/artifacts/uploads"],
    ["GET", "/v1/sessions/ses%2Fa/artifacts/art%2Fa"],
    ["POST", "/v1/sessions/ses%2Fa/artifacts/art%2Fa/download"],
    ["GET", "/v1/approvals"], ["GET", "/v1/approvals/apr%2Fa"], ["POST", "/v1/approvals/apr%2Fa/decision"],
  ]);
  assert.equal(new URL(transport.calls[3]!.url).searchParams.get("page_token"), "next token");
  assert.equal(new URL(transport.calls[21]!.url).searchParams.get("limit"), "20");
  assert.equal(new URL(transport.calls[21]!.url).searchParams.get("page_token"), "next page");
  assert.equal(transport.calls[20]!.init.body, undefined);
  assert.equal(
    new Headers(transport.calls[20]!.init.headers).get("content-type"),
    null,
  );
  assert.equal(
    new Headers(transport.calls[15]!.init.headers).get("idempotency-key"),
    null,
  );
  assert.equal(client.viewerWebSocketUrl("ses/a"), "wss://api.example/v1/sessions/ses%2Fa/viewer");
});

test("validates base URL and never propagates credentials, token, query, or fragment", () => {
  for (const baseUrl of [
    "/relative",
    "ftp://api.example",
    "https://user:password@api.example",
    "https://api.example?tenant=other",
    "https://api.example#fragment",
  ]) {
    assert.throws(() => new BrowserdClient({ baseUrl }));
  }
  const client = new BrowserdClient({
    baseUrl: "https://api.example/proxy/",
    token: "secret-token",
    fetch: async () => jsonResponse(200, {}),
  });
  const viewer = new URL(client.viewerWebSocketUrl("ses/../other"));
  assert.equal(viewer.href, "wss://api.example/proxy/v1/sessions/ses%2F..%2Fother/viewer");
  assert.equal(viewer.username, "");
  assert.equal(viewer.password, "");
  assert.equal(viewer.search, "");
  assert.equal(viewer.hash, "");
  assert.equal(viewer.href.includes("secret-token"), false);
});

test("sets authorization, request ID, idempotency and Prefer headers", async () => {
  const transport = scripted([jsonResponse(202, wire("operation_queued", { id: "op-1" }, "trace-1"))]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", token: "token", fetch: transport.fetch });
  await client.createSession({}, { requestId: "req-1", idempotencyKey: "idem-1", waitMs: 123 });
  const headers = new Headers(transport.calls[0]!.init.headers);
  assert.equal(headers.get("authorization"), "Bearer token");
  assert.equal(headers.get("x-request-id"), "req-1");
  assert.equal(headers.get("idempotency-key"), "idem-1");
  assert.equal(headers.get("prefer"), "wait=123");

  const read = scripted([jsonResponse(200, wire("session", { id: "ses-1" }))]);
  const readClient = new BrowserdClient({ baseUrl: "https://api.example", fetch: read.fetch });
  await readClient.getSession("ses-1", { requestId: "req-read" });
  assert.equal(new Headers(read.calls[0]!.init.headers).get("x-request-id"), "req-read");
});

test("raises a typed error envelope with response request ID", async () => {
  const transport = scripted([jsonResponse(409, { error: { code: "idempotency_conflict", message: "different body", retryable: false, details: { field: "action" }, trace_id: "trace-2" } }, { "x-request-id": "req-server" })]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: transport.fetch });
  await assert.rejects(client.getSession("ses-1"), (error: unknown) => {
    assert.ok(error instanceof BrowserdError);
    assert.equal(error.code, "idempotency_conflict");
    assert.equal(error.status, 409);
    assert.equal(error.retryable, false);
    assert.equal(error.traceId, "trace-2");
    assert.equal(error.requestId, "req-server");
    return true;
  });
});

test("never replays a mutating action after transport dispatch uncertainty", async () => {
  const transport = scripted([new TypeError("connection reset"), jsonResponse(200, { status: "succeeded" })]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: transport.fetch, maxRetries: 3 });
  await assert.rejects(
    client.createAction("ses-1", { action: { type: "click", node_ref: "node-1" } }, { idempotencyKey: "idem-1", requestId: "req-1" }),
    (error: unknown) => error instanceof DispatchUncertainError && error.idempotencyKey === "idem-1",
  );
  assert.equal(transport.calls.length, 1);
});

test("never replays artifact download-token creation after dispatch uncertainty", async () => {
  const transport = scripted([new TypeError("connection reset"), jsonResponse(200, { token: "bad-replay" })]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: transport.fetch, maxRetries: 3 });
  await assert.rejects(
    client.createArtifactDownloadToken("ses/a", "art/a", { requestId: "req-download" }),
    (error: unknown) => error instanceof DispatchUncertainError && error.requestId === "req-download",
  );
  assert.equal(transport.calls.length, 1);
});

test("retries replay-safe artifact metadata reads", async () => {
  const artifact = { id: "art-1", state: "available", display_filename: "첨부 문서.txt" };
  const transport = scripted([
    new TypeError("connection reset"),
    jsonResponse(200, { data: { artifact }, trace_id: "trace-artifact" }),
  ]);
  const client = new BrowserdClient({
    baseUrl: "https://api.example",
    fetch: transport.fetch,
    maxRetries: 1,
    sleep: async () => {},
  });
  assert.deepEqual(await client.getArtifact("ses-1", "art-1"), { ...artifact, trace_id: "trace-artifact" });
  assert.equal(transport.calls.length, 2);
});

test("lists artifact pages using the HTTP envelope and an encoded continuation cursor", async () => {
  const first: ArtifactListPage = {
    artifacts: [
      { id: "art-1", state: "available", size_bytes: 0, content_type: "application/octet-stream", display_filename: "한".repeat(85) },
      { id: "art-2", state: "available", display_filename: null },
      { id: "art-3", state: "available" },
    ],
    next_cursor: "art/a?&after=other +한글",
  };
  const last: ArtifactListPage = { artifacts: [], next_cursor: null };
  const transport = scripted([
    jsonResponse(200, { data: first, trace_id: "trace-1" }),
    jsonResponse(200, { data: last, trace_id: "trace-2" }),
  ]);
  const client = new BrowserdClient({ baseUrl: "https://api.example/proxy/", fetch: transport.fetch });
  const page = await client.listArtifacts("ses/a?&한글", { requestId: "req-list" });
  assert.deepEqual(page, { ...first, trace_id: "trace-1" });
  assert.deepEqual(await client.listArtifacts("ses/a?&한글", { after: page.next_cursor!, limit: 100 }), { ...last, trace_id: "trace-2" });
  const initial = new URL(transport.calls[0]!.url);
  assert.equal(initial.pathname, "/proxy/v1/sessions/ses%2Fa%3F%26%ED%95%9C%EA%B8%80/artifacts");
  assert.deepEqual([...initial.searchParams], [["limit", "50"]]);
  const next = new URL(transport.calls[1]!.url);
  assert.deepEqual([...next.searchParams], [["after", first.next_cursor], ["limit", "100"]]);
  assert.equal(next.hash, "");
  for (const call of transport.calls) {
    assert.equal(call.init.method, "GET");
    assert.equal(call.init.body, undefined);
    assert.equal(new Headers(call.init.headers).get("idempotency-key"), null);
  }
  assert.equal(new Headers(transport.calls[0]!.init.headers).get("x-request-id"), "req-list");
});

test("rejects invalid artifact limits and dot path identifiers before transport", async () => {
  const transport = scripted([]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: transport.fetch });
  for (const limit of [0, 101, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    await assert.rejects(client.listArtifacts("ses-1", { limit }), RangeError);
  }
  for (const sessionId of ["", ".", ".."]) {
    await assert.rejects(client.listArtifacts(sessionId), TypeError);
  }
  assert.equal(transport.calls.length, 0);
});

test("retries artifact listing as a read while preserving pagination and request identity", async () => {
  const page: ArtifactListPage = { artifacts: [], next_cursor: null };
  const transport = scripted([new Error("reset"), jsonResponse(200, { data: page, trace_id: "trace-list" })]);
  const client = new BrowserdClient({
    baseUrl: "https://api.example", fetch: transport.fetch, maxRetries: 1, sleep: async () => {},
  });
  assert.deepEqual(await client.listArtifacts("ses-1", { after: "art-1", limit: 1, requestId: "req-list" }), { ...page, trace_id: "trace-list" });
  assert.equal(transport.calls.length, 2);
  assert.equal(transport.calls[0]!.url, transport.calls[1]!.url);
  for (const call of transport.calls) {
    assert.equal(new Headers(call.init.headers).get("x-request-id"), "req-list");
    assert.equal(new Headers(call.init.headers).get("idempotency-key"), null);
  }
});

test("returns OUTCOME_UNKNOWN as a terminal value and never replays it", async () => {
  const transport = scripted([jsonResponse(200, wire("action_unknown", { action_id: "act-1" }, "trace-3"))]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: transport.fetch, maxRetries: 3 });
  const result = await client.createAction("ses-1", { action: { type: "click" } });
  assert.equal(result.status, "outcome_unknown");
  assert.equal(result.action_id, "act-1");
  assert.equal(client.isOutcomeUnknown(result), true);
  assert.equal(transport.calls.length, 1);
});

test("retries reads and explicitly pre-dispatch errors, retaining one idempotency key", async () => {
  const read = scripted([jsonResponse(503, { error: { code: "worker_unavailable", message: "retry", retryable: true, details: {}, trace_id: "t1" } }), jsonResponse(200, wire("session", { id: "ses-1" }))]);
  const readClient = new BrowserdClient({ baseUrl: "https://api.example", fetch: read.fetch, maxRetries: 1, sleep: async () => {} });
  assert.equal((await readClient.getSession("ses-1")).id, "ses-1");
  assert.equal(read.calls.length, 2);

  const action = scripted([jsonResponse(503, { error: { code: "action_admission_timeout", message: "not dispatched", retryable: true, details: {}, trace_id: "t2" } }), jsonResponse(202, wire("action_queued", { action_id: "act-1" }))]);
  const actionClient = new BrowserdClient({ baseUrl: "https://api.example", fetch: action.fetch, maxRetries: 1, sleep: async () => {} });
  await actionClient.createAction("ses-1", { action: { type: "screenshot" } });
  assert.equal(action.calls.length, 2);
  const keys = action.calls.map((call) => new Headers(call.init.headers).get("idempotency-key"));
  assert.ok(keys[0]);
  assert.equal(keys[0], keys[1]);
});

test("does not classify status-only routing failures as pre-dispatch", async () => {
  const transport = scripted([
    jsonResponse(503, {
      error: {
        code: "worker_unavailable",
        message: "query action status",
        retryable: true,
        details: {},
        trace_id: "t-status",
      },
    }),
    jsonResponse(200, { action_id: "act-2", status: "succeeded" }),
  ]);
  const client = new BrowserdClient({
    baseUrl: "https://api.example",
    fetch: transport.fetch,
    maxRetries: 2,
    sleep: async () => {},
  });
  await assert.rejects(
    client.createAction("ses-1", { action: { type: "click" } }),
    (error: unknown) => error instanceof BrowserdError && error.code === "worker_unavailable",
  );
  assert.equal(transport.calls.length, 1);
});

test("reports an undecodable mutating response as dispatch uncertainty", async () => {
  const transport = scripted([new Response("not-json", { status: 200 })]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: transport.fetch });
  await assert.rejects(
    client.createAction("ses-1", { action: { type: "click" } }, { requestId: "req-bad" }),
    (error: unknown) => error instanceof DispatchUncertainError && error.requestId === "req-bad",
  );
  assert.equal(transport.calls.length, 1);
});

test("polls operations to a terminal state and resumes event cursor", async () => {
  const operation = scripted([
    jsonResponse(200, wire("operation_queued", { id: "op-1", state: "creating" })),
    jsonResponse(200, wire("operation_succeeded", { id: "op-1" })),
  ]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: operation.fetch, sleep: async () => {} });
  assert.equal((await client.waitForOperation("op-1", { intervalMs: 0, maxPolls: 2 })).state, "succeeded");

  const events = scripted([
    jsonResponse(200, wire("event_page", { events: [{ ...fixture.responses.event_page.data.events[0], event_id: "ev-1" }], next_cursor: "cur-2" })),
    jsonResponse(200, wire("event_page", { events: [{ ...fixture.responses.event_page.data.events[0], event_id: "ev-2", kind: "action.state_changed" }], next_cursor: "cur-3" })),
  ]);
  const eventClient = new BrowserdClient({ baseUrl: "https://api.example", fetch: events.fetch, sleep: async () => {} });
  const received = [];
  for await (const event of eventClient.resumeEvents({ cursor: "cur-1", intervalMs: 0, maxPolls: 2 })) received.push(event.event_id);
  assert.deepEqual(received, ["ev-1", "ev-2"]);
  assert.equal(new URL(events.calls[1]!.url).searchParams.get("cursor"), "cur-2");
});

test("event resume surfaces retention gaps instead of silently skipping state", async () => {
  const events = scripted([jsonResponse(200, wire("event_gap", { next_cursor: "cur-latest" }))]);
  const client = new BrowserdClient({ baseUrl: "https://api.example", fetch: events.fetch });
  await assert.rejects(async () => {
    for await (const _event of client.resumeEvents({ cursor: "cur-expired", maxPolls: 1 })) {
      // No event should be emitted across an explicit retention gap.
    }
  }, (error: unknown) => error instanceof EventGapError && error.latestCursor === "cur-latest");
});
