import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { BrowserdClient, DispatchUncertainError, TransportError } from "../src/index.ts";

const fixture = JSON.parse(readFileSync(new URL("../../fixtures/http_contract.json", import.meta.url), "utf8"));
const body = (name: string) => structuredClone(fixture.responses[name]);
function clientFor(responses: unknown[]) {
  const urls: string[] = [];
  const client = new BrowserdClient({ baseUrl: "https://api.example", maxRetries: 0, sleep: async () => {}, fetch: async (url) => {
    urls.push(String(url));
    const next = responses.shift();
    assert.notEqual(next, undefined, "an invalid response must not trigger another poll");
    return new Response(JSON.stringify(next), { status: 200 });
  }});
  return { client, urls };
}

test("actual HTTP operation envelope preserves terminal states and session/failure resources", async () => {
  for (const terminal of ["operation_succeeded", "operation_failed", "operation_timed_out"]) {
    const { client } = clientFor([body("operation_queued"), body(terminal)]);
    const result = await client.waitForOperation(fixture.ids.operation, { maxPolls: 2 });
    assert.deepEqual(result, { ...body(terminal).data.operation, trace_id: fixture.ids.trace });
  }
});

test("actual HTTP action and event envelopes preserve uncertainty, cursors and retention gaps", async () => {
  const action = clientFor([body("action_queued"), body("action_unknown")]);
  assert.equal((await action.client.waitForAction(fixture.ids.session, fixture.ids.action, { maxPolls: 2 })).status, "outcome_unknown");
  const events = clientFor([body("event_page"), { data: { events: [], gap: false, next_cursor: fixture.ids.event }, trace_id: fixture.ids.trace }]);
  const received = [];
  for await (const event of events.client.resumeEvents({ cursor: fixture.ids.operation, maxPolls: 2 })) received.push(event);
  assert.deepEqual(received, body("event_page").data.events);
  assert.equal(new URL(events.urls[1]!).searchParams.get("cursor"), fixture.ids.event);
  const gap = clientFor([body("event_gap")]);
  await assert.rejects(async () => { for await (const event of gap.client.resumeEvents({ maxPolls: 1 })) assert.fail(String(event)); }, { name: "EventGapError", latestCursor: fixture.ids.event });
});

test("every SDK method unwraps the HTTP envelope and its endpoint resource exactly once", async () => {
  const methods: Array<[string, (c: BrowserdClient) => Promise<unknown>, string?]> = [
    ["operation_succeeded", (c) => c.createSession({}), "operation"],
    ["operation_succeeded", (c) => c.getOperation("op"), "operation"],
    ["operation_succeeded", (c) => c.cancelOperation("op"), "operation"],
    ["sessions", (c) => c.listSessions()],
    ["session", (c) => c.getSession("ses"), "session"],
    ["session", (c) => c.closeSession("ses"), "session"],
    ["ownership", (c) => c.reconnectSession("ses", {}), "ownership"],
    ["ownership", (c) => c.transferSession("ses", {}), "ownership"],
    ["pages", (c) => c.listPages("ses")],
    ["page", (c) => c.createPage("ses"), "page"],
    ["page_deleted", (c) => c.closePage("ses", "page"), "page"],
    ["page", (c) => c.activatePage("ses", "page"), "page"],
    ["action_unknown", (c) => c.createAction("ses", { action: { type: "click" } })],
    ["action_unknown", (c) => c.getAction("ses", "act")],
    ["action_unknown", (c) => c.cancelAction("ses", "act")],
    ["action_unknown", (c) => c.resolveAction("ses", "act", {})],
    ["event_page", (c) => c.listEvents()],
    ["viewer_ticket", (c) => c.createViewerTicket("ses", {})],
    ["artifact", (c) => c.createArtifactUpload("ses", {}), "artifact"],
    ["artifact", (c) => c.getArtifact("ses", "art"), "artifact"],
    ["artifacts", (c) => c.listArtifacts("ses")],
    ["artifact_download", (c) => c.createArtifactDownloadToken("ses", "art")],
    ["approvals", (c) => c.listApprovals()],
    ["approval", (c) => c.getApproval("apr"), "approval"],
    ["approval", (c) => c.decideApproval("apr", {}), "approval"],
  ];
  for (const [name, call, wrapper] of methods) {
    const response = body(name);
    const { client } = clientFor([response]);
    assert.deepEqual(await call(client), { ...(wrapper ? response.data[wrapper] : response.data), trace_id: response.trace_id }, name);
    const invalid = clientFor([{ data: {}, trace_id: fixture.ids.trace }]);
    await assert.rejects(call(invalid.client), (error: unknown) => error instanceof TransportError || error instanceof DispatchUncertainError);
    assert.equal(invalid.urls.length, 1, name);
  }
});

test("malformed successful responses terminate reads and never replay uncertain mutations", async () => {
  for (const invalid of [null, [], {}, { data: {} }, { data: [], trace_id: fixture.ids.trace }, { data: { operation: { id: "op", state: "timedout" } }, trace_id: fixture.ids.trace }]) {
    const { client, urls } = clientFor([invalid]);
    await assert.rejects(client.waitForOperation("op", { maxPolls: 10 }), TransportError);
    assert.equal(urls.length, 1);
  }
  for (const name of ["operation_succeeded", "action_unknown", "session", "pages", "event_page"]) {
    const invalid = body(name);
    if (name === "operation_succeeded") invalid.data.operation.state = "bogus";
    if (name === "action_unknown") invalid.data.status = "bogus";
    if (name === "session") invalid.data.session.incarnation = "3";
    if (name === "pages") invalid.data.pages[0].document_epoch = -1;
    if (name === "event_page") invalid.data.gap = "true";
    const { client } = clientFor([invalid]);
    const call = name === "operation_succeeded" ? client.getOperation("op") : name === "action_unknown" ? client.getAction("ses", "act") : name === "session" ? client.getSession("ses") : name === "pages" ? client.listPages("ses") : client.listEvents();
    await assert.rejects(call, TransportError);
  }
  const mutation = clientFor([{ data: {}, trace_id: fixture.ids.trace }]);
  await assert.rejects(mutation.client.createSession({}), DispatchUncertainError);
  assert.equal(mutation.urls.length, 1);
});
