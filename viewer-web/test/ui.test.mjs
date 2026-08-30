import assert from "node:assert/strict";
import test from "node:test";

import { createTicketFetcher, mapPointerToFrame } from "../src/ui.mjs";

test("maps pointer positions into bounded frame coordinates", () => {
  const rect = { left: 100, top: 50, width: 640, height: 360 };
  const frame = { width: 1280, height: 720 };

  assert.deepEqual(mapPointerToFrame({ clientX: 420, clientY: 230 }, rect, frame), {
    x: 640,
    y: 360,
  });
  assert.deepEqual(mapPointerToFrame({ clientX: 0, clientY: 999 }, rect, frame), {
    x: 0,
    y: 719,
  });
});

test("ticket fetcher uses a same-origin credentialed POST without a bearer URL", async () => {
  const calls = [];
  const fetchTicket = createTicketFetcher({
    endpoint: "https://viewer.example.test/app/",
    locationOrigin: "https://viewer.example.test",
    requestId: () => "018f0000-0000-7000-8000-000000000001",
    fetchImpl: async (...args) => {
      calls.push(args);
      return {
        ok: true,
        json: async () => ({
          data: { ticket_issued: true },
          trace_id: "trace-viewer-ticket",
        }),
      };
    },
  });

  assert.deepEqual(await fetchTicket("ses_abc", 7), {
    data: { ticket_issued: true },
    trace_id: "trace-viewer-ticket",
  });
  const [url, init] = calls[0];
  assert.equal(url, "https://viewer.example.test/app/v1/sessions/ses_abc/viewer-ticket");
  assert.equal(init.method, "POST");
  assert.equal(init.credentials, "same-origin");
  assert.equal(init.headers.Authorization, undefined);
  assert.equal(init.headers["X-Request-Id"], "018f0000-0000-7000-8000-000000000001");
  assert.deepEqual(JSON.parse(init.body), {
    session_incarnation: 7,
    scopes: { read: true, control: true, admin: false },
    ttl_seconds: 60,
  });
});

test("ticket fetcher rejects cross-origin endpoints and unsafe session ids", async () => {
  assert.throws(
    () => createTicketFetcher({
      endpoint: "https://attacker.test/",
      locationOrigin: "https://viewer.example.test",
      fetchImpl: async () => ({ ok: true }),
    }),
    /same-origin/,
  );

  const fetchTicket = createTicketFetcher({
    endpoint: "https://viewer.example.test/",
    locationOrigin: "https://viewer.example.test",
    fetchImpl: async () => ({ ok: true }),
  });
  await assert.rejects(() => fetchTicket("../escape"), /invalid session id/);
  await assert.rejects(() => fetchTicket("ses_valid", 0), /session incarnation/);
});
