import assert from "node:assert/strict";
import test from "node:test";

import { encodeFrameForTest } from "../src/protocol.mjs";
import { BrowserViewer, ViewerError } from "../src/viewer.mjs";

class FakeSocket {
  static instances = [];

  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.binaryType = "";
    this.readyState = 0;
    this.sent = [];
    FakeSocket.instances.push(this);
  }

  open() {
    this.readyState = 1;
    this.onopen?.({});
  }

  receive(data) {
    this.onmessage?.({ data });
  }

  send(data) {
    this.sent.push(JSON.parse(data));
  }

  close(code = 1000, reason = "") {
    this.readyState = 3;
    this.onclose?.({ code, reason });
  }
}

function newViewer(overrides = {}) {
  FakeSocket.instances = [];
  const frames = [];
  const states = [];
  const viewer = new BrowserViewer({
    sessionId: "ses_example",
    sessionIncarnation: 7,
    endpoint: "https://gateway.example.test/base/",
    fetchTicket: async () => ({
      data: { ticket_issued: true },
      trace_id: "trace-viewer-ticket",
    }),
    WebSocketImpl: FakeSocket,
    setIntervalImpl: () => 1,
    clearIntervalImpl: () => {},
    onFrame: (frame) => frames.push(frame),
    onState: (state) => states.push(state),
    ...overrides,
  });
  return { viewer, frames, states };
}

test("uses an HttpOnly cookie handshake without exposing a ticket to JavaScript", async () => {
  const { viewer } = newViewer();

  await viewer.connect();
  const socket = FakeSocket.instances[0];

  assert.equal(
    socket.url,
    "wss://gateway.example.test/base/v1/sessions/ses_example/viewer",
  );
  assert.equal(new URL(socket.url).search, "");
  assert.deepEqual(socket.protocols, ["browser-viewer.v1"]);
  assert.equal(socket.binaryType, "arraybuffer");

  socket.open();
  assert.deepEqual(socket.sent, []);
});

test("acks every accepted frame immediately and drops stale transforms", async () => {
  const { viewer, frames } = newViewer();
  await viewer.connect();
  const socket = FakeSocket.instances[0];
  socket.open();

  socket.receive(
    encodeFrameForTest({
      frameId: 10n,
      transformEpoch: 3n,
      metadata: { page_id: "pg_a", width: 2, height: 2 },
      jpeg: new Uint8Array([1]),
    }).buffer,
  );
  socket.receive(
    encodeFrameForTest({
      frameId: 11n,
      transformEpoch: 2n,
      metadata: { page_id: "pg_a", width: 2, height: 2 },
      jpeg: new Uint8Array([2]),
    }).buffer,
  );

  assert.deepEqual(
    socket.sent,
    [
      { type: "ack", frame_id: "10" },
      { type: "ack", frame_id: "11" },
    ],
  );
  assert.equal(frames.length, 1);
  assert.equal(frames[0].frameId, 10n);
});

test("binds control input to lease, page, transform, and monotonic sequence", async () => {
  const { viewer } = newViewer();
  await viewer.connect();
  const socket = FakeSocket.instances[0];
  socket.open();

  assert.throws(
    () => viewer.sendInput("mouse", { x: 10, y: 20 }),
    ViewerError,
  );

  socket.receive(JSON.stringify({
    type: "control_changed",
    controller: "human",
    lease_epoch: 8,
    page_id: "pg_a",
    frame_transform_id: 13,
  }));

  viewer.sendInput("mouse", { x: 10, y: 20, button: "left", phase: "down" });
  viewer.sendInput("wheel", { delta_x: 0, delta_y: 100 });

  assert.deepEqual(socket.sent.slice(-2), [
    {
      type: "mouse",
      lease_epoch: 8,
      input_sequence: 1,
      page_id: "pg_a",
      frame_transform_id: 13,
      x: 10,
      y: 20,
      button: "left",
      phase: "down",
    },
    {
      type: "wheel",
      lease_epoch: 8,
      input_sequence: 2,
      page_id: "pg_a",
      frame_transform_id: 13,
      delta_x: 0,
      delta_y: 100,
    },
  ]);
});

test("forwards the complete CJK composition lifecycle", async () => {
  const { viewer } = newViewer();
  await viewer.connect();
  const socket = FakeSocket.instances[0];
  socket.open();
  socket.receive(JSON.stringify({
    type: "control_changed",
    controller: "human",
    lease_epoch: 4,
    page_id: "pg_ime",
    frame_transform_id: 9,
  }));

  viewer.compositionStart();
  viewer.compositionUpdate("ㅎ");
  viewer.compositionUpdate("하");
  viewer.compositionCommit("한");

  assert.deepEqual(
    socket.sent.slice(-4).map((message) => [message.type, message.text]),
    [
      ["composition_start", undefined],
      ["composition_update", "ㅎ"],
      ["composition_update", "하"],
      ["composition_commit", "한"],
    ],
  );
});

test("requires a fresh ticket for reconnect and prevents parallel connections", async () => {
  let issuances = 0;
  const { viewer } = newViewer({
    fetchTicket: async () => {
      issuances += 1;
      return {
        data: { ticket_issued: true },
        trace_id: `trace-${issuances}`,
      };
    },
  });

  await viewer.connect();
  await assert.rejects(() => viewer.connect(), /already connecting/);
  const first = FakeSocket.instances[0];
  first.open();
  first.close(1006, "lost");
  await viewer.connect();
  const second = FakeSocket.instances[1];
  second.open();

  assert.equal(issuances, 2);
  assert.deepEqual(first.sent, []);
  assert.deepEqual(second.sent, []);
});

test("transform updates preserve the active lease input sequence", async () => {
  const { viewer } = newViewer();
  await viewer.connect();
  const socket = FakeSocket.instances[0]; socket.open();
  const control = { type: "control_changed", controller: "human", lease_epoch: 2, page_id: "pg_a", frame_transform_id: 3 };
  socket.receive(JSON.stringify(control));
  viewer.sendInput("insert_text", { text: "a" });
  socket.receive(JSON.stringify({ ...control, frame_transform_id: 4 }));
  viewer.sendInput("insert_text", { text: "b" });
  assert.equal(socket.sent.at(-1).input_sequence, 2);
  assert.equal(socket.sent.at(-1).frame_transform_id, 4);
  socket.receive(JSON.stringify({ ...control, controller: "human_other" }));
  assert.equal(viewer.state.controlling, false);
});

test("heartbeats run only while the current socket is connected", async () => {
  let tick; let cleared = 0;
  const { viewer } = newViewer({
    setIntervalImpl: (callback, milliseconds) => { assert.equal(milliseconds, 5000); tick = callback; return 17; },
    clearIntervalImpl: (id) => { assert.equal(id, 17); cleared += 1; },
  });
  await viewer.connect(); const socket = FakeSocket.instances[0]; socket.open();
  tick(); assert.deepEqual(socket.sent.at(-1), { type: "ping" });
  viewer.disconnect(); assert.equal(cleared, 1);
  tick(); assert.equal(socket.sent.length, 1);
});

test("a new connection resets frame generation and ignores a late old close", async () => {
  const { viewer, frames } = newViewer();
  await viewer.connect(); const first = FakeSocket.instances[0]; first.open();
  first.receive(encodeFrameForTest({ frameId: 10n, transformEpoch: 90n, metadata: {}, jpeg: new Uint8Array([1]) }));
  first.close(); await viewer.connect(); const second = FakeSocket.instances[1]; second.open();
  first.close(); assert.equal(viewer.state.phase, "connected");
  second.receive(encodeFrameForTest({ frameId: 1n, transformEpoch: 2n, metadata: {}, jpeg: new Uint8Array([2]) }));
  assert.equal(frames.length, 2);
});

test("composition commit is inserted exactly once when beforeinput follows it", async () => {
  const { viewer } = newViewer(); await viewer.connect();
  const socket = FakeSocket.instances[0]; socket.open();
  socket.receive(JSON.stringify({ type: "control_changed", controller: "human", lease_epoch: 4, page_id: "pg_a", frame_transform_id: 1 }));
  viewer.compositionStart();
  viewer.beforeInput({ data: "ㅎ", isComposing: true, inputType: "insertCompositionText" });
  viewer.compositionUpdate("한"); viewer.compositionCommit("한");
  viewer.beforeInput({ data: "한", isComposing: false, inputType: "insertText" });
  assert.equal(socket.sent.filter((message) => message.type === "insert_text").length, 0);
  await Promise.resolve();
  viewer.beforeInput({ data: "한", isComposing: false, inputType: "insertText" });
  assert.equal(socket.sent.filter((message) => message.type === "insert_text").length, 1);
});
