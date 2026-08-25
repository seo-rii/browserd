import assert from "node:assert/strict";
import test from "node:test";

import {
  FRAME_MESSAGE_TYPE,
  ProtocolError,
  encodeFrameForTest,
  parseFrame,
} from "../src/protocol.mjs";

test("parses the bounded binary frame envelope", () => {
  const bytes = encodeFrameForTest({
    frameId: 42n,
    transformEpoch: 7n,
    metadata: { width: 1280, height: 720, page_id: "pg_example" },
    jpeg: new Uint8Array([0xff, 0xd8, 0xff, 0xd9]),
  });

  const frame = parseFrame(bytes, {
    maxMetadataBytes: 1024,
    maxJpegBytes: 1024,
  });

  assert.equal(frame.type, FRAME_MESSAGE_TYPE);
  assert.equal(frame.frameId, 42n);
  assert.equal(frame.transformEpoch, 7n);
  assert.deepEqual(frame.metadata, {
    width: 1280,
    height: 720,
    page_id: "pg_example",
  });
  assert.deepEqual(frame.jpeg, new Uint8Array([0xff, 0xd8, 0xff, 0xd9]));
});

test("rejects unknown types, oversized metadata, oversized JPEG, and trailing ambiguity", () => {
  const valid = encodeFrameForTest({
    frameId: 1n,
    transformEpoch: 2n,
    metadata: { width: 1, height: 1 },
    jpeg: new Uint8Array([1, 2, 3]),
  });

  const badType = valid.slice();
  badType[0] = 99;
  assert.throws(() => parseFrame(badType), ProtocolError);
  assert.throws(
    () => parseFrame(valid, { maxMetadataBytes: 1, maxJpegBytes: 100 }),
    /metadata exceeds/,
  );
  assert.throws(
    () => parseFrame(valid, { maxMetadataBytes: 100, maxJpegBytes: 1 }),
    /JPEG exceeds/,
  );

  const truncated = valid.subarray(0, 20);
  assert.throws(() => parseFrame(truncated), /truncated/);
});

test("rejects invalid JSON and unsafe metadata shapes", () => {
  const invalidJson = encodeFrameForTest({
    frameId: 1n,
    transformEpoch: 1n,
    metadataBytes: new TextEncoder().encode("{"),
    jpeg: new Uint8Array(),
  });
  assert.throws(() => parseFrame(invalidJson), /metadata JSON/);

  const arrayMetadata = encodeFrameForTest({
    frameId: 1n,
    transformEpoch: 1n,
    metadata: [],
    jpeg: new Uint8Array(),
  });
  assert.throws(() => parseFrame(arrayMetadata), /metadata must be an object/);
});
