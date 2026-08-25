export const FRAME_MESSAGE_TYPE = 1;

const FRAME_HEADER_BYTES = 21;
const DEFAULT_MAX_METADATA_BYTES = 64 * 1024;
const DEFAULT_MAX_JPEG_BYTES = 16 * 1024 * 1024;

export class ProtocolError extends Error {
  constructor(message) {
    super(message);
    this.name = "ProtocolError";
  }
}

function asBytes(value) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new ProtocolError("frame must be binary");
}

export function parseFrame(value, limits = {}) {
  const bytes = asBytes(value);
  if (bytes.byteLength < FRAME_HEADER_BYTES) {
    throw new ProtocolError("frame header is truncated");
  }
  if (bytes[0] !== FRAME_MESSAGE_TYPE) {
    throw new ProtocolError(`unknown frame message type: ${bytes[0]}`);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const frameId = view.getBigUint64(1, false);
  const transformEpoch = view.getBigUint64(9, false);
  const metadataLength = view.getUint32(17, false);
  const maxMetadataBytes = limits.maxMetadataBytes ?? DEFAULT_MAX_METADATA_BYTES;
  const maxJpegBytes = limits.maxJpegBytes ?? DEFAULT_MAX_JPEG_BYTES;

  if (!Number.isSafeInteger(maxMetadataBytes) || maxMetadataBytes < 0) {
    throw new ProtocolError("invalid metadata byte limit");
  }
  if (!Number.isSafeInteger(maxJpegBytes) || maxJpegBytes < 0) {
    throw new ProtocolError("invalid JPEG byte limit");
  }
  if (metadataLength > maxMetadataBytes) {
    throw new ProtocolError("frame metadata exceeds configured limit");
  }

  const metadataEnd = FRAME_HEADER_BYTES + metadataLength;
  if (metadataEnd > bytes.byteLength) {
    throw new ProtocolError("frame metadata is truncated");
  }
  const jpegLength = bytes.byteLength - metadataEnd;
  if (jpegLength > maxJpegBytes) {
    throw new ProtocolError("frame JPEG exceeds configured limit");
  }

  let metadata;
  try {
    const json = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(FRAME_HEADER_BYTES, metadataEnd),
    );
    metadata = JSON.parse(json);
  } catch (error) {
    throw new ProtocolError(`invalid frame metadata JSON: ${error.message}`);
  }
  if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new ProtocolError("frame metadata must be an object");
  }

  return Object.freeze({
    type: FRAME_MESSAGE_TYPE,
    frameId,
    transformEpoch,
    metadata: Object.freeze(metadata),
    jpeg: bytes.slice(metadataEnd),
  });
}

export function encodeFrameForTest({
  frameId,
  transformEpoch,
  metadata,
  metadataBytes,
  jpeg,
}) {
  const encodedMetadata = metadataBytes ?? new TextEncoder().encode(JSON.stringify(metadata));
  const encodedJpeg = asBytes(jpeg);
  const bytes = new Uint8Array(
    FRAME_HEADER_BYTES + encodedMetadata.byteLength + encodedJpeg.byteLength,
  );
  const view = new DataView(bytes.buffer);
  bytes[0] = FRAME_MESSAGE_TYPE;
  view.setBigUint64(1, BigInt(frameId), false);
  view.setBigUint64(9, BigInt(transformEpoch), false);
  view.setUint32(17, encodedMetadata.byteLength, false);
  bytes.set(encodedMetadata, FRAME_HEADER_BYTES);
  bytes.set(encodedJpeg, FRAME_HEADER_BYTES + encodedMetadata.byteLength);
  return bytes;
}
