export function mapPointerToFrame(event, rect, frame) {
  if (
    !Number.isFinite(rect.left) ||
    !Number.isFinite(rect.top) ||
    !Number.isFinite(rect.width) ||
    !Number.isFinite(rect.height) ||
    rect.width <= 0 ||
    rect.height <= 0 ||
    !Number.isSafeInteger(frame.width) ||
    !Number.isSafeInteger(frame.height) ||
    frame.width < 1 ||
    frame.height < 1
  ) {
    throw new TypeError("frame and rendered dimensions must be positive");
  }
  const rawX = Math.floor(((event.clientX - rect.left) / rect.width) * frame.width);
  const rawY = Math.floor(((event.clientY - rect.top) / rect.height) * frame.height);
  return {
    x: Math.max(0, Math.min(frame.width - 1, rawX)),
    y: Math.max(0, Math.min(frame.height - 1, rawY)),
  };
}

export function createTicketFetcher({
  endpoint,
  locationOrigin,
  fetchImpl = globalThis.fetch,
  requestId = () => globalThis.crypto.randomUUID(),
}) {
  const base = new URL(endpoint);
  if (base.origin !== locationOrigin) {
    throw new TypeError("viewer tickets require a same-origin endpoint");
  }
  if (typeof fetchImpl !== "function") {
    throw new TypeError("fetch implementation is unavailable");
  }

  return async (sessionId, sessionIncarnation) => {
    if (!/^[A-Za-z0-9_-]+$/.test(sessionId)) {
      throw new TypeError("invalid session id");
    }
    if (!Number.isSafeInteger(sessionIncarnation) || sessionIncarnation < 1) {
      throw new TypeError("session incarnation must be a positive integer");
    }
    const path = base.pathname.endsWith("/") ? base.pathname : `${base.pathname}/`;
    const url = new URL(
      `${path}v1/sessions/${sessionId}/viewer-ticket`,
      base.origin,
    );
    const response = await fetchImpl(url.toString(), {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-Request-Id": requestId(),
      },
      body: JSON.stringify({
        session_incarnation: sessionIncarnation,
        scopes: { read: true, control: true, admin: false },
        ttl_seconds: 60,
      }),
    });
    if (!response.ok) {
      throw new Error(`viewer ticket request failed (${response.status ?? "unknown"})`);
    }
    const body = await response.json();
    if (
      body?.data?.ticket_issued !== true ||
      typeof body.trace_id !== "string" ||
      body.trace_id === ""
    ) {
      throw new Error("viewer ticket response is invalid");
    }
    return body;
  };
}
