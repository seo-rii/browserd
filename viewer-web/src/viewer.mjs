import { ProtocolError, parseFrame } from "./protocol.mjs";

const INPUT_TYPES = new Set([
  "mouse",
  "wheel",
  "key",
  "insert_text",
  "composition_start",
  "composition_update",
  "composition_commit",
  "composition_cancel",
]);

export class ViewerError extends Error {
  constructor(message) {
    super(message);
    this.name = "ViewerError";
  }
}

function viewerUrl(endpoint, sessionId) {
  if (!/^[A-Za-z0-9_-]+$/.test(sessionId)) {
    throw new ViewerError("invalid session id");
  }
  const url = new URL(endpoint);
  if (url.protocol === "https:") {
    url.protocol = "wss:";
  } else if (url.protocol === "http:") {
    url.protocol = "ws:";
  } else if (url.protocol !== "wss:" && url.protocol !== "ws:") {
    throw new ViewerError("viewer endpoint must use HTTP(S) or WS(S)");
  }
  url.search = "";
  url.hash = "";
  const base = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
  url.pathname = `${base}v1/sessions/${sessionId}/viewer`;
  return url.toString();
}

export class BrowserViewer {
  #sessionId;
  #sessionIncarnation;
  #url;
  #fetchTicket;
  #WebSocketImpl;
  #onFrame;
  #onState;
  #frameLimits;
  #socket = null;
  #phase = "disconnected";
  #control = null;
  #inputSequence = 0;
  #latestTransformEpoch = -1n;
  #setInterval;
  #clearInterval;
  #heartbeat = null;
  #compositionActive = false;
  #committedText = null;

  constructor({
    sessionId,
    sessionIncarnation,
    endpoint,
    fetchTicket,
    WebSocketImpl = globalThis.WebSocket,
    onFrame = () => {},
    onState = () => {},
    frameLimits = {},
    setIntervalImpl = globalThis.setInterval,
    clearIntervalImpl = globalThis.clearInterval,
  }) {
    if (typeof fetchTicket !== "function") {
      throw new ViewerError("fetchTicket must be a function");
    }
    if (typeof WebSocketImpl !== "function") {
      throw new ViewerError("WebSocket implementation is unavailable");
    }
    if (!Number.isSafeInteger(sessionIncarnation) || sessionIncarnation < 1) {
      throw new ViewerError("session incarnation must be a positive integer");
    }
    this.#sessionId = sessionId;
    this.#sessionIncarnation = sessionIncarnation;
    this.#url = viewerUrl(endpoint, sessionId);
    this.#fetchTicket = fetchTicket;
    this.#WebSocketImpl = WebSocketImpl;
    this.#onFrame = onFrame;
    this.#onState = onState;
    this.#frameLimits = frameLimits;
    this.#setInterval = setIntervalImpl;
    this.#clearInterval = clearIntervalImpl;
  }

  get state() {
    return Object.freeze({
      phase: this.#phase,
      controlling: this.#control !== null,
      leaseEpoch: this.#control?.leaseEpoch ?? null,
      pageId: this.#control?.pageId ?? null,
      frameTransformId: this.#control?.frameTransformId ?? null,
    });
  }

  async connect() {
    if (this.#phase !== "disconnected") {
      throw new ViewerError("viewer is already connecting or connected");
    }
    this.#setPhase("ticketing");
    this.#latestTransformEpoch = -1n;

    let ticketResponse;
    try {
      ticketResponse = await this.#fetchTicket(
        this.#sessionId,
        this.#sessionIncarnation,
      );
    } catch (error) {
      this.#setPhase("disconnected");
      throw error;
    }
    if (
      ticketResponse?.data?.ticket_issued !== true ||
      typeof ticketResponse.trace_id !== "string" ||
      ticketResponse.trace_id === ""
    ) {
      this.#setPhase("disconnected");
      throw new ViewerError("ticket response is invalid");
    }

    const socket = new this.#WebSocketImpl(this.#url, ["browser-viewer.v1"]);
    socket.binaryType = "arraybuffer";
    this.#socket = socket;
    this.#setPhase("connecting");

    socket.onopen = () => {
      if (this.#socket !== socket) return;
      this.#setPhase("connected");
      this.#heartbeat = this.#setInterval(() => {
        if (this.#socket === socket && socket.readyState === 1) this.ping();
      }, 5000);
    };
    socket.onmessage = (event) => {
      if (this.#socket === socket) this.#receive(event.data);
    };
    socket.onerror = () => {
      if (this.#socket === socket) this.#setPhase("error");
    };
    socket.onclose = () => {
      if (this.#socket !== socket) return;
      if (this.#heartbeat !== null) this.#clearInterval(this.#heartbeat);
      this.#heartbeat = null;
      this.#control = null;
      this.#inputSequence = 0;
      this.#compositionActive = false;
      this.#committedText = null;
      this.#socket = null;
      this.#setPhase("disconnected");
    };
  }

  disconnect() {
    this.#socket?.close(1000, "viewer disconnect");
  }

  requestControl({ force = false } = {}) {
    this.#send({ type: "request_control", force: Boolean(force) });
  }

  releaseControl() {
    this.#send({ type: "release_control" });
  }

  selectPage(pageId) {
    if (typeof pageId !== "string" || pageId === "") {
      throw new ViewerError("page id is required");
    }
    this.#send({ type: "select_page", page_id: pageId });
  }

  ping() {
    this.#send({ type: "ping" });
  }

  resizeViewOnly(width, height) {
    if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1) {
      throw new ViewerError("view dimensions must be positive integers");
    }
    this.#send({ type: "resize_view_only", width, height });
  }

  sendInput(type, payload = {}) {
    if (!INPUT_TYPES.has(type)) {
      throw new ViewerError(`unsupported input type: ${type}`);
    }
    if (this.#control === null) {
      throw new ViewerError("human control is not held");
    }
    this.#inputSequence += 1;
    this.#send({
      ...payload,
      type,
      lease_epoch: this.#control.leaseEpoch,
      input_sequence: this.#inputSequence,
      page_id: this.#control.pageId,
      frame_transform_id: this.#control.frameTransformId,
    });
  }

  compositionStart() {
    this.sendInput("composition_start");
    this.#compositionActive = true;
    this.#committedText = null;
  }

  compositionUpdate(text) {
    this.sendInput("composition_update", { text: String(text) });
  }

  compositionCommit(text) {
    this.sendInput("composition_commit", { text: String(text) });
    this.#compositionActive = false;
    const committed = { text: String(text) };
    this.#committedText = committed;
    // Some browser event sequences follow compositionend with an insertText beforeinput.
    // Suppress only that same-turn echo, never a later intentional insertion of equal text.
    queueMicrotask(() => {
      if (this.#committedText === committed) this.#committedText = null;
    });
  }

  compositionCancel() {
    this.sendInput("composition_cancel");
    this.#compositionActive = false;
    this.#committedText = null;
  }

  beforeInput({ data, isComposing, inputType }) {
    if (!data || isComposing || this.#compositionActive ||
      inputType === "insertCompositionText" || inputType === "insertFromComposition") return;
    if (this.#committedText?.text === String(data)) {
      this.#committedText = null;
      return;
    }
    this.sendInput("insert_text", { text: String(data) });
  }

  #receive(data) {
    if (typeof data === "string") {
      this.#receiveControlMessage(data);
      return;
    }

    try {
      const frame = parseFrame(data, this.#frameLimits);
      this.#send({ type: "ack", frame_id: frame.frameId.toString() });
      if (frame.transformEpoch < this.#latestTransformEpoch) {
        return;
      }
      this.#latestTransformEpoch = frame.transformEpoch;
      this.#onFrame(frame);
    } catch (error) {
      this.#setPhase("error");
      if (error instanceof ProtocolError) {
        this.#socket?.close(1002, "invalid frame");
        return;
      }
      throw error;
    }
  }

  #receiveControlMessage(raw) {
    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      this.#socket?.close(1002, "invalid JSON message");
      return;
    }
    if (message.type !== "control_changed") {
      this.#onState(Object.freeze({ ...this.state, event: message }));
      return;
    }

    if (message.controller === "human") {
      if (
        !Number.isSafeInteger(message.lease_epoch) ||
        message.lease_epoch < 1 ||
        typeof message.page_id !== "string" ||
        !Number.isSafeInteger(message.frame_transform_id) ||
        message.frame_transform_id < 0
      ) {
        this.#socket?.close(1002, "invalid control lease");
        return;
      }
      const sameLease = this.#control?.leaseEpoch === message.lease_epoch;
      this.#control = {
        leaseEpoch: message.lease_epoch,
        pageId: message.page_id,
        frameTransformId: message.frame_transform_id,
      };
      if (!sameLease) {
        this.#inputSequence = 0;
        this.#compositionActive = false;
        this.#committedText = null;
      }
    } else {
      this.#control = null;
      this.#inputSequence = 0;
      this.#compositionActive = false;
      this.#committedText = null;
    }
    this.#onState(this.state);
  }

  #send(message) {
    if (this.#socket === null || this.#socket.readyState !== 1) {
      throw new ViewerError("viewer socket is not open");
    }
    this.#socket.send(JSON.stringify(message));
  }

  #setPhase(phase) {
    this.#phase = phase;
    this.#onState(this.state);
  }
}
