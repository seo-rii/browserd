import { createTicketFetcher, mapPointerToFrame } from "./ui.mjs";
import { BrowserViewer } from "./viewer.mjs";

const elements = {
  form: document.querySelector("#connect-form"),
  sessionId: document.querySelector("#session-id"),
  connect: document.querySelector("#connect"),
  disconnect: document.querySelector("#disconnect"),
  control: document.querySelector("#control"),
  release: document.querySelector("#release"),
  status: document.querySelector("#status"),
  statusDot: document.querySelector("#status-dot"),
  viewport: document.querySelector("#viewport"),
  frame: document.querySelector("#frame"),
  empty: document.querySelector("#empty-state"),
  frameDetail: document.querySelector("#frame-detail"),
  ime: document.querySelector("#ime-input"),
};

const apiBase = new URL(document.body.dataset.apiBase || "/", window.location.origin);
let viewer = null;
let objectUrl = null;
let frameDimensions = null;

function sendInputIfControlling(type, payload) {
  if (viewer?.state.controlling) viewer.sendInput(type, payload);
}

function setStatus(state) {
  const labels = {
    disconnected: "Disconnected",
    ticketing: "Authorizing…",
    connecting: "Connecting…",
    connected: state.controlling ? "Human control" : "Observing",
    error: "Connection error",
  };
  elements.status.textContent = labels[state.phase] ?? state.phase;
  elements.statusDot.className = "status-dot";
  if (state.phase === "connected") elements.statusDot.classList.add("online");
  if (state.phase === "error") elements.statusDot.classList.add("error");

  const connected = state.phase === "connected";
  elements.connect.disabled = state.phase !== "disconnected";
  elements.disconnect.disabled = !connected;
  elements.control.disabled = !connected || state.controlling;
  elements.release.disabled = !connected || !state.controlling;
  elements.ime.disabled = !connected || !state.controlling;
}

function showFrame(frame) {
  const width = Number(frame.metadata.width);
  const height = Number(frame.metadata.height);
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1) {
    return;
  }
  frameDimensions = { width, height };
  const nextUrl = URL.createObjectURL(new Blob([frame.jpeg], { type: "image/jpeg" }));
  elements.frame.src = nextUrl;
  elements.frame.classList.add("visible");
  elements.empty.hidden = true;
  elements.frameDetail.textContent = `${width}×${height} · frame ${frame.frameId} · transform ${frame.transformEpoch}`;
  if (objectUrl !== null) URL.revokeObjectURL(objectUrl);
  objectUrl = nextUrl;
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const sessionId = elements.sessionId.value.trim();
  try {
    viewer = new BrowserViewer({
      sessionId,
      endpoint: apiBase,
      fetchTicket: createTicketFetcher({
        endpoint: apiBase,
        locationOrigin: window.location.origin,
      }),
      onFrame: showFrame,
      onState: setStatus,
    });
    await viewer.connect();
  } catch (error) {
    setStatus({ phase: "error", controlling: false });
    elements.status.textContent = error.message;
    viewer = null;
  }
});

elements.disconnect.addEventListener("click", () => viewer?.disconnect());
elements.control.addEventListener("click", () => viewer?.requestControl());
elements.release.addEventListener("click", () => viewer?.releaseControl());

function pointerPayload(event, phase) {
  if (frameDimensions === null || !elements.frame.classList.contains("visible")) return;
  const point = mapPointerToFrame(event, elements.frame.getBoundingClientRect(), frameDimensions);
  sendInputIfControlling("mouse", {
    ...point,
    phase,
    button: ["left", "middle", "right"][event.button] ?? "none",
    buttons: event.buttons,
  });
}

elements.frame.addEventListener("pointerdown", (event) => {
  elements.viewport.focus();
  elements.frame.setPointerCapture(event.pointerId);
  pointerPayload(event, "down");
});
elements.frame.addEventListener("pointermove", (event) => {
  if (event.buttons !== 0) pointerPayload(event, "move");
});
elements.frame.addEventListener("pointerup", (event) => pointerPayload(event, "up"));
elements.frame.addEventListener("contextmenu", (event) => event.preventDefault());
elements.frame.addEventListener("wheel", (event) => {
  event.preventDefault();
  sendInputIfControlling("wheel", { delta_x: event.deltaX, delta_y: event.deltaY });
}, { passive: false });

elements.viewport.addEventListener("keydown", (event) => {
  if (event.target === elements.ime) return;
  event.preventDefault();
  sendInputIfControlling("key", {
    phase: "down",
    key: event.key,
    code: event.code,
    alt: event.altKey,
    ctrl: event.ctrlKey,
    meta: event.metaKey,
    shift: event.shiftKey,
  });
});
elements.viewport.addEventListener("keyup", (event) => {
  if (event.target === elements.ime) return;
  event.preventDefault();
  sendInputIfControlling("key", {
    phase: "up",
    key: event.key,
    code: event.code,
    alt: event.altKey,
    ctrl: event.ctrlKey,
    meta: event.metaKey,
    shift: event.shiftKey,
  });
});

elements.ime.addEventListener("compositionstart", () => {
  if (viewer?.state.controlling) viewer.compositionStart();
});
elements.ime.addEventListener("compositionupdate", (event) => {
  if (viewer?.state.controlling) viewer.compositionUpdate(event.data);
});
elements.ime.addEventListener("compositionend", (event) => {
  if (viewer?.state.controlling) viewer.compositionCommit(event.data);
  elements.ime.value = "";
});
elements.ime.addEventListener("beforeinput", (event) => {
  if (!event.isComposing && event.data) sendInputIfControlling("insert_text", { text: event.data });
});

window.addEventListener("beforeunload", () => {
  viewer?.disconnect();
  if (objectUrl !== null) URL.revokeObjectURL(objectUrl);
});

const initialSession = new URLSearchParams(window.location.search).get("session_id");
if (initialSession && /^[A-Za-z0-9_-]+$/.test(initialSession)) {
  elements.sessionId.value = initialSession;
}
setStatus({ phase: "disconnected", controlling: false });
