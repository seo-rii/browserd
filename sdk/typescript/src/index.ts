export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export type JsonObject = Record<string, unknown>;
export type OperationState =
  | "accepted"
  | "queued"
  | "reserving"
  | "creating"
  | "succeeded"
  | "failed"
  | "timed_out"
  | "cancelled"
  | "cancel_pending";
export type ActionStatus =
  | "accepted"
  | "queued"
  | "pending_approval"
  | "ready_to_dispatch"
  | "may_have_executed"
  | "succeeded"
  | "failed_known"
  | "cancelled_before_dispatch"
  | "cancelled_confirmed"
  | "outcome_unknown";
export type ActionType =
  | "navigate" | "reload" | "go_back" | "go_forward"
  | "click" | "double_click" | "hover" | "fill" | "fill_secret" | "type_text"
  | "press_key" | "scroll" | "select_option" | "set_files" | "focus" | "blur"
  | "check" | "uncheck" | "handle_dialog"
  | "snapshot" | "get_text" | "get_html" | "get_url" | "get_title" | "get_attribute"
  | "get_properties" | "get_computed_style" | "query_all" | "extract_table"
  | "new_page" | "close_page" | "activate_page" | "wait_for" | "evaluate"
  | "screenshot" | "pdf" | "scrape" | "checkpoint";

export interface Action extends JsonObject { type: ActionType }
export interface ActionRequest extends JsonObject { action: Action; page_id?: string; if_session_incarnation?: number; execution_timeout_ms?: number }
export interface ActionResponse extends JsonObject { action_id: string; status: ActionStatus; trace_id?: string; retryable?: false }
export interface Operation extends JsonObject { id: string; state: OperationState; poll_url?: string }
export interface BrowserdEvent extends JsonObject { event_id: string; type?: string }
export interface EventPage extends JsonObject { events: BrowserdEvent[]; next_cursor?: string; cursor?: string; latest_cursor?: string; gap?: boolean }
export interface ArtifactMetadata extends JsonObject { artifact_id?: string; state?: string; size_bytes?: number; content_type?: string }
export interface ArtifactDownloadToken extends JsonObject { token?: string; expires_at?: string }
export interface ErrorEnvelope {
  code: string;
  message: string;
  retryable: boolean;
  details: JsonObject;
  trace_id?: string;
}

export class BrowserdError extends Error {
  readonly code: string;
  readonly status: number;
  readonly retryable: boolean;
  readonly details: JsonObject;
  readonly traceId?: string;
  readonly requestId?: string;

  constructor(status: number, envelope: ErrorEnvelope, requestId?: string) {
    super(envelope.message);
    this.name = "BrowserdError";
    this.code = envelope.code;
    this.status = status;
    this.retryable = envelope.retryable;
    this.details = envelope.details ?? {};
    this.traceId = envelope.trace_id;
    this.requestId = requestId;
  }
}

export class DispatchUncertainError extends Error {
  readonly requestId: string;
  readonly idempotencyKey?: string;
  readonly cause: unknown;

  constructor(requestId: string, idempotencyKey: string | undefined, cause: unknown) {
    super("The mutating request may have been dispatched; it was not automatically replayed.");
    this.name = "DispatchUncertainError";
    this.requestId = requestId;
    this.idempotencyKey = idempotencyKey;
    this.cause = cause;
  }
}

export class TransportError extends Error {
  readonly requestId: string;
  readonly cause: unknown;

  constructor(requestId: string, cause: unknown) {
    super("browserd transport failed");
    this.name = "TransportError";
    this.requestId = requestId;
    this.cause = cause;
  }
}

export class EventGapError extends Error {
  readonly latestCursor?: string;

  constructor(latestCursor?: string) {
    super("The event cursor is outside the retention window; poll resource state before resuming.");
    this.name = "EventGapError";
    this.latestCursor = latestCursor;
  }
}

export interface ClientOptions {
  baseUrl: string;
  token?: string;
  fetch?: FetchLike;
  maxRetries?: number;
  retryBaseMs?: number;
  sleep?: (milliseconds: number) => Promise<void>;
}

export interface RequestOptions {
  requestId?: string;
  idempotencyKey?: string;
  waitMs?: number;
}

type ReplayMode = "read" | "pre-dispatch" | "unsafe";

const PRE_DISPATCH_CODES = new Set([
  "action_admission_timeout",
  "queue_timeout",
  "global_capacity_exceeded",
  "tenant_quota_exceeded",
  "rate_limited",
  "audit_unavailable",
  "browser_start_failed",
  "context_create_failed",
]);
const TERMINAL_OPERATIONS = new Set<OperationState>(["succeeded", "failed", "timed_out", "cancelled"]);

export class BrowserdClient {
  readonly baseUrl: string;
  private readonly token?: string;
  private readonly fetch: FetchLike;
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;
  private readonly sleep: (milliseconds: number) => Promise<void>;

  constructor(options: ClientOptions) {
    let parsedBaseUrl: URL;
    try {
      parsedBaseUrl = new URL(options.baseUrl);
    } catch (cause) {
      throw new TypeError("baseUrl must be an absolute HTTP(S) URL", { cause });
    }
    if (
      !["http:", "https:"].includes(parsedBaseUrl.protocol)
      || !parsedBaseUrl.hostname
      || parsedBaseUrl.username
      || parsedBaseUrl.password
      || options.baseUrl.includes("?")
      || options.baseUrl.includes("#")
    ) {
      throw new TypeError("baseUrl must be HTTP(S) and contain no credentials, query, or fragment");
    }
    this.baseUrl = parsedBaseUrl.toString().replace(/\/+$/, "");
    this.token = options.token;
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.maxRetries = Math.max(0, options.maxRetries ?? 2);
    this.retryBaseMs = Math.max(0, options.retryBaseMs ?? 100);
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  }

  async createSession(body: JsonObject, options: RequestOptions = {}): Promise<JsonObject> {
    return this.request("POST", "/v1/sessions", { body, replay: "pre-dispatch", ...options });
  }

  async getOperation(operationId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<Operation> {
    return this.request("GET", `/v1/operations/${this.segment(operationId)}`, { replay: "read", ...options });
  }

  async cancelOperation(operationId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("DELETE", `/v1/operations/${this.segment(operationId)}`, { replay: "read", ...options });
  }

  async listSessions(options: { lifecycle?: string; isolation?: string; metadataKey?: string; limit?: number; pageToken?: string; requestId?: string } = {}): Promise<JsonObject> {
    return this.request("GET", this.withQuery("/v1/sessions", {
      lifecycle: options.lifecycle,
      isolation: options.isolation,
      metadata_key: options.metadataKey,
      limit: options.limit,
      page_token: options.pageToken,
    }), { replay: "read", requestId: options.requestId });
  }

  async getSession(sessionId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("GET", `/v1/sessions/${this.segment(sessionId)}`, { replay: "read", ...options });
  }

  async closeSession(sessionId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("DELETE", `/v1/sessions/${this.segment(sessionId)}`, { replay: "read", ...options });
  }

  async reconnectSession(sessionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/reconnect`, { body, replay: "unsafe", ...options });
  }

  async transferSession(sessionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/transfer`, { body, replay: "unsafe", ...options });
  }

  async listPages(sessionId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("GET", `/v1/sessions/${this.segment(sessionId)}/pages`, { replay: "read", ...options });
  }

  async createPage(sessionId: string, body: JsonObject = {}, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/pages`, { body, replay: "unsafe", ...options });
  }

  async closePage(sessionId: string, pageId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("DELETE", `/v1/sessions/${this.segment(sessionId)}/pages/${this.segment(pageId)}`, { replay: "read", ...options });
  }

  async activatePage(sessionId: string, pageId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/pages/${this.segment(pageId)}/activate`, { body: {}, replay: "unsafe", ...options });
  }

  async createAction(sessionId: string, body: ActionRequest, options: RequestOptions = {}): Promise<ActionResponse> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/actions`, { body, replay: "pre-dispatch", ...options });
  }

  async getAction(sessionId: string, actionId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<ActionResponse> {
    return this.request("GET", `/v1/sessions/${this.segment(sessionId)}/actions/${this.segment(actionId)}`, { replay: "read", ...options });
  }

  async cancelAction(sessionId: string, actionId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<ActionResponse> {
    return this.request("DELETE", `/v1/sessions/${this.segment(sessionId)}/actions/${this.segment(actionId)}`, { replay: "read", ...options });
  }

  async resolveAction(sessionId: string, actionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/actions/${this.segment(actionId)}/resolve`, { body, replay: "read", ...options });
  }

  async listEvents(options: { cursor?: string; limit?: number; requestId?: string } = {}): Promise<EventPage> {
    return this.request("GET", this.withQuery("/v1/events", { cursor: options.cursor, limit: options.limit }), { replay: "read", requestId: options.requestId });
  }

  async createViewerTicket(sessionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/viewer-ticket`, { body, replay: "unsafe", ...options });
  }

  viewerWebSocketUrl(sessionId: string): string {
    const url = new URL(`${this.baseUrl}/v1/sessions/${this.segment(sessionId)}/viewer`);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    return url.toString();
  }

  async createArtifactUpload(sessionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/artifacts/uploads`, { body, replay: "unsafe", ...options });
  }

  async getArtifact(sessionId: string, artifactId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<ArtifactMetadata> {
    return this.request("GET", `/v1/sessions/${this.segment(sessionId)}/artifacts/${this.segment(artifactId)}`, { replay: "read", ...options });
  }

  async createArtifactDownloadToken(sessionId: string, artifactId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<ArtifactDownloadToken> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/artifacts/${this.segment(artifactId)}/download`, { replay: "unsafe", ...options });
  }

  async listApprovals(options: { state?: string; sessionId?: string; limit?: number; pageToken?: string; requestId?: string } = {}): Promise<JsonObject> {
    return this.request("GET", this.withQuery("/v1/approvals", {
      state: options.state,
      session_id: options.sessionId,
      limit: options.limit,
      page_token: options.pageToken,
    }), { replay: "read", requestId: options.requestId });
  }

  async getApproval(approvalId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("GET", `/v1/approvals/${this.segment(approvalId)}`, { replay: "read", ...options });
  }

  async decideApproval(approvalId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<JsonObject> {
    return this.request("POST", `/v1/approvals/${this.segment(approvalId)}/decision`, { body, replay: "unsafe", ...options });
  }

  async waitForOperation(operationId: string, options: { intervalMs?: number; maxPolls?: number; signal?: AbortSignal } = {}): Promise<Operation> {
    const intervalMs = Math.max(0, options.intervalMs ?? 250);
    const maxPolls = Math.max(1, options.maxPolls ?? Number.POSITIVE_INFINITY);
    for (let poll = 0; poll < maxPolls; poll += 1) {
      if (options.signal?.aborted) throw options.signal.reason ?? new Error("aborted");
      const operation = await this.getOperation(operationId);
      if (TERMINAL_OPERATIONS.has(operation.state)) return operation;
      if (poll + 1 < maxPolls) await this.sleep(intervalMs);
    }
    throw new Error("operation polling limit reached");
  }

  async *resumeEvents(options: { cursor?: string; limit?: number; intervalMs?: number; maxPolls?: number; signal?: AbortSignal } = {}): AsyncGenerator<BrowserdEvent> {
    let cursor = options.cursor;
    const maxPolls = Math.max(1, options.maxPolls ?? Number.POSITIVE_INFINITY);
    for (let poll = 0; poll < maxPolls; poll += 1) {
      if (options.signal?.aborted) return;
      const page = await this.listEvents({ cursor, limit: options.limit });
      if (page.gap) throw new EventGapError(page.latest_cursor ?? page.next_cursor ?? page.cursor);
      for (const event of page.events ?? []) yield event;
      cursor = page.next_cursor ?? page.latest_cursor ?? page.cursor ?? cursor;
      if (poll + 1 < maxPolls) await this.sleep(Math.max(0, options.intervalMs ?? 250));
    }
  }

  async waitForAction(sessionId: string, actionId: string, options: { intervalMs?: number; maxPolls?: number; signal?: AbortSignal } = {}): Promise<ActionResponse> {
    const terminal = new Set<ActionStatus>(["succeeded", "failed_known", "cancelled_before_dispatch", "cancelled_confirmed", "outcome_unknown"]);
    const maxPolls = Math.max(1, options.maxPolls ?? Number.POSITIVE_INFINITY);
    for (let poll = 0; poll < maxPolls; poll += 1) {
      if (options.signal?.aborted) throw options.signal.reason ?? new Error("aborted");
      const action = await this.getAction(sessionId, actionId);
      if (terminal.has(action.status)) return action;
      if (poll + 1 < maxPolls) await this.sleep(Math.max(0, options.intervalMs ?? 250));
    }
    throw new Error("action polling limit reached");
  }

  isOutcomeUnknown(value: Pick<ActionResponse, "status">): boolean {
    return value.status === "outcome_unknown";
  }

  private segment(value: string): string {
    return encodeURIComponent(value);
  }

  private withQuery(path: string, values: Record<string, string | number | undefined>): string {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) if (value !== undefined) query.set(key, String(value));
    const encoded = query.toString();
    return encoded ? `${path}?${encoded}` : path;
  }

  private async request<T>(method: string, path: string, options: RequestOptions & { body?: unknown; replay: ReplayMode }): Promise<T> {
    const requestId = options.requestId ?? crypto.randomUUID();
    const idempotencyKey = options.idempotencyKey ?? (options.replay === "pre-dispatch" ? crypto.randomUUID() : undefined);
    const headers = new Headers({ "accept": "application/json", "x-request-id": requestId });
    if (this.token) headers.set("authorization", `Bearer ${this.token}`);
    if (options.body !== undefined) headers.set("content-type", "application/json");
    if (idempotencyKey) headers.set("idempotency-key", idempotencyKey);
    if (options.waitMs !== undefined) headers.set("prefer", `wait=${Math.max(0, Math.floor(options.waitMs))}`);
    const init: RequestInit = { method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) };

    for (let attempt = 0; ; attempt += 1) {
      let response: Response;
      try {
        response = await this.fetch(`${this.baseUrl}${path}`, init);
      } catch (cause) {
        if (options.replay === "read" && attempt < this.maxRetries) {
          await this.sleep(this.retryBaseMs * 2 ** attempt);
          continue;
        }
        if (options.replay !== "read") throw new DispatchUncertainError(requestId, idempotencyKey, cause);
        throw new TransportError(requestId, cause);
      }
      let decoded: JsonObject;
      try {
        const text = await response.text();
        decoded = text ? JSON.parse(text) as JsonObject : {};
      } catch (cause) {
        if (options.replay !== "read") {
          throw new DispatchUncertainError(requestId, idempotencyKey, cause);
        }
        throw new TransportError(requestId, cause);
      }
      if (response.ok) return decoded as T;
      const raw = decoded.error as Partial<ErrorEnvelope> | undefined;
      const envelope: ErrorEnvelope = {
        code: raw?.code ?? "internal",
        message: raw?.message ?? `browserd returned HTTP ${response.status}`,
        retryable: raw?.retryable === true,
        details: raw?.details ?? {},
        trace_id: raw?.trace_id,
      };
      const error = new BrowserdError(response.status, envelope, response.headers.get("x-request-id") ?? requestId);
      const replaySafe = options.replay === "read" || (options.replay === "pre-dispatch" && PRE_DISPATCH_CODES.has(error.code));
      if (error.retryable && replaySafe && attempt < this.maxRetries) {
        await this.sleep(this.retryBaseMs * 2 ** attempt);
        continue;
      }
      throw error;
    }
  }
}
