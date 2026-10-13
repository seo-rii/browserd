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
  | "cancelled";
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
export interface ActionResponse extends JsonObject { action_id: string; status: ActionStatus; session_sequence: number; trace_id?: string; retryable?: false }
export interface ApiEnvelope<T> { data: T; trace_id: string }
export type Isolation = "shared_context" | "tenant_dedicated_shard" | "dedicated_process" | "dedicated_worker";
export type SessionState = "creating" | "ready" | "closing" | "closed" | "failed";
export interface SessionResource extends JsonObject { id: string; state: SessionState; lifecycle: SessionState; incarnation: number; requested_isolation: Isolation; effective_isolation: Isolation; metadata: Record<string, string>; trace_id?: string }
export interface SessionListPage extends JsonObject { sessions: SessionResource[]; next_page_token: string | null; trace_id?: string }
export interface PageResource extends JsonObject { id: string; session_id: string; active: boolean; target_incarnation: number; document_epoch: number; url_revision: number; trace_id?: string }
export interface PageList extends JsonObject { pages: PageResource[]; trace_id?: string }
export interface DeletedPage extends JsonObject { id: string; deleted: true; trace_id?: string }
export interface Ownership extends JsonObject { worker_id: string; worker_epoch: number; placement_version: number; session_incarnation: number; trace_id?: string }
export interface OperationFailure extends JsonObject { code: string; message: string; retryable: boolean; details: Record<string, string> }
export interface Operation extends JsonObject { id: string; state: OperationState; poll_url: string; session: SessionResource | null; failure: OperationFailure | null; trace_id?: string }
export type EventKind = "operation.state_changed" | "session.lifecycle_changed" | "session.execution_changed" | "action.state_changed" | "action.approval_required" | "approval.decided" | "browser.control.changed" | "download.completed" | "artifact.state_changed";
export interface BrowserdEvent extends JsonObject { event_id: string; kind: EventKind; created_at: string; resource: { type: "operation" | "session" | "action" | "approval" | "artifact"; id: string }; aggregate_revision: number; session_id?: string; summary?: JsonObject }
export interface EventPage extends JsonObject { events: BrowserdEvent[]; next_cursor: string | null; gap: boolean; trace_id?: string }
export type ArtifactState = "uploading" | "stored" | "scanning" | "available" | "quarantined" | "rejected" | "generating" | "finalizing" | "failed" | "deleting" | "deleted";
export interface ArtifactMetadata extends JsonObject { id: string; state: ArtifactState; size_bytes?: number | null; content_type?: string | null; display_filename?: string | null; trace_id?: string }
export interface ArtifactListPage extends JsonObject { artifacts: ArtifactMetadata[]; next_cursor: string | null; trace_id?: string }
export interface ArtifactDownloadToken extends JsonObject { download_token: string; trace_id?: string }
export interface ViewerTicketIssued extends JsonObject { ticket_issued: true; trace_id?: string }
export interface Approval extends JsonObject { id: string; session_id: string; action_id: string; state: "pending" | "approved" | "denied" | "expired"; summary: JsonObject; trace_id?: string }
export interface ApprovalListPage extends JsonObject { approvals: Approval[]; next_page_token: string | null; trace_id?: string }
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

const OPERATION_STATES = new Set(["accepted", "queued", "reserving", "creating", "succeeded", "failed", "timed_out", "cancelled"]);
const ACTION_STATES = new Set(["accepted", "queued", "pending_approval", "ready_to_dispatch", "may_have_executed", "succeeded", "failed_known", "cancelled_before_dispatch", "cancelled_confirmed", "outcome_unknown"]);
const SESSION_STATES = new Set(["creating", "ready", "closing", "closed", "failed"]);
const ISOLATIONS = new Set(["shared_context", "tenant_dedicated_shard", "dedicated_process", "dedicated_worker"]);
const ARTIFACT_STATES = new Set(["uploading", "stored", "scanning", "available", "quarantined", "rejected", "generating", "finalizing", "failed", "deleting", "deleted"]);
const EVENT_KINDS = new Set(["operation.state_changed", "session.lifecycle_changed", "session.execution_changed", "action.state_changed", "action.approval_required", "approval.decided", "browser.control.changed", "download.completed", "artifact.state_changed"]);

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function requireWire(condition: unknown): asserts condition {
  if (!condition) throw new TypeError("invalid browserd success response");
}
function wireObject(value: unknown): JsonObject { requireWire(isObject(value)); return value; }
function wireString(value: unknown): void { requireWire(typeof value === "string" && value.length > 0); }
function wireInteger(value: unknown, minimum = 0): void { requireWire(Number.isSafeInteger(value) && (value as number) >= minimum); }
function wireState(value: unknown, states: Set<string>): void { requireWire(typeof value === "string" && states.has(value)); }
function wireCursor(value: unknown): void { if (value !== null) wireString(value); }
function wireArray(value: unknown, check: (item: unknown) => void): void { requireWire(Array.isArray(value)); value.forEach(check); }

function checkSession(value: unknown): void {
  const session = wireObject(value);
  wireString(session.id);
  wireState(session.state, SESSION_STATES);
  wireState(session.lifecycle, SESSION_STATES);
  requireWire(session.state === session.lifecycle);
  wireInteger(session.incarnation, 1);
  wireState(session.requested_isolation, ISOLATIONS);
  wireState(session.effective_isolation, ISOLATIONS);
  requireWire(Object.values(wireObject(session.metadata)).every((entry) => typeof entry === "string"));
}
function checkOperation(value: unknown): void {
  const operation = wireObject(value);
  wireString(operation.id);
  wireString(operation.poll_url);
  wireState(operation.state, OPERATION_STATES);
  requireWire(Object.hasOwn(operation, "session") && Object.hasOwn(operation, "failure"));
  if (operation.session !== null) checkSession(operation.session);
  if (operation.failure !== null) {
    const failure = wireObject(operation.failure);
    wireString(failure.code);
    requireWire(typeof failure.message === "string" && typeof failure.retryable === "boolean");
    requireWire(Object.values(wireObject(failure.details)).every((entry) => typeof entry === "string"));
  }
  requireWire(operation.state !== "succeeded" || (operation.session !== null && operation.failure === null));
  requireWire(operation.state === "succeeded" || operation.session === null);
}
function checkPage(value: unknown): void {
  const page = wireObject(value);
  wireString(page.id);
  wireString(page.session_id);
  requireWire(typeof page.active === "boolean");
  wireInteger(page.target_incarnation, 1);
  wireInteger(page.document_epoch, 1);
  wireInteger(page.url_revision);
}
function checkAction(value: unknown): void {
  const action = wireObject(value);
  wireString(action.action_id);
  wireState(action.status, ACTION_STATES);
  wireInteger(action.session_sequence, 1);
  if (action.status === "outcome_unknown") requireWire(action.retryable === false);
}
function checkArtifact(value: unknown): void {
  const artifact = wireObject(value);
  wireString(artifact.id);
  wireState(artifact.state, ARTIFACT_STATES);
  if (artifact.size_bytes !== undefined && artifact.size_bytes !== null) wireInteger(artifact.size_bytes);
  for (const field of ["content_type", "display_filename"]) {
    if (artifact[field] !== undefined && artifact[field] !== null) requireWire(typeof artifact[field] === "string");
  }
}
function checkApproval(value: unknown): void {
  const approval = wireObject(value);
  for (const field of ["id", "session_id", "action_id"]) wireString(approval[field]);
  wireState(approval.state, new Set(["pending", "approved", "denied", "expired"]));
  wireObject(approval.summary);
}
function checkEvent(value: unknown): void {
  const event = wireObject(value);
  wireString(event.event_id);
  wireState(event.kind, EVENT_KINDS);
  wireString(event.created_at);
  requireWire(Number.isFinite(Date.parse(event.created_at as string)));
  const resource = wireObject(event.resource);
  wireState(resource.type, new Set(["operation", "session", "action", "approval", "artifact"]));
  wireString(resource.id);
  wireInteger(event.aggregate_revision);
  if (event.session_id !== undefined) wireString(event.session_id);
  if (event.summary !== undefined) {
    const summary = wireObject(event.summary);
    const states: Record<string, Set<string>> = {
      operation: OPERATION_STATES, session_lifecycle: SESSION_STATES,
      session_execution: new Set(["idle", "running", "pending_approval", "reconciliation_required"]),
      action: ACTION_STATES, approval: new Set(["approved", "denied", "expired"]),
      control: new Set(["agent", "human"]), download: new Set(["completed"]), artifact: ARTIFACT_STATES,
    };
    wireString(summary.type);
    if (summary.type === "approval_required") wireString(summary.approval_id);
    else { requireWire(Object.hasOwn(states, summary.type as string)); wireState(summary.state, states[summary.type as string]!); }
    if (summary.action_id !== undefined) wireString(summary.action_id);
    if (summary.resolution !== undefined) wireState(summary.resolution, new Set(["confirmed_executed", "confirmed_not_executed", "abandoned"]));
  }
}

function decodeSuccess(value: unknown, method: string, path: string): JsonObject {
  const envelope = wireObject(value);
  wireString(envelope.trace_id);
  const data = wireObject(envelope.data);
  const parts = path.split("?", 1)[0]!.split("/").filter(Boolean);
  let result = data;
  if (parts[1] === "operations" || (parts.length === 2 && parts[1] === "sessions" && method === "POST")) {
    result = wireObject(data.operation); checkOperation(result);
  } else if (parts[1] === "events") {
    wireArray(data.events, checkEvent); requireWire(typeof data.gap === "boolean"); wireCursor(data.next_cursor);
  } else if (parts[1] === "approvals") {
    if (parts.length === 2) { wireArray(data.approvals, checkApproval); wireCursor(data.next_page_token); }
    else { result = wireObject(data.approval); checkApproval(result); }
  } else if (parts[1] === "sessions") {
    if (parts.length === 2) { wireArray(data.sessions, checkSession); wireCursor(data.next_page_token); }
    else if (parts.length === 3) { result = wireObject(data.session); checkSession(result); }
    else if (parts[3] === "reconnect" || parts[3] === "transfer") {
      result = wireObject(data.ownership); wireString(result.worker_id);
      for (const field of ["worker_epoch", "placement_version", "session_incarnation"]) wireInteger(result[field], 1);
    } else if (parts[3] === "pages") {
      if (parts.length === 4 && method === "GET") wireArray(data.pages, checkPage);
      else {
        result = wireObject(data.page);
        if (method === "DELETE") { wireString(result.id); requireWire(result.deleted === true); }
        else checkPage(result);
      }
    } else if (parts[3] === "actions") checkAction(result);
    else if (parts[3] === "viewer-ticket") requireWire(data.ticket_issued === true);
    else if (parts[3] === "artifacts") {
      if (parts.length === 4) { wireArray(data.artifacts, checkArtifact); wireCursor(data.next_cursor); }
      else if (parts[5] === "download") wireString(data.download_token);
      else { result = wireObject(data.artifact); checkArtifact(result); }
    } else requireWire(false);
  } else requireWire(false);
  return { ...result, trace_id: envelope.trace_id };
}

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

  async createSession(body: JsonObject, options: RequestOptions = {}): Promise<Operation> {
    return this.request("POST", "/v1/sessions", { body, replay: "pre-dispatch", ...options });
  }

  async getOperation(operationId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<Operation> {
    return this.request("GET", `/v1/operations/${this.segment(operationId)}`, { replay: "read", ...options });
  }

  async cancelOperation(operationId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<Operation> {
    return this.request("DELETE", `/v1/operations/${this.segment(operationId)}`, { replay: "read", ...options });
  }

  async listSessions(options: { lifecycle?: SessionState; isolation?: Isolation; metadataKey?: string; limit?: number; pageToken?: string; requestId?: string } = {}): Promise<SessionListPage> {
    return this.request("GET", this.withQuery("/v1/sessions", {
      lifecycle: options.lifecycle,
      isolation: options.isolation,
      metadata_key: options.metadataKey,
      limit: options.limit,
      page_token: options.pageToken,
    }), { replay: "read", requestId: options.requestId });
  }

  async getSession(sessionId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<SessionResource> {
    return this.request("GET", `/v1/sessions/${this.segment(sessionId)}`, { replay: "read", ...options });
  }

  async closeSession(sessionId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<SessionResource> {
    return this.request("DELETE", `/v1/sessions/${this.segment(sessionId)}`, { replay: "read", ...options });
  }

  async reconnectSession(sessionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<Ownership> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/reconnect`, { body, replay: "unsafe", ...options });
  }

  async transferSession(sessionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<Ownership> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/transfer`, { body, replay: "unsafe", ...options });
  }

  async listPages(sessionId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<PageList> {
    return this.request("GET", `/v1/sessions/${this.segment(sessionId)}/pages`, { replay: "read", ...options });
  }

  async createPage(sessionId: string, body: JsonObject = {}, options: Pick<RequestOptions, "requestId"> = {}): Promise<PageResource> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/pages`, { body, replay: "unsafe", ...options });
  }

  async closePage(sessionId: string, pageId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<DeletedPage> {
    return this.request("DELETE", `/v1/sessions/${this.segment(sessionId)}/pages/${this.segment(pageId)}`, { replay: "read", ...options });
  }

  async activatePage(sessionId: string, pageId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<PageResource> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/pages/${this.segment(pageId)}/activate`, { replay: "unsafe", ...options });
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

  async resolveAction(sessionId: string, actionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<ActionResponse> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/actions/${this.segment(actionId)}/resolve`, { body, replay: "read", ...options });
  }

  async listEvents(options: { cursor?: string; limit?: number; requestId?: string } = {}): Promise<EventPage> {
    return this.request("GET", this.withQuery("/v1/events", { cursor: options.cursor, limit: options.limit }), { replay: "read", requestId: options.requestId });
  }

  async createViewerTicket(sessionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<ViewerTicketIssued> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/viewer-ticket`, { body, replay: "unsafe", ...options });
  }

  viewerWebSocketUrl(sessionId: string): string {
    const url = new URL(`${this.baseUrl}/v1/sessions/${this.segment(sessionId)}/viewer`);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    return url.toString();
  }

  async createArtifactUpload(sessionId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<ArtifactMetadata> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/artifacts/uploads`, { body, replay: "unsafe", ...options });
  }

  async getArtifact(sessionId: string, artifactId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<ArtifactMetadata> {
    return this.request<ArtifactMetadata>(
      "GET", `/v1/sessions/${this.segment(sessionId)}/artifacts/${this.segment(artifactId)}`, { replay: "read", ...options },
    );
  }

  async listArtifacts(sessionId: string, options: { after?: string; limit?: number; requestId?: string } = {}): Promise<ArtifactListPage> {
    if (!sessionId || sessionId === "." || sessionId === "..") {
      throw new TypeError("sessionId must be a nonempty identifier, not a dot path segment");
    }
    const limit = options.limit ?? 50;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new RangeError("artifact limit must be an integer from 1 to 100");
    }
    return this.request<ArtifactListPage>("GET", this.withQuery(
      `/v1/sessions/${this.segment(sessionId)}/artifacts`,
      { after: options.after, limit },
    ), { replay: "read", requestId: options.requestId });
  }

  async createArtifactDownloadToken(sessionId: string, artifactId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<ArtifactDownloadToken> {
    return this.request("POST", `/v1/sessions/${this.segment(sessionId)}/artifacts/${this.segment(artifactId)}/download`, { replay: "unsafe", ...options });
  }

  async listApprovals(options: { state?: string; sessionId?: string; limit?: number; pageToken?: string; requestId?: string } = {}): Promise<ApprovalListPage> {
    return this.request("GET", this.withQuery("/v1/approvals", {
      state: options.state,
      session_id: options.sessionId,
      limit: options.limit,
      page_token: options.pageToken,
    }), { replay: "read", requestId: options.requestId });
  }

  async getApproval(approvalId: string, options: Pick<RequestOptions, "requestId"> = {}): Promise<Approval> {
    return this.request("GET", `/v1/approvals/${this.segment(approvalId)}`, { replay: "read", ...options });
  }

  async decideApproval(approvalId: string, body: JsonObject, options: Pick<RequestOptions, "requestId"> = {}): Promise<Approval> {
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
      if (page.gap) throw new EventGapError(page.next_cursor ?? undefined);
      for (const event of page.events) yield event;
      cursor = page.next_cursor ?? cursor;
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
      let decoded: unknown;
      try {
        const text = await response.text();
        decoded = text ? JSON.parse(text) : null;
        if (response.ok) return decodeSuccess(decoded, method, path) as T;
      } catch (cause) {
        if (options.replay !== "read") {
          throw new DispatchUncertainError(requestId, idempotencyKey, cause);
        }
        throw new TransportError(requestId, cause);
      }
      const raw = isObject(decoded) && isObject(decoded.error) ? decoded.error as Partial<ErrorEnvelope> : undefined;
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
