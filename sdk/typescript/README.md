# browserd TypeScript client

Dependency-free client for the public browserd `/v1` API. It uses the platform `fetch`, generates
`X-Request-Id` and idempotency keys, provides operation/action polling and resumable event polling,
and exposes every public HTTP route in `SPEC.md`.

```ts
import { BrowserdClient } from "@browserd/client";

const client = new BrowserdClient({ baseUrl: "https://browserd.example", token: process.env.BROWSERD_TOKEN });
const created = await client.createSession({
  isolation: "shared_context", workload_class_hint: "interactive",
  viewport: { width: 1280, height: 720, device_scale_factor: 1 },
  locale: "ko-KR", timezone: "Asia/Seoul", network_policy_id: "public-web-default",
  network_class: "public", dialog_policy: "auto_dismiss", feature_profile: "standard",
  ttl_seconds: 1800, idle_timeout_seconds: 600, metadata: {},
});
const operation = await client.waitForOperation(created.id);
if (operation.state === "succeeded") console.log(operation.session?.id);
```

Successful HTTP responses use `{ data, trace_id }`. Each SDK method validates and removes
that envelope and its resource wrapper once: session creation and operation methods return
`Operation`, session methods return `SessionResource`, and action methods return
`ActionResponse`. Lists retain their collection and continuation fields. Every returned
resource or list retains `trace_id`; operation polling also retains `session` and `failure`.
Session resources include equal `state` and `lifecycle` fields, requested/effective isolation,
and incarnation. Page resources retain target incarnation, document epoch and URL revision.
Events use `kind`, `resource` and `summary`; `next_cursor` advances polling and `gap` raises
`EventGapError`. Viewer ticket creation returns `ticket_issued` and download authorization
returns `download_token`.

A malformed success response raises `TransportError` for reads and
`DispatchUncertainError` for mutations. It stops polling immediately and is never replayed.
The shared `sdk/fixtures/http_contract.json` is checked against the Rust HTTP renderer and
consumed by both SDK suites.

Safety behavior is deliberately conservative:

- a transport failure during a mutating request raises `DispatchUncertainError` and is never replayed;
- `status: "outcome_unknown"` is returned as a terminal `ActionResponse`, never thrown or retried;
- only reads/idempotent deletes and explicitly known pre-dispatch error codes are retried;
- event retention gaps raise `EventGapError`; callers must poll authoritative resource state.
- base URLs must be HTTP(S) and cannot contain credentials, query parameters, or fragments.

Run tests with `npm test` on Node.js 22.18 or newer.

Query a nested iframe, including an out-of-process iframe, with `frame_path`.
Each CSS selector in the path must match exactly one frame element in the current
document. The final `selector` queries that frame's document and returns opaque
`node_refs` for subsequent node actions on the same `page_id`. Omit `frame_path`
or pass `[]` to query the main document. Paths allow at most 8 selectors, each at
most 8,192 UTF-8 bytes, with a combined limit of 32,768 bytes. A missing or
ambiguous frame is rejected. `fill_secret` and `set_files` support main-document
nodes only.

```ts
await client.createAction(sessionId, {
  page_id: pageId,
  if_session_incarnation: sessionIncarnation,
  execution_timeout_ms: 30_000,
  action: {
    type: "query_all",
    frame_path: ["iframe#checkout", "iframe[name=address]"],
    selector: "input[name=city]",
  },
});
```

List session artifacts, including browser downloads after scan and publication, with
`listArtifacts`. It returns an `ArtifactListPage` containing `artifacts` and `next_cursor`.
The default page size is 50; `limit` must be an integer from 1 to 100. Pass `next_cursor`
as `after` to continue, and stop when it is `null`.
`getArtifact` returns the same metadata shape as each list item. `display_filename`
is the original upload basename when available; it may be `null` or absent for
unnamed artifacts. It is display metadata; downloads use the fixed `artifact.bin` filename.

```ts
const page = await client.listArtifacts("ses-...", { limit: 50 });
for (const artifact of page.artifacts) console.log(artifact.id, artifact.size_bytes);
if (page.next_cursor !== null) {
  const nextPage = await client.listArtifacts("ses-...", { after: page.next_cursor });
}
```

Attach available artifacts from the same session to a file input obtained with
`query_all`. The capability needs `browser:act` and `artifact:read`. File paths
are managed by the server; send only artifact IDs. Upload basenames are preserved.

```ts
await client.createAction(sessionId, {
  page_id: pageId,
  action: { type: "set_files", node_ref: inputNodeRef, artifact_ids: [artifactId] },
});
```

Fill a configured credential reference with `browser:act` and `secret:use`.
The worker must grant the tenant and principal access at the exact page origin.
Send the reference and node handle; keep the value in the worker's private provider.

```ts
await client.createAction(sessionId, {
  page_id: pageId,
  action: { type: "fill_secret", node_ref: inputNodeRef, secret_ref: "login/password" },
});
```

Create a checkpoint with `browser:act` and `checkpoint:create`. List exact origins
whose owned pages have the desired `localStorage`; omit the list for cookies only.
Poll the returned action until it succeeds, then use `result.checkpoint_ref` in
a new `createSession` request. Restoration additionally needs `checkpoint:read`.
It creates a new session and requires the same tenant and Chromium artifact.

```ts
await client.createAction(sessionId, {
  action: { type: "checkpoint", origins: ["https://example.test"] },
});
// After polling the action and reading its checkpoint_ref:
await client.createSession({ ...sessionOptions, checkpoint_ref: checkpointRef });
```
