# browserd Python client

Standard-library-only client for every public browserd `/v1` HTTP route. It generates request and
idempotency IDs, decodes typed error envelopes, polls operations/actions, and resumes event polling.

```python
from browserd import BrowserdClient

client = BrowserdClient("https://browserd.example", token="service-capability")
created = client.create_session({
    "isolation": "shared_context", "workload_class_hint": "interactive",
    "viewport": {"width": 1280, "height": 720, "device_scale_factor": 1},
    "locale": "ko-KR", "timezone": "Asia/Seoul", "network_policy_id": "public-web-default",
    "network_class": "public", "dialog_policy": "auto_dismiss", "feature_profile": "standard",
    "ttl_seconds": 1800, "idle_timeout_seconds": 600, "metadata": {},
})
operation = client.wait_for_operation(created["id"])
if operation["state"] == "succeeded":
    print(operation["session"]["id"])
```

Successful HTTP responses use `{data, trace_id}`. Each SDK method validates and removes
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

Mutating transport uncertainty raises `DispatchUncertainError` without replay. An
`outcome_unknown` action remains a normal terminal response and is never automatically retried.
Expired event cursors raise `EventGapError` so callers can poll authoritative resource state.
Base URLs must be HTTP(S) and cannot contain credentials, query parameters, or fragments.

Run tests with `PYTHONPATH=. python3 -m unittest discover -s tests -v`.

Query a nested iframe, including an out-of-process iframe, with `frame_path`.
Each CSS selector in the path must match exactly one frame element in the current
document. The final `selector` queries that frame's document and returns opaque
`node_refs` for subsequent node actions on the same `page_id`. Omit `frame_path`
or pass `[]` to query the main document. Paths allow at most 8 selectors, each at
most 8,192 UTF-8 bytes, with a combined limit of 32,768 bytes. A missing or
ambiguous frame is rejected. `fill_secret` and `set_files` support main-document
nodes only.

```python
client.create_action(session_id, {
    "page_id": page_id,
    "if_session_incarnation": session_incarnation,
    "execution_timeout_ms": 30_000,
    "action": {
        "type": "query_all",
        "frame_path": ["iframe#checkout", "iframe[name=address]"],
        "selector": "input[name=city]",
    },
})
```

List session artifacts, including browser downloads after scan and publication, with
`list_artifacts`. It returns an `ArtifactListPage` containing `artifacts` and `next_cursor`.
The default page size is 50; `limit` must be an integer from 1 to 100. Pass `next_cursor`
as `after` to continue, and stop when it is `None`.
`get_artifact` returns the same metadata shape as each list item. `display_filename`
is the original upload basename when available; it may be `None` or absent for
unnamed artifacts. It is display metadata; downloads use the fixed `artifact.bin` filename.

```python
page = client.list_artifacts("ses-...", limit=50)
for artifact in page["artifacts"]:
    print(artifact["id"], artifact["size_bytes"])
if page["next_cursor"] is not None:
    next_page = client.list_artifacts("ses-...", after=page["next_cursor"])
```

Attach available artifacts from the same session to a file input obtained with
`query_all`. The capability needs `browser:act` and `artifact:read`. File paths
are managed by the server; send only artifact IDs. Upload basenames are preserved.

```python
client.create_action(session_id, {
    "page_id": page_id,
    "action": {
        "type": "set_files", "node_ref": input_node_ref,
        "artifact_ids": [artifact_id],
    },
})
```

Fill a configured credential reference with `browser:act` and `secret:use`.
The worker must grant the tenant and principal access at the exact page origin.
Send the reference and node handle; keep the value in the worker's private provider.

```python
client.create_action(session_id, {
    "page_id": page_id,
    "action": {
        "type": "fill_secret", "node_ref": input_node_ref,
        "secret_ref": "login/password",
    },
})
```

Create a checkpoint with `browser:act` and `checkpoint:create`. List exact origins
whose owned pages have the desired `localStorage`; omit the list for cookies only.
Poll the returned action until it succeeds, then use `result["checkpoint_ref"]`
in a new `create_session` request. Restoration additionally needs `checkpoint:read`.
It creates a new session and requires the same tenant and Chromium artifact.

```python
client.create_action(session_id, {
    "action": {"type": "checkpoint", "origins": ["https://example.test"]},
})
# After polling the action and reading its checkpoint_ref:
client.create_session({**session_options, "checkpoint_ref": checkpoint_ref})
```
