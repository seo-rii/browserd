# BRD-006 implementation plan — artifact & feature actions end to end

**Finding.** Screenshot/PDF/scrape produce no artifact in production: there is no
CDP capture command anywhere, the production worker injects `RejectArtifacts`
(always `Err`), the gateway refuses these actions at submit and serves only
artifact *metadata* (never bytes), and the features admission/preflight crate is
not wired into dispatch. The artifact *domain* and the feature *type* layer are,
by contrast, fully built and Chromium-free.

This plan is phased so each phase is independently shippable and **unit-testable
against the mock CDP transport**, deferring only genuine byte production to a
real-Chromium integration pass (Phase 5). Line anchors are current-tree hints;
prefer the named symbols, which are stable.

## What already exists (reuse, don't rebuild)

- **Artifact domain** (`crates/browserd-artifacts`): the full state machine
  (`state.rs` — `new_generated`, `apply_materialized`, the Generated path
  `GENERATING→FINALIZING→{AVAILABLE|FAILED}`), quota reserve/commit (`quota.rs`),
  streaming write+commit (`streaming.rs` — `StreamingArtifactWriter`
  begin/write_chunk/finish → `ArtifactWriteReceipt`), read-back
  (`object_store.rs` — `ArtifactObjectStore::open_read`), a real
  `FilesystemArtifactStore` (`filesystem.rs`), one-time `DownloadToken`
  (`token.rs`), and the janitor (`janitor.rs`). Contract: *reserve quota →
  `StreamingArtifactWriter::begin` → `write_chunk` → `finish` → receipt*; later
  *`open_read(namespace, key, expected_generation, expected_metadata, limits)`*.
- **Feature type layer** (`crates/browserd-features`): `BuiltinFeature::{Screenshot,
  Pdf,Scrape,Snapshot}`, per-feature `FeatureManifest`, `FeatureAdmission` +
  `AdmissionPermit` (RAII), `AdmissionClass`, `FeatureConcurrencyLimits`, and typed
  `preflight` (`ScreenshotLimits`, `PdfLimits`, `ScrapeBudget`, `BoundedByteStream`).
  All declarative/pure today; **not called** in worker dispatch.
- **Contract shells**: `ActionPayload::{Screenshot,Pdf,Scrape}` (bare unit
  variants, `crates/browserd-api`), artifact routes + `ApiRequest`/`ApiResponse`
  artifact variants, worker `ArtifactStoreRequest`/`ArtifactStoreReceipt`, the
  `RoutedArtifactStore` seam, and gateway `get_artifact` (metadata only).

## SPEC contract to honor

- **§17.1**: each feature is a typed action; the result binary is stored *through
  the artifact state machine*; heavy features pass **ActionAdmission (§11.6:
  per-shard PDF=1 / full-page screenshot=1 / large snapshot=2, per-worker
  artifact-bytes-in-flight bounded)**; preflight size *before* generation and apply
  a byte quota *during*; keep "browser effect/result" state separate from "artifact
  upload/finalization" state.
- **§17.2 screenshot**: PNG/JPEG/WebP, viewport/full-page/clip/quality, mandatory
  max dimensions/pixels/encoded-bytes/capture-time (→ `ScreenshotLimits`).
- **§17.3 PDF**: Chromium `printToPDF` **streamed** → bounded read chunk → artifact
  upload → byte-limit check → finalize/abort, so the full base64 never lands in
  worker memory; header/footer restricted to a placeholder schema (→ `PdfLimits`).
- **§16.1 inline delivery**: `{include:["screenshot"], screenshot:{format,quality,
  delivery}}`; result carries `screenshot_artifact:{id}` (delivery=artifact) or
  `screenshot_inline` base64 (delivery=inline, under the §12.4 limit) with auto
  fallback to artifact + `screenshot_inline_fallback=true`.
- **§20**: namespace is Tenant/Session/ArtifactId (no caller paths); state machine
  byte-identical to `state.rs`; quota reservation accounting; download by
  ArtifactId; §20.6 one-time signed token consume (→ `token.rs`).

## Phases

### Phase 0 — Production artifact store (no browser; immediate value)
Replace `RejectArtifacts` (`bins/browser-worker/src/main.rs` ~234-243, wired ~166-175)
with a real `RoutedArtifactStore` backed by `FilesystemArtifactStore` +
`StreamingArtifactWriter` + quota, reading a root dir + quota limits from env
(e.g. `BROWSERD_ARTIFACT_ROOT`, byte limits), mirroring the audit-WAL opt-in style.
This alone makes **client uploads** work end to end (today `upload_artifact`
→ `store_artifact` → `RejectArtifacts` → `Err`).
- **Tests (here):** existing fakes already inject a `RoutedArtifactStore`
  (`RecordingArtifacts`); add a worker test that an upload commits and the state
  machine reaches `Available`, and that a quota-exceeding upload fails closed.

### Phase 1 — CDP capture commands (mock-CDP testable)
Add `PageCommand::CaptureScreenshot{format,quality,clip,full_page}` and
`CapturePdf{landscape,print_background,scale,paper,…}` to `chromium_owner.rs`
(enum ~1201-1286; handle in `execute_page_command` ~2410+, reusing
`command_event_first`, exactly as `capture_snapshot` issues
`Accessibility.getFullAXTree`). Add matching `WorkerActionCommand` variants +
translation (`cdp_driver.rs` ~507-620).
- Screenshot: `Page.captureScreenshot` returnByValue base64, bounded by
  `ScreenshotLimits` (reject over the encoded-byte cap).
- PDF: `Page.printToPDF` with `transferMode:"ReturnAsStream"` → an `IO.read` loop
  (new owner helper) → bounded chunks, so the document never fully buffers; add an
  `IO.close`. This is the one new CDP interaction pattern (streamed read).
- Captures are **guarded page executions** (fence + epoch re-check like every
  other page command) and are **read-only** (no page side effect).
- **Tests (here):** mock transport returns a canned `captureScreenshot`/`printToPDF`
  (+ `IO.read` chunks) reply; assert the command arguments, the chunk assembly, and
  the over-limit rejection. Real pixel/PDF bytes are fixtures, not Chromium output.

### Phase 2 — Capture → artifact bridge + admission/preflight (mock-CDP testable)
Generalize `ArtifactStoreRequest`/`ArtifactStoreReceipt` (`crates/browserd-worker/src/lib.rs`
~744-863) to carry `ArtifactContentSource::Generated` + content type (today pinned
to `ClientUpload`), and add a streaming request variant for PDF. Add a control-plane
path analogous to `upload_artifact` (~3262-3369) that drives the **Generated** state
machine (`new_generated` → `apply_materialized(GenerationCompleted, …)` →
`FinalizationSucceeded`) and returns an `ArtifactId`. In the heavy-action dispatch
path: acquire a `FeatureAdmission` permit, run `ScreenshotLimits/PdfLimits/
ScrapeBudget::preflight`, capture (Phase 1), store as Generated (Phase 0),
release the permit on **every** path.
- **State separation (§17.1):** capture is read-only, so an artifact-finalization
  failure after a successful capture is a clean `FailedKnown` (no page effect to be
  uncertain about) — simpler than the mutating-action case.
- **Delivery (§16.1):** delivery=artifact → store, return `screenshot_artifact:{id}`;
  delivery=inline → return `screenshot_inline` base64 if under the §12.4 limit, else
  store and set `screenshot_inline_fallback=true`. Never log/trace the bytes.
- **Tests (here):** admission capacity exhaustion → reject + permit released;
  preflight over-limit → reject before capture; canned capture → artifact committed,
  receipt carries the ArtifactId; inline-vs-fallback branch.

### Phase 3 — API contract (no browser)
Give `ActionPayload::Screenshot` real options + a `delivery` field, and add the
`screenshot_inline`/`screenshot_artifact`/`screenshot_inline_fallback` result
fields and the §16.1 snapshot `include`/`screenshot` integration
(`crates/browserd-api/src/lib.rs` ~403-405, validation ~546-549). Add an
artifact-bytes route to `PUBLIC_ROUTES` (~45-70) if bytes are served by the gateway.
- **Tests (here):** request/response serde round-trips; validation of
  format/quality/delivery bounds; scope checks (`artifact:read`).

### Phase 4 — Gateway wiring (mock-worker testable)
Stop rejecting `ActionPayload::{Screenshot,Pdf,Scrape}` at submit
(`bins/browser-gateway/src/lib.rs` ~1472-1484) and map them to the new
`WorkerActionCommand`s. Implement `UploadArtifact`/`DownloadArtifact` in
`execute_runtime` (replace the `_ => "runtime endpoint is not available"` catch-all
~2730-2733). Add an **artifact-bytes** path: a download route that mints/consumes a
one-time `DownloadToken` and streams via `ArtifactObjectStore::open_read` (§20.5/20.6),
added to the `browserd_http` router (`bins/browser-gateway/src/main.rs` ~219-226).
- **Tests (here):** fake worker client; assert screenshot/pdf/scrape now forward,
  upload/download round-trip, bytes stream with generation+integrity checks, and a
  consumed token is rejected on reuse.

### Phase 5 — Real-Chromium integration (needs a browser; not verifiable here)
Validate actual PNG/JPEG/WebP and PDF byte production, full-page layout-metric
preflight accuracy, device-scale-factor, large-PDF streaming/multipart under real
sizes, and end-to-end byte integrity/quota under genuine capture sizes. This is the
only part that fundamentally requires the pinned Chromium + privileged sandbox.

## Integration seams (summary)
1. `PageCommand::CaptureScreenshot|CapturePdf` + owner handlers (`chromium_owner.rs`);
   `WorkerActionCommand` variants + translation (`cdp_driver.rs`); an `IO.read`
   stream helper for PDF.
2. `ArtifactStoreRequest`/`Receipt` Generated+streaming variants; a `generate_artifact`
   control-plane path running the Generated state machine (`crates/browserd-worker/src/lib.rs`).
3. Real `RoutedArtifactStore` over `FilesystemArtifactStore` replacing `RejectArtifacts`
   (`bins/browser-worker/src/main.rs`).
4. `FeatureAdmission` permit + `*Limits::preflight` in heavy-action dispatch
   (`crates/browserd-features` into the worker dispatch path).
5. Gateway: forward Screenshot/Pdf/Scrape, implement upload/download + artifact-bytes
   route (`bins/browser-gateway`), fed by `ArtifactObjectStore` + `DownloadToken`.
6. API: real screenshot options/delivery + result fields + bytes route
   (`crates/browserd-api`).

## Cross-cutting
- **Fail-closed everywhere:** admission capacity, preflight over-limit, quota
  exhaustion, and store-commit failure each reject before/without a partial
  artifact; `FeatureAdmission`/quota permits release on every path (mirror the
  BRD-020 audit-gate pattern).
- **Fencing:** captures run as guarded page executions with the epoch re-check all
  page commands already use.
- **No secret/byte leakage:** never log or trace captured bytes or inline base64.
- **Ordering:** Phase 0 is independently valuable (client uploads) and de-risks the
  rest; Phases 1–4 are each unit-testable here; Phase 5 is the real-browser gate.
