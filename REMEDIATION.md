# Remediation log — 2026-09-07 code review

This records how the findings of the 2026-09-07 review (`BRD-001`…`BRD-026`, tracked
in the review bundle's `evidence/findings.json`) were addressed on `main`. Each row
is **Done**, **Partial**, or **Open**, with the commit(s) that carry the change.

## Validation methodology

The review follow-up full native run at
`~/logs/browserd-review-native-final-ao896i50/status.json` finished with exit 1:
15/16 probes pass, while lifecycle completes 192 cycles before session creation
returns `Remote/backend`. Native/service/container/cgroup cleanup is positive
and source is unchanged. All 212 durable journals complete ten cleanup stages;
the unique unfinished preparation stops before gated-child completion. The
underlying spawn cause is not established by the omitted message. Typed
spawn-stage/errno diagnostics now pass an actual missing-interpreter regression
and eleven parser/privacy cases, focused strict Clippy and formatting (exit 0).
A fresh full run is tracked at
`~/logs/browserd-native-spawn-diagnostic-mv_xpowb/status.json`; its result remains
pending. The 72-hour soak stays excluded.

The historical commit references below describe the original review fixes. The
2026-10-08 follow-up is currently an uncommitted local change set.

- `scripts/validation.py` separates deterministic unit/SDK checks, real
  Redis/PostgreSQL adapters, process contracts, privileged kernel qualification
  and a measured 72-hour soak. Missing prerequisites are blocked, never passed.
- New storage, recovery, capture and viewer contracts have focused fault tests.
  Redis and PostgreSQL conformance runs use isolated local test services.
- Sandboxed Chromium behavior tests exercise both extracted in-page helpers and
  the actual CDP connection owner. Local headless-shell results establish browser
  behavior only; they do not qualify the production sandbox or approved artifact.
- Production qualification still requires a pinned approved Chromium artifact,
  delegated cgroup and namespace evidence, approved deployment inputs for the
  production kernel runner, and the complete soak duration. No deployment or
  qualified release is claimed here.
- The 2026-10-11 production probe implementation passes 132 Python runner,
  packaging and device-host tests, plus 98 focused Rust probe, journal and RPC
  tests. The built CLI also returns exit 2 with all 16 probes blocked when the
  default operator configuration is absent; its response preserves the exact
  run/source binding and produces no qualification receipt. These checks cover
  the runner implementation. The engine build, workspace formatting and focused
  all-targets/all-features Clippy checks pass with warnings denied.
  A measured passing production run still requires
  the approved isolated deployment and assets described in the README.
- The 2026-10-11 follow-up adds `deploy/prepare-kernel-probe-assets.py`, which
  preserves the verified Chromium manifest and source bytes, writes a complete
  checksum/runtime inventory, and produces a reviewed SHA-authenticated root
  installer for a new immutable asset directory. Preparation and installation
  create no operational approval or qualification receipt. The separate
  `deploy/kernel-probe-seccomp.py` generates a versioned x86_64 cBPF denylist
  from actual Linux headers; generation alone does not attest runtime filtering
  or a qualified release policy.
- `deploy/kernel-probe-lab.py` provides a source- and image-pinned Docker
  measurement using genuine isolated Redis, native durable safety
  initialization, sandbox/egress daemons, current ClamAV scanning and owned
  canaries. It authorizes only the explicit isolated measurement. The genuine
  image and exact cgroup/namespace prerequisite checks passed; the full 16-probe
  run has not yet executed. Completion requires its real 1,000 start/stop
  iterations, positive shard/service cleanup and a fresh wrapper receipt. A
  prepared plan or successful prerequisite is insufficient. The user's current
  completion request excludes the 72-hour validation; no soak was run and the
  qualified-release gate still requires that separate evidence. See the README
  for the asset-install and fresh-stage lab commands.
- The actual Chromium resource smoke in
  `~/logs/browserd-chromium-resource-smoke-22j7t5iz` used the same pinned browser
  and bubblewrap. An executable-only baseline failed with exit 133 because ICU
  was missing; exact adjacent resource copies then produced `about:blank` HTML
  with exit 0 while Chromium's sandbox remained enabled, with no
  `--no-sandbox`. The owned container was positively removed. This measures the
  resource launch requirement, not any complete production probe receipt.
  The reproducible lab stage mounts exact resource hashes at
  `/browserd-chromium`, preserves the sealed executable/native ICU overlays, and
  supplies the guest ELF interpreter as an executable mode 0555 regular file.
  The isolated Docker lab allows inner `/proc` mounting through
  `systempaths=unconfined` while retaining inner NoNewPrivileges, UID 1003,
  zero effective capabilities and separate PID/network namespaces. Supervisor,
  directory and factory leases are aligned to 30, 60 and 30 seconds, and the
  isolated egress profile is `public-web`. Bounded private structural RPC
  diagnostics are implemented; a passing native 15-probe preflight and the full
  16-probe/1,000-start-stop measurement remain pending.
- The latest actual native preflight,
  `~/logs/browserd-proxy-repeat-preflight-8yajrqc0/status.json`, finishes with
  exit 0, `preflight_completed`, all 15 probes passing and 64/64 actual proxy
  loopback repetitions with positive cleanup. Services, container and cgroup
  are removed and source stays unchanged. Full SHA, exact namespace/root checks
  and original helper/deadline bounds are retained.
- Earlier actual repetition failed the third proxy close after two successes
  with `OutcomeUncertain`; the original raw RPC data is unavailable. Bounded
  sanitized RPC failures, typed cleanup-outcome diagnostics, three cleanup
  booleans and the last 32 events per exact shard are implemented. The original
  raw response remains unknown and cannot be retroactively attributed to the
  separately confirmed native cleanup-intent defect.
- Latest engineering verification in
  `~/logs/browserd-cleanup-intent-final-checks-pxf4j9u5/status.json` finishes
  exit 0 with all 21 steps passing: 34 factory and 16 router cases, 16 separate
  corrected panic-case repetitions, optimized sandbox/probe/safety builds,
  five-package all-target/all-feature Clippy with warnings denied and formatting.
  The earlier `0ciqb80j` sandbox/runtime phases pass 281 and 20 cases; its overall
  exit 101 was an old factory observation fixture narrowly corrected before the
  final rerun. Together 351 unique related Rust cases pass, with 16 repetitions
  counted separately; the prior 54 Python tests remain passing. Diagnostic
  preflight now has a 900-second bound capped by the original caller deadline
  and a 1,500-second native outer bound. The full production request remains
  7,200 seconds and retains all 1,000 start/stop iterations.
- The separate actual read-only control in
  `~/logs/browserd-chromium-readonly-control-6d90cagl/status.json` exits 0 with
  the exact Chromium bytes, observed `ST_RDONLY`, canonical self-exec and denied
  root and executable-parent changes; nested temporary/profile/scratch writes
  succeed. The passing diagnostic preflight omits `start_stop_1000` and creates
  no qualification receipt. The first full attempt,
  `~/logs/browserd-kernel-full-validation-w3j1r_ls`, finished with exit 1,
  14/16 passed and no receipt: proxy cleanup was incomplete and lifecycle
  session creation reached the retained-plan cap. Lab services/container/cgroup
  were removed with unchanged source.
- The full-run journal contains 256 completed launches with all ten cleanup
  stages; launch 257 fails `prepare_egress` and rolls back. The isolated
  `BROWSER_EGRESS_MAX_PLANS=256` cap includes retained terminal plans. The
  isolated cap is now 2,048 with measured capacity-configuration tests,
  preserving tombstones and production defaults. The full retry,
  `~/logs/browserd-kernel-full-validation-hrghwllj`, finished with exit 1 and
  15/16 passed. Lifecycle completes 24 iterations, then fails `close_session`.
  The exact `cancel_or_kill_shard` reply is `CleanupIncomplete` with
  `route_revoked=true`, `cgroup_killed=false`, `namespaces_cleaned=false` and
  `rpc_failures=[]`. Final lab service reaping and cgroup removal complete with
  unchanged source. A deterministic actual-journal regression confirmed the
  native ordering defect: `AbortGate` must wait for durable `RevokeEgress`
  intent. The implemented fix commits intent under the existing cleanup mutex
  before context/retirement remote effects, retaining parallel post-intent kill
  and original supervisor deadlines/success gates. Three real-journal
  regressions pass, including a hung post-intent revoke; the intended pending
  assertion failed before the fix. Fresh full retry
  `~/logs/browserd-kernel-full-validation-gl01q7fc` finished with exit 1 and
  15/16 probes passing. The lifecycle probe completed 675 cycles, then its exact
  cleanup RPC failed with `ConnectionClosed`. All 695 durable journals later
  completed all ten stages, but missing positive remote/service cleanup keeps
  this run failed. The review follow-up adds one identical fenced cleanup
  confirmation after connection closure, within the original total deadline;
  seven actual Unix-RPC/supervisor regressions pass. A fresh full run is still
  required. The genuine
  all-15/64-repeat preflight remains passed. Full success remains
  pending until final exit 0, positive native cleanup and a fresh wrapper
  receipt. The 72-hour validation is excluded from this request. The isolated
  denylist does not become a qualified release policy, and no host deployment
  is claimed.
- The baseline egress-daemon failure was test interference: concurrent epoch
  allocator children briefly inherited CLOEXEC listener/control sockets before
  exec. Sharing the existing listener-test lock with child spawning preserves
  the TCP-refusal assertion. A test-first multithread rollback regression and
  100 complete suite repetitions pass without changing production revoke logic.
- OOPIF regressions cover bootstrap before/after the navigation acknowledgement,
  ordinary-request serialization, the parent deadline and shutdown. Actual
  sandboxed Chromium input tests include options-context OOPIF `load` and reload.
  Frame UA and `Accept-Language` now apply before resume, including sessions
  without a custom UA; native client hints are preserved in that case. Child
  Native locale/timezone now bind to the dedicated process and approved catalog
  resources. Exact OOPIF `Intl` survives renderer replacement and peer detach in
  local functional tests; deployment qualification remains in ARCH-016.
- Unknown-context attachment now closes owner admission, taints/drains the shard
  and terminates the CDP connection even during an active command, lifecycle wait
  or nested child bootstrap. The current action keeps its existing known-rejection
  result, but queued/future owner work is rejected. Tests first reproduced the
  missing fail-closed transition and then verify drain, request rejection and EOF.
- The `approval_binding` close/query and expiry/query tests wait for actual driver
  cleanup entry before checking that action queries complete while the effect
  remains blocked. They replace an unsynchronized 50 ms scheduling assumption
  with a bounded deadlock watchdog. The production mutex code is unchanged; deliberately
  holding that mutex across cleanup fails the strengthened test, and restoring
  the byte-identical source passes both the focused test and all 36 contracts.
  Both checks retain the assertion that queries complete before the admitted
  effect is released. The expiry-specific mutex-holding mutation also fails the
  strengthened test, with the production source restored byte-identically.
  After both synchronization fixes, 100 full-suite repetitions on one CPU with
  four concurrent processes pass: 3,600 test executions and zero failures.
- The final fast gate passes all 37 commands, including formatting, workspace
  Clippy, 1,332 Rust unit/integration/doc tests, SDKs and viewer checks. The process
  gate also passes.
  The latest source also passes all eight actual sandboxed Chromium input,
  capture and viewer tests, including OOPIF load/reload.
- The sandbox-daemon cancellation test's Active timeout was a lost test-fixture
  notification. `FakeControl` signalled install entry before constructing the
  release waiter; `notify_waiters` could then discard an early release. A semaphore
  gate now forces that order in the existing regression, and `notify_one` retains
  the single install owner's release permit. The forced order reproduces the
  original timeout before the fix. Production install/reconcile logic and its
  deadlines are unchanged. All 20 sandbox-daemon tests pass, followed by 100
  complete library-suite repetitions: 1,500 test executions with zero failures.
- The emulation follow-up uses actual Chromium 153.0.8010.12 and loopback origins.
  Top-document locale/timezone/viewport, frame JS/HTTP UA and language, reload,
  renderer replacement and execution-before-rejection tests pass. All eight
  emulation tests now pass, including the three previously failing exact OOPIF
  profiles and surviving-peer readback after detach.
  Raw CDP measurements with a UTC baseline reproduce missing parent inheritance,
  duplicate renderer locale claims and surviving-frame resets after owner detach.
  Paused OOPIFs have no default JS execution context for validating a duplicate
  override. Native launches instead use fixed process locale/timezone defaults,
  catalog-approved ICU/pak digests and a read-only exact `ko-KR.pak` alias. RPC,
  factory and owner enforce an immutable profile before effects; unsupported
  profiles and artifact drift fail closed. No duplicate-error bypass or weaker
  locale comparison was added. Approved deployment qualification is still pending.
- Native artifact verification is now shared by kernel/soak preflight and release
  packaging. Missing catalogs, schema/launch-digest mismatches, unlisted ICU/pak
  resources and ambiguous binary mappings are rejected. Packaging revalidates
  its archived catalog bytes and rejects manifest changes after initial verification.
  The process gate passes locally; external kernel and 72-hour soak remain blocked
  until approved artifact, delegated cgroup and trusted runner paths are configured.
- Device setup now installs independent private Chromium copies, observed version
  and protocol documents, native resources and device runtime inventories, with a
  pinned local candidate config and an explicit functional-only test launcher.
  `deploy/setup-validation-host.py` renders a separate cpu/memory/pids delegation
  service and starts fixed validation jobs inside it without relaxing
  `NoNewPrivileges`. The operator applied the root bootstrap on 2026-10-10;
  the dedicated service is active and exposes cpu/memory/pids to its workload
  subtree. Validation jobs start inside that service, while the original agent
  process remains undelegated. The partial device runner verifies the actual
  pinned Chromium identity, reads back cpu/memory/pids limits, accounts for an
  attached process and confirms `cgroup.kill` SIGKILL termination and cgroup
  removal. Its separate user/PID/mount/network namespace smoke retains
  `NoNewPrivileges` and observes an unreachable direct TCP destination.
  The delegated kernel run passes all five ordinary commands: Python browser,
  foreign-network-namespace, exact nested-bubblewrap namespace listener authority,
  Linux backend and Rust browser. The nested check retains `NoNewPrivileges`,
  verifies host denial and in-namespace TCP, and cleans up its owned processes.
  The partial runner returns exit 2
  with the other 15 production probes blocked and no passing receipt.
  Neither those checks nor candidate installation supply production
  artifact approval or the missing real deployment/72-hour workload runners.
  Configured Rust owner fixtures verify the complete supplied identity, file
  manifest and native catalog before launch. Their private native snapshots
  preserve the original catalog bytes and resource geometry; unconfigured
  fixtures still generate a separate catalog. All nine offline fixture
  regressions run in the fast gate. The actual candidate passes 21 Python and
  16 Rust browser cases, including all eight native emulation cases.
  Candidate preparation now stores the version-only identity consumed by the
  Chromium connection while retaining the raw CDP product in provenance. A new
  candidate was rebuilt and rebound; the original artifact and reports remain.
  Five fresh locked/offline debug executable inputs, matching SDKs and the
  Chromium candidate are packaged as an unqualified review bundle; all 772
  archive members, modes, sizes and hashes are verified. Production launch still
  needs approved launch-gate/runtime assets outside the prohibited home paths,
  approved seccomp input and the actual production behavior/soak runners.

- The 2026-10-10 context-route follow-up binds the exact active egress listener,
  namespace, tenant, policy and full fence to the receipted CDP pipe transfer.
  Production factory admission rejects missing/mismatched bindings before CDP.
  Context creation fixes the HTTP proxy, removes implicit loopback bypass and
  acknowledges context-scoped download denial before publishing a page; unexpected
  browser-wide download events close admission without importing event paths.
  The real launch gate now preserves only LANG/LC_ALL/LANGUAGE/TZ from the trusted
  launcher. Test-first regressions reproduced both the lost native environment
  and the previously successful unbound production qualification.
  All 159 focused gate/binding/RPC/driver/factory/adapter cases pass, including
  cleanup when binding metadata exceeds the RPC frame limit. Clippy on the five
  affected packages and the workspace formatting check pass.
  The delegated-device rerun passes 89 Linux backend cases and 38 actual browser
  cases (21 Python, 17 Rust). Its new routed-owner case proves an accessible
  loopback origin is reached only through the fixed proxy and remains unconnected
  after that proxy stops. Context download-deny setup is acknowledged by the
  pinned browser; allowed browser-download storage is not qualified.
  Kernel report `~/logs/browserd-kernel-_e3v6bg9/report.json` remains blocked,
  exit 2: one identity probe passes, 15 production probes have no receipt, and
  approved runtime/launch assets, seccomp input and the 72-hour soak remain absent.
  The earlier unqualified archive predates these fixes and needs fresh executable
  inputs before production launch. Pro review failed at the model picker and
  supplies no review approval.

## Status

The 2026-10-11 managed-fleet follow-up adds private allowlisted worker inventory,
durable tenant FIFO and weighted deficit admission, normalized least-loaded
placement and exact operator-exclusive `dedicated_worker` assignment. Bounded
worker observation and virtual fairness rounds let a lone weight-one cost-64
request progress without extending its original deadline. Worker-issued tokens
bind the complete create scope, fresh boot, profile and resources. The worker's
capacity lock transfers reservations into creation; exposed uncertainty never
expires into free capacity. Exact cleanup acknowledgements retain terminal proof
through the original 24-hour horizon.

Ready activation commits directory and action authority together. PostgreSQL
operation projection converges with an explicit durable acknowledgement, and
active/closing rows remain discoverable after it. Immutable placement authority
and independent lease revisions fence actions and loss observations. Historical
reads stay on the original worker at its current serving epoch, including during
drain or unreadiness. Lost commit replies inspect the original token rather than
replaying creation. Format 5 requires the explicit offline upgrade and preserves
legacy terminal/custody evidence without creating live fleet authority.

The seven related packages pass 1,454 tests, including actual Redis and PostgreSQL
conformance (`~/logs/browserd-fleet-quality-3fbaea8c9313`, test exit 0). After boxing
the two large RPC response variants, all 12 authenticated worker admission tests
and six gateway fleet tests pass (`~/logs/browserd-fleet-final-1147df1514e0`, test
exit 0). Workspace formatting and all-target Clippy pass with warnings denied
(`~/logs/browserd-fleet-clippy-85c5ade05430`, exit 0). These are local implementation
checks; operator migration, deployment and external qualification remain pending.

The 2026-10-11 shared-placement follow-up adds bounded worker-local reuse for
`shared_context` and `tenant_dedicated_shard`, with request-specific actual isolation
in session receipts and approval bindings. Reuse needs an immutable private policy,
an exact artifact/kernel qualification and a tenant grant; missing evidence selects
a dedicated process. The pool limits live contexts to eight, lifetime creations to
500 and shard age to two hours, and retains uncertain starts against capacity.
Supervisor-owned durable context route records fence attach, renewal, release and
restart recovery. Shared attachment requires the same kernel network-namespace
cookie, immutable policy and separate context identity. Context disposal verifies
its own absence and precisely owned siblings; capacity returns only after the exact
route is durably Released. Process cleanup is a separate operation.

The actual sandbox-enabled Chromium fixture passes with eight contexts at the same
origin: cookies, localStorage, IndexedDB, Cache API, same-name SharedWorkers,
ServiceWorkers and proxy routes remain separate. Existing sibling workers, storage
and network access survive closing the first context and stopping its listener.
These controlled local proxies establish browser behavior only; they are not
production network-namespace qualification or permission to deploy shared mode.
The owner, pool, supervisor/recovery and policy regressions pass with the related
worker, gateway, API and HTTP suites. Existing fixture races now observe the actual
post-response terminal-taint transition, use distinct proxy addresses and answer
bounded orphan rechecks while retaining uncertainty and cleanup assertions.
Workspace formatting and all-target Clippy on the eleven related packages pass;
final quality runner `~/logs/browserd-shared-context-quality-982fde43f6cd` exits 0.

| ID | Pri | Title | Status | Commit(s) / note |
|----|-----|-------|--------|------------------|
| BRD-001 | P0 | Requested vs. production isolation mismatch | Done | `436d660` — isolation negotiation; requested + effective recorded durably |
| BRD-002 | P0 | Session directory / action GET lost on gateway restart | Done | `a75e6fc` covers terminal GET. Local review follow-up adds durable session GET/list, same-key POST replay before live admission and exact Worker ownership validation; actual replacement, tenant listing and Redis adapter regressions pass |
| BRD-003 | P0 | Action authority durability / rollback contract | Done | durable event-outbox series (`b84aa6f`…`4ffdc29`), `a541d14` |
| BRD-004 | P0 | Standard-session `evaluate` not bound to profile | Done | `436d660` — evaluate denied at dispatch for the standard profile |
| BRD-005 | P0 | Double-click partial dispatch → stale known-failure | Done | compound-input dispatch returns outcome-uncertain after a landed press |
| BRD-006 | P1 | Artifact / feature actions not wired end to end | Done | Local follow-up: durable bounded storage, upload/download transport, generated screenshot/PDF/scrape and actual Chromium capture; supported scope and remaining scanner/publication risks below |
| BRD-007 | P1 | Viewer ticket → worker screencast not connected | Done | Local follow-up: fenced tickets, WebSocket bridge, shared screencast/ACK, input cleanup and durable control-event recovery; actual Chromium owner and WebSocket contracts pass |
| BRD-008 | P1 | Snapshot returns raw CDP AX tree, not a normalized schema | Done | `a003491` — SPEC §16.1 envelope, opaque node refs, bounds |
| BRD-009 | P1 | `query_all` epoch attached late (navigation race) | Done | General `dispatch_fence=None` path also uses the existing sequence guard; review regression verifies known `document_changed`, no stale handle and successful fresh read after navigation |
| BRD-010 | P1 | `DOM.resolveNode` remote objects never released | Done | `Runtime.releaseObject` after a successful node read |
| BRD-011 | P1 | `network_quiet` ignored in-flight requests | Done | `24a0806` ledger plus local bounded frame/loader tracking; commit preserves new-document unfinished requests, verified by actual CDP event ordering |
| BRD-012 | P1 | Click actionability is content-quad centroid only | Done | Local follow-up: bounded three-frame stability, scroll/occlusion and document checks; actual top-document, nested iframe and OOPIF input tests pass with ancestor fencing and occlusion checks |
| BRD-013 | P1 | `fill`/`check`/`select` bypass element semantics | Done | Local follow-up: native setters, inherited disabled/readonly and document checks; sandboxed browser tests cover controlled inputs and Korean insertion/IME |
| BRD-014 | P1 | Gateway readiness pinned to the first probe | Done | `d8b6b8c` — dependency health monitor drives dynamic readiness |
| BRD-015 | P1 | Graceful shutdown only on SIGINT | Done | `a541d14` — SIGTERM drain |
| BRD-016 | P1 | CreateOperation reconcile loop absent from production main | Done | `a541d14` — reconcile pass in the supervisor loop |
| BRD-017 | P1 | Event channel's durable transition → outbox missing | Done | Durable event-outbox series (`b84aa6f`…`4ffdc29`) and existing local Redis terminal publication obligations, independent publisher and ACK-pinned retention; review loss/publication recovery and actual Redis/PostgreSQL adapter revalidation pass |
| BRD-018 | P1 | Closed-session / create-binding lifetime & GC | Done | Historical retention fixes plus local bounded runtime-cache/catalog reclamation and independent PostgreSQL janitor; actual PostgreSQL bounded-purge and terminal-retention regressions pass |
| BRD-019 | P1 | HTTP ingress not bounded before the blocking queue | Done | `e0bcc6f` — global + per-tenant admission with a reserved control lane |
| BRD-020 | P1 | Feature admission / audit not mandatory on dispatch | Done | Production startup requires an open usable audit WAL before epoch mutation, including missing-sink rejection; WAL append failure blocks effect dispatch. Capture profiles, concurrent limits and byte reservations remain enforced |
| BRD-021 | P2 | Fleet model vs. actual single-worker routing | Done | Initial release explicitly supports one host, one worker and one dedicated process per session; multi-worker scheduling is not advertised |
| BRD-022 | P1 | Session option schema wider than production capability | Partial | Native OOPIF, worker startup/lifetime and operator-enabled privileged evaluation pass local contracts and sandboxed browser tests; actual approved gated launch and deployment qualification remain blocked in ARCH-016 |
| BRD-023 | P0 | Dependency / kernel qualification not separated from release | Partial | Separate validation tiers plus production factory/RPC/CDP kernel probes and source-bound evidence; approved deployment qualification and the measured 72-hour soak still required |
| BRD-024 | P1 | TypeScript SDK distribution / typecheck gate missing | Done | `b76b1ef` — built package with declarations |
| BRD-025 | P1 | Reproducible release package / deploy runbook absent | Done | Deterministic offline packaging, source-bound gate reports, manifest/checksums, systemd templates and coordinated restart/rollback runbook; a qualified archive still requires BRD-023 evidence |
| BRD-026 | P2 | `query_all` silent truncation / fixed snapshot identity | Done | truncation signaled explicitly; snapshot identity via `a003491` |

## Summary

Done: 25 · Partial: 1 · Open: 0 (26 original findings total).

“Done” describes the supported implementation and tooling. It does not certify
an operating production deployment. The original findings do not encompass every
issue in the private risk register or every later browser behavior failure.

The initial supported scope is one host/worker with dedicated session processes,
main-document and explicit iframe/OOPIF query/input, generated captures, live-session artifact publication
and bounded viewer connections. Browser downloads now have bounded sandbox scratch,
exact frame/session attribution, scanned artifact publication, cleanup retries and
paginated discovery in HTTP and both SDKs. File-input attachment resolves owned,
scanned artifact IDs into bounded immutable scratch files, preserves uploaded
display names and verifies the resulting browser FileList. Unicode paths use a
fixed UTF-8 process encoding. Secret injection now resolves tenant/principal grants
for an exact HTTP(S) origin, requires a redacted credential intent audit and uses
a bounded sensitive CDP lane. It rechecks the owned document before dispatch;
uncertain effects are not replayed. The sandbox-enabled browser proof covers
Korean values, native input events, stale documents and different origin ports.
Checkpoint actions now save a bounded cookie/localStorage subset in a private
authenticated encrypted store. Restoration requires the same tenant and exact
Chromium identity, creates a fresh session and seeds origins without upstream
traffic before publishing readiness. The actual browser round-trip and storage,
audit, cancellation and partial-cleanup contracts pass. Bounded selector paths now
resolve nested same-process and cross-process frames, and opaque node handles bind
the full session fence, flattened CDP route and every ancestor document. Native
node input validates ownership, stable affine geometry and ancestor occlusion.
Actual Chromium tests cover frame adoption, renderer swaps, reloads, sibling
isolation and Korean input. Typed approval observations and file/secret injection now
cover owned child frames, including OOPIFs, with trusted browser origins and ancestor
document/realm guards. Native options sessions now support dedicated,
shared and service workers with immutable first-script settings, context-fenced
admission and confirmed retirement. Privileged evaluation is operator-enabled by
an immutable tenant/principal grant policy, with mandatory durable audit and fenced
effect admission. HTTP `Prefer: wait` now observes a single durable submission
with a bounded synchronous budget, scoped status polling and admission leases
that survive client disconnect. Nonterminal recovery now has immutable submission
leases, pending discovery and exact fenced worker-result queries without browser
replay. The standalone Redis upgrade uses an explicit offline, restartable migration;
all gateway writers must be stopped externally. Confirmed `Closed`/`Failed` session
observations now seal admission and commit a canonical, fully fenced loss journal;
bounded recovery preserves known terminal results before deriving remaining losses.
Unreachable workers still need an authenticated supervisor exit proof. Durable
artifact publication now has a separate durable journal preserving full original
ownership, generation, source, scan disposition and optional display names.
Historical scoped read RPCs serve retained files after session close or restart
without restoring a browser session. Publication expiry applies to reads and file
attachments, including per-chunk checks. Completed-artifact disk cleanup and
bounded retention now run independently of heartbeat, with durable orphan grace,
exact-generation deletion, reader/writer ownership and confirmed quota release.
Deletion receipt retirement and journal compaction retain a bounded retry window;
older retries fail closed. The authenticated Unix scanner now observes bounded
database freshness and equal before/after versions under an explicit UTC service
contract. Exact byte/ownership/generation-bound evidence is persisted atomically
with publication and checked through retained RPCs. Legacy scanned publications
without evidence remain charged and hidden until expiry cleanup. Production
scanner deployment and qualification remain in SEC-004; version metadata does
not prove a cryptographic pin or digest of all signature database contents.

Production action admission now uses an immutable tenant/principal/action policy
snapshot. Mutations default to four-eyes manual approval, observations default to
automatic admission, and exact operator grants can allow or deny a document scope
and full navigation destination. Queue-head typed proposals bind action identity,
full ownership, policy digest, node guards, secret grants, ordered file publications
and checkpoint origins/build identity. Public approval summaries and authenticated
RPC preserve those bindings through decision and one-time effect admission.
Mandatory durable proposal/decision/dispatch audit, stale binding rejection,
cancellation and uncertain post-effect results pass unit/integration tests; actual
sandbox-enabled Chromium covers child-frame secret/files and blank-context
checkpoints. Resolution audit and abandoned-action policy remain in SEC-003.

Production action-WAL admission now reserves worker/tenant bytes and inode slots,
inventories retained journals before epoch admission, and preserves terminal write
capacity. Exact worker custody is committed with terminal/resolution authority and
source events. Independent gateway copy-ACK/final-release recovery and bounded
worker maintenance require positive cleanup, current receipt evidence, the full
retention horizon and real descriptor closure before deletion and quota release.
Legacy and uncertain journals remain charged. Optional custody projection failure
preserves a known result and its original custody requirement. Independent bounded
historical reads attach matching proof after worker restart, then reuse copy/release
recovery. Proof attachment preserves results, operator annotations, revisions,
source events and retention horizons. Missing managed/legacy proof pins payload GC;
only an authenticated original unmanaged terminal result can declare unsupported.

Gateway action payload admission now has independent namespace/session limits.
Terminal horizons use trusted store time and remain fixed across unrelated claims,
reads and ACKs. A bounded fair janitor reclaims exact payload/idempotency pairs only
after source-event ACK, custody release and lane checks, preserving permanent
placement, loss and sequence authority. Zero-score padded pending members preserve
full `u64` ordering. Format v4 requires an explicit restartable offline upgrade of
existing namespaces with every gateway writer stopped, including validation of an
existing v3 retained catalog; migration retains legacy
authority and fails closed on corrupt or over-capacity data. Operator data has not
been migrated by this repository change.

Release admission remains blocked on an approved Chromium artifact, the complete
kernel qualification receipt and the measured 72-hour soak. Local browser tests
use the sandbox-enabled matching Chromium headless shell. The OOPIF load fix gives
paused-target bootstrap a bounded owner queue serviced during CDP and lifecycle
waits, retaining ownership checks, the original deadline and shutdown handling.
Options contexts apply target UA/language to owned iframes before resume. Native
process profiles pass the exact child `Intl` locale/timezone lifetime regressions,
which remain in the kernel tier for approved deployment qualification. Native
dedicated, shared and service workers use process-wide UA defaults, a single
browser attachment for shared/service targets and bounded per-context admission.
Legacy inspector-only options contexts continue to reject workers. Cleanup
uncertainty taints the manager and closes further admission. Default GUI Chromium UI targets and the complete
child-target emulation matrix remain unqualified. No release archive is
represented as qualified and no infrastructure was deployed.

REL-003 now has an atomic source journal, permanent sink projection watermarks,
exact acknowledgement and restart recovery. Viewer control uses a separate
persistent sequence namespace and a bounded worker journal with fail-closed
backpressure; browser effects are never replayed to repair event delivery.

F20 now has authenticated durable webhook management and bounded independent
delivery with private versioned HMAC signing masters, pinned HTTPS/public DNS-IP
inspection, immutable retry bodies, exact attempt CAS and explicit retention-gap
resume. All nine initial event kinds have real production producers: operation
events share their PostgreSQL transaction, and Worker Action WAL, lifecycle/
execution, artifact/download and control state share immutable source descriptors.
Historical RPC33 and an independent bounded relay import whole commits and
permanent watermarks before exact source ACK. Legacy checksum/custody behavior
remains compatible, pending source ACK independently pins cleanup, and worker
source ownership prevents duplicate legacy projections. Original event time is
separate from sink retention time. The full eight-package gate passes 1,676 tests,
formatting and Clippy with warnings denied, using actual isolated Redis/PostgreSQL
fixtures; 31 external-prerequisite tests remain explicitly ignored. Final exit 0:
`~/logs/browserd-notification-quality-fe824a6b4763.log`. No operator endpoint or
production database was changed, and production qualification remains separate.

F21 adds the global authenticated runtime safety API under
`/v1/admin/safety-switches`, with separate read/write operator scopes, explicit
conservative version-0 initialization and canonical versioned mutations. Memory
and Redis share one bounded reducer: snapshot, principal/tenant-bound exact receipt,
trusted time floor and durable audit intent commit together. Exact oldest audit
ACKs start a minimum 24-hour receipt window; pending audits never expire, and GC
preserves current state, permanent version and audit watermarks. Read/connect never
initialize missing state, and an admitted actor command survives caller timeout.

Worker and egressd independently verify the same Redis namespace, with private
durable namespace/version/digest pins fsynced before cache publication. Freshness
uses local monotonic time, bounded to 30 seconds; rollback, equivocation, missing
authority and uncertain disk writes fail closed. Runtime feature, pool/target and
network gates intersect existing immutable launch/qualification policy, so operator
updates cannot grant shared-context qualification. Mutation responses report
`persisted` and `pending_observation`, separately from daemon application.

F21 local root validation passed: 1,936 tests across 11 packages, 32 explicit
external-prerequisite tests ignored, formatting and all-target Clippy with warnings
denied. The gate exited 0 at
`~/logs/browserd-runtime-safety-quality-0b5c434d7106.log`; three real HTTP transport
startup tests passed separately. Original create wire/hash stays canonical, while
separate immutable reservation profile/debit survive relaxation. Insufficient
reservations reject before effects. Accepted observer file descriptors prevent
inode reuse from hiding recreation/hardlink/symlink replacement. No deployment,
operator Redis initialization, production qualification or 72-hour soak is claimed.

F22 optional retained quarantine is implemented and locally validated. The default
stays metadata-only rejection. Explicit authenticated scanner policy adds bounded
private retention under `.quarantine`, with exact size/SHA/generation and ownership
authority committed atomically with the Quarantined notification. Public reading,
materialization, Available publication and DownloadCompleted remain prohibited.
Failed seal/authority writes keep their private byte/count charge through exact
cleanup. Pending source ACK pins expiry; positive generation-bound deletion and
durable registry/ledger transitions precede charge release. Existing bounded
multipart/retention maintenance owns restart, orphans and empty private namespaces.

Disabling new retention, reducing general limits or exceeding the old scanner
freshness horizon preserves existing authority and charges. Original admission
time validates recovered evidence. Snapshot compaction preserves older pending
authority, exact ACK retry, permanent source watermarks and full-capacity rejection
checkpoints while preventing stale new admission after retirement.

The full 12-package test command passed 2,042 tests, with 32 explicit external-
prerequisite tests ignored; the initial Redis timing failure passed both isolated
and full reruns without a Redis code change. Its test command exited 0 in
`~/logs/browserd-artifact-quarantine-quality-287cc8d29eec.log` (that combined runner
later exited 101 at Clippy). After equivalent expression changes, all 17 focused
quarantine/configuration tests passed in
`~/logs/browserd-artifact-quarantine-quality-940a6bf64ea1.log`. Remaining test-only
lint allowances follow repository convention. Final formatting and 12-package
all-target Clippy with warnings denied exited 0 in
`~/logs/browserd-artifact-quarantine-lint-04d4fa48fe38.log`. No operator storage,
scanner configuration, deployment, production qualification or 72-hour soak was
changed or proved by these local checks.
