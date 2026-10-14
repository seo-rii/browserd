# Follow-up to the 79d3389 boundary review

The supplied review describes committed `79d3389`. This follow-up compares its
18 findings with the existing uncommitted work and implements the remaining
execution-boundary fixes. The review text was available; the linked ZIP was not
available as a local attachment. Regression cases were reconstructed from the
described scenarios, rather than treating the attachment's reproduction `PASS`
labels as successful behavior.

## Scope and observable behavior

| Review | Change or existing fix | Regression boundary |
| --- | --- | --- |
| 2.1 HTTP/SDK | Shared public resource serialization; validated success envelopes and endpoint-specific extraction in both SDKs | Actual HTTP serializer fixtures cover terminal states, failure/session/resource identities, event gaps and result bodies; malformed success responses stop without mutation replay |
| 2.2 sandbox launch | Existing local fix applies resource limits before exec, without unsupported bubblewrap flags | Production-generated launch and real pinned sandbox execution remain the native gate |
| 2.3 lockfile | Existing local lockfile contains both observability dependencies | Pinned Rust 1.94.0 checks use `--locked` |
| 3.1 session recovery | Typed durable session directory, tenant index and bounded cache rehydration | Gateway replacement restores session GET/list and same-key POST; effects require exact current Worker ownership/readiness; terminal replay precedes live admission |
| 3.2 Worker loss | Existing confirmed-loss coordinator connection retained | Exact loss identity and fence materialize unfinished actions without replaying uncertain effects |
| 3.3 publication | Existing durable terminal publication obligations and independent publisher retained | Store/publisher interruption and restart eventually append the same event once; retention remains pinned until ACK |
| 4.1 owner/heartbeat | Bounded owner control lane; renderer qualification separated from native ownership renewal; bounded concurrent shard maintenance | Health, dialog and shutdown progress during page waits; renewal uses the fresh completion clock and preserves session clock monotonicity |
| 4.2 document fence | Existing sequence fence retained; positively identified read-only document changes return `document_changed` | Navigation before the last DOM response issues no stale handle and does not taint a known read failure |
| 4.3 snapshot | Immutable action-specific result budgets through Worker, durable store, receipt and RPC | Snapshot accepts up to 4 MiB; excess is known `snapshot_too_large`; other actions and legacy records retain 64 KiB; UTF-8 and JSON framing are covered |
| 4.4 dialog | Owner directly handles owned dialog events while work waits | Alert accepts; confirm, prompt and before-unload dismiss; retired-target completion cannot affect a replacement |
| 4.5 network | Bounded request ledger includes frame/loader identity | Commit prunes only positively identified previous-loader requests; the new document's unfinished request prevents quiet |
| 5.1 admission | Typed new-connection rejection separated from fatal listener failure | Quota excess closes only the new socket and preserves the route and existing connection |
| 5.2 relay | Independently polled bounded bidirectional pumps with shared cancellation and write deadlines | Simultaneous backpressure progresses; EOF closes only the corresponding write half and allows the response |
| 5.3 clock | Registry samples one monotonic clock inside its serialized live state access | Delayed handler scheduling cannot move shared quota time backwards |
| 5.4 capacity | Active plan budget separated from bounded retained history | Released plans free active capacity; revoking plans remain charged until guard drain; stale receipts stay fenced |
| 5.5 path | Validated origin wire path/query retained separately from policy normalization | Double/trailing slash, encoded delimiters and query ordering survive forwarding |
| 6.1 audit | Existing production startup requires a usable audit WAL before epoch mutation | Missing/unusable WAL prevents startup; append failure prevents effect dispatch |
| 6.2 GC | Bounded catalog/cache janitors and independent PostgreSQL purge maintenance | Exact terminal/expiry guards, busy and unresolved retention, bounded indexed candidate selection and shared purge permit |

## Retained safety limits

Egress tombstones are not deleted to make admission appear unlimited. Active
capacity and historical authority have separate limits. The optional
`BROWSER_EGRESS_MAX_PLAN_HISTORY` bounds retained history; exhaustion requires
an orderly complete drain and coordinated daemon and Worker/supervisor epoch
replacement. Restarting only egress is not sufficient authority to accept old
prepare messages. No service epoch rotation or infrastructure deployment was
performed by this change.

Large snapshot results do not enlarge every action's budget or the digest-only
Worker journal reservation. The result profile binds to accepted action identity,
and old records default to the original small limit. Ordinary action effects with
ambiguous execution still require reconciliation.

The durable directory records the last confirmed session lifecycle. Listing it
does not grant dispatch authority: fresh exact Worker ownership and readiness
checks remain mandatory before effects.

## Evidence and remaining gate

Both SDK suites, TypeScript typecheck/build and all 128 CDP driver tests passed.
Egress tests passed, including the reconstructed admission, duplex, clock and
wire-path scenarios. Seven real Unix-RPC cleanup-confirmation tests passed.
The isolated PostgreSQL GC regression first reproduced 80 expired rows deleted
in one pass; the implementation now selects at most 32 indexed candidates.
Actual PostgreSQL/Redis session recovery, publication, bounded purge and snapshot
storage tests passed, together with the actual 4 MiB Worker RPC roundtrip and
lease-clock regressions. Pinned Rust 1.94.0 locked workspace Clippy (all targets,
all features, warnings denied), documentation tests and formatting passed.
Ignored privileged cases are not counted as passing native evidence.

Final engineering status: `~/logs/browserd-review-strict-source-final-fw_asp8n/status.json`.
Actual adapter regressions: `~/logs/browserd-review-final-quality3-_tfddkum/status.json`
(the two fixture failures in that historical run are corrected and pass in
`~/logs/browserd-review-final-quality4-42u_4chy/status.json`; its initial Clippy
warning is corrected and passes in the final strict gate). Failed historical
statuses remain unchanged. The fresh native gate is recorded separately at
`~/logs/browserd-review-native-final-ao896i50/status.json`; it finished with exit 1.
Fifteen probes passed; lifecycle completed 192 cycles and failed on the next
session's creation with a generic `Remote/backend` error. Native cleanup,
service reaping and container/cgroup removal succeeded; source stayed unchanged.
All 212 durable journals completed ten cleanup stages. The unique newest
incomplete preparation has filesystem/cgroup and egress preparation complete,
but no `spawn_gated_child` completion. The retained diagnostic does not prove
the underlying OS cause. The process-spawn producer now preserves a fixed
stage prefix; the probe records only a typed category and numeric errno while
omitting arbitrary messages. The actual missing-interpreter failure first
reproduced the missing context, then passed after correction. Eleven parser and
privacy regressions, focused all-target/all-feature Clippy and formatting pass:
`~/logs/browserd-native-spawn-green-ajip9hum/status.json` (exit 0).
The fresh full measurement is tracked at
`~/logs/browserd-native-spawn-diagnostic-mv_xpowb/status.json`; its result remains
pending. Diagnostic correctness does not establish the original OS cause.

The original-source full native run finished with 15/16 probes passing. Its
1,000-cycle lifecycle probe stopped after 675 completed cycles when the exact
cleanup RPC connection closed. All 695 durable cleanup journals later contained
all ten completed stages, but the run had no positive remote cleanup receipt and
therefore failed. The new client permits one identical, fully fenced cleanup
confirmation after `ConnectionClosed`, within the original absolute deadline;
all other failures remain final. Tests use actual supervisor responses, including
`AlreadyTerminated`, rather than inferring success from journal contents.

A fresh source-bound full native run remains necessary after integration. The
requested scope excludes the 72-hour soak. An isolated measured run does not
qualify the denylist as a production release policy or claim a host deployment.

Artifact and Viewer production support already exists in the local work; the
old commit's rejection paths are not evidence that those local implementations
are still missing. No additional feature work was introduced in this follow-up.
