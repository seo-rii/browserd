# Remediation log — 2026-09-07 code review

This records how the findings of the 2026-09-07 review (`BRD-001`…`BRD-026`, tracked
in the review bundle's `evidence/findings.json`) were addressed on `main`. Each row
is **Done**, **Partial**, or **Open**, with the commit(s) that carry the change.

## Validation methodology

- The Linux-only crates (`browserd-worker`, `browserd-sandbox`, …) are built and
  tested on an ext4 WSL copy; `cargo clippy --workspace --all-targets --all-features
  -- -D warnings`, `cargo fmt --all -- --check`, and `cargo test --workspace` are the
  gates, with the durable-coordination suites run against real Postgres/Redis in
  Docker.
- The Chromium execution layer is exercised through a **mock CDP transport** that
  injects protocol events and responses, so the control-plane logic and the CDP
  command/enforcement sequences are unit-tested deterministically.
- What that environment **cannot** do is launch a real Chromium or a privileged
  Linux sandbox (SPEC Phase -1). So for the execution-layer findings, the Rust
  enforcement and contract are tested here, while the in-page JavaScript runtime
  behavior and real browser geometry are validated by the review's extracted-JS
  diagnostics and still want a live browser for full end-to-end coverage. Those
  cases are marked **Partial** below with the deferred portion named.

## Status

| ID | Pri | Title | Status | Commit(s) / note |
|----|-----|-------|--------|------------------|
| BRD-001 | P0 | Requested vs. production isolation mismatch | Done | `436d660` — isolation negotiation; requested + effective recorded durably |
| BRD-002 | P0 | Session directory / action GET lost on gateway restart | Done | `a75e6fc` — terminal GET served from durable state |
| BRD-003 | P0 | Action authority durability / rollback contract | Done | durable event-outbox series (`b84aa6f`…`4ffdc29`), `a541d14` |
| BRD-004 | P0 | Standard-session `evaluate` not bound to profile | Done | `436d660` — evaluate denied at dispatch for the standard profile |
| BRD-005 | P0 | Double-click partial dispatch → stale known-failure | Done | compound-input dispatch returns outcome-uncertain after a landed press |
| BRD-006 | P1 | Artifact / feature actions not wired end to end | Open | screenshot/PDF/scrape capture needs a real Chromium to produce bytes |
| BRD-007 | P1 | Viewer ticket → worker screencast not connected | Open | needs real Chromium + a WebSocket stream bridge |
| BRD-008 | P1 | Snapshot returns raw CDP AX tree, not a normalized schema | Done | `a003491` — SPEC §16.1 envelope, opaque node refs, bounds |
| BRD-009 | P1 | `query_all` epoch attached late (navigation race) | Done | guarded by the page-execution fence; mid-sequence navigation aborts |
| BRD-010 | P1 | `DOM.resolveNode` remote objects never released | Done | `Runtime.releaseObject` after a successful node read |
| BRD-011 | P1 | `network_quiet` ignored in-flight requests | Done | `24a0806` — owner-side in-flight request ledger |
| BRD-012 | P1 | Click actionability is content-quad centroid only | Partial | `62501f4` — scroll-into-view + viewport gate + occlusion hit-test; real geometry and cross-frame/animation cases need a browser |
| BRD-013 | P1 | `fill`/`check`/`select` bypass element semantics | Partial | `350bd52` — element-kind/disabled/readonly gating + reject on mis-target; IME/controlled-input runtime behavior needs a browser |
| BRD-014 | P1 | Gateway readiness pinned to the first probe | Done | `d8b6b8c` — dependency health monitor drives dynamic readiness |
| BRD-015 | P1 | Graceful shutdown only on SIGINT | Done | `a541d14` — SIGTERM drain |
| BRD-016 | P1 | CreateOperation reconcile loop absent from production main | Done | `a541d14` — reconcile pass in the supervisor loop |
| BRD-017 | P1 | Event channel's durable transition → outbox missing | Done | durable event-outbox series (`b84aa6f`…`4ffdc29`) |
| BRD-018 | P1 | Closed-session / create-binding lifetime & GC | Done | `4678864`, `b225a7c`, `71b3369`, `7b63a83`, `33f6df7`, `f87cfea` |
| BRD-019 | P1 | HTTP ingress not bounded before the blocking queue | Done | `e0bcc6f` — global + per-tenant admission with a reserved control lane |
| BRD-020 | P1 | Feature admission / audit not mandatory on dispatch | Partial | `55623a4` — mandatory critical audit intent before every effect, fail-closed; the FeatureAdmission resource reservation is deferred to when heavy features (BRD-006) land |
| BRD-021 | P2 | Fleet model vs. actual single-worker routing | Open | multi-worker scheduler (M6) needs cluster infrastructure |
| BRD-022 | P1 | Session option schema wider than production capability | Done | `436d660` — option support re-validated at gateway and worker |
| BRD-023 | P0 | Dependency / kernel qualification not separated from release | Open | tiered fast/adapter/process/kernel/soak gate needs a privileged kernel + CI |
| BRD-024 | P1 | TypeScript SDK distribution / typecheck gate missing | Done | `b76b1ef` — built package with declarations |
| BRD-025 | P1 | Reproducible release package / deploy runbook absent | Open | needs CI + ops packaging |
| BRD-026 | P2 | `query_all` silent truncation / fixed snapshot identity | Done | truncation signaled explicitly; snapshot identity via `a003491` |

## Summary

Done: 18 · Partial: 3 · Open: 5 (26 findings total).

The remaining **Open** items (006, 007, 021, 023, 025) and the deferred portions of
the **Partial** items each need something this validation environment does not
provide — a real Chromium to produce or drive browser bytes/streams, kernel/sandbox
privileges, or cluster/CI/ops infrastructure — rather than additional
unit-level work.
