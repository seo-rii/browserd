# browserd

`browserd` is a Rust browser runtime for multitenant AI agents. It exposes a
typed Skill API while keeping Chromium, CDP target identifiers, filesystem
paths, and raw browser handles behind server-side capability boundaries.

The authoritative product and architecture contract is [SPEC.md](SPEC.md).

## Safety status

This repository starts fail-closed. A build is not production-ready merely
because it compiles or its simulated adapters pass. Shared-context admission
must remain disabled until the pinned Chromium compatibility artifact passes
the Phase -1 and production sandbox gates in `SPEC.md` on the deployment
kernel. In particular, production requires an outer user/PID/mount/network
namespace, delegated cgroup v2 controls, Chromium's own sandbox, and a
mandatory egress route with no direct fallback.

## Development

The workspace uses Rust 1.94 and edition 2024. Each behavior-oriented work unit
is developed test-first and committed separately. Run the repository gates
with:

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```
