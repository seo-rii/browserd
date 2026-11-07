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

While a page action waits for CDP or navigation lifecycle events, the Chromium
owner services a separate bounded queue for paused-target bootstrap and rejection
cleanup. Ordinary page actions remain serialized, and bootstrap work retains the
parent action's deadline and the target's ownership fence. Options contexts apply
user-agent and `Accept-Language` to owned iframe targets before resume, preserving
the native UA and client hints when a custom UA is absent. Iframes do not become public
pages. Options sessions bind exact locale/timezone to an immutable native process
profile. The sandbox sets fixed locale variables and `TZ`, and installs sealed,
catalog-approved ICU data and the exact locale pak alias beside its pinned
executable. The owner does not create inspector locale/timezone overrides on this
path, avoiding renderer-peer resets when an iframe handler detaches. Native
options sessions also support dedicated, shared and service workers. Custom UA
is bound to the immutable process profile so every worker receives it from its
first script; omitting it preserves Chromium defaults. Worker targets stay private
to the owning context and full session fence. Deployment qualification is tracked
in `RISK_REGISTER.md` as ARCH-016.
An attached target from an unknown browser context closes owner admission and
drains the shard even during an active action; no later bootstrap or page action
may run on that connection.

Both production daemons require `BROWSERD_CHROMIUM_ARTIFACT_ROOT`. Its verified
`compatibility.json` must include `native-process-profiles.json`, whose SHA-256 is
the identity's `launch_profile_digest`. For example:

```json
{"schema_version":1,"icu_data":"icudtl.dat","locales":[{"locale":"ko-KR","pak":"locales/ko.pak"}],"time_zones":["Asia/Seoul","UTC"]}
```

The ICU file must be beside the unique manifest executable, and every selected
resource must have its own verified manifest digest. Locale and timezone names
are exact allowlists; unsupported requests fail before sandbox creation. The
sandbox resource destinations `<executable-dir>/icudtl.dat` and
`<executable-dir>/locales` must not overlap configured read-only mounts. Existing
callers must send the mandatory `process_profile.schema` in sandbox RPC requests;
deploy worker and sandbox daemon versions together. This catalog declares the
approved resource profile; local fixture manifests do not qualify a release.

## Validation gates

Run `python3 scripts/validation.py <tier>` to produce private command logs and a
machine-readable report under `~/logs`. A missing prerequisite is **blocked**
(exit 2), a failed check is exit 1, and only a completed gate returns exit 0.
`--plan` lists commands without running or passing a gate.

| Tier | Scope |
| --- | --- |
| `fast` | Formatting, Clippy, Rust unit/contract/doc tests, SDKs and viewer checks |
| `adapter` | Real Redis and PostgreSQL conformance suites |
| `process` | Launch-gate, daemon startup and local RPC process tests |
| `kernel` | Linux backend tests plus pinned Chromium and deployment-kernel qualification |
| `soak` | Real workload running at least 72 hours with resource and isolation evidence |

`adapter` requires `BROWSERD_REDIS_TEST_URL` and
`BROWSERD_COORDINATION_TEST_DATABASE_URL` pointing to isolated disposable test
services; the suites write data and apply migrations. An unset URL cannot count
as adapter coverage even though an individual Cargo test may return early.

`kernel` and `soak` require an approved Chromium artifact, an explicitly delegated
cgroup v2 subtree and a trusted deployment-specific probe runner. Use
`python3 scripts/validation.py kernel --describe` for the environment and receipt
contract. A runner's successful exit alone is insufficient: each required probe
must supply evidence bound to the current run and artifact. The repository does
not substitute mock CDP results for these probes. Running namespace helpers
successfully does not qualify Chromium's sandbox or mandatory egress.
An external kernel/soak runner returns exit 2 when deployment prerequisites or
required probes are incomplete; the report remains blocked. Exit 2 from an
ordinary test command is still a failure, and neither case passes qualification.

Artifact preflight for both tiers verifies the native catalog schema, its
`launch_profile_digest`, the unique binary mapping, and declared ICU/locale pak
hashes before running commands. Release packaging uses the same catalog contract
and validates the exact catalog bytes put in the archive. A binary-only legacy
manifest cannot pass these checks. These checks establish resource consistency;
operator approval and the real kernel/soak receipts are still required.

The GitHub workflow runs fast, adapter and process gates automatically. Kernel
and soak jobs are manual on labelled trusted runners and require their paths to
be configured. Adding the workflow does not configure or qualify such a host.

`live_chromium_emulation` belongs to the kernel tier. Its positive tests cover
top-document locale/timezone/viewport, frame JS and HTTP UA/language, reload and
renderer replacement. `live_chromium_workers` covers first-script locale, timezone,
JS/HTTP UA and language for all three worker kinds with default and custom UA,
nested dedicated workers, shared reconnect and service registration lifetimes.
The native process profile passes the emulation regressions on the local
shell, including exact explicit/default-UA OOPIF locale/timezone inheritance and
surviving-frame readback after detach. These functional results do not replace
approved-artifact and deployment-kernel qualification.
`scripts/chromium_emulation_matrix.py` records raw CDP measurements separately;
exit 0 means observations completed, not that the profile or artifact is qualified.

### Device-local validation setup

`scripts/prepare_device_artifact.py` snapshots the installed Playwright Chromium
headless shell into independent private copies. It obtains the version and full
protocol schema from the copied executable with Chromium's sandbox enabled, and
records the actual ICU, locale, library, font and certificate bytes. The artifact
remains `local_candidate` with `operator_approval=false`. The protocol digests
identify documented partitions of the observed combined schema; deployment must
qualify those identities and the runtime mounts separately.
The manifest's `product_version` contains the version component expected by the
Chromium connection; provenance retains the original CDP product and brand.

```sh
python3 scripts/prepare_device_artifact.py \
  --destination "$HOME/.local/state/browserd-validation/artifacts/chromium-candidate"
python3 scripts/device_validation.py install \
  --artifact-root "$HOME/.local/state/browserd-validation/artifacts/chromium-candidate"
python3 scripts/device_validation.py functional
python3 scripts/device_validation.py doctor
```

The functional command runs the Python browser suites, all seven ignored Rust
browser suites and the real file-input, secret-injection, checkpoint and frame-input proofs
against that copy, with private logs
under `~/logs`. Its report
is a `device-functional` result, not a kernel/soak gate. Installation records the
manifest digest and rejects later artifact drift; `candidate.env` clears inherited
qualification runner/trust settings before exporting the local test paths.

With `BROWSERD_CHROMIUM_ARTIFACT_ROOT` configured, the Rust owner fixtures verify
the supplied identity, complete file manifest and native catalog before launch.
The browser observation does not replace the pinned expected identity. Native
snapshots preserve the supplied catalog bytes and resource layout without
rewriting shared assets. The fast gate runs all nine offline fixture regressions.

Production pipe claims retain the exact namespace-attached egress listener
address, tenant, policy and complete launch/session fence. Sandbox RPC transfers
this validated binding with the receipted CDP pipe pair; a missing or mismatched
binding closes production admission before any browser command. Upgrade
launch-gate, sandboxd and worker together. Legacy direct-browser fixture constructors remain
unqualified functional entrypoints.

The routed functional browser case proves that an accessible loopback origin
receives no direct connection either with the fixed proxy active or after it
stops. It exercises the actual context proxy and download-deny setup, but does
not qualify the outer sandbox or production egress daemon.

The production owner creates each context with its fixed HTTP proxy and
`proxyBypassList=<-loopback>`. Downloads remain denied unless the worker has a
configured scanner and explicitly enables the sandbox's directory capability.
Enabled downloads use a private 32 MiB tmpfs, at most four pending files of 8 MiB
each, and a 120-second deadline. The owner attributes each canonical GUID to the
exact frame, session and ownership fence and ignores suggested filenames and
event paths. The worker scans and stores the pinned file with one stable ArtifactId
before acknowledging scratch cleanup. Download publication runs independently of
the heartbeat timer and is also reconciled on artifact listing. Actual deployment
qualification still requires the approved artifact and kernel/soak gates.
The approval gate preserves only `LANG`, `LC_ALL`, `LANGUAGE` and `TZ` from the
trusted launcher, so verified native defaults survive exec while other inherited
environment variables are cleared. The launcher fixes `LANG` and `LC_ALL` to
`C.UTF-8` so Chromium preserves Unicode file paths even without an installed
language-specific POSIX locale. Native browser language still comes from the
verified locale resources, language flags and session options.

`deploy/setup-validation-host.py --user USER --repo ABSOLUTE_REPO --state-dir
ABSOLUTE_STATE --render` produces a reviewable, separate systemd service. Applying
the same command with `--apply` requires root in an ordinary host shell. It
delegates only that service's cpu/memory/pids cgroup, keeps `NoNewPrivileges=yes`,
and does not change existing services. Its private socket can start only the fixed
kernel/soak validation entrypoint as the configured user, inside the delegation.
Creating a cgroup elsewhere does not permit an undelegated process to migrate
into it. Use `--state-dir ABSOLUTE_STATE --run diagnose` to inspect an installed
service. This bootstrap does not install approved probe configuration, seccomp
inputs, approved artifacts or a trusted-validation flag; those remain required
by the gates.

After bootstrap, `device_validation.py doctor` checks the private service socket,
holder identity, actual controller delegation and workload subtree. It reports
the original caller's cgroup separately: an undelegated development terminal does
not invalidate a working dedicated service.

`scripts/device_kernel_runner.py` is a partial device diagnostic runner. It
checks the pinned Chromium version and independent cgroup/namespace capabilities
inside the service. Its `partial-evidence.json` keeps every production probe
outside its diagnostic scope blocked, writes no passing receipt and returns exit 2. Configure
its executable path and `BROWSERD_TRUSTED_VALIDATION=1` for that explicit private
test request only; candidate provenance and the saved candidate environment stay
unqualified. Controller and namespace smoke checks do not attest the production
sandbox, proxy routing, lifecycle stress or the 72-hour workload.

The production runner is `scripts/production_kernel_runner.py`, backed by the
`browserd-kernel-probe` binary in `browser-worker`. It uses existing isolated
sandbox/egress services, the production shard factory, router and artifact store.
Its 16 kernel probes cover the pinned identity, Chromium and outer sandbox,
context lifecycle, fixed proxy and direct-egress denial, paused target bootstrap,
context ownership, native emulation, downloaded bytes and acknowledgment, PDF
stream completion and close, screencast frame acknowledgment, orphan targets,
1,000 actual start/stop iterations, worker SIGKILL lease cleanup and cross-shard
isolation. A bounded passive trace pairs actual CDP commands with successful
replies on the original claimed pipes. Cleanup must complete before a passing
receipt can be published; forced runner cleanup cannot satisfy the SIGKILL probe.
Outer sandbox evidence pins the live bubblewrap ancestry, its actual gated
command and consumed seccomp descriptor to the approved files. The evidence
records kernel-filter readback and a browser denied-syscall observation separately.

Build the engine with `cargo build --locked -p browser-worker --bin
browserd-kernel-probe`. An operator must separately provide
`/etc/browserd/kernel-probe-approval.json` for the exact executable, artifact,
daemon binaries, launch gate, bubblewrap, seccomp and runtime files. Review
[`deploy/kernel-probe-approval.example.json`](deploy/kernel-probe-approval.example.json)
and [`deploy/kernel-probe-runtime-manifest.example.json`](deploy/kernel-probe-runtime-manifest.example.json)
for the input shape. The examples have no approval and their placeholder hashes
do not authorize execution. Configuration must be root-owned, readable by the
validation user, mode 0400/0440/0600/0640, with root-owned ancestors that other
users cannot write. Approved assets and their ancestors also require root
ownership and no group/world write permission. Runtime inventory must exactly
cover the configured read-only mounts, including every file and digest.

For an installed delegation service, load the candidate environment first, then
select the production runner for one explicit kernel request:

```sh
. "$HOME/.local/state/browserd-validation/candidate.env"
export BROWSERD_KERNEL_RUNNER="$(pwd)/scripts/production_kernel_runner.py"
export BROWSERD_TRUSTED_VALIDATION=1
python3 deploy/setup-validation-host.py \
  --state-dir "$HOME/.local/state/browserd-validation" --run kernel
```

Run this from the repository root. The default approval path works with the
existing holder protocol. A custom approval path requires both
`BROWSERD_KERNEL_PROBE_CONFIG` and `BROWSERD_KERNEL_PROBE_CONFIG_SHA256`, and a
holder configured to forward these keys. The code does not restart that holder.
Fixture addresses and public origin must refer to isolated approved canaries
reachable through the production egress policy; the runner does not relax
localhost/private-address denial. Downloads additionally require the configured
production scanner; PDF requires explicit `worker.privileged_evaluate=true` in
the approved configuration. The example keeps that authority disabled. Missing
inputs return 2 with no passing receipt.

The wrapper pins and rehashes approved assets, rejects stale or repeated evidence,
and publishes a fresh private receipt only after all 16 probes pass with complete
cleanup. Evidence binds the run, kernel, artifact, configuration, executable and
current source contents. Source changes during qualification fail the gate.
Implementing these probes does not approve the current device candidate or supply
the separate 72-hour soak evidence.

`deploy/prepare-kernel-probe-assets.py` prepares the native deployment inputs
without installing them. Supply the verified Chromium artifact and a directory
containing the current `browserd-kernel-probe`, `browser-sandboxd`,
`browser-egressd` and `browserd-launch-gate` executables:

```sh
python3 deploy/prepare-kernel-probe-assets.py \
  --artifact-root "$BROWSERD_CHROMIUM_ARTIFACT_ROOT" \
  --binary-dir "$(pwd)/target/debug" \
  --output-dir "$HOME/.local/state/browserd-probe-assets-new"
```

The output path must be new, absolute and separate from the source trees. The
preparer copies every Chromium file, retains the original `compatibility.json`
bytes, rejects symlinks and special files, and detects source changes. Add
`--include-worker` to include `browser-worker`. Its private output contains the
read-only `assets/` tree, exact `inventory.json`, a complete mount checksum
manifest, `preparation.json`, `install-assets.py` and `install-command.txt`.
The default install destination is `/opt/browserd/kernel-probe/<content-sha256>`;
`--install-destination` selects another new, absolute asset destination.

Review the inventory, destination, generated installer and recorded
`installer_sha256` before executing the exact command in `install-command.txt`
from an ordinary root shell. That command starts isolated Python, authenticates
the installer bytes against the recorded SHA-256, then verifies the prepared
inventory and every payload file before installation. The installer rejects
unsafe parents and existing destinations, copies into a private root-owned
temporary tree, and publishes it atomically without replacing a raced
destination. Installed files are mode 0444 or 0555 and directories are 0555.
This installs assets only: it creates no service, approval configuration or
passing receipt. Both `prepared` and `installed` results retain
`operator_approval=false` and `production_qualified=false`. A shell started by a
`NoNewPrivileges` development process cannot obtain the root privileges needed
for this installation.

`deploy/kernel-probe-seccomp.py` generates a separate input for isolated x86_64
Linux measurements:

```sh
python3 deploy/kernel-probe-seccomp.py \
  --output-dir "$HOME/.local/state/browserd-probe-seccomp-new"
```

The new private directory contains `policy.bpf` and `policy.json`, which records
the exact digest, Linux-header constants and policy limits. Generation requires
the actual installed Linux headers and C compiler; unsupported hosts fail. The
filter rejects architecture changes and x32, and denies named privileged,
inspection, keyring and `io_uring` calls while preserving Chromium namespace
setup. It is a bounded denylist whose other calls are allowed. Generating it
proves neither runtime installation nor a release syscall allowlist. The
Chromium sandbox and measured outer namespace/resource/network isolation remain
required; the generated policy grants no operator approval.

For a separate native measurement, `deploy/kernel-probe-lab.py` and
[`deploy/Dockerfile.kernel-probe-lab`](deploy/Dockerfile.kernel-probe-lab)
provide an isolated Docker lab. The image contains genuine bubblewrap, Redis and
ClamAV programs. Build it locally and use its exact local `sha256:` image ID;
the launcher never pulls a replacement during the run:

```sh
docker build --file deploy/Dockerfile.kernel-probe-lab \
  --tag browserd-kernel-probe-lab:local deploy
BROWSERD_PROBE_IMAGE_ID="$(docker image inspect \
  --format '{{.Id}}' browserd-kernel-probe-lab:local)"
```

Use `--build-arg BASE_IMAGE=IMAGE@sha256:DIGEST` for a reviewed base-image pin.
Prepare a caller-owned
mode 0700 stage containing independent regular-file copies of:

| Staged path | Required input |
| --- | --- |
| `chromium/` | The complete verified Chromium artifact, including its original manifest |
| `bin/browserd-kernel-probe` | Current native probe engine |
| `bin/browserd-launch-gate` | Current native launch gate |
| `bin/browser-sandboxd` and `bin/browser-egressd` | Current production daemon executables |
| `bin/browserd-safety-initialize` | Native initializer restricted to this lab's Redis endpoint and run prefix |
| `seccomp/filter.bpf` | Reviewed restrictive cBPF input, such as the generated `policy.bpf` |
| `runtime/chromium-resources/` | Exact Chromium resource copies and the pinned executable alias described below |
| Runtime mount trees | Complete libraries, fonts, certificates and other files for each selected sandbox destination |

The asset preparer's `assets/chromium` and `assets/bin` copies can supply the
first four rows. The lab additionally requires the native safety initializer,
seccomp input and complete runtime mount trees. Build the initializer with
`cargo build --locked -p browser-worker --bin browserd-safety-initialize`.
The stage must contain no links, special files or shared hard links. Runtime
mounts must reproduce the actual browser runtime paths; listing a mount does
not discover or synthesize missing libraries, font configuration or trust data.

The headless shell also needs resources next to its guest executable. Populate
`runtime/chromium-resources/` with independent SHA-256-matching copies of the
verified artifact's `icudtl.dat`, `headless_command_resources.pak`,
`headless_lib_data.pak`, `headless_lib_strings.pak` and
`v8_context_snapshot.bin`. Include the exact approved binary as executable
`chromium` and an empty `locales/` directory. Mount that tree at
`/browserd-chromium`; the guest executable is
`/browserd-chromium/chromium`, while the launch gate remains
`/browserd/launch-gate`. The selected resource source parent must be mode 0555
in the root-owned container asset copy. The lab validates the executable alias against the
approved binary digest. Resource mounts apply before the sealed executable and
validated native ICU/locale overlays, preserving those pins. The empty locale
mount point is recreated in the container asset copy for the native overlay.
The guest ELF interpreter `/lib64/ld-linux-x86-64.so.2` must be a regular-file
copy whose stage mode is 0555; mode 0444 prevents execution despite matching
bytes. Every library SONAME alias must likewise be an independent regular file.

With fresh, empty mode 0700 output owned by the validation UID, the existing
validation service's delegated `workloads` path, and current source bindings,
prepare a reviewable plan as follows. The `runtime/lib`, `runtime/lib64`,
`runtime/usr` and `runtime/etc` mappings shown here require corresponding complete
staged trees, including the ELF interpreter and regular-file copies of library
SONAME aliases:

```sh
python3 deploy/kernel-probe-lab.py \
  --stage "$BROWSERD_PROBE_STAGE" \
  --output "$BROWSERD_PROBE_OUTPUT" \
  --delegated-workloads "$BROWSERD_VALIDATION_CGROUP_ROOT" \
  --image "$BROWSERD_PROBE_IMAGE_ID" --uid "$(id -u)" \
  --chromium-binary "chromium/chrome-headless-shell" \
  --runtime-mount "runtime/chromium-resources=/browserd-chromium" \
  --runtime-mount "runtime/lib=/lib" \
  --runtime-mount "runtime/lib64=/lib64" \
  --runtime-mount "runtime/usr=/usr" \
  --runtime-mount "runtime/etc=/etc" \
  --source-revision "$BROWSERD_PROBE_SOURCE_REVISION" \
  --source-content-sha256 "$BROWSERD_PROBE_SOURCE_CONTENT_SHA256" \
  --source-dirty "$BROWSERD_PROBE_SOURCE_DIRTY" \
  --approve-isolated-measurement
```

Replace `--chromium-binary` with the executable's actual staged path. Derive
the revision, dirty flag and content digest with `scripts.validation`'s
`source_identity` and `source_content_identity` after fixing the measured source
tree. `--approve-isolated-measurement` records authorization for this isolated
run; it does not approve an operational deployment or qualify a release.
Without `--run`, the command only writes `lab-plan.json` and prints the exact
Docker argument list. Review that plan and list. To execute, use new stage and
output directories and append `--run` to the initial invocation; stage helpers
and run state cannot be reused. Execution creates only a fresh child of the
existing delegation and starts the pinned image. It does not restart the
existing holder or install host services.

Before the long measurement, append `--preflight --run` to a fresh initial
invocation. This starts the same genuine services and admits the same approved
inputs, then runs bounded native diagnostics for the 15 functional probes. It
omits only `start_stop_1000`, uses `preflight-response.json`, records
`diagnostic=true` and `qualification=false`, and never invokes the production
receipt publisher. Success is `preflight_completed`, with positive service and
shard cleanup. Use a new stage/output incarnation for the subsequent full run.
Diagnostic preflight has a 900-second bound capped by the original caller's
deadline, with a 1,500-second native outer bound. The complete production
request retains its 7,200-second deadline and all 1,000 lifecycle iterations.
Optional staged `clamav/` database files are exact-inventory inputs copied to
private container tmpfs; genuine freshclam still validates and updates them.
Native preflight RPC diagnostics preserve bounded structural errors in private
evidence rather than collapsing every transport, admission and remote error
into one message. The latest actual preflight,
`~/logs/browserd-proxy-repeat-preflight-8yajrqc0/status.json`, finished with
exit 0, `preflight_completed`, all 15 probes passed and all 64 actual proxy
loopback repetitions completed with positive cleanup. Every owned service,
container and cgroup was removed; source stayed unchanged. Full SHA and
namespace/root checks and original helper/deadline bounds remain in force.

The earlier repeat control failed its third proxy close after two successful
iterations with `OutcomeUncertain`; its original raw RPC data is unavailable.
Bounded sanitized RPC failures, typed cleanup outcomes, three cleanup booleans
and the last 32 events per exact shard are now captured. That original raw
response remains unknown; it cannot be retroactively attributed to the newly
confirmed native cleanup-intent ordering defect.

The native fix waits for the actual durable `RevokeEgress` intent before
`AbortGate`. It commits that intent under the existing cleanup mutex before
context/retirement remote effects, while retaining parallel post-intent kill,
the original supervisor deadlines and positive success gates. A real-journal
regression first failed at the intended assertion and now passes; the hung
post-intent revoke regression also passes. Verification covers 351 distinct
Rust cases plus 16 separate repetitions of the corrected factory panic case.
Final checks, Clippy, formatting and three optimized native binary builds exit
0 in `~/logs/browserd-cleanup-intent-final-checks-pxf4j9u5/status.json`.
The earlier sandbox/runtime phases passed 281 and 20 cases in `0ciqb80j`, whose
overall exit 101 was an old factory observation fixture corrected before the
final 34 factory and 16 router cases passed. The prior 54 Python tests remain
passing. A separate actual
read-only control, `~/logs/browserd-chromium-readonly-control-6d90cagl/status.json`,
exits 0: the exact Chromium bytes and canonical self-exec work, `ST_RDONLY` is
observed, root and executable-parent changes are denied, and nested temporary,
profile and scratch mounts remain writable. The diagnostic preflight omits
`start_stop_1000` and creates no qualification receipt.
The first full attempt, `~/logs/browserd-kernel-full-validation-w3j1r_ls`,
finished with exit 1, 14/16 passed and no receipt: proxy cleanup was incomplete
and lifecycle session creation exhausted the retained-plan cap.

Journal evidence contains 256 completed launches with all ten cleanup stages;
the next launch failed at `prepare_egress` and rolled back. The isolated lab's
`BROWSER_EGRESS_MAX_PLANS=256` counted retained terminal plans. The isolated cap
is now 2,048, with measured tests covering the capacity configuration while
retaining tombstones and production defaults. The retry at
`~/logs/browserd-kernel-full-validation-hrghwllj` finished with exit 1 and
15/16 passed. Lifecycle stress completed 24 iterations, then failed
`close_session`. The exact `cancel_or_kill_shard` reply is `CleanupIncomplete`:
`route_revoked=true`, `cgroup_killed=false`, `namespaces_cleaned=false`, with
`rpc_failures=[]`. Final lab service reaping and cgroup removal completed with
unchanged source. After the tested intent-order correction, a fresh full retry
is prepared at `~/logs/browserd-kernel-full-validation-gl01q7fc`; its
`status.json` records the process state and final exit code. The
16-probe/1,000-cycle result remains pending. The passing
all-15/64-repeat diagnostic supplies no full qualification receipt.
A new full result still requires exit 0, positive native cleanup and a fresh wrapper
receipt. The current request excludes the 72-hour validation. The
denylist remains an isolated measurement policy; no qualified release or host
deployment is claimed.

The container receives a read-only input mount, fresh private output and the
exact fresh cgroup child. Its assets are copied into container-only tmpfs as
root-owned read-only files; services and the probe run as the validation UID
with `NoNewPrivileges`. Docker's outer seccomp/AppArmor restrictions are disabled
for nested sandbox measurement. `systempaths=unconfined` permits the inner
sandbox to mount its own `/proc`; it does not select host PID or network
namespaces or Docker privileged mode. The lab requires the browser and owned helpers to retain
`NoNewPrivileges`, validation UID 1003 and zero effective capabilities in the
inner sandbox. The approved bubblewrap filter and Chromium's own sandbox remain
required. Sandbox supervisor leases are 30 seconds, directory leases are 60
seconds, and the production factory's 30-second lease matches those bounds.
The current isolated egress configuration uses the production `public-web` profile.
The lab starts genuine isolated Redis,
the native durable safety initializer, sandbox/egress daemons, current ClamAV
signature update and scanner, and owned network canaries. A failed database
update or prerequisite blocks the run instead of supplying substitute evidence.

The lab invokes the complete production runner, including all 1,000 real
start/stop iterations. Accept only a zero final exit with all 16 fresh probe
results, positive shard and service cleanup, and the wrapper's
`evidence/receipt.json`; `lab-status.json` records the runner exit and service
reaping separately. Remove the exact lab cgroup/container only after confirming
they contain no surviving owned processes or shards. An image build, controller
check, namespace check or prepared plan alone cannot satisfy these conditions.
The 2026-10-11 setup checks established the genuine image and cgroup/namespace
prerequisites. A separate actual resource smoke used the same pinned Chromium
and bubblewrap: the executable-only baseline exited 133 with missing ICU data;
the exact resource mount produced `about:blank` HTML with exit 0 while Chromium's
sandbox remained enabled, without `--no-sandbox`. The owned container was
positively removed; private evidence is in
`~/logs/browserd-chromium-resource-smoke-22j7t5iz`. This smoke supplies neither
the native 15-probe preflight nor the full 16-probe passing evidence. The current
completion request excludes the 72-hour soak. This lab does not run that soak or
change the qualified-release requirement for its separate evidence.

The kernel tier also executes an exact nested-network-namespace prerequisite.
It retains `NoNewPrivileges`, pins bubblewrap's actual host child namespace,
uses the production listener helper, checks host denial and in-namespace TCP,
and verifies cleanup. Its privileged prerequisite result does not prove listener
authority for the genuine UID-1003/capability-free daemon or qualify the
production sandbox/egress path. Production launch still requires approved launch-gate and
runtime assets outside the prohibited home paths, plus an approved seccomp input.

## Initial release scope and packaging

The initial distribution runs on one Linux host with one worker and
`dedicated_process` sessions. Fleet scheduling and multi-worker routing remain
future work; the broader architecture in SPEC does not imply those capabilities
are present in this release.

`scripts/package_release.py` produces a deterministic gzip/tar archive containing
the five binaries, built TypeScript SDK, Python wheel, viewer assets, deployment
templates, verified Chromium files, source identity and SHA-256 inventory. It
refuses secret and runtime-state paths. A deployment-qualified package requires
clean committed source, a build performed by the packager and passed reports for
all five tiers. Kernel and soak reports must match the bundled Chromium artifact
and the same target kernel and machine.

```sh
python3 scripts/package_release.py --build \
  --chromium-artifact-root /approved/chromium \
  --gate-report /evidence/fast/report.json \
  --gate-report /evidence/adapter/report.json \
  --gate-report /evidence/process/report.json \
  --gate-report /evidence/kernel/report.json \
  --gate-report /evidence/soak/report.json \
  --require-qualified --output /releases/browserd.tar.gz
```

The build uses locked, offline Cargo and cached SDK build dependencies. Download
dependencies in the build environment beforehand. `--binary-dir` with
`--python-wheel` accepts prebuilt inputs; `--dev-dirty` permits an uncommitted
review bundle. Both cases remain unqualified for deployment. Packaging tests use
synthetic inputs and do not substitute for a real release build or kernel gate.

## Single-host operating procedure

Upgrade gateway and worker together: this change uses worker RPC protocol 33 and
outbox migrations through `0004_event_notifications.sql`. Notification import
(`migrations/notifications/0001_worker_notification_import.sql`) and webhook
delivery (`0005_webhook_delivery.sql`) use separate migration histories. Mixed
binary/schema versions are outside the supported deployment contract. Retain both source journals and projection
watermarks when planning a rollback; restoring older binaries alone does not undo
the event schema changes.

The deployment templates do not provision infrastructure. PostgreSQL, Redis,
qualified bubblewrap/runtime libraries, a binary seccomp filter, TLS termination,
viewer hosting and an existing delegated cgroup v2 subtree are prerequisites.

1. Verify the extracted `SHA256SUMS`. Keep release files immutable and root-owned,
   including Chromium and launch helpers. Copy `deploy/.env.example` to
   `/etc/browserd/browserd.env` with mode `0600`, and replace every placeholder.
   Socket aliases, worker IDs, UID bindings and paired egress tokens must agree.
   The current gateway and worker require the same service UID.
2. Prepare private state and artifact directories with mode `0700` and ownership
   for the service UID. Configure the qualified cgroup subtree and runtime mounts.
   Audit WAL, control-event journal configuration and positive artifact quotas are
   mandatory. An optional authenticated ClamAV Unix socket enables uploads; missing or failed scanning
   rejects uploads while generated captures use their separate provenance.
3. With **all four daemons stopped**, calculate the next incarnation bindings:

   ```sh
   python3 deploy/next_epochs.py \
     --worker-state /var/lib/browserd/worker/epoch \
     --egress-state /var/lib/browserd/egress/epoch \
     --sandbox-state /var/lib/browserd/sandbox/epoch
   ```

   Update the four reported environment values. The helper only reads state.
4. Start egress, sandbox, worker and gateway in that order. The unit dependencies
   and `deploy/wait_ready.py` check startup transport reachability; `/readyz`
   separately reports whether browser admission is ready. The sandbox wrapper
   opens the approved seccomp filter on descriptor 5. On the first start, use the
   authenticated safety Initialize API below after the gateway is reachable.
   Browser effects stay closed until worker and egress independently verify that
   authority. Preserve an existing namespace instead of initializing it again.
5. After a failed start or restart, stop the whole stack and recompute epochs.
   `Restart=no` is intentional; never delete epoch state to retry. Drain gateway
   admission and sessions before shutdown, and retain action journals, audit WALs,
   control-event journals, runtime safety pins and artifact quota ledgers.
6. Roll back only after checking schema compatibility and completing shutdown.
   Restore the prior immutable release/configuration, recompute epochs and qualify
   the kernel/artifact combination again. Archive creation performs no deployment.

## HTTP action waiting

`POST /v1/sessions/{session_id}/actions` accepts one optional `Prefer: wait=N`
header, where `N` is an integer from 0 to 30,000 **milliseconds**. The wait budget
starts when the authenticated submission enters service processing and includes
coordination and enqueue delays. The gateway reports the durable action receipt
before waiting for worker completion; `wait=0` returns as soon as that receipt or
an immediate final result is available. Before durable acceptance, a timeout
cannot manufacture an ActionId or a successful `202` response.

A terminal action returns `200`, including `outcome_unknown`, which remains
non-retryable. A pending action returns `202` with the same `action_id` and a
`Location` header for `GET /v1/sessions/{session_id}/actions/{action_id}`. Action
responses use `Cache-Control: no-store`. `Preference-Applied: wait=N` appears when
the preference was applied. Expiry or HTTP disconnect leaves the original action
running; neither causes cancellation, a second submission or a replay.

Positive waits require `session:read` in addition to the action's normal scopes.
Without it, the optional preference is ignored and the ordinary submission path
is used. `wait=0` needs no additional read scope. Each wait observes only the same
authenticated tenant, session and immutable action identity. Failed or mismatched
status reads preserve the last valid accepted receipt.

Waiting is limited to 256 actions globally and 32 per tenant. Internal status
lookups have a separate limit of 64 globally and 8 per tenant, issue at most one
lookup per waiting action at a time and leave the ingress GET lane available.
Saturated wait or lookup admission returns the durable receipt without applying
the positive preference. Blocking submissions and lookups retain their admission leases until they
actually finish, including after the HTTP response or disconnect. These limits
can be reduced with `HttpConfig::with_action_wait_limits`.

## Action restart recovery

An accepted action retains its immutable identity in standalone Redis. Only the
creator can arm a new submission, using a one-second submission lease. Repeating
the same key returns its current receipt and never acquires dispatch authority.
The oldest pending action holds the session dispatch lane across action kinds;
an unresolved mutating outcome still requires explicit resolution.

Startup and the 15-second supervisor recover bounded pages of pending actions.
Each pass visits at most seven actions and issues at most fourteen worker read
RPCs. Existing per-call timeouts bound the pass. An exact expired, unattempted
lease becomes `failed_known` with `NotDispatched`. Armed or exposed actions are
queried using the full durable placement and authenticated `InspectSession`
ownership receipts, even while the worker is draining or not ready. An exact
`Closed` or `Failed` receipt commits one canonical session-loss identity. An
available terminal action receipt is saved first; remaining armed actions become
non-retryable unknown outcomes, while unattempted actions have proven non-delivery.
Close/failure observation seals live admission before any fallible journal write.
Retries after restart or a lost reply adopt the same loss identity, and durable
event discovery owns bounded materialization and notification delivery.

Unavailable workers, missing session receipts and identity mismatches provide no
loss proof. An abrupt worker-process death still needs an authenticated supervisor
exit receipt; this path does not infer loss from a timeout. Recovery sends no browser action, creates no
session and grants no new mutation admission. Nonterminal GET can query this
route after gateway restart without reconstructing a Ready session.

All pending records retain their hashes and index without expiry, including
read-only and unattempted actions. Pending admission is limited to 256 per session
and 65,536 per Redis namespace. Pending order uses zero-score, padded integer
members, preserving every `u64` sequence. Terminal transitions release pending
capacity. Original
worker completion remains owned after an exposure-write failure and can converge
with a concurrent recovery result through the same revision/dispatch CAS.

Action payloads have a separate admission limit: 65,536 retained records per
namespace and 4,096 per session by default. Configure
`BROWSERD_ACTION_MAX_RETAINED_RECORDS` (1..1,048,576) and
`BROWSERD_ACTION_MAX_RETAINED_RECORDS_PER_SESSION` (1..65,536, no greater than
the namespace limit) consistently for gateways and the offline migration.
Exhaustion rejects a new claim before dispatch; an existing idempotency receipt
remains readable. Session fences, loss identities and sequence high-water marks
remain permanent authority outside these payload limits.

The first terminal result starts a fixed retention horizon of at least 24 hours,
using Redis server time. A new resolution starts another horizon without shortening
the existing one. Claims, reads, event ACKs and custody retries do not extend it.
An independent startup/15-second janitor examines at most 32 due records per pass,
advancing past pinned records. Deletion requires the exact current record, placement,
sequence and idempotency mappings, ACK of its last source event, completed custody
release, and no pending dispatch or unresolved mutation. Legacy records without
an exact source watermark remain pinned. Payload and idempotency deletion commit
atomically; a later query returns `operation_not_found`, and the key can admit a
new action with a new sequence. No worker RPC or live browser session is required.

Production workers now inventory a private action-WAL directory before admission.
Worker/tenant limits cover retained WAL bytes, terminal-write reserves and metadata,
plus inode slots across restarts. Defaults are 1 GiB/256 MiB and 3,072/384 inode
slots; each session reserves three slots and 512 KiB for atomic metadata replacement
and accepts at most 1,024 actions. The five `BROWSERD_ACTION_JOURNAL_MAX_*` and
`BROWSERD_ACTION_JOURNAL_RETENTION_MILLIS` settings configure these bounds; retention
must be at least 24 hours. Quota exhaustion rejects admission before browser effects.

Workers can reuse a Chromium process for `shared_context` and
`tenant_dedicated_shard` sessions when explicitly authorized by
`BROWSERD_SHARED_CONTEXT_POLICY_FILE`. The optional JSON file is an immutable
startup snapshot in an absolute, symlink-free path; its immediate parent must be
owned by the worker UID with mode `0700`, and the regular file must have mode
`0600` and one hard link. The version-1 fields are `version`,
`force_dedicated_process`, `max_contexts_per_shard` (1–8),
`max_contexts_created_lifetime` (at least the live limit, at most 500),
`max_shard_age_secs` (1–7200), `qualification` (a complete
`browserd_chromium::QualificationReceipt`, or null), and `tenant_reuse` (tenant UUID
keys with `cross_tenant`, `same_tenant_only`, or `no_reuse` values). Limits apply
to each process; empty processes terminate immediately. The worker-local pool
retains at most 256 shards, including uncertain starts.

Reuse requires every existing shared-context qualification gate to pass for the
exact Chromium artifact and running kernel. Missing qualification, a mismatch,
force-dedicated, or a missing tenant grant selects a dedicated process with a
single context. `same_tenant_only` selects a tenant-specific shard even for a
shared request. An explicitly configured invalid or insecure policy fails startup.
Only the `public` network class and `public-web-default` policy support pooling;
immutable process settings, network policy, feature and dialog profiles separate
pool entries. Session receipts and approval bindings record the actual isolation.
`dedicated_worker` requires the exact whole-worker tenant assignment described below.
Shared placement requires matching worker, sandboxd and egressd binaries: the
supervisor-authenticated prepare contract explicitly distinguishes context routes
from the legacy single-route launch. Mixed versions do not support this mode.

Each context has an exact supervisor-issued proxy capability, a conservative local
lease deadline and a durable route record. Context disposal proves its own targets
and browser context absent while checking every remaining sibling's ownership.
Route capacity returns only after the exact listener is closed, accepted
connections drain, and a durable `Released` receipt arrives. Uncertain cleanup
retains capacity and drains that shard. Final process termination is separate;
startup recovery reclaims every recorded context route before retiring the shard.
Local eight-context Chromium fixtures exercise storage, workers and routing; they
do not produce production qualification or authorize shared deployment.

Multi-worker mode uses `BROWSERD_FLEET_GATEWAY_CONFIG_FILE` and matching
`BROWSERD_FLEET_WORKER_POLICY_FILE` snapshots. The gateway file has `schema_version: 1`,
`admission`, and `peers`. Each peer supplies `worker_id`, an absolute `socket_path`,
`peer_uid`, and `expected_worker_epoch`; its path must exactly match the worker's
inventory endpoint. Gateway files require an owned `0700` parent and a regular,
single-link `0400` or `0600` file, at most 1 MiB. Directory entries can select only
these authenticated peers. Current serving epochs are discovered on the configured
socket; historical artifact, event and custody reads remain pinned to the original
worker ID and ownership. A missing worker never triggers broadcast or reassignment.

The admission configuration supplies `region`, `workers`, `profiles`,
`default_tenant_policy`, `tenant_overrides`, and `limits`. Worker entries bind
compatibility/profile digests, a six-dimensional capacity ceiling and optional
`exclusive_tenant`. Profiles bind `profile_digest`, `compatibility_digest`,
`isolation`, `workload`, `resources`, and `drr_cost` (1–64). Exactly one profile must
match a request's isolation and workload. Tenant policies define weight (1–16),
resource limits, live sessions, queued operations and retained operations. Namespace
limits bound retained records, queued/live operations, queued tenants and aggregate
resources. Admission keeps FIFO order within each tenant and persistent weighted
deficits; each pass examines at most 64 tenant heads and 32 worker candidates.
Deficit credit is capped at the maximum cost, 64. The gateway observes one bounded
worker page and can advance at most 64 virtual fairness rounds per request, so
a weight-one tenant can admit a cost-64 request within its original deadline.
Placement maximizes the smallest free-to-capacity ratio across nonzero resource
dimensions, including unacknowledged reservation debits. Equal scores rotate
through the persisted worker cursor; larger inventories rotate bounded pages.
Configuration digests are immutable within the managed Redis namespace.

The worker file has `version: 1`, the exact `artifact_identity`,
`egress_policy_profile`, `egress_policy_digest`, `compatibility_digest`, `capacity`,
`budgets`, `max_retained_tokens` (1–65536), and optional `exclusive_assignment`.
Each of at most 128 budgets binds a `profile_digest`, requested `isolation` and
exact `resources`; each session consumes one context. Its file requires an owned
`0700` parent and a single-link `0600` regular file, at most 512 KiB. Worker policy
pins the actual artifact and egress binding before epoch admission. A whole-worker
assignment binds `worker_id`, `tenant_id`, and a nonzero `assignment_digest`.
Both the control plane and context factory reject foreign tenants; only this
operator assignment permits the `dedicated_worker` tier.

Worker-issued epoch/boot-bound reservation nonces fence create and inspection.
Only a positive no-effect receipt or exact context-disposal proof releases an
exposed obligation. Unknown create results stay charged and are inspected on their
original worker. Ready placement and action authority commit together in Redis;
PostgreSQL create projection and its durable acknowledgement converge separately.
Lease renewal preserves immutable placement authority and uses one fixed provider
deadline per nonce. Managed workers use a 60-second ownership lease with a
30-second directory lease and a separate 3-second maintenance pass. Drain rejects
new reservations while preserving existing leases and historical reads. Terminal
reservation proofs remain retained until coordination acknowledges cleanup and
their original 24-hour horizon passes. Inventory exhaustion rejects new reservations.

RPC 31 terminal receipts carry exact durable WAL custody and the original journal's
custody requirement. The gateway atomically
stores terminal/result or resolution evidence, its source events and a custody
obligation. Its independent startup/15-second pass processes at most sixteen
copy/release RPCs. A positive worker copy ACK is durably recorded before a separate
final release authorizes cleanup. Lost replies in either phase converge after
restart; neither phase depends on live sessions, worker readiness or event delivery.
The serving epoch may advance while the immutable original ownership remains fixed.

Worker maintenance runs every 30 seconds with a 32-session/5-second budget. It
requires positively confirmed session cleanup, terminal evidence, exact current
copy ACK and final release, elapsed retention after the latest seal/ACK/release,
and closure of every live WAL descriptor. Exact unlink and directory fsync precede
quota release. Unknown results are preserved as unknown; a later resolution requires
fresh custody. Legacy WALs without authority, missing custody and uncertain cleanup
remain charged and retained. A transient custody-projection failure preserves the
known result and its durable requirement. An independent startup/15-second catch-up
pass examines at most sixteen retained records and performs at most sixteen
historical proof reads. It contacts the same original worker at its current serving
epoch, binds the complete original scope and action sequence/kind, and attaches only
matching proof before the existing copy/release phases. This path sends no browser
action and does not require readiness, a live session or event delivery. Attaching
proof does not change the result, revision, retention horizon or source events.
If a historical read carries a newly committed worker resolution, its actual
annotation is restored through the normal atomic resolution transition; a
conflicting existing annotation is preserved.

An original unmanaged journal can explicitly report `unsupported` with its terminal
result. Missing legacy capability and managed projection failures remain required
and pin payload GC; a timeout, missing historical record or pool absence never
becomes `unsupported`. A saved original terminal revision permits late unresolved
proof to coexist with a later gateway-only resolution. Legacy records without that
anchor remain pinned when their exact current proof cannot be matched. Unknown
results and operator annotations are preserved; no execution is replayed.

Redis Cluster is rejected because the global pending index and session keys must
change atomically. Redis ACLs must permit `INFO cluster` as well as the adapter's
Lua, time, hash, sorted-set and TTL commands. Existing unmarked namespaces fail
startup with `RecoveryMigrationRequired`; an incomplete migration fails with
`RecoveryMigrationInProgress`. A fresh empty namespace initializes format v5.
Existing format-v2/v3/v4 namespaces require the explicit offline upgrade; older
writers reject the v5 marker. The v4 upgrade preserves its original horizons,
terminal custody and historical placement evidence. It creates no live fleet authority
for legacy sessions.

To upgrade existing data, stop **every gateway writer**, retain a backup, and
explicitly run the offline tool with the same `BROWSERD_REDIS_URL` and
`BROWSERD_REDIS_PREFIX` as the gateway:

```sh
cargo run --locked -p browser-gateway --bin action_migrate -- \
  --confirm-gateway-writers-stopped
```

The tool performs bounded steps with a durable migration cursor. If interrupted,
resume the same command before starting gateways. It preserves action identities,
terminal receipts, pending event journals, custody obligations and placement/loss
fences. The legacy backfill assigns terminal records a conservative new horizon
and preserves it across retries. A v3 upgrade validates its existing retained catalog
with a durable cursor and preserves its current horizons and proofs. Legacy
unattempted rows receive an expired lease only under this explicit quiescence
assertion; legacy armed rows are queried, never replayed. The assertion cannot
stop an old binary itself: mixed old/new writers and downgrade after migration are
unsupported. Records already expired before discovery cannot be reconstructed.
Over-capacity or corrupt data leaves migration closed for operator resolution.
Raise the configured record limits within their allowed bounds before resuming
an otherwise valid over-capacity migration.
This repository change does not execute an operator-data migration.

## Secret injection

`fill_secret` accepts an owned main-document `node_ref` and `secret_ref`. It
requires both `browser:act` and `secret:use`. The worker checks the configured
tenant, principal and exact HTTP(S) origin, including its port, before reading a
value. It rechecks the document and origin immediately before injection. Secret
values are excluded from the injection action's requests, results, durable journal
and audit payloads; the credential intent audit is mandatory. Revocation or
cancellation committed before dispatch admission prevents injection. An effect
already admitted may finish. An uncertain dispatched effect remains
`outcome_unknown` and is never automatically replayed.

Set `BROWSERD_SECRET_CONFIG_FILE` to an absolute catalog path to enable the
private-file provider. Its directory must be owned by the worker user with no
group or other access. The catalog and UTF-8 value files require private regular
files, with no symlinks or hard links. Values are at most 16 KiB and are resolved
only for an authorized running action; the catalog contains metadata and server
chosen basenames:

```json
{
  "schema_version": 1,
  "grants": [{
    "tenant_id": "019ccad0-0000-7000-8000-000000000001",
    "principal_ids": ["019ccad0-0000-7000-8000-000000000002"],
    "secret_ref": "login/password",
    "allowed_origins": ["https://example.test"],
    "value_file": "password.txt"
  }]
}
```

```json
{"action":{"type":"fill_secret","node_ref":"opaque-node-ref","secret_ref":"login/password"}}
```

Injection requires a configured audit WAL. Manual approval tokens for this action
are currently rejected before consumption; their integration belongs to the
subsequent approval policy work. Gateway and worker must use the same RPC version.
Page scripts and rendered captures can access an injected value according to
normal browser behavior.

## Frame selectors and node input

`query_all` accepts an optional `frame_path` of CSS selectors. Each step must
match exactly one `iframe` or `frame` in the current document. Nested same-origin
frames and cross-origin OOPIFs use the same contract:

```json
{"action":{"type":"query_all","frame_path":["#checkout","iframe.payment"],"selector":"input[name=cardholder]"}}
```

Omitting the path or supplying `[]` queries the main document and preserves the
original request hash. Paths contain at most eight steps, with at most 8,192 UTF-8
bytes per selector and 32,768 bytes in total. Results contain opaque `node_refs`;
use these with node reads, focus/blur, fill, check/uncheck, select, click,
double-click and hover. Frame IDs and CDP sessions remain private.

A reference binds to the owning session, page, frame, ancestor documents and
execution realm. Navigation, detachment or a renderer swap invalidates affected
references. Same-document hash navigation retains them. Pointer input scrolls
the relevant frames and checks stable geometry, frame borders, affine transforms
and ancestor occlusion; unsupported geometry is rejected before input.

Navigation, snapshots and actions without a node reference retain their page
semantics. `fill_secret`, `set_files` and manual approval proposals currently
accept main-document nodes only.

## Worker targets

Dedicated workers, nested dedicated workers, shared workers and service workers
inherit the Native session process's locale, timezone, language and optional UA.
Workers are scoped to their browser context, tenant and full session fence; they
are not exposed as pages or node handles. Shared/service targets use one browser
attachment, with recursive attachments excluding these kinds to avoid multiple
paused sessions on the same target. Every admitted worker completes its required
bootstrap before resume. Legacy inspector-only options contexts reject workers.

Each context admits at most 8 pages, 64 iframe targets, 16 dedicated/shared workers
combined, 8 service workers and 96 targets total, with 64 target creations per
10 seconds. Exact duplicate attachments consume one reservation. Shared/service
workers may outlive their originating document, and unregistering a service worker
does not itself prove target termination. Capacity remains charged until exact
retirement or confirmed context disposal. Disposal waits up to 3 seconds for
known owned worker targets to disappear; unowned targets or uncertain cleanup
close further admission.

## Action approval

The production worker installs an immutable action policy. Observational actions
are allowed by default; mutations and sensitive checkpoint export require external
approval unless an exact operator rule allows them. Missing configuration keeps
this default. An explicitly configured invalid file refuses startup.

Set `BROWSERD_ACTION_APPROVAL_POLICY_FILE` to a private absolute-path JSON file
(directory mode 0700, file mode 0600, both owned by the worker UID). For example:

```json
{
  "schema_version": 1,
  "default_require_four_eyes": true,
  "grants": [
    {
      "tenant_id": "01900000-0000-7000-8000-000000000001",
      "principal_id": "01900000-0000-7000-8000-000000000002",
      "action": "navigate",
      "context_scope": {"kind": "opaque_document"},
      "navigation_destination": "https://example.test/",
      "outcome": "allow",
      "require_four_eyes": true
    }
  ]
}
```

Rules match exact tenant, requesting principal, action and current HTTP origin
(including scheme and port), or an explicit opaque-document/browser-context scope.
Navigation additionally matches the complete canonical destination URL, including
path, query and fragment. Wildcards are rejected. `deny` overrides matching
`manual` and `allow` rules. Four-eyes enforcement applies to manual decisions and
requires a principal different from the requester; it is configurable in the
operator snapshot. A rule never supplies feature scopes, credential grants, file
authority or the privileged evaluate grant.

At the queue head the worker observes its owned target and publishes a bounded
proposal. Pending approval has a separate deadline and remains cancellable before
dispatch. `GET /v1/approvals` and `GET /v1/approvals/{id}` require `approval:read`
and return the same `summary` shape, containing action/context/expiry, requester,
proposal and policy digests, optional bounded node hints, and safe file or secret
reference metadata. Summaries exclude secret values, file bytes, fill values and
evaluate source. The decision endpoint requires `approval:decide`.

Version 2 proposals bind the exact action ID/sequence, full worker ownership fence,
immutable policy, payload, and actor target guard. Node observations include the
leaf route, unique default execution realm and all ancestor documents. Files bind
ordered IDs, generations, checksums, names, publication and scan evidence; secret
input binds an immutable provider grant without resolving its value. Checkpoints
bind the context, ordered origins and Chromium identity, including cookie-only
capture of a blank context. Preparation precedes one-time approval consumption;
the owner revalidates the target at the native effect boundary. Changed evidence
fails as stale, and an uncertain admitted effect is never replayed. Proposal,
decision, expiry and dispatch intents require durable audit records.

The transport-neutral control plane retains an explicit no-policy compatibility
mode for library fixtures. The production binary always installs the policy and
rejects gateway-supplied approval evidence. Upgrade gateway and worker together
for RPC 29 and the approval list's resource objects.

## Privileged evaluate

`evaluate` requires `browser:act`, `browser:evaluate` and a session created with
`feature_profile: "privileged"`. Privileged session creation additionally requires
`browser:evaluate`. The worker defaults to disabled. To enable it, set
`BROWSERD_PRIVILEGED_EVALUATE_POLICY_FILE` to an absolute path containing:

```json
{
  "schema_version": 1,
  "grants": [
    {
      "tenant_id": "01900000-0000-7000-8000-000000000001",
      "principal_id": "01900000-0000-7000-8000-000000000002"
    }
  ]
}
```

Use the actual tenant and authenticated principal UUIDs. The containing directory
must be owned by the worker with mode `0700`; the regular file must be owned by
the worker with mode `0600`. Symlinks and hardlinked files are rejected. The file
is limited to 256 KiB and 1,024 unique grants. Unknown fields, duplicate grants or
invalid configuration refuse startup. An empty grant list keeps evaluate disabled.
The immutable policy is loaded at startup; changes require a worker restart.

Creation checks whether the tenant has a grant. Every action checks the exact
tenant/principal pair, including requests in an existing privileged session and
actions with manual approval. A mandatory durable audit intent records ownership,
request and policy digests without the JavaScript expression or result. Failure
to record the intent prevents execution.
Use the action `snapshot` result's target, document epoch and URL revision when
constructing a manual evaluate proposal; page-list metadata does not supply these
live approval observations.

Immediately before execution, the worker validates the active action, complete
ownership fence, page, cancellation state, action deadline, session lease and
emergency policy. Chromium's frame metadata supplies the origin. A JavaScript
exception after submission produces `outcome_unknown`; the action is never
automatically replayed. The Chromium resource profile remains `standard`.
Literal origin IPs participate in emergency IP admission. DNS origins do not
provide a verified peer address through this observation; network requests retain
the separate egress policy checks.

## Storage checkpoints

`checkpoint` requires `browser:act` and `checkpoint:create`. It saves the session's
cookies and `localStorage` for explicitly listed origins. Omitting `origins` saves
cookies only. Origins must be canonical HTTP(S) origins, including any port, and
currently have an owned main document in the session; up to 16 are supported.
The result contains only an opaque `checkpoint_ref`:

```json
{"action":{"type":"checkpoint","origins":["https://example.test"]}}
```

Set both `BROWSERD_CHECKPOINT_ROOT` and `BROWSERD_CHECKPOINT_KEY_FILE` to absolute
paths to enable checkpoint storage. The root must be a private directory owned
by the worker. The key is a private, owner-held regular file containing exactly
32 random bytes. Symlinks and hard links are rejected. Preserve this key across
worker restarts; changing it does not migrate existing checkpoints. Records are
authenticated and encrypted, retained for 24 hours, and bounded to 32 KiB of state,
128 cookies and 256 storage entries. The store holds at most 128 records and
8 MiB. Checkpoints are excluded from normal artifact listing and download.

Pass the returned reference as `checkpoint_ref` in a new session request.
Restoration requires both `session:create` and `checkpoint:read`, the same tenant
and the exact Chromium artifact identity. A mandatory audit intent precedes
capture or restoration. The worker creates a new session and restores storage
before publishing it as ready. Origin documents are fulfilled locally with empty
content; restoration sends no request to the sites. The published primary page
starts at `about:blank`. Restoration runs once, so later navigations preserve
changes made by the page. A partial restore fails creation and disposes the new
context; uncertain disposal closes further admission.

The resulting session records `restored_from_checkpoint` and
`recovered_from_session` as server-provided metadata. Existing page IDs, node
references, pending actions and viewer control are not restored. IndexedDB,
sessionStorage, service workers, caches and DOM/JS state are outside this subset.
Partitioned cookies are rejected rather than silently omitted. Manual approval
for checkpoint creation remains unsupported until the subsequent approval work.

## Artifact transfers

`POST /v1/sessions/{session_id}/artifacts/uploads` accepts a JSON body containing
`display_filename`, optional `declared_content_type`, `expected_size_bytes` and
`data_base64`. This ingress accepts at most 512 KiB of decoded bytes. Size and
base64 must agree exactly; a metadata-only body cannot store a file. Filename and
declared MIME type do not authorize filesystem paths or publication. The production
scanner must confirm uploaded content before it becomes available.

Enable the scanner with `BROWSERD_ARTIFACT_SCANNER_SOCKET`, its expected service
UID in `BROWSERD_ARTIFACT_SCANNER_UID`, and
`BROWSERD_ARTIFACT_SCANNER_TIMESTAMP_TIMEZONE=UTC`. Configure that authenticated
clamd service with `TZ=UTC` before declaring this contract: its version date has
no timezone offset. Browserd does not change the scanner deployment. The default
maximum database age is 48 hours, with five minutes of future clock skew.
`BROWSERD_ARTIFACT_SCANNER_MAX_DATABASE_AGE_MS` can specify a positive age up to
seven days; `BROWSERD_ARTIFACT_SCANNER_MAX_FUTURE_SKEW_MS` permits zero to five
minutes. Scanner operation timeouts must be at most five minutes.

The Unix adapter authenticates the peer UID and brackets a bounded `INSTREAM`
scan with equal `VERSION` responses on the same `IDSESSION` connection. Missing,
stale, malformed or changed version metadata, unexpected responses and clock
regression reject publication. The recorded version digest identifies metadata;
it does not attest all database contents or cryptographically pin the engine
during the scan. This interpretation follows the
[ClamAV protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) and its
[version timestamp implementation](https://github.com/Cisco-Talos/clamav/blob/main/clamd/session.c).

Uploads and browser downloads preserve a private scan attestation binding the
reported program/database version, UTC timestamps, authenticated UID and freshness
policy to the exact tenant/session fence, source, committed generation, size and
SHA-256. Freshness is checked again before first publication. The whole evidence
is committed with publication authority and validated after restart and through
retained RPCs. Reads validate the original publication time; they do not rescan
stored content. Existing scanned publications without evidence stay charged and
unlisted until expiry cleanup; generated artifacts retain their separate source
without scan evidence.

Use a `set_files` action with the file input's `node_ref` and `artifact_ids` from
the same session to attach available artifacts. This requires both `browser:act`
and `artifact:read`. Provide 1–128 distinct IDs, with at most 8 MiB per action
subject to the configured artifact limits. Uploaded names must be safe basenames
and are preserved as the browser's `File.name`; unnamed artifacts use their ID
with a `.bin` suffix. File paths are generated inside the bounded sandbox scratch.
The browser retains at most 128 materialized files and 16 MiB until context cleanup
so later page reads can still access the selected files. A failed integrity check,
stale node or invalid file input rejects the action before attachment. Deploy
gateway and worker versions together for the named-upload RPC.

```json
{"action":{"type":"set_files","node_ref":"opaque-node-ref","artifact_ids":["artifact-id"]}}
```

`GET /v1/sessions/{session_id}/artifacts?limit=50` lists artifacts with
`artifact:read` scope, including completed browser downloads. The response contains
`data.artifacts` and `data.next_cursor`; pass that cursor as `after` for the next
page. The page limit is 1–100. TypeScript `listArtifacts` and Python `list_artifacts`
return this page directly. Downloads become available only after a clean scan;
failed publication retains exact cleanup receipts rather than storing a duplicate.

Metadata includes optional `display_filename`; uploaded safe basenames round-trip
through list/get responses and both SDKs. HTTP content keeps its fixed safe
attachment filename. Available artifacts have an immutable publication record
separate from byte completion, preserving the original worker/session fence,
object generation, checksum, source and name in a private, bounded journal.
Exact committed retries adopt the existing publication; uncertain publication or
withdrawal retains cleanup ownership and quota.

With the same private artifact root and a gateway configured for the serving
worker's current incarnation, list/get/download also work after session close or
worker/gateway restart. Retained read RPCs authenticate the current service while
preserving the original publication ownership; they create no browser session or
mutation admission. Publications expire after 24 hours. Ordinary reads and file
attachments also check expiry, and content streams recheck it for each chunk.
Existing completed files without publication records stay charged and unlisted;
startup never creates publication authority for them. Their exact committed
identity is recorded privately with a durable first observation and a one-hour
orphan grace period, independent of filesystem modification times.

The worker runs artifact maintenance separately from heartbeat and session
lifecycle every 30 seconds, admitting at most 32 entries within a five-second
pass budget. Expired publications are withdrawn before exact-generation deletion;
only a confirmed deletion permits a durable quota release. Active readers keep
the full object charged until their actual file handles close, and unfinished or
cancelled writes retain ownership until their filesystem work settles. Failed or
uncertain cleanup remains charged and retries on a later pass.

Deletion receipts remain for 24 hours after confirmed cleanup. After that retry
window, maintenance prunes exact filesystem receipts and compacts the private
journals with a durable retirement cutoff. Older retries fail closed rather than
claiming deletion from file absence. Journal and entry limits still enforce
backpressure while retained receipts occupy capacity. The configured
`BROWSERD_ARTIFACT_MAX_RETAINED_ARTIFACTS` includes these cleanup records: confirmed
deletion returns byte quota immediately, while its metadata slot becomes reusable
after retirement. Keep the parent runtime alive for owned cleanup; start a
replacement worker after the previous process has exited.

Request a short-lived one-use token through
`POST /v1/sessions/{session_id}/artifacts/{artifact_id}/download`, then send it in
`X-Browserd-Download-Token` on authenticated
`GET /v1/sessions/{session_id}/artifacts/{artifact_id}/content`. The token is scoped
to tenant, session, artifact and worker incarnation. Content uses bounded worker
chunks, fixed attachment headers and `Cache-Control: no-store`. The final chunk
is withheld until size and checksum verification complete. Keep token headers out
of proxy logs; the token is never put in a URL. Interrupted streams require a new
token. Gateway restart invalidates outstanding tokens.


Viewer control transitions are committed to the private worker journal configured
by `BROWSERD_CONTROL_EVENT_JOURNAL_FILE` before a grant becomes visible. The gateway
relays pending records on startup and during health reconciliation, and acknowledges
only after durable projection. Terminal-action and viewer-control projections use
independent persistent sequence namespaces. The journal permits at most 1,024
pending transitions, 65,536 lifetime session namespaces and an 8 MiB snapshot;
capacity or persistence failure blocks new transitions. A failed release keeps
agent dispatch blocked until input cleanup and the release record both succeed.
Preserve this journal across worker restarts; deleting it resets source sequence
history and is not a supported recovery procedure. New production transitions use
the notification batch protocol below. Existing legacy pending records keep their
original projection and acknowledgement protocol.

## Durable events and webhooks

Polling through `GET /v1/events` remains available when webhook delivery is
unconfigured. Event objects carry a stable `event_id`, dotted `kind`, original
`created_at`, resource type/id, aggregate revision, parent session ID where needed,
and a finite state summary. The initial kinds are `operation.state_changed`,
`session.lifecycle_changed`, `session.execution_changed`, `action.state_changed`,
`action.approval_required`, `approval.decided`, `browser.control.changed`,
`download.completed`, and `artifact.state_changed`. Existing legacy records retain
their available metadata. A retention gap requires reconciliation through the
resource's normal polling API.

One webhook endpoint can be registered per tenant. Use `webhooks:write` for
`PUT`/`DELETE /v1/webhook-endpoint` and `POST /v1/webhook-endpoint/resume`, and
`webhooks:read` for `GET /v1/webhook-endpoint`. Mutations require one UUID
`Idempotency-Key` header. Initial registration uses this body:

```json
{"url":"https://receiver.example/events","expected_revision":null}
```

Updates and deletion require the current `expected_revision`. A successful PUT
returns the signing key ID and a 32-byte signing secret encoded as unpadded
base64url. Retrying the same principal/idempotency/body binding recovers that exact
committed secret; a conflicting binding is rejected. GET, DELETE and resume return
endpoint metadata. All successful endpoint responses use `Cache-Control: no-store`.

Configure the gateway with `BROWSERD_WEBHOOK_SIGNING_KEY_FILE` to enable management
and delivery. It must name an absolute, owned, single-link regular file with mode
`0400` or `0600` in an owned private `0700` directory. Its JSON format is:

```json
{"schema_version":1,"active_master_version_id":"v1","keys":[{"master_version_id":"v1","key_base64":"<standard-base64-encoded-32-byte-master>"}]}
```

The loader accepts at most eight master versions. Endpoint records contain only
version/key references; the gateway derives a tenant-specific secret from the
referenced master and key ID. Keep every referenced master version across gateway
restarts. Loading a new active version changes subsequent registration/rotation;
existing endpoints keep their persisted version. A missing referenced master
blocks delivery until its key or a valid endpoint rotation is available.

Webhook bodies use the common event object. The signature headers are
`Browserd-Webhook-Timestamp` (decimal UTC seconds), `Browserd-Webhook-Signature`
(`v1=` plus hexadecimal HMAC-SHA256), `Browserd-Webhook-Event-Id`, and
`Browserd-Webhook-Key-Id`. The signed bytes are the decimal timestamp, one `.`,
and the exact raw JSON body. Verify with the registered secret, require a timestamp
within five minutes of the receiver's clock, and deduplicate the signed body's
event ID. The exported `verify_webhook_signature` helper verifies the raw bytes
and timestamp. Return a 2xx response after accepting the event durably.

Delivery runs independently of request polling and worker recovery. It admits at
most four concurrent sends, with a five-second total DNS/HTTPS budget and a bounded
response body. Each attempt rechecks all DNS answers against its independent
public-address policy, pins the inspected numeric destination, and retains the
original HTTPS host for Host/SNI. Ambient proxies and redirects are disabled.
The webhook IPv6 policy allows ordinary native global unicast and conservatively
excludes translation, protocol-assignment and documentation ranges. Browser egress
configuration cannot relax it.

HTTP 408/425/429 and 5xx responses retry with backoff; permanent failures suspend
the endpoint. Uncertain sends retain the same immutable event body and event ID
for retry with a fresh attempt identity and signing timestamp. A lease/revision
CAS makes stale completion unable to advance a replaced endpoint. Pending bodies
survive endpoint deletion, gateway restart and event pruning. Successful delivery
starts a fixed 24-hour acknowledgement/payload retention window.

Resume uses `{"expected_revision":N,"mode":{"type":"continue"}}` for a normal
suspension. GET reports an observed `gap_observation` if outbox retention overtakes
the endpoint cursor. Explicitly accepting that observed gap uses:

```json
{"expected_revision":7,"mode":{"type":"accept_gap_to_tail","expected_pruned_through":12,"expected_tail":19}}
```

Worker producers persist state and immutable notification descriptors together.
Action WALs record approval identity before the approval-required transition;
terminal custody and notification acknowledgements are separate GC obligations.
Artifact publication emits available and completed-download descriptors as one
batch after a clean scan. Rejection/quarantine records contain metadata only by
default; optional private quarantine retention is described below.
Compaction and confirmed byte deletion preserve pending notifications and source
sequence history. Session lifecycle/execution uses a private synced authority
snapshot, retaining capacity for terminal state changes before accepting work.
Its optional `BROWSERD_SESSION_EVENT_JOURNAL_FILE` defaults to the control journal
path with the extension `session-events.journal`.

The gateway scans original workers and event families on an independent bounded
loop. It imports one source's oldest whole batch and its permanent watermark in
one PostgreSQL transaction before acknowledging the exact source digest. Event
retention starts at import while public event time preserves the original
observation. The latest 64 source receipts survive event pruning; older
unverifiable retries fail closed. Lifetime source quotas and sequence history
remain charged after event retention. Preserve the private source journals and
PostgreSQL watermark tables across restarts. Deploy gateway and worker together
for worker RPC protocol 33; these local implementation checks are separate from
production sandbox qualification.

## Private quarantine retention

Nonclean uploads and browser downloads are rejected. By default their bytes are
not retained. To enable bounded private retention, configure an authenticated
artifact scanner and set `BROWSERD_ARTIFACT_QUARANTINE_ENABLED=true` with all five
limits below:

| Environment variable | Constraint |
| --- | --- |
| `BROWSERD_ARTIFACT_QUARANTINE_RETENTION_MS` | Positive milliseconds, at most 86,400,000 |
| `BROWSERD_ARTIFACT_QUARANTINE_MAX_FILE_BYTES` | Positive, no greater than the general artifact file limit |
| `BROWSERD_ARTIFACT_QUARANTINE_MAX_WORKER_BYTES` | Positive, no greater than the general worker byte limit |
| `BROWSERD_ARTIFACT_QUARANTINE_MAX_SESSION_BYTES` | Positive, no greater than the general session byte limit |
| `BROWSERD_ARTIFACT_QUARANTINE_MAX_RETAINED_ARTIFACTS` | Positive, no greater than the general retained-artifact count |

Unset or `false` keeps retention disabled and requires all five limits to be
unset. Incomplete configuration, unsupported boolean values, excessive limits or
enabling retention without a scanner fail startup. Limits also intersect the
existing artifact and in-flight quotas.

Only a complete, authenticated, fresh scan bound to the exact size and SHA-256
can authorize retention of nonclean bytes. Early FOUND replies, protocol errors,
missing evidence and stale scans cannot do so. Retained bytes remain under private
`.quarantine` directories with owned `0700` directories and `0600` regular files.
They cannot be published as Available, read through public artifact APIs,
materialized into a browser, or cause a DownloadCompleted notification. The
durable notification contains Quarantined metadata only; the store still returns
rejection to the caller.

The original expiry and exact generation survive restart and compaction. Pending
notification acknowledgement pins deletion, so retention can extend beyond the
configured deadline until the exact source ACK arrives. Bounded maintenance then
deletes only the owned generation, persists positive deletion proof, and releases
its charge. Failed seals or registry writes also retain their private byte/count
charge until exact cleanup; uncertain deletion remains charged. Disabling retention
stops new private admissions while existing records continue recovery and cleanup. Preserve
the artifact root and its authority journals across restarts.

## Runtime safety switches

The global operator API uses `/v1/admin/safety-switches`. Its state and pending
audit exports are stored atomically in the configured Redis namespace, independently
of PostgreSQL and browser readiness. Authorization precedes request decoding:

| Method and path | Required scope | Purpose |
| --- | --- | --- |
| `GET /v1/admin/safety-switches` | `admin:safety:read` | Read the current namespace, snapshot and digest |
| `POST /v1/admin/safety-switches/initialize` | `admin:safety:write` | Explicitly initialize an absent authority |
| `PATCH /v1/admin/safety-switches` | `admin:safety:write` | Apply one versioned mutation |
| `GET /v1/admin/safety-switches/audits` | `admin:safety:read` | Export up to 32 oldest pending audit intents and exact ACK tokens |
| `POST /v1/admin/safety-switches/audit-ack` | `admin:safety:write` | Acknowledge the exact oldest exported intent |

These scopes grant global operator authority. The authenticated tenant and
principal bind each receipt and audit; they do not restrict a switch to one tenant.
Initialization and mutation require exactly one canonical, nonnil UUID
`Idempotency-Key` header and a nonempty `reason` of at most 2,048 UTF-8 bytes without
control characters. Use a fresh UUID for each new command, retaining the original
key and body when recovering an uncertain response.

An absent authority is never initialized by a read, connection or daemon restart.
Explicit initialization accepts:

```json
{"reason":"Initialize conservative runtime safety controls"}
```

It atomically creates a stable namespace UUID, version 0 snapshot, initialization
receipt and audit sequence 1. Defaults require dedicated processes, one context
per shard and at most 32 targets per session; evaluate is disabled. Existing
immutable policy, approval and deployment qualification remain required. A fresh
Initialize on an existing authority is rejected; an exact retry returns its
original receipt.

Read the current snapshot version before PATCH. For example, disable downloads:

```json
{"expected_version":0,"mutation":{"type":"disable_downloads","value":true},"reason":"Pause autonomous downloads during incident response"}
```

Mutations use the strict adjacent-tagged `type`/`value` form with `snake_case`
variant names. Boolean switches are `disable_evaluate`, `disable_viewer_control`,
`disable_downloads` and `disable_checkpoint`. Integer switches are
`set_max_contexts_per_shard` (1–8) and `set_max_targets_per_session` (1–128).
`set_force_dedicated_process` takes a boolean; enabling it also lowers density to
one. `force_dedicated_process` is the equivalent unit mutation, with no `value`.
Raising density requires the force flag to be false and remains bounded by the
worker's immutable qualification and launch policy. Runtime changes never mint
shared-context qualification; `set_shared_admission` is rejected.

The remaining finite mutations accept object values:

```json
{"type":"set_denied_domain","value":{"domain":"example.com","denied":true}}
```

```json
{"type":"set_denied_ip","value":{"ip":"203.0.113.7","denied":true}}
```

```json
{"type":"set_chromium_build_disabled","value":{"digest":"<64-hex-binary-digest>","disabled":true}}
```

```json
{"type":"set_stopped_network_class","value":{"network_class":"public","stopped":true}}
```

Domain denies cover the base domain and subdomains. IP denies normalize mapped
IPv4 addresses and check every DNS answer before inspected connect. Build denies
use the worker's trusted actual Chromium digest. Network-class stops prevent new
sessions for the exact class. Every successful mutation increments the permanent
version, including a semantic no-op.

Accepted create requests retain their original isolation/options/hash across retries.
New fleet admission selects the current effective profile and its exact resource
debit separately. Existing reservations retain that immutable profile and debit
under relaxation; tightening beyond it rejects before effects. Exact completed
receipt recovery remains available after policy changes.

Initialization and PATCH responses contain
`data: {"receipt": ..., "status":"persisted", "application":"pending_observation"}`.
This confirms the original command, snapshot digest and audit intent were committed;
it does not claim every daemon has observed the version. GET reads current authority
truth. An exact retry recovers the historical receipt even at capacity; changing the
canonical request under the same retained principal/key binding rejects the request.
A stale `expected_version` is rejected, so an expired receipt's original command
cannot apply again.

Audit export returns `data.items`, each containing `event` and `ack`. Durably accept
the exported event in the operator's audit sink before sending that exact `ack`
object as the `/audit-ack` request body. ACKs advance only the oldest intent; a
duplicate latest exact ACK succeeds, while altered or out-of-order ACKs fail.
No background task automatically acknowledges unexported audit. Pending intents
never expire. Exact command receipts remain for at least 24 hours after their audit
ACK, then may be pruned; clients use a fresh key after that window. Audit and receipt
quotas reject further changes before altering the snapshot. Cleanup preserves the
namespace, current snapshot, permanent version and audit watermark.

Gateway, worker and egressd must use the same `BROWSERD_REDIS_URL` and
`BROWSERD_REDIS_PREFIX`. Worker and egressd independently poll once per second and
require a validated snapshot fresh for at most 30 seconds using local monotonic
time. A successful same-version, same-digest refresh extends freshness without
reviving a cancelled generation. Transient read failure does not extend freshness;
missing authority, rollback, equivocation or uncertain local persistence closes
admission immediately. Staleness denies new effect starts; egress DNS, connect and
live streams also observe generation cancellation and the freshness deadline.
An already admitted browser effect may finish according to its existing ownership
and approval contract. Cleanup, release and observation remain available.

Each observer fsyncs a private namespace/version/digest pin before publishing fresh
state. Worker defaults to `BROWSERD_CONTROL_EVENT_JOURNAL_FILE` with extension
`safety-state`; egressd uses `BROWSER_EGRESS_DAEMON_EPOCH_STATE` with that extension.
Optional `BROWSERD_SAFETY_STATE_FILE` overrides the path **per service**. Use distinct
absolute files in service-owned `0700` directories, with private regular-file and
single-link ownership; do not set one common override for both daemons. Retain pins
and their lock files across restarts and rollback. Reopening starts unavailable
until authority verification. Never delete pins or the Redis authority to recover:
an explicit new namespace after Redis loss cannot silently reset previously pinned
workers or egress daemons. Recovery requires a coordinated operator decision.

F21 local validation passed 1,936 tests across 11 packages, with 32 explicit
external-prerequisite tests ignored; workspace formatting and all-target Clippy
with warnings denied also passed. Actual Redis/PostgreSQL fixtures and production
Unix RPC bootstrap are included. The recorded gate exited 0 at
`~/logs/browserd-runtime-safety-quality-0b5c434d7106.log`. This does not initialize
operator Redis state, deploy infrastructure or establish Chromium/kernel/soak
qualification.
