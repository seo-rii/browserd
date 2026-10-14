//! Actual production-owner behavior, witnessed on the claimed sandbox CDP pipes.
//!
//! These probes never launch a functional test browser or manufacture a route or
//! approval. The shared harness owns the approved factory, router, artifact store,
//! bounded passive pipe trace, and exact sandbox cleanup.
use super::control::{ProbeWorker, open_worker};
use super::rpc::{TraceDirection, TraceEntry};
use super::{Harness, OwnedSession, ProbeError, ProbeResult};
use browserd_artifacts::{ArtifactContentSource, ArtifactKey, ArtifactState};
use browserd_core::{ArtifactId, ShardFence, TenantId};
use browserd_features::CaptureCommand;
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActionExecutionResult, ArtifactScanVerdict, AuthenticatedPeer, ChromiumDriver,
    CreateSessionCommand, DependencyError, GeneratedArtifactRequest, MAX_VIEWER_JPEG_BYTES,
    SandboxClient, SystemWorkerClock, WorkerClock, WorkerSessionOptionsV1,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::time::{Duration, Instant};

const DOWNLOAD_CANARY: &[u8] = b"browserd-production-kernel-download\n";
const MAX_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PDF_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRACE_TARGETS: usize = 4096;
const TARGET_RESUME_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);

type Probe = fn(&Harness) -> Result<Value, ProbeError>;

pub(super) fn run_behavior_probes(harness: &Harness) -> BTreeMap<String, ProbeResult> {
    let probes: [(&str, Probe); 8] = [
        ("context_create_dispose", context_create_dispose),
        ("target_pause_resume", target_pause_resume),
        ("context_ownership", context_ownership),
        ("emulation", emulation),
        ("downloads", downloads),
        ("pdf_streaming", pdf_streaming),
        ("screencast_ack", screencast_ack),
        ("orphan_targets_zero", orphan_targets_zero),
    ];
    probes
        .into_iter()
        .map(|(name, probe)| {
            let result = if Instant::now() >= harness.deadline {
                Err(ProbeError::failed("browser probe run deadline reached"))
            } else {
                probe(harness)
            };
            (
                name.to_owned(),
                match result {
                    Ok(observations) => ProbeResult::passed(observations),
                    Err(error) => ProbeResult::failed(error),
                },
            )
        })
        .collect()
}

fn require(condition: bool, message: &str) -> Result<(), ProbeError> {
    if condition {
        Ok(())
    } else {
        Err(ProbeError::failed(message))
    }
}

fn same_pipe(a: &TraceEntry, b: &TraceEntry) -> bool {
    a.shard == b.shard && a.session_id == b.session_id
}

struct Exchange<'a> {
    request: &'a TraceEntry,
    reply: &'a TraceEntry,
}

fn successful<'a>(rows: &'a [TraceEntry], method: &str, shard: &ShardFence) -> Vec<Exchange<'a>> {
    rows.iter()
        .filter(|row| {
            matches!(row.direction, TraceDirection::Command)
                && row.shard == *shard
                && row.method.as_deref() == Some(method)
        })
        .filter_map(|request| {
            let id = request.id?;
            rows.iter()
                .find(|reply| {
                    matches!(reply.direction, TraceDirection::Reply)
                        && reply.id == Some(id)
                        && same_pipe(request, reply)
                        && reply.sequence > request.sequence
                        && reply.summary.get("success") == Some(&Value::Bool(true))
                        && reply.summary.get("result").is_some_and(Value::is_object)
                        && reply.summary.get("error").is_none()
                })
                .map(|reply| Exchange { request, reply })
        })
        .collect()
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, ProbeError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .ok_or_else(|| {
            ProbeError::failed("required bounded production protocol identifier is absent")
        })
}

fn context_id(rows: &[TraceEntry], shard: &ShardFence) -> Result<String, ProbeError> {
    let created = successful(rows, "Target.createBrowserContext", shard);
    require(
        created.len() == 1,
        "probe shard did not create exactly one owned browser context",
    )?;
    Ok(text(&created[0].reply.summary, "/result/browserContextId")?.to_owned())
}

fn target_absence(
    rows: &[TraceEntry],
    shard: &ShardFence,
    context: &str,
    global: bool,
) -> Result<Value, ProbeError> {
    let disposed = successful(rows, "Target.disposeBrowserContext", shard)
        .into_iter()
        .find(|exchange| {
            exchange
                .request
                .summary
                .pointer("/params/browserContextId")
                .and_then(Value::as_str)
                == Some(context)
        })
        .ok_or_else(|| {
            ProbeError::failed("exact context disposal has no successful production reply")
        })?;
    let snapshot = successful(rows, "Target.getTargets", shard)
        .into_iter()
        .rfind(|exchange| exchange.request.sequence > disposed.reply.sequence)
        .ok_or_else(|| {
            ProbeError::failed("no real target absence snapshot followed context disposal")
        })?;
    let targets = snapshot
        .reply
        .summary
        .pointer("/result/targetInfos")
        .and_then(Value::as_array)
        .ok_or_else(|| ProbeError::failed("production target snapshot is absent"))?;
    require(
        targets.len() <= MAX_TRACE_TARGETS,
        "production target snapshot exceeded its bound",
    )?;
    let owned = targets
        .iter()
        .filter(|target| target.get("browserContextId").and_then(Value::as_str) == Some(context))
        .count();
    require(
        owned == 0,
        "owned context still has real browser targets after disposal",
    )?;
    let context_snapshot = successful(rows, "Target.getBrowserContexts", shard)
        .into_iter()
        .rfind(|exchange| exchange.request.sequence > snapshot.reply.sequence)
        .ok_or_else(|| {
            ProbeError::failed("no real browser-context absence snapshot followed target disposal")
        })?;
    let contexts = context_snapshot
        .reply
        .summary
        .pointer("/result/browserContextIds")
        .and_then(Value::as_array)
        .ok_or_else(|| ProbeError::failed("production browser-context snapshot is absent"))?;
    require(
        contexts.len() <= MAX_TRACE_TARGETS
            && contexts
                .iter()
                .all(|id| id.as_str().is_some_and(|id| id != context)),
        "disposed context remains present or its real browser-context snapshot is malformed",
    )?;
    let browser_targets = targets
        .iter()
        .filter(|target| target.get("type").and_then(Value::as_str) != Some("browser"))
        .count();
    if global {
        require(
            browser_targets == 0 && contexts.is_empty(),
            "sandbox browser retains orphan targets or browser contexts after disposal",
        )?;
    }
    Ok(
        json!({"context_dispose_reply_sequence":disposed.reply.sequence,
        "absence_snapshot_reply_sequence":snapshot.reply.sequence,"context_snapshot_reply_sequence":context_snapshot.reply.sequence,
        "owned_context_targets":owned,"remaining_browser_contexts":contexts.len(),
        "remaining_non_browser_targets":browser_targets,"snapshot_target_count":targets.len()}),
    )
}

fn with_session(
    harness: &Harness,
    options: Option<WorkerSessionOptionsV1>,
    effect: impl FnOnce(&OwnedSession) -> Result<Value, ProbeError>,
) -> Result<Value, ProbeError> {
    let session = harness.open_session(options)?;
    let observed = effect(&session);
    let cleanup = harness.close_session(&session);
    match (observed, cleanup) {
        (Ok(mut observed), Ok(cleanup)) => {
            let object = observed
                .as_object_mut()
                .ok_or_else(|| ProbeError::failed("invalid bounded probe observations"))?;
            object.insert("cleanup".to_owned(), cleanup);
            Ok(observed)
        }
        (_, Err(error)) | (Err(error), _) => Err(error),
    }
}

fn with_worker_session(
    harness: &Harness,
    effect: impl FnOnce(&OwnedSession, &ProbeWorker, &AuthenticatedPeer) -> Result<Value, ProbeError>,
) -> Result<Value, ProbeError> {
    let state = harness
        .config
        .worker
        .state_root
        .join(&harness.binding.run_id)
        .join("downloads-control");
    let (worker, peer) = open_worker(harness, &state)?;
    let tenant = TenantId::new();
    let mut options = harness.default_options()?;
    options.feature_profile = "standard".to_owned();
    let request =
        json!({"tenant_id":tenant,"options":options,"placement_version":1,"session_incarnation":1});
    let encoded = serde_json::to_vec(&request)
        .map_err(|_| ProbeError::failed("worker download create request encoding failed"))?;
    let created = worker
        .create_session_with_options(
            &peer,
            CreateSessionCommand {
                tenant_id: tenant.clone(),
                idempotency_key: format!("kernel-download-{}", harness.binding.run_id),
                canonical_request_hash: Sha256::digest(&encoded).into(),
                placement_version: 1,
                session_incarnation: 1,
            },
            &options,
            SystemWorkerClock
                .now()
                .map_err(|_| ProbeError::failed("worker download creation clock unavailable"))?,
        )
        .map_err(|_| ProbeError::failed("actual worker download session creation failed"))?;
    let session = match harness.adopt_worker_session(tenant, &created) {
        Ok(session) => session,
        Err(error) => {
            if let Ok(now) = SystemWorkerClock.now() {
                let _ = worker.close_session(&peer, &created.session_id, &created.fence, now);
            }
            return Err(error);
        }
    };
    let observed = effect(&session, worker.as_ref(), &peer);
    let cleanup = SystemWorkerClock
        .now()
        .map_err(|_| ProbeError::failed("worker download cleanup clock unavailable"))
        .and_then(|now| {
            worker
                .close_session(&peer, &session.session, &session.fence, now)
                .map_err(|_| {
                    ProbeError::failed("actual worker download session cleanup incomplete")
                })?;
            harness.finish_worker_session(&session)
        });
    match (observed, cleanup) {
        (Ok(mut observed), Ok(cleanup)) => {
            let object = observed
                .as_object_mut()
                .ok_or_else(|| ProbeError::failed("worker download observations invalid"))?;
            object.insert("cleanup".to_owned(), cleanup);
            Ok(observed)
        }
        (_, Err(error)) | (Err(error), _) => Err(error),
    }
}

fn navigate(harness: &Harness, session: &OwnedSession, kind: &str) -> Result<(), ProbeError> {
    let url = harness.fixture_url(kind)?;
    session.action(
        json!({"type":"navigate","url":url,"wait_until":"load"}),
        harness.deadline,
    )?;
    Ok(())
}

fn node(session: &OwnedSession, selector: &str, deadline: Instant) -> Result<String, ProbeError> {
    let result = session.action(json!({"type":"query_all","selector":selector}), deadline)?;
    let nodes = result
        .get("node_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| ProbeError::failed("fixture node lookup returned no owned handles"))?;
    require(
        nodes.len() == 1,
        "fixture selector did not resolve to exactly one owned node",
    )?;
    nodes[0]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .map(str::to_owned)
        .ok_or_else(|| ProbeError::failed("fixture node reference is malformed"))
}

fn context_create_dispose(harness: &Harness) -> Result<Value, ProbeError> {
    let mark = harness.trace.mark();
    with_session(harness, None, |session| {
        let context = context_id(&harness.trace.since(mark)?, &session.shard)?;
        let absence = dispose_context_observed(harness, session, mark, &context, false)?;
        Ok(json!({"created_contexts":1,"context":context,"shard":session.shard,"absence":absence}))
    })
}

fn dispose_context_observed(
    harness: &Harness,
    session: &OwnedSession,
    mark: u64,
    context: &str,
    global: bool,
) -> Result<Value, ProbeError> {
    // Forced shard termination is a cleanup proof, not a live context-disposal reply.
    // Exercise the same actor detach and positive absence checks as production qualification
    // while the exact browser remains alive; with_session still owns final cleanup.
    harness
        .router
        .dispose_context_verified_until(
            &session.tenant,
            &session.session,
            &session.fence,
            harness.deadline,
        )
        .map_err(|_| ProbeError::failed("actual production context disposal did not verify"))?;
    target_absence(&harness.trace.since(mark)?, &session.shard, context, global)
}

fn target_pause_resume(harness: &Harness) -> Result<Value, ProbeError> {
    let mark = harness.trace.mark();
    with_session(harness, Some(harness.default_options()?), |session| {
        navigate(harness, session, "target_pause_resume")?;
        let context = context_id(&harness.trace.since(mark)?, &session.shard)?;
        let deadline = (Instant::now() + TARGET_RESUME_OBSERVATION_TIMEOUT).min(harness.deadline);
        wait_for_paused_target_proof(
            || harness.trace.since(mark),
            &session.shard,
            &context,
            deadline,
        )
    })
}

fn wait_for_paused_target_proof(
    mut observe: impl FnMut() -> Result<Vec<TraceEntry>, ProbeError>,
    shard: &ShardFence,
    context: &str,
    deadline: Instant,
) -> Result<Value, ProbeError> {
    loop {
        // Page load can complete while an observed iframe or worker is still paused in its
        // real production bootstrap. Wait only for passive, successful reply evidence.
        let rows = observe()?;
        match paused_target_proof(&rows, shard, context) {
            Ok(proof) => {
                require(
                    Instant::now() < deadline,
                    "actual target resume observation deadline elapsed",
                )?;
                return Ok(proof);
            }
            Err(error) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(error);
                }
                std::thread::sleep(remaining.min(Duration::from_millis(25)));
            }
        }
    }
}

fn owned_attachments<'a>(
    rows: &'a [TraceEntry],
    shard: &ShardFence,
    context: &str,
) -> Result<Vec<&'a TraceEntry>, ProbeError> {
    let mut sessions = BTreeSet::new();
    let mut owned = Vec::new();
    for attached in rows.iter().filter(|row| {
        row.shard == *shard
            && matches!(row.direction, TraceDirection::Event)
            && row.method.as_deref() == Some("Target.attachedToTarget")
    }) {
        let declared = attached
            .summary
            .pointer("/params/targetInfo/browserContextId")
            .and_then(Value::as_str);
        let inherited = attached
            .session_id
            .as_ref()
            .is_some_and(|parent| sessions.contains(parent));
        if declared == Some(context) || (declared.is_none() && inherited) {
            sessions.insert(text(&attached.summary, "/params/sessionId")?.to_owned());
            owned.push(attached);
            require(owned.len() <= 32, "probe created too many managed targets")?;
        } else if inherited {
            return Err(ProbeError::failed(
                "owned parent attached a target declaring a foreign browser context",
            ));
        }
    }
    Ok(owned)
}

fn paused_target_proof(
    rows: &[TraceEntry],
    shard: &ShardFence,
    context: &str,
) -> Result<Value, ProbeError> {
    let mut targets = Vec::new();
    for attached in owned_attachments(rows, shard, context)? {
        require(
            attached.summary.pointer("/params/waitingForDebugger") == Some(&Value::Bool(true)),
            "owned target attached without its real debugger pause",
        )?;
        let target_session = text(&attached.summary, "/params/sessionId")?;
        let target = text(&attached.summary, "/params/targetInfo/targetId")?;
        let kind = text(&attached.summary, "/params/targetInfo/type")?;
        let resume = successful(rows, "Runtime.runIfWaitingForDebugger", shard)
            .into_iter()
            .find(|exchange| {
                exchange.request.session_id.as_deref() == Some(target_session)
                    && exchange.request.sequence > attached.sequence
            })
            .ok_or_else(|| {
                ProbeError::failed("paused owned target has no successful real resume")
            })?;
        let mut required = vec!["Target.setAutoAttach", "Network.enable"];
        if matches!(kind, "page" | "iframe") {
            required.extend([
                "Runtime.enable",
                "Page.enable",
                "Page.setInterceptFileChooserDialog",
            ]);
            required.push("Network.setUserAgentOverride");
            if kind == "page" {
                required.push("Emulation.setDeviceMetricsOverride");
            }
        } else {
            // Approved native workers inherit immutable process defaults and intentionally
            // acquire no page Runtime observer or inspector emulation lease.
            require(
                matches!(kind, "worker" | "shared_worker" | "service_worker"),
                "owned target kind is outside the production bootstrap contract",
            )?;
        }
        let mut stages = Vec::new();
        for method in required {
            let stage = successful(rows, method, shard)
                .into_iter()
                .find(|exchange| {
                    exchange.request.session_id.as_deref() == Some(target_session)
                        && exchange.request.sequence > attached.sequence
                        && exchange.reply.sequence < resume.request.sequence
                })
                .ok_or_else(|| {
                    ProbeError::failed("target resumed before a required bootstrap success reply")
                })?;
            if method == "Target.setAutoAttach" {
                for key in ["autoAttach", "waitForDebuggerOnStart", "flatten"] {
                    require(
                        stage.request.summary.pointer(&format!("/params/{key}"))
                            == Some(&Value::Bool(true)),
                        "recursive auto-attach did not preserve its production debugger pause",
                    )?;
                }
            }
            if method == "Page.setInterceptFileChooserDialog" {
                require(
                    stage.request.summary.pointer("/params/enabled") == Some(&Value::Bool(true)),
                    "file chooser interception was not installed before target resume",
                )?;
            }
            stages.push(json!({"method":method,"reply_sequence":stage.reply.sequence}));
        }
        targets.push(json!({"target":target,"kind":kind,"attached_sequence":attached.sequence,
                "bootstrap":stages,"resume_request_sequence":resume.request.sequence,"resume_reply_sequence":resume.reply.sequence}));
    }
    require(
        !targets.is_empty(),
        "probe observed no paused owned targets on actual sandbox pipes",
    )?;
    Ok(json!({"paused_and_resumed_targets":targets.len(),"targets":targets,"context":context}))
}

fn context_ownership(harness: &Harness) -> Result<Value, ProbeError> {
    with_session(harness, None, |first| {
        let second_observations = with_session(harness, None, |second| {
            require(
                first.session != second.session && first.page != second.page,
                "ownership probe did not create distinct real sessions",
            )?;
            let mark = harness.trace.mark();
            let foreign_page = second.driver.execute_action_until(
                &second.session,
                Some(&first.page),
                &serde_json::to_vec(&json!({"type":"get_title"}))
                    .map_err(|_| ProbeError::failed("fixed action encoding failed"))?,
                harness.deadline,
            );
            require(
                matches!(foreign_page, ActionExecutionResult::FailedKnown(_)),
                "cross-session page was not rejected before its effect",
            )?;
            let foreign_tenant =
                first
                    .driver
                    .create_context_owned(&TenantId::new(), &first.session, &first.fence);
            require(
                matches!(foreign_tenant, Err(DependencyError::Rejected)),
                "foreign tenant did not receive known rejection for an existing owned browser context",
            )?;
            let mut rejected_fences = 0usize;
            for (epoch, placement, incarnation) in [
                (
                    first.fence.worker_epoch().checked_add(1),
                    Some(first.fence.placement_version()),
                    Some(first.fence.session_incarnation()),
                ),
                (
                    Some(first.fence.worker_epoch()),
                    first.fence.placement_version().checked_add(1),
                    Some(first.fence.session_incarnation()),
                ),
                (
                    Some(first.fence.worker_epoch()),
                    Some(first.fence.placement_version()),
                    first.fence.session_incarnation().checked_add(1),
                ),
            ] {
                let (Some(epoch), Some(placement), Some(incarnation)) =
                    (epoch, placement, incarnation)
                else {
                    return Err(ProbeError::failed(
                        "fence counter cannot be safely perturbed",
                    ));
                };
                let fence = OwnershipFence::new(
                    first.fence.worker_id().clone(),
                    epoch,
                    placement,
                    incarnation,
                );
                require(
                    matches!(
                        first.driver.close_context_fenced(&first.session, &fence),
                        Err(DependencyError::Rejected)
                    ),
                    "stale full fence did not receive known rejection before context disposal",
                )?;
                rejected_fences += 1;
            }
            let rows = harness.trace.since(mark)?;
            require(
                !rows.iter().any(|row| {
                    matches!(row.direction, TraceDirection::Command)
                        && matches!(
                            row.method.as_deref(),
                            Some(
                                "Target.createBrowserContext"
                                    | "Target.disposeBrowserContext"
                                    | "Target.closeTarget"
                                    | "Runtime.callFunctionOn"
                            )
                        )
                }),
                "rejected ownership attempts submitted browser effects",
            )?;
            first.action(json!({"type":"get_title"}), harness.deadline)?;
            second.action(json!({"type":"get_title"}), harness.deadline)?;
            Ok(
                json!({"real_sessions":2,"cross_session_page_rejected":true,"foreign_tenant_rejected":true,
                "full_fence_components_rejected":rejected_fences,"live_sessions_remain_usable":true}),
            )
        })?;
        Ok(json!({"second_session":second_observations,"first_session_remains_usable":true}))
    })
}

fn emulation(harness: &Harness) -> Result<Value, ProbeError> {
    let options = harness.default_options()?;
    let expected = options.clone();
    with_session(harness, Some(options), |session| {
        navigate(harness, session, "emulation")?;
        let node = node(session, "#emulation", harness.deadline)?;
        let value = session.action(json!({"type":"get_text","node_ref":node}), harness.deadline)?;
        let encoded = value
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| text.len() <= 4096)
            .ok_or_else(|| {
                ProbeError::failed("first-script emulation evidence is absent or unbounded")
            })?;
        let observed: Value = serde_json::from_str(encoded)
            .map_err(|_| ProbeError::failed("first-script emulation evidence is not JSON"))?;
        require(
            observed.get("width").and_then(Value::as_u64)
                == Some(u64::from(expected.viewport.width))
                && observed.get("height").and_then(Value::as_u64)
                    == Some(u64::from(expected.viewport.height))
                && observed.get("device_scale_factor").and_then(Value::as_u64)
                    == Some(u64::from(expected.viewport.device_scale_factor))
                && observed.get("locale").and_then(Value::as_str) == Some(expected.locale.as_str())
                && observed.get("intl_locale").and_then(Value::as_str)
                    == Some(expected.locale.as_str())
                && observed.get("number_locale").and_then(Value::as_str)
                    == Some(expected.locale.as_str())
                && observed.get("timezone").and_then(Value::as_str)
                    == Some(expected.timezone.as_str()),
            "native emulation was not effective when the fixture's first script ran",
        )?;
        let ua = observed
            .get("user_agent")
            .and_then(Value::as_str)
            .filter(|ua| !ua.is_empty() && ua.len() <= 512)
            .ok_or_else(|| ProbeError::failed("native user agent observation is absent"))?;
        if let Some(expected_ua) = &expected.user_agent {
            require(
                ua == expected_ua,
                "native user agent does not match the approved profile",
            )?;
        }
        let headers = harness.fixture.request_headers("emulation")?;
        require(
            !headers.is_empty(),
            "emulation fixture has no current-run HTTP request evidence",
        )?;
        for request in &headers {
            require(
                request.user_agent.as_deref() == Some(ua),
                "HTTP user agent differs from first-script approved emulation",
            )?;
            let language = request
                .accept_language
                .as_deref()
                .and_then(|value| value.split(',').next())
                .and_then(|value| value.split(';').next())
                .map(str::trim);
            require(
                language == Some(expected.locale.as_str()),
                "HTTP Accept-Language differs from approved native locale",
            )?;
        }
        Ok(
            json!({"first_script":observed,"http_requests":headers,"approved_options":{
            "width":expected.viewport.width,"height":expected.viewport.height,"device_scale_factor":expected.viewport.device_scale_factor,
            "locale":expected.locale,"timezone":expected.timezone,"user_agent":expected.user_agent}}),
        )
    })
}

fn wait_until(
    harness: &Harness,
    budget: Duration,
    mut poll: impl FnMut() -> Result<bool, ProbeError>,
) -> Result<(), ProbeError> {
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| ProbeError::failed("probe deadline overflow"))?
        .min(harness.deadline);
    loop {
        if Instant::now() >= deadline {
            return Err(ProbeError::failed(
                "bounded browser evidence deadline reached",
            ));
        }
        if poll()? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn downloads(harness: &Harness) -> Result<Value, ProbeError> {
    if !harness.downloads_enabled() {
        return Err(ProbeError::blocked(
            "approved authenticated scanner configuration is required for production browser downloads",
        ));
    }
    with_worker_session(harness, |session, worker, peer| {
        navigate(harness, session, "downloads")?;
        let button = node(session, "#download", harness.deadline)?;
        session.action(json!({"type":"click","node_ref":button}), harness.deadline)?;
        let mut completed = None;
        wait_until(harness, Duration::from_secs(20), || {
            let pending = session
                .driver
                .pending_browser_downloads(&session.session, &session.fence, 4)
                .map_err(|_| ProbeError::failed("actual owner download polling failed"))?;
            require(
                pending.len() <= 1,
                "fixture minted multiple browser downloads",
            )?;
            completed = pending.into_iter().next();
            Ok(completed.is_some())
        })?;
        let completion =
            completed.ok_or_else(|| ProbeError::failed("download completion disappeared"))?;
        require(
            completion.tenant_id == session.tenant
                && completion.session_id == session.session
                && completion.page_id == session.page
                && completion.fence == session.fence
                && completion.expected_size_bytes == DOWNLOAD_CANARY.len() as u64,
            "browser download receipt is not bound to the exact probe session and bytes",
        )?;
        require(
            session
                .driver
                .pending_browser_downloads(&session.session, &session.fence, 4)
                .map_err(|_| ProbeError::failed("stable download polling failed"))?
                == vec![completion.clone()],
            "repeated download poll changed the artifact identity",
        )?;
        let mut forged = completion.clone();
        forged.artifact_id = ArtifactId::new();
        require(
            session.driver.open_browser_download(&forged).is_err(),
            "forged download artifact identity opened scratch bytes",
        )?;
        let mut forged_fence = completion.clone();
        forged_fence.fence = OwnershipFence::new(
            session.fence.worker_id().clone(),
            session.fence.worker_epoch(),
            session.fence.placement_version(),
            session
                .fence
                .session_incarnation()
                .checked_add(1)
                .ok_or_else(|| ProbeError::failed("fence counter overflow"))?,
        );
        require(
            session.driver.open_browser_download(&forged_fence).is_err(),
            "foreign full fence opened scratch bytes",
        )?;
        require(
            matches!(
                session.driver.ack_browser_download(&forged),
                Err(DependencyError::Rejected)
            ) && matches!(
                session.driver.ack_browser_download(&forged_fence),
                Err(DependencyError::Rejected)
            ),
            "forged artifact or full fence did not receive known rejection before download ACK",
        )?;
        require(
            session
                .driver
                .pending_browser_downloads(&session.session, &session.fence, 4)
                .map_err(|_| ProbeError::failed("post-rejection download polling failed"))?
                == vec![completion.clone()],
            "rejected download ACK changed the real pending completion",
        )?;
        let file = session
            .driver
            .open_browser_download(&completion)
            .map_err(|_| ProbeError::failed("actual pinned scratch file could not open"))?;
        file.validate_unchanged()
            .map_err(|_| ProbeError::failed("scratch object changed before its read"))?;
        let mut bytes = Vec::new();
        file.file()
            .take(MAX_DOWNLOAD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ProbeError::failed("actual scratch file read failed"))?;
        file.validate_unchanged()
            .map_err(|_| ProbeError::failed("scratch object changed during its read"))?;
        require(
            bytes == DOWNLOAD_CANARY && file.size_bytes() == bytes.len() as u64,
            "actual downloaded scratch bytes differ from the private canary",
        )?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        drop(file);
        worker
            .heartbeat(
                peer,
                SystemWorkerClock
                    .now()
                    .map_err(|_| ProbeError::failed("worker download renewal clock unavailable"))?,
            )
            .map_err(|_| ProbeError::failed("actual worker download lease renewal failed"))?;
        require(
            worker
                .reconcile_browser_downloads(peer, &session.session, &session.fence)
                .map_err(|_| {
                    ProbeError::failed("actual scanner-backed browser download publication failed")
                })?
                == 1,
            "production reconciliation did not publish the one exact browser download",
        )?;
        let artifact = worker
            .get_artifact(
                peer,
                &session.session,
                &completion.artifact_id,
                &session.fence,
            )
            .map_err(|_| {
                ProbeError::failed("published browser download is absent from the actual worker")
            })?;
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        require(
            artifact.artifact_id == completion.artifact_id
                && artifact.state == ArtifactState::Available
                && artifact.source == ArtifactContentSource::BrowserDownload
                && artifact.origin == "browserd-worker-download"
                && artifact.size_bytes == bytes.len() as u64
                && artifact.checksum_sha256 == checksum
                && artifact
                    .object_generation
                    .as_bytes()
                    .iter()
                    .any(|byte| *byte != 0),
            "production download publication changed identity, bytes, source, or durable generation",
        )?;
        let key = ArtifactKey::new(
            session.tenant.clone(),
            session.session.clone(),
            completion.artifact_id.clone(),
        );
        let publication = worker
            .get_retained_artifact(
                peer,
                session.fence.worker_id(),
                session.fence.worker_epoch(),
                &key,
            )
            .map_err(|_| {
                ProbeError::failed("durable production download publication readback failed")
            })?;
        require(
            publication.key() == &key
                && publication.original_fence() == &session.fence
                && publication.state() == ArtifactState::Available
                && publication.scan_verdict() == Some(ArtifactScanVerdict::Clean)
                && publication.object_generation() == artifact.object_generation
                && publication.metadata().source() == ArtifactContentSource::BrowserDownload
                && publication.metadata().size_bytes() == artifact.size_bytes
                && publication.metadata().checksum().as_bytes() == &checksum,
            "durable browser download publication lost exact ownership or clean scan binding",
        )?;
        let scan = publication.scan_attestation().ok_or_else(|| {
            ProbeError::failed("actual browser download publication has no scan attestation")
        })?;
        scan.validate_for(
            &key,
            &session.fence,
            publication.metadata(),
            publication.object_generation(),
        )
        .and_then(|()| scan.validate_at(publication.published_at_unix_millis()))
        .map_err(|_| {
            ProbeError::failed("actual download scan attestation does not bind the published bytes")
        })?;
        let mut reader = worker
            .open_artifact(
                peer,
                &session.session,
                &completion.artifact_id,
                &session.fence,
                64 * 1024,
            )
            .map_err(|_| ProbeError::failed("actual stored browser download could not open"))?;
        let mut stored = Vec::new();
        while let Some(chunk) = reader
            .next_chunk()
            .map_err(|_| ProbeError::failed("actual stored browser download read failed"))?
        {
            require(
                chunk.len() <= 64 * 1024
                    && stored.len().saturating_add(chunk.len()) as u64 <= MAX_DOWNLOAD_BYTES,
                "actual stored browser download exceeded the bounded read",
            )?;
            stored.extend(chunk);
        }
        require(
            stored == bytes,
            "durable production browser download bytes differ from the exact scratch canary",
        )?;
        drop(reader);
        require(
            worker
                .reconcile_browser_downloads(peer, &session.session, &session.fence)
                .map_err(|_| {
                    ProbeError::failed("production download reconciliation retry failed")
                })?
                == 0,
            "production download reconciliation retry republished the completed download",
        )?;
        require(
            worker
                .get_artifact(
                    peer,
                    &session.session,
                    &completion.artifact_id,
                    &session.fence,
                )
                .map_err(|_| ProbeError::failed("published download identity vanished on retry"))?
                == artifact,
            "production download retry changed its published artifact identity or generation",
        )?;
        session
            .driver
            .ack_browser_download(&completion)
            .map_err(|_| ProbeError::failed("exact lost-ACK retry failed"))?;
        require(
            session
                .driver
                .pending_browser_downloads(&session.session, &session.fence, 4)
                .map_err(|_| ProbeError::failed("post-ACK polling failed"))?
                .is_empty(),
            "acknowledged download remains pending",
        )?;
        require(
            session.driver.open_browser_download(&completion).is_err(),
            "positive download ACK left its scratch object available",
        )?;
        Ok(
            json!({"artifact_id":completion.artifact_id,"bytes":bytes.len(),"sha256":digest,
            "stable_artifact_identity":true,"forged_artifact_and_fence_rejected":true,"exact_ack_retry":true,"scratch_unavailable_after_ack":true,
            "production_reconciliation_published":true,"available_artifact_readback":true,
            "object_generation":hex::encode(artifact.object_generation.as_bytes()),
            "scan_attestation":scan}),
        )
    })
}

fn pdf_streaming(harness: &Harness) -> Result<Value, ProbeError> {
    if !harness.privileged_enabled() {
        return Err(ProbeError::blocked(
            "explicit approved privileged capture capability is required for production PDF streaming",
        ));
    }
    let mark = harness.trace.mark();
    with_session(harness, Some(harness.default_options()?), |session| {
        navigate(harness, session, "pdf_streaming")?;
        let command = CaptureCommand::Pdf {
            options: Default::default(),
        };
        let request = GeneratedArtifactRequest::new(
            ArtifactKey::new(
                session.tenant.clone(),
                session.session.clone(),
                ArtifactId::new(),
            ),
            session.fence.clone(),
            "application/pdf",
            "production-kernel-probe",
            MAX_PDF_BYTES,
        )
        .map_err(|_| ProbeError::failed("bounded real PDF reservation rejected"))?;
        let sink: std::sync::Arc<dyn SandboxClient> = session.driver.clone();
        let mut captured = session
            .driver
            .execute_capture_until(
                &session.session,
                &session.page,
                command,
                request,
                sink,
                harness.deadline,
            )
            .map_err(|_| ProbeError::failed("actual production owner PDF capture failed"))?;
        let observed = (|| {
            let receipt = captured
                .receipt
                .as_ref()
                .ok_or_else(|| ProbeError::failed("PDF produced no actual artifact receipt"))?;
            let bytes = harness.read_generated(receipt)?;
            require(
                bytes.len() as u64 <= MAX_PDF_BYTES
                    && bytes.starts_with(b"%PDF-")
                    && bytes.windows(5).any(|window| window == b"%%EOF"),
                "actual PDF artifact is invalid or exceeds its reservation",
            )?;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            require(
                receipt.size_bytes() == bytes.len() as u64
                    && receipt.checksum().as_bytes() == &digest
                    && receipt.detected_content_type() == "application/pdf",
                "actual PDF receipt size/hash/content type mismatch",
            )?;
            let rows = harness.trace.since(mark)?;
            let stream = pdf_protocol_proof(&rows, &session.shard, &bytes)?;
            Ok(
                json!({"artifact_id":receipt.key().artifact_id(),"bytes":receipt.size_bytes(),
                "sha256":format!("{:x}",Sha256::digest(&bytes)),"stream":stream}),
            )
        })();
        let mut cleanup = captured.cleanup.take().ok_or_else(|| {
            ProbeError::failed("actual PDF artifact has no owned rollback handle")
        })?;
        harness
            .runtime
            .block_on(cleanup.abort())
            .map_err(|_| ProbeError::failed("actual PDF artifact rollback failed"))?;
        observed
    })
}

fn pdf_protocol_proof(
    rows: &[TraceEntry],
    shard: &ShardFence,
    stored_bytes: &[u8],
) -> Result<Value, ProbeError> {
    let expected_bytes = stored_bytes.len() as u64;
    require(
        expected_bytes > 0 && expected_bytes <= MAX_PDF_BYTES,
        "PDF receipt size exceeds the finite probe reservation",
    )?;
    let printed = successful(rows, "Page.printToPDF", shard)
        .into_iter()
        .next_back()
        .ok_or_else(|| ProbeError::failed("no successful actual printToPDF response"))?;
    require(
        printed
            .request
            .summary
            .pointer("/params/transferMode")
            .and_then(Value::as_str)
            == Some("ReturnAsStream"),
        "PDF capture did not request a production CDP stream",
    )?;
    let handle = text(&printed.reply.summary, "/result/stream")?;
    let reads: Vec<_> = successful(rows, "IO.read", shard)
        .into_iter()
        .filter(|read| {
            read.request.session_id == printed.request.session_id
                && read.request.sequence > printed.reply.sequence
                && read
                    .request
                    .summary
                    .pointer("/params/handle")
                    .and_then(Value::as_str)
                    == Some(handle)
        })
        .collect();
    require(
        !reads.is_empty() && reads.len() <= 4096,
        "PDF stream has no finite sequence of reads on the real owner pipes",
    )?;
    let mut streamed = 0u64;
    let mut eof_sequence = None;
    let mut previous_reply = printed.reply.sequence;
    for read in &reads {
        require(
            eof_sequence.is_none() && read.request.sequence > previous_reply,
            "PDF read continued after EOF or before the preceding stream reply",
        )?;
        let size = read
            .request
            .summary
            .pointer("/params/size")
            .and_then(Value::as_u64)
            .ok_or_else(|| ProbeError::failed("PDF stream read has no finite chunk request"))?;
        let actual = read
            .reply
            .summary
            .pointer("/result/data_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                ProbeError::failed("PDF passive trace has no actual decoded byte count")
            })?;
        require(
            size > 0 && size <= 64 * 1024 && actual <= size,
            "PDF stream exceeded its production chunk ceiling",
        )?;
        let begin = usize::try_from(streamed)
            .map_err(|_| ProbeError::failed("PDF stream offset exceeds addressable bounds"))?;
        streamed = streamed
            .checked_add(actual)
            .ok_or_else(|| ProbeError::failed("PDF stream byte count overflow"))?;
        require(
            streamed <= MAX_PDF_BYTES,
            "actual PDF stream exceeded its reservation",
        )?;
        let end = usize::try_from(streamed)
            .map_err(|_| ProbeError::failed("PDF stream offset exceeds addressable bounds"))?;
        let chunk = stored_bytes
            .get(begin..end)
            .ok_or_else(|| ProbeError::failed("PDF stream exceeds its actual stored artifact"))?;
        let digest = format!("{:x}", Sha256::digest(chunk));
        require(
            read.reply
                .summary
                .pointer("/result/data_sha256")
                .and_then(Value::as_str)
                == Some(digest.as_str()),
            "PDF decoded stream chunk digest differs from its actual stored artifact",
        )?;
        let eof = read
            .reply
            .summary
            .pointer("/result/eof")
            .and_then(Value::as_bool)
            .ok_or_else(|| ProbeError::failed("PDF stream EOF flag missing"))?;
        if eof {
            eof_sequence = Some(read.reply.sequence);
        }
        previous_reply = read.reply.sequence;
    }
    let eof =
        eof_sequence.ok_or_else(|| ProbeError::failed("actual PDF stream never returned EOF"))?;
    require(
        streamed == expected_bytes,
        "PDF IO stream bytes differ from the actual stored artifact",
    )?;
    let closed = successful(rows, "IO.close", shard)
        .into_iter()
        .find(|close| {
            close.request.session_id == printed.request.session_id
                && close.request.sequence > eof
                && close
                    .request
                    .summary
                    .pointer("/params/handle")
                    .and_then(Value::as_str)
                    == Some(handle)
        })
        .ok_or_else(|| {
            ProbeError::failed("exact PDF stream has no successful IO.close receipt after EOF")
        })?;
    Ok(
        json!({"stream_reads":reads.len(),"bytes":streamed,"eof_reply_sequence":eof,
        "close_reply_sequence":closed.reply.sequence,"max_chunk_bytes":64*1024}),
    )
}

fn screencast_ack(harness: &Harness) -> Result<Value, ProbeError> {
    with_session(harness, Some(harness.default_options()?), |session| {
        navigate(harness, session, "screencast_ack")?;
        let mark = harness.trace.mark();
        session
            .driver
            .viewer_start(&session.session, &session.page, &session.fence)
            .map_err(|_| ProbeError::failed("actual owner screencast start failed"))?;
        let observed = (|| {
            // Do not poll viewer_frame until three real frames have been ACKed.
            let mut acknowledged = Vec::new();
            wait_until(harness, Duration::from_secs(12), || {
                let rows = harness.trace.since(mark)?;
                acknowledged = screencast_receipts(&rows, &session.shard)?;
                let images: BTreeSet<_> = acknowledged
                    .iter()
                    .filter_map(|frame| frame.get("image_sha256").and_then(Value::as_str))
                    .collect();
                Ok(acknowledged.len() >= 3 && images.len() >= 2)
            })?;
            let frame = session
                .driver
                .viewer_frame(&session.session, &session.page, &session.fence)
                .map_err(|_| ProbeError::failed("actual latest screencast frame read failed"))?
                .ok_or_else(|| {
                    ProbeError::failed("ACKed real screencast supplied no observer frame")
                })?;
            require(
                frame.page_id == session.page
                    && frame.frame_id > 0
                    && frame.frame_transform_id > 0
                    && !frame.jpeg_base64.is_empty()
                    && frame.jpeg_base64.len() <= MAX_VIEWER_JPEG_BYTES.div_ceil(3) * 4,
                "actual screencast frame ownership or finite image bound is invalid",
            )?;
            let first_id = frame.frame_id;
            wait_until(harness, Duration::from_secs(8), || {
                let next = session
                    .driver
                    .viewer_frame(&session.session, &session.page, &session.fence)
                    .map_err(|_| ProbeError::failed("subsequent real viewer frame read failed"))?;
                Ok(next
                    .is_some_and(|next| next.page_id == session.page && next.frame_id > first_id))
            })?;
            Ok(
                json!({"real_frames_acked_without_client_polling":acknowledged.len(),"acks":acknowledged,
                "first_observed_frame_id":first_id,"subsequent_new_frame":true}),
            )
        })();
        session
            .driver
            .viewer_stop(&session.session, &session.page, &session.fence)
            .map_err(|_| ProbeError::failed("actual owner screencast stop failed"))?;
        observed
    })
}

fn screencast_receipts(rows: &[TraceEntry], shard: &ShardFence) -> Result<Vec<Value>, ProbeError> {
    let acknowledgements = successful(rows, "Page.screencastFrameAck", shard);
    let mut events = BTreeSet::new();
    let mut acknowledged_commands = BTreeSet::new();
    let mut found = Vec::new();
    for event in rows.iter().filter(|row| {
        row.shard == *shard
            && matches!(row.direction, TraceDirection::Event)
            && row.method.as_deref() == Some("Page.screencastFrame")
    }) {
        let id = event
            .summary
            .pointer("/params/sessionId")
            .and_then(Value::as_u64)
            .ok_or_else(|| ProbeError::failed("actual screencast frame identity is absent"))?;
        let bytes = event
            .summary
            .pointer("/params/data_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| ProbeError::failed("actual screencast image byte count is absent"))?;
        require(
            bytes > 0 && bytes <= MAX_VIEWER_JPEG_BYTES as u64,
            "actual screencast image exceeded its finite bound",
        )?;
        let image = text(&event.summary, "/params/data_sha256")?;
        require(
            image.len() == 64
                && image
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "actual screencast image has no valid bounded digest",
        )?;
        require(
            events.insert(event.sequence),
            "screencast proof duplicated an actual event sequence",
        )?;
        let Some(ack) = acknowledgements.iter().find(|ack| {
            same_pipe(event, ack.request)
                && ack.request.sequence > event.sequence
                && !acknowledged_commands
                    .contains(&(ack.request.session_id.clone(), ack.request.id))
                && ack
                    .request
                    .summary
                    .pointer("/params/sessionId")
                    .and_then(Value::as_u64)
                    == Some(id)
        }) else {
            continue;
        };
        // Chromium may reuse params.sessionId for every frame in one stream. The
        // distinct event and actual successful command/reply pair identify each ACK.
        acknowledged_commands.insert((ack.request.session_id.clone(), ack.request.id));
        found.push(json!({"frame_session_id":id,"event_sequence":event.sequence,"ack_command_id":ack.request.id,
            "ack_request_sequence":ack.request.sequence,"ack_reply_sequence":ack.reply.sequence,"image_bytes":bytes,"image_sha256":image}));
        require(
            found.len() <= 64,
            "screencast proof exceeded its finite sample bound",
        )?;
    }
    Ok(found)
}

fn orphan_targets_zero(harness: &Harness) -> Result<Value, ProbeError> {
    let mark = harness.trace.mark();
    with_session(harness, Some(harness.default_options()?), |session| {
        navigate(harness, session, "orphan_targets_zero")?;
        let before = harness.trace.since(mark)?;
        let context = context_id(&before, &session.shard)?;
        let attachments = owned_attachments(&before, &session.shard, &context)?;
        require(
            attachments.iter().any(|attached| {
                matches!(
                    attached
                        .summary
                        .pointer("/params/targetInfo/type")
                        .and_then(Value::as_str),
                    Some("iframe" | "worker" | "shared_worker" | "service_worker")
                )
            }),
            "orphan cleanup probe did not observe an actual child frame or worker target",
        )?;
        let absence = dispose_context_observed(harness, session, mark, &context, true)?;
        Ok(
            json!({"all_probe_contexts_positively_disposed":1,"actual_child_targets_observed":true,
            "real_non_browser_targets":0,"absence":absence}),
        )
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use browserd_core::{LaunchGeneration, OwnerFence, ShardId, WorkerEpoch, WorkerId};

    fn shard() -> ShardFence {
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new("kernel-proof-check").expect("worker id"),
                WorkerEpoch::new(7).expect("epoch"),
            ),
            ShardId::new(),
            LaunchGeneration::new(3).expect("launch"),
        )
    }

    fn row(
        sequence: u64,
        shard: &ShardFence,
        direction: TraceDirection,
        id: Option<u64>,
        session: Option<&str>,
        method: Option<&str>,
        summary: Value,
    ) -> TraceEntry {
        TraceEntry {
            sequence,
            shard: shard.clone(),
            direction,
            id,
            session_id: session.map(str::to_owned),
            method: method.map(str::to_owned),
            summary,
        }
    }

    fn exchange(
        rows: &mut Vec<TraceEntry>,
        shard: &ShardFence,
        session: Option<&str>,
        method: &str,
        params: Value,
        result: Value,
    ) {
        let sequence = rows.last().map_or(1, |row| row.sequence + 1);
        rows.push(row(
            sequence,
            shard,
            TraceDirection::Command,
            Some(sequence),
            session,
            Some(method),
            json!({"params":params}),
        ));
        rows.push(row(
            sequence + 1,
            shard,
            TraceDirection::Reply,
            Some(sequence),
            session,
            None,
            json!({"success":true,"result":result}),
        ));
    }

    fn reply_mut<'a>(rows: &'a mut [TraceEntry], method: &str) -> &'a mut TraceEntry {
        let id = rows
            .iter()
            .find(|row| row.method.as_deref() == Some(method))
            .expect("command")
            .id;
        rows.iter_mut()
            .find(|row| matches!(row.direction, TraceDirection::Reply) && row.id == id)
            .expect("reply")
    }

    #[test]
    fn replies_require_exact_launch_flattened_session_id_order_and_actual_success() {
        let shard = shard();
        let other_launch = ShardFence::new(
            shard.owner().clone(),
            shard.shard_id().clone(),
            LaunchGeneration::new(4).expect("new launch"),
        );
        let mut rows = vec![
            row(
                1,
                &shard,
                TraceDirection::Command,
                Some(11),
                Some("owned"),
                Some("Page.enable"),
                json!({"params":{}}),
            ),
            row(
                2,
                &other_launch,
                TraceDirection::Reply,
                Some(11),
                Some("owned"),
                None,
                json!({"success":true,"result":{}}),
            ),
            row(
                3,
                &shard,
                TraceDirection::Reply,
                Some(11),
                Some("foreign"),
                None,
                json!({"success":true,"result":{}}),
            ),
        ];
        assert!(successful(&rows, "Page.enable", &shard).is_empty());
        rows.push(row(
            0,
            &shard,
            TraceDirection::Reply,
            Some(11),
            Some("owned"),
            None,
            json!({"success":true,"result":{}}),
        ));
        rows.push(row(
            4,
            &shard,
            TraceDirection::Reply,
            Some(11),
            Some("owned"),
            None,
            json!({"success":false,"result":{}}),
        ));
        rows.push(row(
            5,
            &shard,
            TraceDirection::Reply,
            Some(11),
            Some("owned"),
            None,
            json!({"success":true,"error":{"code":-1},"result":{}}),
        ));
        rows.push(row(
            6,
            &shard,
            TraceDirection::Reply,
            Some(11),
            Some("owned"),
            None,
            json!({"success":true}),
        ));
        assert!(successful(&rows, "Page.enable", &shard).is_empty());
        rows.push(row(
            7,
            &shard,
            TraceDirection::Reply,
            Some(11),
            Some("owned"),
            None,
            json!({"success":true,"result":{}}),
        ));
        assert_eq!(
            successful(&rows, "Page.enable", &shard)
                .first()
                .expect("exact reply")
                .reply
                .sequence,
            7
        );
    }

    fn disposal_rows(shard: &ShardFence, targets: Value, contexts: Value) -> Vec<TraceEntry> {
        let mut rows = Vec::new();
        exchange(
            &mut rows,
            shard,
            None,
            "Target.disposeBrowserContext",
            json!({"browserContextId":"owned"}),
            json!({}),
        );
        exchange(
            &mut rows,
            shard,
            None,
            "Target.getTargets",
            json!({}),
            json!({"targetInfos":targets}),
        );
        exchange(
            &mut rows,
            shard,
            None,
            "Target.getBrowserContexts",
            json!({}),
            json!({"browserContextIds":contexts}),
        );
        rows
    }

    #[test]
    fn disposal_requires_positive_exact_reply_and_both_later_absence_snapshots() {
        let shard = shard();
        let mut rows = disposal_rows(&shard, json!([]), json!([]));
        assert!(target_absence(&rows, &shard, "owned", true).is_ok());
        assert!(target_absence(&rows, &shard, "foreign", true).is_err());
        reply_mut(&mut rows, "Target.disposeBrowserContext").summary["success"] = json!(false);
        assert!(target_absence(&rows, &shard, "owned", true).is_err());
        rows = disposal_rows(&shard, json!([]), json!([]));
        rows.retain(|row| row.method.as_deref() != Some("Target.getBrowserContexts"));
        assert!(target_absence(&rows, &shard, "owned", true).is_err());
        rows = disposal_rows(&shard, json!([]), json!([]));
        rows.iter_mut()
            .find(|row| row.method.as_deref() == Some("Target.getTargets"))
            .expect("snapshot")
            .sequence = 1;
        assert!(target_absence(&rows, &shard, "owned", true).is_err());
    }

    #[test]
    fn disposal_fails_for_owned_targets_contexts_and_global_foreign_orphans() {
        let shard = shard();
        let owned_target = disposal_rows(
            &shard,
            json!([{"type":"page","browserContextId":"owned"}]),
            json!([]),
        );
        assert!(target_absence(&owned_target, &shard, "owned", false).is_err());
        let owned_context = disposal_rows(&shard, json!([]), json!(["owned"]));
        assert!(target_absence(&owned_context, &shard, "owned", false).is_err());
        let foreign = disposal_rows(
            &shard,
            json!([{"type":"worker","browserContextId":"foreign"}]),
            json!(["foreign"]),
        );
        assert!(target_absence(&foreign, &shard, "owned", false).is_ok());
        assert!(target_absence(&foreign, &shard, "owned", true).is_err());
        let malformed = disposal_rows(&shard, json!([]), json!([null]));
        assert!(target_absence(&malformed, &shard, "owned", false).is_err());
    }

    fn pause_rows(shard: &ShardFence) -> Vec<TraceEntry> {
        let mut rows = vec![row(
            1,
            shard,
            TraceDirection::Event,
            None,
            None,
            Some("Target.attachedToTarget"),
            json!({"params":{"sessionId":"page-pipe","waitingForDebugger":true,
                "targetInfo":{"targetId":"page-target","browserContextId":"owned","type":"page"}}}),
        )];
        for (method, params) in [
            (
                "Target.setAutoAttach",
                json!({"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true}),
            ),
            ("Network.enable", json!({})),
            ("Runtime.enable", json!({})),
            ("Page.enable", json!({})),
            (
                "Page.setInterceptFileChooserDialog",
                json!({"enabled":true}),
            ),
            ("Network.setUserAgentOverride", json!({})),
            ("Emulation.setDeviceMetricsOverride", json!({})),
            ("Runtime.runIfWaitingForDebugger", json!({})),
        ] {
            exchange(
                &mut rows,
                shard,
                Some("page-pipe"),
                method,
                params,
                json!({}),
            );
        }
        rows
    }

    #[test]
    fn pause_proof_requires_all_success_replies_before_resume_and_actual_waiting() {
        let shard = shard();
        let mut rows = pause_rows(&shard);
        assert!(paused_target_proof(&rows, &shard, "owned").is_ok());
        reply_mut(&mut rows, "Network.enable").sequence = 100;
        assert!(paused_target_proof(&rows, &shard, "owned").is_err());
        rows = pause_rows(&shard);
        reply_mut(&mut rows, "Emulation.setDeviceMetricsOverride").summary["success"] =
            json!(false);
        assert!(paused_target_proof(&rows, &shard, "owned").is_err());
        rows = pause_rows(&shard);
        rows.first_mut().expect("attach").summary["params"]["waitingForDebugger"] = json!(false);
        assert!(paused_target_proof(&rows, &shard, "owned").is_err());
        rows = pause_rows(&shard);
        rows.iter_mut()
            .find(|row| row.method.as_deref() == Some("Target.setAutoAttach"))
            .expect("attach command")
            .summary["params"]["flatten"] = json!(false);
        assert!(paused_target_proof(&rows, &shard, "owned").is_err());
    }

    #[test]
    fn pause_observation_waits_for_a_late_actual_reply_without_adding_evidence() {
        let shard = shard();
        let complete = pause_rows_with_worker(&shard);
        let mut pending = complete.clone();
        let resume = pending
            .iter()
            .find(|row| {
                row.method.as_deref() == Some("Runtime.runIfWaitingForDebugger")
                    && row.session_id.as_deref() == Some("worker-pipe")
            })
            .expect("resume request")
            .id;
        pending.retain(|row| !matches!(row.direction, TraceDirection::Reply) || row.id != resume);
        assert!(paused_target_proof(&pending, &shard, "owned").is_err());
        let mut observations = 0;
        let proof = wait_for_paused_target_proof(
            || {
                observations += 1;
                Ok(if observations < 3 {
                    pending.clone()
                } else {
                    complete.clone()
                })
            },
            &shard,
            "owned",
            Instant::now() + Duration::from_secs(1),
        )
        .expect("observed resume reply");
        assert_eq!(observations, 3);
        let actual = successful(&complete, "Runtime.runIfWaitingForDebugger", &shard)
            .into_iter()
            .find(|exchange| exchange.request.session_id.as_deref() == Some("worker-pipe"))
            .expect("worker resume");
        assert_eq!(proof["paused_and_resumed_targets"], 2);
        assert_eq!(
            proof["targets"][1]["resume_reply_sequence"],
            actual.reply.sequence
        );
        assert!(paused_target_proof(&pending, &shard, "owned").is_err());
    }

    #[test]
    fn pause_observation_never_accepts_errors_foreign_replies_or_incomplete_trace() {
        let shard = shard();
        let mut failed = pause_rows(&shard);
        reply_mut(&mut failed, "Runtime.runIfWaitingForDebugger").summary =
            json!({"success":false,"error":{"code":-32000}});
        assert!(
            wait_for_paused_target_proof(|| Ok(failed.clone()), &shard, "owned", Instant::now())
                .is_err()
        );
        let mut foreign = pause_rows(&shard);
        reply_mut(&mut foreign, "Runtime.runIfWaitingForDebugger").session_id =
            Some("foreign-pipe".into());
        assert!(
            wait_for_paused_target_proof(|| Ok(foreign.clone()), &shard, "owned", Instant::now())
                .is_err()
        );
        let complete = pause_rows(&shard);
        assert!(
            wait_for_paused_target_proof(|| Ok(complete.clone()), &shard, "owned", Instant::now())
                .is_err()
        );
        let mut observations = 0;
        let error = wait_for_paused_target_proof(
            || {
                observations += 1;
                Err(ProbeError::failed(
                    "CDP proof trace is incomplete/truncated",
                ))
            },
            &shard,
            "owned",
            Instant::now() + Duration::from_secs(1),
        );
        assert!(error.is_err());
        assert_eq!(observations, 1);
    }

    fn pause_rows_with_worker(shard: &ShardFence) -> Vec<TraceEntry> {
        let mut rows = pause_rows(shard);
        rows.push(row(18, shard, TraceDirection::Event, None, Some("page-pipe"), Some("Target.attachedToTarget"),
            json!({"params":{"sessionId":"worker-pipe","waitingForDebugger":true,"targetInfo":{"targetId":"worker-target","type":"worker"}}})));
        exchange(
            &mut rows,
            shard,
            Some("worker-pipe"),
            "Target.setAutoAttach",
            json!({"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true}),
            json!({}),
        );
        exchange(
            &mut rows,
            shard,
            Some("worker-pipe"),
            "Network.enable",
            json!({}),
            json!({}),
        );
        exchange(
            &mut rows,
            shard,
            Some("worker-pipe"),
            "Runtime.runIfWaitingForDebugger",
            json!({}),
            json!({}),
        );
        rows
    }

    #[test]
    fn native_worker_ownership_requires_observed_parent_and_pre_resume_network_bootstrap() {
        let shard = shard();
        let mut rows = pause_rows_with_worker(&shard);
        assert_eq!(
            owned_attachments(&rows, &shard, "owned")
                .expect("owned child")
                .len(),
            2
        );
        assert_eq!(
            paused_target_proof(&rows, &shard, "owned").expect("native worker proof")["paused_and_resumed_targets"],
            json!(2)
        );
        rows.iter_mut()
            .find(|row| row.sequence == 18)
            .expect("child attach")
            .summary["params"]["targetInfo"]["browserContextId"] = json!("foreign");
        assert!(owned_attachments(&rows, &shard, "owned").is_err());
        rows.iter_mut()
            .find(|row| row.sequence == 18)
            .expect("child attach")
            .summary["params"]["targetInfo"]
            .as_object_mut()
            .expect("target info")
            .remove("browserContextId");
        rows.iter_mut()
            .find(|row| row.sequence == 18)
            .expect("child attach")
            .session_id = Some("unknown-parent".into());
        assert_eq!(
            owned_attachments(&rows, &shard, "owned")
                .expect("not inherited")
                .len(),
            1
        );
    }

    const PDF_BYTES: &[u8] = b"%PDF-proof\n%%EOF";

    fn pdf_rows(shard: &ShardFence) -> Vec<TraceEntry> {
        let mut rows = Vec::new();
        exchange(
            &mut rows,
            shard,
            Some("page"),
            "Page.printToPDF",
            json!({"transferMode":"ReturnAsStream"}),
            json!({"stream":"pdf-handle"}),
        );
        for (chunk, eof) in [
            (PDF_BYTES.get(..5).expect("prefix"), false),
            (PDF_BYTES.get(5..).expect("suffix"), true),
        ] {
            exchange(
                &mut rows,
                shard,
                Some("page"),
                "IO.read",
                json!({"handle":"pdf-handle","size":65536}),
                json!({"data_bytes":chunk.len(),"data_sha256":format!("{:x}",Sha256::digest(chunk)),"eof":eof}),
            );
        }
        exchange(
            &mut rows,
            shard,
            Some("page"),
            "IO.close",
            json!({"handle":"pdf-handle"}),
            json!({}),
        );
        rows
    }

    #[test]
    fn pdf_requires_actual_eof_then_successful_exact_handle_close_and_stored_chunk_hashes() {
        let shard = shard();
        let mut rows = pdf_rows(&shard);
        let proof = pdf_protocol_proof(&rows, &shard, PDF_BYTES).expect("finite PDF stream");
        assert_eq!(proof["stream_reads"], json!(2));
        rows.iter_mut()
            .filter(|row| matches!(row.direction, TraceDirection::Reply))
            .for_each(|row| {
                if let Some(eof) = row.summary.pointer_mut("/result/eof") {
                    *eof = json!(false);
                }
            });
        assert!(pdf_protocol_proof(&rows, &shard, PDF_BYTES).is_err());
        rows = pdf_rows(&shard);
        reply_mut(&mut rows, "IO.close").summary["success"] = json!(false);
        assert!(pdf_protocol_proof(&rows, &shard, PDF_BYTES).is_err());
        rows = pdf_rows(&shard);
        rows.iter_mut()
            .find(|row| row.method.as_deref() == Some("IO.close"))
            .expect("close")
            .summary["params"]["handle"] = json!("foreign-handle");
        assert!(pdf_protocol_proof(&rows, &shard, PDF_BYTES).is_err());
        rows = pdf_rows(&shard);
        reply_mut(&mut rows, "IO.read").summary["result"]["data_sha256"] = json!("00".repeat(32));
        assert!(pdf_protocol_proof(&rows, &shard, PDF_BYTES).is_err());
    }

    #[test]
    fn pdf_rejects_unbounded_chunks_cross_session_reads_and_reads_after_eof() {
        let shard = shard();
        let mut rows = pdf_rows(&shard);
        rows.iter_mut()
            .find(|row| row.method.as_deref() == Some("IO.read"))
            .expect("read")
            .summary["params"]["size"] = json!(65537);
        assert!(pdf_protocol_proof(&rows, &shard, PDF_BYTES).is_err());
        rows = pdf_rows(&shard);
        let command = rows
            .iter_mut()
            .find(|row| row.method.as_deref() == Some("IO.read"))
            .expect("read");
        let id = command.id;
        command.session_id = Some("foreign".into());
        rows.iter_mut()
            .find(|row| row.id == id && matches!(row.direction, TraceDirection::Reply))
            .expect("reply")
            .session_id = Some("foreign".into());
        assert!(pdf_protocol_proof(&rows, &shard, PDF_BYTES).is_err());
        rows = pdf_rows(&shard);
        reply_mut(&mut rows, "IO.read").summary["result"]["eof"] = json!(true);
        assert!(pdf_protocol_proof(&rows, &shard, PDF_BYTES).is_err());
        rows = pdf_rows(&shard);
        assert!(pdf_protocol_proof(&rows, &shard, b"short").is_err());
    }

    fn screencast_rows(shard: &ShardFence) -> Vec<TraceEntry> {
        let mut rows = Vec::new();
        for id in 1..=3 {
            let sequence = rows.last().map_or(1, |row: &TraceEntry| row.sequence + 1);
            rows.push(row(
                sequence,
                shard,
                TraceDirection::Event,
                None,
                Some("page"),
                Some("Page.screencastFrame"),
                json!({"params":{"sessionId":id,"data_bytes":512,"data_sha256":format!("{id:064x}")}}),
            ));
            exchange(
                &mut rows,
                shard,
                Some("page"),
                "Page.screencastFrameAck",
                json!({"sessionId":id}),
                json!({}),
            );
        }
        rows
    }

    #[test]
    fn screencast_counts_distinct_actual_frames_only_with_exact_successful_ack_replies() {
        let shard = shard();
        let mut rows = screencast_rows(&shard);
        assert_eq!(
            screencast_receipts(&rows, &shard)
                .expect("actual ACKs")
                .len(),
            3
        );
        reply_mut(&mut rows, "Page.screencastFrameAck").summary["success"] = json!(false);
        assert_eq!(
            screencast_receipts(&rows, &shard)
                .expect("failed ACK excluded")
                .len(),
            2
        );
        rows = screencast_rows(&shard);
        rows.iter_mut()
            .find(|row| row.method.as_deref() == Some("Page.screencastFrameAck"))
            .expect("ack")
            .summary["params"]["sessionId"] = json!(999);
        assert_eq!(
            screencast_receipts(&rows, &shard)
                .expect("foreign ACK excluded")
                .len(),
            2
        );
        rows = screencast_rows(&shard);
        rows.iter_mut()
            .filter(|row| {
                row.method.as_deref() == Some("Page.screencastFrameAck")
                    || matches!(row.direction, TraceDirection::Reply)
            })
            .for_each(|row| row.session_id = Some("foreign".into()));
        assert!(
            screencast_receipts(&rows, &shard)
                .expect("different pipe excluded")
                .is_empty()
        );
    }

    #[test]
    fn screencast_reuses_stream_identity_with_distinct_events_and_ack_commands() {
        let shard = shard();
        let mut rows = screencast_rows(&shard);
        for row in &mut rows {
            if row.method.as_deref().is_some_and(|method| {
                matches!(method, "Page.screencastFrame" | "Page.screencastFrameAck")
            }) {
                row.summary["params"]["sessionId"] = json!(7);
            }
        }
        let receipts =
            screencast_receipts(&rows, &shard).expect("same stream with distinct real ACKs");
        assert_eq!(receipts.len(), 3);
        assert!(
            receipts
                .iter()
                .all(|receipt| receipt["frame_session_id"] == json!(7))
        );
        let identities: BTreeSet<_> = receipts
            .iter()
            .map(|receipt| receipt["ack_command_id"].as_u64().expect("ACK id"))
            .collect();
        assert_eq!(identities.len(), 3);
        rows.retain(|row| row.sequence <= 3 || matches!(row.direction, TraceDirection::Event));
        assert_eq!(
            screencast_receipts(&rows, &shard)
                .expect("one ACK cannot cover three events")
                .len(),
            1
        );
    }

    #[test]
    fn screencast_rejects_duplicate_event_sequence_and_oversized_actual_image() {
        let shard = shard();
        let mut rows = screencast_rows(&shard);
        rows.push(row(
            1,
            &shard,
            TraceDirection::Event,
            None,
            Some("page"),
            Some("Page.screencastFrame"),
            json!({"params":{"sessionId":1,"data_bytes":512,"data_sha256":"01".repeat(32)}}),
        ));
        exchange(
            &mut rows,
            &shard,
            Some("page"),
            "Page.screencastFrameAck",
            json!({"sessionId":1}),
            json!({}),
        );
        assert!(screencast_receipts(&rows, &shard).is_err());
        rows = screencast_rows(&shard);
        rows.first_mut().expect("frame").summary["params"]["data_bytes"] =
            json!(MAX_VIEWER_JPEG_BYTES + 1);
        assert!(screencast_receipts(&rows, &shard).is_err());
    }
}
