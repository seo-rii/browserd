use super::config::{self, ApprovedConfig, EngineRequest, RuntimeManifest};
use super::rpc::{self, RecordingSandboxRpc, Trace};
use super::{Harness, OwnedSession, ProbeError, ProbeResult, ProbeResultValue};
use crate::{
    ArtifactScanner, ArtifactStoreConfig, ClamAvFreshnessPolicy, ProductionArtifactStore,
    ProductionSessionShardConfig, ProductionSessionShardFactory, SessionShardRouter,
    UnixClamAvScanner,
};
use browser_sandboxd::{
    EgressClientConfig, EgressControlPlane, HttpEgressControl, RouteStatusState,
};
use browserd_chromium::{
    ChromiumConnectionConfig, CompatibilityArtifact, VerifiedNativeProfileCatalog,
};
use browserd_coordination::{
    RedisSafetyAuthority, RedisSafetyAuthorityConfig, SafetyAuthorityConfig, SafetyObserver,
};
use browserd_core::{RuntimeSafetyCache, ShardFence};
use browserd_sandbox::{
    CleanupReason, EgressPolicyBinding, FilePreparedShardJournal, PreparedShardCleanupStage,
    PreparedShardCleanupStageStatus, PreparedShardJournalLimits, PreparedShardRecoveryDisposition,
    PreparedShardRecoveryRoots, SandboxRpcClient,
};
use browserd_worker::{SandboxClient, SandboxShardRpc, SystemWorkerClock};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

mod network;
mod process;
mod worker_child;
pub(super) fn worker_child_main(path: &Path) -> Result<(), String> {
    worker_child::child_main(path)
}
pub(super) fn namespace_helper_main(path: &Path) -> Result<(), String> {
    network::helper_main(path)
}

pub(super) fn open_harness(
    request: &EngineRequest,
    approved: ApprovedConfig,
) -> ProbeResultValue<Harness> {
    open_harness_scoped(request, approved, None)
}

pub(super) fn open_harness_scoped(
    request: &EngineRequest,
    approved: ApprovedConfig,
    child_state: Option<&Path>,
) -> ProbeResultValue<Harness> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| ProbeError::blocked("probe async runtime unavailable"))?;
    let config = approved.deployment;
    let artifact: CompatibilityArtifact = serde_json::from_slice(&config::read_bounded(
        &Path::new(&config.artifact_root).join("compatibility.json"),
        1024 * 1024,
        true,
    )?)
    .map_err(|_| ProbeError::blocked("approved artifact schema invalid"))?;
    artifact
        .verify(Path::new(&config.artifact_root))
        .map_err(|_| ProbeError::blocked("approved Chromium verification failed"))?;
    let deadline = Instant::now() + Duration::from_secs(request.deadline_seconds);
    let pin = runtime.block_on(rpc::pin_peer(
        &config.sandbox.socket_path,
        config.sandbox.expected_server_uid,
        &config.assets.sandbox_daemon_executable,
    ))?;
    let egress_pin = runtime.block_on(rpc::pin_peer(
        &config.egress.install_socket,
        config.egress.expected_server_uid,
        &config.assets.egress_daemon_executable,
    ))?;
    process::verify_http_listener(&egress_pin, &config.egress.control_url)?;
    let client = SandboxRpcClient::new(
        config.sandbox.socket_path.clone(),
        4 * 1024 * 1024,
        Duration::from_secs(30),
        config.sandbox.expected_server_uid,
        config.sandbox.daemon_epoch,
    )
    .map_err(|_| ProbeError::blocked("approved sandbox RPC configuration invalid"))?;
    let trace = Arc::new(Trace::default());
    let rpc = Arc::new(RecordingSandboxRpc::new(
        client,
        pin,
        Arc::clone(&trace),
        deadline,
    ));
    let epoch = runtime
        .block_on(
            rpc.client
                .probe_daemon_epoch(&config.worker_id()?, config.sandbox.worker_epoch),
        )
        .map_err(|_| ProbeError::blocked("authenticated production sandbox unavailable"))?;
    if epoch != config.sandbox.daemon_epoch {
        return Err(ProbeError::blocked("production sandbox epoch mismatch"));
    }
    let egress = HttpEgressControl::new(
        EgressClientConfig::new(
            url::Url::parse(&config.egress.control_url)
                .map_err(|_| ProbeError::blocked("egress URL invalid"))?,
            config.egress.install_socket.clone(),
            config.egress.daemon_epoch,
            config.egress.expected_server_uid,
            config.egress.worker_token.clone(),
            config.egress.supervisor_token.clone(),
            Duration::from_secs(5),
            65536,
        )
        .map_err(|_| ProbeError::blocked("egress authentication configuration invalid"))?,
    )
    .map_err(|_| ProbeError::blocked("production egress client unavailable"))?;
    if runtime
        .block_on(egress.authenticated_current_daemon_epoch())
        .map_err(|_| ProbeError::blocked("authenticated production egress unavailable"))?
        != config.egress.daemon_epoch
    {
        return Err(ProbeError::blocked("production egress epoch mismatch"));
    }
    let safety = Arc::new(RuntimeSafetyCache::new());
    let authority = runtime
        .block_on(RedisSafetyAuthority::connect(
            RedisSafetyAuthorityConfig::new(
                config.runtime.redis_url.clone(),
                config.runtime.redis_prefix.clone(),
                SafetyAuthorityConfig::default(),
                4,
                Duration::from_secs(5),
            )
            .map_err(|_| ProbeError::blocked("runtime safety configuration invalid"))?,
        ))
        .map_err(|_| ProbeError::blocked("durable runtime safety authority unavailable"))?;
    let observer = Arc::new(
        SafetyObserver::open(
            child_state.map_or_else(
                || config.runtime.safety_pin_path.clone(),
                |path| path.join("safety-pin.json"),
            ),
            Arc::new(authority),
            Arc::clone(&safety),
            Duration::from_secs(30),
        )
        .map_err(|_| ProbeError::blocked("durable runtime safety observer unavailable"))?,
    );
    runtime.block_on(observer.refresh()).map_err(|_| {
        ProbeError::blocked("operator runtime safety has not been initialized/freshly observed")
    })?;
    let state = child_state.map_or_else(
        || config.worker.state_root.join(&request.binding.run_id),
        Path::to_path_buf,
    );
    private_subdirectory(&state)?;
    let artifact_root = state.join("artifacts");
    private_subdirectory(&artifact_root)?;
    let scanner: Option<Arc<dyn ArtifactScanner>> = config
        .worker
        .scanner
        .as_ref()
        .map(|scanner| {
            let policy = ClamAvFreshnessPolicy::new_utc(
                Duration::from_millis(scanner.max_database_age_millis),
                Duration::from_millis(scanner.max_future_skew_millis),
            )
            .map_err(|_| ProbeError::blocked("approved scanner freshness bounds invalid"))?;
            let scanner = UnixClamAvScanner::new(
                scanner.socket_path.clone(),
                scanner.expected_uid,
                32 * 1024 * 1024,
                Duration::from_secs(30),
                policy,
                Arc::new(SystemWorkerClock),
            )
            .map_err(|_| ProbeError::blocked("approved scanner configuration invalid"))?;
            Ok(Arc::new(scanner) as Arc<dyn ArtifactScanner>)
        })
        .transpose()?;
    let artifacts = Arc::new(
        ProductionArtifactStore::open(
            ArtifactStoreConfig {
                root: artifact_root,
                max_file_bytes: 32 * 1024 * 1024,
                max_worker_bytes: 256 * 1024 * 1024,
                max_worker_in_flight_bytes: 64 * 1024 * 1024,
                max_session_bytes: 64 * 1024 * 1024,
                max_session_in_flight_bytes: 32 * 1024 * 1024,
                max_retained_artifacts: 256,
                max_operations: 8,
                chunk_bytes: 65536,
                operation_timeout: Duration::from_secs(30),
            },
            runtime.handle().clone(),
            scanner,
        )
        .map_err(|_| ProbeError::blocked("real private artifact store unavailable"))?,
    );
    let catalog =
        VerifiedNativeProfileCatalog::load(Path::new(&config.artifact_root), &artifact)
            .map_err(|_| ProbeError::blocked("verified native profile catalog unavailable"))?;
    let policy_digest: [u8; 32] = hex::decode(&config.egress.policy_digest)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ProbeError::blocked("invalid egress policy digest"))?;
    let factory_config = ProductionSessionShardConfig::new(
        config.worker_id()?,
        config.sandbox.worker_epoch,
        config.sandbox.daemon_epoch,
        artifact.identity.clone(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new(config.egress.policy_profile.clone(), policy_digest)
            .map_err(|_| ProbeError::blocked("invalid egress policy binding"))?,
        Duration::from_secs(30),
    )
    .map_err(|_| ProbeError::blocked("production factory configuration invalid"))?
    .with_native_profiles(catalog)
    .map_err(|_| ProbeError::blocked("native catalog identity mismatch"))?
    .with_browser_downloads(config.worker.scanner.is_some())
    .with_privileged_evaluate(config.worker.privileged_evaluate);
    let factory = Arc::new(
        ProductionSessionShardFactory::new(
            factory_config,
            Arc::clone(&rpc),
            runtime.handle().clone(),
        )
        .map_err(|_| ProbeError::blocked("actual production factory unavailable"))?
        .with_runtime_safety(Arc::clone(&safety)),
    );
    let router = Arc::new(
        SessionShardRouter::new(
            config.worker_id()?,
            config.sandbox.worker_epoch,
            factory,
            Arc::clone(&artifacts),
            config.worker.max_session_count,
        )
        .map_err(|_| ProbeError::blocked("actual production router unavailable"))?,
    );
    let fixture = if child_state.is_some() {
        super::fixture::Fixture::borrow(&config.fixtures, &request.binding.run_id)?
    } else {
        super::fixture::Fixture::open(&config.fixtures, &request.binding.run_id, deadline)?
    };
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    let observer_task=runtime.spawn(async move{
        let mut tick=tokio::time::interval(Duration::from_secs(1));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop{tokio::select!{()=stop.cancelled()=>break,_=tick.tick()=>{let _=observer.refresh().await;}}}
    });
    let heartbeat_router = Arc::clone(&router);
    let worker = config.worker_id()?;
    let epoch = config.sandbox.worker_epoch;
    let stop = shutdown.clone();
    let heartbeat_task=runtime.spawn(async move{
        let mut tick=tokio::time::interval(Duration::from_secs(3));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop{tokio::select!{()=stop.cancelled()=>break,_=tick.tick()=>{
            let router=Arc::clone(&heartbeat_router);let worker=worker.clone();let _=tokio::task::spawn_blocking(move||router.heartbeat(&worker,epoch)).await;
        }}}
    });
    Ok(Harness {
        runtime,
        router,
        rpc,
        config,
        trace,
        deadline,
        binding: request.binding.clone(),
        artifacts,
        artifact,
        safety,
        egress,
        request: request.clone(),
        fixture,
        sessions: Mutex::new(BTreeMap::new()),
        shutdown,
        background: vec![observer_task, heartbeat_task],
    })
}
pub(super) fn private_subdirectory(path: &Path) -> ProbeResultValue<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(ProbeError::blocked(
                "owned validation state directory unavailable",
            ));
        }
    }
    config::private_directory(path)
}
pub(super) fn record(
    h: &Harness,
    shard: &ShardFence,
) -> ProbeResultValue<browserd_sandbox::PreparedShardJournalRecord> {
    FilePreparedShardJournal::inspect_existing_record(
        &h.config.sandbox.journal_directory,
        PreparedShardJournalLimits::default(),
        PreparedShardRecoveryRoots::new(
            h.config.sandbox.cgroup_root.clone(),
            h.config.sandbox.runtime_root.clone(),
        )
        .map_err(|_| ProbeError::blocked("approved recovery roots invalid"))?,
        shard,
    )
    .map_err(|_| ProbeError::failed("exact durable sandbox generation record unavailable/invalid"))
}
pub(super) fn verify_cleanup(h: &Harness, shard: &ShardFence) -> ProbeResultValue<Value> {
    // Positive Released tombstones and their ten cleanup completions are irreversible for this
    // exact generation. Retain that proof rather than issuing 1000 redundant terminal HTTP reads.
    if let Some(proof) = h.rpc.cleanup_proof(shard)? {
        return Ok(proof);
    }
    let record = record(h, shard)?;
    if record.recovery_disposition() != PreparedShardRecoveryDisposition::ReleasedTombstone
        || !PreparedShardCleanupStage::ALL.into_iter().all(|stage| {
            record.cleanup_progress(stage).is_ok_and(|progress| {
                progress.status() == PreparedShardCleanupStageStatus::Completed
            })
        })
    {
        return Err(ProbeError::failed(
            "exact durable cleanup stages are not all positively complete",
        ));
    }
    let locators = record.locators();
    for path in [locators.cgroup_path(), locators.runtime_path()] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(ProbeError::failed(
                    "exact generation cgroup/runtime still exists or is unreadable",
                ));
            }
        }
    }
    let spec = h.rpc.spec_for_shard(shard)?;
    let fence = spec.dedicated_egress().egress_fence();
    if locators.egress_daemon_epoch() != Some(h.config.egress.daemon_epoch)
        || locators.egress_fence() != Some(fence)
    {
        return Err(ProbeError::failed(
            "durable exact cleanup egress binding mismatch",
        ));
    }
    let status = h
        .runtime
        .block_on(h.egress.status(h.config.egress.daemon_epoch, fence))
        .map_err(|_| {
            ProbeError::failed("positive authenticated exact egress cleanup status unavailable")
        })?
        .ok_or_else(|| {
            ProbeError::failed("exact egress generation has no positive cleanup receipt")
        })?;
    if status.daemon_epoch() != h.config.egress.daemon_epoch
        || status.egress_fence() != fence
        || status.state() != RouteStatusState::Released
    {
        return Err(ProbeError::failed(
            "exact egress generation not positively Released",
        ));
    }
    if !h.rpc.join_tees(Some(shard)) {
        return Err(ProbeError::failed(
            "owned CDP observer endpoints did not close/reap",
        ));
    }
    let proof = json!({"shard":shard,"durable_cleanup_stages":10,"egress_state":"released","cgroup_absent":true,"runtime_absent":true,"observer_reaped":true});
    h.rpc.retain_cleanup_proof(shard, &proof)?;
    Ok(proof)
}
pub(super) fn with_session(
    h: &Harness,
    probe: impl FnOnce(&OwnedSession) -> ProbeResultValue<Value>,
) -> ProbeResultValue<Value> {
    let session = h.open_session(None)?;
    let result = probe(&session);
    let cleanup = h.close_session(&session)?;
    result.map(|observations| json!({"actual":observations,"cleanup":cleanup}))
}
pub(super) fn finish_harness(h: &mut Harness) -> bool {
    let mut complete = true;
    let sessions = h
        .sessions
        .lock()
        .map(|s| s.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    for session in sessions {
        complete &= h.close_session(&session).is_ok();
    }
    if let Ok(specs) = h.rpc.specs() {
        for spec in specs {
            let shard = spec.dedicated_egress().egress_fence().shard();
            if verify_cleanup(h, shard).is_err() {
                let _ = h.runtime.block_on(
                    h.rpc
                        .cancel_or_kill_shard(&spec, CleanupReason::Administrative),
                );
                complete &= verify_cleanup(h, shard).is_ok();
            }
        }
    } else {
        complete = false;
    }
    h.shutdown.cancel();
    for task in h.background.drain(..) {
        complete &= h
            .runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(6), task).await })
            .is_ok();
    }
    complete &= h.fixture.finish();
    complete &= h.rpc.join_tees(None);
    complete
}
type Probe = fn(&Harness) -> ProbeResultValue<Value>;
pub(super) fn run_foundation_probes(h: &Harness) -> BTreeMap<String, ProbeResult> {
    run_foundation_probes_with_proxy_runs(h, Ok(1))
}
pub(super) fn run_foundation_preflight_probes(h: &Harness) -> BTreeMap<String, ProbeResult> {
    let value = std::env::var_os("BROWSERD_KERNEL_PREFLIGHT_PROXY_REPETITIONS");
    run_foundation_probes_with_proxy_runs(h, proxy_repetitions(value.as_deref()))
}
fn proxy_repetitions(value: Option<&std::ffi::OsStr>) -> ProbeResultValue<usize> {
    let Some(value) = value else { return Ok(1) };
    let parsed = value
        .to_str()
        .filter(|text| text.len() <= 2)
        .and_then(|text| {
            text.parse::<usize>()
                .ok()
                .filter(|count| text == count.to_string())
        });
    parsed
        .filter(|count| (1..=64).contains(count))
        .ok_or_else(|| {
            ProbeError::blocked("private loopback diagnostic repetition bound is invalid")
        })
}
fn run_foundation_probes_with_proxy_runs(
    h: &Harness,
    proxy_runs: ProbeResultValue<usize>,
) -> BTreeMap<String, ProbeResult> {
    let probes: [(&str, Probe); 7] = [
        ("chromium_identity", process::chromium_identity),
        ("chromium_sandbox", process::chromium_sandbox),
        ("outer_sandbox", process::outer_sandbox),
        ("proxy_loopback", network::proxy_loopback),
        ("direct_egress_denial", network::direct_egress_denial),
        (
            "worker_sigkill_cleanup",
            worker_child::worker_sigkill_cleanup,
        ),
        ("cross_shard_isolation", cross_shard_isolation),
    ];
    probes
        .into_iter()
        .map(|(name, probe)| {
            let observed = (|| {
                let runs = *proxy_runs.as_ref().map_err(Clone::clone)?;
                let runs = if name == "proxy_loopback" { runs } else { 1 };
                let mut last = Value::Null;
                for completed in 0..runs {
                    match h.check_deadline().and_then(|()| probe(h)) {
                        Ok(value) => last = value,
                        Err(error) => {
                            if name == "proxy_loopback" && runs > 1 {
                                let _ = config::write_private(
                                    &h.request.log_dir.join("proxy-loopback-repetitions.json"),
                                    &json!({"schema_version":1,"binding":h.binding,"diagnostic":true,
                                        "qualification":false,"expected_iterations":runs,
                                        "completed_iterations":completed,"status":"failed"}),
                                );
                            }
                            return Err(error);
                        }
                    }
                }
                if name == "proxy_loopback" && runs > 1 {
                    last["diagnostic_repetitions"] = json!({"expected_iterations":runs,
                        "completed_iterations":runs,"all_positive_cleanup":true});
                }
                Ok(last)
            })();
            (
                name.to_owned(),
                match observed {
                    Ok(v) => ProbeResult::passed(v),
                    Err(e) => ProbeResult::failed(e),
                },
            )
        })
        .collect()
}

pub(super) fn run_lifecycle_stress(h: &Harness) -> ProbeResult {
    match h.check_deadline().and_then(|()| start_stop_1000(h)) {
        Ok(value) => ProbeResult::passed(value),
        Err(error) => ProbeResult::failed(error),
    }
}
fn start_stop_1000(h: &Harness) -> ProbeResultValue<Value> {
    let mut shards = BTreeSet::new();
    let mut digest = sha2::Sha256::new();
    use sha2::Digest;
    for index in 0..1000 {
        let mut phase = "deadline";
        let iteration = (|| {
            h.check_deadline()?;
            phase = "create_session";
            let session = h.open_session(None)?;
            phase = "unique_generation";
            let key = serde_json::to_vec(&session.shard)
                .map_err(|_| ProbeError::failed("invalid lifecycle shard"))?;
            if !shards.insert(key.clone()) {
                return Err(ProbeError::failed("lifecycle reused a launch generation"));
            }
            phase = "close_session";
            let cleanup = h.close_session(&session)?;
            phase = "record_cleanup";
            digest.update((index as u64).to_be_bytes());
            digest.update(key);
            digest.update(
                serde_json::to_vec(&cleanup)
                    .map_err(|_| ProbeError::failed("invalid cleanup proof"))?,
            );
            Ok(())
        })();
        if let Err(error) = iteration {
            // Retain only the actually completed prefix and a fixed phase. This
            // diagnostic never supplies a lifecycle success or qualification receipt.
            let _ = config::write_private(
                &h.request.log_dir.join("lifecycle-failure.json"),
                &json!({"schema_version":1,"binding":h.binding,"diagnostic":true,
                    "qualification":false,"expected_iterations":1000,
                    "completed_iterations":index,"failure_phase":phase,
                    "rpc_failures":h.rpc.rpc_failures().unwrap_or_default()}),
            );
            return Err(error);
        }
    }
    Ok(
        json!({"iterations":1000,"unique_launch_generations":shards.len(),"all_positive_cleanup":true,"cleanup_receipts_sha256":hex::encode(digest.finalize())}),
    )
}
fn cross_shard_isolation(h: &Harness) -> ProbeResultValue<Value> {
    let a = h.open_session(None)?;
    let b = match h.open_session(None) {
        Ok(b) => b,
        Err(e) => {
            let _ = h.close_session(&a);
            return Err(e);
        }
    };
    let result = (|| {
        if a.shard == b.shard {
            return Err(ProbeError::failed(
                "dedicated probe sessions share a physical shard",
            ));
        }
        let a_process = process::browser_process(h, &a.shard)?;
        let b_process = process::browser_process(h, &b.shard)?;
        if a_process.identity == b_process.identity
            || a_process.net_namespace == b_process.net_namespace
        {
            return Err(ProbeError::failed(
                "cross-shard process/network namespace isolation absent",
            ));
        }
        let private_isolation = network::cross_shard_private_isolation(h, &a, &b)?;
        a.action(
            json!({"type":"navigate","url":h.fixture_url("isolation_a")?,"wait_until":"load"}),
            h.deadline,
        )?;
        let seeded = a.action(json!({"type":"get_title"}), h.deadline)?;
        if seeded.get("title").and_then(Value::as_str) != Some("isolation-a-seeded") {
            return Err(ProbeError::failed(
                "same-origin cookie/storage positive seed control failed",
            ));
        }
        b.action(
            json!({"type":"navigate","url":h.fixture_url("isolation_b")?,"wait_until":"load"}),
            h.deadline,
        )?;
        let b_value = b.action(json!({"type":"get_title"}), h.deadline)?;
        if b_value.get("title").and_then(Value::as_str) != Some("isolation-clean") {
            return Err(ProbeError::failed(
                "cookies/local storage leaked across dedicated shards",
            ));
        }
        Ok(
            json!({"shard_a":a.shard,"shard_b":b.shard,"network_namespaces_distinct":true,"cookie_storage_canary_absent":true,"private_file_socket":private_isolation}),
        )
    })();
    let a_cleanup = h.close_session(&a)?;
    let b_survived = b.action(json!({"type":"get_title"}), h.deadline);
    let b_cleanup = h.close_session(&b)?;
    if b_survived.is_err() {
        return Err(ProbeError::failed(
            "closing one shard interrupted its sibling",
        ));
    }
    result.map(|actual|json!({"actual":actual,"sibling_survived_cleanup":true,"cleanup_a":a_cleanup,"cleanup_b":b_cleanup}))
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn private_loopback_repetition_bound_rejects_invalid_and_nonunicode_overrides() {
        assert!(proxy_repetitions(None).is_ok_and(|count| count == 1));
        for count in [1, 2, 64] {
            let value = count.to_string();
            assert!(
                proxy_repetitions(Some(OsStr::new(&value))).is_ok_and(|actual| actual == count)
            );
        }
        for value in ["", "0", "65", "1000", "+1", "01", "-1", " 1", "1 "] {
            assert!(proxy_repetitions(Some(OsStr::new(value))).is_err());
        }
        assert!(proxy_repetitions(Some(OsStr::from_bytes(&[0xff]))).is_err());
    }
}
