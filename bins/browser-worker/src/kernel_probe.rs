//! Real production kernel observations. This engine never creates a qualification receipt.
mod browser;
mod config;
mod control;
mod fixture;
mod lifecycle;
mod rpc;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use browserd_chromium::{CompatibilityArtifact, VerifiedNativeProfileCatalog};
use browserd_core::{PageId, RuntimeSafetyCache, SessionId, ShardFence, TenantId};
use browserd_session::OwnershipFence;
use browserd_worker::{ChromiumDriver, DependencyError, WorkerSessionOptionsV1};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::{ProductionArtifactStore, ProductionSessionShardFactory, SessionShardRouter};
use config::{DeploymentConfig, EngineRequest};
use rpc::{RecordingSandboxRpc, Trace};

pub(super) const PROBES: [&str; 16] = [
    "chromium_identity",
    "chromium_sandbox",
    "outer_sandbox",
    "context_create_dispose",
    "proxy_loopback",
    "direct_egress_denial",
    "target_pause_resume",
    "context_ownership",
    "emulation",
    "downloads",
    "pdf_streaming",
    "screencast_ack",
    "orphan_targets_zero",
    "start_stop_1000",
    "worker_sigkill_cleanup",
    "cross_shard_isolation",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunBinding {
    pub run_id: String,
    pub tier: String,
    pub manifest_sha256: String,
    pub kernel_release: String,
    pub machine: String,
    pub config_sha256: String,
    pub probe_executable_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_dirty: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_content_sha256: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) enum ProbeError {
    Blocked(String),
    Failed(String),
}
impl ProbeError {
    pub fn blocked(reason: impl Into<String>) -> Self {
        Self::Blocked(reason.into())
    }
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed(reason.into())
    }
    fn reason(&self) -> &str {
        match self {
            Self::Blocked(s) | Self::Failed(s) => s,
        }
    }
}
type ProbeResultValue<T> = Result<T, ProbeError>;

#[derive(Clone, Debug, Serialize)]
pub(super) struct ProbeResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip)]
    observations: Value,
}
impl ProbeResult {
    pub fn passed(observations: Value) -> Self {
        Self {
            status: "passed".into(),
            evidence: None,
            reason: None,
            observations,
        }
    }
    pub fn failed(error: ProbeError) -> Self {
        let status = if matches!(error, ProbeError::Blocked(_)) {
            "blocked"
        } else {
            "failed"
        };
        Self {
            status: status.into(),
            evidence: None,
            reason: Some(error.reason().to_owned()),
            observations: Value::Null,
        }
    }
}

type ProbeRouter =
    SessionShardRouter<ProductionSessionShardFactory<RecordingSandboxRpc>, ProductionArtifactStore>;

struct Harness {
    pub runtime: Runtime,
    pub router: Arc<ProbeRouter>,
    pub rpc: Arc<RecordingSandboxRpc>,
    pub config: DeploymentConfig,
    pub trace: Arc<Trace>,
    pub deadline: Instant,
    pub binding: RunBinding,
    pub artifacts: Arc<ProductionArtifactStore>,
    pub artifact: CompatibilityArtifact,
    pub safety: Arc<RuntimeSafetyCache>,
    pub egress: browser_sandboxd::HttpEgressControl,
    request: EngineRequest,
    fixture: fixture::Fixture,
    sessions: Mutex<BTreeMap<SessionId, OwnedSession>>,
    shutdown: CancellationToken,
    background: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Clone)]
struct OwnedSession {
    pub tenant: TenantId,
    pub session: SessionId,
    pub fence: OwnershipFence,
    pub page: PageId,
    pub shard: ShardFence,
    pub driver: Arc<ProbeRouter>,
}
impl OwnedSession {
    pub fn action(&self, command: Value, deadline: Instant) -> ProbeResultValue<Value> {
        let payload = serde_json::to_vec(&command)
            .map_err(|_| ProbeError::failed("invalid owned probe command"))?;
        match self
            .driver
            .execute_action_until(&self.session, Some(&self.page), &payload, deadline)
        {
            browserd_worker::ActionExecutionResult::Succeeded(bytes) => {
                serde_json::from_slice(&bytes)
                    .map_err(|_| ProbeError::failed("owned action returned invalid JSON"))
            }
            _ => Err(ProbeError::failed("owned browser action did not succeed")),
        }
    }
}

impl Harness {
    pub fn check_deadline(&self) -> ProbeResultValue<()> {
        if Instant::now() >= self.deadline {
            Err(ProbeError::blocked("kernel run deadline reached"))
        } else {
            Ok(())
        }
    }
    pub fn default_options(&self) -> ProbeResultValue<WorkerSessionOptionsV1> {
        VerifiedNativeProfileCatalog::load(Path::new(&self.config.artifact_root), &self.artifact)
            .and_then(|catalog| catalog.process_profile("ko-KR", "Asia/Seoul").map(|_| ()))
            .map_err(|_| {
                ProbeError::blocked(
                    "approved native catalog lacks required ko-KR/Asia-Seoul profile",
                )
            })?;
        Ok(WorkerSessionOptionsV1 {
            workload_class_hint: "production-kernel-probe".into(),
            viewport: browserd_worker::WorkerViewport {
                width: 800,
                height: 600,
                device_scale_factor: 1,
            },
            locale: "ko-KR".into(),
            timezone: "Asia/Seoul".into(),
            user_agent: Some("browserd-production-kernel-probe/1.0".into()),
            network_policy_id: self.config.egress.policy_profile.clone(),
            network_class: "public".into(),
            checkpoint_ref: None,
            dialog_policy: "auto_dismiss".into(),
            feature_profile: if self.privileged_enabled() {
                "privileged"
            } else {
                "standard"
            }
            .into(),
            ttl_seconds: 1800,
            idle_timeout_seconds: 600,
            metadata: BTreeMap::new(),
        })
    }
    pub fn fixture_url(&self, kind: &str) -> ProbeResultValue<String> {
        self.fixture.url(kind)
    }
    pub fn downloads_enabled(&self) -> bool {
        self.config.worker.scanner.is_some()
    }
    pub fn privileged_enabled(&self) -> bool {
        self.config.worker.privileged_evaluate
    }
    pub fn open_session(
        &self,
        options: Option<WorkerSessionOptionsV1>,
    ) -> ProbeResultValue<OwnedSession> {
        self.check_deadline()?;
        let options = options.map_or_else(|| self.default_options(), Ok)?;
        let tenant = TenantId::new();
        let session = SessionId::new();
        let fence = OwnershipFence::new(
            self.config.worker_id()?,
            self.config.sandbox.worker_epoch,
            1,
            1,
        );
        let created = self
            .router
            .create_context_owned_with_options(&tenant, &session, &fence, &options)
            .map_err(|_| ProbeError::failed("production session creation did not succeed"))?;
        let spec = match self.rpc.spec_for_session(&session) {
            Ok(spec) => spec,
            Err(error) => {
                let _ = self.router.close_context_fenced(&session, &fence);
                return Err(error);
            }
        };
        let owned = OwnedSession {
            tenant,
            session: session.clone(),
            fence,
            page: created,
            shard: spec.dedicated_egress().egress_fence().shard().clone(),
            driver: Arc::clone(&self.router),
        };
        match self.sessions.lock() {
            Ok(mut sessions) => {
                sessions.insert(session, owned.clone());
            }
            Err(_) => {
                let _ = self
                    .router
                    .close_context_fenced(&owned.session, &owned.fence);
                return Err(ProbeError::failed("session ownership poisoned"));
            }
        }
        Ok(owned)
    }
    pub fn close_session(&self, session: &OwnedSession) -> ProbeResultValue<Value> {
        if let Err(error) = self
            .router
            .close_context_fenced(&session.session, &session.fence)
        {
            let diagnostic = self
                .router
                .cleanup_failure_summary(&session.tenant, &session.session, &session.fence)
                .ok()
                .flatten();
            let _ = write_cleanup_failure(
                &self.request,
                &session.session,
                &session.shard,
                error,
                diagnostic.as_ref(),
                &self.rpc.rpc_failures().unwrap_or_default(),
                &self
                    .rpc
                    .cleanup_outcomes(&session.shard)
                    .unwrap_or_default(),
            );
            return Err(ProbeError::failed(
                "exact production context/shard cleanup incomplete",
            ));
        }
        let evidence = lifecycle::verify_cleanup(self, &session.shard)?;
        self.sessions
            .lock()
            .map_err(|_| ProbeError::failed("session ownership poisoned"))?
            .remove(&session.session);
        Ok(evidence)
    }
    pub fn adopt_worker_session(
        &self,
        tenant: TenantId,
        created: &browserd_worker::CreateSessionOutcome,
    ) -> ProbeResultValue<OwnedSession> {
        if created.effective_isolation != browserd_worker::WorkerIsolationProfile::DedicatedProcess
            || created.fence.worker_id() != &self.config.worker_id()?
            || created.fence.worker_epoch() != self.config.sandbox.worker_epoch
        {
            return Err(ProbeError::failed(
                "actual Worker session is not owned by this dedicated production run",
            ));
        }
        let spec = self.rpc.spec_for_session(&created.session_id)?;
        if spec.worker_id() != created.fence.worker_id()
            || spec.worker_epoch() != created.fence.worker_epoch()
            || spec.tenant_id() != &tenant
            || spec
                .dedicated_egress()
                .egress_fence()
                .session_incarnation()
                .get()
                != created.fence.session_incarnation()
        {
            return Err(ProbeError::failed(
                "actual Worker session and full recorded launch fence disagree",
            ));
        }
        let owned = OwnedSession {
            tenant,
            session: created.session_id.clone(),
            fence: created.fence.clone(),
            page: created.primary_page_id.clone(),
            shard: spec.dedicated_egress().egress_fence().shard().clone(),
            driver: Arc::clone(&self.router),
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| ProbeError::failed("session ownership poisoned"))?;
        if sessions.contains_key(&owned.session) {
            return Err(ProbeError::failed(
                "Worker session already adopted by this run",
            ));
        }
        sessions.insert(owned.session.clone(), owned.clone());
        Ok(owned)
    }
    pub fn finish_worker_session(&self, session: &OwnedSession) -> ProbeResultValue<Value> {
        let evidence = lifecycle::verify_cleanup(self, &session.shard)?;
        self.sessions
            .lock()
            .map_err(|_| ProbeError::failed("session ownership poisoned"))?
            .remove(&session.session);
        Ok(evidence)
    }
    pub fn read_generated(
        &self,
        receipt: &browserd_worker::ArtifactStoreReceipt,
    ) -> ProbeResultValue<Vec<u8>> {
        use crate::RoutedArtifactStore;
        let owned = self
            .sessions
            .lock()
            .map_err(|_| ProbeError::failed("session ownership poisoned"))?
            .get(receipt.key().session_id())
            .cloned()
            .ok_or_else(|| ProbeError::failed("generated artifact has no owned session"))?;
        let metadata = browserd_artifacts::ArtifactContentMetadata::new(
            receipt.size_bytes(),
            *receipt.checksum(),
            receipt.detected_content_type().to_owned(),
            receipt.source(),
            "production-kernel-probe",
        )
        .map_err(|_| ProbeError::failed("invalid generated artifact metadata"))?;
        let request = browserd_worker::ArtifactReadRequest::new(
            receipt.key().clone(),
            owned.fence,
            metadata,
            receipt.object_generation(),
            65536,
        )
        .map_err(|_| ProbeError::failed("invalid generated read"))?;
        let mut reader = self
            .artifacts
            .open_read(&request)
            .map_err(|_| ProbeError::failed("generated artifact read rejected"))?;
        let mut bytes = Vec::new();
        while let Some(chunk) = reader
            .next_chunk()
            .map_err(|_| ProbeError::failed("generated artifact read failed"))?
        {
            if bytes.len().saturating_add(chunk.len()) > 32 * 1024 * 1024 {
                return Err(ProbeError::failed("generated artifact exceeded bound"));
            }
            bytes.extend(chunk);
        }
        Ok(bytes)
    }
}

/// Execute only a bound private request; caller receives no invented qualification receipt.
pub fn run_kernel_probe(request: &Path, response: &Path) -> Result<u8, String> {
    run_measurement(request, response, false)
}

/// Bounded actual native diagnostics. This response cannot qualify a kernel run.
pub fn run_kernel_preflight(request: &Path, response: &Path) -> Result<u8, String> {
    run_measurement(request, response, true)
}

fn write_structural_failure(
    request: &EngineRequest,
    spec_count: usize,
    failures: &[rpc::RpcFailure],
    error: DependencyError,
    cdp_trace: Option<&Trace>,
) -> ProbeResultValue<()> {
    // Match the safe enum explicitly rather than formatting an error that may
    // acquire external string fields in a future dependency change.
    let variant = match error {
        DependencyError::Unavailable => "Unavailable",
        DependencyError::Rejected => "Rejected",
        DependencyError::OutcomeUncertain => "OutcomeUncertain",
    };
    let mut value = json!({"schema_version":1,"binding":request.binding,
        "diagnostic":true,"qualification":false,"spec_count":spec_count,
        "rpc_failures":failures,"qualification_error":{
            "variant":variant,"debug":format!("DependencyError::{variant}")}});
    if let Some(trace) = cdp_trace {
        value["cdp_failure"] = trace.failure_summary();
    }
    config::write_private(&request.log_dir.join("structural-failure.json"), &value)
}

fn bounded_cleanup_diagnostic(diagnostic: &Value) -> Value {
    let mut safe = json!({});
    for (key, allowed) in [
        (
            "stage",
            &[
                "idle",
                "coordinated",
                "coordinated_timeout",
                "coordinated_complete",
                "owner_verification",
                "owner_deadline_elapsed",
                "complete",
                "panicked",
            ][..],
        ),
        (
            "final_error",
            &["Rejected", "Unavailable", "OutcomeUncertain"][..],
        ),
    ] {
        if let Some(value) = diagnostic.get(key).and_then(Value::as_str)
            && allowed.contains(&value)
        {
            safe[key] = json!(value);
        }
    }
    let variants = [
        "Rejected",
        "Unavailable",
        "Cancelled",
        "OutcomeUncertain",
        "Runtime",
        "InvalidConfiguration",
        "StaleShardFence",
        "StaleSessionFence",
        "InvalidLifecycle",
        "AdmissionClosed",
        "CapacityExceeded",
        "SessionNotFound",
        "MailboxFull",
        "OwnershipLost",
        "ActorStopped",
    ];
    for key in [
        "actor_shutdown",
        "actor_join",
        "exact_termination",
        "owner_shutdown",
    ] {
        let Some(input) = diagnostic.get(key) else {
            continue;
        };
        let mut result = json!({});
        for (field, allowed) in [
            (
                "outcome",
                &["ok", "error", "panic", "cancelled", "missing"][..],
            ),
            ("variant", &variants[..]),
            (
                "runtime_variant",
                &["Rejected", "Unavailable", "Cancelled", "OutcomeUncertain"][..],
            ),
        ] {
            if let Some(value) = input.get(field).and_then(Value::as_str)
                && allowed.contains(&value)
            {
                result[field] = json!(value);
            }
        }
        if result.as_object().is_some_and(|object| !object.is_empty()) {
            safe[key] = result;
        }
    }
    for key in ["forced_confirmation", "owner_joined_after_exact"] {
        if let Some(value) = diagnostic.get(key).and_then(Value::as_bool) {
            safe[key] = json!(value);
        }
    }
    safe
}

fn write_cleanup_failure(
    request: &EngineRequest,
    session: &SessionId,
    shard: &ShardFence,
    error: DependencyError,
    diagnostic: Option<&Value>,
    rpc_failures: &[rpc::RpcFailure],
    cleanup_outcomes: &[rpc::CleanupOutcome],
) -> ProbeResultValue<()> {
    let variant = match error {
        DependencyError::Rejected => "Rejected",
        DependencyError::Unavailable => "Unavailable",
        DependencyError::OutcomeUncertain => "OutcomeUncertain",
    };
    let value = json!({"schema_version":1,"binding":request.binding,
        "diagnostic":true,"qualification":false,"shard":shard,
        "cleanup_error":variant,"cleanup_attempt":diagnostic.map(bounded_cleanup_diagnostic),
        "rpc_failures":rpc_failures,"cleanup_outcomes":cleanup_outcomes});
    config::write_private(
        &request
            .log_dir
            .join(format!("cleanup-failure-{session}.json")),
        &value,
    )
}

fn run_measurement(request: &Path, response: &Path, preflight: bool) -> Result<u8, String> {
    let request = config::read_request(request).map_err(|error| error.reason().to_owned())?;
    let response_name = if preflight {
        "preflight-response.json"
    } else {
        "production-response.json"
    };
    if response != request.log_dir.join(response_name) {
        return Err("engine response must be the current private run response path".to_owned());
    }
    let approved = config::load_approved(&request);
    let mut results = BTreeMap::new();
    let mut cleanup_complete = true;
    match approved.and_then(|approved| lifecycle::open_harness(&request, approved)) {
        Ok(mut harness) => {
            if preflight {
                // Actual executable and mounted-runtime attestation hashes the complete
                // approved files. Keep that diagnostic bounded without truncating its
                // fifteen functional probes on devices using unoptimized binaries.
                harness.deadline = harness
                    .deadline
                    .min(Instant::now() + std::time::Duration::from_secs(900));
            }
            if let Err(error) = ChromiumDriver::qualify(harness.router.as_ref()) {
                // Diagnostic publication must never alter qualification,
                // cleanup or the existing strict production/preflight result.
                let _ = harness.rpc.spec_count().and_then(|spec_count| {
                    let failures = harness.rpc.rpc_failures()?;
                    write_structural_failure(
                        &request,
                        spec_count,
                        &failures,
                        error,
                        Some(&harness.trace),
                    )
                });
                for name in PROBES {
                    results.insert(
                        name.to_owned(),
                        ProbeResult::failed(ProbeError::blocked(
                            "production structural qualification failed",
                        )),
                    );
                }
            } else {
                results.extend(if preflight {
                    lifecycle::run_foundation_preflight_probes(&harness)
                } else {
                    lifecycle::run_foundation_probes(&harness)
                });
                results.extend(browser::run_behavior_probes(&harness));
                if !preflight {
                    results.insert(
                        "start_stop_1000".to_owned(),
                        lifecycle::run_lifecycle_stress(&harness),
                    );
                }
            }
            cleanup_complete = lifecycle::finish_harness(&mut harness);
        }
        Err(error) => {
            for name in PROBES {
                results.insert(name.to_owned(), ProbeResult::failed(error.clone()));
            }
        }
    }
    if preflight {
        results.remove("start_stop_1000");
    }
    for (name, result) in &mut results {
        if result.status == "passed" {
            let evidence = request.log_dir.join(format!("{name}.json"));
            config::write_private(
                &evidence,
                &json!({"schema_version":1,"binding":request.binding,"probe":name,
                "status":"passed","observations":result.observations}),
            )
            .map_err(|error| error.reason().to_owned())?;
            result.evidence = Some(evidence);
        }
    }
    let status = if !cleanup_complete || results.values().any(|r| r.status == "failed") {
        "failed"
    } else if results.values().all(|r| r.status == "passed") {
        "passed"
    } else {
        "blocked"
    };
    let value = if preflight {
        json!({"schema_version":1,"binding":request.binding,
        "status":if status == "passed" {"preflight_completed"} else {status},
        "diagnostic":true,"qualification":false,"cleanup_complete":cleanup_complete,
        "observations":results,"omitted_probes":["start_stop_1000"]})
    } else {
        json!({"schema_version":1,"binding":request.binding,"status":status,
        "cleanup_complete":cleanup_complete,"probes":results})
    };
    config::write_private(response, &value).map_err(|error| error.reason().to_owned())?;
    Ok(match status {
        "passed" => 0,
        "failed" => 1,
        _ => 2,
    })
}

/// Private subprocess entry used only for this engine's admitted Worker and namespace helpers.
pub fn run_probe_helper(kind: &str, input: &Path) -> Result<(), String> {
    match kind {
        "worker" => lifecycle::worker_child_main(input),
        "namespace" => lifecycle::namespace_helper_main(input),
        _ => Err("invalid private probe helper kind".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn request(directory: &Path) -> Value {
        json!({"schema_version":1,"binding":{
            "run_id":uuid::Uuid::new_v4().to_string(),"tier":"kernel",
            "manifest_sha256":"a".repeat(64),
            "kernel_release":std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim_end(),
            "machine":std::env::consts::ARCH,"config_sha256":"b".repeat(64),
            "probe_executable_sha256":"c".repeat(64),
            "source_revision":"d".repeat(40),"source_dirty":true,"source_content_sha256":"e".repeat(64)},
            "config_path":directory.join("absent-approval.json"),"log_dir":directory,"deadline_seconds":7200})
    }

    #[test]
    fn cleanup_failure_is_private_bound_exclusive_and_omits_external_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let request: EngineRequest = serde_json::from_value(request(directory.path()))?;
        let session = SessionId::new();
        let shard = ShardFence::new(
            browserd_core::OwnerFence::new(
                browserd_core::WorkerId::new("cleanup-diagnostic")?,
                browserd_core::WorkerEpoch::new(1).ok_or("epoch")?,
            ),
            browserd_core::ShardId::new(),
            browserd_core::LaunchGeneration::new(1).ok_or("generation")?,
        );
        let secret = "external-URL-token-request-session-and-panic-content";
        let diagnostic = json!({"stage":"owner_verification","final_error":"OutcomeUncertain",
            "actor_shutdown":{"outcome":"error","variant":"Runtime","runtime_variant":"OutcomeUncertain","message":secret},
            "actor_join":{"outcome":"panic","panic_payload":secret},
            "exact_termination":{"outcome":"ok"},"forced_confirmation":true,
            "owner_shutdown":{"outcome":"error","variant":"OutcomeUncertain","URL":secret},
            "owner_joined_after_exact":false,"sessionId":secret,"payload":secret.repeat(8192)});
        write_cleanup_failure(
            &request,
            &session,
            &shard,
            DependencyError::OutcomeUncertain,
            Some(&diagnostic),
            &[],
            &[],
        )
        .map_err(|error| error.reason().to_owned())?;
        let path = directory
            .path()
            .join(format!("cleanup-failure-{session}.json"));
        let bytes = std::fs::read(&path)?;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        let report: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(report["binding"], serde_json::to_value(&request.binding)?);
        assert_eq!(report["shard"], serde_json::to_value(&shard)?);
        assert_eq!(report["diagnostic"], true);
        assert_eq!(report["qualification"], false);
        assert_eq!(report["cleanup_error"], "OutcomeUncertain");
        assert_eq!(
            report["cleanup_attempt"]["actor_shutdown"]["variant"],
            "Runtime"
        );
        assert_eq!(report["cleanup_attempt"]["actor_join"]["outcome"], "panic");
        assert_eq!(report["cleanup_attempt"]["owner_joined_after_exact"], false);
        assert!(!String::from_utf8(bytes.clone())?.contains(secret));
        assert!(bytes.len() < 4096);
        assert!(
            write_cleanup_failure(
                &request,
                &session,
                &shard,
                DependencyError::Rejected,
                None,
                &[],
                &[]
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path)?, bytes);
        for name in [
            "receipt.json",
            "preflight-response.json",
            "production-response.json",
        ] {
            assert!(!directory.path().join(name).exists());
        }
        Ok(())
    }

    #[test]
    fn cleanup_diagnostic_rejects_unknown_variants_and_arbitrary_shapes() {
        let secret = "arbitrary-backend-credential-and-address";
        let safe = bounded_cleanup_diagnostic(&json!({
            "stage":secret,"final_error":secret,
            "actor_shutdown":{"outcome":secret,"variant":secret,"runtime_variant":secret},
            "actor_join":[secret],"exact_termination":secret,
            "owner_shutdown":{"outcome":"error","variant":"Cancelled","details":secret},
            "forced_confirmation":secret,"owner_joined_after_exact":{"value":secret},"extra":secret,
        }));
        assert_eq!(
            safe,
            json!({"owner_shutdown":{"outcome":"error","variant":"Cancelled"}})
        );
        assert_eq!(bounded_cleanup_diagnostic(&Value::Null), json!({}));
    }

    #[test]
    fn structural_failure_is_private_exclusive_and_cannot_publish_qualification()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let request: EngineRequest = serde_json::from_value(request(directory.path()))?;
        write_structural_failure(&request, 7, &[], DependencyError::Rejected, None)
            .map_err(|error| error.reason().to_owned())?;
        let path = directory.path().join("structural-failure.json");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        let bytes = std::fs::read(&path)?;
        let report: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(report["binding"], serde_json::to_value(&request.binding)?);
        assert_eq!(report["diagnostic"], true);
        assert_eq!(report["qualification"], false);
        assert_eq!(report["spec_count"], 7);
        assert_eq!(report["rpc_failures"], json!([]));
        assert_eq!(report["qualification_error"]["variant"], "Rejected");
        assert_eq!(
            report["qualification_error"]["debug"],
            "DependencyError::Rejected"
        );
        assert!(
            write_structural_failure(&request, 99, &[], DependencyError::Unavailable, None)
                .is_err()
        );
        assert_eq!(std::fs::read(path)?, bytes);
        for name in [
            "receipt.json",
            "preflight-response.json",
            "production-response.json",
        ] {
            assert!(!directory.path().join(name).exists());
        }
        Ok(())
    }

    #[test]
    fn structural_failure_includes_only_the_optional_bounded_cdp_diagnostic()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let request: EngineRequest = serde_json::from_value(request(directory.path()))?;
        let trace = Trace::default();
        write_structural_failure(
            &request,
            1,
            &[],
            DependencyError::OutcomeUncertain,
            Some(&trace),
        )
        .map_err(|error| error.reason().to_owned())?;
        let path = directory.path().join("structural-failure.json");
        let report: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(report["cdp_failure"], trace.failure_summary());
        assert_eq!(report["cdp_failure"]["sequence"], 0);
        assert_eq!(report["qualification"], false);
        assert_eq!(report["qualification_error"]["variant"], "OutcomeUncertain");
        assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        assert!(!directory.path().join("receipt.json").exists());
        assert!(!directory.path().join("preflight-response.json").exists());
        Ok(())
    }

    #[test]
    fn missing_approval_reports_all_probes_blocked_with_exact_source_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let input = directory.path().join("production-request.json");
        let output = directory.path().join("production-response.json");
        let value = request(directory.path());
        config::write_private(&input, &value).map_err(|error| error.reason().to_owned())?;
        assert_eq!(run_kernel_probe(&input, &output)?, 2);
        let response: Value = serde_json::from_slice(&std::fs::read(&output)?)?;
        assert_eq!(response["binding"], value["binding"]);
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["cleanup_complete"], true);
        let probes = response["probes"].as_object().ok_or("probe map absent")?;
        assert_eq!(probes.len(), PROBES.len());
        for name in PROBES {
            assert_eq!(probes[name]["status"], "blocked");
            assert!(probes[name].get("evidence").is_none());
        }
        assert!(!directory.path().join("receipt.json").exists());
        assert!(!directory.path().join("structural-failure.json").exists());
        Ok(())
    }

    #[test]
    fn preflight_cannot_publish_a_production_response_or_qualification_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let input = directory.path().join("preflight-request.json");
        let value = request(directory.path());
        config::write_private(&input, &value).map_err(|error| error.reason().to_owned())?;
        assert!(
            run_kernel_preflight(&input, &directory.path().join("production-response.json"))
                .is_err()
        );
        let output = directory.path().join("preflight-response.json");
        assert_eq!(run_kernel_preflight(&input, &output)?, 2);
        let response: Value = serde_json::from_slice(&std::fs::read(output)?)?;
        assert_eq!(response["binding"], value["binding"]);
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["diagnostic"], true);
        assert_eq!(response["qualification"], false);
        assert_eq!(response["cleanup_complete"], true);
        assert_eq!(response["omitted_probes"], json!(["start_stop_1000"]));
        let observations = response["observations"]
            .as_object()
            .ok_or("diagnostic observations absent")?;
        assert_eq!(observations.len(), 15);
        assert!(!observations.contains_key("start_stop_1000"));
        assert!(
            observations
                .values()
                .all(|value| value["status"] == "blocked")
        );
        assert!(response.get("probes").is_none());
        assert!(!directory.path().join("production-response.json").exists());
        assert!(!directory.path().join("receipt.json").exists());
        assert!(!directory.path().join("structural-failure.json").exists());
        Ok(())
    }

    #[test]
    fn dirty_request_without_content_identity_and_foreign_response_are_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let input = directory.path().join("production-request.json");
        let mut value = request(directory.path());
        value["binding"]
            .as_object_mut()
            .ok_or("binding absent")?
            .remove("source_content_sha256");
        config::write_private(&input, &value).map_err(|error| error.reason().to_owned())?;
        assert!(
            run_kernel_probe(&input, &directory.path().join("production-response.json")).is_err()
        );
        std::fs::remove_file(&input)?;
        config::write_private(&input, &request(directory.path()))
            .map_err(|error| error.reason().to_owned())?;
        assert!(run_kernel_probe(&input, &directory.path().join("foreign-response.json")).is_err());
        assert!(!directory.path().join("foreign-response.json").exists());
        Ok(())
    }

    #[test]
    fn process_wire_identity_preserves_start_time_and_rejects_ambiguous_pids()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = browserd_sandbox::ChildIdentity::new(12345, 9876);
        let encoded = serde_json::to_value(identity)?;
        assert_eq!(
            serde_json::from_value::<browserd_sandbox::ChildIdentity>(encoded)?,
            identity
        );
        for invalid in [
            json!({"pid":0,"start_time_ticks":9876}),
            json!({"pid":12345,"start_time_ticks":0}),
            json!({"pid":12345,"start_time_ticks":9876,"extra":true}),
        ] {
            assert!(serde_json::from_value::<browserd_sandbox::ChildIdentity>(invalid).is_err());
        }
        Ok(())
    }
}
