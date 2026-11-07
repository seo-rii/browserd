//! Isolated durable worker authority for production publication probes.
use super::lifecycle::private_subdirectory;
use super::{Harness, ProbeError, ProbeResultValue, ProbeRouter};
use browserd_observability::{AuditWal, AuditWalPolicy};
use browserd_session::{LeasePolicy, SessionTimeoutPolicy};
use browserd_worker::{
    ActionJournalConfig, ActionJournalPool, ActionJournalPoolConfig, AuthenticatedPeer,
    ControlEventJournal, InternalEndpoint, SessionEventJournal, SessionOptionSupport,
    WorkerArtifactLimits, WorkerConfig, WorkerControlPlane,
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub(super) type ProbeWorker = WorkerControlPlane<ProbeRouter, ProbeRouter>;

/// Uses the actual router, scanner-backed artifact store, journals, and observed safety authority.
/// No runtime download timer is started: the probe witnesses exact pending scratch before it
/// explicitly invokes the same publication operation that production maintenance invokes.
pub(super) fn open_worker(
    h: &Harness,
    state: &Path,
) -> ProbeResultValue<(Arc<ProbeWorker>, AuthenticatedPeer)> {
    let run_root = h.config.worker.state_root.join(&h.binding.run_id);
    if state != run_root.join("downloads-control")
        && state != run_root.join("worker-child").join("control")
    {
        return Err(ProbeError::blocked(
            "worker authority state escapes the current probe run",
        ));
    }
    private_subdirectory(state)?;
    let actions = state.join("actions");
    private_subdirectory(&actions)?;
    let peer = AuthenticatedPeer::new(format!("kernel-probe-{}", h.binding.run_id))
        .map_err(|_| ProbeError::failed("worker probe peer identity invalid"))?;
    let worker_config = WorkerConfig::new(
        h.config.worker_id()?,
        h.config.sandbox.worker_epoch,
        InternalEndpoint::unix(state.join("w.sock"))
            .map_err(|_| ProbeError::blocked("worker probe socket path invalid or too long"))?,
        peer.clone(),
        h.config.worker.max_session_count,
        128,
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(3))
            .map_err(|_| ProbeError::failed("worker probe lease bounds invalid"))?,
        SessionTimeoutPolicy::new(Duration::from_secs(1800), Duration::from_secs(600))
            .map_err(|_| ProbeError::failed("worker probe session bounds invalid"))?,
        Duration::from_secs(300),
        ActionJournalConfig::with_default_limits(&actions)
            .map_err(|_| ProbeError::failed("worker probe action journal configuration invalid"))?,
    )
    .map_err(|_| ProbeError::failed("worker probe configuration invalid"))?
    .with_session_option_support(SessionOptionSupport::single_host_default())
    .with_artifact_limits(
        WorkerArtifactLimits::new(8 * 1024 * 1024, 16 * 1024 * 1024, 8 * 1024 * 1024)
            .map_err(|_| ProbeError::failed("worker probe artifact limits invalid"))?,
    );
    let audit = Arc::new(
        AuditWal::open(
            state.join("audit.wal"),
            AuditWalPolicy::new(64 * 1024 * 1024, 65536)
                .map_err(|_| ProbeError::failed("worker probe audit bounds invalid"))?,
        )
        .map_err(|_| ProbeError::failed("worker probe durable audit unavailable"))?,
    );
    let pool = ActionJournalPool::open(
        ActionJournalPoolConfig::new(actions, Default::default())
            .map_err(|_| ProbeError::failed("worker probe action pool config invalid"))?,
        h.config.worker_id()?,
    )
    .map_err(|_| ProbeError::failed("worker probe durable action pool unavailable"))?;
    let control = Arc::new(
        ControlEventJournal::open(&state.join("control.journal"), 1024, 65536, 8 * 1024 * 1024)
            .map_err(|_| ProbeError::failed("worker probe durable control journal unavailable"))?,
    );
    control
        .enable_notifications(&h.config.worker_id()?)
        .map_err(|_| ProbeError::failed("worker probe control notification binding rejected"))?;
    let sessions = Arc::new(
        SessionEventJournal::open(
            &state.join("sessions.journal"),
            4096,
            16384,
            32 * 1024 * 1024,
        )
        .map_err(|_| ProbeError::failed("worker probe durable session journal unavailable"))?,
    );
    sessions
        .bind_worker(&h.config.worker_id()?)
        .map_err(|_| ProbeError::failed("worker probe session notification binding rejected"))?;
    let worker = Arc::new(
        WorkerControlPlane::new(worker_config, Arc::clone(&h.router), Arc::clone(&h.router))
            .with_audit_wal(audit)
            .with_action_journal_pool(pool)
            .with_control_event_journal(control)
            .with_session_event_journal(sessions)
            .with_runtime_safety_cache(
                Arc::clone(&h.safety),
                h.artifact.identity.binary_digest.to_string(),
            )
            .map_err(|_| ProbeError::failed("worker probe runtime safety binding rejected"))?,
    );
    if !worker.is_ready() {
        return Err(ProbeError::blocked(
            "actual worker probe dependencies are not ready",
        ));
    }
    Ok((worker, peer))
}
