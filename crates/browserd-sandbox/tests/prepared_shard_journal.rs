#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::fs::{self, OpenOptions};
use std::future::pending;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, PreparedShardState, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    FilePreparedShardJournal, PreparedShardCleanupStage, PreparedShardCleanupStageStatus,
    PreparedShardEffect, PreparedShardEffectPermit, PreparedShardJournalError,
    PreparedShardJournalLimits, PreparedShardJournalRecord, PreparedShardRecoveryBackend,
    PreparedShardRecoveryDisposition, PreparedShardRecoveryError, PreparedShardRecoveryLocators,
    StartupPreparedShardReconciler,
};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use sha2::{Digest, Sha256};

const RECORD_MAGIC_BYTES: usize = 8;
const RECORD_LENGTH_BYTES: usize = 4;

fn rewrite_stable_record(directory: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let path = fs::read_dir(directory)
        .expect("journal directory must be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|extension| extension == "psj"))
        .expect("stable prepared-shard record must exist");
    rewrite_record_file(&path, mutate);
}

fn rewrite_fenced_record(
    directory: &Path,
    fence: &ShardFence,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    rewrite_record_file(
        &directory.join(format!("{}.psj", fence_record_key(fence))),
        mutate,
    );
}

fn rewrite_record_file(path: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let bytes = fs::read(path).expect("stable record must be readable");
    let payload_length = u32::from_be_bytes(
        bytes[RECORD_MAGIC_BYTES..RECORD_MAGIC_BYTES + RECORD_LENGTH_BYTES]
            .try_into()
            .expect("record length must be encoded"),
    ) as usize;
    let payload_start = RECORD_MAGIC_BYTES + RECORD_LENGTH_BYTES;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes[payload_start..payload_start + payload_length])
            .expect("record payload must be JSON");
    mutate(&mut value);
    let payload = serde_json::to_vec(&value).expect("mutated record must encode");
    let payload_length = u32::try_from(payload.len()).expect("fixture payload must be bounded");
    let checksum = Sha256::digest(&payload);
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("stable record must be writable by the corruption fixture");
    file.write_all(b"BRPSJ001")
        .expect("record magic must be written");
    file.write_all(&payload_length.to_be_bytes())
        .expect("record length must be written");
    file.write_all(&payload)
        .expect("record payload must be written");
    file.write_all(&checksum)
        .expect("record checksum must be written");
    file.sync_all().expect("corrupt record must be durable");
}

fn shard_fence() -> ShardFence {
    ShardFence::new(
        OwnerFence::new(
            WorkerId::new("worker-journal-a").expect("worker identity must be valid"),
            WorkerEpoch::new(17).expect("worker epoch must be positive"),
        ),
        ShardId::new(),
        LaunchGeneration::new(3).expect("launch generation must be positive"),
    )
}

fn fence_record_key(fence: &ShardFence) -> String {
    let worker = fence.owner().worker_id().as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"browserd-prepared-shard-journal-key-v1");
    hasher.update(
        u16::try_from(worker.len())
            .expect("worker identity is bounded")
            .to_be_bytes(),
    );
    hasher.update(worker);
    hasher.update(fence.owner().worker_epoch().get().to_be_bytes());
    hasher.update(fence.shard_id().as_bytes());
    hasher.update(fence.launch_generation().get().to_be_bytes());
    format!("{:x}", hasher.finalize())
}

fn advance_to_release_intent(
    journal: &FilePreparedShardJournal,
    fence: &ShardFence,
    locators: PreparedShardRecoveryLocators,
    release_sequence: u64,
) -> PreparedShardEffectPermit {
    let mut record = journal
        .reserve(fence.clone(), locators)
        .expect("fence reservation must be durable");
    let egress_fence = EgressFence::new(
        fence.clone(),
        RouteGeneration::new(5).expect("route generation must be positive"),
        SessionId::new(),
        SessionIncarnation::new(2).expect("session incarnation must be positive"),
    );
    let preparation = [
        PreparedShardEffect::CreateFilesystemCgroup,
        PreparedShardEffect::SpawnGatedChild,
        PreparedShardEffect::ProveProcessIdentity,
        PreparedShardEffect::AttachCgroup,
        PreparedShardEffect::ProveNetworkNamespace,
        PreparedShardEffect::RegisterIngress(egress_fence),
        PreparedShardEffect::ClaimCdp,
        PreparedShardEffect::ProveContainment,
    ];
    for effect in preparation {
        let permit = journal
            .begin_effect(fence, record.sequence(), effect)
            .expect("preparation intent must be durable");
        record = journal
            .complete_effect(&permit)
            .expect("preparation completion must be durable");
    }
    journal
        .begin_effect(
            fence,
            record.sequence(),
            PreparedShardEffect::SendReleaseToken { release_sequence },
        )
        .expect("release intent must be durable before token send")
}

#[derive(Default)]
struct HangingRevokeBackend {
    hang_revoke: AtomicBool,
    calls: Mutex<Vec<PreparedShardCleanupStage>>,
}

#[derive(Default)]
struct GatedRevokeBackend {
    revoke_started: tokio::sync::Notify,
    release_revoke: tokio::sync::Notify,
}

#[derive(Default)]
struct FailingDeathProofBackend {
    calls: Mutex<Vec<PreparedShardCleanupStage>>,
}

#[derive(Default)]
struct FailingEgressDrainBackend {
    calls: Mutex<Vec<PreparedShardCleanupStage>>,
}

#[derive(Default)]
struct PanickingRevokeBackend {
    calls: Mutex<Vec<PreparedShardCleanupStage>>,
}

struct ConcurrentShardBackend {
    slow_fence: ShardFence,
    slow_revoke_started: tokio::sync::Notify,
    release_slow_revoke: tokio::sync::Notify,
    fast_kill_started: tokio::sync::Notify,
}

#[derive(Default)]
struct BoundedRevokeBackend {
    active: AtomicUsize,
    maximum_active: AtomicUsize,
    revoke_started: AtomicUsize,
    released: AtomicBool,
    state_changed: tokio::sync::Notify,
}

#[async_trait]
impl PreparedShardRecoveryBackend for BoundedRevokeBackend {
    async fn run_stage(
        &self,
        _record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError> {
        if stage == PreparedShardCleanupStage::RevokeEgress {
            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            self.maximum_active.fetch_max(active, Ordering::AcqRel);
            self.revoke_started.fetch_add(1, Ordering::AcqRel);
            self.state_changed.notify_waiters();
            while !self.released.load(Ordering::Acquire) {
                let changed = self.state_changed.notified();
                if self.released.load(Ordering::Acquire) {
                    break;
                }
                changed.await;
            }
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
        Ok(())
    }
}

#[async_trait]
impl PreparedShardRecoveryBackend for ConcurrentShardBackend {
    async fn run_stage(
        &self,
        record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError> {
        if record.fence() == &self.slow_fence && stage == PreparedShardCleanupStage::RevokeEgress {
            self.slow_revoke_started.notify_one();
            self.release_slow_revoke.notified().await;
        } else if record.fence() != &self.slow_fence
            && stage == PreparedShardCleanupStage::KillCgroup
        {
            self.fast_kill_started.notify_one();
        }
        Ok(())
    }
}

#[async_trait]
impl PreparedShardRecoveryBackend for PanickingRevokeBackend {
    async fn run_stage(
        &self,
        _record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(stage);
        if stage == PreparedShardCleanupStage::RevokeEgress {
            panic!("injected revoke panic");
        }
        Ok(())
    }
}

#[async_trait]
impl PreparedShardRecoveryBackend for FailingDeathProofBackend {
    async fn run_stage(
        &self,
        _record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(stage);
        if matches!(
            stage,
            PreparedShardCleanupStage::KillCgroup | PreparedShardCleanupStage::ConfirmProcessDeath
        ) {
            Err(PreparedShardRecoveryError::new())
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl PreparedShardRecoveryBackend for FailingEgressDrainBackend {
    async fn run_stage(
        &self,
        _record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(stage);
        if stage == PreparedShardCleanupStage::ConfirmEgressDrained {
            Err(PreparedShardRecoveryError::new())
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl PreparedShardRecoveryBackend for GatedRevokeBackend {
    async fn run_stage(
        &self,
        _record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError> {
        if stage == PreparedShardCleanupStage::RevokeEgress {
            self.revoke_started.notify_one();
            self.release_revoke.notified().await;
        }
        Ok(())
    }
}

impl HangingRevokeBackend {
    fn set_revoke_hang(&self, hang: bool) {
        self.hang_revoke.store(hang, Ordering::Release);
    }

    fn calls(&self) -> Vec<PreparedShardCleanupStage> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[async_trait]
impl PreparedShardRecoveryBackend for HangingRevokeBackend {
    async fn run_stage(
        &self,
        _record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(stage);
        if stage == PreparedShardCleanupStage::RevokeEgress
            && self.hang_revoke.load(Ordering::Acquire)
        {
            pending::<()>().await;
        }
        Ok(())
    }
}

#[test]
fn crash_after_cgroup_creation_intent_is_recovered_as_cleanup_only() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let locators = PreparedShardRecoveryLocators::new(
        "backend-token-cgroup",
        PathBuf::from("/sys/fs/cgroup/browserd/shard-cgroup"),
        PathBuf::from("/run/browserd/shards/shard-cgroup"),
    )
    .expect("recovery locators must be valid");
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    let reserved = journal
        .reserve(fence.clone(), locators)
        .expect("fence reservation must be durable");

    let permit = journal
        .begin_effect(
            &fence,
            reserved.sequence(),
            PreparedShardEffect::CreateFilesystemCgroup,
        )
        .expect("effect intent must be durable before creating the cgroup");
    assert_eq!(permit.sequence().get(), 2);
    drop(journal);

    let reopened = FilePreparedShardJournal::open(directory.path())
        .expect("prepared-shard journal must reopen");
    let records = reopened
        .records()
        .expect("durable records must be recoverable");

    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].pending_effect(),
        Some(&PreparedShardEffect::CreateFilesystemCgroup)
    );
    assert_eq!(
        records[0].recovery_disposition(),
        PreparedShardRecoveryDisposition::CleanupOnly
    );
}

#[test]
fn legacy_cleanup_effects_cannot_bypass_the_evidenced_cleanup_protocol() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            fence,
            PreparedShardRecoveryLocators::new(
                "backend-token-no-cleanup-bypass",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-no-cleanup-bypass"),
                PathBuf::from("/run/browserd/shards/shard-no-cleanup-bypass"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    drop(journal);
    rewrite_stable_record(directory.path(), |record| {
        record["sequence"] = serde_json::json!(2);
        record["events"] = serde_json::json!([{
            "phase": "intent",
            "sequence": 2,
            "effect": { "effect": "revoke_ingress" }
        }]);
    });

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn reserved_fence_and_cleanup_locators_recover_exactly_after_restart() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let locators = PreparedShardRecoveryLocators::new(
        "backend-token-a",
        PathBuf::from("/sys/fs/cgroup/browserd/shard-a"),
        PathBuf::from("/run/browserd/shards/shard-a"),
    )
    .expect("recovery locators must be valid");

    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    let reserved = journal
        .reserve(fence.clone(), locators.clone())
        .expect("fence reservation must be durable");
    assert_eq!(reserved.sequence().get(), 1);
    drop(journal);

    let reopened = FilePreparedShardJournal::open(directory.path())
        .expect("prepared-shard journal must reopen");
    let records = reopened
        .records()
        .expect("durable records must be recoverable");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].fence(), &fence);
    assert_eq!(records[0].locators(), &locators);
    assert_eq!(records[0].sequence().get(), 1);
    assert_eq!(
        records[0].recovery_disposition(),
        PreparedShardRecoveryDisposition::CleanupOnly
    );
}

#[test]
fn crash_after_release_intent_never_recovers_as_resumable() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let locators = PreparedShardRecoveryLocators::new(
        "backend-token-release",
        PathBuf::from("/sys/fs/cgroup/browserd/shard-release"),
        PathBuf::from("/run/browserd/shards/shard-release"),
    )
    .expect("recovery locators must be valid");
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    advance_to_release_intent(&journal, &fence, locators, 29);
    drop(journal);

    let reopened = FilePreparedShardJournal::open(directory.path())
        .expect("prepared-shard journal must reopen");
    let records = reopened
        .records()
        .expect("durable records must be recoverable");
    assert_eq!(
        records[0]
            .lifecycle_state()
            .expect("history must replay through the domain model"),
        PreparedShardState::ReleaseIntent
    );
    assert!(matches!(
        records[0].pending_effect(),
        Some(PreparedShardEffect::SendReleaseToken {
            release_sequence: 29
        })
    ));
    assert_eq!(
        records[0].recovery_disposition(),
        PreparedShardRecoveryDisposition::CleanupOnly
    );
}

#[tokio::test]
async fn revoke_timeout_never_blocks_kill_and_restart_retries_only_incomplete_cleanup() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let initial_journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    advance_to_release_intent(
        &initial_journal,
        &fence,
        PreparedShardRecoveryLocators::new(
            "backend-token-reconcile",
            PathBuf::from("/sys/fs/cgroup/browserd/shard-reconcile"),
            PathBuf::from("/run/browserd/shards/shard-reconcile"),
        )
        .expect("recovery locators must be valid"),
        31,
    );
    drop(initial_journal);
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path())
            .expect("startup must reopen the prepared-shard journal"),
    );
    let backend = Arc::new(HangingRevokeBackend::default());
    backend.set_revoke_hang(true);

    let first = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_millis(20),
    )
    .expect("reconciler configuration must be valid")
    .start_detached();
    let first_report = first
        .wait()
        .await
        .expect("a stage timeout must remain a retryable reconciliation result");
    assert_eq!(first_report.cleanup_pending(), 1);
    let first_calls = backend.calls();
    assert!(first_calls.contains(&PreparedShardCleanupStage::AbortGate));
    assert!(first_calls.contains(&PreparedShardCleanupStage::KillCgroup));
    let after_timeout = journal
        .records()
        .expect("cleanup progress must remain durable")
        .pop()
        .expect("prepared-shard record must remain");
    assert_eq!(
        after_timeout.recovery_disposition(),
        PreparedShardRecoveryDisposition::CleanupPending
    );
    assert_eq!(
        after_timeout
            .cleanup_progress(PreparedShardCleanupStage::RevokeEgress)
            .expect("revoke progress must replay")
            .status(),
        PreparedShardCleanupStageStatus::Failed
    );
    assert_eq!(
        after_timeout
            .cleanup_progress(PreparedShardCleanupStage::KillCgroup)
            .expect("kill progress must replay")
            .status(),
        PreparedShardCleanupStageStatus::Completed
    );

    backend.set_revoke_hang(false);
    let second = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_millis(20),
    )
    .expect("reconciler configuration must be valid")
    .start_detached();
    let second_report = second.wait().await.expect("cleanup retry must complete");
    assert_eq!(second_report.released_tombstones(), 1);
    assert_eq!(second_report.cleanup_pending(), 0);
    let all_calls = backend.calls();
    assert_eq!(
        all_calls
            .iter()
            .filter(|stage| **stage == PreparedShardCleanupStage::RevokeEgress)
            .count(),
        2
    );
    assert_eq!(
        all_calls
            .iter()
            .filter(|stage| **stage == PreparedShardCleanupStage::KillCgroup)
            .count(),
        1
    );
    let tombstone = journal
        .records()
        .expect("cleanup tombstone must remain durable")
        .pop()
        .expect("prepared-shard tombstone must remain");
    assert_eq!(
        tombstone.recovery_disposition(),
        PreparedShardRecoveryDisposition::ReleasedTombstone
    );
}

#[tokio::test]
async fn repeated_cleanup_failures_never_exhaust_the_durable_kill_path() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    let mut record = journal
        .reserve(
            fence.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-retry-capacity",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-retry-capacity"),
                PathBuf::from("/run/browserd/shards/shard-retry-capacity"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");

    for _ in 0..520 {
        let permit = journal
            .begin_cleanup_stage(
                &fence,
                record.sequence(),
                PreparedShardCleanupStage::RevokeEgress,
            )
            .expect("retry intent must never consume terminal cleanup capacity");
        record = journal
            .record_cleanup_failure(
                &permit,
                browserd_sandbox::PreparedShardCleanupFailure::Backend,
            )
            .expect("retry failure must remain compact and durable");
    }

    let backend = Arc::new(HangingRevokeBackend::default());
    let report = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(1),
    )
    .expect("reconciler configuration must be valid")
    .start_detached()
    .wait()
    .await
    .expect("cleanup capacity must remain available for revoke, abort, and kill");

    assert_eq!(report.released_tombstones(), 1);
    assert!(
        backend
            .calls()
            .contains(&PreparedShardCleanupStage::KillCgroup)
    );
}

#[tokio::test]
async fn exact_process_capabilities_remain_open_until_death_is_proven() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    journal
        .reserve(
            fence,
            PreparedShardRecoveryLocators::new(
                "backend-token-death-proof",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-death-proof"),
                PathBuf::from("/run/browserd/shards/shard-death-proof"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    let backend = Arc::new(FailingDeathProofBackend::default());

    let report = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(1),
    )
    .expect("reconciler configuration must be valid")
    .start_detached()
    .wait()
    .await
    .expect("failed death proof must remain durable and retryable");

    assert_eq!(report.cleanup_pending(), 1);
    let calls = backend
        .calls
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(calls.contains(&PreparedShardCleanupStage::KillCgroup));
    assert!(calls.contains(&PreparedShardCleanupStage::ConfirmProcessDeath));
    assert!(!calls.contains(&PreparedShardCleanupStage::CloseCapabilities));
}

#[tokio::test]
async fn exact_egress_capabilities_remain_open_until_drain_is_proven() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-egress-proof",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-egress-proof"),
                PathBuf::from("/run/browserd/shards/shard-egress-proof"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    let backend = Arc::new(FailingEgressDrainBackend::default());

    let report = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(1),
    )
    .expect("reconciler configuration must be valid")
    .start_detached()
    .wait()
    .await
    .expect("failed egress proof must remain durable and retryable");

    assert_eq!(report.cleanup_pending(), 1);
    let calls = backend
        .calls
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(calls.contains(&PreparedShardCleanupStage::ConfirmProcessDeath));
    assert!(calls.contains(&PreparedShardCleanupStage::ConfirmEgressDrained));
    assert!(!calls.contains(&PreparedShardCleanupStage::CloseCapabilities));
}

#[tokio::test]
async fn revoke_panic_is_isolated_and_never_prevents_abort_or_kill() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-panic",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-panic"),
                PathBuf::from("/run/browserd/shards/shard-panic"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-panic-other",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-panic-other"),
                PathBuf::from("/run/browserd/shards/shard-panic-other"),
            )
            .expect("other shard recovery locators must be valid"),
        )
        .expect("other shard fence reservation must be durable");
    let backend = Arc::new(PanickingRevokeBackend::default());

    let report = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(1),
    )
    .expect("reconciler configuration must be valid")
    .start_detached()
    .wait()
    .await
    .expect("a backend panic must be converted into durable cleanup failure");

    assert_eq!(report.cleanup_pending(), 2);
    let calls = backend
        .calls
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(calls.contains(&PreparedShardCleanupStage::AbortGate));
    assert_eq!(
        calls
            .iter()
            .filter(|stage| **stage == PreparedShardCleanupStage::KillCgroup)
            .count(),
        2
    );
}

#[tokio::test]
async fn a_slow_shard_never_serializes_other_shard_cleanup() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    let first = shard_fence();
    let second = shard_fence();
    let (slow_fence, fast_fence) = if fence_record_key(&first) < fence_record_key(&second) {
        (first, second)
    } else {
        (second, first)
    };
    for (fence, token, leaf) in [
        (slow_fence.clone(), "backend-token-slow", "slow"),
        (fast_fence, "backend-token-fast", "fast"),
    ] {
        journal
            .reserve(
                fence,
                PreparedShardRecoveryLocators::new(
                    token,
                    PathBuf::from(format!("/sys/fs/cgroup/browserd/{leaf}")),
                    PathBuf::from(format!("/run/browserd/shards/{leaf}")),
                )
                .expect("recovery locators must be valid"),
            )
            .expect("fence reservation must be durable");
    }
    let backend = Arc::new(ConcurrentShardBackend {
        slow_fence,
        slow_revoke_started: tokio::sync::Notify::new(),
        release_slow_revoke: tokio::sync::Notify::new(),
        fast_kill_started: tokio::sync::Notify::new(),
    });
    let handle = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(5),
    )
    .expect("reconciler configuration must be valid")
    .with_max_concurrency(2)
    .expect("two concurrent shard actors must be valid")
    .start_detached();
    backend.slow_revoke_started.notified().await;

    let fast_progress = tokio::time::timeout(
        Duration::from_millis(250),
        backend.fast_kill_started.notified(),
    )
    .await;
    backend.release_slow_revoke.notify_one();
    assert!(
        fast_progress.is_ok(),
        "a blocked shard must not delay another shard's kill path"
    );
    let report = handle.wait().await.expect("both shards must reconcile");
    assert_eq!(report.released_tombstones(), 2);
}

#[tokio::test]
async fn configured_reconciliation_concurrency_is_a_hard_upper_bound() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    for (token, leaf) in [
        ("backend-token-bound-one", "bound-one"),
        ("backend-token-bound-two", "bound-two"),
        ("backend-token-bound-three", "bound-three"),
    ] {
        journal
            .reserve(
                shard_fence(),
                PreparedShardRecoveryLocators::new(
                    token,
                    PathBuf::from(format!("/sys/fs/cgroup/browserd/{leaf}")),
                    PathBuf::from(format!("/run/browserd/shards/{leaf}")),
                )
                .expect("recovery locators must be valid"),
            )
            .expect("fence reservation must be durable");
    }
    let backend = Arc::new(BoundedRevokeBackend::default());
    let handle = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(5),
    )
    .expect("reconciler configuration must be valid")
    .with_max_concurrency(2)
    .expect("two concurrent shard actors must be valid")
    .start_detached();

    tokio::time::timeout(Duration::from_secs(1), async {
        while backend.revoke_started.load(Ordering::Acquire) < 2 {
            backend.state_changed.notified().await;
        }
    })
    .await
    .expect("two shard actors must start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(backend.revoke_started.load(Ordering::Acquire), 2);
    assert_eq!(backend.maximum_active.load(Ordering::Acquire), 2);

    backend.released.store(true, Ordering::Release);
    backend.state_changed.notify_waiters();
    let report = handle.wait().await.expect("all shards must reconcile");
    assert_eq!(report.released_tombstones(), 3);
}

#[tokio::test]
async fn one_journal_allows_only_one_active_reconciler_and_one_global_bound() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-single-reconciler",
                PathBuf::from("/sys/fs/cgroup/browserd/single-reconciler"),
                PathBuf::from("/run/browserd/shards/single-reconciler"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    let backend = Arc::new(BoundedRevokeBackend::default());
    let first = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(5),
    )
    .expect("first reconciler configuration must be valid")
    .with_max_concurrency(1)
    .expect("one shard actor must be valid")
    .start_detached();
    tokio::time::timeout(Duration::from_secs(1), async {
        while backend.revoke_started.load(Ordering::Acquire) < 1 {
            backend.state_changed.notified().await;
        }
    })
    .await
    .expect("first reconciler must own the revoke stage");

    let second = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(5),
    )
    .expect("second reconciler configuration must be valid")
    .with_max_concurrency(1)
    .expect("one shard actor must be valid")
    .start_detached();
    let duplicate_started = tokio::time::timeout(Duration::from_millis(250), async {
        while backend.revoke_started.load(Ordering::Acquire) < 2 {
            backend.state_changed.notified().await;
        }
    })
    .await
    .is_ok();

    backend.released.store(true, Ordering::Release);
    backend.state_changed.notify_waiters();
    let first_result = first.wait().await;
    let second_result = second.wait().await;
    assert!(
        !duplicate_started,
        "a second reconciler must not dispatch the same durable stage"
    );
    assert!(first_result.is_ok(), "the established owner must finish");
    assert!(second_result.is_err(), "a second owner must fail closed");
    assert_eq!(backend.maximum_active.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn dropping_the_reconciliation_waiter_does_not_cancel_cleanup_ownership() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    journal
        .reserve(
            fence,
            PreparedShardRecoveryLocators::new(
                "backend-token-detached",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-detached"),
                PathBuf::from("/run/browserd/shards/shard-detached"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    let backend = Arc::new(GatedRevokeBackend::default());
    let handle = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        Arc::clone(&backend),
        Duration::from_secs(1),
    )
    .expect("reconciler configuration must be valid")
    .start_detached();
    backend.revoke_started.notified().await;

    drop(handle);
    backend.release_revoke.notify_one();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let disposition = journal
                .records()
                .expect("cleanup progress must remain readable")
                .pop()
                .expect("prepared-shard record must remain")
                .recovery_disposition();
            if disposition == PreparedShardRecoveryDisposition::ReleasedTombstone {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached reconciler must retain cleanup ownership");
}

#[tokio::test]
async fn cleanup_intent_left_by_a_crash_is_reclaimed_and_completed() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    let reserved = journal
        .reserve(
            fence.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-pending-cleanup",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-pending-cleanup"),
                PathBuf::from("/run/browserd/shards/shard-pending-cleanup"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    journal
        .begin_cleanup_stage(
            &fence,
            reserved.sequence(),
            PreparedShardCleanupStage::RevokeEgress,
        )
        .expect("cleanup intent must be durable before the external effect");
    drop(journal);

    let reopened = Arc::new(
        FilePreparedShardJournal::open(directory.path())
            .expect("journal with a pending cleanup intent must reopen"),
    );
    let report = StartupPreparedShardReconciler::new(
        Arc::clone(&reopened),
        Arc::new(HangingRevokeBackend::default()),
        Duration::from_secs(1),
    )
    .expect("reconciler configuration must be valid")
    .start_detached()
    .wait()
    .await
    .expect("a durable pending cleanup intent must be reclaimable");

    assert_eq!(report.released_tombstones(), 1);
    assert_eq!(report.cleanup_pending(), 0);
}

#[test]
fn validly_checksummed_unknown_fields_fail_the_whole_journal_closed() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-unknown",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-unknown"),
                PathBuf::from("/run/browserd/shards/shard-unknown"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    drop(journal);
    rewrite_stable_record(directory.path(), |record| {
        record["unexpected_future_meaning"] = serde_json::json!(true);
    });

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn huge_retry_counters_are_rejected_without_unbounded_replay_work() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-huge-counter",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-huge-counter"),
                PathBuf::from("/run/browserd/shards/shard-huge-counter"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    drop(journal);
    rewrite_stable_record(directory.path(), |record| {
        record["cleanup"][0] = serde_json::json!({
            "status": "in_progress",
            "attempts": 1_000_000_000_u64,
            "last_failure": null
        });
        record["cleanup_writes"] = serde_json::json!(1_000_000_000_u64);
    });

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn in_progress_cleanup_rejects_an_impossible_finish_write() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    let record = journal
        .reserve(
            fence.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-impossible-cleanup-write",
                PathBuf::from("/sys/fs/cgroup/browserd/impossible-cleanup-write"),
                PathBuf::from("/run/browserd/shards/impossible-cleanup-write"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("reservation must be durable");
    journal
        .begin_cleanup_stage(
            &fence,
            record.sequence(),
            PreparedShardCleanupStage::RevokeEgress,
        )
        .expect("cleanup intent must be durable");
    drop(journal);
    rewrite_stable_record(directory.path(), |record| {
        record["sequence"] = serde_json::json!(3);
        record["cleanup_writes"] = serde_json::json!(2);
    });

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn validly_checksummed_unknown_fence_fields_fail_closed() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-unknown-fence",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-unknown-fence"),
                PathBuf::from("/run/browserd/shards/shard-unknown-fence"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    drop(journal);
    rewrite_stable_record(directory.path(), |record| {
        record["fence"]["unexpected_owner_semantics"] = serde_json::json!(true);
    });

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn deserialization_revalidates_recovery_locators() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-revalidate",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-revalidate"),
                PathBuf::from("/run/browserd/shards/shard-revalidate"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    drop(journal);
    rewrite_stable_record(directory.path(), |record| {
        record["locators"]["backend_token"] = serde_json::json!("");
    });

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn validly_checksummed_locator_outside_trusted_roots_fails_before_backend_dispatch() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-root-escape",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-root-escape"),
                PathBuf::from("/run/browserd/shards/shard-root-escape"),
            )
            .expect("initial locators must be within production roots"),
        )
        .expect("fence reservation must be durable");
    drop(journal);
    rewrite_stable_record(directory.path(), |record| {
        record["locators"]["cgroup_path"] = serde_json::json!("/tmp/attacker-controlled-cgroup");
    });
    let backend = HangingRevokeBackend::default();

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
    assert!(backend.calls().is_empty());
}

#[test]
fn backend_token_is_redacted_from_debug_output() {
    let secret = "backend-token-that-must-not-leak";
    let locators = PreparedShardRecoveryLocators::new(
        secret,
        PathBuf::from("/sys/fs/cgroup/browserd/shard-redacted"),
        PathBuf::from("/run/browserd/shards/shard-redacted"),
    )
    .expect("recovery locators must be valid");

    assert!(!format!("{locators:?}").contains(secret));
}

#[test]
fn journal_open_rejects_a_symbolic_link_in_an_ancestor_component() {
    let root = tempfile::tempdir().expect("temporary root must be created");
    let real_parent = root.path().join("real-parent");
    let real_journal = real_parent.join("journal");
    fs::create_dir(&real_parent).expect("real parent must be created");
    fs::create_dir(&real_journal).expect("real journal directory must be created");
    let linked_parent = root.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).expect("ancestor symlink must be created");

    assert!(FilePreparedShardJournal::open(linked_parent.join("journal")).is_err());
}

#[test]
fn journal_open_rejects_a_fifo_record_without_blocking() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fifo = directory.path().join(format!("{}.psj", "a".repeat(64)));
    mkfifo(&fifo, Mode::from_bits_truncate(0o600)).expect("FIFO fixture must be created");
    let journal_directory = directory.path().to_path_buf();
    let (sender, receiver) = mpsc::channel();
    let opener = thread::spawn(move || {
        sender
            .send(FilePreparedShardJournal::open(journal_directory).is_err())
            .expect("open outcome receiver must remain");
    });

    let prompt_rejection = receiver.recv_timeout(Duration::from_millis(250));
    if prompt_rejection.is_err() {
        let writer = OpenOptions::new()
            .write(true)
            .open(&fifo)
            .expect("writer must unblock the legacy blocking reader");
        drop(writer);
    }
    opener.join().expect("journal opener must not panic");

    assert!(matches!(prompt_rejection, Ok(true)));
}

#[test]
fn restart_scavenges_an_orphan_temporary_record_before_cleanup_writes() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let orphan_name = format!(".{}.1.tmp", fence_record_key(&fence));
    let orphan_path = directory.path().join(orphan_name);
    let mut orphan = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&orphan_path)
        .expect("orphan temporary record must be created");
    orphan
        .write_all(b"interrupted atomic journal replacement")
        .expect("orphan fixture must be written");
    orphan.sync_all().expect("orphan fixture must be durable");
    drop(orphan);

    let journal = FilePreparedShardJournal::open(directory.path())
        .expect("journal must reclaim non-authoritative temporary records");
    assert!(!orphan_path.exists());
    journal
        .reserve(
            fence,
            PreparedShardRecoveryLocators::new(
                "backend-token-orphan-temp",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-orphan-temp"),
                PathBuf::from("/run/browserd/shards/shard-orphan-temp"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("a stale temporary name must not block the first durable write");
}

#[test]
fn record_filename_uses_an_explicit_canonical_fence_encoding() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            fence.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-canonical",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-canonical"),
                PathBuf::from("/run/browserd/shards/shard-canonical"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");

    let expected = format!("{}.psj", fence_record_key(&fence));
    let stable_name = fs::read_dir(directory.path())
        .expect("journal directory must be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .find(|name| Path::new(name).extension().is_some_and(|ext| ext == "psj"))
        .expect("stable prepared-shard record must exist");

    assert_eq!(stable_name.to_string_lossy(), expected);
}

#[test]
fn exact_sequence_cas_has_one_winner_and_stale_fences_are_read_only() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal = Arc::new(
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open"),
    );
    let reserved = journal
        .reserve(
            fence.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-cas",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-cas"),
                PathBuf::from("/run/browserd/shards/shard-cas"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    let reserved_sequence = reserved.sequence();
    let outcomes = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..2 {
            let journal = Arc::clone(&journal);
            let fence = fence.clone();
            threads.push(scope.spawn(move || {
                journal.begin_effect(
                    &fence,
                    reserved_sequence,
                    PreparedShardEffect::CreateFilesystemCgroup,
                )
            }));
        }
        threads
            .into_iter()
            .map(|thread| thread.join().expect("CAS contender must not panic"))
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(PreparedShardJournalError::StaleSequence { .. })
            ))
            .count(),
        1
    );

    let stable_path = fs::read_dir(directory.path())
        .expect("journal directory must be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|extension| extension == "psj"))
        .expect("stable prepared-shard record must exist");
    let before_rejections = fs::read(&stable_path).expect("record must be readable");
    assert!(matches!(
        journal.begin_effect(
            &fence,
            reserved_sequence,
            PreparedShardEffect::CreateFilesystemCgroup,
        ),
        Err(PreparedShardJournalError::StaleSequence { .. })
    ));
    let foreign = shard_fence();
    assert!(matches!(
        journal.begin_effect(
            &foreign,
            reserved_sequence,
            PreparedShardEffect::CreateFilesystemCgroup,
        ),
        Err(PreparedShardJournalError::RecordNotFound)
    ));
    assert_eq!(
        fs::read(stable_path).expect("record must remain readable"),
        before_rejections
    );
}

#[test]
fn same_instance_cannot_reclaim_an_in_progress_cleanup_attempt() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let fence = shard_fence();
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    let record = journal
        .reserve(
            fence.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-reclaim-boundary",
                PathBuf::from("/sys/fs/cgroup/browserd/reclaim-boundary"),
                PathBuf::from("/run/browserd/shards/reclaim-boundary"),
            )
            .expect("recovery locators must be valid"),
        )
        .expect("fence reservation must be durable");
    let first = journal
        .begin_cleanup_stage(
            &fence,
            record.sequence(),
            PreparedShardCleanupStage::RevokeEgress,
        )
        .expect("first cleanup attempt must be durable");
    let current = journal
        .records()
        .expect("journal must remain readable")
        .pop()
        .expect("record must remain");

    assert!(matches!(
        journal.begin_cleanup_stage(
            &fence,
            current.sequence(),
            PreparedShardCleanupStage::RevokeEgress,
        ),
        Err(PreparedShardJournalError::CleanupStageInProgress)
    ));
    drop(first);
    drop(journal);

    let reopened = FilePreparedShardJournal::open(directory.path())
        .expect("reopen must establish a new cleanup ownership epoch");
    let abandoned = reopened
        .records()
        .expect("reopened journal must be readable")
        .pop()
        .expect("abandoned cleanup record must remain");
    let reclaimed = reopened
        .begin_cleanup_stage(
            &fence,
            abandoned.sequence(),
            PreparedShardCleanupStage::RevokeEgress,
        )
        .expect("only a reopened journal may reclaim an abandoned attempt");
    assert_eq!(reclaimed.attempt(), 2);
}

#[test]
fn an_unreleased_shard_fence_blocks_aliasing_and_stale_launch_generations() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let shard_id = ShardId::new();
    let owner = OwnerFence::new(
        WorkerId::new("worker-journal-fence").expect("worker identity must be valid"),
        WorkerEpoch::new(9).expect("worker epoch must be positive"),
    );
    let current = ShardFence::new(
        owner.clone(),
        shard_id.clone(),
        LaunchGeneration::new(4).expect("launch generation must be positive"),
    );
    let stale = ShardFence::new(
        owner,
        shard_id,
        LaunchGeneration::new(3).expect("launch generation must be positive"),
    );
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    let shared_cgroup = PathBuf::from("/sys/fs/cgroup/browserd/shared-shard-path");
    let shared_runtime = PathBuf::from("/run/browserd/shards/shared-shard-path");
    let mut current_record = journal
        .reserve(
            current.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-current",
                shared_cgroup.clone(),
                shared_runtime.clone(),
            )
            .expect("current locators must be valid"),
        )
        .expect("current fence reservation must be durable");

    assert!(
        journal
            .reserve(
                stale,
                PreparedShardRecoveryLocators::new(
                    "backend-token-stale",
                    shared_cgroup.clone(),
                    shared_runtime.clone(),
                )
                .expect("stale locators are structurally valid"),
            )
            .is_err()
    );

    for stage in PreparedShardCleanupStage::ALL {
        let permit = journal
            .begin_cleanup_stage(&current, current_record.sequence(), stage)
            .expect("current generation cleanup intent must be durable");
        current_record = journal
            .complete_cleanup_stage(&permit)
            .expect("current generation cleanup completion must be durable");
    }
    let next = ShardFence::new(
        current.owner().clone(),
        current.shard_id().clone(),
        LaunchGeneration::new(5).expect("launch generation must be positive"),
    );
    assert!(matches!(
        journal.reserve(
            next.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-current",
                PathBuf::from("/sys/fs/cgroup/browserd/new-generation-path"),
                PathBuf::from("/run/browserd/shards/new-generation-path"),
            )
            .expect("token-alias locators are structurally valid"),
        ),
        Err(PreparedShardJournalError::ReservationConflict)
    ));
    assert!(matches!(
        journal.reserve(
            next,
            PreparedShardRecoveryLocators::new(
                "backend-token-next",
                shared_cgroup,
                shared_runtime,
            )
            .expect("path-alias locators are structurally valid"),
        ),
        Err(PreparedShardJournalError::ReservationConflict)
    ));
}

#[test]
fn reopen_rejects_cross_record_permanent_locator_aliases() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let first = shard_fence();
    let second = shard_fence();
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            first,
            PreparedShardRecoveryLocators::new(
                "backend-token-reopen-alias",
                PathBuf::from("/sys/fs/cgroup/browserd/reopen-alias-first"),
                PathBuf::from("/run/browserd/shards/reopen-alias-first"),
            )
            .expect("first locators must be valid"),
        )
        .expect("first reservation must be durable");
    journal
        .reserve(
            second.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-reopen-distinct",
                PathBuf::from("/sys/fs/cgroup/browserd/reopen-alias-second"),
                PathBuf::from("/run/browserd/shards/reopen-alias-second"),
            )
            .expect("second locators must be valid"),
        )
        .expect("second reservation must be durable");
    drop(journal);
    rewrite_fenced_record(directory.path(), &second, |record| {
        record["locators"]["backend_token"] = serde_json::json!("backend-token-reopen-alias");
    });

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn reopen_rejects_cross_record_live_shard_aliases() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let shared_shard = ShardId::new();
    let first = ShardFence::new(
        OwnerFence::new(
            WorkerId::new("worker-reopen-live-first").expect("worker identity must be valid"),
            WorkerEpoch::new(3).expect("worker epoch must be positive"),
        ),
        shared_shard.clone(),
        LaunchGeneration::new(4).expect("launch generation must be positive"),
    );
    let second_source = ShardFence::new(
        OwnerFence::new(
            WorkerId::new("worker-reopen-live-second").expect("worker identity must be valid"),
            WorkerEpoch::new(8).expect("worker epoch must be positive"),
        ),
        ShardId::new(),
        LaunchGeneration::new(1).expect("launch generation must be positive"),
    );
    let second_aliased = ShardFence::new(
        second_source.owner().clone(),
        shared_shard,
        second_source.launch_generation(),
    );
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    journal
        .reserve(
            first,
            PreparedShardRecoveryLocators::new(
                "backend-token-reopen-live-first",
                PathBuf::from("/sys/fs/cgroup/browserd/reopen-live-first"),
                PathBuf::from("/run/browserd/shards/reopen-live-first"),
            )
            .expect("first locators must be valid"),
        )
        .expect("first reservation must be durable");
    journal
        .reserve(
            second_source.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-reopen-live-second",
                PathBuf::from("/sys/fs/cgroup/browserd/reopen-live-second"),
                PathBuf::from("/run/browserd/shards/reopen-live-second"),
            )
            .expect("second locators must be valid"),
        )
        .expect("second reservation must be durable");
    drop(journal);
    rewrite_fenced_record(directory.path(), &second_source, |record| {
        record["fence"] = serde_json::to_value(&second_aliased).expect("aliased fence must encode");
    });
    fs::rename(
        directory
            .path()
            .join(format!("{}.psj", fence_record_key(&second_source))),
        directory
            .path()
            .join(format!("{}.psj", fence_record_key(&second_aliased))),
    )
    .expect("rewritten record must be renamed to its canonical key");

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn reopen_rejects_cross_record_launch_generation_regression() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let owner = OwnerFence::new(
        WorkerId::new("worker-reopen-generation").expect("worker identity must be valid"),
        WorkerEpoch::new(11).expect("worker epoch must be positive"),
    );
    let shared_shard = ShardId::new();
    let higher = ShardFence::new(
        owner.clone(),
        shared_shard.clone(),
        LaunchGeneration::new(5).expect("launch generation must be positive"),
    );
    let lower_source = ShardFence::new(
        owner.clone(),
        ShardId::new(),
        LaunchGeneration::new(4).expect("launch generation must be positive"),
    );
    let lower_regression = ShardFence::new(
        owner,
        shared_shard,
        LaunchGeneration::new(4).expect("launch generation must be positive"),
    );
    let journal =
        FilePreparedShardJournal::open(directory.path()).expect("prepared-shard journal must open");
    let mut higher_record = journal
        .reserve(
            higher.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-reopen-generation-high",
                PathBuf::from("/sys/fs/cgroup/browserd/reopen-generation-high"),
                PathBuf::from("/run/browserd/shards/reopen-generation-high"),
            )
            .expect("higher-generation locators must be valid"),
        )
        .expect("higher generation must be durable");
    for stage in PreparedShardCleanupStage::ALL {
        let permit = journal
            .begin_cleanup_stage(&higher, higher_record.sequence(), stage)
            .expect("higher-generation cleanup intent must be durable");
        higher_record = journal
            .complete_cleanup_stage(&permit)
            .expect("higher-generation cleanup completion must be durable");
    }
    journal
        .reserve(
            lower_source.clone(),
            PreparedShardRecoveryLocators::new(
                "backend-token-reopen-generation-low",
                PathBuf::from("/sys/fs/cgroup/browserd/reopen-generation-low"),
                PathBuf::from("/run/browserd/shards/reopen-generation-low"),
            )
            .expect("lower-generation locators must be valid"),
        )
        .expect("source reservation must be durable");
    drop(journal);
    rewrite_fenced_record(directory.path(), &lower_source, |record| {
        record["fence"] =
            serde_json::to_value(&lower_regression).expect("regressed fence must encode");
    });
    fs::rename(
        directory
            .path()
            .join(format!("{}.psj", fence_record_key(&lower_source))),
        directory
            .path()
            .join(format!("{}.psj", fence_record_key(&lower_regression))),
    )
    .expect("rewritten record must be renamed to its canonical key");

    assert!(FilePreparedShardJournal::open(directory.path()).is_err());
}

#[test]
fn configured_record_limits_reject_resource_exhaustion_before_writing() {
    let directory = tempfile::tempdir().expect("journal directory must be created");
    let limits = PreparedShardJournalLimits::new(1, 64 * 1024, 128 * 1024, 4)
        .expect("journal limits must be internally consistent");
    let journal = FilePreparedShardJournal::open_with_limits(directory.path(), limits)
        .expect("bounded journal must open");
    journal
        .reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-limit-one",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-limit-one"),
                PathBuf::from("/run/browserd/shards/shard-limit-one"),
            )
            .expect("first locators must be valid"),
        )
        .expect("first record must fit");

    assert!(matches!(
        journal.reserve(
            shard_fence(),
            PreparedShardRecoveryLocators::new(
                "backend-token-limit-two",
                PathBuf::from("/sys/fs/cgroup/browserd/shard-limit-two"),
                PathBuf::from("/run/browserd/shards/shard-limit-two"),
            )
            .expect("second locators must be valid"),
        ),
        Err(PreparedShardJournalError::LimitExceeded)
    ));
    assert_eq!(
        journal
            .records()
            .expect("bounded records remain readable")
            .len(),
        1
    );
}
