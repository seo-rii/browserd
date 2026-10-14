use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_sandbox::{
    PreparedShardCleanupStage, PreparedShardJournalRecord, PreparedShardRecoveryBackend,
    PreparedShardRecoveryError, SandboxFilesystem, StdSandboxFilesystem,
};

use crate::egress::{EgressControlPlane, RouteStatusReceipt};

pub struct LinuxPreparedShardRecovery<C> {
    filesystem: StdSandboxFilesystem,
    egress: Arc<C>,
}

impl<C> LinuxPreparedShardRecovery<C>
where
    C: EgressControlPlane,
{
    pub fn new(
        egress: Arc<C>,
        cgroup_root: PathBuf,
        runtime_root: PathBuf,
    ) -> Result<Self, browserd_sandbox::SandboxError> {
        Ok(Self {
            filesystem: StdSandboxFilesystem::new(cgroup_root, runtime_root)?,
            egress,
        })
    }

    async fn old_epoch_is_superseded(
        &self,
        record: &PreparedShardJournalRecord,
    ) -> Result<bool, PreparedShardRecoveryError> {
        let recorded_epoch = record
            .locators()
            .egress_daemon_epoch()
            .ok_or_else(PreparedShardRecoveryError::new)?;
        let current_epoch = self
            .egress
            .current_daemon_epoch()
            .await
            .map_err(|_| PreparedShardRecoveryError::new())?;
        if current_epoch < recorded_epoch {
            return Err(PreparedShardRecoveryError::new());
        }
        Ok(current_epoch > recorded_epoch)
    }

    async fn egress_status(
        &self,
        record: &PreparedShardJournalRecord,
    ) -> Result<Option<RouteStatusReceipt>, PreparedShardRecoveryError> {
        if self.old_epoch_is_superseded(record).await? {
            return Ok(None);
        }
        let epoch = record
            .locators()
            .egress_daemon_epoch()
            .ok_or_else(PreparedShardRecoveryError::new)?;
        let fence = record
            .locators()
            .egress_fence()
            .ok_or_else(PreparedShardRecoveryError::new)?;
        self.egress
            .status(epoch, fence)
            .await
            .map_err(|_| PreparedShardRecoveryError::new())
    }

    async fn all_context_routes_terminal(
        &self,
        record: &PreparedShardJournalRecord,
        revoke: bool,
    ) -> Result<(), PreparedShardRecoveryError> {
        if self.old_epoch_is_superseded(record).await? {
            return Ok(());
        }
        let epoch = record
            .locators()
            .egress_daemon_epoch()
            .ok_or_else(PreparedShardRecoveryError::new)?;
        for route in record.context_routes() {
            if route.egress_daemon_epoch() != epoch
                || route.request().egress().egress_fence().shard() != record.fence()
            {
                return Err(PreparedShardRecoveryError::new());
            }
            let fence = route.request().egress().egress_fence();
            if revoke {
                crate::egress::release_context_route_positive(
                    self.egress.as_ref(),
                    epoch,
                    route.request().tenant_id(),
                    route.request().egress(),
                    route.binding().is_some(),
                )
                .await
                .map_err(|_| PreparedShardRecoveryError::new())?;
            } else {
                let status = self
                    .egress
                    .status(epoch, fence)
                    .await
                    .map_err(|_| PreparedShardRecoveryError::new())?;
                if !status.as_ref().is_some_and(|status| {
                    status.daemon_epoch() == epoch
                        && status.egress_fence() == fence
                        && status.state() == crate::egress::RouteStatusState::Released
                }) {
                    return Err(PreparedShardRecoveryError::new());
                }
            }
        }
        Ok(())
    }

    fn terminal_status(
        record: &PreparedShardJournalRecord,
        status: Option<RouteStatusReceipt>,
    ) -> Result<(), PreparedShardRecoveryError> {
        let Some(status) = status else {
            return Ok(());
        };
        let expected_epoch = record
            .locators()
            .egress_daemon_epoch()
            .ok_or_else(PreparedShardRecoveryError::new)?;
        let expected_fence = record
            .locators()
            .egress_fence()
            .ok_or_else(PreparedShardRecoveryError::new)?;
        if status.daemon_epoch() != expected_epoch
            || status.egress_fence() != expected_fence
            || !status.state().is_terminal()
        {
            return Err(PreparedShardRecoveryError::new());
        }
        Ok(())
    }
}

#[async_trait]
impl<C> PreparedShardRecoveryBackend for LinuxPreparedShardRecovery<C>
where
    C: EgressControlPlane,
{
    async fn run_stage(
        &self,
        record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError> {
        match stage {
            PreparedShardCleanupStage::RevokeEgress => {
                if self.old_epoch_is_superseded(record).await? {
                    return Ok(());
                }
                let epoch = record
                    .locators()
                    .egress_daemon_epoch()
                    .ok_or_else(PreparedShardRecoveryError::new)?;
                let fence = record
                    .locators()
                    .egress_fence()
                    .ok_or_else(PreparedShardRecoveryError::new)?;
                let status = self
                    .egress
                    .revoke(epoch, fence)
                    .await
                    .map_err(|_| PreparedShardRecoveryError::new())?;
                Self::terminal_status(record, status)?;
                self.all_context_routes_terminal(record, true).await
            }
            PreparedShardCleanupStage::AbortGate => {
                // A startup reconciler runs in a fresh process. Every parent-side launch-gate
                // writer from the previous incarnation is already closed by process exit, and
                // the helper treats EOF as a permanent denial.
                Ok(())
            }
            PreparedShardCleanupStage::KillCgroup => {
                let path = record.locators().cgroup_path().to_path_buf();
                let filesystem = self.filesystem.clone();
                let check_path = path.clone();
                if !tokio::task::spawn_blocking(move || filesystem.is_directory(&check_path))
                    .await
                    .map_err(|_| PreparedShardRecoveryError::new())?
                    .map_err(|_| PreparedShardRecoveryError::new())?
                {
                    return Ok(());
                }
                let filesystem = self.filesystem.clone();
                tokio::task::spawn_blocking(move || {
                    filesystem.write_file(&path.join("cgroup.kill"), "1")
                })
                .await
                .map_err(|_| PreparedShardRecoveryError::new())?
                .map_err(|_| PreparedShardRecoveryError::new())
            }
            PreparedShardCleanupStage::ConfirmProcessDeath => {
                let path = record.locators().cgroup_path().to_path_buf();
                let filesystem = self.filesystem.clone();
                let check_path = path.clone();
                if !tokio::task::spawn_blocking(move || filesystem.is_directory(&check_path))
                    .await
                    .map_err(|_| PreparedShardRecoveryError::new())?
                    .map_err(|_| PreparedShardRecoveryError::new())?
                {
                    return Ok(());
                }
                let events_path = path.join("cgroup.events");
                loop {
                    let filesystem = self.filesystem.clone();
                    let read_path = events_path.clone();
                    let events =
                        tokio::task::spawn_blocking(move || filesystem.read_file(&read_path))
                            .await
                            .map_err(|_| PreparedShardRecoveryError::new())?
                            .map_err(|_| PreparedShardRecoveryError::new())?;
                    if events.lines().any(|line| line.trim() == "populated 0") {
                        return Ok(());
                    }
                    // The startup reconciler owns the absolute per-stage deadline and
                    // cancellation boundary. Polling here lets cgroup.kill converge without
                    // making an ordinary asynchronous kernel transition look terminally failed.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            PreparedShardCleanupStage::ConfirmEgressDrained
            | PreparedShardCleanupStage::ReleaseEgressGeneration => {
                let status = self.egress_status(record).await?;
                Self::terminal_status(record, status)?;
                self.all_context_routes_terminal(record, false).await?;
                if stage == PreparedShardCleanupStage::ReleaseEgressGeneration
                    && !self.old_epoch_is_superseded(record).await?
                {
                    self.egress
                        .retire_shard(
                            record
                                .locators()
                                .egress_daemon_epoch()
                                .ok_or_else(PreparedShardRecoveryError::new)?,
                            record.fence(),
                        )
                        .await
                        .map_err(|_| PreparedShardRecoveryError::new())?;
                }
                Ok(())
            }
            PreparedShardCleanupStage::CloseCapabilities
            | PreparedShardCleanupStage::CleanupNetworkNamespace => {
                // The old daemon incarnation owned these descriptors. Process exit is the
                // capability close proof; cgroup death is ordered before these stages.
                Ok(())
            }
            PreparedShardCleanupStage::CleanupRuntimeFilesystem => {
                let path = record.locators().runtime_path().to_path_buf();
                let filesystem = self.filesystem.clone();
                let check_path = path.clone();
                if !tokio::task::spawn_blocking(move || filesystem.is_directory(&check_path))
                    .await
                    .map_err(|_| PreparedShardRecoveryError::new())?
                    .map_err(|_| PreparedShardRecoveryError::new())?
                {
                    return Ok(());
                }
                let filesystem = self.filesystem.clone();
                tokio::task::spawn_blocking(move || filesystem.remove_directory(&path))
                    .await
                    .map_err(|_| PreparedShardRecoveryError::new())?
                    .map_err(|_| PreparedShardRecoveryError::new())
            }
            PreparedShardCleanupStage::RemoveCgroup => {
                let path = record.locators().cgroup_path().to_path_buf();
                let filesystem = self.filesystem.clone();
                let check_path = path.clone();
                if !tokio::task::spawn_blocking(move || filesystem.is_directory(&check_path))
                    .await
                    .map_err(|_| PreparedShardRecoveryError::new())?
                    .map_err(|_| PreparedShardRecoveryError::new())?
                {
                    return Ok(());
                }
                let filesystem = self.filesystem.clone();
                tokio::task::spawn_blocking(move || filesystem.remove_directory(&path))
                    .await
                    .map_err(|_| PreparedShardRecoveryError::new())?
                    .map_err(|_| PreparedShardRecoveryError::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use browserd_core::{
        EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
        ShardFence, ShardId, WorkerEpoch, WorkerId,
    };
    use browserd_egress_control::{ActiveInstallResponse, InstallRequest};
    use browserd_sandbox::{
        FilePreparedShardJournal, PreparedShardJournalLimits, PreparedShardRecoveryLocators,
        PreparedShardRecoveryRoots,
    };
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use tempfile::tempdir;

    use super::*;
    use crate::egress::{EgressControlError, PrepareRouteRequest, PreparedRouteReceipt};

    #[derive(Clone)]
    struct TerminalControl;

    #[async_trait]
    impl EgressControlPlane for TerminalControl {
        async fn current_daemon_epoch(&self) -> Result<u64, EgressControlError> {
            Ok(41)
        }

        async fn prepare(
            &self,
            _request: PrepareRouteRequest,
        ) -> Result<PreparedRouteReceipt, EgressControlError> {
            Err(EgressControlError::Protocol("unused prepare".into()))
        }

        async fn install(
            &self,
            _request: InstallRequest,
            _listener: OwnedFd,
        ) -> Result<ActiveInstallResponse, EgressControlError> {
            Err(EgressControlError::Protocol("unused install".into()))
        }

        async fn status(
            &self,
            _daemon_epoch: u64,
            _fence: &EgressFence,
        ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
            Err(EgressControlError::Protocol("unused status".into()))
        }

        async fn retire_shard(
            &self,
            _daemon_epoch: u64,
            _fence: &browserd_core::ShardFence,
        ) -> Result<(), EgressControlError> {
            Ok(())
        }

        async fn revoke(
            &self,
            _daemon_epoch: u64,
            _fence: &EgressFence,
        ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
            Err(EgressControlError::Protocol("unused revoke".into()))
        }
    }

    #[derive(Clone)]
    struct SupersededControl {
        revoke_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl EgressControlPlane for SupersededControl {
        async fn current_daemon_epoch(&self) -> Result<u64, EgressControlError> {
            Ok(42)
        }

        async fn prepare(
            &self,
            _request: PrepareRouteRequest,
        ) -> Result<PreparedRouteReceipt, EgressControlError> {
            Err(EgressControlError::Protocol("unused prepare".into()))
        }

        async fn install(
            &self,
            _request: InstallRequest,
            _listener: OwnedFd,
        ) -> Result<ActiveInstallResponse, EgressControlError> {
            Err(EgressControlError::Protocol("unused install".into()))
        }

        async fn status(
            &self,
            _daemon_epoch: u64,
            _fence: &EgressFence,
        ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
            Err(EgressControlError::Protocol(
                "old epoch status must not be queried".into(),
            ))
        }

        async fn retire_shard(
            &self,
            _daemon_epoch: u64,
            _fence: &browserd_core::ShardFence,
        ) -> Result<(), EgressControlError> {
            Ok(())
        }

        async fn revoke(
            &self,
            _daemon_epoch: u64,
            _fence: &EgressFence,
        ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
            self.revoke_calls.fetch_add(1, Ordering::SeqCst);
            Err(EgressControlError::Protocol(
                "old epoch revoke must not be sent to the new daemon".into(),
            ))
        }
    }

    fn fence() -> EgressFence {
        EgressFence::new(
            ShardFence::new(
                OwnerFence::new(
                    WorkerId::new("sandboxd-recovery-worker").expect("worker ID should be valid"),
                    WorkerEpoch::new(7).expect("worker epoch should be valid"),
                ),
                ShardId::new(),
                LaunchGeneration::new(3).expect("launch generation should be valid"),
            ),
            RouteGeneration::new(5).expect("route generation should be valid"),
            SessionId::new(),
            SessionIncarnation::new(2).expect("session incarnation should be valid"),
        )
    }

    #[tokio::test]
    async fn restart_recovery_waits_for_the_killed_cgroup_to_become_empty() {
        let temporary = tempdir().expect("temporary directory should exist");
        let cgroup_root = temporary.path().join("cgroups");
        let runtime_root = temporary.path().join("runtime");
        let journal_root = temporary.path().join("journal");
        std::fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        std::fs::create_dir_all(&runtime_root).expect("runtime root should exist");
        std::fs::create_dir_all(&journal_root).expect("journal root should exist");
        let egress_fence = fence();
        let instance = format!(
            "{}-launch-{}",
            egress_fence.shard().shard_id(),
            egress_fence.shard().launch_generation().get()
        );
        let cgroup_path = cgroup_root.join(&instance);
        let runtime_path = runtime_root.join(instance);
        std::fs::create_dir(&cgroup_path).expect("test cgroup should exist");
        std::fs::create_dir(&runtime_path).expect("test runtime should exist");
        let events_path = cgroup_path.join("cgroup.events");
        std::fs::write(&events_path, "populated 1\n").expect("initial events should be written");
        std::fs::write(cgroup_path.join("cgroup.kill"), "0").expect("kill control should exist");

        let journal = FilePreparedShardJournal::open_with_limits_and_roots(
            &journal_root,
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(cgroup_root.clone(), runtime_root.clone())
                .expect("recovery roots should be valid"),
        )
        .expect("journal should open");
        let record = journal
            .reserve(
                egress_fence.shard().clone(),
                PreparedShardRecoveryLocators::new(
                    "restart-owned-token",
                    cgroup_path,
                    runtime_path,
                )
                .expect("locators should be valid")
                .with_egress_binding(41, egress_fence)
                .expect("egress binding should be valid"),
            )
            .expect("prepared record should be reserved");
        let recovery =
            LinuxPreparedShardRecovery::new(Arc::new(TerminalControl), cgroup_root, runtime_root)
                .expect("recovery backend should construct");
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            std::fs::write(events_path, "populated 0\n")
                .expect("terminal events should be written");
        });

        recovery
            .run_stage(&record, PreparedShardCleanupStage::ConfirmProcessDeath)
            .await
            .expect("recovery should wait for the exact cgroup to empty");
        writer.await.expect("events writer should finish");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_cgroup_read_does_not_starve_the_async_recovery_deadline() {
        let temporary = tempdir().expect("temporary directory should exist");
        let cgroup_root = temporary.path().join("cgroups");
        let runtime_root = temporary.path().join("runtime");
        let journal_root = temporary.path().join("journal");
        std::fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        std::fs::create_dir_all(&runtime_root).expect("runtime root should exist");
        std::fs::create_dir_all(&journal_root).expect("journal root should exist");
        let egress_fence = fence();
        let instance = format!(
            "{}-launch-{}",
            egress_fence.shard().shard_id(),
            egress_fence.shard().launch_generation().get()
        );
        let cgroup_path = cgroup_root.join(&instance);
        let runtime_path = runtime_root.join(instance);
        std::fs::create_dir(&cgroup_path).expect("test cgroup should exist");
        std::fs::create_dir(&runtime_path).expect("test runtime should exist");
        let events_path = cgroup_path.join("cgroup.events");
        mkfifo(&events_path, Mode::S_IRUSR | Mode::S_IWUSR)
            .expect("blocking cgroup-events fixture should exist");

        let record = FilePreparedShardJournal::open_with_limits_and_roots(
            &journal_root,
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(cgroup_root.clone(), runtime_root.clone())
                .expect("recovery roots should be valid"),
        )
        .expect("journal should open")
        .reserve(
            egress_fence.shard().clone(),
            PreparedShardRecoveryLocators::new(
                "blocking-read-owned-token",
                cgroup_path,
                runtime_path,
            )
            .expect("locators should be valid")
            .with_egress_binding(41, egress_fence)
            .expect("egress binding should be valid"),
        )
        .expect("prepared record should be reserved");
        let recovery =
            LinuxPreparedShardRecovery::new(Arc::new(TerminalControl), cgroup_root, runtime_root)
                .expect("recovery backend should construct");
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let mut events = std::fs::OpenOptions::new()
                .write(true)
                .open(events_path)
                .expect("FIFO writer should connect");
            events
                .write_all(b"populated 0\n")
                .expect("terminal cgroup event should be written");
        });
        let stage = tokio::spawn(async move {
            recovery
                .run_stage(&record, PreparedShardCleanupStage::ConfirmProcessDeath)
                .await
        });

        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "a blocking filesystem read starved the asynchronous recovery deadline"
        );
        stage
            .await
            .expect("recovery task should not panic")
            .expect("terminal cgroup event should finish recovery");
        writer.join().expect("FIFO writer should finish");
    }

    #[tokio::test]
    async fn authenticated_new_epoch_terminalizes_old_listener_without_reinstalling_it() {
        let temporary = tempdir().expect("temporary directory should exist");
        let cgroup_root = temporary.path().join("cgroups");
        let runtime_root = temporary.path().join("runtime");
        let journal_root = temporary.path().join("journal");
        std::fs::create_dir_all(&cgroup_root).expect("cgroup root should exist");
        std::fs::create_dir_all(&runtime_root).expect("runtime root should exist");
        std::fs::create_dir_all(&journal_root).expect("journal root should exist");
        let egress_fence = fence();
        let record = FilePreparedShardJournal::open_with_limits_and_roots(
            &journal_root,
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(cgroup_root.clone(), runtime_root.clone())
                .expect("recovery roots should be valid"),
        )
        .expect("journal should open")
        .reserve(
            egress_fence.shard().clone(),
            PreparedShardRecoveryLocators::new(
                "superseded-owned-token",
                cgroup_root.join("old-launch"),
                runtime_root.join("old-launch"),
            )
            .expect("locators should be valid")
            .with_egress_binding(41, egress_fence)
            .expect("egress binding should be valid"),
        )
        .expect("prepared record should be reserved");
        let revoke_calls = Arc::new(AtomicUsize::new(0));
        let recovery = LinuxPreparedShardRecovery::new(
            Arc::new(SupersededControl {
                revoke_calls: Arc::clone(&revoke_calls),
            }),
            cgroup_root,
            runtime_root,
        )
        .expect("recovery backend should construct");

        recovery
            .run_stage(&record, PreparedShardCleanupStage::RevokeEgress)
            .await
            .expect("a nonce-bound newer epoch proves the old listener owner exited");
        assert_eq!(revoke_calls.load(Ordering::SeqCst), 0);
    }
    struct ContextRecoveryControl {
        released: std::sync::Mutex<std::collections::HashSet<EgressFence>>,
        prepared: std::sync::Mutex<Vec<EgressFence>>,
        revoked: std::sync::Mutex<Vec<EgressFence>>,
        retired: AtomicUsize,
        missing: bool,
    }
    #[async_trait]
    impl EgressControlPlane for ContextRecoveryControl {
        async fn current_daemon_epoch(&self) -> Result<u64, EgressControlError> {
            Ok(41)
        }
        async fn prepare(
            &self,
            request: PrepareRouteRequest,
        ) -> Result<PreparedRouteReceipt, EgressControlError> {
            self.prepared
                .lock()
                .expect("prepared")
                .push(request.egress_fence.clone());
            Ok(PreparedRouteReceipt::fixture(request))
        }
        #[allow(clippy::panic)]
        async fn install(
            &self,
            _request: InstallRequest,
            _listener: OwnedFd,
        ) -> Result<ActiveInstallResponse, EgressControlError> {
            panic!("recovery must not reinstall routes")
        }
        async fn status(
            &self,
            epoch: u64,
            fence: &EgressFence,
        ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
            Ok(self
                .released
                .lock()
                .expect("released")
                .contains(fence)
                .then(|| RouteStatusReceipt::released_fixture(epoch, fence.clone())))
        }
        async fn revoke(
            &self,
            epoch: u64,
            fence: &EgressFence,
        ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
            self.revoked.lock().expect("revoked").push(fence.clone());
            if !self.missing {
                self.released
                    .lock()
                    .expect("released")
                    .insert(fence.clone());
            }
            self.status(epoch, fence).await
        }
        async fn retire_shard(
            &self,
            epoch: u64,
            fence: &ShardFence,
        ) -> Result<(), EgressControlError> {
            assert_eq!(epoch, 41);
            assert!(
                self.revoked
                    .lock()
                    .expect("revoked")
                    .iter()
                    .all(|route| route.shard() == fence
                        && self.released.lock().expect("released").contains(route))
            );
            self.retired.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[tokio::test]
    async fn restart_recovery_releases_every_durable_context_before_final_shard_retirement() {
        use browserd_core::{PlacementFence, TenantId};
        use browserd_sandbox::{
            ChromiumBinaryDigest, ContextEgressRequest, ContextRoutePhase, ContextRoutePolicy,
            DedicatedEgressProxyBinding, DedicatedEgressSpec, EgressPolicyBinding, LaunchSpec,
            PinnedNetworkNamespace, ShardEgressReservation, ShardIngressLease, ShardIngressReceipt,
        };
        let directory = tempdir().expect("directory");
        let cgroups = directory.path().join("cgroups");
        let runtime = directory.path().join("runtime");
        std::fs::create_dir_all(&cgroups).expect("cgroups");
        std::fs::create_dir_all(&runtime).expect("runtime");
        let roots =
            PreparedShardRecoveryRoots::new(cgroups.clone(), runtime.clone()).expect("roots");
        let journal_path = directory.path().join("journal");
        std::fs::create_dir(&journal_path).expect("journal directory");
        let journal = FilePreparedShardJournal::open_with_limits_and_roots(
            &journal_path,
            PreparedShardJournalLimits::default(),
            roots.clone(),
        )
        .expect("journal");
        let spec = LaunchSpec::production(
            TenantId::new(),
            DedicatedEgressSpec::new(
                fence(),
                EgressPolicyBinding::new("public", [7; 32]).expect("policy"),
                Duration::from_secs(30),
            )
            .expect("egress"),
            ChromiumBinaryDigest::new([3; 32]),
        )
        .with_context_route_policy(
            ContextRoutePolicy::new(PlacementFence::new(7, 1, 2), false, 8, 500).expect("contexts"),
        )
        .expect("launch");
        let shard = spec.dedicated_egress().egress_fence().shard();
        journal
            .reserve(
                shard.clone(),
                PreparedShardRecoveryLocators::new(
                    "context-recovery",
                    cgroups.join("context-recovery"),
                    runtime.join("context-recovery"),
                )
                .expect("locators")
                .with_egress_binding(41, spec.dedicated_egress().egress_fence().clone())
                .expect("epoch"),
            )
            .expect("reserve");
        journal
            .configure_context_routes(shard, spec.context_route_policy().expect("shared").clone())
            .expect("policy");
        let initial = ContextEgressRequest::initial(&spec).expect("initial");
        let reservation = ShardEgressReservation::from_launch_spec(&spec);
        journal
            .reserve_context_route(initial.clone(), reservation.generation().clone(), 41, false)
            .expect("primary intent");
        let namespace = PinnedNetworkNamespace::from_owned_fd(
            std::fs::File::open("/proc/self/ns/net")
                .expect("namespace")
                .into(),
        )
        .expect("pin");
        let binding = DedicatedEgressProxyBinding::from_lease(&ShardIngressLease::from_attachment(
            reservation,
            namespace.identity(),
            ShardIngressReceipt::with_proxy_address("127.0.0.1:43117".parse().expect("address"))
                .expect("receipt"),
        ))
        .expect("binding");
        journal
            .set_context_route_phase(&initial, ContextRoutePhase::Active, Some(binding))
            .expect("active");
        let mut expected = vec![initial.egress().egress_fence().clone()];
        for generation in [6, 7] {
            let request = ContextEgressRequest::new(
                TenantId::new(),
                PlacementFence::new(7, generation, 1),
                DedicatedEgressSpec::new(
                    EgressFence::new(
                        shard.clone(),
                        RouteGeneration::new(generation).expect("route"),
                        SessionId::new(),
                        SessionIncarnation::new(1).expect("incarnation"),
                    ),
                    spec.dedicated_egress().policy_binding().clone(),
                    Duration::from_secs(30),
                )
                .expect("egress"),
            )
            .expect("request");
            journal
                .reserve_context_route(
                    request.clone(),
                    browserd_core::LeaseId::new(),
                    41,
                    generation == 7,
                )
                .expect("intent or cancelled-before-effect");
            expected.push(request.egress().egress_fence().clone());
        }
        drop(journal);
        let record = FilePreparedShardJournal::open_with_limits_and_roots(
            &journal_path,
            PreparedShardJournalLimits::default(),
            roots,
        )
        .expect("restart")
        .records()
        .expect("inventory")
        .remove(0);
        let control = Arc::new(ContextRecoveryControl {
            released: Default::default(),
            prepared: Default::default(),
            revoked: Default::default(),
            retired: AtomicUsize::new(0),
            missing: false,
        });
        let recovery =
            LinuxPreparedShardRecovery::new(control.clone(), cgroups.clone(), runtime.clone())
                .expect("recovery");
        for stage in [
            PreparedShardCleanupStage::RevokeEgress,
            PreparedShardCleanupStage::ConfirmEgressDrained,
            PreparedShardCleanupStage::ReleaseEgressGeneration,
        ] {
            recovery
                .run_stage(&record, stage)
                .await
                .expect("recovery proof");
        }
        {
            let released = control.released.lock().expect("released");
            assert_eq!(released.len(), expected.len());
            assert!(expected.iter().all(|fence| released.contains(fence)));
        }
        assert_eq!(control.retired.load(Ordering::SeqCst), 1);
        let missing = Arc::new(ContextRecoveryControl {
            released: Default::default(),
            prepared: Default::default(),
            revoked: Default::default(),
            retired: AtomicUsize::new(0),
            missing: true,
        });
        let recovery = LinuxPreparedShardRecovery::new(missing.clone(), cgroups, runtime)
            .expect("missing control");
        assert!(
            recovery
                .all_context_routes_terminal(&record, true)
                .await
                .is_err(),
            "active journal binding must not be cleared by missing status"
        );
        assert!(
            missing.prepared.lock().expect("prepared").is_empty(),
            "known-active route cannot be replaced by a synthetic fresh reservation"
        );
    }
}
