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
                Self::terminal_status(record, status)
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
                Self::terminal_status(record, status)
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
}
