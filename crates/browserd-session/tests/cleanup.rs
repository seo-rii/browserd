use std::time::Duration;

use browserd_session::{
    CleanupBackend, CleanupFailure, CleanupStage, ExpireDecision, LeasePolicy, OwnershipFence,
    SessionError, SessionId, SessionLifecycle, SessionMachine, SessionTime, SessionTimeoutPolicy,
    TargetId, WorkerId,
};

#[derive(Default)]
struct RecordingCleanup {
    events: Vec<(CleanupStage, Vec<TargetId>)>,
    fail_once_at: Option<CleanupStage>,
}

impl CleanupBackend for RecordingCleanup {
    fn run_stage(
        &mut self,
        stage: CleanupStage,
        active_targets: &[TargetId],
    ) -> Result<(), CleanupFailure> {
        self.events.push((stage, active_targets.to_vec()));
        if self.fail_once_at == Some(stage) {
            self.fail_once_at = None;
            Err(CleanupFailure::Injected)
        } else {
            Ok(())
        }
    }
}

fn expiring_with_targets() -> Option<(SessionMachine, OwnershipFence)> {
    let policy = LeasePolicy::new(Duration::from_millis(1_000), Duration::from_millis(20));
    let timeouts =
        SessionTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(100));
    assert!(policy.is_ok());
    assert!(timeouts.is_ok());
    let policy = policy.ok()?;
    let timeouts = timeouts.ok()?;
    let worker = WorkerId::new("worker-a").ok()?;
    let (mut machine, fence) = SessionMachine::create_with_timeouts(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        policy,
        timeouts,
        SessionTime::new(0),
    );
    assert_eq!(
        machine.start(&fence, SessionTime::new(0)),
        Ok(SessionLifecycle::Creating),
    );
    assert_eq!(
        machine.mark_running(&fence, SessionTime::new(1)),
        Ok(SessionLifecycle::Ready),
    );
    assert_eq!(
        machine.register_target(&fence, TargetId::new("target-b")),
        Ok(()),
    );
    assert_eq!(
        machine.register_target(&fence, TargetId::new("target-a")),
        Ok(()),
    );
    assert_eq!(machine.active_target_count(), 2);
    assert_eq!(
        machine.expire_due(&fence, SessionTime::new(100)),
        Ok(ExpireDecision::BeganExpiring),
    );
    Some((machine, fence))
}

#[test]
fn expiry_closes_target_admission_then_cleanup_drains_in_exact_order() {
    let Some((mut machine, fence)) = expiring_with_targets() else {
        return;
    };
    assert!(!machine.accepting_targets());
    assert_eq!(
        machine.register_target(&fence, TargetId::new("target-c")),
        Err(SessionError::TargetAdmissionClosed),
    );

    let mut backend = RecordingCleanup::default();
    let report = machine.run_cleanup(&fence, &mut backend);
    assert!(report.is_ok());
    let Some(report) = report.ok() else {
        return;
    };
    assert_eq!(report.drained_targets, 2);
    assert_eq!(report.completed_stages, 11);
    assert_eq!(machine.lifecycle(), SessionLifecycle::Closed);
    assert_eq!(machine.active_target_count(), 0);

    let expected = [
        CleanupStage::RejectNewWork,
        CleanupStage::CancelQueuedActions,
        CleanupStage::QuiesceRunningAction,
        CleanupStage::StopViewers,
        CleanupStage::CancelDownloads,
        CleanupStage::ForceCloseTargets,
        CleanupStage::DisposeBrowserContext,
        CleanupStage::VerifyRegistriesEmpty,
        CleanupStage::RevokeProxyRoute,
        CleanupStage::DeleteMaterializedFiles,
        CleanupStage::FinalizeArtifacts,
    ];
    assert_eq!(
        backend
            .events
            .iter()
            .map(|(stage, _)| *stage)
            .collect::<Vec<_>>(),
        expected,
    );
    assert_eq!(
        backend.events[5].1,
        vec![TargetId::new("target-a"), TargetId::new("target-b")],
    );
    assert!(backend.events[6].1.is_empty());
}

#[test]
fn cleanup_retry_resumes_at_the_failed_stage_without_replaying_completed_effects() {
    let Some((mut machine, fence)) = expiring_with_targets() else {
        return;
    };
    let mut first = RecordingCleanup {
        events: Vec::new(),
        fail_once_at: Some(CleanupStage::DisposeBrowserContext),
    };
    assert_eq!(
        machine.run_cleanup(&fence, &mut first),
        Err(SessionError::CleanupFailed {
            stage: CleanupStage::DisposeBrowserContext,
            cause: CleanupFailure::Injected,
        }),
    );
    assert_eq!(machine.lifecycle(), SessionLifecycle::Closing);
    assert_eq!(machine.active_target_count(), 0);

    let mut retry = RecordingCleanup::default();
    assert!(machine.run_cleanup(&fence, &mut retry).is_ok());
    assert_eq!(
        retry.events.first().map(|(stage, _)| *stage),
        Some(CleanupStage::DisposeBrowserContext),
    );
    assert_eq!(machine.lifecycle(), SessionLifecycle::Closed);
}
