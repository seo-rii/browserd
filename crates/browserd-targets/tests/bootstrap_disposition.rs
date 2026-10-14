use browserd_targets::{
    BootstrapBackend, BootstrapDisposition, BootstrapStage, BootstrapStageFailure, PausedTarget,
    ShardTaintReason, TargetBootstrapBarrier, TargetKind,
};

#[derive(Default)]
struct Backend {
    stages: Vec<BootstrapStage>,
    stop: Option<BootstrapDisposition>,
    unknown: bool,
    closed: bool,
    tainted: bool,
}

impl BootstrapBackend for Backend {
    fn run_stage(
        &mut self,
        _target: &PausedTarget,
        stage: BootstrapStage,
    ) -> Result<(), BootstrapStageFailure> {
        self.stages.push(stage);
        Ok(())
    }
    fn run_stage_with_disposition(
        &mut self,
        target: &PausedTarget,
        stage: BootstrapStage,
    ) -> Result<BootstrapDisposition, BootstrapStageFailure> {
        self.run_stage(target, stage)?;
        if stage == BootstrapStage::ApplyEmulation {
            if self.unknown {
                return Err(BootstrapStageFailure::UnknownOwnership);
            }
            if let Some(stop) = self.stop {
                return Ok(stop);
            }
        }
        Ok(BootstrapDisposition::Completed)
    }
    fn close_paused_target(&mut self, _target: &PausedTarget) {
        self.closed = true;
    }
    fn taint_shard(&mut self, _reason: ShardTaintReason) {
        self.tainted = true;
    }
}

#[test]
fn owned_closing_or_retired_stops_before_resume_without_fabricating_ready() {
    let target = PausedTarget::new("exact-target", TargetKind::DedicatedWorker);
    for disposition in [
        BootstrapDisposition::OwnedClosing,
        BootstrapDisposition::OwnedRetired,
    ] {
        let mut backend = Backend {
            stop: Some(disposition),
            ..Backend::default()
        };
        assert_eq!(
            TargetBootstrapBarrier::new().bootstrap_with_disposition(&target, &mut backend),
            Ok(disposition)
        );
        assert!(!backend.stages.contains(&BootstrapStage::Resume));
        assert!(!backend.closed);
        assert!(!backend.tainted);
        assert!(
            TargetBootstrapBarrier::new()
                .bootstrap(
                    &target,
                    &mut Backend {
                        stop: Some(disposition),
                        ..Backend::default()
                    }
                )
                .is_err()
        );
    }
}

#[test]
fn unowned_failure_still_closes_and_taints_while_completed_keeps_order() {
    let target = PausedTarget::new("unknown", TargetKind::Iframe);
    let mut unknown = Backend {
        unknown: true,
        ..Backend::default()
    };
    assert!(
        TargetBootstrapBarrier::new()
            .bootstrap_with_disposition(&target, &mut unknown)
            .is_err()
    );
    assert!(unknown.closed && unknown.tainted);
    assert!(!unknown.stages.contains(&BootstrapStage::Resume));
    let mut completed = Backend::default();
    assert!(
        TargetBootstrapBarrier::new()
            .bootstrap(&target, &mut completed)
            .is_ok()
    );
    assert_eq!(completed.stages.len(), 14);
    assert_eq!(completed.stages.last(), Some(&BootstrapStage::Resume));
}
