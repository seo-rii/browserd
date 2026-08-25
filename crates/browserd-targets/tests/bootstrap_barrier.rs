use browserd_targets::{
    BootstrapBackend, BootstrapError, BootstrapStage, BootstrapStageFailure, PausedTarget,
    ShardTaintReason, TargetBootstrapBarrier, TargetKind,
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Stage(BootstrapStage),
    Close,
    Taint(ShardTaintReason),
}

struct RecordingBackend {
    events: Vec<Event>,
    fail_at: Option<(BootstrapStage, BootstrapStageFailure)>,
}

impl RecordingBackend {
    fn succeeding() -> Self {
        Self {
            events: Vec::new(),
            fail_at: None,
        }
    }

    fn failing(stage: BootstrapStage, failure: BootstrapStageFailure) -> Self {
        Self {
            events: Vec::new(),
            fail_at: Some((stage, failure)),
        }
    }
}

impl BootstrapBackend for RecordingBackend {
    fn run_stage(
        &mut self,
        _target: &PausedTarget,
        stage: BootstrapStage,
    ) -> Result<(), BootstrapStageFailure> {
        self.events.push(Event::Stage(stage));
        match self.fail_at {
            Some((failed_stage, failure)) if failed_stage == stage => Err(failure),
            _ => Ok(()),
        }
    }

    fn close_paused_target(&mut self, _target: &PausedTarget) {
        self.events.push(Event::Close);
    }

    fn taint_shard(&mut self, reason: ShardTaintReason) {
        self.events.push(Event::Taint(reason));
    }
}

const PRE_RESUME_STAGES: [BootstrapStage; 13] = [
    BootstrapStage::AttributeOwnership,
    BootstrapStage::ValidateTargetType,
    BootstrapStage::ValidateQuotas,
    BootstrapStage::ValidateCreationRate,
    BootstrapStage::AssignIncarnation,
    BootstrapStage::RegisterTarget,
    BootstrapStage::InstallRecursiveAutoAttach,
    BootstrapStage::ApplyEmulation,
    BootstrapStage::InstallNetworkHooks,
    BootstrapStage::RunFeatureHooks,
    BootstrapStage::InstallLifecycleHandlers,
    BootstrapStage::InstallDialogHandlers,
    BootstrapStage::InstallFileChooserHandlers,
];

fn paused_page() -> PausedTarget {
    PausedTarget::new("target-primary", TargetKind::Page)
}

#[test]
fn paused_target_runs_every_bootstrap_stage_in_security_order_before_resume() {
    let barrier = TargetBootstrapBarrier::new();
    let mut backend = RecordingBackend::succeeding();

    assert!(barrier.bootstrap(&paused_page(), &mut backend).is_ok());

    let mut expected: Vec<Event> = PRE_RESUME_STAGES.into_iter().map(Event::Stage).collect();
    expected.push(Event::Stage(BootstrapStage::Resume));
    assert_eq!(backend.events, expected);
}

#[test]
fn failure_at_any_pre_resume_stage_closes_the_paused_target_without_resuming_it() {
    let barrier = TargetBootstrapBarrier::new();

    for (failed_index, failed_stage) in PRE_RESUME_STAGES.into_iter().enumerate() {
        let mut backend = RecordingBackend::failing(failed_stage, BootstrapStageFailure::Rejected);
        let result = barrier.bootstrap(&paused_page(), &mut backend);

        assert_eq!(
            result,
            Err(BootstrapError::StageFailed {
                stage: failed_stage,
                cause: BootstrapStageFailure::Rejected,
            }),
        );
        let mut expected: Vec<Event> = PRE_RESUME_STAGES[..=failed_index]
            .iter()
            .copied()
            .map(Event::Stage)
            .collect();
        expected.push(Event::Close);
        assert_eq!(backend.events, expected, "failure at {failed_stage:?}");
        assert!(
            !backend
                .events
                .contains(&Event::Stage(BootstrapStage::Resume))
        );
    }
}

#[test]
fn unknown_ownership_closes_the_target_and_requests_shard_taint() {
    let barrier = TargetBootstrapBarrier::new();
    let mut backend = RecordingBackend::failing(
        BootstrapStage::AttributeOwnership,
        BootstrapStageFailure::UnknownOwnership,
    );

    assert_eq!(
        barrier.bootstrap(&paused_page(), &mut backend),
        Err(BootstrapError::StageFailed {
            stage: BootstrapStage::AttributeOwnership,
            cause: BootstrapStageFailure::UnknownOwnership,
        }),
    );
    assert_eq!(
        backend.events,
        vec![
            Event::Stage(BootstrapStage::AttributeOwnership),
            Event::Close,
            Event::Taint(ShardTaintReason::UnknownTargetOwnership),
        ],
    );
    assert!(
        !backend
            .events
            .contains(&Event::Stage(BootstrapStage::Resume))
    );
}
