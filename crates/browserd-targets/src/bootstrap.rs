use crate::TargetKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapStage {
    AttributeOwnership,
    ValidateTargetType,
    ValidateQuotas,
    ValidateCreationRate,
    AssignIncarnation,
    RegisterTarget,
    InstallRecursiveAutoAttach,
    ApplyEmulation,
    InstallNetworkHooks,
    RunFeatureHooks,
    InstallLifecycleHandlers,
    InstallDialogHandlers,
    InstallFileChooserHandlers,
    Resume,
}

const ORDERED_STAGES: [BootstrapStage; 14] = [
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
    BootstrapStage::Resume,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapStageFailure {
    Rejected,
    UnknownOwnership,
    StateOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardTaintReason {
    UnknownTargetOwnership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    StageFailed {
        stage: BootstrapStage,
        cause: BootstrapStageFailure,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PausedTarget {
    target_id: String,
    kind: TargetKind,
}

impl PausedTarget {
    #[must_use]
    pub fn new(target_id: impl Into<String>, kind: TargetKind) -> Self {
        Self {
            target_id: target_id.into(),
            kind,
        }
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    #[must_use]
    pub const fn kind(&self) -> &TargetKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyTarget {
    target_id: String,
}

impl ReadyTarget {
    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
}

/// The single-writer interface used by the bootstrap barrier. Implementations
/// own CDP and registry mutation; the barrier alone determines ordering.
pub trait BootstrapBackend {
    fn run_stage(
        &mut self,
        target: &PausedTarget,
        stage: BootstrapStage,
    ) -> Result<(), BootstrapStageFailure>;

    fn close_paused_target(&mut self, target: &PausedTarget);

    fn taint_shard(&mut self, reason: ShardTaintReason);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TargetBootstrapBarrier;

impl TargetBootstrapBarrier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn bootstrap<B: BootstrapBackend>(
        &self,
        target: &PausedTarget,
        backend: &mut B,
    ) -> Result<ReadyTarget, BootstrapError> {
        for stage in ORDERED_STAGES {
            if let Err(cause) = backend.run_stage(target, stage) {
                backend.close_paused_target(target);
                if cause == BootstrapStageFailure::UnknownOwnership {
                    backend.taint_shard(ShardTaintReason::UnknownTargetOwnership);
                }
                return Err(BootstrapError::StageFailed { stage, cause });
            }
        }
        Ok(ReadyTarget {
            target_id: target.target_id.clone(),
        })
    }
}
