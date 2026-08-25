//! Session lifecycle, ownership fencing, reconnect capabilities, and cleanup.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use browserd_core::{
    ActionId, LeaseId as ReconnectToken, PlacementFence, PlacementState, SessionExecution,
    SessionExecutionEvent, SessionId, SessionLifecycle, WorkerId,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetId(String);

impl TargetId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionTime(u64);

impl SessionTime {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipFence {
    worker_id: WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
}

impl OwnershipFence {
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        placement_version: u64,
        session_incarnation: u64,
    ) -> Self {
        Self {
            worker_id,
            worker_epoch,
            placement_version,
            session_incarnation,
        }
    }

    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }

    pub const fn placement_version(&self) -> u64 {
        self.placement_version
    }

    pub const fn session_incarnation(&self) -> u64 {
        self.session_incarnation
    }

    pub const fn as_placement_fence(&self) -> PlacementFence {
        PlacementFence::new(
            self.worker_epoch,
            self.placement_version,
            self.session_incarnation,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionControl {
    Agent,
    Human,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionOperation {
    Start,
    MarkRunning,
    RenewLease,
    TransferOwner,
    RegisterTarget,
    RecordActivity,
    BeginAction,
    FinishAction,
    MarkActionOutcomeUnknown,
    ResolveAction,
    AcquireHumanControl,
    ReleaseHumanControl,
    BeginClose,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpireCause {
    OwnershipLease,
    SessionTtl,
    IdleTimeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidTransition {
        from: SessionLifecycle,
        operation: SessionOperation,
    },
    StaleWorkerId,
    WorkerEpochMismatch {
        expected: u64,
        received: u64,
    },
    PlacementVersionMismatch {
        expected: u64,
        received: u64,
    },
    SessionIncarnationMismatch {
        expected: u64,
        received: u64,
    },
    ClockMovedBackwards,
    TimeOverflow,
    RenewGraceElapsed {
        expired_at: SessionTime,
        grace_until: SessionTime,
    },
    SessionDeadlineElapsed {
        cause: ExpireCause,
        expired_at: SessionTime,
    },
    PlacementVersionOverflow,
    InvalidWorkerEpoch,
    TargetAdmissionClosed,
    DuplicateTarget,
    ActionAlreadyRunning,
    ActionNotRunning,
    ActionIdentityMismatch,
    HumanControlActive,
    HumanControlAlreadyAcquired,
    HumanControlNotAcquired,
    ExecutionNotIdle,
    StateUnavailable,
    CleanupFailed {
        stage: CleanupStage,
        cause: CleanupFailure,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeasePolicyError {
    ZeroTtl,
    DurationOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeasePolicy {
    ttl_millis: u64,
    renew_grace_millis: u64,
}

impl LeasePolicy {
    pub fn new(ttl: Duration, renew_grace: Duration) -> Result<Self, LeasePolicyError> {
        let ttl_millis =
            u64::try_from(ttl.as_millis()).map_err(|_| LeasePolicyError::DurationOverflow)?;
        let renew_grace_millis = u64::try_from(renew_grace.as_millis())
            .map_err(|_| LeasePolicyError::DurationOverflow)?;
        if ttl_millis == 0 {
            return Err(LeasePolicyError::ZeroTtl);
        }
        Ok(Self {
            ttl_millis,
            renew_grace_millis,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTimeoutPolicyError {
    ZeroTtl,
    ZeroIdleTimeout,
    DurationOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionTimeoutPolicy {
    ttl_millis: u64,
    idle_timeout_millis: u64,
}

impl SessionTimeoutPolicy {
    pub fn new(ttl: Duration, idle_timeout: Duration) -> Result<Self, SessionTimeoutPolicyError> {
        let ttl_millis = u64::try_from(ttl.as_millis())
            .map_err(|_| SessionTimeoutPolicyError::DurationOverflow)?;
        let idle_timeout_millis = u64::try_from(idle_timeout.as_millis())
            .map_err(|_| SessionTimeoutPolicyError::DurationOverflow)?;
        if ttl_millis == 0 {
            return Err(SessionTimeoutPolicyError::ZeroTtl);
        }
        if idle_timeout_millis == 0 {
            return Err(SessionTimeoutPolicyError::ZeroIdleTimeout);
        }
        Ok(Self {
            ttl_millis,
            idle_timeout_millis,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseRenewal {
    pub previous_expires_at: SessionTime,
    pub expires_at: SessionTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpireDecision {
    NotDue { expires_at: SessionTime },
    BeganExpiring,
    OwnershipLost,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBinding {
    principal_id: String,
    channel_id: String,
}

impl ClientBinding {
    pub fn new(principal_id: impl Into<String>, channel_id: impl Into<String>) -> Self {
        Self {
            principal_id: principal_id.into(),
            channel_id: channel_id.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconnectError {
    InvalidLifecycle,
    StaleWorkerId,
    WorkerEpochMismatch,
    PlacementVersionMismatch,
    SessionIncarnationMismatch,
    InvalidTtl,
    TimeOverflow,
    ClockMovedBackwards,
    SessionMismatch,
    BindingMismatch,
    TokenExpired,
    TokenUsedOrUnknown,
    StaleOwnershipFence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupStage {
    RejectNewWork,
    CancelQueuedActions,
    QuiesceRunningAction,
    StopViewers,
    CancelDownloads,
    ForceCloseTargets,
    DisposeBrowserContext,
    VerifyRegistriesEmpty,
    RevokeProxyRoute,
    DeleteMaterializedFiles,
    FinalizeArtifacts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupFailure {
    Injected,
    RegistryNotEmpty,
}

pub trait CleanupBackend {
    fn run_stage(
        &mut self,
        stage: CleanupStage,
        active_targets: &[TargetId],
    ) -> Result<(), CleanupFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupReport {
    pub drained_targets: usize,
    pub completed_stages: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    pub lifecycle: SessionLifecycle,
    pub placement: PlacementState,
    pub execution: SessionExecution,
    pub control: SessionControl,
    pub owner_fence: OwnershipFence,
    pub lease_expires_at: Option<SessionTime>,
    pub session_expires_at: Option<SessionTime>,
    pub idle_expires_at: Option<SessionTime>,
    pub accepting_targets: bool,
    pub active_targets: usize,
}

#[derive(Clone, Debug)]
struct ReconnectGrant {
    session_id: SessionId,
    binding: ClientBinding,
    owner_fence: OwnershipFence,
    expires_at: SessionTime,
}

const CLEANUP_STAGES: [CleanupStage; 11] = [
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

#[derive(Clone, Debug)]
pub struct SessionMachine {
    session_id: SessionId,
    owner_fence: OwnershipFence,
    lease_policy: LeasePolicy,
    lifecycle: SessionLifecycle,
    creation_started: bool,
    placement: PlacementState,
    execution: SessionExecution,
    control: SessionControl,
    lease_expires_at: Option<SessionTime>,
    session_expires_at: Option<SessionTime>,
    idle_expires_at: Option<SessionTime>,
    idle_timeout_millis: Option<u64>,
    last_observed_at: SessionTime,
    expire_cause: Option<ExpireCause>,
    accepting_targets: bool,
    active_targets: BTreeSet<TargetId>,
    reconnect_grants: BTreeMap<ReconnectToken, ReconnectGrant>,
    cleanup_stage_index: usize,
    cleanup_drained_targets: usize,
}

impl SessionMachine {
    pub fn create(
        session_id: SessionId,
        fence: OwnershipFence,
        policy: LeasePolicy,
        now: SessionTime,
    ) -> (Self, OwnershipFence) {
        let lease_expires_at = now.0.checked_add(policy.ttl_millis).map(SessionTime::new);
        (
            Self {
                session_id,
                owner_fence: fence.clone(),
                lease_policy: policy,
                lifecycle: SessionLifecycle::Creating,
                creation_started: false,
                placement: PlacementState::Reserved,
                execution: SessionExecution::Idle,
                control: SessionControl::Agent,
                lease_expires_at,
                session_expires_at: None,
                idle_expires_at: None,
                idle_timeout_millis: None,
                last_observed_at: now,
                expire_cause: None,
                accepting_targets: false,
                active_targets: BTreeSet::new(),
                reconnect_grants: BTreeMap::new(),
                cleanup_stage_index: 0,
                cleanup_drained_targets: 0,
            },
            fence,
        )
    }

    pub fn create_with_timeouts(
        session_id: SessionId,
        fence: OwnershipFence,
        lease_policy: LeasePolicy,
        timeout_policy: SessionTimeoutPolicy,
        now: SessionTime,
    ) -> (Self, OwnershipFence) {
        let (mut machine, fence) = Self::create(session_id, fence, lease_policy, now);
        machine.session_expires_at = now
            .0
            .checked_add(timeout_policy.ttl_millis)
            .map(SessionTime::new);
        machine.idle_expires_at = now
            .0
            .checked_add(timeout_policy.idle_timeout_millis)
            .map(SessionTime::new);
        machine.idle_timeout_millis = Some(timeout_policy.idle_timeout_millis);
        (machine, fence)
    }

    pub const fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle
    }

    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub const fn lease_expires_at(&self) -> Option<SessionTime> {
        self.lease_expires_at
    }

    pub const fn accepting_targets(&self) -> bool {
        self.accepting_targets
    }

    pub fn active_target_count(&self) -> usize {
        self.active_targets.len()
    }

    pub const fn expire_cause(&self) -> Option<ExpireCause> {
        self.expire_cause
    }

    pub fn start(
        &mut self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<SessionLifecycle, SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Creating || self.creation_started {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::Start,
            });
        }
        if self.lease_expires_at.is_none()
            || (self.idle_timeout_millis.is_some()
                && (self.session_expires_at.is_none() || self.idle_expires_at.is_none()))
        {
            return Err(SessionError::TimeOverflow);
        }
        self.observe_time(now)?;
        self.creation_started = true;
        Ok(self.lifecycle)
    }

    pub fn mark_running(
        &mut self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<SessionLifecycle, SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Creating || !self.creation_started {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::MarkRunning,
            });
        }
        self.validate_active_deadlines(now)?;
        self.observe_time(now)?;
        self.lifecycle = SessionLifecycle::Ready;
        self.placement = PlacementState::Attached;
        self.accepting_targets = true;
        Ok(self.lifecycle)
    }

    pub fn renew_lease(
        &mut self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<LeaseRenewal, SessionError> {
        self.validate_fence(fence)?;
        if !matches!(
            self.lifecycle,
            SessionLifecycle::Creating | SessionLifecycle::Ready
        ) {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::RenewLease,
            });
        }
        if now < self.last_observed_at {
            return Err(SessionError::ClockMovedBackwards);
        }
        if let Some(expires_at) = self.session_expires_at
            && now >= expires_at
        {
            return Err(SessionError::SessionDeadlineElapsed {
                cause: ExpireCause::SessionTtl,
                expired_at: expires_at,
            });
        }
        if let Some(expires_at) = self.idle_expires_at
            && now >= expires_at
        {
            return Err(SessionError::SessionDeadlineElapsed {
                cause: ExpireCause::IdleTimeout,
                expired_at: expires_at,
            });
        }
        let Some(previous_expires_at) = self.lease_expires_at else {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::RenewLease,
            });
        };
        let grace_until = previous_expires_at
            .0
            .checked_add(self.lease_policy.renew_grace_millis)
            .map(SessionTime::new)
            .ok_or(SessionError::TimeOverflow)?;
        if now > grace_until {
            return Err(SessionError::RenewGraceElapsed {
                expired_at: previous_expires_at,
                grace_until,
            });
        }
        let expires_at = now
            .0
            .checked_add(self.lease_policy.ttl_millis)
            .map(SessionTime::new)
            .ok_or(SessionError::TimeOverflow)?;
        self.last_observed_at = now;
        self.lease_expires_at = Some(expires_at);
        Ok(LeaseRenewal {
            previous_expires_at,
            expires_at,
        })
    }

    pub fn expire_due(
        &mut self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<ExpireDecision, SessionError> {
        self.validate_fence(fence)?;
        if !matches!(
            self.lifecycle,
            SessionLifecycle::Creating | SessionLifecycle::Ready
        ) {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::Cleanup,
            });
        }
        if now < self.last_observed_at {
            return Err(SessionError::ClockMovedBackwards);
        }

        let due = if self
            .session_expires_at
            .is_some_and(|expires_at| now >= expires_at)
        {
            self.session_expires_at
                .map(|expires_at| (ExpireCause::SessionTtl, expires_at))
        } else if self
            .idle_expires_at
            .is_some_and(|expires_at| now >= expires_at)
        {
            self.idle_expires_at
                .map(|expires_at| (ExpireCause::IdleTimeout, expires_at))
        } else if self
            .lease_expires_at
            .is_some_and(|expires_at| now >= expires_at)
        {
            self.lease_expires_at
                .map(|expires_at| (ExpireCause::OwnershipLease, expires_at))
        } else {
            None
        };

        if let Some((cause, _)) = due {
            self.last_observed_at = now;
            self.accepting_targets = false;
            self.expire_cause = Some(cause);
            if cause == ExpireCause::OwnershipLease {
                self.lifecycle = SessionLifecycle::Failed;
                self.placement = PlacementState::Lost;
                if let SessionExecution::Running(action_id) = self.execution.clone() {
                    self.execution = self
                        .execution
                        .clone()
                        .transition(SessionExecutionEvent::OutcomeUnknown(action_id))
                        .map_err(|_| SessionError::ActionIdentityMismatch)?;
                } else if let SessionExecution::PendingApproval(action_id) = self.execution.clone()
                {
                    self.execution = self
                        .execution
                        .clone()
                        .transition(SessionExecutionEvent::KnownCompletion(action_id))
                        .map_err(|_| SessionError::ActionIdentityMismatch)?;
                }
                self.reconnect_grants.clear();
                return Ok(ExpireDecision::OwnershipLost);
            }
            self.lifecycle = SessionLifecycle::Closing;
            self.reconnect_grants.clear();
            self.cleanup_drained_targets = self.active_targets.len();
            return Ok(ExpireDecision::BeganExpiring);
        }

        let expires_at = [
            self.lease_expires_at,
            self.session_expires_at,
            self.idle_expires_at,
        ]
        .into_iter()
        .flatten()
        .min()
        .ok_or(SessionError::TimeOverflow)?;
        self.last_observed_at = now;
        Ok(ExpireDecision::NotDue { expires_at })
    }

    pub fn transfer_owner(
        &mut self,
        fence: &OwnershipFence,
        new_worker_id: WorkerId,
        new_worker_epoch: u64,
        now: SessionTime,
    ) -> Result<OwnershipFence, SessionError> {
        self.validate_fence(fence)?;
        if !matches!(
            self.lifecycle,
            SessionLifecycle::Creating | SessionLifecycle::Ready
        ) {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::TransferOwner,
            });
        }
        self.validate_active_deadlines(now)?;
        if now < self.last_observed_at {
            return Err(SessionError::ClockMovedBackwards);
        }
        if new_worker_epoch == 0 {
            return Err(SessionError::InvalidWorkerEpoch);
        }
        if new_worker_id == self.owner_fence.worker_id
            && new_worker_epoch <= self.owner_fence.worker_epoch
        {
            return Err(SessionError::WorkerEpochMismatch {
                expected: self.owner_fence.worker_epoch.saturating_add(1),
                received: new_worker_epoch,
            });
        }
        let placement_version = self
            .owner_fence
            .placement_version
            .checked_add(1)
            .ok_or(SessionError::PlacementVersionOverflow)?;
        let lease_expires_at = now
            .0
            .checked_add(self.lease_policy.ttl_millis)
            .map(SessionTime::new)
            .ok_or(SessionError::TimeOverflow)?;
        self.last_observed_at = now;
        self.owner_fence = OwnershipFence::new(
            new_worker_id,
            new_worker_epoch,
            placement_version,
            self.owner_fence.session_incarnation,
        );
        self.lease_expires_at = Some(lease_expires_at);
        Ok(self.owner_fence.clone())
    }

    pub fn begin_close(
        &mut self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<SessionLifecycle, SessionError> {
        self.validate_fence(fence)?;
        if matches!(
            self.lifecycle,
            SessionLifecycle::Closing | SessionLifecycle::Closed
        ) {
            return Ok(self.lifecycle);
        }
        if !matches!(
            self.lifecycle,
            SessionLifecycle::Creating | SessionLifecycle::Ready
        ) {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::BeginClose,
            });
        }
        self.observe_time(now)?;
        if let SessionExecution::Running(action_id) = self.execution.clone() {
            self.execution = self
                .execution
                .clone()
                .transition(SessionExecutionEvent::OutcomeUnknown(action_id))
                .map_err(|_| SessionError::ActionIdentityMismatch)?;
        } else if let SessionExecution::PendingApproval(action_id) = self.execution.clone() {
            self.execution = self
                .execution
                .clone()
                .transition(SessionExecutionEvent::KnownCompletion(action_id))
                .map_err(|_| SessionError::ActionIdentityMismatch)?;
        }
        self.lifecycle = SessionLifecycle::Closing;
        self.accepting_targets = false;
        self.reconnect_grants.clear();
        self.cleanup_drained_targets = self.active_targets.len();
        Ok(self.lifecycle)
    }

    pub fn register_target(
        &mut self,
        fence: &OwnershipFence,
        target: TargetId,
    ) -> Result<(), SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Ready || !self.accepting_targets {
            return Err(SessionError::TargetAdmissionClosed);
        }
        if !self.active_targets.insert(target) {
            return Err(SessionError::DuplicateTarget);
        }
        Ok(())
    }

    pub fn record_activity(
        &mut self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<(), SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Ready {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::RecordActivity,
            });
        }
        self.validate_active_deadlines(now)?;
        if now < self.last_observed_at {
            return Err(SessionError::ClockMovedBackwards);
        }
        if let Some(idle_timeout_millis) = self.idle_timeout_millis {
            let mut idle_expires_at = now
                .0
                .checked_add(idle_timeout_millis)
                .map(SessionTime::new)
                .ok_or(SessionError::TimeOverflow)?;
            if let Some(session_expires_at) = self.session_expires_at {
                idle_expires_at = idle_expires_at.min(session_expires_at);
            }
            self.idle_expires_at = Some(idle_expires_at);
        }
        self.last_observed_at = now;
        Ok(())
    }

    pub fn begin_action(
        &mut self,
        fence: &OwnershipFence,
        action_id: ActionId,
        now: SessionTime,
    ) -> Result<(), SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Ready {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::BeginAction,
            });
        }
        if self.control == SessionControl::Human {
            return Err(SessionError::HumanControlActive);
        }
        let execution = self
            .execution
            .clone()
            .transition(SessionExecutionEvent::ActionAccepted(action_id))
            .map_err(|_| SessionError::ActionAlreadyRunning)?;
        self.validate_active_deadlines(now)?;
        self.observe_time(now)?;
        self.execution = execution;
        Ok(())
    }

    pub fn finish_action(
        &mut self,
        fence: &OwnershipFence,
        action_id: &ActionId,
        now: SessionTime,
    ) -> Result<(), SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Ready {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::FinishAction,
            });
        }
        if !matches!(self.execution, SessionExecution::Running(_)) {
            return Err(SessionError::ActionNotRunning);
        }
        let execution = self
            .execution
            .clone()
            .transition(SessionExecutionEvent::KnownCompletion(action_id.clone()))
            .map_err(|_| SessionError::ActionIdentityMismatch)?;
        self.observe_time(now)?;
        self.execution = execution;
        Ok(())
    }

    pub fn mark_action_outcome_unknown(
        &mut self,
        fence: &OwnershipFence,
        action_id: &ActionId,
        now: SessionTime,
    ) -> Result<(), SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Ready {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::MarkActionOutcomeUnknown,
            });
        }
        let execution = self
            .execution
            .clone()
            .transition(SessionExecutionEvent::OutcomeUnknown(action_id.clone()))
            .map_err(|_| SessionError::ActionIdentityMismatch)?;
        self.validate_active_deadlines(now)?;
        self.observe_time(now)?;
        self.execution = execution;
        Ok(())
    }

    pub fn resolve_action(
        &mut self,
        fence: &OwnershipFence,
        action_id: &ActionId,
        now: SessionTime,
    ) -> Result<(), SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Ready {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::ResolveAction,
            });
        }
        let execution = self
            .execution
            .clone()
            .transition(SessionExecutionEvent::Resolve(action_id.clone()))
            .map_err(|_| SessionError::ActionIdentityMismatch)?;
        self.validate_active_deadlines(now)?;
        self.observe_time(now)?;
        self.execution = execution;
        Ok(())
    }

    pub fn acquire_human_control(
        &mut self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<(), SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Ready {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::AcquireHumanControl,
            });
        }
        if self.execution != SessionExecution::Idle {
            return Err(SessionError::ExecutionNotIdle);
        }
        if self.control == SessionControl::Human {
            return Err(SessionError::HumanControlAlreadyAcquired);
        }
        self.validate_active_deadlines(now)?;
        self.observe_time(now)?;
        self.control = SessionControl::Human;
        Ok(())
    }

    pub fn release_human_control(
        &mut self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<(), SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Ready {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::ReleaseHumanControl,
            });
        }
        if self.control == SessionControl::Agent {
            return Err(SessionError::HumanControlNotAcquired);
        }
        self.validate_active_deadlines(now)?;
        self.observe_time(now)?;
        self.control = SessionControl::Agent;
        Ok(())
    }

    pub fn issue_reconnect_token(
        &mut self,
        fence: &OwnershipFence,
        binding: ClientBinding,
        now: SessionTime,
        ttl: Duration,
    ) -> Result<ReconnectToken, ReconnectError> {
        if fence.worker_id != self.owner_fence.worker_id {
            return Err(ReconnectError::StaleWorkerId);
        }
        if fence.worker_epoch != self.owner_fence.worker_epoch {
            return Err(ReconnectError::WorkerEpochMismatch);
        }
        if fence.placement_version != self.owner_fence.placement_version {
            return Err(ReconnectError::PlacementVersionMismatch);
        }
        if fence.session_incarnation != self.owner_fence.session_incarnation {
            return Err(ReconnectError::SessionIncarnationMismatch);
        }
        if self.lifecycle != SessionLifecycle::Ready {
            return Err(ReconnectError::InvalidLifecycle);
        }
        if now < self.last_observed_at {
            return Err(ReconnectError::ClockMovedBackwards);
        }
        if self
            .session_expires_at
            .is_some_and(|expires_at| now >= expires_at)
            || self
                .idle_expires_at
                .is_some_and(|expires_at| now >= expires_at)
            || self
                .lease_expires_at
                .is_some_and(|expires_at| now >= expires_at)
        {
            return Err(ReconnectError::InvalidLifecycle);
        }
        let ttl_millis =
            u64::try_from(ttl.as_millis()).map_err(|_| ReconnectError::TimeOverflow)?;
        if ttl_millis == 0 {
            return Err(ReconnectError::InvalidTtl);
        }
        let expires_at = now
            .0
            .checked_add(ttl_millis)
            .map(SessionTime::new)
            .ok_or(ReconnectError::TimeOverflow)?;
        let token = ReconnectToken::new();
        self.last_observed_at = now;
        self.reconnect_grants.insert(
            token.clone(),
            ReconnectGrant {
                session_id: self.session_id.clone(),
                binding,
                owner_fence: self.owner_fence.clone(),
                expires_at,
            },
        );
        Ok(token)
    }

    pub fn consume_reconnect_token(
        &mut self,
        token: &ReconnectToken,
        session_id: &SessionId,
        binding: &ClientBinding,
        now: SessionTime,
    ) -> Result<OwnershipFence, ReconnectError> {
        if now < self.last_observed_at {
            return Err(ReconnectError::ClockMovedBackwards);
        }
        let Some(grant) = self.reconnect_grants.get(token) else {
            return Err(ReconnectError::TokenUsedOrUnknown);
        };
        if now >= grant.expires_at {
            self.last_observed_at = now;
            self.reconnect_grants.remove(token);
            return Err(ReconnectError::TokenExpired);
        }
        if grant.owner_fence != self.owner_fence {
            self.last_observed_at = now;
            self.reconnect_grants.remove(token);
            return Err(ReconnectError::StaleOwnershipFence);
        }
        if self.lifecycle != SessionLifecycle::Ready || self.validate_active_deadlines(now).is_err()
        {
            self.last_observed_at = now;
            self.reconnect_grants.remove(token);
            return Err(ReconnectError::InvalidLifecycle);
        }
        if &grant.session_id != session_id {
            return Err(ReconnectError::SessionMismatch);
        }
        if &grant.binding != binding {
            return Err(ReconnectError::BindingMismatch);
        }
        let owner_fence = grant.owner_fence.clone();
        self.last_observed_at = now;
        self.reconnect_grants.remove(token);
        Ok(owner_fence)
    }

    pub fn run_cleanup<B: CleanupBackend>(
        &mut self,
        fence: &OwnershipFence,
        backend: &mut B,
    ) -> Result<CleanupReport, SessionError> {
        self.validate_fence(fence)?;
        if self.lifecycle != SessionLifecycle::Closing {
            return Err(SessionError::InvalidTransition {
                from: self.lifecycle,
                operation: SessionOperation::Cleanup,
            });
        }

        while self.cleanup_stage_index < CLEANUP_STAGES.len() {
            let stage = CLEANUP_STAGES[self.cleanup_stage_index];
            let active_targets = if stage == CleanupStage::ForceCloseTargets {
                self.active_targets.iter().cloned().collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            if let Err(cause) = backend.run_stage(stage, &active_targets) {
                return Err(SessionError::CleanupFailed { stage, cause });
            }
            if stage == CleanupStage::ForceCloseTargets {
                self.active_targets.clear();
            }
            self.cleanup_stage_index += 1;
        }

        self.lifecycle = SessionLifecycle::Closed;
        self.accepting_targets = false;
        self.lease_expires_at = None;
        self.reconnect_grants.clear();
        Ok(CleanupReport {
            drained_targets: self.cleanup_drained_targets,
            completed_stages: self.cleanup_stage_index,
        })
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            lifecycle: self.lifecycle,
            placement: self.placement,
            execution: self.execution.clone(),
            control: self.control,
            owner_fence: self.owner_fence.clone(),
            lease_expires_at: self.lease_expires_at,
            session_expires_at: self.session_expires_at,
            idle_expires_at: self.idle_expires_at,
            accepting_targets: self.accepting_targets,
            active_targets: self.active_targets.len(),
        }
    }

    fn validate_fence(&self, fence: &OwnershipFence) -> Result<(), SessionError> {
        if fence.worker_id != self.owner_fence.worker_id {
            return Err(SessionError::StaleWorkerId);
        }
        if fence.worker_epoch != self.owner_fence.worker_epoch {
            return Err(SessionError::WorkerEpochMismatch {
                expected: self.owner_fence.worker_epoch,
                received: fence.worker_epoch,
            });
        }
        if fence.placement_version != self.owner_fence.placement_version {
            return Err(SessionError::PlacementVersionMismatch {
                expected: self.owner_fence.placement_version,
                received: fence.placement_version,
            });
        }
        if fence.session_incarnation != self.owner_fence.session_incarnation {
            return Err(SessionError::SessionIncarnationMismatch {
                expected: self.owner_fence.session_incarnation,
                received: fence.session_incarnation,
            });
        }
        Ok(())
    }

    fn validate_active_deadlines(&self, now: SessionTime) -> Result<(), SessionError> {
        if let Some(expires_at) = self.session_expires_at
            && now >= expires_at
        {
            return Err(SessionError::SessionDeadlineElapsed {
                cause: ExpireCause::SessionTtl,
                expired_at: expires_at,
            });
        }
        if let Some(expires_at) = self.idle_expires_at
            && now >= expires_at
        {
            return Err(SessionError::SessionDeadlineElapsed {
                cause: ExpireCause::IdleTimeout,
                expired_at: expires_at,
            });
        }
        if let Some(expires_at) = self.lease_expires_at
            && now >= expires_at
        {
            return Err(SessionError::SessionDeadlineElapsed {
                cause: ExpireCause::OwnershipLease,
                expired_at: expires_at,
            });
        }
        Ok(())
    }

    fn observe_time(&mut self, now: SessionTime) -> Result<(), SessionError> {
        if now < self.last_observed_at {
            return Err(SessionError::ClockMovedBackwards);
        }
        self.last_observed_at = now;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SharedSession(Arc<Mutex<SessionMachine>>);

impl SharedSession {
    pub fn new(machine: SessionMachine) -> Self {
        Self(Arc::new(Mutex::new(machine)))
    }

    pub fn renew_lease(
        &self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<LeaseRenewal, SessionError> {
        match self.0.lock() {
            Ok(mut machine) => machine.renew_lease(fence, now),
            Err(_) => Err(SessionError::StateUnavailable),
        }
    }

    pub fn expire_due(
        &self,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<ExpireDecision, SessionError> {
        match self.0.lock() {
            Ok(mut machine) => machine.expire_due(fence, now),
            Err(_) => Err(SessionError::StateUnavailable),
        }
    }

    pub fn snapshot(&self) -> Result<SessionSnapshot, SessionError> {
        match self.0.lock() {
            Ok(machine) => Ok(machine.snapshot()),
            Err(_) => Err(SessionError::StateUnavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_shared_state_fails_closed_for_reads_and_mutations() {
        let policy = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20));
        assert!(policy.is_ok());
        let Some(policy) = policy.ok() else {
            return;
        };
        let worker = WorkerId::new("worker-a");
        assert!(worker.is_ok());
        let Some(worker) = worker.ok() else {
            return;
        };
        let initial = OwnershipFence::new(worker, 1, 1, 1);
        let (machine, fence) =
            SessionMachine::create(SessionId::new(), initial, policy, SessionTime::new(0));
        let shared = SharedSession::new(machine);
        let poison_target = shared.clone();
        let poison = std::thread::spawn(move || {
            let guard = poison_target.0.lock();
            assert!(guard.is_ok());
            assert!(std::thread::current().name().is_some());
        })
        .join();
        assert!(poison.is_err());

        assert_eq!(shared.snapshot(), Err(SessionError::StateUnavailable));
        assert_eq!(
            shared.renew_lease(&fence, SessionTime::new(1)),
            Err(SessionError::StateUnavailable),
        );
        assert_eq!(
            shared.expire_due(&fence, SessionTime::new(100)),
            Err(SessionError::StateUnavailable),
        );
    }
}
