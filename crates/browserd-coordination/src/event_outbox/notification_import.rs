//! Atomic imports from immutable worker notification journals.
//!
//! A permanent source watermark prevents payload retention from reopening source sequences.
//! The most recent 64 sequence digests also survive retention. The authenticated relay must
//! acknowledge the oldest source commit before advancing; an older retry outside that bounded
//! receipt window fails closed rather than fabricating an acknowledgement.

use std::collections::{HashSet, VecDeque};

use browserd_core::{
    NotificationAck, NotificationActionResolution, NotificationActionState,
    NotificationApprovalDecision, NotificationArtifactState, NotificationCommit,
    NotificationControlState, NotificationSessionExecutionState, NotificationSessionLifecycleState,
    NotificationSourceFamily, WorkerNotificationEvent,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    EventActionResolution, EventActionState, EventApprovalDecision, EventArtifactState,
    EventControlState, EventDownloadState, EventOutboxError, EventSessionExecutionState,
    EventSessionLifecycleState, EventStateSummary, MemoryEventOutbox, OutboxAggregate,
    OutboxAppend, OutboxEvent, OutboxEventKind,
};

pub const NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE: usize = 64;
const MAX_NOTIFICATION_SOURCES: usize = 1_048_576;

/// Lifetime capacity for permanent source identities, independent of payload retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotificationImportConfig {
    max_sources: usize,
    max_sources_per_tenant: usize,
}

impl NotificationImportConfig {
    pub fn new(
        max_sources: usize,
        max_sources_per_tenant: usize,
    ) -> Result<Self, EventOutboxError> {
        if !(1..=MAX_NOTIFICATION_SOURCES).contains(&max_sources)
            || max_sources_per_tenant == 0
            || max_sources_per_tenant > max_sources
        {
            return Err(EventOutboxError::InvalidNotificationImportConfig);
        }
        Ok(Self {
            max_sources,
            max_sources_per_tenant,
        })
    }

    #[must_use]
    pub const fn max_sources(self) -> usize {
        self.max_sources
    }

    #[must_use]
    pub const fn max_sources_per_tenant(self) -> usize {
        self.max_sources_per_tenant
    }

    pub(super) fn digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"browserd.notification-import-config.v1\0");
        hash.update((self.max_sources as u64).to_be_bytes());
        hash.update((self.max_sources_per_tenant as u64).to_be_bytes());
        hash.update((NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE as u64).to_be_bytes());
        hash.finalize().into()
    }
}

impl Default for NotificationImportConfig {
    fn default() -> Self {
        Self {
            max_sources: 16_384,
            max_sources_per_tenant: 1_024,
        }
    }
}

#[derive(Default)]
pub(super) struct NotificationMemoryNamespace {
    pub config_digest: Option<[u8; 32]>,
    pub source_count: usize,
}

#[derive(Default)]
pub(super) struct NotificationWatermark {
    highwater: u64,
    receipts: VecDeque<(u64, [u8; 32])>,
}

impl NotificationWatermark {
    fn is_replay(&self, commit: &NotificationCommit) -> Result<bool, EventOutboxError> {
        if commit.source_sequence() > self.highwater {
            if commit.source_sequence() != self.highwater + 1 {
                return Err(EventOutboxError::ProjectionGap);
            }
            return Ok(false);
        }
        let digest = self
            .receipts
            .iter()
            .find_map(|(seq, digest)| (*seq == commit.source_sequence()).then_some(*digest))
            .ok_or(EventOutboxError::NotificationReceiptExpired)?;
        if digest != commit.digest() {
            return Err(EventOutboxError::NotificationDigestMismatch);
        }
        Ok(true)
    }

    fn record(&mut self, commit: &NotificationCommit) {
        self.highwater = commit.source_sequence();
        self.receipts
            .push_back((commit.source_sequence(), commit.digest()));
        if self.receipts.len() > NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE {
            self.receipts.pop_front();
        }
    }
}

macro_rules! map_states {
    ($source:ident => $target:ident {$($variant:ident),+ $(,)?}) => {
        impl From<$source> for $target {
            fn from(state: $source) -> Self {
                match state { $($source::$variant => Self::$variant),+ }
            }
        }
    };
}
map_states!(NotificationSessionLifecycleState => EventSessionLifecycleState {
    Creating, Ready, Closing, Closed, Failed
});
map_states!(NotificationSessionExecutionState => EventSessionExecutionState {
    Idle, Running, PendingApproval, ReconciliationRequired
});
map_states!(NotificationActionState => EventActionState {
    Accepted, Queued, PendingApproval, ReadyToDispatch, MayHaveExecuted, Succeeded,
    FailedKnown, CancelledBeforeDispatch, CancelledConfirmed, OutcomeUnknown
});
map_states!(NotificationActionResolution => EventActionResolution {
    ConfirmedExecuted, ConfirmedNotExecuted, Abandoned
});
map_states!(NotificationApprovalDecision => EventApprovalDecision { Approved, Denied, Expired });
map_states!(NotificationControlState => EventControlState { Agent, Human });
map_states!(NotificationArtifactState => EventArtifactState {
    Uploading, Stored, Scanning, Available, Quarantined, Rejected, Generating,
    Finalizing, Failed, Deleting, Deleted
});

pub(super) fn source_family_name(family: NotificationSourceFamily) -> &'static str {
    match family {
        NotificationSourceFamily::ActionJournal => "action_journal",
        NotificationSourceFamily::ArtifactRegistry => "artifact_registry",
        NotificationSourceFamily::SessionLifecycle => "session_lifecycle",
        NotificationSourceFamily::ControlJournal => "control_journal",
    }
}

pub(super) struct PreparedNotificationBatch {
    pub(super) created_at: DateTime<Utc>,
    pub(super) events: Vec<(Uuid, OutboxAppend)>,
}

pub(super) fn mapped_events(
    commit: &NotificationCommit,
) -> Result<PreparedNotificationBatch, EventOutboxError> {
    commit
        .validate()
        .map_err(|_| EventOutboxError::InvalidNotificationCommit)?;
    let created_at = DateTime::from_timestamp_millis(
        i64::try_from(commit.occurred_at_unix_ms())
            .map_err(|_| EventOutboxError::InvalidNotificationCommit)?,
    )
    .ok_or(EventOutboxError::InvalidNotificationCommit)?;
    let mut events = Vec::with_capacity(commit.descriptors().len());
    let mut keys = HashSet::with_capacity(commit.descriptors().len());
    for descriptor in commit.descriptors() {
        let session_id = descriptor.session_scope().session_id().clone();
        let session = || OutboxAggregate::Session {
            session_id: session_id.clone(),
        };
        let (aggregate, kind, summary) = match descriptor.event() {
            WorkerNotificationEvent::SessionLifecycleChanged { state } => (
                session(),
                OutboxEventKind::SessionLifecycleChanged,
                EventStateSummary::SessionLifecycle {
                    state: (*state).into(),
                },
            ),
            WorkerNotificationEvent::SessionExecutionChanged { state, action_id } => (
                session(),
                OutboxEventKind::SessionExecutionChanged,
                EventStateSummary::SessionExecution {
                    state: (*state).into(),
                    action_id: action_id.clone(),
                },
            ),
            WorkerNotificationEvent::ActionStateChanged {
                action_id,
                state,
                resolution,
            } => (
                OutboxAggregate::Action {
                    session_id,
                    action_id: action_id.clone(),
                },
                OutboxEventKind::ActionStateChanged,
                EventStateSummary::Action {
                    state: (*state).into(),
                    resolution: resolution.map(Into::into),
                },
            ),
            WorkerNotificationEvent::ActionApprovalRequired {
                action_id,
                approval_id,
            } => (
                OutboxAggregate::Action {
                    session_id,
                    action_id: action_id.clone(),
                },
                OutboxEventKind::ActionApprovalRequired,
                EventStateSummary::ApprovalRequired {
                    approval_id: approval_id.clone(),
                },
            ),
            WorkerNotificationEvent::ApprovalDecided {
                action_id,
                approval_id,
                state,
            } => (
                OutboxAggregate::Approval {
                    session_id,
                    action_id: action_id.clone(),
                    approval_id: approval_id.clone(),
                },
                OutboxEventKind::ApprovalDecided,
                EventStateSummary::Approval {
                    state: (*state).into(),
                },
            ),
            WorkerNotificationEvent::BrowserControlChanged { state } => (
                session(),
                OutboxEventKind::BrowserControlChanged,
                EventStateSummary::Control {
                    state: (*state).into(),
                },
            ),
            WorkerNotificationEvent::DownloadCompleted { artifact_id } => (
                OutboxAggregate::Artifact {
                    session_id,
                    artifact_id: artifact_id.clone(),
                },
                OutboxEventKind::DownloadCompleted,
                EventStateSummary::Download {
                    state: EventDownloadState::Completed,
                },
            ),
            WorkerNotificationEvent::ArtifactStateChanged { artifact_id, state } => (
                OutboxAggregate::Artifact {
                    session_id,
                    artifact_id: artifact_id.clone(),
                },
                OutboxEventKind::ArtifactStateChanged,
                EventStateSummary::Artifact {
                    state: (*state).into(),
                },
            ),
        };
        let append = OutboxAppend::state_changed(
            commit.scope().tenant_id().clone(),
            aggregate,
            commit.source_sequence(),
            kind,
            summary,
        )?;
        if !keys.insert((
            append.aggregate.clone(),
            append.aggregate_revision,
            append.kind,
        )) {
            return Err(EventOutboxError::InvalidNotificationCommit);
        }
        events.push((descriptor.event_id(), append));
    }
    Ok(PreparedNotificationBatch { created_at, events })
}

impl MemoryEventOutbox {
    /// Set immutable lifetime source capacities before the namespace's first successful import.
    /// Clones with incompatible configuration cannot mutate an already-bound namespace.
    pub fn with_notification_import_config(
        mut self,
        config: NotificationImportConfig,
    ) -> Result<Self, EventOutboxError> {
        {
            let namespace = self
                .notification_namespace
                .lock()
                .map_err(|_| EventOutboxError::LockUnavailable)?;
            if namespace
                .config_digest
                .is_some_and(|digest| digest != config.digest())
            {
                return Err(EventOutboxError::InvalidNotificationImportConfig);
            }
        }
        self.notification_import_config = config;
        Ok(self)
    }

    pub(super) fn import_notification(
        &self,
        commit: NotificationCommit,
        now: DateTime<Utc>,
    ) -> Result<NotificationAck, EventOutboxError> {
        let PreparedNotificationBatch {
            created_at,
            events: mapped,
        } = mapped_events(&commit)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        let mut namespace = self
            .notification_namespace
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        let config = self.notification_import_config;
        if namespace
            .config_digest
            .is_some_and(|digest| digest != config.digest())
        {
            return Err(EventOutboxError::InvalidNotificationImportConfig);
        }
        let existing = state.get(commit.scope().tenant_id());
        let watermark =
            existing.and_then(|tenant| tenant.notification_watermarks.get(commit.scope()));
        if let Some(watermark) = watermark {
            if watermark.is_replay(&commit)? {
                return Ok(commit.ack());
            }
        } else {
            if commit.source_sequence() != 1 {
                return Err(EventOutboxError::ProjectionGap);
            }
            if namespace.source_count >= config.max_sources
                || existing.map_or(0, |tenant| tenant.notification_watermarks.len())
                    >= config.max_sources_per_tenant
            {
                return Err(EventOutboxError::NotificationSourceCapacity);
            }
        }
        let is_new = watermark.is_none();
        let starting_sequence = existing.map_or(0, |tenant| tenant.next_seq);
        let count = u64::try_from(mapped.len()).map_err(|_| EventOutboxError::SequenceOverflow)?;
        if starting_sequence
            .checked_add(count)
            .is_none_or(|tail| tail > i64::MAX as u64)
        {
            return Err(EventOutboxError::SequenceOverflow);
        }

        // Preflight pruning without changing authority, so any conflict or timestamp error leaves
        // the entire batch unapplied. No retained tenant stream is cloned for this bounded batch.
        let mut to_prune: usize = 0;
        if let Some(tenant) = existing {
            for event in &tenant.events {
                let retained_at = tenant
                    .retention_started
                    .get(&event.tenant_seq)
                    .copied()
                    .unwrap_or(event.created_at);
                let age = now
                    .signed_duration_since(retained_at)
                    .to_std()
                    .map_err(|_| EventOutboxError::RetentionTimestampOverflow)?;
                if age < self.retention {
                    break;
                }
                to_prune += 1;
            }
            let pruned_through = to_prune
                .checked_sub(1)
                .and_then(|index| tenant.events.get(index))
                .map_or(tenant.pruned_through, |event| event.tenant_seq);
            for (id, append) in &mapped {
                let key = (
                    append.aggregate.clone(),
                    append.aggregate_revision,
                    append.kind,
                );
                if tenant
                    .dedup
                    .get(&key)
                    .is_some_and(|seq| *seq > pruned_through)
                    || tenant
                        .events
                        .iter()
                        .skip(to_prune)
                        .any(|event| event.event_id == *id)
                {
                    return Err(EventOutboxError::ConflictingEvent);
                }
            }
        }

        let tenant = state.entry(commit.scope().tenant_id().clone()).or_default();
        tenant.prune(self.retention, now)?;
        for (event_id, append) in mapped {
            tenant.next_seq += 1;
            let event = OutboxEvent {
                event_id,
                tenant_id: append.tenant_id,
                tenant_seq: tenant.next_seq,
                aggregate: append.aggregate,
                aggregate_revision: append.aggregate_revision,
                kind: append.kind,
                created_at,
                summary: append.summary,
            };
            tenant.dedup.insert(
                (
                    event.aggregate.clone(),
                    event.aggregate_revision,
                    event.kind,
                ),
                event.tenant_seq,
            );
            tenant.retention_started.insert(event.tenant_seq, now);
            tenant.events.push_back(event);
        }
        tenant
            .notification_watermarks
            .entry(commit.scope().clone())
            .or_default()
            .record(&commit);
        namespace.config_digest = Some(config.digest());
        if is_new {
            namespace.source_count += 1;
        }
        Ok(commit.ack())
    }
}
