//! Immutable, bounded notification custody in the publication authority's own frames.
use super::*;
use browserd_core::{
    NotificationAck, NotificationArtifactState, NotificationCommit, NotificationDescriptor,
    NotificationSessionScope, NotificationSourceFamily, NotificationSourceScope, PlacementFence,
    WorkerNotificationEvent,
};
use browserd_worker::WorkerNotificationPage;
use uuid::Uuid;

const MAX_SOURCES: usize = 1024;
const MAX_PENDING: usize = 4096;
const MAX_REJECTIONS: usize = 1024;
const REJECTION_RETENTION_MILLIS: u64 = 86_400_000;
type SourceKey = (TenantId, WorkerId);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceCheckpoint {
    scope: NotificationSourceScope,
    acknowledged_sequence: u64,
    acknowledged_digest: [u8; 32],
    tail_sequence: u64,
    tail_digest: [u8; 32],
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn full_rejection_capacity_replays_exact_pinned_checkpoints_after_pending_commits() {
        let mut authority = Notifications::default();
        authority
            .apply(&Change::Initialize {
                source_id: Uuid::new_v4(),
            })
            .expect("source");
        let tenant = TenantId::new();
        let session = SessionId::new();
        let fence = OwnershipFence::new(
            WorkerId::new("quarantine-capacity").expect("worker"),
            1,
            1,
            1,
        );
        let mut pins = std::collections::BTreeSet::new();
        for _ in 0..MAX_REJECTIONS {
            let key = ArtifactKey::new(tenant.clone(), session.clone(), ArtifactId::new());
            let commit = authority
                .commit(
                    &key,
                    &fence,
                    1000,
                    vec![WorkerNotificationEvent::ArtifactStateChanged {
                        artifact_id: key.artifact_id().clone(),
                        state: NotificationArtifactState::Quarantined,
                    }],
                )
                .expect("bounded commit");
            authority
                .apply(&Change::Commit { commit })
                .expect("authority transition");
            pins.insert(index_key(&key));
        }
        assert_eq!(authority.rejections.len(), MAX_REJECTIONS);
        let changes = authority.compact_changes(1000, &pins).expect("compact");
        let mut replay = Notifications::default();
        for change in &changes {
            replay
                .apply(change)
                .expect("exact duplicate checkpoint at capacity");
        }
        replay
            .validate_replay(MAX_REJECTIONS * 2)
            .expect("reserved future cleanup frames");
        assert_eq!(replay.rejections.len(), MAX_REJECTIONS);
        assert_eq!(
            replay.sources.values().next().expect("source").pending,
            authority.sources.values().next().expect("source").pending
        );
        let source = replay.sources.values().next().expect("source");
        let tail = source.pending.last_key_value().expect("tail").1.clone();
        replay
            .apply(&Change::Acknowledge {
                ack: tail.ack(),
                acknowledged_at: 1000,
            })
            .expect("exact ACK");
        let mut acknowledged = Notifications::default();
        for change in replay
            .compact_changes(1000 + REJECTION_RETENTION_MILLIS * 2, &pins)
            .expect("pinned compaction")
        {
            acknowledged
                .apply(&change)
                .expect("acknowledged pinned checkpoint");
        }
        assert_eq!(acknowledged.rejections.len(), MAX_REJECTIONS);
        assert!(
            acknowledged
                .sources
                .values()
                .all(|source| source.pending.is_empty())
        );
        assert!(
            !acknowledged
                .validate_ack(&tail.ack())
                .expect("lost ACK reply replay")
        );
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RejectionCheckpoint {
    commit: NotificationCommit,
    acknowledged_at: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Change {
    Initialize {
        source_id: Uuid,
    },
    Commit {
        commit: NotificationCommit,
    },
    Acknowledge {
        ack: NotificationAck,
        acknowledged_at: u64,
    },
    SourceCheckpoint {
        checkpoint: SourceCheckpoint,
    },
    RejectionCheckpoint {
        checkpoint: RejectionCheckpoint,
    },
}

#[derive(Clone)]
struct SourceState {
    scope: NotificationSourceScope,
    sequence: u64,
    digest: [u8; 32],
    acknowledged_sequence: u64,
    acknowledged_digest: [u8; 32],
    pending: BTreeMap<u64, NotificationCommit>,
    replay_tail: Option<(u64, [u8; 32])>,
}

#[derive(Clone, Default)]
pub(super) struct Notifications {
    source_id: Option<Uuid>,
    sources: BTreeMap<SourceKey, SourceState>,
    rejections: BTreeMap<IndexKey, RejectionCheckpoint>,
    pub clock_floor: u64,
}

fn source_key(scope: &NotificationSourceScope) -> SourceKey {
    (
        scope.tenant_id().clone(),
        scope.original_worker_id().clone(),
    )
}

fn rejection_key(commit: &NotificationCommit) -> Result<Option<IndexKey>, DependencyError> {
    let [descriptor] = commit.descriptors() else {
        return Ok(None);
    };
    match descriptor.event() {
        WorkerNotificationEvent::ArtifactStateChanged {
            artifact_id,
            state: NotificationArtifactState::Rejected | NotificationArtifactState::Quarantined,
        } => Ok(Some((
            commit.scope().tenant_id().clone(),
            descriptor.session_scope().session_id().clone(),
            artifact_id.clone(),
        ))),
        _ => Ok(None),
    }
}

impl Notifications {
    pub fn initialized(&self) -> bool {
        self.source_id.is_some()
    }

    pub fn advance_clock(&mut self, now: u64) {
        self.clock_floor = self.clock_floor.max(now);
    }

    pub fn apply(&mut self, change: &Change) -> Result<(), DependencyError> {
        match change {
            Change::Initialize { source_id } => {
                if self.source_id.is_some() || !matches!(source_id.get_version_num(), 4 | 7) {
                    return Err(DependencyError::Rejected);
                }
                self.source_id = Some(*source_id);
            }
            Change::SourceCheckpoint { checkpoint } => {
                self.validate_scope(&checkpoint.scope)?;
                if self.sources.len() >= MAX_SOURCES
                    || self.sources.contains_key(&source_key(&checkpoint.scope))
                    || checkpoint.acknowledged_sequence > i64::MAX as u64
                    || checkpoint.tail_sequence < checkpoint.acknowledged_sequence
                    || checkpoint.tail_sequence > i64::MAX as u64
                    || (checkpoint.tail_sequence == checkpoint.acknowledged_sequence
                        && checkpoint.tail_digest != checkpoint.acknowledged_digest)
                    || (checkpoint.acknowledged_sequence == 0)
                        != (checkpoint.acknowledged_digest == [0; 32])
                {
                    return Err(DependencyError::Rejected);
                }
                self.sources.insert(
                    source_key(&checkpoint.scope),
                    SourceState {
                        scope: checkpoint.scope.clone(),
                        sequence: checkpoint.acknowledged_sequence,
                        digest: checkpoint.acknowledged_digest,
                        acknowledged_sequence: checkpoint.acknowledged_sequence,
                        acknowledged_digest: checkpoint.acknowledged_digest,
                        pending: BTreeMap::new(),
                        replay_tail: (checkpoint.tail_sequence > checkpoint.acknowledged_sequence)
                            .then_some((checkpoint.tail_sequence, checkpoint.tail_digest)),
                    },
                );
            }
            Change::Commit { commit } => {
                commit.validate().map_err(|_| DependencyError::Rejected)?;
                self.validate_scope(commit.scope())?;
                let key = source_key(commit.scope());
                if !self.sources.contains_key(&key) {
                    if self.sources.len() >= MAX_SOURCES {
                        return Err(DependencyError::Rejected);
                    }
                    self.sources.insert(
                        key.clone(),
                        SourceState {
                            scope: commit.scope().clone(),
                            sequence: 0,
                            digest: [0; 32],
                            acknowledged_sequence: 0,
                            acknowledged_digest: [0; 32],
                            pending: BTreeMap::new(),
                            replay_tail: None,
                        },
                    );
                }
                let source = self
                    .sources
                    .get_mut(&key)
                    .ok_or(DependencyError::Rejected)?;
                if source.scope != *commit.scope()
                    || source.sequence.checked_add(1) != Some(commit.source_sequence())
                {
                    return Err(DependencyError::Rejected);
                }
                source.sequence = commit.source_sequence();
                source.digest = commit.digest();
                if let Some((sequence, digest)) = source.replay_tail
                    && source.sequence == sequence
                {
                    if source.digest != digest {
                        return Err(DependencyError::Rejected);
                    }
                    source.replay_tail = None;
                }
                source
                    .pending
                    .insert(commit.source_sequence(), commit.clone());
                if let Some(key) = rejection_key(commit)? {
                    if self.rejections.contains_key(&key) || self.rejections.len() >= MAX_REJECTIONS
                    {
                        return Err(DependencyError::Rejected);
                    }
                    self.rejections.insert(
                        key,
                        RejectionCheckpoint {
                            commit: commit.clone(),
                            acknowledged_at: None,
                        },
                    );
                }
            }
            Change::Acknowledge {
                ack,
                acknowledged_at,
            } => {
                self.validate_ack(ack)?;
                self.advance_clock(*acknowledged_at);
                let source = self
                    .sources
                    .get_mut(&source_key(ack.scope()))
                    .ok_or(DependencyError::Rejected)?;
                source.acknowledged_sequence = ack.source_sequence();
                source.acknowledged_digest = ack.digest();
                source
                    .pending
                    .retain(|sequence, _| *sequence > ack.source_sequence());
                for rejection in self.rejections.values_mut() {
                    if rejection.commit.scope() == ack.scope()
                        && rejection.commit.source_sequence() <= ack.source_sequence()
                    {
                        rejection.acknowledged_at.get_or_insert(*acknowledged_at);
                    }
                }
            }
            Change::RejectionCheckpoint { checkpoint } => {
                checkpoint
                    .commit
                    .validate()
                    .map_err(|_| DependencyError::Rejected)?;
                self.validate_scope(checkpoint.commit.scope())?;
                let key = rejection_key(&checkpoint.commit)?.ok_or(DependencyError::Rejected)?;
                let source = self
                    .sources
                    .get(&source_key(checkpoint.commit.scope()))
                    .ok_or(DependencyError::Rejected)?;
                if checkpoint.commit.source_sequence() > source.sequence
                    || checkpoint.acknowledged_at.is_some_and(|_| {
                        checkpoint.commit.source_sequence() > source.acknowledged_sequence
                    })
                    || (!self.rejections.contains_key(&key)
                        && self.rejections.len() >= MAX_REJECTIONS)
                {
                    return Err(DependencyError::Rejected);
                }
                match self.rejections.get(&key) {
                    Some(existing)
                        if existing.commit == checkpoint.commit
                            && existing.acknowledged_at == checkpoint.acknowledged_at => {}
                    Some(_) => return Err(DependencyError::Rejected),
                    None => {
                        self.rejections.insert(key, checkpoint.clone());
                    }
                }
            }
        }
        self.check_capacity(0)
    }

    fn validate_scope(&self, scope: &NotificationSourceScope) -> Result<(), DependencyError> {
        scope.validate().map_err(|_| DependencyError::Rejected)?;
        if self.source_id != Some(scope.source_id())
            || scope.family() != NotificationSourceFamily::ArtifactRegistry
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }

    pub fn check_capacity(&self, cleanup_reserves: usize) -> Result<(), DependencyError> {
        let pending = self
            .sources
            .values()
            .map(|source| source.pending.len())
            .sum::<usize>();
        if pending
            .checked_add(cleanup_reserves)
            .is_none_or(|total| total > MAX_PENDING)
            || self.sources.len() > MAX_SOURCES
            || self.rejections.len() > MAX_REJECTIONS
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }

    pub fn validate_replay(&self, cleanup_reserves: usize) -> Result<(), DependencyError> {
        if self
            .sources
            .values()
            .any(|source| source.replay_tail.is_some())
        {
            return Err(DependencyError::Rejected);
        }
        self.check_capacity(cleanup_reserves)
    }

    pub fn commit(
        &self,
        key: &ArtifactKey,
        fence: &OwnershipFence,
        now: u64,
        events: Vec<WorkerNotificationEvent>,
    ) -> Result<NotificationCommit, DependencyError> {
        let scope = NotificationSourceScope::new(
            key.tenant_id().clone(),
            fence.worker_id().clone(),
            self.source_id.ok_or(DependencyError::Rejected)?,
            NotificationSourceFamily::ArtifactRegistry,
        )
        .map_err(|_| DependencyError::Rejected)?;
        let sequence = self
            .sources
            .get(&source_key(&scope))
            .map_or(0, |source| source.sequence)
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or(DependencyError::Rejected)?;
        let session_scope = NotificationSessionScope::new(
            key.session_id().clone(),
            PlacementFence::new(
                fence.worker_epoch(),
                fence.placement_version(),
                fence.session_incarnation(),
            ),
        )
        .map_err(|_| DependencyError::Rejected)?;
        let descriptors = events
            .into_iter()
            .map(|event| {
                NotificationDescriptor::new(Uuid::now_v7(), session_scope.clone(), event)
                    .map_err(|_| DependencyError::Rejected)
            })
            .collect::<Result<Vec<_>, _>>()?;
        NotificationCommit::new(scope, sequence, now.max(self.clock_floor), descriptors)
            .map_err(|_| DependencyError::Rejected)
    }

    pub fn rejection_exists(
        &self,
        key: &ArtifactKey,
        fence: &OwnershipFence,
        state: NotificationArtifactState,
    ) -> Result<bool, DependencyError> {
        let Some(existing) = self.rejections.get(&index_key(key)) else {
            return Ok(false);
        };
        let [descriptor] = existing.commit.descriptors() else {
            return Err(DependencyError::Rejected);
        };
        if existing.commit.scope().original_worker_id() != fence.worker_id()
            || descriptor.session_scope().fence()
                != PlacementFence::new(
                    fence.worker_epoch(),
                    fence.placement_version(),
                    fence.session_incarnation(),
                )
            || descriptor.event()
                != &(WorkerNotificationEvent::ArtifactStateChanged {
                    artifact_id: key.artifact_id().clone(),
                    state,
                })
        {
            return Err(DependencyError::Rejected);
        }
        Ok(true)
    }

    pub fn has_rejection(&self, key: &ArtifactKey) -> bool {
        self.rejections.contains_key(&index_key(key))
    }

    pub fn validate_ack(&self, ack: &NotificationAck) -> Result<bool, DependencyError> {
        ack.validate().map_err(|_| DependencyError::Rejected)?;
        self.validate_scope(ack.scope())?;
        let source = self
            .sources
            .get(&source_key(ack.scope()))
            .ok_or(DependencyError::Rejected)?;
        if source.scope != *ack.scope() {
            return Err(DependencyError::Rejected);
        }
        if ack.source_sequence() == source.acknowledged_sequence
            && ack.digest() == source.acknowledged_digest
        {
            return Ok(false);
        }
        let commit = source
            .pending
            .get(&ack.source_sequence())
            .ok_or(DependencyError::Rejected)?;
        if commit.digest() != ack.digest() {
            return Err(DependencyError::Rejected);
        }
        Ok(true)
    }

    pub fn page(
        &self,
        cursor: Option<&str>,
        max_scopes: usize,
        max_descriptors: usize,
    ) -> Result<WorkerNotificationPage, DependencyError> {
        if !(1..=32).contains(&max_scopes) || !(1..=8).contains(&max_descriptors) {
            return Err(DependencyError::Rejected);
        }
        let after = cursor
            .map(|cursor| self.decode_cursor(cursor))
            .transpose()?;
        let mut page = WorkerNotificationPage {
            commits: Vec::new(),
            cursor: None,
            examined: 0,
            is_complete: true,
        };
        let mut descriptors = 0usize;
        for (key, source) in &self.sources {
            if after.as_ref().is_some_and(|after| key <= after) {
                continue;
            }
            if page.examined == max_scopes {
                page.is_complete = false;
                break;
            }
            if let Some(commit) = source.pending.values().next() {
                if commit.descriptors().len() > max_descriptors {
                    return Err(DependencyError::Rejected);
                }
                if descriptors + commit.descriptors().len() > max_descriptors {
                    page.is_complete = false;
                    break;
                }
                descriptors += commit.descriptors().len();
                page.commits.push(commit.clone());
            }
            page.examined += 1;
            page.cursor = Some(self.encode_cursor(key)?);
        }
        if page.is_complete {
            page.cursor = None;
        }
        Ok(page)
    }

    fn encode_cursor(&self, key: &SourceKey) -> Result<String, DependencyError> {
        Ok(format!(
            "{}:{}:{}",
            key.0,
            hex::encode(key.1.as_str().as_bytes()),
            self.source_id.ok_or(DependencyError::Rejected)?
        ))
    }
    fn decode_cursor(&self, cursor: &str) -> Result<SourceKey, DependencyError> {
        if cursor.len() > 1024 {
            return Err(DependencyError::Rejected);
        }
        let mut components = cursor.split(':');
        let tenant = components
            .next()
            .ok_or(DependencyError::Rejected)?
            .parse()
            .map_err(|_| DependencyError::Rejected)?;
        let worker = String::from_utf8(
            hex::decode(components.next().ok_or(DependencyError::Rejected)?)
                .map_err(|_| DependencyError::Rejected)?,
        )
        .map_err(|_| DependencyError::Rejected)?;
        let worker = WorkerId::new(worker).map_err(|_| DependencyError::Rejected)?;
        let source = Uuid::parse_str(components.next().ok_or(DependencyError::Rejected)?)
            .map_err(|_| DependencyError::Rejected)?;
        if components.next().is_some() || self.source_id != Some(source) {
            return Err(DependencyError::Rejected);
        }
        Ok((tenant, worker))
    }

    pub fn rejection_pending(&self, key: &ArtifactKey) -> bool {
        self.rejections
            .get(&index_key(key))
            .is_some_and(|entry| entry.acknowledged_at.is_none())
    }
    pub fn rejection_retirable(&self, key: &ArtifactKey, now: u64) -> bool {
        self.rejections.get(&index_key(key)).is_none_or(|entry| {
            entry
                .acknowledged_at
                .is_some_and(|at| now >= at.saturating_add(REJECTION_RETENTION_MILLIS))
        })
    }
    pub fn compact_changes(
        &self,
        now: u64,
        pins: &std::collections::BTreeSet<IndexKey>,
    ) -> Result<Vec<Change>, DependencyError> {
        let mut changes = vec![Change::Initialize {
            source_id: self.source_id.ok_or(DependencyError::Rejected)?,
        }];
        for source in self.sources.values() {
            changes.push(Change::SourceCheckpoint {
                checkpoint: SourceCheckpoint {
                    scope: source.scope.clone(),
                    acknowledged_sequence: source.acknowledged_sequence,
                    acknowledged_digest: source.acknowledged_digest,
                    tail_sequence: source.sequence,
                    tail_digest: source.digest,
                },
            });
            changes.extend(
                source
                    .pending
                    .values()
                    .cloned()
                    .map(|commit| Change::Commit { commit }),
            );
        }
        for rejection in self.rejections.values() {
            if !pins.contains(&rejection_key(&rejection.commit)?.ok_or(DependencyError::Rejected)?)
                && rejection
                    .acknowledged_at
                    .is_some_and(|at| now >= at.saturating_add(REJECTION_RETENTION_MILLIS))
            {
                continue;
            }
            changes.push(Change::RejectionCheckpoint {
                checkpoint: rejection.clone(),
            });
        }
        Ok(changes)
    }

    pub fn retire_rejections(&mut self, now: u64, pins: &std::collections::BTreeSet<IndexKey>) {
        self.rejections.retain(|key, entry| {
            pins.contains(key)
                || entry
                    .acknowledged_at
                    .is_none_or(|at| now < at.saturating_add(REJECTION_RETENTION_MILLIS))
        });
    }
}
