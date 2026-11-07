use std::collections::{BTreeMap, BTreeSet};

use browserd_core::SafetySwitchSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::model::AuditRequest;
use super::{
    SafetyAuditAck, SafetyAuditIntent, SafetyAuthorityConfig, SafetyAuthorityError,
    SafetyAuthoritySnapshot, SafetyInitializeRequest, SafetyMutationReceipt, SafetyMutationRequest,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    audit: SafetyAuditIntent,
    acknowledged_at: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    format_version: u8,
    config_digest: [u8; 32],
    pub(super) authority: SafetyAuthoritySnapshot,
    floor: u64,
    audit_tail: u64,
    audit_delivered: u64,
    last_ack: Option<SafetyAuditAck>,
    receipts: BTreeMap<String, StoredReceipt>,
    pending: BTreeMap<u64, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    state: State,
    checksum: [u8; 32],
}

pub(super) enum Command {
    Initialize(SafetyInitializeRequest, Uuid, Uuid),
    Mutate(SafetyMutationRequest, Uuid),
    Ack(SafetyAuditAck),
    Prune,
}
pub(super) enum Outcome {
    Receipt(SafetyMutationReceipt),
    Ack,
    Pruned(usize),
}
pub(super) struct Transition {
    pub(super) state: State,
    pub(super) outcome: Outcome,
}

fn key(request: &AuditRequest) -> String {
    format!(
        "{}/{}/{}",
        request.identity().tenant_id(),
        hex::encode(request.identity().principal()),
        request.key()
    )
}

impl State {
    pub(super) fn validate(
        &self,
        config: SafetyAuthorityConfig,
    ) -> Result<(), SafetyAuthorityError> {
        if self.config_digest != config.digest() {
            return Err(SafetyAuthorityError::ConfigMismatch);
        }
        self.authority.validate()?;
        if self.format_version != 1
            || self.floor > i64::MAX as u64
            || self.audit_tail != self.authority.snapshot().version() + 1
            || self.audit_delivered > self.audit_tail
            || self.receipts.len() > config.max_receipts()
            || self.pending.len() > config.max_pending_audits()
            || self.pending.len() as u64 != self.audit_tail - self.audit_delivered
        {
            return Err(SafetyAuthorityError::CorruptState);
        }
        if (self.audit_delivered == 0) != self.last_ack.is_none()
            || self.last_ack.as_ref().is_some_and(|ack| {
                ack.namespace_id() != self.authority.namespace_id()
                    || ack.audit_sequence() != self.audit_delivered
            })
        {
            return Err(SafetyAuthorityError::CorruptState);
        }
        if let Some(ack) = &self.last_ack {
            SafetyAuditAck::new(
                ack.namespace_id(),
                ack.audit_sequence(),
                ack.event_id(),
                ack.digest(),
            )
            .map_err(|_| SafetyAuthorityError::CorruptState)?;
        }
        let mut counts = BTreeMap::<(String, String), usize>::new();
        let mut sequences = BTreeSet::new();
        let mut event_ids = BTreeSet::new();
        let mut pending_count = 0;
        for (stored_key, record) in &self.receipts {
            record.audit.validate()?;
            let receipt = record.audit.receipt();
            if *stored_key != key(&record.audit.request)
                || receipt.namespace_id() != self.authority.namespace_id()
                || receipt.audit_sequence() > self.audit_tail
                || receipt.occurred_at_unix_ms() > self.floor
                || !sequences.insert(receipt.audit_sequence())
                || !event_ids.insert(receipt.audit_event_id())
                || (receipt.audit_sequence() == self.audit_delivered
                    && self.last_ack.as_ref() != Some(&record.audit.ack()))
            {
                return Err(SafetyAuthorityError::CorruptState);
            }
            let count = counts
                .entry((
                    record.audit.identity().tenant_id().to_string(),
                    record.audit.identity().principal().to_owned(),
                ))
                .or_default();
            *count += 1;
            if *count > config.max_receipts_per_actor() {
                return Err(SafetyAuthorityError::CorruptState);
            }
            match record.acknowledged_at {
                Some(at) => {
                    if at > self.floor
                        || at < receipt.occurred_at_unix_ms()
                        || receipt.audit_sequence() > self.audit_delivered
                    {
                        return Err(SafetyAuthorityError::CorruptState);
                    }
                }
                None => {
                    pending_count += 1;
                    if receipt.audit_sequence() <= self.audit_delivered
                        || self.pending.get(&receipt.audit_sequence()) != Some(stored_key)
                    {
                        return Err(SafetyAuthorityError::CorruptState);
                    }
                }
            }
            if receipt.audit_sequence() == self.audit_tail
                && receipt.snapshot_digest() != self.authority.snapshot_digest()
            {
                return Err(SafetyAuthorityError::CorruptState);
            }
        }
        if pending_count != self.pending.len() {
            return Err(SafetyAuthorityError::CorruptState);
        }
        for (offset, (sequence, stored_key)) in self.pending.iter().enumerate() {
            if *sequence != self.audit_delivered + offset as u64 + 1
                || self
                    .receipts
                    .get(stored_key)
                    .is_none_or(|record| record.audit.receipt().audit_sequence() != *sequence)
            {
                return Err(SafetyAuthorityError::CorruptState);
            }
        }
        Ok(())
    }

    pub(super) fn pending_audits(
        &self,
        limit: usize,
    ) -> Result<Vec<SafetyAuditIntent>, SafetyAuthorityError> {
        if !(1..=32).contains(&limit) {
            return Err(SafetyAuthorityError::InvalidInput);
        }
        self.pending
            .values()
            .take(limit)
            .map(|key| {
                self.receipts
                    .get(key)
                    .map(|receipt| receipt.audit.clone())
                    .ok_or(SafetyAuthorityError::CorruptState)
            })
            .collect()
    }

    fn replay(
        &self,
        request: &AuditRequest,
    ) -> Result<Option<SafetyMutationReceipt>, SafetyAuthorityError> {
        let Some(record) = self.receipts.get(&key(request)) else {
            return Ok(None);
        };
        if record.audit.receipt().request_digest()
            != request.digest(self.authority.namespace_id())?
        {
            return Err(SafetyAuthorityError::IdempotencyConflict);
        }
        Ok(Some(record.audit.receipt().clone()))
    }

    fn prune(&mut self, config: SafetyAuthorityConfig) -> usize {
        let before = self.receipts.len();
        self.receipts.retain(|_, record| {
            record
                .acknowledged_at
                .and_then(|at| at.checked_add(config.retention_ms()))
                .is_none_or(|expires| expires > self.floor)
        });
        before - self.receipts.len()
    }

    fn append(
        &mut self,
        request: AuditRequest,
        event_id: Uuid,
        previous_version: Option<u64>,
        config: SafetyAuthorityConfig,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError> {
        let actor_count = self
            .receipts
            .values()
            .filter(|record| record.audit.identity() == request.identity())
            .count();
        if self.receipts.len() >= config.max_receipts()
            || actor_count >= config.max_receipts_per_actor()
            || self.pending.len() >= config.max_pending_audits()
        {
            return Err(SafetyAuthorityError::Capacity);
        }
        let receipt = SafetyMutationReceipt {
            namespace_id: self.authority.namespace_id(),
            idempotency_key: request.key(),
            previous_version,
            version: self.authority.snapshot().version(),
            audit_sequence: self.audit_tail,
            audit_event_id: event_id,
            request_digest: request.digest(self.authority.namespace_id())?,
            snapshot_digest: self.authority.snapshot_digest(),
            occurred_at_unix_ms: self.floor,
        };
        let mut audit = SafetyAuditIntent {
            receipt: receipt.clone(),
            request,
            digest: [0; 32],
        };
        audit.digest = audit.computed_digest()?;
        let key = key(&audit.request);
        if self.pending.insert(self.audit_tail, key.clone()).is_some()
            || self
                .receipts
                .insert(
                    key,
                    StoredReceipt {
                        audit,
                        acknowledged_at: None,
                    },
                )
                .is_some()
        {
            return Err(SafetyAuthorityError::CorruptState);
        }
        Ok(receipt)
    }
}

pub(super) fn transition(
    existing: Option<&State>,
    command: &Command,
    trusted_now: u64,
    config: SafetyAuthorityConfig,
) -> Result<Transition, SafetyAuthorityError> {
    if trusted_now > i64::MAX as u64 {
        return Err(SafetyAuthorityError::Unavailable);
    }
    if let Some(state) = existing {
        state.validate(config)?;
    }
    // Recovery of an already committed command changes nothing, even at the byte quota.
    if let Some(state) = existing {
        if let Command::Ack(ack) = command
            && state.last_ack.as_ref() == Some(ack)
        {
            return Ok(Transition {
                state: state.clone(),
                outcome: Outcome::Ack,
            });
        }
        let request = match command {
            Command::Initialize(request, _, _) => Some(AuditRequest::Initialize(request.clone())),
            Command::Mutate(request, _) => Some(AuditRequest::Mutate(request.clone())),
            Command::Ack(_) | Command::Prune => None,
        };
        if let Some(request) = request {
            request.validate()?;
            if let Some(receipt) = state.replay(&request)? {
                return Ok(Transition {
                    state: state.clone(),
                    outcome: Outcome::Receipt(receipt),
                });
            }
        }
    }
    let mut state = match (existing, command) {
        (None, Command::Initialize(request, namespace, _)) => {
            request.validate()?;
            State {
                format_version: 1,
                config_digest: config.digest(),
                authority: SafetyAuthoritySnapshot::new(
                    *namespace,
                    SafetySwitchSnapshot::default(),
                )?,
                floor: trusted_now,
                audit_tail: 1,
                audit_delivered: 0,
                last_ack: None,
                receipts: BTreeMap::new(),
                pending: BTreeMap::new(),
            }
        }
        (None, _) => return Err(SafetyAuthorityError::MissingAuthority),
        (Some(state), _) => state.clone(),
    };
    state.floor = state.floor.max(trusted_now);
    let outcome = match command {
        Command::Initialize(request, _, event_id) => {
            request.validate()?;
            let audit_request = AuditRequest::Initialize(request.clone());
            if existing.is_some() {
                if let Some(receipt) = state.replay(&audit_request)? {
                    Outcome::Receipt(receipt)
                } else {
                    return Err(SafetyAuthorityError::AlreadyInitialized);
                }
            } else {
                Outcome::Receipt(state.append(audit_request, *event_id, None, config)?)
            }
        }
        Command::Mutate(request, event_id) => {
            request.validate()?;
            let audit_request = AuditRequest::Mutate(request.clone());
            if let Some(receipt) = state.replay(&audit_request)? {
                Outcome::Receipt(receipt)
            } else {
                let current = state.authority.snapshot().version();
                if current != request.expected_version() {
                    return Err(SafetyAuthorityError::VersionConflict {
                        expected: request.expected_version(),
                        current,
                    });
                }
                state.prune(config);
                let snapshot = state
                    .authority
                    .snapshot()
                    .apply(request.mutation())
                    .map_err(|_| SafetyAuthorityError::InvalidSnapshot)?;
                state.authority =
                    SafetyAuthoritySnapshot::new(state.authority.namespace_id(), snapshot)?;
                state.audit_tail = state.authority.snapshot().version() + 1;
                Outcome::Receipt(state.append(audit_request, *event_id, Some(current), config)?)
            }
        }
        Command::Ack(ack) => {
            if ack.namespace_id() != state.authority.namespace_id() {
                return Err(SafetyAuthorityError::InvalidAck);
            }
            if state.last_ack.as_ref() != Some(ack) {
                let Some((sequence, key)) = state.pending.first_key_value() else {
                    return Err(SafetyAuthorityError::InvalidAck);
                };
                if *sequence != ack.audit_sequence()
                    || state
                        .receipts
                        .get(key)
                        .is_none_or(|record| record.audit.ack() != *ack)
                {
                    return Err(SafetyAuthorityError::InvalidAck);
                }
                let key = key.clone();
                state
                    .receipts
                    .get_mut(&key)
                    .ok_or(SafetyAuthorityError::CorruptState)?
                    .acknowledged_at = Some(state.floor);
                state.pending.remove(&ack.audit_sequence());
                state.audit_delivered = ack.audit_sequence();
                state.last_ack = Some(ack.clone());
            }
            Outcome::Ack
        }
        Command::Prune => Outcome::Pruned(state.prune(config)),
    };
    state.validate(config)?;
    // Encode before the backend commits anything, including the time floor or receipt pruning.
    encode(&state, config)?;
    Ok(Transition { state, outcome })
}

pub(super) fn encode(
    state: &State,
    config: SafetyAuthorityConfig,
) -> Result<Vec<u8>, SafetyAuthorityError> {
    let checksum: [u8; 32] =
        Sha256::digest(serde_json::to_vec(state).map_err(|_| SafetyAuthorityError::CorruptState)?)
            .into();
    let bytes = serde_json::to_vec(&Envelope {
        state: state.clone(),
        checksum,
    })
    .map_err(|_| SafetyAuthorityError::CorruptState)?;
    if bytes.len() > config.max_encoded_bytes() {
        return Err(SafetyAuthorityError::Capacity);
    }
    Ok(bytes)
}
pub(super) fn decode(
    bytes: &[u8],
    config: SafetyAuthorityConfig,
) -> Result<State, SafetyAuthorityError> {
    if bytes.len() > config.max_encoded_bytes() {
        return Err(SafetyAuthorityError::CorruptState);
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| SafetyAuthorityError::CorruptState)?;
    let checksum: [u8; 32] = Sha256::digest(
        serde_json::to_vec(&envelope.state).map_err(|_| SafetyAuthorityError::CorruptState)?,
    )
    .into();
    if checksum != envelope.checksum {
        return Err(SafetyAuthorityError::CorruptState);
    }
    envelope.state.validate(config)?;
    Ok(envelope.state)
}
