use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::IsolationProfile;

const MAX_CONTEXTS_PER_SHARD: u16 = 8;
const MAX_TARGETS_PER_SESSION: u16 = 128;
const MAX_ACTOR_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 2_048;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SafetySwitchSnapshot {
    version: u64,
    shared_context_qualified: bool,
    force_dedicated_process: bool,
    max_contexts_per_shard: u16,
    max_targets_per_session: u16,
    disable_evaluate: bool,
    disable_viewer_control: bool,
    disable_downloads: bool,
    disable_checkpoint: bool,
    disabled_chromium_builds: BTreeSet<String>,
    denied_domains: BTreeSet<String>,
    stopped_network_classes: BTreeSet<String>,
}

impl SafetySwitchSnapshot {
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn force_dedicated_process(&self) -> bool {
        self.force_dedicated_process
    }

    #[must_use]
    pub const fn max_contexts_per_shard(&self) -> u16 {
        self.max_contexts_per_shard
    }

    #[must_use]
    pub const fn max_targets_per_session(&self) -> u16 {
        self.max_targets_per_session
    }

    #[must_use]
    pub const fn evaluate_disabled(&self) -> bool {
        self.disable_evaluate
    }

    #[must_use]
    pub const fn viewer_control_disabled(&self) -> bool {
        self.disable_viewer_control
    }

    #[must_use]
    pub const fn downloads_disabled(&self) -> bool {
        self.disable_downloads
    }

    #[must_use]
    pub const fn checkpoint_disabled(&self) -> bool {
        self.disable_checkpoint
    }

    #[must_use]
    pub const fn shared_context_admission_allowed(&self) -> bool {
        self.shared_context_qualified
            && !self.force_dedicated_process
            && self.max_contexts_per_shard > 1
    }

    #[must_use]
    pub fn effective_isolation(&self, requested: IsolationProfile) -> IsolationProfile {
        if self.force_dedicated_process && requested != IsolationProfile::DedicatedWorker {
            requested.max(IsolationProfile::DedicatedProcess)
        } else {
            requested
        }
    }

    #[must_use]
    pub fn chromium_build_disabled(&self, digest: &str) -> bool {
        self.disabled_chromium_builds.contains(digest)
    }

    #[must_use]
    pub fn domain_denied(&self, domain: &str) -> bool {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.denied_domains.contains(&normalized)
    }

    #[must_use]
    pub fn network_class_stopped(&self, network_class: &str) -> bool {
        self.stopped_network_classes.contains(network_class)
    }
}

impl Default for SafetySwitchSnapshot {
    fn default() -> Self {
        Self {
            version: 0,
            shared_context_qualified: false,
            force_dedicated_process: true,
            max_contexts_per_shard: 1,
            max_targets_per_session: 32,
            disable_evaluate: true,
            disable_viewer_control: false,
            disable_downloads: false,
            disable_checkpoint: false,
            disabled_chromium_builds: BTreeSet::new(),
            denied_domains: BTreeSet::new(),
            stopped_network_classes: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SafetySwitchMutation {
    SetSharedAdmission {
        qualified: bool,
        force_dedicated_process: bool,
        max_contexts_per_shard: u16,
    },
    ForceDedicatedProcess,
    SetMaxTargetsPerSession(u16),
    DisableEvaluate(bool),
    DisableViewerControl(bool),
    DisableDownloads(bool),
    DisableCheckpoint(bool),
    SetChromiumBuildDisabled {
        digest: String,
        disabled: bool,
    },
    SetDeniedDomain {
        domain: String,
        denied: bool,
    },
    SetStoppedNetworkClass {
        network_class: String,
        stopped: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetySwitchUpdate {
    previous_version: u64,
    version: u64,
    actor: String,
    reason: String,
    mutation: SafetySwitchMutation,
    snapshot: SafetySwitchSnapshot,
}

impl SafetySwitchUpdate {
    #[must_use]
    pub const fn previous_version(&self) -> u64 {
        self.previous_version
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub const fn mutation(&self) -> &SafetySwitchMutation {
        &self.mutation
    }

    #[must_use]
    pub const fn snapshot(&self) -> &SafetySwitchSnapshot {
        &self.snapshot
    }
}

#[derive(Debug)]
pub struct SafetySwitchRegistry {
    snapshot: Mutex<SafetySwitchSnapshot>,
}

impl SafetySwitchRegistry {
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            snapshot: Mutex::new(SafetySwitchSnapshot::default()),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> SafetySwitchSnapshot {
        self.lock_snapshot().clone()
    }

    pub fn update(
        &self,
        expected_version: u64,
        actor: impl Into<String>,
        reason: impl Into<String>,
        mutation: SafetySwitchMutation,
    ) -> Result<SafetySwitchUpdate, SafetySwitchError> {
        let actor = actor.into();
        let reason = reason.into();
        if actor.is_empty() || actor.len() > MAX_ACTOR_BYTES {
            return Err(SafetySwitchError::ActorRequired);
        }
        if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
            return Err(SafetySwitchError::ReasonRequired);
        }

        let mut current = self.lock_snapshot();
        if current.version != expected_version {
            return Err(SafetySwitchError::VersionConflict {
                expected: expected_version,
                actual: current.version,
            });
        }
        let next_version = current
            .version
            .checked_add(1)
            .ok_or(SafetySwitchError::VersionExhausted)?;
        let mut next = current.clone();
        match &mutation {
            SafetySwitchMutation::SetSharedAdmission {
                qualified,
                force_dedicated_process,
                max_contexts_per_shard,
            } => {
                if !(1..=MAX_CONTEXTS_PER_SHARD).contains(max_contexts_per_shard) {
                    return Err(SafetySwitchError::InvalidContextLimit {
                        value: *max_contexts_per_shard,
                    });
                }
                if !qualified && !force_dedicated_process {
                    return Err(SafetySwitchError::SharedContextNotQualified);
                }
                if !force_dedicated_process && *max_contexts_per_shard == 1 {
                    return Err(SafetySwitchError::SharedContextDensityRequired);
                }
                next.shared_context_qualified = *qualified;
                next.force_dedicated_process = *force_dedicated_process;
                next.max_contexts_per_shard = if *force_dedicated_process {
                    1
                } else {
                    *max_contexts_per_shard
                };
            }
            SafetySwitchMutation::ForceDedicatedProcess => {
                next.force_dedicated_process = true;
                next.max_contexts_per_shard = 1;
            }
            SafetySwitchMutation::SetMaxTargetsPerSession(value) => {
                if !(1..=MAX_TARGETS_PER_SESSION).contains(value) {
                    return Err(SafetySwitchError::InvalidTargetLimit { value: *value });
                }
                next.max_targets_per_session = *value;
            }
            SafetySwitchMutation::DisableEvaluate(disabled) => {
                next.disable_evaluate = *disabled;
            }
            SafetySwitchMutation::DisableViewerControl(disabled) => {
                next.disable_viewer_control = *disabled;
            }
            SafetySwitchMutation::DisableDownloads(disabled) => {
                next.disable_downloads = *disabled;
            }
            SafetySwitchMutation::DisableCheckpoint(disabled) => {
                next.disable_checkpoint = *disabled;
            }
            SafetySwitchMutation::SetChromiumBuildDisabled { digest, disabled } => {
                if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(SafetySwitchError::InvalidChromiumDigest);
                }
                let digest = digest.to_ascii_lowercase();
                if *disabled {
                    next.disabled_chromium_builds.insert(digest);
                } else {
                    next.disabled_chromium_builds.remove(&digest);
                }
            }
            SafetySwitchMutation::SetDeniedDomain { domain, denied } => {
                let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
                if domain.is_empty()
                    || domain.len() > 253
                    || domain.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    })
                {
                    return Err(SafetySwitchError::InvalidDomain);
                }
                if *denied {
                    next.denied_domains.insert(domain);
                } else {
                    next.denied_domains.remove(&domain);
                }
            }
            SafetySwitchMutation::SetStoppedNetworkClass {
                network_class,
                stopped,
            } => {
                if network_class.is_empty()
                    || network_class.len() > 64
                    || !network_class
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                {
                    return Err(SafetySwitchError::InvalidNetworkClass);
                }
                if *stopped {
                    next.stopped_network_classes.insert(network_class.clone());
                } else {
                    next.stopped_network_classes.remove(network_class);
                }
            }
        }

        next.version = next_version;
        *current = next.clone();
        Ok(SafetySwitchUpdate {
            previous_version: expected_version,
            version: next_version,
            actor,
            reason,
            mutation,
            snapshot: next,
        })
    }

    fn lock_snapshot(&self) -> MutexGuard<'_, SafetySwitchSnapshot> {
        self.snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for SafetySwitchRegistry {
    fn default() -> Self {
        Self::production_defaults()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SafetySwitchError {
    VersionConflict { expected: u64, actual: u64 },
    VersionExhausted,
    ActorRequired,
    ReasonRequired,
    InvalidContextLimit { value: u16 },
    InvalidTargetLimit { value: u16 },
    SharedContextNotQualified,
    SharedContextDensityRequired,
    InvalidChromiumDigest,
    InvalidDomain,
    InvalidNetworkClass,
}
