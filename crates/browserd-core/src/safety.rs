use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::IsolationProfile;

const MAX_CONTEXTS_PER_SHARD: u16 = 8;
const MAX_TARGETS_PER_SESSION: u16 = 128;
const MAX_ACTOR_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 2_048;
pub const MAX_SAFETY_RULES_PER_SET: usize = 1_024;
pub const MAX_SAFETY_SNAPSHOT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "SafetySwitchSnapshotWire")]
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
    denied_ips: BTreeSet<IpAddr>,
    stopped_network_classes: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SafetySwitchSnapshotWire {
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
    #[serde(default)]
    denied_ips: BTreeSet<IpAddr>,
    stopped_network_classes: BTreeSet<String>,
}

impl TryFrom<SafetySwitchSnapshotWire> for SafetySwitchSnapshot {
    type Error = SafetySwitchError;

    fn try_from(wire: SafetySwitchSnapshotWire) -> Result<Self, Self::Error> {
        let snapshot = Self {
            version: wire.version,
            shared_context_qualified: wire.shared_context_qualified,
            force_dedicated_process: wire.force_dedicated_process,
            max_contexts_per_shard: wire.max_contexts_per_shard,
            max_targets_per_session: wire.max_targets_per_session,
            disable_evaluate: wire.disable_evaluate,
            disable_viewer_control: wire.disable_viewer_control,
            disable_downloads: wire.disable_downloads,
            disable_checkpoint: wire.disable_checkpoint,
            disabled_chromium_builds: wire.disabled_chromium_builds,
            denied_domains: wire.denied_domains,
            denied_ips: wire.denied_ips,
            stopped_network_classes: wire.stopped_network_classes,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}

impl SafetySwitchSnapshot {
    pub fn validate(&self) -> Result<(), SafetySwitchError> {
        if self.version > i64::MAX as u64 {
            return Err(SafetySwitchError::VersionExhausted);
        }
        if !(1..=MAX_CONTEXTS_PER_SHARD).contains(&self.max_contexts_per_shard) {
            return Err(SafetySwitchError::InvalidContextLimit {
                value: self.max_contexts_per_shard,
            });
        }
        if !(1..=MAX_TARGETS_PER_SESSION).contains(&self.max_targets_per_session) {
            return Err(SafetySwitchError::InvalidTargetLimit {
                value: self.max_targets_per_session,
            });
        }
        if self.force_dedicated_process && self.max_contexts_per_shard != 1 {
            return Err(SafetySwitchError::InvalidContextLimit {
                value: self.max_contexts_per_shard,
            });
        }
        if [
            self.disabled_chromium_builds.len(),
            self.denied_domains.len(),
            self.denied_ips.len(),
            self.stopped_network_classes.len(),
        ]
        .into_iter()
        .any(|count| count > MAX_SAFETY_RULES_PER_SET)
        {
            return Err(SafetySwitchError::RuleCapacity);
        }
        for digest in &self.disabled_chromium_builds {
            if canonical_digest(digest)? != *digest {
                return Err(SafetySwitchError::InvalidChromiumDigest);
            }
        }
        for domain in &self.denied_domains {
            if canonical_domain(domain)? != *domain {
                return Err(SafetySwitchError::InvalidDomain);
            }
        }
        if self
            .denied_ips
            .iter()
            .any(|ip| normalize_safety_ip(*ip) != *ip)
        {
            return Err(SafetySwitchError::InvalidIp);
        }
        for class in &self.stopped_network_classes {
            validate_network_class(class)?;
        }
        if serde_json::to_vec(self)
            .map_err(|_| SafetySwitchError::Encoding)?
            .len()
            > MAX_SAFETY_SNAPSHOT_BYTES
        {
            return Err(SafetySwitchError::Encoding);
        }
        Ok(())
    }

    /// Computes a new snapshot without changing any authority or admission state.
    /// Runtime force/density intent never grants the independent local Chromium qualification.
    pub fn apply(&self, mutation: &SafetySwitchMutation) -> Result<Self, SafetySwitchError> {
        self.validate()?;
        let mutation = mutation.canonicalized()?;
        let mut next = self.clone();
        match &mutation {
            SafetySwitchMutation::SetSharedAdmission {
                qualified,
                force_dedicated_process,
                max_contexts_per_shard,
            } => {
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
            SafetySwitchMutation::ForceDedicatedProcess
            | SafetySwitchMutation::SetForceDedicatedProcess(true) => {
                next.force_dedicated_process = true;
                next.max_contexts_per_shard = 1;
            }
            SafetySwitchMutation::SetForceDedicatedProcess(false) => {
                next.force_dedicated_process = false
            }
            SafetySwitchMutation::SetMaxContextsPerShard(value) => {
                next.max_contexts_per_shard = *value
            }
            SafetySwitchMutation::SetMaxTargetsPerSession(value) => {
                next.max_targets_per_session = *value
            }
            SafetySwitchMutation::DisableEvaluate(disabled) => next.disable_evaluate = *disabled,
            SafetySwitchMutation::DisableViewerControl(disabled) => {
                next.disable_viewer_control = *disabled
            }
            SafetySwitchMutation::DisableDownloads(disabled) => next.disable_downloads = *disabled,
            SafetySwitchMutation::DisableCheckpoint(disabled) => {
                next.disable_checkpoint = *disabled
            }
            SafetySwitchMutation::SetChromiumBuildDisabled { digest, disabled } => {
                if *disabled {
                    next.disabled_chromium_builds.insert(digest.clone());
                } else {
                    next.disabled_chromium_builds.remove(digest);
                }
            }
            SafetySwitchMutation::SetDeniedDomain { domain, denied } => {
                if *denied {
                    next.denied_domains.insert(domain.clone());
                } else {
                    next.denied_domains.remove(domain);
                }
            }
            SafetySwitchMutation::SetDeniedIp { ip, denied } => {
                if *denied {
                    next.denied_ips.insert(*ip);
                } else {
                    next.denied_ips.remove(ip);
                }
            }
            SafetySwitchMutation::SetStoppedNetworkClass {
                network_class,
                stopped,
            } => {
                if *stopped {
                    next.stopped_network_classes.insert(network_class.clone());
                } else {
                    next.stopped_network_classes.remove(network_class);
                }
            }
        }
        next.version = self
            .version
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(SafetySwitchError::VersionExhausted)?;
        next.validate()?;
        Ok(next)
    }

    pub fn digest(&self) -> Result<[u8; 32], SafetySwitchError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SafetySwitchError::Encoding)?;
        let mut digest = Sha256::new();
        digest.update(b"browserd-runtime-safety-snapshot-v1\0");
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
        Ok(digest.finalize().into())
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
    #[must_use]
    pub const fn shared_context_qualified(&self) -> bool {
        self.shared_context_qualified
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
        if (self.force_dedicated_process || self.max_contexts_per_shard == 1)
            && requested != IsolationProfile::DedicatedWorker
        {
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
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        self.denied_domains.iter().any(|denied| {
            normalized == *denied
                || normalized
                    .strip_suffix(denied)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
    #[must_use]
    pub fn ip_denied(&self, ip: IpAddr) -> bool {
        self.denied_ips.contains(&normalize_safety_ip(ip))
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
            denied_ips: BTreeSet::new(),
            stopped_network_classes: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SafetySwitchMutation {
    SetSharedAdmission {
        qualified: bool,
        force_dedicated_process: bool,
        max_contexts_per_shard: u16,
    },
    ForceDedicatedProcess,
    SetForceDedicatedProcess(bool),
    SetMaxContextsPerShard(u16),
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
    SetDeniedIp {
        ip: IpAddr,
        denied: bool,
    },
    SetStoppedNetworkClass {
        network_class: String,
        stopped: bool,
    },
}

impl SafetySwitchMutation {
    pub fn normalized(&self) -> Result<Self, SafetySwitchError> {
        self.canonicalized()
    }

    pub fn canonicalized(&self) -> Result<Self, SafetySwitchError> {
        let mut value = self.clone();
        match &mut value {
            Self::SetSharedAdmission {
                max_contexts_per_shard,
                ..
            }
            | Self::SetMaxContextsPerShard(max_contexts_per_shard) => {
                if !(1..=MAX_CONTEXTS_PER_SHARD).contains(max_contexts_per_shard) {
                    return Err(SafetySwitchError::InvalidContextLimit {
                        value: *max_contexts_per_shard,
                    });
                }
            }
            Self::SetMaxTargetsPerSession(limit) => {
                if !(1..=MAX_TARGETS_PER_SESSION).contains(limit) {
                    return Err(SafetySwitchError::InvalidTargetLimit { value: *limit });
                }
            }
            Self::SetChromiumBuildDisabled { digest, .. } => *digest = canonical_digest(digest)?,
            Self::SetDeniedDomain { domain, .. } => *domain = canonical_domain(domain)?,
            Self::SetDeniedIp { ip, .. } => *ip = normalize_safety_ip(*ip),
            Self::SetStoppedNetworkClass { network_class, .. } => {
                validate_network_class(network_class)?
            }
            _ => {}
        }
        Ok(value)
    }
    #[must_use]
    pub const fn is_runtime_mutation(&self) -> bool {
        !matches!(self, Self::SetSharedAdmission { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SafetySwitchUpdate {
    previous_version: u64,
    version: u64,
    actor: String,
    reason: String,
    mutation: SafetySwitchMutation,
    snapshot: SafetySwitchSnapshot,
}
impl SafetySwitchUpdate {
    pub fn new(
        current: &SafetySwitchSnapshot,
        actor: impl Into<String>,
        reason: impl Into<String>,
        mutation: SafetySwitchMutation,
    ) -> Result<Self, SafetySwitchError> {
        let actor = actor.into();
        let reason = reason.into();
        if !valid_text(&actor, MAX_ACTOR_BYTES) {
            return Err(SafetySwitchError::ActorRequired);
        }
        if !valid_text(&reason, MAX_REASON_BYTES) {
            return Err(SafetySwitchError::ReasonRequired);
        }
        let mutation = mutation.canonicalized()?;
        let snapshot = current.apply(&mutation)?;
        Ok(Self {
            previous_version: current.version(),
            version: snapshot.version(),
            actor,
            reason,
            mutation,
            snapshot,
        })
    }
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
        self.snapshot.lock().map_or_else(
            |_| SafetySwitchSnapshot::default(),
            |snapshot| snapshot.clone(),
        )
    }
    pub fn update(
        &self,
        expected_version: u64,
        actor: impl Into<String>,
        reason: impl Into<String>,
        mutation: SafetySwitchMutation,
    ) -> Result<SafetySwitchUpdate, SafetySwitchError> {
        let mut current = self
            .snapshot
            .lock()
            .map_err(|_| SafetySwitchError::Unavailable)?;
        if current.version() != expected_version {
            return Err(SafetySwitchError::VersionConflict {
                expected: expected_version,
                actual: current.version(),
            });
        }
        let update = SafetySwitchUpdate::new(&current, actor, reason, mutation)?;
        *current = update.snapshot.clone();
        Ok(update)
    }
}
impl Default for SafetySwitchRegistry {
    fn default() -> Self {
        Self::production_defaults()
    }
}

#[must_use]
pub fn normalize_safety_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
        value => value,
    }
}
fn canonical_digest(digest: &str) -> Result<String, SafetySwitchError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SafetySwitchError::InvalidChromiumDigest);
    }
    Ok(digest.to_ascii_lowercase())
}
fn canonical_domain(domain: &str) -> Result<String, SafetySwitchError> {
    let value = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.parse::<IpAddr>().is_ok()
        || value.split('.').any(|label| {
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
    Ok(value)
}
fn validate_network_class(value: &str) -> Result<(), SafetySwitchError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Err(SafetySwitchError::InvalidNetworkClass)
    } else {
        Ok(())
    }
}
fn valid_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
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
    InvalidIp,
    InvalidNetworkClass,
    RuleCapacity,
    Encoding,
    Unavailable,
}
impl fmt::Display for SafetySwitchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid or unavailable safety switch state")
    }
}
impl std::error::Error for SafetySwitchError {}
