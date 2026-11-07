//! Immutable operator authorization for qualified worker-local Chromium reuse.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::{Duration, Instant};

use browserd_chromium::{ChromiumArtifactIdentity, QualificationReceipt};
use browserd_core::TenantId;
use browserd_worker::{DependencyError, WorkerIsolationProfile};
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

const MAX_POLICY_BYTES: usize = 512 * 1024;
const MAX_TENANT_GRANTS: usize = 4096;
const LOAD_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantShardReusePolicy {
    CrossTenant,
    SameTenantOnly,
    NoReuse,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedContextPlacementConfig {
    pub version: u32,
    pub force_dedicated_process: bool,
    pub max_contexts_per_shard: usize,
    pub max_contexts_created_lifetime: u64,
    pub max_shard_age_secs: u64,
    pub qualification: Option<QualificationReceipt>,
    #[serde(deserialize_with = "deserialize_tenant_grants")]
    pub tenant_reuse: BTreeMap<TenantId, TenantShardReusePolicy>,
}

#[derive(Clone)]
pub struct SharedContextPlacementPolicy {
    artifact_identity: ChromiumArtifactIdentity,
    qualified: bool,
    max_contexts_per_shard: usize,
    max_contexts_created_lifetime: u64,
    max_shard_age: Duration,
    tenant_reuse: BTreeMap<TenantId, TenantShardReusePolicy>,
}

impl fmt::Debug for SharedContextPlacementPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedContextPlacementPolicy")
            .field("qualified", &self.qualified)
            .field("max_contexts_per_shard", &self.max_contexts_per_shard)
            .field("tenant_grants", &self.tenant_reuse.len())
            .finish_non_exhaustive()
    }
}

impl SharedContextPlacementPolicy {
    /// `config` must come from trusted operator configuration. Functional test fixtures can
    /// supply their own receipt; this never creates production qualification evidence.
    pub fn from_config(
        config: SharedContextPlacementConfig,
        artifact: &ChromiumArtifactIdentity,
        kernel_release: &str,
    ) -> Result<Self, SharedContextPolicyError> {
        if config.version != 1
            || !(1..=8).contains(&config.max_contexts_per_shard)
            || config.max_contexts_created_lifetime < config.max_contexts_per_shard as u64
            || config.max_contexts_created_lifetime > 500
            || !(1..=7200).contains(&config.max_shard_age_secs)
            || config.tenant_reuse.len() > MAX_TENANT_GRANTS
            || config
                .tenant_reuse
                .keys()
                .any(|tenant| tenant.as_uuid().is_nil())
            || artifact.validate().is_err()
            || kernel_release.is_empty()
            || kernel_release.len() > 256
            || kernel_release.chars().any(char::is_control)
        {
            return Err(SharedContextPolicyError::Rejected);
        }
        let qualified = !config.force_dedicated_process
            && config.max_contexts_per_shard > 1
            && config
                .qualification
                .as_ref()
                .is_some_and(|receipt| receipt.allows_shared_context(artifact, kernel_release));
        Ok(Self {
            artifact_identity: artifact.clone(),
            qualified,
            max_contexts_per_shard: if qualified {
                config.max_contexts_per_shard
            } else {
                1
            },
            max_contexts_created_lifetime: if qualified {
                config.max_contexts_created_lifetime
            } else {
                1
            },
            max_shard_age: Duration::from_secs(config.max_shard_age_secs),
            tenant_reuse: config.tenant_reuse,
        })
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> &ChromiumArtifactIdentity {
        &self.artifact_identity
    }

    #[must_use]
    pub const fn max_contexts_per_shard(&self) -> usize {
        self.max_contexts_per_shard
    }

    #[must_use]
    pub const fn max_contexts_created_lifetime(&self) -> u64 {
        self.max_contexts_created_lifetime
    }

    #[must_use]
    pub const fn max_shard_age(&self) -> Duration {
        self.max_shard_age
    }

    pub fn effective_isolation(
        &self,
        tenant_id: &TenantId,
        requested: WorkerIsolationProfile,
    ) -> Result<WorkerIsolationProfile, DependencyError> {
        if requested == WorkerIsolationProfile::DedicatedWorker || tenant_id.as_uuid().is_nil() {
            return Err(DependencyError::Rejected);
        }
        if !self.qualified || requested == WorkerIsolationProfile::DedicatedProcess {
            return Ok(WorkerIsolationProfile::DedicatedProcess);
        }
        Ok(match self.tenant_reuse.get(tenant_id) {
            Some(TenantShardReusePolicy::CrossTenant) => requested,
            Some(TenantShardReusePolicy::SameTenantOnly) => {
                WorkerIsolationProfile::TenantDedicatedShard
            }
            Some(TenantShardReusePolicy::NoReuse) | None => {
                WorkerIsolationProfile::DedicatedProcess
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedContextPolicyError {
    Rejected,
    Unavailable,
}

impl fmt::Display for SharedContextPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "shared context policy rejected",
            Self::Unavailable => "shared context policy unavailable",
        })
    }
}

impl std::error::Error for SharedContextPolicyError {}

/// Missing configuration preserves dedicated process. An explicitly configured unreadable,
/// malformed or unsafe file fails startup; absent/mismatched qualification safely strengthens
/// placement to dedicated. The supervisor's approved launch checks remain independently required.
pub fn load_shared_context_policy(
    path: Option<&Path>,
    artifact: &ChromiumArtifactIdentity,
) -> Result<Option<Arc<SharedContextPlacementPolicy>>, SharedContextPolicyError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = read_private_policy(path)?;
    let config: SharedContextPlacementConfig =
        serde_json::from_slice(&bytes).map_err(|_| SharedContextPolicyError::Rejected)?;
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|_| SharedContextPolicyError::Unavailable)?;
    SharedContextPlacementPolicy::from_config(config, artifact, kernel.trim_end())
        .map(Arc::new)
        .map(Some)
}

pub(crate) fn read_private_policy(path: &Path) -> Result<Vec<u8>, SharedContextPolicyError> {
    if !path.is_absolute() {
        return Err(SharedContextPolicyError::Rejected);
    }
    let parent = path.parent().ok_or(SharedContextPolicyError::Rejected)?;
    let filename = path.file_name().ok_or(SharedContextPolicyError::Rejected)?;
    let uid = nix::unistd::geteuid().as_raw();
    let deadline = Instant::now() + LOAD_BUDGET;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory = File::from(
        open(Path::new("/"), flags, Mode::empty())
            .map_err(|_| SharedContextPolicyError::Unavailable)?,
    );
    for component in parent.components() {
        if Instant::now() >= deadline {
            return Err(SharedContextPolicyError::Unavailable);
        }
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(
                    openat(&directory, Path::new(name), flags, Mode::empty())
                        .map_err(|_| SharedContextPolicyError::Rejected)?,
                );
            }
            _ => return Err(SharedContextPolicyError::Rejected),
        }
    }
    let parent_before = directory
        .metadata()
        .map_err(|_| SharedContextPolicyError::Unavailable)?;
    if !parent_before.is_dir()
        || parent_before.uid() != uid
        || parent_before.mode() & 0o7777 != 0o700
    {
        return Err(SharedContextPolicyError::Rejected);
    }
    let mut file = File::from(
        openat(
            &directory,
            Path::new(filename),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SharedContextPolicyError::Unavailable)?,
    );
    let before = file
        .metadata()
        .map_err(|_| SharedContextPolicyError::Unavailable)?;
    if !before.is_file()
        || before.uid() != uid
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_POLICY_BYTES as u64
    {
        return Err(SharedContextPolicyError::Rejected);
    }
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        if Instant::now() >= deadline {
            return Err(SharedContextPolicyError::Unavailable);
        }
        let count = file
            .read(&mut chunk)
            .map_err(|_| SharedContextPolicyError::Unavailable)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > MAX_POLICY_BYTES {
            return Err(SharedContextPolicyError::Rejected);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let after = file
        .metadata()
        .map_err(|_| SharedContextPolicyError::Unavailable)?;
    let parent_after = directory
        .metadata()
        .map_err(|_| SharedContextPolicyError::Unavailable)?;
    if !unchanged_file(&before, &after)
        || bytes.len() as u64 != before.len()
        || parent_after.dev() != parent_before.dev()
        || parent_after.ino() != parent_before.ino()
        || parent_after.uid() != uid
        || parent_after.mode() & 0o7777 != 0o700
    {
        return Err(SharedContextPolicyError::Rejected);
    }
    Ok(bytes)
}

fn unchanged_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn deserialize_tenant_grants<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<TenantId, TenantShardReusePolicy>, D::Error> {
    struct TenantGrantsVisitor;
    impl<'de> Visitor<'de> for TenantGrantsVisitor {
        type Value = BTreeMap<TenantId, TenantShardReusePolicy>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map of unique tenant reuse grants")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut grants = BTreeMap::new();
            while let Some((tenant, reuse)) = map.next_entry()? {
                if grants.len() >= MAX_TENANT_GRANTS || grants.insert(tenant, reuse).is_some() {
                    return Err(serde::de::Error::custom("invalid tenant reuse grants"));
                }
            }
            Ok(grants)
        }
    }
    deserializer.deserialize_map(TenantGrantsVisitor)
}
