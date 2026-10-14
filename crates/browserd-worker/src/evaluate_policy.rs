//! Immutable, private-file authorization for privileged JavaScript evaluation.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use browserd_core::{PrincipalId, TenantId};
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAX_PRIVILEGED_EVALUATE_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_PRIVILEGED_EVALUATE_GRANTS: usize = 1024;
const READ_BYTES: usize = 4096;
const LOAD_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedEvaluateGrant {
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
}

impl fmt::Debug for PrivilegedEvaluateGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivilegedEvaluateGrant")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegedEvaluatePolicyError {
    Rejected,
    Unavailable,
}

impl fmt::Display for PrivilegedEvaluatePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "privileged evaluate policy rejected",
            Self::Unavailable => "privileged evaluate policy unavailable",
        })
    }
}

impl std::error::Error for PrivilegedEvaluatePolicyError {}

/// A process-lifetime snapshot. Missing configuration is represented by `Default`, which denies
/// every request; an explicitly configured invalid or missing file is an error, never a fallback.
#[derive(Clone, Eq, PartialEq)]
pub struct PrivilegedEvaluatePolicy {
    grants: BTreeSet<(TenantId, PrincipalId)>,
    digest: [u8; 32],
}

impl Default for PrivilegedEvaluatePolicy {
    fn default() -> Self {
        Self::from_valid_grants(BTreeSet::new())
    }
}

impl fmt::Debug for PrivilegedEvaluatePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivilegedEvaluatePolicy")
            .field("grant_count", &self.grants.len())
            .finish_non_exhaustive()
    }
}

impl PrivilegedEvaluatePolicy {
    pub fn new(
        grants: Vec<PrivilegedEvaluateGrant>,
    ) -> Result<Self, PrivilegedEvaluatePolicyError> {
        if grants.len() > MAX_PRIVILEGED_EVALUATE_GRANTS {
            return Err(PrivilegedEvaluatePolicyError::Rejected);
        }
        let mut canonical = BTreeSet::new();
        for grant in grants {
            if grant.tenant_id.as_uuid().is_nil()
                || grant.principal_id.as_uuid().is_nil()
                || !canonical.insert((grant.tenant_id, grant.principal_id))
            {
                return Err(PrivilegedEvaluatePolicyError::Rejected);
            }
        }
        Ok(Self::from_valid_grants(canonical))
    }

    /// Loads one immutable snapshot through pinned directory/file descriptors. Every path
    /// component rejects symlinks; the immediate parent must be owned by the effective UID with
    /// mode 0700, and the regular, singly linked file must have the same owner and mode 0600.
    pub fn open(path: &Path) -> Result<Self, PrivilegedEvaluatePolicyError> {
        if !path.is_absolute() {
            return Err(PrivilegedEvaluatePolicyError::Rejected);
        }
        let parent = path
            .parent()
            .ok_or(PrivilegedEvaluatePolicyError::Rejected)?;
        let filename = path
            .file_name()
            .ok_or(PrivilegedEvaluatePolicyError::Rejected)?;
        let deadline = Instant::now() + LOAD_BUDGET;
        let owner_uid = nix::unistd::geteuid().as_raw();
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let mut directory = File::from(
            open(Path::new("/"), flags, Mode::empty())
                .map_err(|_| PrivilegedEvaluatePolicyError::Unavailable)?,
        );
        for component in parent.components() {
            if Instant::now() >= deadline {
                return Err(PrivilegedEvaluatePolicyError::Unavailable);
            }
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    directory = File::from(
                        openat(&directory, Path::new(name), flags, Mode::empty())
                            .map_err(|_| PrivilegedEvaluatePolicyError::Rejected)?,
                    );
                }
                _ => return Err(PrivilegedEvaluatePolicyError::Rejected),
            }
        }
        let parent_metadata = directory
            .metadata()
            .map_err(|_| PrivilegedEvaluatePolicyError::Unavailable)?;
        if !parent_metadata.is_dir()
            || parent_metadata.uid() != owner_uid
            || parent_metadata.mode() & 0o7777 != 0o700
        {
            return Err(PrivilegedEvaluatePolicyError::Rejected);
        }
        if Instant::now() >= deadline {
            return Err(PrivilegedEvaluatePolicyError::Unavailable);
        }
        let mut file = File::from(
            openat(
                &directory,
                Path::new(filename),
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| PrivilegedEvaluatePolicyError::Unavailable)?,
        );
        let before = file
            .metadata()
            .map_err(|_| PrivilegedEvaluatePolicyError::Unavailable)?;
        let bytes = read_bounded(&mut file, &before, owner_uid, deadline, File::metadata)?;
        let after_parent = directory
            .metadata()
            .map_err(|_| PrivilegedEvaluatePolicyError::Unavailable)?;
        if !after_parent.is_dir()
            || after_parent.dev() != parent_metadata.dev()
            || after_parent.ino() != parent_metadata.ino()
            || after_parent.uid() != owner_uid
            || after_parent.mode() & 0o7777 != 0o700
        {
            return Err(PrivilegedEvaluatePolicyError::Rejected);
        }
        let result = Self::from_bytes(&bytes);
        if Instant::now() >= deadline {
            return Err(PrivilegedEvaluatePolicyError::Unavailable);
        }
        result
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.grants.is_empty()
    }

    #[must_use]
    pub fn allows_tenant(&self, tenant_id: &TenantId) -> bool {
        self.grants.iter().any(|(tenant, _)| tenant == tenant_id)
    }

    #[must_use]
    pub fn allows(&self, tenant_id: &TenantId, principal_id: &PrincipalId) -> bool {
        self.grants
            .contains(&(tenant_id.clone(), principal_id.clone()))
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    fn from_valid_grants(grants: BTreeSet<(TenantId, PrincipalId)>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"browserd-privileged-evaluate-policy\0");
        hasher.update(1u32.to_be_bytes());
        hasher.update((grants.len() as u32).to_be_bytes());
        for (tenant, principal) in &grants {
            hasher.update(tenant.as_bytes());
            hasher.update(principal.as_bytes());
        }
        Self {
            grants,
            digest: hasher.finalize().into(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PrivilegedEvaluatePolicyError> {
        if bytes.len() > MAX_PRIVILEGED_EVALUATE_POLICY_BYTES {
            return Err(PrivilegedEvaluatePolicyError::Rejected);
        }
        let config: PrivilegedEvaluateConfig =
            serde_json::from_slice(bytes).map_err(|_| PrivilegedEvaluatePolicyError::Rejected)?;
        if config.schema_version != 1 {
            return Err(PrivilegedEvaluatePolicyError::Rejected);
        }
        Self::new(config.grants.0)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivilegedEvaluateConfig {
    schema_version: u32,
    grants: BoundedGrants,
}

struct BoundedGrants(Vec<PrivilegedEvaluateGrant>);

impl<'de> Deserialize<'de> for BoundedGrants {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct GrantsVisitor;
        impl<'de> Visitor<'de> for GrantsVisitor {
            type Value = BoundedGrants;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded privileged evaluate grant array")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut grants = Vec::new();
                while let Some(grant) = sequence.next_element()? {
                    if grants.len() == MAX_PRIVILEGED_EVALUATE_GRANTS {
                        return Err(serde::de::Error::custom("too many evaluate grants"));
                    }
                    grants.push(grant);
                }
                Ok(BoundedGrants(grants))
            }
        }
        deserializer.deserialize_seq(GrantsVisitor)
    }
}

fn read_bounded<R: Read>(
    reader: &mut R,
    before: &Metadata,
    owner_uid: u32,
    deadline: Instant,
    after_metadata: impl FnOnce(&R) -> std::io::Result<Metadata>,
) -> Result<Zeroizing<Vec<u8>>, PrivilegedEvaluatePolicyError> {
    if Instant::now() >= deadline {
        return Err(PrivilegedEvaluatePolicyError::Unavailable);
    }
    if !before.is_file()
        || before.uid() != owner_uid
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > MAX_PRIVILEGED_EVALUATE_POLICY_BYTES as u64
    {
        return Err(PrivilegedEvaluatePolicyError::Rejected);
    }
    // Full preallocation ensures file growth cannot leave an unwiped previous allocation.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PRIVILEGED_EVALUATE_POLICY_BYTES));
    let mut chunk = Zeroizing::new([0u8; READ_BYTES]);
    loop {
        if Instant::now() >= deadline {
            return Err(PrivilegedEvaluatePolicyError::Unavailable);
        }
        let count = reader
            .read(chunk.as_mut())
            .map_err(|_| PrivilegedEvaluatePolicyError::Unavailable)?;
        if Instant::now() >= deadline {
            return Err(PrivilegedEvaluatePolicyError::Unavailable);
        }
        if count == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|length| length > MAX_PRIVILEGED_EVALUATE_POLICY_BYTES)
        {
            return Err(PrivilegedEvaluatePolicyError::Rejected);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let after = after_metadata(reader).map_err(|_| PrivilegedEvaluatePolicyError::Unavailable)?;
    if !after.is_file()
        || after.uid() != owner_uid
        || after.nlink() != 1
        || after.mode() & 0o7777 != 0o600
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(PrivilegedEvaluatePolicyError::Rejected);
    }
    if Instant::now() >= deadline {
        return Err(PrivilegedEvaluatePolicyError::Unavailable);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "evaluate_policy_tests.rs"]
mod tests;
