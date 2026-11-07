//! Private versioned operator keys. Persisted endpoint references contain no key bytes.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use browserd_api::{WebhookKeyError, WebhookSigningKeyProvider, WebhookSigningSecret};
use browserd_coordination::WebhookSigningKeyRef;
use browserd_core::TenantId;
use hmac::{Hmac, Mac};
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use serde::Deserialize;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const MAX_KEY_FILE_BYTES: usize = 4096;
const MAX_MASTER_KEYS: usize = 8;
const LOAD_BUDGET: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    schema_version: u32,
    active_master_version_id: String,
    keys: Vec<MasterKeyInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MasterKeyInput {
    master_version_id: String,
    key_base64: String,
}

impl Drop for MasterKeyInput {
    fn drop(&mut self) {
        self.key_base64.zeroize();
    }
}

pub struct WebhookMasterKeyRing {
    active_master_version_id: String,
    keys: BTreeMap<String, Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for WebhookMasterKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookMasterKeyRing")
            .field("active_master_version_id", &self.active_master_version_id)
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl WebhookMasterKeyRing {
    fn parse(bytes: &[u8]) -> Result<Self, WebhookKeyError> {
        let input: KeyFile =
            serde_json::from_slice(bytes).map_err(|_| WebhookKeyError::InvalidReference)?;
        if input.schema_version != 1
            || input.keys.is_empty()
            || input.keys.len() > MAX_MASTER_KEYS
            || !valid_master_version(&input.active_master_version_id)
        {
            return Err(WebhookKeyError::InvalidReference);
        }
        let mut keys = BTreeMap::new();
        for entry in &input.keys {
            if !valid_master_version(&entry.master_version_id) {
                return Err(WebhookKeyError::InvalidReference);
            }
            let decoded = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(&entry.key_base64)
                    .map_err(|_| WebhookKeyError::InvalidReference)?,
            );
            let canonical =
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&decoded[..]));
            if decoded.len() != 32 || canonical.as_str() != entry.key_base64 {
                return Err(WebhookKeyError::InvalidReference);
            }
            let mut key = Zeroizing::new([0; 32]);
            key.copy_from_slice(&decoded);
            if keys.insert(entry.master_version_id.clone(), key).is_some() {
                return Err(WebhookKeyError::InvalidReference);
            }
        }
        if !keys.contains_key(&input.active_master_version_id) {
            return Err(WebhookKeyError::InvalidReference);
        }
        Ok(Self {
            active_master_version_id: input.active_master_version_id,
            keys,
        })
    }
}

impl WebhookSigningKeyProvider for WebhookMasterKeyRing {
    fn active_master_version_id(&self) -> &str {
        &self.active_master_version_id
    }

    fn derive(
        &self,
        tenant: &TenantId,
        key_ref: &WebhookSigningKeyRef,
    ) -> Result<WebhookSigningSecret, WebhookKeyError> {
        if tenant.as_uuid().is_nil()
            || !valid_master_version(key_ref.master_version_id())
            || key_ref.key_id().get_version() != Some(uuid::Version::Random)
        {
            return Err(WebhookKeyError::InvalidReference);
        }
        let master = self
            .keys
            .get(key_ref.master_version_id())
            .ok_or(WebhookKeyError::Unavailable)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&master[..])
            .map_err(|_| WebhookKeyError::Unavailable)?;
        mac.update(b"browserd.webhook.signing-key.v1\0");
        let version = key_ref.master_version_id().as_bytes();
        mac.update(&(version.len() as u32).to_be_bytes());
        mac.update(version);
        mac.update(&16_u32.to_be_bytes());
        mac.update(tenant.as_uuid().as_bytes());
        mac.update(&16_u32.to_be_bytes());
        mac.update(key_ref.key_id().as_bytes());
        let mut derived = Zeroizing::new([0; 32]);
        let mut digest = mac.finalize().into_bytes();
        derived.copy_from_slice(&digest);
        digest[..].zeroize();
        Ok(WebhookSigningSecret::new(*derived))
    }
}

fn valid_master_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Unconfigured webhooks leave polling available. An explicitly configured unsafe or
/// malformed file fails startup; missing historical key versions never use the active key.
pub fn load_webhook_signing_keys(
    path: Option<&Path>,
) -> Result<Option<Arc<WebhookMasterKeyRing>>, WebhookKeyError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = read_private_keys(path)?;
    WebhookMasterKeyRing::parse(&bytes).map(Arc::new).map(Some)
}

fn read_private_keys(path: &Path) -> Result<Zeroizing<Vec<u8>>, WebhookKeyError> {
    if !path.is_absolute() {
        return Err(WebhookKeyError::InvalidReference);
    }
    let parent = path.parent().ok_or(WebhookKeyError::InvalidReference)?;
    let filename = path.file_name().ok_or(WebhookKeyError::InvalidReference)?;
    let uid = nix::unistd::geteuid().as_raw();
    let deadline = Instant::now() + LOAD_BUDGET;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory = File::from(
        open(Path::new("/"), flags, Mode::empty()).map_err(|_| WebhookKeyError::Unavailable)?,
    );
    for component in parent.components() {
        if Instant::now() >= deadline {
            return Err(WebhookKeyError::Unavailable);
        }
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(
                    openat(&directory, Path::new(name), flags, Mode::empty())
                        .map_err(|_| WebhookKeyError::InvalidReference)?,
                );
            }
            _ => return Err(WebhookKeyError::InvalidReference),
        }
    }
    let parent_before = directory
        .metadata()
        .map_err(|_| WebhookKeyError::Unavailable)?;
    if !parent_before.is_dir()
        || parent_before.uid() != uid
        || parent_before.mode() & 0o7777 != 0o700
    {
        return Err(WebhookKeyError::InvalidReference);
    }
    let mut file = File::from(
        openat(
            &directory,
            Path::new(filename),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| WebhookKeyError::Unavailable)?,
    );
    let before = file.metadata().map_err(|_| WebhookKeyError::Unavailable)?;
    if !before.is_file()
        || before.uid() != uid
        || !matches!(before.mode() & 0o7777, 0o400 | 0o600)
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_KEY_FILE_BYTES as u64
    {
        return Err(WebhookKeyError::InvalidReference);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; 1024]);
    loop {
        if Instant::now() >= deadline {
            return Err(WebhookKeyError::Unavailable);
        }
        let count = file
            .read(&mut chunk[..])
            .map_err(|_| WebhookKeyError::Unavailable)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > MAX_KEY_FILE_BYTES {
            return Err(WebhookKeyError::InvalidReference);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let after = file.metadata().map_err(|_| WebhookKeyError::Unavailable)?;
    let parent_after = directory
        .metadata()
        .map_err(|_| WebhookKeyError::Unavailable)?;
    if !unchanged_file(&before, &after)
        || bytes.len() as u64 != before.len()
        || parent_after.dev() != parent_before.dev()
        || parent_after.ino() != parent_before.ino()
        || parent_after.uid() != uid
        || parent_after.mode() & 0o7777 != 0o700
    {
        return Err(WebhookKeyError::InvalidReference);
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

#[cfg(test)]
mod tests;
