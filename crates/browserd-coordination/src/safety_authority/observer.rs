use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use browserd_core::{MAX_RUNTIME_SAFETY_FRESHNESS, RuntimeSafetyCache, RuntimeSafetyError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{SafetyAuthority, SafetyAuthorityError, SafetyAuthoritySnapshot};

const MAX_PIN_BYTES: u64 = 4_096;
const QUALIFIED: &[u8] = b"browserd-safety-observer-v1\n";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyObserverWatermark {
    namespace_id: Uuid,
    version: u64,
    snapshot_digest: [u8; 32],
}
impl SafetyObserverWatermark {
    pub const fn namespace_id(&self) -> Uuid {
        self.namespace_id
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinEnvelope {
    format_version: u8,
    pin: SafetyObserverWatermark,
    checksum: [u8; 32],
}
struct Disk {
    directory: File,
    path: PathBuf,
    lock: File,
    uid: u32,
}
struct ObserverState {
    pin: Option<SafetyObserverWatermark>,
    // Keep the accepted inode alive so an unlinked pin cannot be replaced by a reused inode.
    pin_file: Option<File>,
    poisoned: bool,
}

pub struct SafetyObserver {
    authority: Arc<dyn SafetyAuthority>,
    cache: Arc<RuntimeSafetyCache>,
    ttl: Duration,
    disk: Disk,
    state: Mutex<ObserverState>,
    refresh_gate: tokio::sync::Mutex<()>,
}

fn durability<E>(_: E) -> SafetyAuthorityError {
    SafetyAuthorityError::DurabilityUnavailable
}
fn private_file(file: &File, uid: u32) -> Result<std::fs::Metadata, SafetyAuthorityError> {
    let metadata = file.metadata().map_err(durability)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(SafetyAuthorityError::DurabilityUnavailable);
    }
    Ok(metadata)
}
fn cache_error(error: RuntimeSafetyError) -> SafetyAuthorityError {
    match error {
        RuntimeSafetyError::NamespaceConflict => SafetyAuthorityError::NamespaceMismatch,
        RuntimeSafetyError::VersionRollback => SafetyAuthorityError::Rollback,
        RuntimeSafetyError::Equivocation => SafetyAuthorityError::Equivocation,
        _ => SafetyAuthorityError::Unavailable,
    }
}

impl SafetyObserver {
    pub fn open(
        path: PathBuf,
        authority: Arc<dyn SafetyAuthority>,
        cache: Arc<RuntimeSafetyCache>,
        freshness_ttl: Duration,
    ) -> Result<Self, SafetyAuthorityError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || freshness_ttl.is_zero()
            || freshness_ttl > MAX_RUNTIME_SAFETY_FRESHNESS
        {
            return Err(SafetyAuthorityError::InvalidConfig);
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| {
                !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
            })
            .ok_or(SafetyAuthorityError::InvalidConfig)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(path.parent().ok_or(SafetyAuthorityError::InvalidConfig)?)
            .map_err(durability)?;
        let uid = std::fs::metadata("/proc/self").map_err(durability)?.uid();
        let metadata = directory.metadata().map_err(durability)?;
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(SafetyAuthorityError::InvalidConfig);
        }
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let pinned_path = pinned.join(name);
        let mut lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(pinned.join(format!("{name}.lock")))
            .map_err(durability)?;
        let lock_metadata = private_file(&lock, uid)?;
        if lock_metadata.len() > QUALIFIED.len() as u64 {
            return Err(SafetyAuthorityError::DurabilityUnavailable);
        }
        lock.try_lock().map_err(durability)?;
        let mut qualification = Vec::new();
        lock.read_to_end(&mut qualification).map_err(durability)?;
        if !qualification.is_empty() && qualification != QUALIFIED {
            return Err(SafetyAuthorityError::DurabilityUnavailable);
        }
        let (pin, pin_file) = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&pinned_path)
        {
            Ok(file) => {
                let metadata = private_file(&file, uid)?;
                if metadata.len() > MAX_PIN_BYTES {
                    return Err(SafetyAuthorityError::DurabilityUnavailable);
                }
                let mut bytes = Vec::new();
                (&file)
                    .take(MAX_PIN_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(durability)?;
                if bytes.len() > MAX_PIN_BYTES as usize {
                    return Err(SafetyAuthorityError::DurabilityUnavailable);
                }
                let envelope: PinEnvelope = serde_json::from_slice(&bytes).map_err(durability)?;
                let digest: [u8; 32] =
                    Sha256::digest(serde_json::to_vec(&envelope.pin).map_err(durability)?).into();
                if envelope.format_version != 1
                    || digest != envelope.checksum
                    || envelope.pin.namespace_id.is_nil()
                    || envelope.pin.version > i64::MAX as u64
                {
                    return Err(SafetyAuthorityError::DurabilityUnavailable);
                }
                (Some(envelope.pin), Some(file))
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && qualification.is_empty() =>
            {
                (None, None)
            }
            Err(error) => return Err(durability(error)),
        };
        // A process restart cannot carry RAM freshness into the new observer's verification.
        cache.invalidate().map_err(cache_error)?;
        Ok(Self {
            authority,
            cache,
            ttl: freshness_ttl,
            disk: Disk {
                directory,
                path: pinned_path,
                lock,
                uid,
            },
            state: Mutex::new(ObserverState {
                pin,
                pin_file,
                poisoned: false,
            }),
            refresh_gate: tokio::sync::Mutex::new(()),
        })
    }
    pub fn last_accepted(&self) -> Result<Option<SafetyObserverWatermark>, SafetyAuthorityError> {
        let state = self.state.lock().map_err(durability)?;
        if state.poisoned {
            return Err(SafetyAuthorityError::DurabilityUnavailable);
        }
        Ok(state.pin.clone())
    }
    fn invalidate(&self) {
        let _ = self.cache.invalidate();
    }

    fn verify_current_pin(&self, expected: Option<&File>) -> Result<(), SafetyAuthorityError> {
        // The held descriptor detects unlinking even if the replacement has identical bytes.
        let expected_metadata = expected
            .map(|file| private_file(file, self.disk.uid))
            .transpose()?;
        match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.disk.path)
        {
            Ok(file) => {
                let metadata = private_file(&file, self.disk.uid)?;
                if expected_metadata.is_none_or(|expected| {
                    metadata.dev() != expected.dev() || metadata.ino() != expected.ino()
                }) {
                    return Err(SafetyAuthorityError::DurabilityUnavailable);
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && expected.is_none() => {
                Ok(())
            }
            Err(error) => Err(durability(error)),
        }
    }

    fn persist(
        &self,
        state: &mut ObserverState,
        pin: SafetyObserverWatermark,
    ) -> Result<(), SafetyAuthorityError> {
        let temporary = self
            .disk
            .path
            .with_extension(format!("{}.pending", Uuid::new_v4()));
        let result = (|| -> Result<(), SafetyAuthorityError> {
            self.verify_current_pin(state.pin_file.as_ref())?;
            let checksum = Sha256::digest(serde_json::to_vec(&pin).map_err(durability)?).into();
            let bytes = serde_json::to_vec(&PinEnvelope {
                format_version: 1,
                pin: pin.clone(),
                checksum,
            })
            .map_err(durability)?;
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(durability)?;
            file.write_all(&bytes).map_err(durability)?;
            file.sync_all().map_err(durability)?;
            self.verify_current_pin(state.pin_file.as_ref())?;
            std::fs::rename(&temporary, &self.disk.path).map_err(durability)?;
            self.disk.directory.sync_all().map_err(durability)?;
            // This permanent qualification marker detects loss of a previously established pin.
            let mut lock = &self.disk.lock;
            lock.seek(SeekFrom::Start(0)).map_err(durability)?;
            lock.write_all(QUALIFIED).map_err(durability)?;
            lock.set_len(QUALIFIED.len() as u64).map_err(durability)?;
            lock.sync_all().map_err(durability)?;
            // Swap descriptors only after the new pin and qualification marker are durable.
            self.verify_current_pin(Some(&file))?;
            state.pin_file = Some(file);
            state.pin = Some(pin);
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
            state.poisoned = true;
            self.invalidate();
        }
        result
    }

    pub async fn refresh(&self) -> Result<SafetyAuthoritySnapshot, SafetyAuthorityError> {
        let _refresh = self.refresh_gate.lock().await;
        let authority = match self.authority.read().await {
            Ok(authority) => authority,
            Err(error) => {
                // Transient reads do not extend freshness; the cache's monotonic deadline stands.
                if !matches!(
                    error,
                    SafetyAuthorityError::Unavailable | SafetyAuthorityError::TimedOut
                ) {
                    self.invalidate();
                }
                return Err(error);
            }
        };
        if let Err(error) = authority.validate() {
            self.invalidate();
            return Err(error);
        }
        let mut state = self.state.lock().map_err(|error| {
            self.invalidate();
            durability(error)
        })?;
        if state.poisoned {
            self.invalidate();
            return Err(SafetyAuthorityError::DurabilityUnavailable);
        }
        if let Some(pin) = &state.pin {
            let error = if pin.namespace_id != authority.namespace_id() {
                Some(SafetyAuthorityError::NamespaceMismatch)
            } else if pin.version > authority.snapshot().version() {
                Some(SafetyAuthorityError::Rollback)
            } else if pin.version == authority.snapshot().version()
                && pin.snapshot_digest != authority.snapshot_digest()
            {
                Some(SafetyAuthorityError::Equivocation)
            } else {
                None
            };
            if let Some(error) = error {
                self.invalidate();
                return Err(error);
            }
        }
        let pin = SafetyObserverWatermark {
            namespace_id: authority.namespace_id(),
            version: authority.snapshot().version(),
            snapshot_digest: authority.snapshot_digest(),
        };
        // Persist even an exact refresh: path replacement/deletion must not regain freshness.
        self.persist(&mut state, pin)?;
        self.cache
            .install(
                authority.namespace_id(),
                authority.snapshot().clone(),
                self.ttl,
            )
            .map_err(cache_error)?;
        Ok(authority)
    }
}
