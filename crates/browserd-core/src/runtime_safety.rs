//! Fresh, monotonic runtime admission; persistence belongs to the safety authority/observer.
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::SafetySwitchSnapshot;

pub const MAX_RUNTIME_SAFETY_FRESHNESS: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSafetyError {
    Unavailable,
    Expired,
    InvalidNamespace,
    InvalidSnapshot,
    InvalidFreshness,
    NamespaceConflict,
    VersionRollback,
    Equivocation,
}
impl fmt::Display for RuntimeSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("runtime safety authority unavailable or inconsistent")
    }
}
impl std::error::Error for RuntimeSafetyError {}

#[derive(Clone, Debug)]
pub struct RuntimeSafetyGeneration {
    namespace_id: Uuid,
    version: u64,
    cancellation_token: CancellationToken,
    expires_at: Instant,
}
impl RuntimeSafetyGeneration {
    #[must_use]
    pub const fn namespace_id(&self) -> Uuid {
        self.namespace_id
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }
    #[must_use]
    pub const fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

#[derive(Debug)]
struct InstalledSafety {
    namespace_id: Uuid,
    snapshot: SafetySwitchSnapshot,
    digest: [u8; 32],
    cancellation_token: CancellationToken,
    expires_at: Instant,
    available: bool,
}
impl InstalledSafety {
    fn invalidate(&mut self) {
        self.available = false;
        self.cancellation_token.cancel();
    }
}

#[derive(Debug, Default)]
pub struct RuntimeSafetyCache {
    installed: Mutex<Option<InstalledSafety>>,
}
impl RuntimeSafetyCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The durable observer must fsync its namespace/version/digest pin BEFORE publication.
    /// Invalid input cancels current users but never clears the permanent local continuity pin.
    pub fn install(
        &self,
        namespace_id: Uuid,
        snapshot: SafetySwitchSnapshot,
        freshness_ttl: Duration,
    ) -> Result<(), RuntimeSafetyError> {
        let mut installed = self.installed.lock().map_err(|poisoned| {
            if let Some(current) = poisoned.into_inner().as_mut() {
                current.invalidate();
            }
            RuntimeSafetyError::Unavailable
        })?;
        let checked = (|| {
            if namespace_id.is_nil() {
                return Err(RuntimeSafetyError::InvalidNamespace);
            }
            if freshness_ttl.is_zero() || freshness_ttl > MAX_RUNTIME_SAFETY_FRESHNESS {
                return Err(RuntimeSafetyError::InvalidFreshness);
            }
            let digest = snapshot
                .digest()
                .map_err(|_| RuntimeSafetyError::InvalidSnapshot)?;
            let expires_at = Instant::now()
                .checked_add(freshness_ttl)
                .ok_or(RuntimeSafetyError::InvalidFreshness)?;
            if let Some(current) = installed.as_ref() {
                if current.namespace_id != namespace_id {
                    return Err(RuntimeSafetyError::NamespaceConflict);
                }
                if snapshot.version() < current.snapshot.version() {
                    return Err(RuntimeSafetyError::VersionRollback);
                }
                if snapshot.version() == current.snapshot.version() && digest != current.digest {
                    return Err(RuntimeSafetyError::Equivocation);
                }
            }
            Ok((digest, expires_at))
        })();
        let (digest, expires_at) = match checked {
            Ok(value) => value,
            Err(error) => {
                if let Some(current) = installed.as_mut() {
                    current.invalidate();
                }
                return Err(error);
            }
        };
        if let Some(current) = installed.as_mut()
            && current.snapshot.version() == snapshot.version()
        {
            // Healthy polling must not terminate long-lived flows. Once invalidated/expired,
            // old tokens stay cancelled and restoration creates a separate generation.
            if !current.available
                || current.expires_at <= Instant::now()
                || current.cancellation_token.is_cancelled()
            {
                current.cancellation_token.cancel();
                current.cancellation_token = CancellationToken::new();
            }
            current.expires_at = expires_at;
            current.available = true;
            return Ok(());
        }
        if let Some(current) = installed.as_mut() {
            current.invalidate();
        }
        *installed = Some(InstalledSafety {
            namespace_id,
            snapshot,
            digest,
            cancellation_token: CancellationToken::new(),
            expires_at,
            available: true,
        });
        Ok(())
    }

    pub fn invalidate(&self) -> Result<(), RuntimeSafetyError> {
        let mut installed = self.installed.lock().map_err(|poisoned| {
            if let Some(current) = poisoned.into_inner().as_mut() {
                current.invalidate();
            }
            RuntimeSafetyError::Unavailable
        })?;
        if let Some(current) = installed.as_mut() {
            current.invalidate();
        }
        Ok(())
    }

    /// The callback is the effect-admission linearization point. It must be short, synchronous,
    /// non-reentrant, and must not perform browser I/O or acquire observer/authority locks.
    pub fn with_fresh_snapshot<T>(
        &self,
        callback: impl FnOnce(&SafetySwitchSnapshot) -> T,
    ) -> Result<T, RuntimeSafetyError> {
        let mut installed = self.installed.lock().map_err(|poisoned| {
            if let Some(current) = poisoned.into_inner().as_mut() {
                current.invalidate();
            }
            RuntimeSafetyError::Unavailable
        })?;
        let current = installed.as_mut().ok_or(RuntimeSafetyError::Unavailable)?;
        if !current.available {
            return Err(RuntimeSafetyError::Unavailable);
        }
        if current.expires_at <= Instant::now() {
            current.invalidate();
            return Err(RuntimeSafetyError::Expired);
        }
        Ok(callback(&current.snapshot))
    }

    /// Consumers select BOTH cancellation and the captured deadline. On deadline, a healthy
    /// unchanged generation may be fetched again to rearm; a cancelled old token never revives.
    pub fn generation(&self) -> Result<RuntimeSafetyGeneration, RuntimeSafetyError> {
        let mut installed = self.installed.lock().map_err(|poisoned| {
            if let Some(current) = poisoned.into_inner().as_mut() {
                current.invalidate();
            }
            RuntimeSafetyError::Unavailable
        })?;
        let current = installed.as_mut().ok_or(RuntimeSafetyError::Unavailable)?;
        if !current.available {
            return Err(RuntimeSafetyError::Unavailable);
        }
        if current.expires_at <= Instant::now() {
            current.invalidate();
            return Err(RuntimeSafetyError::Expired);
        }
        Ok(RuntimeSafetyGeneration {
            namespace_id: current.namespace_id,
            version: current.snapshot.version(),
            cancellation_token: current.cancellation_token.clone(),
            expires_at: current.expires_at,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
