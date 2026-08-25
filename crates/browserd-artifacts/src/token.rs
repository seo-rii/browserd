use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, MutexGuard};

use browserd_core::ArtifactId;
use chrono::{DateTime, Utc};

use crate::{ArtifactKey, ArtifactNamespace};

#[derive(Clone, Eq, PartialEq)]
pub struct DownloadToken {
    first: ArtifactId,
    second: ArtifactId,
}

impl Hash for DownloadToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.first.hash(state);
        self.second.hash(state);
    }
}

impl fmt::Debug for DownloadToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DownloadToken([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DownloadTokenError {
    Unavailable,
}

impl fmt::Display for DownloadTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("download token is unavailable")
    }
}

impl std::error::Error for DownloadTokenError {}

struct TokenRecord {
    key: ArtifactKey,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct OneTimeDownloadTokenRegistry {
    tokens: Mutex<HashMap<DownloadToken, TokenRecord>>,
}

impl OneTimeDownloadTokenRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn issue(&self, key: &ArtifactKey, expires_at: DateTime<Utc>) -> DownloadToken {
        let mut tokens = lock(&self.tokens);
        loop {
            let token = DownloadToken {
                first: ArtifactId::new(),
                second: ArtifactId::new(),
            };
            if !tokens.contains_key(&token) {
                tokens.insert(
                    token.clone(),
                    TokenRecord {
                        key: key.clone(),
                        expires_at,
                    },
                );
                return token;
            }
        }
    }

    pub async fn consume(
        &self,
        token: &DownloadToken,
        namespace: &ArtifactNamespace,
        now: DateTime<Utc>,
    ) -> Result<ArtifactKey, DownloadTokenError> {
        let mut tokens = lock(&self.tokens);
        let Some(record) = tokens.get(token) else {
            return Err(DownloadTokenError::Unavailable);
        };

        if now >= record.expires_at || namespace.authorize(&record.key).is_err() {
            if now >= record.expires_at {
                tokens.remove(token);
            }
            return Err(DownloadTokenError::Unavailable);
        }

        match tokens.remove(token) {
            Some(record) => Ok(record.key),
            None => Err(DownloadTokenError::Unavailable),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
