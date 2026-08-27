use std::fmt;

use chrono::{DateTime, Utc};

use crate::{ArtifactKey, ArtifactNamespace};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CleanupKind {
    OrphanTempFile,
    AbandonedMultipart,
    ExpiredReservation,
    FailedQuarantineObject,
    ExpiredArtifact,
}

/// Backend-issued immutable identity for one incarnation of a cleanup target.
///
/// Backends may derive this from a native object version, ETag, inode
/// generation, or another collision-resistant conditional-delete token. They
/// must never reuse it when replacing an object, even under the same artifact
/// key and backend object id.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactObjectGeneration([u8; Self::LENGTH]);

impl ArtifactObjectGeneration {
    pub const LENGTH: usize = 32;

    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CleanupCandidate {
    key: ArtifactKey,
    id: String,
    kind: CleanupKind,
    object_generation: ArtifactObjectGeneration,
}

impl CleanupCandidate {
    #[must_use]
    pub fn new(
        key: ArtifactKey,
        id: impl Into<String>,
        kind: CleanupKind,
        object_generation: ArtifactObjectGeneration,
    ) -> Self {
        Self {
            key,
            id: id.into(),
            kind,
            object_generation,
        }
    }

    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn kind(&self) -> CleanupKind {
        self.kind
    }

    #[must_use]
    pub const fn object_generation(&self) -> ArtifactObjectGeneration {
        self.object_generation
    }
}

/// A cleanup candidate that has passed the janitor's tenant/session fence.
///
/// Backends must atomically revalidate both [`Self::key`] and
/// [`Self::object_generation`] against the current owner and incarnation of
/// [`Self::id`] before performing a destructive operation. Returning
/// [`CleanupOutcome::AlreadyClean`] makes exact retries after response loss
/// safe. A generation mismatch is not `AlreadyClean`: it is a stale cleanup
/// request and must perform no destructive effect.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuthorizedCleanupCandidate {
    candidate: CleanupCandidate,
}

impl AuthorizedCleanupCandidate {
    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        self.candidate.key()
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.candidate.id()
    }

    #[must_use]
    pub const fn kind(&self) -> CleanupKind {
        self.candidate.kind()
    }

    #[must_use]
    pub const fn object_generation(&self) -> ArtifactObjectGeneration {
        self.candidate.object_generation()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupOutcome {
    Cleaned,
    AlreadyClean,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JanitorError {
    message: String,
}

impl JanitorError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for JanitorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for JanitorError {}

#[allow(async_fn_in_trait)]
pub trait JanitorBackend: Send + Sync {
    async fn scan(&self, now: DateTime<Utc>) -> Result<Vec<CleanupCandidate>, JanitorError>;

    /// Conditionally cleans exactly the supplied key and object generation.
    /// The ownership and generation comparisons and the destructive effect
    /// must be one atomic backend operation.
    async fn cleanup(
        &self,
        candidate: &AuthorizedCleanupCandidate,
    ) -> Result<CleanupOutcome, JanitorError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JanitorReport {
    pub scanned: usize,
    pub cleaned: usize,
    pub already_clean: usize,
    pub namespace_denied: usize,
    pub failed: usize,
}

pub struct ArtifactJanitor<B> {
    namespace: ArtifactNamespace,
    backend: B,
}

impl<B> ArtifactJanitor<B>
where
    B: JanitorBackend,
{
    #[must_use]
    pub const fn new(namespace: ArtifactNamespace, backend: B) -> Self {
        Self { namespace, backend }
    }

    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<JanitorReport, JanitorError> {
        let candidates = self.backend.scan(now).await?;
        let mut report = JanitorReport {
            scanned: candidates.len(),
            ..JanitorReport::default()
        };

        for candidate in candidates {
            if self.namespace.authorize(candidate.key()).is_err() {
                report.namespace_denied += 1;
                continue;
            }
            let candidate = AuthorizedCleanupCandidate { candidate };
            match self.backend.cleanup(&candidate).await {
                Ok(CleanupOutcome::Cleaned) => report.cleaned += 1,
                Ok(CleanupOutcome::AlreadyClean) => report.already_clean += 1,
                Err(_) => report.failed += 1,
            }
        }

        Ok(report)
    }
}
