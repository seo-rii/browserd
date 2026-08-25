use std::fmt;

use chrono::{DateTime, Utc};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CleanupKind {
    OrphanTempFile,
    AbandonedMultipart,
    ExpiredReservation,
    FailedQuarantineObject,
    ExpiredArtifact,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CleanupCandidate {
    id: String,
    kind: CleanupKind,
}

impl CleanupCandidate {
    #[must_use]
    pub fn new(id: impl Into<String>, kind: CleanupKind) -> Self {
        Self {
            id: id.into(),
            kind,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn kind(&self) -> CleanupKind {
        self.kind
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

    async fn cleanup(&self, candidate: &CleanupCandidate) -> Result<CleanupOutcome, JanitorError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JanitorReport {
    pub scanned: usize,
    pub cleaned: usize,
    pub already_clean: usize,
    pub failed: usize,
}

pub struct ArtifactJanitor<B> {
    backend: B,
}

impl<B> ArtifactJanitor<B>
where
    B: JanitorBackend,
{
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    pub async fn run_once(&self, now: DateTime<Utc>) -> Result<JanitorReport, JanitorError> {
        let candidates = self.backend.scan(now).await?;
        let mut report = JanitorReport {
            scanned: candidates.len(),
            ..JanitorReport::default()
        };

        for candidate in candidates {
            match self.backend.cleanup(&candidate).await {
                Ok(CleanupOutcome::Cleaned) => report.cleaned += 1,
                Ok(CleanupOutcome::AlreadyClean) => report.already_clean += 1,
                Err(_) => report.failed += 1,
            }
        }

        Ok(report)
    }
}
