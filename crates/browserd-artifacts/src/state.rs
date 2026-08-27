use std::collections::HashSet;

use crate::{ArtifactContentMetadata, ArtifactContentSource, ArtifactError, ArtifactKey};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    Upload,
    Generated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactState {
    Uploading,
    Stored,
    Scanning,
    Available,
    Quarantined,
    Rejected,
    Generating,
    Finalizing,
    Failed,
    Deleting,
    Deleted,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArtifactEvent {
    UploadStored,
    ScanStarted,
    ScanPassed,
    ScanQuarantined,
    ScanRejected,
    GenerationCompleted,
    FinalizationSucceeded,
    FinalizationFailed,
    DeleteRequested,
    DeleteCompleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Debug)]
pub struct Artifact {
    key: ArtifactKey,
    kind: ArtifactKind,
    state: ArtifactState,
    applied_events: HashSet<ArtifactEvent>,
    content_metadata: Option<ArtifactContentMetadata>,
}

impl Artifact {
    #[must_use]
    pub fn new_upload(key: ArtifactKey) -> Self {
        Self {
            key,
            kind: ArtifactKind::Upload,
            state: ArtifactState::Uploading,
            applied_events: HashSet::new(),
            content_metadata: None,
        }
    }

    #[must_use]
    pub fn new_generated(key: ArtifactKey) -> Self {
        Self {
            key,
            kind: ArtifactKind::Generated,
            state: ArtifactState::Generating,
            applied_events: HashSet::new(),
            content_metadata: None,
        }
    }

    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }

    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    #[must_use]
    pub const fn state(&self) -> ArtifactState {
        self.state
    }

    #[must_use]
    pub const fn content_metadata(&self) -> Option<&ArtifactContentMetadata> {
        self.content_metadata.as_ref()
    }

    pub fn apply_materialized(
        &mut self,
        event: ArtifactEvent,
        metadata: ArtifactContentMetadata,
    ) -> Result<TransitionOutcome, ArtifactError> {
        let event_matches = matches!(
            (self.kind, event),
            (ArtifactKind::Upload, ArtifactEvent::UploadStored)
                | (ArtifactKind::Generated, ArtifactEvent::GenerationCompleted)
        );
        if !event_matches {
            return Err(ArtifactError::MetadataNotAllowed);
        }

        let source_matches = matches!(
            (self.kind, metadata.source()),
            (
                ArtifactKind::Upload,
                ArtifactContentSource::ClientUpload | ArtifactContentSource::BrowserDownload
            ) | (ArtifactKind::Generated, ArtifactContentSource::Generated)
        );
        if !source_matches {
            return Err(ArtifactError::MetadataSourceMismatch);
        }

        if self.applied_events.contains(&event) {
            return match self.content_metadata.as_ref() {
                Some(committed) if committed == &metadata => Ok(TransitionOutcome::AlreadyApplied),
                Some(_) | None => Err(ArtifactError::MetadataConflict),
            };
        }
        if self.content_metadata.is_some() {
            return Err(ArtifactError::MetadataConflict);
        }

        let outcome = self.apply_transition(event)?;
        self.content_metadata = Some(metadata);
        Ok(outcome)
    }

    pub fn apply(&mut self, event: ArtifactEvent) -> Result<TransitionOutcome, ArtifactError> {
        if matches!(
            (self.kind, event),
            (ArtifactKind::Upload, ArtifactEvent::UploadStored)
                | (ArtifactKind::Generated, ArtifactEvent::GenerationCompleted)
        ) {
            return Err(ArtifactError::MetadataRequired);
        }
        self.apply_transition(event)
    }

    fn apply_transition(
        &mut self,
        event: ArtifactEvent,
    ) -> Result<TransitionOutcome, ArtifactError> {
        if self.applied_events.contains(&event) {
            return Ok(TransitionOutcome::AlreadyApplied);
        }

        use ArtifactEvent as Event;
        use ArtifactKind as Kind;
        use ArtifactState as State;

        let next = match (self.kind, self.state, event) {
            (Kind::Upload, State::Uploading, Event::UploadStored) => State::Stored,
            (Kind::Upload, State::Stored, Event::ScanStarted) => State::Scanning,
            (Kind::Upload, State::Scanning, Event::ScanPassed) => State::Available,
            (Kind::Upload, State::Scanning, Event::ScanQuarantined) => State::Quarantined,
            (Kind::Upload, State::Scanning, Event::ScanRejected) => State::Rejected,
            (Kind::Generated, State::Generating, Event::GenerationCompleted) => State::Finalizing,
            (Kind::Generated, State::Finalizing, Event::FinalizationSucceeded) => State::Available,
            (Kind::Generated, State::Finalizing, Event::FinalizationFailed) => State::Failed,
            (_, State::Available, Event::DeleteRequested) => State::Deleting,
            (_, State::Deleting, Event::DeleteCompleted) => State::Deleted,
            _ => {
                return Err(ArtifactError::InvalidTransition {
                    from: self.state,
                    event,
                });
            }
        };
        self.state = next;
        self.applied_events.insert(event);
        Ok(TransitionOutcome::Applied)
    }
}
