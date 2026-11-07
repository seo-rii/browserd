//! Immutable durable publication and read-only retained artifact authority.
use crate::{
    ArtifactReadStream, ArtifactScanAttestation, ArtifactScanVerdict, AuthenticatedPeer,
    ChromiumDriver, SandboxClient, WorkerControlPlane, WorkerError,
};
use browserd_artifacts::{
    ArtifactContentMetadata, ArtifactContentSource, ArtifactKey, ArtifactObjectGeneration,
    ArtifactReadLimits, ArtifactState,
};
use browserd_core::{ArtifactId, SessionId, TenantId, WorkerId};
use browserd_session::OwnershipFence;

pub const ARTIFACT_PUBLICATION_TTL_MILLIS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_RETAINED_ARTIFACT_PAGE: usize = 101;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactPublication {
    key: ArtifactKey,
    original_fence: OwnershipFence,
    metadata: ArtifactContentMetadata,
    object_generation: ArtifactObjectGeneration,
    scan_verdict: Option<ArtifactScanVerdict>,
    display_filename: Option<String>,
    published_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    scan_attestation: Option<ArtifactScanAttestation>,
}
impl ArtifactPublication {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: ArtifactKey,
        original_fence: OwnershipFence,
        metadata: ArtifactContentMetadata,
        object_generation: ArtifactObjectGeneration,
        scan_verdict: Option<ArtifactScanVerdict>,
        display_filename: Option<String>,
        published_at_unix_millis: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, WorkerError> {
        Self::new_with_scan_attestation(
            key,
            original_fence,
            metadata,
            object_generation,
            scan_verdict,
            display_filename,
            published_at_unix_millis,
            expires_at_unix_millis,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_scan_attestation(
        key: ArtifactKey,
        original_fence: OwnershipFence,
        metadata: ArtifactContentMetadata,
        object_generation: ArtifactObjectGeneration,
        scan_verdict: Option<ArtifactScanVerdict>,
        display_filename: Option<String>,
        published_at_unix_millis: u64,
        expires_at_unix_millis: u64,
        scan_attestation: Option<ArtifactScanAttestation>,
    ) -> Result<Self, WorkerError> {
        let publication = Self {
            key,
            original_fence,
            metadata,
            object_generation,
            scan_verdict,
            display_filename,
            published_at_unix_millis,
            expires_at_unix_millis,
            scan_attestation,
        };
        publication.validate()?;
        Ok(publication)
    }
    pub fn validate(&self) -> Result<(), WorkerError> {
        let expected_scan = match self.metadata.source() {
            ArtifactContentSource::Generated => None,
            ArtifactContentSource::ClientUpload | ArtifactContentSource::BrowserDownload => {
                Some(ArtifactScanVerdict::Clean)
            }
        };
        if self.original_fence.worker_epoch() == 0
            || self.original_fence.placement_version() == 0
            || self.original_fence.session_incarnation() == 0
            || self.object_generation.as_bytes().iter().all(|b| *b == 0)
            || self.scan_verdict != expected_scan
            || self.expires_at_unix_millis <= self.published_at_unix_millis
            || self.expires_at_unix_millis - self.published_at_unix_millis
                > ARTIFACT_PUBLICATION_TTL_MILLIS
            || self
                .display_filename
                .as_deref()
                .is_some_and(|name| !crate::valid_artifact_display_filename(name))
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        match self.metadata.source() {
            ArtifactContentSource::Generated if self.scan_attestation.is_none() => {}
            ArtifactContentSource::Generated => return Err(WorkerError::InvalidConfiguration),
            ArtifactContentSource::ClientUpload | ArtifactContentSource::BrowserDownload => {
                let evidence = self
                    .scan_attestation
                    .as_ref()
                    .ok_or(WorkerError::InvalidConfiguration)?;
                evidence.validate_for(
                    &self.key,
                    &self.original_fence,
                    &self.metadata,
                    self.object_generation,
                )?;
                // Durable reads validate the scan at its original publication time. A database
                // becoming older later does not retroactively change immutable scan evidence.
                evidence.validate_at(self.published_at_unix_millis)?;
            }
        }
        Ok(())
    }
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }
    pub const fn original_fence(&self) -> &OwnershipFence {
        &self.original_fence
    }
    pub const fn metadata(&self) -> &ArtifactContentMetadata {
        &self.metadata
    }
    pub const fn object_generation(&self) -> ArtifactObjectGeneration {
        self.object_generation
    }
    pub const fn scan_verdict(&self) -> Option<ArtifactScanVerdict> {
        self.scan_verdict
    }
    pub const fn scan_attestation(&self) -> Option<&ArtifactScanAttestation> {
        self.scan_attestation.as_ref()
    }
    pub fn display_filename(&self) -> Option<&str> {
        self.display_filename.as_deref()
    }
    pub const fn published_at_unix_millis(&self) -> u64 {
        self.published_at_unix_millis
    }
    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.expires_at_unix_millis
    }
    pub const fn state(&self) -> ArtifactState {
        ArtifactState::Available
    }
}

struct ExpiringArtifactReader {
    inner: Box<dyn ArtifactReadStream>,
    clock: std::sync::Arc<dyn crate::WorkerClock>,
    publication: ArtifactPublication,
}
impl ArtifactReadStream for ExpiringArtifactReader {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, crate::DependencyError> {
        let now = self
            .clock
            .now()
            .map_err(|_| crate::DependencyError::Unavailable)?
            .get();
        if now < self.publication.published_at_unix_millis()
            || now >= self.publication.expires_at_unix_millis()
        {
            return Err(crate::DependencyError::Rejected);
        }
        let chunk = self.inner.next_chunk()?;
        let after = self
            .clock
            .now()
            .map_err(|_| crate::DependencyError::Unavailable)?
            .get();
        if after < self.publication.published_at_unix_millis()
            || after >= self.publication.expires_at_unix_millis()
        {
            return Err(crate::DependencyError::Rejected);
        }
        Ok(chunk)
    }
}
impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    pub(crate) fn validate_artifact_record_publication(
        &self,
        record: &crate::ArtifactRecord,
        fence: &OwnershipFence,
    ) -> Result<(), WorkerError> {
        if record.artifact.state() != ArtifactState::Available {
            return Ok(());
        }
        let publication = record
            .publication
            .as_ref()
            .ok_or(WorkerError::ArtifactNotFound)?;
        publication.validate()?;
        if publication.key() != record.artifact.key()
            || publication.original_fence() != fence
            || Some(publication.metadata()) != record.artifact.content_metadata()
            || publication.object_generation() != record.object_generation
            || publication.display_filename() != record.display_filename.as_deref()
        {
            return Err(WorkerError::StaleFence);
        }
        let now = self.clock.now()?.get();
        if now < publication.published_at_unix_millis()
            || now >= publication.expires_at_unix_millis()
        {
            return Err(WorkerError::ArtifactNotFound);
        }
        Ok(())
    }
    pub(crate) fn expiring_artifact_reader(
        &self,
        reader: Box<dyn ArtifactReadStream>,
        publication: &ArtifactPublication,
    ) -> Box<dyn ArtifactReadStream> {
        Box::new(ExpiringArtifactReader {
            inner: reader,
            clock: self.clock.clone(),
            publication: publication.clone(),
        })
    }
    /// Publication is called with the session authority mutex held. Production providers must
    /// bound I/O and must not call back into the control plane.
    pub(crate) fn publish_authorized_artifact(
        &self,
        publication: &ArtifactPublication,
    ) -> Result<(), WorkerError> {
        match self.sandbox.publish_artifact(publication) {
            Ok(()) => Ok(()),
            Err(_) => {
                // A lost reply is not evidence of non-publication. Only canonical exact equality
                // permits adopting a durable winner; all other outcomes keep cleanup conservative.
                match self
                    .sandbox
                    .get_retained_artifact(publication.key(), self.clock.now()?.get())
                {
                    Ok(Some(existing)) if existing == *publication => Ok(()),
                    _ => Err(WorkerError::DependencyUnavailable),
                }
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_artifact_publication(
        &self,
        key: ArtifactKey,
        fence: OwnershipFence,
        metadata: ArtifactContentMetadata,
        generation: ArtifactObjectGeneration,
        scan: Option<ArtifactScanVerdict>,
        name: Option<String>,
        scan_attestation: Option<ArtifactScanAttestation>,
    ) -> Result<ArtifactPublication, WorkerError> {
        let now = self.clock.now()?.get();
        ArtifactPublication::new_with_scan_attestation(
            key,
            fence,
            metadata,
            generation,
            scan,
            name,
            now,
            now.checked_add(ARTIFACT_PUBLICATION_TTL_MILLIS)
                .ok_or(WorkerError::StateUnavailable)?,
            scan_attestation,
        )
    }
    pub fn authorize_retained_artifact_scope(
        &self,
        peer: &AuthenticatedPeer,
        expected_worker_id: &WorkerId,
        expected_worker_epoch: u64,
    ) -> Result<u64, WorkerError> {
        self.authorize(peer)?;
        if expected_worker_id != &self.config.worker_id
            || expected_worker_epoch == 0
            || expected_worker_epoch != self.config.worker_epoch
        {
            return Err(WorkerError::StaleFence);
        }
        Ok(self.clock.now()?.get())
    }
    fn validate_retained_publication(
        &self,
        publication: &ArtifactPublication,
        tenant: &TenantId,
        session: &SessionId,
        now: u64,
    ) -> Result<(), WorkerError> {
        publication.validate()?;
        if publication.key().tenant_id() != tenant
            || publication.key().session_id() != session
            || publication.original_fence().worker_id() != &self.config.worker_id
            || publication.original_fence().worker_epoch() > self.config.worker_epoch
        {
            return Err(WorkerError::StaleFence);
        }
        if now < publication.published_at_unix_millis()
            || now >= publication.expires_at_unix_millis()
        {
            return Err(WorkerError::ArtifactNotFound);
        }
        Ok(())
    }
    pub fn get_retained_artifact(
        &self,
        peer: &AuthenticatedPeer,
        expected_worker_id: &WorkerId,
        expected_worker_epoch: u64,
        key: &ArtifactKey,
    ) -> Result<ArtifactPublication, WorkerError> {
        let now = self.authorize_retained_artifact_scope(
            peer,
            expected_worker_id,
            expected_worker_epoch,
        )?;
        let publication = self
            .sandbox
            .get_retained_artifact(key, now)
            .map_err(|_| WorkerError::DependencyUnavailable)?
            .ok_or(WorkerError::ArtifactNotFound)?;
        self.validate_retained_publication(&publication, key.tenant_id(), key.session_id(), now)?;
        if publication.key() != key {
            return Err(WorkerError::StaleFence);
        }
        Ok(publication)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn list_retained_artifacts(
        &self,
        peer: &AuthenticatedPeer,
        expected_worker_id: &WorkerId,
        expected_worker_epoch: u64,
        tenant: &TenantId,
        session: &SessionId,
        after: Option<&ArtifactId>,
        limit: usize,
    ) -> Result<Vec<ArtifactPublication>, WorkerError> {
        let now = self.authorize_retained_artifact_scope(
            peer,
            expected_worker_id,
            expected_worker_epoch,
        )?;
        if limit == 0 || limit > MAX_RETAINED_ARTIFACT_PAGE {
            return Err(WorkerError::InvalidConfiguration);
        }
        let publications = self
            .sandbox
            .list_retained_artifacts(tenant, session, after, limit, now)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        if publications.len() > limit {
            return Err(WorkerError::DependencyUnavailable);
        }
        let mut previous = after;
        for publication in &publications {
            self.validate_retained_publication(publication, tenant, session, now)?;
            if previous.is_some_and(|id| id >= publication.key().artifact_id()) {
                return Err(WorkerError::DependencyUnavailable);
            }
            previous = Some(publication.key().artifact_id());
        }
        Ok(publications)
    }
    pub fn open_retained_artifact(
        &self,
        peer: &AuthenticatedPeer,
        expected_worker_id: &WorkerId,
        expected_worker_epoch: u64,
        publication: &ArtifactPublication,
        max_chunk_bytes: usize,
    ) -> Result<Box<dyn ArtifactReadStream>, WorkerError> {
        let now = self.authorize_retained_artifact_scope(
            peer,
            expected_worker_id,
            expected_worker_epoch,
        )?;
        self.validate_retained_publication(
            publication,
            publication.key().tenant_id(),
            publication.key().session_id(),
            now,
        )?;
        let canonical = self.get_retained_artifact(
            peer,
            expected_worker_id,
            expected_worker_epoch,
            publication.key(),
        )?;
        if canonical != *publication {
            return Err(WorkerError::StaleFence);
        }
        let limits = ArtifactReadLimits::new(max_chunk_bytes)
            .map_err(|_| WorkerError::InvalidConfiguration)?;
        let reader = self
            .sandbox
            .open_retained_artifact(publication, limits, now)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        let after = self.authorize_retained_artifact_scope(
            peer,
            expected_worker_id,
            expected_worker_epoch,
        )?;
        self.validate_retained_publication(
            publication,
            publication.key().tenant_id(),
            publication.key().session_id(),
            after,
        )?;
        Ok(self.expiring_artifact_reader(reader, publication))
    }
}
