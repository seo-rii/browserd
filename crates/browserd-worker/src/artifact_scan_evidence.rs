//! Scanner observations and immutable byte/ownership-bound scan evidence.
use browserd_artifacts::{
    ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource, ArtifactKey,
    ArtifactObjectGeneration,
};
use browserd_core::{ArtifactId, SessionId, TenantId, WorkerId};
use browserd_session::OwnershipFence;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::WorkerError;

const MAX_SCAN_INTERVAL_MILLIS: u64 = 5 * 60 * 1000;
const MAX_DATABASE_AGE_MILLIS: u64 = 7 * 24 * 60 * 60 * 1000;
const DOMAIN: &[u8] = b"browserd.artifact.scan-attestation.v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactScannerObservation {
    pub schema_version: u8,
    /// Program version reported by the daemon's VERSION command.
    pub program_version: String,
    pub database_version: u64,
    pub database_built_at_unix_millis: u64,
    pub observed_before_unix_millis: u64,
    pub observed_after_unix_millis: u64,
    pub expected_peer_uid: u32,
    pub peer_uid: u32,
    pub version_metadata_sha256: [u8; 32],
    pub scanned_size_bytes: u64,
    pub scanned_checksum_sha256: [u8; 32],
    pub max_database_age_millis: u64,
    pub max_future_skew_millis: u64,
}
impl ArtifactScannerObservation {
    pub fn validate_at(&self, now: u64) -> Result<(), WorkerError> {
        if self.schema_version != 1
            || self.program_version.is_empty()
            || self.program_version.len() > 64
            || self.program_version.trim() != self.program_version
            || !self
                .program_version
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
            || self.database_version == 0
            || self.expected_peer_uid != self.peer_uid
            || self.version_metadata_sha256.iter().all(|b| *b == 0)
            || self.max_database_age_millis == 0
            || self.max_database_age_millis > MAX_DATABASE_AGE_MILLIS
            || self.max_future_skew_millis > MAX_SCAN_INTERVAL_MILLIS
            || self.observed_before_unix_millis > self.observed_after_unix_millis
            || self.observed_after_unix_millis - self.observed_before_unix_millis
                > MAX_SCAN_INTERVAL_MILLIS
            || now < self.observed_after_unix_millis
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        for instant in [
            self.observed_before_unix_millis,
            self.observed_after_unix_millis,
            now,
        ] {
            if self.database_built_at_unix_millis.saturating_sub(instant)
                > self.max_future_skew_millis
                || instant.saturating_sub(self.database_built_at_unix_millis)
                    > self.max_database_age_millis
            {
                return Err(WorkerError::InvalidConfiguration);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScanSource {
    ClientUpload,
    BrowserDownload,
}
impl ScanSource {
    fn from_source(source: ArtifactContentSource) -> Result<Self, WorkerError> {
        match source {
            ArtifactContentSource::ClientUpload => Ok(Self::ClientUpload),
            ArtifactContentSource::BrowserDownload => Ok(Self::BrowserDownload),
            ArtifactContentSource::Generated => Err(WorkerError::InvalidConfiguration),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactScanAttestation {
    schema_version: u8,
    tenant_id: TenantId,
    session_id: SessionId,
    artifact_id: ArtifactId,
    worker_id: WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
    source: ScanSource,
    object_generation: [u8; 32],
    size_bytes: u64,
    checksum_sha256: [u8; 32],
    observation: ArtifactScannerObservation,
    digest_sha256: [u8; 32],
}

// Struct serialization preserves this explicit field order, independent of map ordering.
#[derive(Serialize)]
struct DigestMaterial<'a> {
    schema_version: u8,
    tenant_id: &'a TenantId,
    session_id: &'a SessionId,
    artifact_id: &'a ArtifactId,
    worker_id: &'a WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
    source: ScanSource,
    object_generation: &'a [u8; 32],
    size_bytes: u64,
    checksum_sha256: &'a [u8; 32],
    observation: &'a ArtifactScannerObservation,
}
impl ArtifactScanAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: &ArtifactKey,
        fence: &OwnershipFence,
        source: ArtifactContentSource,
        generation: ArtifactObjectGeneration,
        size_bytes: u64,
        checksum: ArtifactChecksum,
        observation: ArtifactScannerObservation,
    ) -> Result<Self, WorkerError> {
        let mut evidence = Self {
            schema_version: 1,
            tenant_id: key.tenant_id().clone(),
            session_id: key.session_id().clone(),
            artifact_id: key.artifact_id().clone(),
            worker_id: fence.worker_id().clone(),
            worker_epoch: fence.worker_epoch(),
            placement_version: fence.placement_version(),
            session_incarnation: fence.session_incarnation(),
            source: ScanSource::from_source(source)?,
            object_generation: *generation.as_bytes(),
            size_bytes,
            checksum_sha256: *checksum.as_bytes(),
            observation,
            digest_sha256: [0; 32],
        };
        evidence.validate_material()?;
        evidence.digest_sha256 = evidence.compute_digest()?;
        Ok(evidence)
    }
    fn validate_material(&self) -> Result<(), WorkerError> {
        self.observation
            .validate_at(self.observation.observed_after_unix_millis)?;
        if self.schema_version != 1
            || self.tenant_id.as_uuid().is_nil()
            || self.session_id.as_uuid().is_nil()
            || self.artifact_id.as_uuid().is_nil()
            || self.worker_epoch == 0
            || self.placement_version == 0
            || self.session_incarnation == 0
            || self.object_generation.iter().all(|b| *b == 0)
            || self.observation.scanned_size_bytes != self.size_bytes
            || self.observation.scanned_checksum_sha256 != self.checksum_sha256
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(())
    }
    fn compute_digest(&self) -> Result<[u8; 32], WorkerError> {
        let encoded = serde_json::to_vec(&DigestMaterial {
            schema_version: self.schema_version,
            tenant_id: &self.tenant_id,
            session_id: &self.session_id,
            artifact_id: &self.artifact_id,
            worker_id: &self.worker_id,
            worker_epoch: self.worker_epoch,
            placement_version: self.placement_version,
            session_incarnation: self.session_incarnation,
            source: self.source,
            object_generation: &self.object_generation,
            size_bytes: self.size_bytes,
            checksum_sha256: &self.checksum_sha256,
            observation: &self.observation,
        })
        .map_err(|_| WorkerError::InvalidConfiguration)?;
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(encoded);
        Ok(digest.finalize().into())
    }
    fn validate(&self) -> Result<(), WorkerError> {
        self.validate_material()?;
        if self.compute_digest()? != self.digest_sha256 {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(())
    }
    pub fn validate_for(
        &self,
        key: &ArtifactKey,
        fence: &OwnershipFence,
        metadata: &ArtifactContentMetadata,
        generation: ArtifactObjectGeneration,
    ) -> Result<(), WorkerError> {
        self.validate_receipt(
            key,
            metadata.source(),
            generation,
            metadata.size_bytes(),
            *metadata.checksum(),
        )?;
        if &self.worker_id != fence.worker_id()
            || self.worker_epoch != fence.worker_epoch()
            || self.placement_version != fence.placement_version()
            || self.session_incarnation != fence.session_incarnation()
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(())
    }
    pub(crate) fn validate_receipt(
        &self,
        key: &ArtifactKey,
        source: ArtifactContentSource,
        generation: ArtifactObjectGeneration,
        size: u64,
        checksum: ArtifactChecksum,
    ) -> Result<(), WorkerError> {
        self.validate()?;
        if &self.tenant_id != key.tenant_id()
            || &self.session_id != key.session_id()
            || &self.artifact_id != key.artifact_id()
            || self.source != ScanSource::from_source(source)?
            || self.object_generation != *generation.as_bytes()
            || self.size_bytes != size
            || self.checksum_sha256 != *checksum.as_bytes()
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(())
    }
    pub fn validate_at(&self, now: u64) -> Result<(), WorkerError> {
        self.validate()?;
        self.observation.validate_at(now)
    }
    pub const fn observation(&self) -> &ArtifactScannerObservation {
        &self.observation
    }
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest_sha256
    }
}

#[cfg(test)]
pub(crate) fn attest_test_receipt(
    receipt: crate::ArtifactStoreReceipt,
    fence: &OwnershipFence,
    now: u64,
) -> Result<crate::ArtifactStoreReceipt, WorkerError> {
    if receipt.scan_verdict() != Some(crate::ArtifactScanVerdict::Clean)
        || receipt.source() == ArtifactContentSource::Generated
    {
        return Ok(receipt);
    }
    let evidence = ArtifactScanAttestation::new(
        receipt.key(),
        fence,
        receipt.source(),
        receipt.object_generation(),
        receipt.size_bytes(),
        *receipt.checksum(),
        ArtifactScannerObservation {
            schema_version: 1,
            program_version: "fixture-1".to_owned(),
            database_version: 1,
            database_built_at_unix_millis: now,
            observed_before_unix_millis: now,
            observed_after_unix_millis: now,
            expected_peer_uid: 1000,
            peer_uid: 1000,
            version_metadata_sha256: [1; 32],
            scanned_size_bytes: receipt.size_bytes(),
            scanned_checksum_sha256: *receipt.checksum().as_bytes(),
            max_database_age_millis: MAX_DATABASE_AGE_MILLIS,
            max_future_skew_millis: 0,
        },
    )?;
    receipt.with_scan_attestation(evidence)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        ArtifactPublication, ArtifactPublicationWire, ArtifactScanVerdict, ArtifactStoreReceipt,
    };

    fn fixture() -> (
        ArtifactKey,
        OwnershipFence,
        ArtifactContentMetadata,
        ArtifactObjectGeneration,
        ArtifactScannerObservation,
    ) {
        let key = ArtifactKey::new(TenantId::new(), SessionId::new(), ArtifactId::new());
        let fence = OwnershipFence::new(WorkerId::new("scan-worker").expect("worker ID"), 1, 2, 3);
        let metadata = ArtifactContentMetadata::new(
            4,
            ArtifactChecksum::new([5; 32]),
            "text/plain",
            ArtifactContentSource::ClientUpload,
            "browserd-worker-upload",
        )
        .expect("metadata");
        let observation = ArtifactScannerObservation {
            schema_version: 1,
            program_version: "1.5.1".to_owned(),
            database_version: 55,
            database_built_at_unix_millis: 900,
            observed_before_unix_millis: 1000,
            observed_after_unix_millis: 1010,
            expected_peer_uid: 1000,
            peer_uid: 1000,
            version_metadata_sha256: [7; 32],
            scanned_size_bytes: 4,
            scanned_checksum_sha256: [5; 32],
            max_database_age_millis: 1000,
            max_future_skew_millis: 10,
        };
        (
            key,
            fence,
            metadata,
            ArtifactObjectGeneration::new([6; 32]),
            observation,
        )
    }
    fn evidence(
        key: &ArtifactKey,
        fence: &OwnershipFence,
        metadata: &ArtifactContentMetadata,
        generation: ArtifactObjectGeneration,
        observation: ArtifactScannerObservation,
    ) -> ArtifactScanAttestation {
        ArtifactScanAttestation::new(
            key,
            fence,
            metadata.source(),
            generation,
            metadata.size_bytes(),
            *metadata.checksum(),
            observation,
        )
        .expect("valid evidence")
    }
    #[test]
    fn observation_freshness_has_exact_age_skew_and_interval_bounds() {
        let (_, _, _, _, mut o) = fixture();
        assert_eq!(o.validate_at(1900), Ok(()));
        assert!(o.validate_at(1901).is_err());
        assert!(o.validate_at(1009).is_err());
        o.database_built_at_unix_millis = 1010;
        assert_eq!(o.validate_at(1010), Ok(()));
        o.database_built_at_unix_millis = 1011;
        assert!(
            o.validate_at(1011).is_err(),
            "future skew checked before scan as well as afterward"
        );
        let (_, _, _, _, mut o) = fixture();
        o.max_database_age_millis = MAX_DATABASE_AGE_MILLIS;
        o.observed_after_unix_millis = o.observed_before_unix_millis + MAX_SCAN_INTERVAL_MILLIS;
        assert_eq!(o.validate_at(o.observed_after_unix_millis), Ok(()));
        o.observed_after_unix_millis += 1;
        assert!(o.validate_at(o.observed_after_unix_millis).is_err());
        o.observed_after_unix_millis = 999;
        assert!(o.validate_at(1010).is_err());
    }
    #[test]
    fn observation_rejects_untrusted_metadata_and_policy_bounds() {
        let (_, _, _, _, base) = fixture();
        for invalid in 0..10 {
            let mut o = base.clone();
            match invalid {
                0 => o.schema_version = 2,
                1 => o.program_version = String::new(),
                2 => o.program_version = "x".repeat(65),
                3 => o.program_version = "version\n".to_owned(),
                4 => o.database_version = 0,
                5 => o.peer_uid += 1,
                6 => o.version_metadata_sha256 = [0; 32],
                7 => o.max_database_age_millis = 0,
                8 => o.max_database_age_millis = MAX_DATABASE_AGE_MILLIS + 1,
                _ => o.max_future_skew_millis = MAX_SCAN_INTERVAL_MILLIS + 1,
            }
            assert!(
                o.validate_at(1010).is_err(),
                "invalid observation case {invalid}"
            );
        }
        let mut near_max = base;
        near_max.database_built_at_unix_millis = u64::MAX;
        near_max.observed_before_unix_millis = u64::MAX - 10;
        near_max.observed_after_unix_millis = u64::MAX;
        assert_eq!(
            near_max.validate_at(u64::MAX),
            Ok(()),
            "freshness uses no overflowing timestamp addition"
        );
    }
    #[test]
    fn evidence_rejects_every_immutable_context_mismatch_even_with_valid_digest() {
        let (key, fence, metadata, generation, o) = fixture();
        let original = evidence(&key, &fence, &metadata, generation, o);
        for field in 0..11 {
            let mut changed = original.clone();
            match field {
                0 => changed.tenant_id = TenantId::new(),
                1 => changed.session_id = SessionId::new(),
                2 => changed.artifact_id = ArtifactId::new(),
                3 => changed.worker_id = WorkerId::new("other-worker").expect("worker ID"),
                4 => changed.worker_epoch += 1,
                5 => changed.placement_version += 1,
                6 => changed.session_incarnation += 1,
                7 => changed.source = ScanSource::BrowserDownload,
                8 => changed.object_generation[0] ^= 1,
                9 => {
                    changed.size_bytes += 1;
                    changed.observation.scanned_size_bytes += 1;
                }
                _ => {
                    changed.checksum_sha256[0] ^= 1;
                    changed.observation.scanned_checksum_sha256[0] ^= 1;
                }
            }
            changed.digest_sha256 = changed
                .compute_digest()
                .expect("changed material should encode");
            assert!(
                changed
                    .validate_for(&key, &fence, &metadata, generation)
                    .is_err(),
                "field {field} must bind to requested object"
            );
        }
        let mut damaged = original;
        damaged.digest_sha256[0] ^= 1;
        assert!(
            damaged
                .validate_for(&key, &fence, &metadata, generation)
                .is_err()
        );
    }
    #[test]
    fn evidence_strict_serde_and_recomputed_digest_survive_roundtrip() {
        let (key, fence, metadata, generation, o) = fixture();
        let original = evidence(&key, &fence, &metadata, generation, o);
        let bytes = serde_json::to_vec(&original).expect("serialize evidence");
        let decoded: ArtifactScanAttestation =
            serde_json::from_slice(&bytes).expect("deserialize evidence");
        assert_eq!(decoded, original);
        assert_eq!(
            decoded.validate_for(&key, &fence, &metadata, generation),
            Ok(())
        );
        let mut value = serde_json::to_value(original).expect("evidence JSON");
        value["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ArtifactScanAttestation>(value.clone()).is_err());
        value.as_object_mut().expect("object").remove("extra");
        value["tenant_id"] = serde_json::json!("00000000-0000-0000-0000-000000000000");
        assert!(serde_json::from_value::<ArtifactScanAttestation>(value).is_err());
        let mut value = serde_json::to_value(decoded.observation()).expect("observation JSON");
        value["extra"] = serde_json::json!(0);
        assert!(serde_json::from_value::<ArtifactScannerObservation>(value).is_err());
    }
    #[test]
    fn scanned_publication_requires_exact_fresh_evidence_but_retained_reads_use_publication_time() {
        let (key, fence, metadata, generation, o) = fixture();
        assert!(
            ArtifactPublication::new(
                key.clone(),
                fence.clone(),
                metadata.clone(),
                generation,
                Some(ArtifactScanVerdict::Clean),
                None,
                1010,
                2010
            )
            .is_err()
        );
        let attestation = evidence(&key, &fence, &metadata, generation, o);
        let publication = ArtifactPublication::new_with_scan_attestation(
            key.clone(),
            fence.clone(),
            metadata.clone(),
            generation,
            Some(ArtifactScanVerdict::Clean),
            None,
            1010,
            2010,
            Some(attestation.clone()),
        )
        .expect("fresh publication");
        assert!(attestation.validate_at(2000).is_err());
        assert_eq!(
            publication.validate(),
            Ok(()),
            "later retention reads must not rescan immutable evidence"
        );
        let wire = ArtifactPublicationWire::from_publication(&publication);
        assert_eq!(
            wire.to_publication().expect("wire evidence should bind"),
            publication
        );
        let mut wrong = wire.clone();
        wrong.artifact.fence.worker_epoch += 1;
        assert!(wrong.to_publication().is_err());
        let mut old = wire;
        old.scan_attestation = None;
        assert!(old.to_publication().is_err());
        assert!(
            ArtifactPublication::new_with_scan_attestation(
                key,
                fence,
                metadata,
                generation,
                Some(ArtifactScanVerdict::Clean),
                None,
                1901,
                2010,
                Some(attestation)
            )
            .is_err()
        );
    }
    #[test]
    fn generated_publication_and_receipts_reject_scan_evidence() {
        let (key, fence, metadata, generation, o) = fixture();
        let attestation = evidence(&key, &fence, &metadata, generation, o);
        let generated = ArtifactContentMetadata::new(
            4,
            *metadata.checksum(),
            "text/plain",
            ArtifactContentSource::Generated,
            "browserd-capture",
        )
        .expect("generated metadata");
        assert!(
            ArtifactPublication::new(
                key.clone(),
                fence.clone(),
                generated.clone(),
                generation,
                None,
                None,
                1010,
                2010
            )
            .is_ok()
        );
        assert!(
            ArtifactPublication::new_with_scan_attestation(
                key.clone(),
                fence.clone(),
                generated,
                generation,
                None,
                None,
                1010,
                2010,
                Some(attestation.clone())
            )
            .is_err()
        );
        assert!(
            ArtifactStoreReceipt::new_generated(
                key.clone(),
                4,
                *metadata.checksum(),
                "text/plain",
                generation
            )
            .expect("generated receipt")
            .with_scan_attestation(attestation.clone())
            .is_err()
        );
        assert!(
            ArtifactStoreReceipt::new(
                key,
                5,
                *metadata.checksum(),
                "text/plain",
                generation,
                ArtifactScanVerdict::Clean
            )
            .expect("receipt")
            .with_scan_attestation(attestation)
            .is_err()
        );
    }
}
