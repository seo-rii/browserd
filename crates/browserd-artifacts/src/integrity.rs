use crate::ArtifactError;

/// SHA-256 digest of the exact byte stream committed for an artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactChecksum([u8; Self::LENGTH]);

impl ArtifactChecksum {
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArtifactContentSource {
    ClientUpload,
    BrowserDownload,
    Generated,
}

/// Immutable facts about the bytes behind an artifact reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactContentMetadata {
    size_bytes: u64,
    checksum: ArtifactChecksum,
    content_type: String,
    source: ArtifactContentSource,
    origin: String,
}

impl ArtifactContentMetadata {
    pub const MAX_CONTENT_TYPE_BYTES: usize = 255;
    pub const MAX_ORIGIN_BYTES: usize = 2_048;

    pub fn new(
        size_bytes: u64,
        checksum: ArtifactChecksum,
        content_type: impl Into<String>,
        source: ArtifactContentSource,
        origin: impl Into<String>,
    ) -> Result<Self, ArtifactError> {
        let content_type = content_type.into();
        let origin = origin.into();
        if content_type.is_empty()
            || content_type.len() > Self::MAX_CONTENT_TYPE_BYTES
            || content_type.trim() != content_type
            || content_type.chars().any(char::is_control)
            || origin.is_empty()
            || origin.len() > Self::MAX_ORIGIN_BYTES
            || origin.trim() != origin
            || origin.chars().any(char::is_control)
        {
            return Err(ArtifactError::InvalidMetadata);
        }

        Ok(Self {
            size_bytes,
            checksum,
            content_type,
            source,
            origin,
        })
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub const fn checksum(&self) -> &ArtifactChecksum {
        &self.checksum
    }

    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    #[must_use]
    pub const fn source(&self) -> ArtifactContentSource {
        self.source
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}
