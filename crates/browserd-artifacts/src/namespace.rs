use std::fmt;

use browserd_core::{ArtifactId, SessionId, TenantId};

use crate::{ArtifactEvent, ArtifactState};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactNamespace {
    tenant_id: TenantId,
    session_id: SessionId,
}

impl ArtifactNamespace {
    #[must_use]
    pub const fn new(tenant_id: TenantId, session_id: SessionId) -> Self {
        Self {
            tenant_id,
            session_id,
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn authorize(&self, key: &ArtifactKey) -> Result<(), ArtifactError> {
        if self.tenant_id == key.tenant_id && self.session_id == key.session_id {
            Ok(())
        } else {
            Err(ArtifactError::NamespaceDenied)
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactKey {
    tenant_id: TenantId,
    session_id: SessionId,
    artifact_id: ArtifactId,
}

impl ArtifactKey {
    #[must_use]
    pub const fn new(tenant_id: TenantId, session_id: SessionId, artifact_id: ArtifactId) -> Self {
        Self {
            tenant_id,
            session_id,
            artifact_id,
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    #[must_use]
    pub fn namespace(&self) -> ArtifactNamespace {
        ArtifactNamespace::new(self.tenant_id.clone(), self.session_id.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    NamespaceDenied,
    InvalidMetadata,
    MetadataConflict,
    MetadataNotAllowed,
    MetadataRequired,
    MetadataSourceMismatch,
    InvalidTransition {
        from: ArtifactState,
        event: ArtifactEvent,
    },
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NamespaceDenied => formatter.write_str("artifact namespace access denied"),
            Self::InvalidMetadata => formatter.write_str("artifact metadata is invalid"),
            Self::MetadataConflict => {
                formatter.write_str("artifact metadata conflicts with the committed metadata")
            }
            Self::MetadataNotAllowed => {
                formatter.write_str("artifact metadata is not allowed for this transition")
            }
            Self::MetadataRequired => {
                formatter.write_str("artifact materialization metadata is required")
            }
            Self::MetadataSourceMismatch => {
                formatter.write_str("artifact metadata source does not match the artifact kind")
            }
            Self::InvalidTransition { from, event } => {
                write!(
                    formatter,
                    "invalid artifact transition from {from:?} via {event:?}"
                )
            }
        }
    }
}

impl std::error::Error for ArtifactError {}
