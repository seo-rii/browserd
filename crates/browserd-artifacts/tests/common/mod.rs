#![allow(dead_code)]

use browserd_artifacts::{ArtifactKey, ArtifactNamespace};
use browserd_core::{ArtifactId, SessionId, TenantId};

pub struct ArtifactFixture {
    pub namespace: ArtifactNamespace,
    pub key: ArtifactKey,
}

pub fn artifact_fixture() -> ArtifactFixture {
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();

    ArtifactFixture {
        namespace: ArtifactNamespace::new(tenant_id.clone(), session_id.clone()),
        key: ArtifactKey::new(tenant_id, session_id, ArtifactId::new()),
    }
}

pub fn artifact_key(namespace: &ArtifactNamespace) -> ArtifactKey {
    ArtifactKey::new(
        namespace.tenant_id().clone(),
        namespace.session_id().clone(),
        ArtifactId::new(),
    )
}
