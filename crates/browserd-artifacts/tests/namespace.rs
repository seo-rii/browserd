mod common;

use browserd_artifacts::{ArtifactError, ArtifactKey, ArtifactNamespace};
use browserd_core::{ArtifactId, SessionId, TenantId};

use common::artifact_fixture;

#[test]
fn artifact_key_is_authorized_only_in_its_tenant_and_session_namespace() {
    let fixture = artifact_fixture();

    assert_eq!(fixture.namespace.authorize(&fixture.key), Ok(()));

    let wrong_tenant =
        ArtifactNamespace::new(TenantId::new(), fixture.namespace.session_id().clone());
    let wrong_session =
        ArtifactNamespace::new(fixture.namespace.tenant_id().clone(), SessionId::new());

    assert_eq!(
        wrong_tenant.authorize(&fixture.key),
        Err(ArtifactError::NamespaceDenied)
    );
    assert_eq!(
        wrong_session.authorize(&fixture.key),
        Err(ArtifactError::NamespaceDenied)
    );
}

#[test]
fn tenant_or_session_mismatch_uses_the_same_non_enumerating_error() {
    let fixture = artifact_fixture();
    let alien_key = ArtifactKey::new(TenantId::new(), SessionId::new(), ArtifactId::new());

    assert_eq!(
        fixture.namespace.authorize(&alien_key),
        Err(ArtifactError::NamespaceDenied)
    );
}

#[test]
fn changing_only_the_artifact_id_keeps_the_key_inside_the_same_namespace() {
    let fixture = artifact_fixture();
    let sibling_key = ArtifactKey::new(
        fixture.namespace.tenant_id().clone(),
        fixture.namespace.session_id().clone(),
        ArtifactId::new(),
    );

    assert_eq!(fixture.namespace.authorize(&sibling_key), Ok(()));
}
