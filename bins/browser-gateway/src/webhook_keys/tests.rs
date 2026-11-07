#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::unix::fs::{PermissionsExt, symlink};

use super::*;

fn config(active: &str, entries: &[(&str, u8)]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "active_master_version_id": active,
        "keys": entries.iter().map(|(id, value)| serde_json::json!({
            "master_version_id": id,
            "key_base64": base64::engine::general_purpose::STANDARD.encode([*value; 32]),
        })).collect::<Vec<_>>(),
    }))
    .expect("fixture JSON")
}

#[test]
fn tenant_and_key_identity_separate_secrets_and_rotation_preserves_pending_keys() {
    let old = WebhookMasterKeyRing::parse(&config("old", &[("old", 17)])).unwrap();
    let rotated = WebhookMasterKeyRing::parse(&config("new", &[("old", 17), ("new", 29)])).unwrap();
    let tenant = TenantId::new();
    let other_tenant = TenantId::new();
    let reference = WebhookSigningKeyRef::new("old", uuid::Uuid::new_v4()).unwrap();
    let different_key = WebhookSigningKeyRef::new("old", uuid::Uuid::new_v4()).unwrap();
    let secret = old.derive(&tenant, &reference).unwrap();
    assert_eq!(
        secret.as_bytes(),
        rotated.derive(&tenant, &reference).unwrap().as_bytes()
    );
    assert_ne!(
        secret.as_bytes(),
        old.derive(&other_tenant, &reference).unwrap().as_bytes()
    );
    assert_ne!(
        secret.as_bytes(),
        old.derive(&tenant, &different_key).unwrap().as_bytes()
    );
    assert_eq!(rotated.active_master_version_id(), "new");
    let removed = WebhookMasterKeyRing::parse(&config("new", &[("new", 29)])).unwrap();
    assert!(matches!(
        removed.derive(&tenant, &reference),
        Err(WebhookKeyError::Unavailable)
    ));
    let debug = format!("{old:?} {secret:?}");
    assert!(!debug.contains(&base64::engine::general_purpose::STANDARD.encode([17; 32])));
    assert!(!debug.contains(&hex::encode(secret.as_bytes())));
}

#[test]
fn master_version_is_part_of_the_derivation_and_malformed_keyrings_are_rejected() {
    let keys =
        WebhookMasterKeyRing::parse(&config("first", &[("first", 7), ("second", 7)])).unwrap();
    let tenant = TenantId::new();
    let key_id = uuid::Uuid::new_v4();
    let first = WebhookSigningKeyRef::new("first", key_id).unwrap();
    let second = WebhookSigningKeyRef::new("second", key_id).unwrap();
    assert_ne!(
        keys.derive(&tenant, &first).unwrap().as_bytes(),
        keys.derive(&tenant, &second).unwrap().as_bytes()
    );
    for bytes in [
        config("missing", &[("present", 1)]),
        config("same", &[("same", 1), ("same", 2)]),
        config("", &[("", 1)]),
        config("current", &[]),
        b"{\"schema_version\":1,\"active_master_version_id\":\"current\",\"keys\":[],\"extra\":true}".to_vec(),
    ] {
        assert!(WebhookMasterKeyRing::parse(&bytes).is_err());
    }
    let mut short: serde_json::Value =
        serde_json::from_slice(&config("current", &[("current", 1)])).unwrap();
    short["keys"][0]["key_base64"] =
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode([1; 31]));
    assert!(WebhookMasterKeyRing::parse(&serde_json::to_vec(&short).unwrap()).is_err());
}

#[test]
fn operator_key_file_requires_private_pinned_regular_single_link_files() {
    assert!(load_webhook_signing_keys(None).unwrap().is_none());
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp.path().join("keys.json");
    std::fs::write(&path, config("current", &[("current", 1)])).unwrap();
    for mode in [0o600, 0o400] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(load_webhook_signing_keys(Some(&path)).unwrap().is_some());
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_webhook_signing_keys(Some(&path)).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = temp.path().join("link.json");
    symlink(&path, &link).unwrap();
    assert!(load_webhook_signing_keys(Some(&link)).is_err());
    let hard = temp.path().join("hard.json");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(load_webhook_signing_keys(Some(&path)).is_err());
    std::fs::remove_file(hard).unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(load_webhook_signing_keys(Some(&path)).is_err());
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(load_webhook_signing_keys(Some(Path::new("keys.json"))).is_err());
    std::fs::write(&path, vec![b' '; MAX_KEY_FILE_BYTES + 1]).unwrap();
    assert!(load_webhook_signing_keys(Some(&path)).is_err());
}
