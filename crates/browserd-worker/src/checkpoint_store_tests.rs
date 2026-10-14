#![allow(clippy::expect_used)]

use super::*;
use browserd_chromium::Sha256Digest;
use nix::unistd::mkfifo;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::Arc;

const SECRET_VALUE: &str = "checkpoint-secret-value-never-public-한글";
const STORAGE_VALUE: &str = "checkpoint-local-storage-secret";

fn private_write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("private file");
}

fn identity() -> ChromiumArtifactIdentity {
    let digest = Sha256Digest::from_hex(&"11".repeat(32)).expect("digest");
    ChromiumArtifactIdentity {
        binary_digest: digest,
        product_version: "Chrome/143.0.0.0".to_owned(),
        chromium_revision: "checkpoint-test-revision".to_owned(),
        browser_protocol_schema_digest: digest,
        js_protocol_schema_digest: digest,
        launch_profile_digest: digest,
        extension_bundle_digest: digest,
        font_bundle_digest: digest,
        certificate_runtime_bundle_digest: digest,
    }
}

fn snapshot() -> CheckpointSnapshot {
    CheckpointSnapshot {
        artifact_identity: identity(),
        cookies: vec![
            CheckpointCookie {
                name: "login".to_owned(),
                value: SECRET_VALUE.to_owned(),
                domain: ".example.test".to_owned(),
                path: "/private".to_owned(),
                expires: Some(2_000_000_000.5),
                http_only: true,
                secure: true,
                same_site: Some("Strict".to_owned()),
                priority: "High".to_owned(),
                source_scheme: "Secure".to_owned(),
                source_port: 8443,
            },
            CheckpointCookie {
                name: "session".to_owned(),
                value: "session-value".to_owned(),
                domain: "example.test".to_owned(),
                path: "/".to_owned(),
                expires: None,
                http_only: false,
                secure: false,
                same_site: None,
                priority: "Medium".to_owned(),
                source_scheme: "NonSecure".to_owned(),
                source_port: 80,
            },
        ],
        origins: vec![CheckpointOriginStorage {
            origin: "https://example.test:8443".to_owned(),
            local_storage: vec![CheckpointStorageEntry {
                name: "credential".to_owned(),
                value: STORAGE_VALUE.to_owned(),
            }],
        }],
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

struct Fixture {
    directory: tempfile::TempDir,
    tenant: TenantId,
    session: SessionId,
    fence: OwnershipFence,
    action: ActionId,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let root = directory.path().join("checkpoints");
        std::fs::create_dir(&root).expect("store directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("store mode");
        private_write(&directory.path().join("key"), &[0x42; 32]);
        Self {
            directory,
            tenant: TenantId::new(),
            session: SessionId::new(),
            fence: OwnershipFence::new(
                WorkerId::new("checkpoint-worker").expect("worker"),
                1,
                1,
                1,
            ),
            action: ActionId::new(),
        }
    }

    fn root(&self) -> PathBuf {
        self.directory.path().join("checkpoints")
    }
    fn key(&self) -> PathBuf {
        self.directory.path().join("key")
    }
    fn store(&self) -> FileCheckpointStore {
        FileCheckpointStore::open(&self.root(), &self.key()).expect("store")
    }
    fn save(&self, store: &FileCheckpointStore, now: u64) -> CheckpointRestoreReceipt {
        store
            .save(
                &self.tenant,
                &self.session,
                &self.fence,
                &self.action,
                snapshot(),
                now,
                deadline(),
            )
            .expect("save checkpoint")
    }
    fn record(&self, receipt: &CheckpointRestoreReceipt) -> PathBuf {
        self.root().join(record_name(&receipt.checkpoint_ref))
    }
}

#[test]
fn roundtrip_preserves_supported_state_and_disk_and_debug_are_redacted() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let receipt = fixture.save(&store, 100);
    canonical_ref(&receipt.checkpoint_ref).expect("canonical opaque ref");
    let disk = std::fs::read(fixture.record(&receipt)).expect("encrypted file");
    assert!(disk.len() <= MAX_CHECKPOINT_FILE_BYTES);
    for value in [
        SECRET_VALUE,
        STORAGE_VALUE,
        "session-value",
        "credential",
        "login",
    ] {
        assert!(
            !disk
                .windows(value.len())
                .any(|bytes| bytes == value.as_bytes())
        );
    }
    let loaded = store
        .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
        .expect("load");
    assert_eq!(loaded.receipt, receipt);
    assert_eq!(loaded.snapshot.artifact_identity, identity());
    assert_eq!(loaded.snapshot.cookies[0].value, SECRET_VALUE);
    assert_eq!(loaded.snapshot.cookies[0].domain, ".example.test");
    assert_eq!(loaded.snapshot.cookies[0].source_port, 8443);
    assert_eq!(loaded.snapshot.cookies[0].expires, Some(2_000_000_000.5));
    assert_eq!(loaded.snapshot.cookies[1].expires, None);
    assert_eq!(
        loaded.snapshot.origins[0].origin,
        "https://example.test:8443"
    );
    assert_eq!(
        loaded.snapshot.origins[0].local_storage[0].value,
        STORAGE_VALUE
    );
    let debug = format!(
        "{store:?} {loaded:?} {:?} {:?} {:?}",
        loaded.snapshot.cookies[0],
        loaded.snapshot.origins[0],
        loaded.snapshot.origins[0].local_storage[0]
    );
    assert!(!debug.contains(SECRET_VALUE) && !debug.contains(STORAGE_VALUE));
    assert!(debug.contains("[REDACTED]"));
    assert_eq!(
        std::fs::metadata(fixture.record(&receipt))
            .expect("file mode")
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn cross_tenant_and_noncanonical_refs_are_rejected_before_loading_state() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let receipt = fixture.save(&store, 100);
    assert_eq!(
        store
            .load(&TenantId::new(), &receipt.checkpoint_ref, 101, deadline())
            .err(),
        Some(CheckpointError::Rejected)
    );
    for checkpoint_ref in [
        "../key".to_owned(),
        receipt.checkpoint_ref.to_uppercase(),
        Uuid::now_v7().to_string(),
        receipt.checkpoint_ref.replace('-', ""),
        "".to_owned(),
    ] {
        assert_eq!(
            store
                .load(&fixture.tenant, &checkpoint_ref, 101, deadline())
                .err(),
            Some(CheckpointError::Rejected)
        );
    }
}

#[test]
fn restart_recovers_authenticated_metadata_and_dedupes_exact_action_and_fence() {
    let fixture = Fixture::new();
    let receipt = {
        let store = fixture.store();
        fixture.save(&store, 100)
    };
    let store = fixture.store();
    let mut changed_snapshot = snapshot();
    changed_snapshot.cookies[0].value = "later-value-must-not-overwrite".to_owned();
    let replay = store
        .save(
            &fixture.tenant,
            &fixture.session,
            &fixture.fence,
            &fixture.action,
            changed_snapshot,
            101,
            deadline(),
        )
        .expect("deduplicated receipt");
    assert_eq!(replay, receipt);
    assert_eq!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
            .expect("original state")
            .snapshot
            .cookies[0]
            .value,
        SECRET_VALUE
    );
    let new_fence = OwnershipFence::new(fixture.fence.worker_id().clone(), 1, 1, 2);
    let next = store
        .save(
            &fixture.tenant,
            &fixture.session,
            &new_fence,
            &fixture.action,
            snapshot(),
            101,
            deadline(),
        )
        .expect("new incarnation is a distinct capture");
    assert_ne!(next.checkpoint_ref, receipt.checkpoint_ref);
    assert_eq!(std::fs::read_dir(fixture.root()).expect("files").count(), 2);
}

#[test]
fn exact_action_cannot_rebind_its_chromium_identity_or_invalid_fence() {
    let fixture = Fixture::new();
    let store = fixture.store();
    fixture.save(&store, 100);
    let mut changed = snapshot();
    changed
        .artifact_identity
        .chromium_revision
        .push_str("-changed");
    assert_eq!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &fixture.action,
                changed,
                101,
                deadline()
            )
            .err(),
        Some(CheckpointError::Rejected)
    );
    let zero_fence = OwnershipFence::new(fixture.fence.worker_id().clone(), 0, 1, 1);
    assert_eq!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &zero_fence,
                &ActionId::new(),
                snapshot(),
                101,
                deadline()
            )
            .err(),
        Some(CheckpointError::Rejected)
    );
}

#[test]
fn root_key_permissions_symlinks_hardlinks_fifo_and_key_size_fail_closed() {
    let fixture = Fixture::new();
    std::fs::set_permissions(fixture.root(), std::fs::Permissions::from_mode(0o750)).expect("mode");
    assert_eq!(
        FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
        Some(CheckpointError::Rejected)
    );
    std::fs::set_permissions(fixture.root(), std::fs::Permissions::from_mode(0o700)).expect("mode");
    std::fs::set_permissions(fixture.key(), std::fs::Permissions::from_mode(0o640)).expect("mode");
    assert_eq!(
        FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
        Some(CheckpointError::Rejected)
    );
    std::fs::set_permissions(fixture.key(), std::fs::Permissions::from_mode(0o600)).expect("mode");
    let link = fixture.directory.path().join("key-link");
    symlink(fixture.key(), &link).expect("symlink");
    assert!(FileCheckpointStore::open(&fixture.root(), &link).is_err());
    std::fs::remove_file(&link).expect("remove symlink");
    std::fs::hard_link(fixture.key(), &link).expect("hardlink");
    assert_eq!(
        FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
        Some(CheckpointError::Rejected)
    );
    std::fs::remove_file(&link).expect("remove hardlink");
    std::fs::remove_file(fixture.key()).expect("remove key");
    mkfifo(&fixture.key(), Mode::from_bits_truncate(0o600)).expect("fifo");
    assert_eq!(
        FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
        Some(CheckpointError::Rejected)
    );
    std::fs::remove_file(fixture.key()).expect("remove fifo");
    private_write(&fixture.key(), &[0x42; 31]);
    assert_eq!(
        FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
        Some(CheckpointError::Rejected)
    );
    private_write(&fixture.key(), &[0x42; 33]);
    assert_eq!(
        FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
        Some(CheckpointError::Rejected)
    );
    let root_link = fixture.directory.path().join("root-link");
    symlink(fixture.root(), &root_link).expect("root symlink");
    assert_eq!(
        FileCheckpointStore::open(&root_link, &fixture.key()).err(),
        Some(CheckpointError::Rejected)
    );
}

#[test]
fn pinned_root_survives_path_replacement_and_second_store_cannot_race_it() {
    let fixture = Fixture::new();
    let store = fixture.store();
    assert_eq!(
        FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
        Some(CheckpointError::Unavailable)
    );
    let moved = fixture.directory.path().join("pinned-original");
    std::fs::rename(fixture.root(), &moved).expect("move pinned directory");
    std::fs::create_dir(fixture.root()).expect("replacement directory");
    std::fs::set_permissions(fixture.root(), std::fs::Permissions::from_mode(0o700))
        .expect("private replacement");
    let receipt = fixture.save(&store, 100);
    assert!(moved.join(record_name(&receipt.checkpoint_ref)).exists());
    assert_eq!(
        std::fs::read_dir(fixture.root())
            .expect("replacement files")
            .count(),
        0
    );
    assert!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
            .is_ok()
    );
}

#[test]
fn every_authority_metadata_field_is_authenticated_on_restart() {
    let mutations: Vec<(&str, serde_json::Value)> = vec![
        ("tenant_id", serde_json::json!(TenantId::new())),
        ("source_session_id", serde_json::json!(SessionId::new())),
        ("action_id", serde_json::json!(ActionId::new())),
        ("schema_version", serde_json::json!(2)),
        ("created_unix_ms", serde_json::json!(101)),
        (
            "expires_unix_ms",
            serde_json::json!(100 + MAX_RETENTION_MS - 1),
        ),
        (
            "fence",
            serde_json::json!({"worker_id":"checkpoint-worker","worker_epoch":2,
            "placement_version":1,"session_incarnation":1}),
        ),
        (
            "artifact_identity",
            serde_json::json!({"product_version":"Chrome/changed"}),
        ),
    ];
    for (field, value) in mutations {
        let fixture = Fixture::new();
        let receipt = {
            let store = fixture.store();
            fixture.save(&store, 100)
        };
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture.record(&receipt)).expect("record"))
                .expect("envelope");
        envelope["metadata"][field] = value;
        private_write(
            &fixture.record(&receipt),
            &serde_json::to_vec(&envelope).expect("tampered envelope"),
        );
        assert_eq!(
            FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
            Some(CheckpointError::Rejected)
        );
    }
}

#[test]
fn ciphertext_nonce_ref_and_envelope_schema_tampering_are_rejected() {
    for field in ["ciphertext", "nonce", "checkpoint_ref", "extra"] {
        let fixture = Fixture::new();
        let receipt = {
            let store = fixture.store();
            fixture.save(&store, 100)
        };
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture.record(&receipt)).expect("record"))
                .expect("envelope");
        match field {
            "ciphertext" => {
                let mut bytes = STANDARD
                    .decode(envelope["ciphertext"].as_str().expect("ciphertext"))
                    .expect("base64");
                bytes[0] ^= 1;
                envelope["ciphertext"] = serde_json::json!(STANDARD.encode(bytes));
            }
            "nonce" => envelope["nonce"] = serde_json::json!(STANDARD.encode([0u8; NONCE_LEN])),
            "checkpoint_ref" => {
                envelope["metadata"]["checkpoint_ref"] =
                    serde_json::json!(Uuid::new_v4().to_string())
            }
            _ => envelope["extra"] = serde_json::json!(true),
        }
        private_write(
            &fixture.record(&receipt),
            &serde_json::to_vec(&envelope).expect("tampered envelope"),
        );
        assert_eq!(
            FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
            Some(CheckpointError::Rejected)
        );
    }
}

#[test]
fn replacement_file_is_neither_loaded_nor_deleted_using_old_identity() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let receipt = fixture.save(&store, 100);
    let replacement = fixture.root().join("replacement");
    private_write(
        &replacement,
        &std::fs::read(fixture.record(&receipt)).expect("encrypted state"),
    );
    std::fs::rename(&replacement, fixture.record(&receipt)).expect("replace inode");
    assert_eq!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
            .err(),
        Some(CheckpointError::Rejected)
    );
    assert_eq!(
        store
            .discard(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &fixture.action,
                &receipt.checkpoint_ref
            )
            .err(),
        Some(CheckpointError::Rejected)
    );
    assert!(fixture.record(&receipt).exists());
}

#[test]
fn expiry_cleanup_releases_quota_and_source_liveness_is_not_required() {
    let fixture = Fixture::new();
    let limits = CheckpointStoreLimits {
        max_records: 1,
        max_bytes: MAX_STORE_BYTES,
        retention_ms: 1000,
    };
    let store = FileCheckpointStore::open_with_limits(&fixture.root(), &fixture.key(), limits)
        .expect("store");
    let receipt = fixture.save(&store, 100);
    assert!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 1099, deadline())
            .is_ok()
    );
    assert_eq!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 1100, deadline())
            .err(),
        Some(CheckpointError::Rejected)
    );
    assert_eq!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &ActionId::new(),
                snapshot(),
                1100,
                deadline()
            )
            .err(),
        Some(CheckpointError::Rejected)
    );
    assert_eq!(store.cleanup_expired(1099).expect("not yet expired"), 0);
    assert_eq!(store.cleanup_expired(1100).expect("expiry cleanup"), 1);
    assert_eq!(
        store
            .cleanup_expired(1100)
            .expect("idempotent expiry cleanup"),
        0
    );
    assert!(!fixture.record(&receipt).exists());
    assert!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &ActionId::new(),
                snapshot(),
                1100,
                deadline()
            )
            .is_ok()
    );
}

#[test]
fn rollback_requires_exact_tenant_source_session_full_fence_action_and_ref() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let receipt = fixture.save(&store, 100);
    let changed_fence = OwnershipFence::new(fixture.fence.worker_id().clone(), 2, 1, 1);
    for result in [
        store.discard(
            &TenantId::new(),
            &fixture.session,
            &fixture.fence,
            &fixture.action,
            &receipt.checkpoint_ref,
        ),
        store.discard(
            &fixture.tenant,
            &SessionId::new(),
            &fixture.fence,
            &fixture.action,
            &receipt.checkpoint_ref,
        ),
        store.discard(
            &fixture.tenant,
            &fixture.session,
            &changed_fence,
            &fixture.action,
            &receipt.checkpoint_ref,
        ),
        store.discard(
            &fixture.tenant,
            &fixture.session,
            &fixture.fence,
            &ActionId::new(),
            &receipt.checkpoint_ref,
        ),
    ] {
        assert_eq!(result, Err(CheckpointError::Rejected));
    }
    assert!(fixture.record(&receipt).exists());
    store
        .discard(
            &fixture.tenant,
            &fixture.session,
            &fixture.fence,
            &fixture.action,
            &receipt.checkpoint_ref,
        )
        .expect("exact rollback");
    store
        .discard(
            &fixture.tenant,
            &fixture.session,
            &fixture.fence,
            &fixture.action,
            &receipt.checkpoint_ref,
        )
        .expect("rollback idempotency");
    assert!(!fixture.record(&receipt).exists());
}

#[test]
fn rollback_waits_out_a_concurrent_store_operation_instead_of_failing() {
    let fixture = Arc::new(Fixture::new());
    let limits = CheckpointStoreLimits {
        max_records: 1,
        max_bytes: MAX_STORE_BYTES,
        retention_ms: 1000,
    };
    let store = Arc::new(
        FileCheckpointStore::open_with_limits(&fixture.root(), &fixture.key(), limits)
            .expect("store"),
    );
    let receipt = fixture.save(&store, 100);
    // Another save, load or expiry sweep owns the store state while the rollback starts.
    let held = store.state.lock().expect("hold store state");
    let (started, entered) = std::sync::mpsc::channel();
    let rollback = {
        let fixture = fixture.clone();
        let store = store.clone();
        let reference = receipt.checkpoint_ref.clone();
        std::thread::spawn(move || {
            started.send(()).expect("rollback started");
            store.discard(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &fixture.action,
                &reference,
            )
        })
    };
    entered.recv().expect("rollback thread");
    std::thread::sleep(Duration::from_millis(50));
    assert!(!rollback.is_finished());
    drop(held);
    assert_eq!(rollback.join().expect("rollback result"), Ok(()));
    assert!(!fixture.record(&receipt).exists());
    // The rolled-back record released its quota, so the store admits the next checkpoint.
    assert!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &ActionId::new(),
                snapshot(),
                200,
                deadline()
            )
            .is_ok()
    );
}

#[test]
fn quotas_invalid_limits_and_unrelated_entries_fail_closed() {
    let fixture = Fixture::new();
    let store = FileCheckpointStore::open_with_limits(
        &fixture.root(),
        &fixture.key(),
        CheckpointStoreLimits {
            max_bytes: 1,
            ..CheckpointStoreLimits::default()
        },
    )
    .expect("tiny store");
    assert_eq!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &fixture.action,
                snapshot(),
                100,
                deadline()
            )
            .err(),
        Some(CheckpointError::Rejected)
    );
    assert_eq!(
        std::fs::read_dir(fixture.root())
            .expect("no writes")
            .count(),
        0
    );
    drop(store);
    assert_eq!(
        FileCheckpointStore::open_with_limits(
            &fixture.root(),
            &fixture.key(),
            CheckpointStoreLimits {
                max_records: MAX_RECORDS + 1,
                ..CheckpointStoreLimits::default()
            }
        )
        .err(),
        Some(CheckpointError::Rejected)
    );
    private_write(&fixture.root().join("unrelated"), b"unrelated data");
    assert_eq!(
        FileCheckpointStore::open(&fixture.root(), &fixture.key()).err(),
        Some(CheckpointError::Rejected)
    );
}

#[test]
fn encrypted_partial_pending_recovery_is_read_only_bounded_and_retained() {
    let fixture = Fixture::new();
    let name = format!(".checkpoint-{}.pending", Uuid::new_v4());
    let pending = fixture.root().join(&name);
    private_write(&pending, b"partial encrypted envelope");
    let created = modified_unix_ms(&std::fs::metadata(&pending).expect("pending metadata"))
        .expect("created time");
    let store = FileCheckpointStore::open_with_limits(
        &fixture.root(),
        &fixture.key(),
        CheckpointStoreLimits {
            max_records: 1,
            max_bytes: MAX_STORE_BYTES,
            retention_ms: 1000,
        },
    )
    .expect("recovered orphan");
    assert!(pending.exists());
    assert_eq!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &fixture.action,
                snapshot(),
                created,
                deadline()
            )
            .err(),
        Some(CheckpointError::Rejected)
    );
    assert_eq!(
        store.cleanup_expired(created + 999).expect("retain orphan"),
        0
    );
    assert_eq!(
        store
            .cleanup_expired(created + 1000)
            .expect("delete expired orphan"),
        1
    );
    assert!(!pending.exists());
}

#[test]
fn failed_pending_metadata_keeps_reservation_and_closes_write_admission() {
    let fixture = Fixture::new();
    let store = FileCheckpointStore::open_with_limits(
        &fixture.root(),
        &fixture.key(),
        CheckpointStoreLimits {
            max_records: 2,
            ..CheckpointStoreLimits::default()
        },
    )
    .expect("store");
    store
        .fail_pending_sync
        .store(true, std::sync::atomic::Ordering::SeqCst);
    store
        .fail_pending_retention_metadata
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &fixture.action,
                snapshot(),
                100,
                deadline()
            )
            .err(),
        Some(CheckpointError::Unavailable)
    );
    let entries: Vec<_> = std::fs::read_dir(fixture.root())
        .expect("retained encrypted staging")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(entries.len(), 1);
    let disk_bytes = std::fs::metadata(&entries[0])
        .expect("orphan metadata")
        .len();
    assert!(disk_bytes > 0);
    let state = store.state.lock().expect("reservation");
    assert!(state.admission_blocked);
    assert_eq!(state.pending.len(), 1);
    assert!(state.bytes >= disk_bytes);
    assert!(
        state
            .pending
            .values()
            .all(|pending| pending.identity.is_none())
    );
    drop(state);
    // Capacity for another record remains, but unidentified orphan creation closes
    // admission rather than repeatedly creating files outside the tracked quota.
    for _ in 0..3 {
        assert_eq!(
            store
                .save(
                    &fixture.tenant,
                    &fixture.session,
                    &fixture.fence,
                    &ActionId::new(),
                    snapshot(),
                    100,
                    deadline()
                )
                .err(),
            Some(CheckpointError::Unavailable)
        );
    }
    assert_eq!(
        std::fs::read_dir(fixture.root())
            .expect("still one orphan")
            .count(),
        1
    );
    drop(store);
    let recovered = fixture.store();
    assert_eq!(
        recovered
            .state
            .lock()
            .expect("recovered bounded orphan")
            .pending
            .len(),
        1
    );
}

#[test]
fn rename_completed_then_error_adopts_exact_final_and_retry_never_duplicates() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store
        .fail_rename_after_effect
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let receipt = fixture.save(&store, 100);
    assert!(fixture.record(&receipt).exists());
    let state = store.state.lock().expect("adopted publication");
    assert_eq!(state.records.len(), 1);
    assert!(state.pending.is_empty());
    assert!(!state.admission_blocked);
    assert_eq!(
        state.bytes,
        std::fs::metadata(fixture.record(&receipt))
            .expect("file size")
            .len()
    );
    drop(state);
    let repeated = fixture.save(&store, 101);
    assert_eq!(repeated, receipt);
    assert_eq!(
        std::fs::read_dir(fixture.root())
            .expect("one final")
            .count(),
        1
    );
    assert_eq!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
            .expect("authenticated final")
            .snapshot
            .cookies[0]
            .value,
        SECRET_VALUE
    );
}

#[test]
fn deadline_before_dispatch_prevents_any_publication_and_load() {
    let fixture = Fixture::new();
    let store = fixture.store();
    assert_eq!(
        store
            .save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &fixture.action,
                snapshot(),
                100,
                Instant::now()
            )
            .err(),
        Some(CheckpointError::DeadlineBeforeDispatch)
    );
    assert_eq!(
        std::fs::read_dir(fixture.root()).expect("no files").count(),
        0
    );
    let receipt = fixture.save(&store, 100);
    assert_eq!(
        store
            .load(
                &fixture.tenant,
                &receipt.checkpoint_ref,
                101,
                Instant::now()
            )
            .err(),
        Some(CheckpointError::DeadlineBeforeDispatch)
    );
}

#[test]
fn validation_enforces_canonical_origins_ports_duplicates_and_supported_cookie_schema() {
    let valid = snapshot();
    valid.validate().expect("valid snapshot");
    for origin in [
        "https://EXAMPLE.test:8443",
        "https://example.test:443",
        "https://example.test/path",
        "https://user@example.test",
        "data:text/plain,x",
        "https://example.test/",
    ] {
        let mut state = snapshot();
        state.origins[0].origin = origin.to_owned();
        assert_eq!(state.validate(), Err(CheckpointError::Rejected));
    }
    let mut duplicate = snapshot();
    duplicate.origins.push(CheckpointOriginStorage {
        origin: duplicate.origins[0].origin.clone(),
        local_storage: vec![],
    });
    assert_eq!(duplicate.validate(), Err(CheckpointError::Rejected));
    let mut duplicate = snapshot();
    duplicate.origins[0]
        .local_storage
        .push(CheckpointStorageEntry {
            name: "credential".to_owned(),
            value: String::new(),
        });
    assert_eq!(duplicate.validate(), Err(CheckpointError::Rejected));
    let mut schema = serde_json::to_value(snapshot()).expect("fixture schema");
    schema["cookies"][0]["partitionKey"] =
        serde_json::json!({"topLevelSite":"https://example.test"});
    assert!(serde_json::from_value::<CheckpointSnapshot>(schema).is_err());
    let mut invalid = snapshot();
    invalid.cookies[0].expires = Some(f64::NAN);
    assert_eq!(invalid.validate(), Err(CheckpointError::Rejected));
    let mut invalid = snapshot();
    invalid.cookies[0].source_port = 0;
    assert_eq!(invalid.validate(), Err(CheckpointError::Rejected));
}

#[test]
fn state_limit_counts_json_escaping_and_writers_never_grow_secret_allocation() {
    let mut state = snapshot();
    state.origins[0].local_storage[0].value = "\0".repeat(6000);
    assert!(state.origins[0].local_storage[0].value.len() < MAX_STORAGE_VALUE_BYTES);
    assert_eq!(state.validate(), Err(CheckpointError::Rejected));
    let mut aggregate = snapshot();
    aggregate.origins[0].local_storage = (0..3)
        .map(|index| CheckpointStorageEntry {
            name: format!("entry-{index}"),
            value: "x".repeat(12 * 1024),
        })
        .collect();
    assert_eq!(aggregate.validate(), Err(CheckpointError::Rejected));
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        MAX_CHECKPOINT_STATE_BYTES + STATE_TAG_BYTES,
    ));
    let initial_capacity = bytes.capacity();
    let mut writer = StateWriter { bytes: &mut bytes };
    writer
        .write_all(&vec![b'x'; MAX_CHECKPOINT_STATE_BYTES])
        .expect("exact bound");
    assert!(writer.write_all(b"x").is_err());
    assert_eq!(bytes.len(), MAX_CHECKPOINT_STATE_BYTES);
    assert_eq!(bytes.capacity(), initial_capacity);
}

#[test]
fn record_permissions_hardlinks_and_file_bounds_are_checked_after_open() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let receipt = fixture.save(&store, 100);
    std::fs::set_permissions(
        fixture.record(&receipt),
        std::fs::Permissions::from_mode(0o640),
    )
    .expect("bad permissions");
    assert_eq!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
            .err(),
        Some(CheckpointError::Rejected)
    );
    std::fs::set_permissions(
        fixture.record(&receipt),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("private permissions");
    let link = fixture.directory.path().join("hardlinked-record");
    std::fs::hard_link(fixture.record(&receipt), &link).expect("record hardlink");
    assert_eq!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
            .err(),
        Some(CheckpointError::Rejected)
    );
    std::fs::remove_file(link).expect("remove hardlink");
    private_write(
        &fixture.record(&receipt),
        &vec![b'x'; MAX_CHECKPOINT_FILE_BYTES + 1],
    );
    assert_eq!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
            .err(),
        Some(CheckpointError::Rejected)
    );
}

#[test]
fn startup_and_retention_authenticate_without_deserializing_plaintext_state() {
    let fixture = Fixture::new();
    let receipt = {
        let store = fixture.store();
        fixture.save(&store, 100)
    };
    let envelope: CheckpointEnvelope =
        serde_json::from_slice(&std::fs::read(fixture.record(&receipt)).expect("record"))
            .expect("envelope");
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &[0x42; 32]).expect("key"));
    let nonce = [0x31; NONCE_LEN];
    let mut plaintext = Zeroizing::new(b"{invalid typed state but valid AEAD}".to_vec());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(metadata_aad(&envelope.metadata).expect("aad")),
        &mut *plaintext,
    )
    .expect("authenticated fixture");
    let authenticated = CheckpointEnvelope {
        metadata: envelope.metadata,
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(plaintext.as_slice()),
    };
    private_write(
        &fixture.record(&receipt),
        &serde_json::to_vec(&authenticated).expect("envelope"),
    );
    let store = fixture.store();
    assert_eq!(
        store
            .load(&fixture.tenant, &receipt.checkpoint_ref, 101, deadline())
            .err(),
        Some(CheckpointError::Rejected)
    );
    assert_eq!(
        store
            .cleanup_expired(100 + MAX_RETENTION_MS)
            .expect("metadata-only cleanup"),
        1
    );
}

#[test]
fn concurrent_identical_saves_never_publish_duplicate_refs() {
    let fixture = Arc::new(Fixture::new());
    let store = Arc::new(fixture.store());
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let fixture = fixture.clone();
        let store = store.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store.save(
                &fixture.tenant,
                &fixture.session,
                &fixture.fence,
                &fixture.action,
                snapshot(),
                100,
                deadline(),
            )
        }));
    }
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("thread"))
        .collect();
    let successful: Vec<_> = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .collect();
    assert!(!successful.is_empty());
    assert!(
        successful
            .iter()
            .all(|receipt| receipt.checkpoint_ref == successful[0].checkpoint_ref)
    );
    assert!(results.iter().all(
        |result| result.is_ok() || result.as_ref().err() == Some(&CheckpointError::Unavailable)
    ));
    assert_eq!(
        std::fs::read_dir(fixture.root())
            .expect("one published record")
            .count(),
        1
    );
}
