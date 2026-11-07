#![allow(clippy::expect_used)]

use std::io::{Cursor, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use super::*;

struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("directory mode");
        Self { directory }
    }

    fn path(&self) -> PathBuf {
        self.directory.path().join("evaluate-policy.json")
    }

    fn write(&self, bytes: &[u8]) {
        std::fs::write(self.path(), bytes).expect("fixture write");
        std::fs::set_permissions(self.path(), std::fs::Permissions::from_mode(0o600))
            .expect("file mode");
    }
}

fn grant() -> PrivilegedEvaluateGrant {
    PrivilegedEvaluateGrant {
        tenant_id: TenantId::new(),
        principal_id: PrincipalId::new(),
    }
}

fn encode(grants: &[PrivilegedEvaluateGrant]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "schema_version": 1, "grants": grants }))
        .expect("fixture JSON")
}

#[test]
fn missing_configuration_and_an_explicit_empty_policy_deny_every_pair() {
    let empty = PrivilegedEvaluatePolicy::default();
    let explicit = PrivilegedEvaluatePolicy::new(Vec::new()).expect("empty policy");
    let grant = grant();
    assert!(!empty.is_enabled());
    assert!(!empty.allows_tenant(&grant.tenant_id));
    assert!(!empty.allows(&grant.tenant_id, &grant.principal_id));
    assert_eq!(empty.digest(), explicit.digest());
    assert_eq!(
        PrivilegedEvaluatePolicy::from_bytes(&encode(&[])).expect("empty config"),
        empty
    );
    let fixture = Fixture::new();
    assert_eq!(
        PrivilegedEvaluatePolicy::open(&fixture.path()),
        Err(PrivilegedEvaluatePolicyError::Unavailable)
    );
}

#[test]
fn exact_tenant_principal_pairs_do_not_form_a_cross_product() {
    let first = grant();
    let second = grant();
    let policy =
        PrivilegedEvaluatePolicy::new(vec![first.clone(), second.clone()]).expect("policy");
    assert!(policy.is_enabled());
    assert!(policy.allows_tenant(&first.tenant_id));
    assert!(policy.allows_tenant(&second.tenant_id));
    assert!(!policy.allows_tenant(&TenantId::new()));
    assert!(policy.allows(&first.tenant_id, &first.principal_id));
    assert!(policy.allows(&second.tenant_id, &second.principal_id));
    assert!(!policy.allows(&first.tenant_id, &second.principal_id));
    assert!(!policy.allows(&second.tenant_id, &first.principal_id));
}

#[test]
fn digest_is_canonical_order_independent_and_binds_both_identifiers() {
    let first = grant();
    let second = grant();
    let policy =
        PrivilegedEvaluatePolicy::new(vec![first.clone(), second.clone()]).expect("policy");
    let reversed =
        PrivilegedEvaluatePolicy::new(vec![second.clone(), first.clone()]).expect("policy");
    assert_eq!(policy.digest(), reversed.digest());
    let mut changed = first.clone();
    changed.principal_id = PrincipalId::new();
    assert_ne!(
        policy.digest(),
        PrivilegedEvaluatePolicy::new(vec![changed, second.clone()])
            .expect("policy")
            .digest()
    );
    let mut changed = first;
    changed.tenant_id = TenantId::new();
    assert_ne!(
        policy.digest(),
        PrivilegedEvaluatePolicy::new(vec![changed, second])
            .expect("policy")
            .digest()
    );
    assert_ne!(
        policy.digest(),
        PrivilegedEvaluatePolicy::default().digest()
    );
}

#[test]
fn snapshot_does_not_observe_later_changes_to_constructor_input_or_file() {
    let allowed = grant();
    let mut input = vec![allowed.clone()];
    let memory_policy = PrivilegedEvaluatePolicy::new(input.clone()).expect("policy");
    input[0].principal_id = PrincipalId::new();
    assert!(memory_policy.allows(&allowed.tenant_id, &allowed.principal_id));
    assert!(!memory_policy.allows(&input[0].tenant_id, &input[0].principal_id));
    let fixture = Fixture::new();
    fixture.write(&encode(std::slice::from_ref(&allowed)));
    let file_policy = PrivilegedEvaluatePolicy::open(&fixture.path()).expect("policy file");
    fixture.write(&encode(&input));
    assert!(file_policy.allows(&allowed.tenant_id, &allowed.principal_id));
    assert_eq!(file_policy.digest(), memory_policy.digest());
}

#[test]
fn duplicate_typed_and_normalized_json_pairs_are_rejected() {
    let allowed = grant();
    assert_eq!(
        PrivilegedEvaluatePolicy::new(vec![allowed.clone(), allowed.clone()]),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
    let uppercase = serde_json::json!({
        "tenant_id": allowed.tenant_id.to_string().to_uppercase(),
        "principal_id": allowed.principal_id.to_string().to_uppercase(),
    });
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "grants": [serde_json::to_value(&allowed).expect("grant"), uppercase],
    }))
    .expect("config");
    assert_eq!(
        PrivilegedEvaluatePolicy::from_bytes(&bytes),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
}

#[test]
fn strict_schema_rejects_unknown_fields_missing_fields_nil_and_wrong_uuid_versions() {
    let allowed = grant();
    let base = serde_json::json!({ "schema_version": 1, "grants": [allowed] });
    let mut invalid = Vec::new();
    let mut unknown = base.clone();
    unknown["unknown"] = serde_json::json!(true);
    invalid.push(unknown);
    let mut unknown = base.clone();
    unknown["grants"][0]["expression"] = serde_json::json!("private-config-marker");
    invalid.push(unknown);
    for version in [
        serde_json::json!(0),
        serde_json::json!(2),
        serde_json::json!("1"),
        serde_json::Value::Null,
    ] {
        let mut value = base.clone();
        value["schema_version"] = version;
        invalid.push(value);
    }
    invalid.push(serde_json::json!({ "grants": [] }));
    invalid.push(serde_json::json!({ "schema_version": 1 }));
    invalid.push(serde_json::json!({ "schema_version": 1, "grants": null }));
    for field in ["tenant_id", "principal_id"] {
        for id in [
            serde_json::json!(uuid::Uuid::nil()),
            serde_json::json!(uuid::Uuid::new_v4()),
            serde_json::Value::Null,
            serde_json::json!("private-config-marker"),
        ] {
            let mut value = base.clone();
            value["grants"][0][field] = id;
            invalid.push(value);
        }
        let mut value = base.clone();
        value["grants"][0]
            .as_object_mut()
            .expect("grant object")
            .remove(field);
        invalid.push(value);
    }
    for value in invalid {
        let bytes = serde_json::to_vec(&value).expect("config");
        assert_eq!(
            PrivilegedEvaluatePolicy::from_bytes(&bytes),
            Err(PrivilegedEvaluatePolicyError::Rejected)
        );
    }
    for bytes in [
        b"".as_slice(),
        b"\xff".as_slice(),
        b"{} {}".as_slice(),
        b"{\"schema_version\":1,\"schema_version\":1,\"grants\":[]}".as_slice(),
    ] {
        assert_eq!(
            PrivilegedEvaluatePolicy::from_bytes(bytes),
            Err(PrivilegedEvaluatePolicyError::Rejected)
        );
    }
}

#[test]
fn grant_count_bound_applies_to_constructor_and_deserialization() {
    let mut grants: Vec<_> = (0..MAX_PRIVILEGED_EVALUATE_GRANTS)
        .map(|_| grant())
        .collect();
    assert!(PrivilegedEvaluatePolicy::new(grants.clone()).is_ok());
    assert!(PrivilegedEvaluatePolicy::from_bytes(&encode(&grants)).is_ok());
    grants.push(grant());
    assert_eq!(
        PrivilegedEvaluatePolicy::new(grants.clone()),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
    assert_eq!(
        PrivilegedEvaluatePolicy::from_bytes(&encode(&grants)),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
}

#[test]
fn exact_file_size_limit_accepts_valid_padding_and_rejects_one_extra_byte() {
    let fixture = Fixture::new();
    let mut bytes = encode(&[grant()]);
    bytes.resize(MAX_PRIVILEGED_EVALUATE_POLICY_BYTES, b' ');
    fixture.write(&bytes);
    assert!(PrivilegedEvaluatePolicy::open(&fixture.path()).is_ok());
    bytes.push(b' ');
    fixture.write(&bytes);
    assert_eq!(
        PrivilegedEvaluatePolicy::open(&fixture.path()),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
}

#[test]
fn relative_parent_traversal_and_symlinked_directory_paths_are_rejected() {
    let fixture = Fixture::new();
    fixture.write(&encode(&[]));
    assert_eq!(
        PrivilegedEvaluatePolicy::open(Path::new("evaluate-policy.json")),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
    let nested = fixture.directory.path().join("nested");
    std::fs::create_dir(&nested).expect("nested directory");
    assert_eq!(
        PrivilegedEvaluatePolicy::open(&nested.join("../evaluate-policy.json")),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
    let alias = fixture.directory.path().join("alias");
    symlink(fixture.directory.path(), &alias).expect("directory symlink");
    assert_eq!(
        PrivilegedEvaluatePolicy::open(&alias.join("evaluate-policy.json")),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
}

#[test]
fn parent_and_file_permissions_must_be_exactly_private() {
    let fixture = Fixture::new();
    fixture.write(&encode(&[]));
    for mode in [0o755, 0o750, 0o1700] {
        std::fs::set_permissions(
            fixture.directory.path(),
            std::fs::Permissions::from_mode(mode),
        )
        .expect("directory mode");
        assert_eq!(
            PrivilegedEvaluatePolicy::open(&fixture.path()),
            Err(PrivilegedEvaluatePolicyError::Rejected)
        );
    }
    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("directory mode");
    for mode in [0o400, 0o640, 0o644, 0o1600] {
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(mode))
            .expect("file mode");
        assert_eq!(
            PrivilegedEvaluatePolicy::open(&fixture.path()),
            Err(PrivilegedEvaluatePolicyError::Rejected)
        );
    }
    std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o600))
        .expect("file mode");
    assert!(PrivilegedEvaluatePolicy::open(&fixture.path()).is_ok());
}

#[test]
fn symlink_hardlink_fifo_and_directory_files_are_rejected_without_reading() {
    let fixture = Fixture::new();
    fixture.write(&encode(&[]));
    let original = fixture.directory.path().join("original.json");
    std::fs::rename(fixture.path(), &original).expect("rename");
    symlink(&original, fixture.path()).expect("file symlink");
    assert!(PrivilegedEvaluatePolicy::open(&fixture.path()).is_err());
    std::fs::remove_file(fixture.path()).expect("unlink symlink");
    std::fs::hard_link(&original, fixture.path()).expect("hardlink");
    assert_eq!(
        PrivilegedEvaluatePolicy::open(&fixture.path()),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
    std::fs::remove_file(fixture.path()).expect("unlink hardlink");
    nix::unistd::mkfifo(&fixture.path(), Mode::S_IRUSR | Mode::S_IWUSR).expect("FIFO");
    assert_eq!(
        PrivilegedEvaluatePolicy::open(&fixture.path()),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
    std::fs::remove_file(fixture.path()).expect("unlink FIFO");
    std::fs::create_dir(fixture.path()).expect("directory");
    assert_eq!(
        PrivilegedEvaluatePolicy::open(&fixture.path()),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
}

#[test]
fn loader_rejects_invalid_utf8_and_reports_no_path_or_config_data() {
    let fixture = Fixture::new();
    fixture.write(b"\xffprivate-config-marker");
    let error = PrivilegedEvaluatePolicy::open(&fixture.path()).expect_err("invalid config");
    assert_eq!(error, PrivilegedEvaluatePolicyError::Rejected);
    let error_text = format!("{error} {error:?}");
    assert!(!error_text.contains("private-config-marker"));
    assert!(!error_text.contains(&fixture.path().display().to_string()));
    let allowed = grant();
    let policy = PrivilegedEvaluatePolicy::new(vec![allowed.clone()]).expect("policy");
    let debug = format!("{policy:?} {allowed:?}");
    assert!(!debug.contains(&allowed.tenant_id.to_string()));
    assert!(!debug.contains(&allowed.principal_id.to_string()));
}

#[test]
fn read_rejects_wrong_owner_expired_deadline_and_mutated_file_metadata() {
    let fixture = Fixture::new();
    fixture.write(&encode(&[]));
    let before = std::fs::metadata(fixture.path()).expect("metadata");
    let owner = nix::unistd::geteuid().as_raw();
    let mut file = File::open(fixture.path()).expect("file");
    assert_eq!(
        read_bounded(
            &mut file,
            &before,
            owner.wrapping_add(1),
            Instant::now() + LOAD_BUDGET,
            File::metadata
        ),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
    assert_eq!(
        read_bounded(&mut file, &before, owner, Instant::now(), File::metadata),
        Err(PrivilegedEvaluatePolicyError::Unavailable)
    );
    let bytes = std::fs::read(fixture.path()).expect("bytes");
    let mut reader = Cursor::new(bytes);
    assert_eq!(
        read_bounded(
            &mut reader,
            &before,
            owner,
            Instant::now() + LOAD_BUDGET,
            |_| {
                std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o640))?;
                std::fs::metadata(fixture.path())
            }
        ),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
}

#[test]
fn read_rejects_growth_truncation_and_replacement_after_snapshot() {
    let fixture = Fixture::new();
    for mutation in 0..4 {
        fixture.write(&encode(&[]));
        let before = std::fs::metadata(fixture.path()).expect("metadata");
        let mut reader = Cursor::new(std::fs::read(fixture.path()).expect("bytes"));
        assert_eq!(
            read_bounded(
                &mut reader,
                &before,
                nix::unistd::geteuid().as_raw(),
                Instant::now() + LOAD_BUDGET,
                |_| {
                    match mutation {
                        0 => std::fs::OpenOptions::new()
                            .append(true)
                            .open(fixture.path())?
                            .write_all(b" ")?,
                        1 => std::fs::OpenOptions::new()
                            .write(true)
                            .open(fixture.path())?
                            .set_len(1)?,
                        2 => {
                            let replacement = fixture.directory.path().join("replacement.json");
                            std::fs::write(&replacement, encode(&[]))?;
                            std::fs::set_permissions(
                                &replacement,
                                std::fs::Permissions::from_mode(0o600),
                            )?;
                            std::fs::rename(replacement, fixture.path())?;
                        }
                        _ => {
                            let mut file = std::fs::OpenOptions::new()
                                .write(true)
                                .open(fixture.path())?;
                            file.write_all(&vec![b' '; before.len() as usize])?;
                            file.set_times(
                                std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH),
                            )?;
                        }
                    }
                    std::fs::metadata(fixture.path())
                }
            ),
            Err(PrivilegedEvaluatePolicyError::Rejected)
        );
    }
}

#[test]
fn bounded_read_never_reallocates_for_growth_and_never_returns_oversize_input() {
    let fixture = Fixture::new();
    fixture.write(&encode(&[]));
    let before = std::fs::metadata(fixture.path()).expect("metadata");
    let owner = nix::unistd::geteuid().as_raw();
    let mut file = File::open(fixture.path()).expect("file");
    let bytes = read_bounded(
        &mut file,
        &before,
        owner,
        Instant::now() + LOAD_BUDGET,
        File::metadata,
    )
    .expect("bounded read");
    assert!(bytes.capacity() >= MAX_PRIVILEGED_EVALUATE_POLICY_BYTES);
    let mut growing = Cursor::new(vec![b' '; MAX_PRIVILEGED_EVALUATE_POLICY_BYTES + 1]);
    assert_eq!(
        read_bounded(
            &mut growing,
            &before,
            owner,
            Instant::now() + LOAD_BUDGET,
            |_| std::fs::metadata(fixture.path())
        ),
        Err(PrivilegedEvaluatePolicyError::Rejected)
    );
}

#[test]
fn read_stream_errors_are_sanitized_and_skip_final_metadata() {
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("private-config-marker"))
        }
    }
    let fixture = Fixture::new();
    fixture.write(&encode(&[]));
    let before = std::fs::metadata(fixture.path()).expect("metadata");
    let mut metadata_called = false;
    let result = read_bounded(
        &mut FailingReader,
        &before,
        nix::unistd::geteuid().as_raw(),
        Instant::now() + LOAD_BUDGET,
        |_| {
            metadata_called = true;
            std::fs::metadata(fixture.path())
        },
    );
    assert_eq!(result, Err(PrivilegedEvaluatePolicyError::Unavailable));
    assert!(!metadata_called);
    assert!(!format!("{result:?}").contains("private-config-marker"));
}
