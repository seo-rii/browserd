#![allow(clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn sandboxd_command(root: &Path) -> Command {
    let chromium = root.join("chrome");
    std::fs::write(&chromium, b"abc").expect("test Chromium should be written");
    std::fs::set_permissions(&chromium, std::fs::Permissions::from_mode(0o755))
        .expect("test Chromium should be executable");
    let mut command = Command::new(env!("CARGO_BIN_EXE_browser-sandboxd"));
    command
        .env_clear()
        .env("BROWSERD_SANDBOX_SOCKET", root.join("sandboxd.sock"))
        .env("BROWSERD_SANDBOX_JOURNAL_DIR", root.join("journal"))
        .env("BROWSERD_SANDBOXD_EPOCH_STATE", root.join("epoch"))
        .env("BROWSERD_SANDBOX_CGROUP_ROOT", root.join("cgroup/browserd"))
        .env("BROWSERD_SANDBOX_RUNTIME_ROOT", root.join("shards"))
        .env("BROWSERD_WORKER_ID", "sandbox-config-test-worker")
        .env("BROWSERD_WORKER_EPOCH", "7")
        .env(
            "BROWSERD_SANDBOX_EXPECTED_PEER_UID",
            nix::unistd::Uid::effective().as_raw().to_string(),
        )
        .env("BROWSERD_SUPERVISOR_LEASE_MILLIS", "1000")
        .env("BROWSERD_DIRECTORY_LEASE_MILLIS", "2000")
        .env("BROWSERD_SANDBOX_CLEANUP_TIMEOUT_MILLIS", "100")
        .env("BROWSERD_SANDBOX_RPC_TIMEOUT_MILLIS", "100")
        .env("BROWSERD_SANDBOX_LEASE_SWEEP_MILLIS", "10")
        .env("BROWSERD_SANDBOX_RPC_MAX_FRAME_BYTES", "65536")
        .env("BROWSERD_SANDBOX_RPC_MAX_CONNECTIONS", "8")
        .env("BROWSERD_SANDBOX_READ_ONLY_MOUNTS_JSON", "[]")
        .env("BROWSERD_CHROMIUM_HOST_EXECUTABLE", chromium)
        .env(
            "BROWSERD_CHROMIUM_SANDBOX_EXECUTABLE",
            "/opt/browser/chrome",
        );
    command
}

#[test]
fn missing_chromium_digest_fails_before_startup_mutation() {
    let temporary = tempfile::Builder::new()
        .prefix("sandboxd-missing-digest-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("private test directory should be created");
    let output = sandboxd_command(temporary.path())
        .output()
        .expect("sandboxd should execute");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("BROWSERD_CHROMIUM_BINARY_SHA256 is required"));
    assert!(!temporary.path().join("sandboxd.sock").exists());
    assert!(!temporary.path().join("epoch").exists());
    assert!(!temporary.path().join("journal").exists());
}

#[test]
fn malformed_chromium_digest_fails_before_startup_mutation() {
    let temporary = tempfile::Builder::new()
        .prefix("sandboxd-malformed-digest-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("private test directory should be created");
    let output = sandboxd_command(temporary.path())
        .env("BROWSERD_CHROMIUM_BINARY_SHA256", "not-a-sha256")
        .output()
        .expect("sandboxd should execute");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("BROWSERD_CHROMIUM_BINARY_SHA256 is invalid"));
    assert!(!temporary.path().join("sandboxd.sock").exists());
    assert!(!temporary.path().join("epoch").exists());
    assert!(!temporary.path().join("journal").exists());
}

#[test]
fn missing_native_artifact_root_fails_before_startup_mutation() {
    let temporary = tempfile::Builder::new()
        .prefix("sandboxd-native-root-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("private test directory");
    let output = sandboxd_command(temporary.path())
        .env(
            "BROWSERD_CHROMIUM_BINARY_SHA256",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .output()
        .expect("sandboxd should execute");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("BROWSERD_CHROMIUM_ARTIFACT_ROOT is required")
    );
    assert!(!temporary.path().join("sandboxd.sock").exists());
    assert!(!temporary.path().join("epoch").exists());
    assert!(!temporary.path().join("journal").exists());
}

#[test]
fn artifact_without_native_catalog_fails_before_startup_mutation() {
    let temporary = tempfile::Builder::new()
        .prefix("sandboxd-native-catalog-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("private test directory");
    let mut command = sandboxd_command(temporary.path());
    let binary_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let resource_digest =
        browserd_chromium::Sha256Digest::from_hex(&"01".repeat(32)).expect("resource digest");
    let identity = browserd_chromium::ChromiumArtifactIdentity {
        binary_digest: browserd_chromium::Sha256Digest::from_hex(binary_digest)
            .expect("fixture digest"),
        product_version: "153.0.8010.12".into(),
        chromium_revision: "971a7443b0c9b0a9b2860529b33331b76077ec62".into(),
        browser_protocol_schema_digest: resource_digest,
        js_protocol_schema_digest: resource_digest,
        launch_profile_digest: browserd_chromium::Sha256Digest::from_hex(&"02".repeat(32))
            .expect("catalog digest"),
        extension_bundle_digest: resource_digest,
        font_bundle_digest: resource_digest,
        certificate_runtime_bundle_digest: resource_digest,
    };
    std::fs::write(
        temporary.path().join("compatibility.json"),
        serde_json::to_vec(&serde_json::json!({
            "identity":identity,"files":[{"relative_path":"chrome","digest":binary_digest}]
        }))
        .expect("manifest JSON"),
    )
    .expect("fixture manifest");
    let output = command
        .env("BROWSERD_CHROMIUM_BINARY_SHA256", binary_digest)
        .env("BROWSERD_CHROMIUM_ARTIFACT_ROOT", temporary.path())
        .output()
        .expect("sandboxd should execute");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Chromium native process profile catalog verification failed")
    );
    assert!(!temporary.path().join("sandboxd.sock").exists());
    assert!(!temporary.path().join("epoch").exists());
    assert!(!temporary.path().join("journal").exists());
}
