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
