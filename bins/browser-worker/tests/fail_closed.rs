use std::path::{Path, PathBuf};
use std::process::Command;

use browserd_chromium::{
    ArtifactFile, ChromiumArtifactIdentity, CompatibilityArtifact, Sha256Digest,
};
use sha2::{Digest, Sha256};

fn compatibility_artifact(directory: &Path) -> Option<PathBuf> {
    let root = directory.join("chromium-artifact");
    std::fs::create_dir(&root).ok()?;
    let binary = b"verified browserd chromium fixture";
    std::fs::write(root.join("chromium"), binary).ok()?;
    let binary_digest = Sha256Digest::from_hex(&hex::encode(Sha256::digest(binary))).ok()?;
    let bundle_digest = Sha256Digest::from_hex(&"33".repeat(32)).ok()?;
    let artifact = CompatibilityArtifact {
        identity: ChromiumArtifactIdentity {
            binary_digest,
            product_version: "149.0.7827.55".to_owned(),
            chromium_revision: "r1234567".to_owned(),
            browser_protocol_schema_digest: bundle_digest,
            js_protocol_schema_digest: bundle_digest,
            launch_profile_digest: bundle_digest,
            extension_bundle_digest: bundle_digest,
            font_bundle_digest: bundle_digest,
            certificate_runtime_bundle_digest: bundle_digest,
        },
        files: vec![ArtifactFile::new("chromium", binary_digest)],
    };
    let manifest = serde_json::to_vec(&artifact).ok()?;
    std::fs::write(root.join("compatibility.json"), manifest).ok()?;
    Some(root)
}

#[test]
fn production_binary_never_claims_ready_without_real_qualified_dependencies() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let journal_directory = directory.path().join("actions");
    assert!(std::fs::create_dir(&journal_directory).is_ok());
    let artifact_root = compatibility_artifact(directory.path());
    assert!(artifact_root.is_some());
    let Some(artifact_root) = artifact_root else {
        return;
    };
    let worker_socket = directory.path().join("worker.sock");
    let sandbox_socket = directory.path().join("sandbox.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env(
            "BROWSERD_WORKER_EPOCH_FILE",
            directory.path().join("worker.epoch"),
        )
        .env(
            "BROWSERD_INTERNAL_ENDPOINT",
            format!("unix:{}", worker_socket.display()),
        )
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .env("BROWSERD_ACTION_JOURNAL_DIR", journal_directory)
        .env("BROWSERD_SANDBOX_SOCKET", sandbox_socket)
        .env("BROWSERD_SANDBOX_EXPECTED_SERVER_UID", "0")
        .env("BROWSERD_SANDBOXD_EPOCH", "1")
        .env("BROWSERD_CHROMIUM_ARTIFACT_ROOT", artifact_root)
        .env("BROWSERD_EGRESS_POLICY_PROFILE", "strict")
        .env("BROWSERD_EGRESS_POLICY_DIGEST", "44".repeat(32))
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr);
    assert!(stderr.is_ok());
    assert!(
        stderr
            .ok()
            .is_some_and(|stderr| stderr.contains("readiness qualification unavailable"))
    );
}

#[test]
fn production_binary_rejects_non_internal_tcp_endpoint_before_startup() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let journal_directory = directory.path().join("actions");
    assert!(std::fs::create_dir(&journal_directory).is_ok());
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env(
            "BROWSERD_WORKER_EPOCH_FILE",
            directory.path().join("worker.epoch"),
        )
        .env("BROWSERD_INTERNAL_ENDPOINT", "0.0.0.0:19010")
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .env("BROWSERD_ACTION_JOURNAL_DIR", journal_directory)
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .ok()
            .is_some_and(|stderr| stderr.contains("invalid internal endpoint"))
    );
}

#[test]
fn production_binary_rejects_relative_action_journal_directory() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .current_dir(directory.path())
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env(
            "BROWSERD_WORKER_EPOCH_FILE",
            directory.path().join("worker.epoch"),
        )
        .env("BROWSERD_INTERNAL_ENDPOINT", "127.0.0.1:19010")
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .env("BROWSERD_ACTION_JOURNAL_DIR", "actions")
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .ok()
            .is_some_and(|stderr| stderr.contains("action journal directory must be absolute"))
    );
}

#[test]
fn production_binary_rejects_relative_epoch_state_before_mutation() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .current_dir(directory.path())
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env("BROWSERD_WORKER_EPOCH_FILE", "worker.epoch")
        .env("BROWSERD_INTERNAL_ENDPOINT", "127.0.0.1:19010")
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .ok()
            .is_some_and(|stderr| stderr.contains("epoch file must be absolute"))
    );
    assert!(!directory.path().join("worker.epoch").exists());
    assert!(!directory.path().join("worker.epoch.lock").exists());
}

#[test]
fn production_binary_rejects_loopback_rpc_before_epoch_mutation() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let journal_directory = directory.path().join("actions");
    assert!(std::fs::create_dir(&journal_directory).is_ok());
    let epoch_path = directory.path().join("worker.epoch");
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env("BROWSERD_WORKER_EPOCH_FILE", &epoch_path)
        .env("BROWSERD_INTERNAL_ENDPOINT", "127.0.0.1:19010")
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .env("BROWSERD_ACTION_JOURNAL_DIR", journal_directory)
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .ok()
            .is_some_and(|stderr| stderr.contains("worker RPC endpoint must be unix"))
    );
    assert!(!epoch_path.exists());
    assert!(!directory.path().join("worker.epoch.lock").exists());
}

#[test]
fn production_binary_requires_sandbox_rpc_before_epoch_mutation() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let journal_directory = directory.path().join("actions");
    assert!(std::fs::create_dir(&journal_directory).is_ok());
    let epoch_path = directory.path().join("worker.epoch");
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env("BROWSERD_WORKER_EPOCH_FILE", &epoch_path)
        .env(
            "BROWSERD_INTERNAL_ENDPOINT",
            format!("unix:{}", directory.path().join("worker.sock").display()),
        )
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .env("BROWSERD_ACTION_JOURNAL_DIR", journal_directory)
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .ok()
            .is_some_and(|stderr| stderr.contains("BROWSERD_SANDBOX_SOCKET is required"))
    );
    assert!(!epoch_path.exists());
    assert!(!directory.path().join("worker.epoch.lock").exists());
}

#[test]
fn production_binary_requires_chromium_artifact_before_epoch_mutation() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let journal_directory = directory.path().join("actions");
    assert!(std::fs::create_dir(&journal_directory).is_ok());
    let epoch_path = directory.path().join("worker.epoch");
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env("BROWSERD_WORKER_EPOCH_FILE", &epoch_path)
        .env(
            "BROWSERD_INTERNAL_ENDPOINT",
            format!("unix:{}", directory.path().join("worker.sock").display()),
        )
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .env("BROWSERD_ACTION_JOURNAL_DIR", journal_directory)
        .env(
            "BROWSERD_SANDBOX_SOCKET",
            directory.path().join("sandbox.sock"),
        )
        .env("BROWSERD_SANDBOX_EXPECTED_SERVER_UID", "0")
        .env("BROWSERD_SANDBOXD_EPOCH", "1")
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .ok()
            .is_some_and(|stderr| stderr.contains("BROWSERD_CHROMIUM_ARTIFACT_ROOT is required"))
    );
    assert!(!epoch_path.exists());
    assert!(!directory.path().join("worker.epoch.lock").exists());
}

#[test]
fn production_binary_rejects_tampered_chromium_artifact_before_epoch_mutation() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let artifact_root = compatibility_artifact(directory.path());
    assert!(artifact_root.is_some());
    let Some(artifact_root) = artifact_root else {
        return;
    };
    assert!(std::fs::write(artifact_root.join("chromium"), b"tampered").is_ok());
    let journal_directory = directory.path().join("actions");
    assert!(std::fs::create_dir(&journal_directory).is_ok());
    let epoch_path = directory.path().join("worker.epoch");
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env("BROWSERD_WORKER_EPOCH_FILE", &epoch_path)
        .env(
            "BROWSERD_INTERNAL_ENDPOINT",
            format!("unix:{}", directory.path().join("worker.sock").display()),
        )
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .env("BROWSERD_ACTION_JOURNAL_DIR", journal_directory)
        .env(
            "BROWSERD_SANDBOX_SOCKET",
            directory.path().join("sandbox.sock"),
        )
        .env("BROWSERD_SANDBOX_EXPECTED_SERVER_UID", "0")
        .env("BROWSERD_SANDBOXD_EPOCH", "1")
        .env("BROWSERD_CHROMIUM_ARTIFACT_ROOT", artifact_root)
        .env("BROWSERD_EGRESS_POLICY_PROFILE", "strict")
        .env("BROWSERD_EGRESS_POLICY_DIGEST", "44".repeat(32))
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };

    assert!(!output.status.success());
    assert!(!epoch_path.exists());
    assert!(!directory.path().join("worker.epoch.lock").exists());
    assert!(String::from_utf8(output.stderr).ok().is_some_and(|stderr| {
        stderr.contains("Chromium compatibility artifact verification failed")
    }));
}

#[test]
fn production_binary_rejects_invalid_chromium_identity_before_epoch_mutation() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let artifact_root = compatibility_artifact(directory.path());
    assert!(artifact_root.is_some());
    let Some(artifact_root) = artifact_root else {
        return;
    };
    let manifest_path = artifact_root.join("compatibility.json");
    let manifest = std::fs::read(&manifest_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CompatibilityArtifact>(&bytes).ok());
    assert!(manifest.is_some());
    let Some(mut manifest) = manifest else {
        return;
    };
    manifest.identity.product_version.clear();
    assert!(
        serde_json::to_vec(&manifest)
            .ok()
            .is_some_and(|bytes| std::fs::write(&manifest_path, bytes).is_ok())
    );
    let journal_directory = directory.path().join("actions");
    assert!(std::fs::create_dir(&journal_directory).is_ok());
    let epoch_path = directory.path().join("worker.epoch");
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env("BROWSERD_WORKER_EPOCH_FILE", &epoch_path)
        .env(
            "BROWSERD_INTERNAL_ENDPOINT",
            format!("unix:{}", directory.path().join("worker.sock").display()),
        )
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
        .env("BROWSERD_ACTION_JOURNAL_DIR", journal_directory)
        .env(
            "BROWSERD_SANDBOX_SOCKET",
            directory.path().join("sandbox.sock"),
        )
        .env("BROWSERD_SANDBOX_EXPECTED_SERVER_UID", "0")
        .env("BROWSERD_SANDBOXD_EPOCH", "1")
        .env("BROWSERD_CHROMIUM_ARTIFACT_ROOT", artifact_root)
        .env("BROWSERD_EGRESS_POLICY_PROFILE", "strict")
        .env("BROWSERD_EGRESS_POLICY_DIGEST", "44".repeat(32))
        .output();
    assert!(output.is_ok());
    let Some(output) = output.ok() else {
        return;
    };

    assert!(!output.status.success());
    assert!(!epoch_path.exists());
    assert!(!directory.path().join("worker.epoch.lock").exists());
    assert!(String::from_utf8(output.stderr).ok().is_some_and(|stderr| {
        stderr.contains("Chromium compatibility artifact verification failed")
    }));
}
