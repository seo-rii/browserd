use std::process::Command;

#[test]
fn production_binary_never_claims_ready_without_real_qualified_dependencies() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env(
            "BROWSERD_WORKER_EPOCH_FILE",
            directory.path().join("worker.epoch"),
        )
        .env("BROWSERD_INTERNAL_ENDPOINT", "127.0.0.1:19010")
        .env("BROWSERD_INTERNAL_PEER", "gateway-production-test")
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
    let output = Command::new(env!("CARGO_BIN_EXE_browser-worker"))
        .env("BROWSERD_WORKER_ID", "worker-production-test")
        .env(
            "BROWSERD_WORKER_EPOCH_FILE",
            directory.path().join("worker.epoch"),
        )
        .env("BROWSERD_INTERNAL_ENDPOINT", "0.0.0.0:19010")
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
            .is_some_and(|stderr| stderr.contains("invalid internal endpoint"))
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
