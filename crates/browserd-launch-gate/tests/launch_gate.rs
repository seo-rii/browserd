#![allow(clippy::expect_used)]

use std::fs;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use browserd_launch_gate::APPROVAL_FRAME;

fn gate_executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_browserd-launch-gate"))
}

fn executable_target(directory: &Path) -> PathBuf {
    let path = directory.join("target");
    fs::write(
        &path,
        r#"#!/bin/sh
if [ "${BROWSERD_TEST_SECRET+x}" = x ]; then
    exit 91
fi
if IFS= read -r unexpected; then
    exit 92
fi
if [ "$#" -ne 2 ] || [ "$1" != "exact argument" ]; then
    exit 93
fi
printf approved > "$2"
"#,
    )
    .expect("target should be written");
    let mut permissions = fs::metadata(&path)
        .expect("target metadata should exist")
        .permissions();
    permissions.set_mode(0o500);
    fs::set_permissions(&path, permissions).expect("target should be executable");
    path
}

fn spawn_gate(target: &Path, marker: &Path) -> Child {
    Command::new(gate_executable())
        .arg("--")
        .arg(target)
        .arg("exact argument")
        .arg(marker)
        .env("BROWSERD_TEST_SECRET", "must-not-cross-exec")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch gate should start")
}

fn assert_rejected(input: &[u8]) {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let marker = directory.path().join("marker");
    let target = executable_target(directory.path());
    let mut gate = spawn_gate(&target, &marker);
    gate.stdin
        .take()
        .expect("gate stdin should be piped")
        .write_all(input)
        .expect("test input should be written");
    let output = gate
        .wait_with_output()
        .expect("launch gate should terminate");
    assert!(
        !output.status.success(),
        "invalid approval must be rejected"
    );
    assert!(!marker.exists(), "rejected input must never execute target");
}

#[test]
fn empty_eof_is_fail_closed() {
    assert_rejected(b"");
}

#[test]
fn partial_approval_frame_is_fail_closed() {
    assert_rejected(&APPROVAL_FRAME[..APPROVAL_FRAME.len() - 1]);
}

#[test]
fn wrong_approval_frame_is_fail_closed() {
    let mut wrong = APPROVAL_FRAME.to_vec();
    wrong[0] ^= 1;
    assert_rejected(&wrong);
}

#[test]
fn oversized_or_trailing_approval_frame_is_fail_closed() {
    let mut oversized = APPROVAL_FRAME.to_vec();
    oversized.extend_from_slice(b"unexpected trailing bytes");
    assert_rejected(&oversized);
}

#[test]
fn exact_approval_frame_executes_exact_argv_with_clean_environment_and_null_stdin() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let marker = directory.path().join("marker");
    let target = executable_target(directory.path());
    let mut gate = spawn_gate(&target, &marker);
    gate.stdin
        .take()
        .expect("gate stdin should be piped")
        .write_all(APPROVAL_FRAME)
        .expect("approval frame should be written");
    let output = gate
        .wait_with_output()
        .expect("approved launch should terminate");
    assert!(
        output.status.success(),
        "approved target failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(marker).expect("approved target should write marker"),
        "approved"
    );
}

#[test]
fn supervisor_sigkill_closes_control_pipe_without_executing_target() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let marker = directory.path().join("marker");
    let target = executable_target(directory.path());
    let (gate_control, supervisor_control) =
        UnixStream::pair().expect("control socket pair should be created");
    let mut supervisor = Command::new("/bin/sleep")
        .arg("30")
        .stdout(Stdio::from(OwnedFd::from(supervisor_control)))
        .spawn()
        .expect("supervisor subprocess should start");
    let mut gate = Command::new(gate_executable())
        .arg("--")
        .arg(&target)
        .arg("exact argument")
        .arg(&marker)
        .stdin(Stdio::from(OwnedFd::from(gate_control)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch gate should start");

    std::thread::sleep(Duration::from_millis(50));
    assert!(!marker.exists(), "target must remain gated before approval");
    assert!(
        gate.try_wait()
            .expect("launch gate status should be observable")
            .is_none(),
        "launch gate must remain blocked while the supervisor owns the writer"
    );
    supervisor.kill().expect("supervisor should be killed");
    supervisor.wait().expect("supervisor should be reaped");

    let output = gate
        .wait_with_output()
        .expect("launch gate should observe supervisor EOF");
    assert!(!output.status.success(), "supervisor EOF must be rejected");
    assert!(
        !marker.exists(),
        "supervisor death must never execute target"
    );
}
