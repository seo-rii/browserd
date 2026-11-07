#![allow(clippy::expect_used)]

use std::fs;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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

fn approved_target_environment(native_environment: &[(&str, &str)]) -> Output {
    let mut gate = Command::new(gate_executable())
        .arg("--")
        .arg("/usr/bin/env")
        .env_clear()
        .envs(native_environment.iter().copied())
        .env("BROWSERD_TEST_SECRET", "must-not-cross-exec")
        .env(
            "BROWSERD_EGRESS_WORKER_TOKEN",
            "worker-token-must-not-cross-exec",
        )
        .env(
            "BROWSERD_EGRESS_SUPERVISOR_TOKEN",
            "supervisor-token-must-not-cross-exec",
        )
        .env(
            "BROWSERD_AUTH_HMAC_SECRET",
            "fake-auth-secret-must-not-cross-exec",
        )
        .env("LD_PRELOAD", "/browserd-test-unapproved-preload.so")
        .env("LD_LIBRARY_PATH", "/browserd-test-unapproved-libraries")
        .env("HOME", "/browserd-test-unapproved-home")
        .env("PATH", "/browserd-test-unapproved-path")
        .env("LC_MESSAGES", "unapproved-locale-must-not-cross-exec")
        .env("UNAPPROVED_ENVIRONMENT", "must-not-cross-exec")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch gate should start with the test environment");
    gate.stdin
        .take()
        .expect("gate stdin should be piped")
        .write_all(APPROVAL_FRAME)
        .expect("approval frame should be written");
    gate.wait_with_output()
        .expect("approved environment target should terminate")
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
fn exact_approval_preserves_only_the_native_locale_and_time_zone_environment() {
    for (language, posix_locale, time_zone) in [
        ("ko-KR", "ko_KR.UTF-8", "Asia/Seoul"),
        ("en-US", "en_US.UTF-8", "UTC"),
    ] {
        let native_environment = [
            ("LANG", posix_locale),
            ("LC_ALL", posix_locale),
            ("LANGUAGE", language),
            ("TZ", time_zone),
        ];
        let output = approved_target_environment(&native_environment);
        assert!(
            output.status.success(),
            "approved native target failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let actual = String::from_utf8(output.stdout).expect("environment should be UTF-8");
        let mut actual: Vec<_> = actual.lines().collect();
        actual.sort_unstable();
        let mut expected: Vec<_> = native_environment
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        expected.sort_unstable();
        assert_eq!(
            actual, expected,
            "native defaults must survive the gate; tokens, loader settings and other variables must not"
        );
    }
}

#[test]
fn baseline_approval_does_not_add_native_defaults_or_inherit_other_environment() {
    let output = approved_target_environment(&[]);
    assert!(
        output.status.success(),
        "approved baseline target failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "baseline target environment must remain empty"
    );
}

#[test]
fn native_environment_cannot_bypass_a_wrong_approval_frame() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let marker = directory.path().join("marker");
    let target = executable_target(directory.path());
    let mut gate = Command::new(gate_executable())
        .arg("--")
        .arg(&target)
        .arg("exact argument")
        .arg(&marker)
        .env_clear()
        .envs([
            ("LANG", "ko_KR.UTF-8"),
            ("LC_ALL", "ko_KR.UTF-8"),
            ("LANGUAGE", "ko-KR"),
            ("TZ", "Asia/Seoul"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch gate should start");
    let mut wrong = APPROVAL_FRAME.to_vec();
    wrong[0] ^= 1;
    gate.stdin
        .take()
        .expect("gate stdin should be piped")
        .write_all(&wrong)
        .expect("wrong frame should be written");
    let output = gate
        .wait_with_output()
        .expect("launch gate should terminate");
    assert_eq!(output.status.code(), Some(77));
    assert!(
        !marker.exists(),
        "native environment must never authorize a target"
    );
}

#[test]
fn native_environment_cannot_bypass_unsafe_target_arguments() {
    for arguments in [
        Vec::<&str>::new(),
        vec!["--"],
        vec!["/usr/bin/env"],
        vec!["--", "env"],
        vec!["--", "/"],
        vec!["--", "/usr/../bin/env"],
    ] {
        let gate = Command::new(gate_executable())
            .args(&arguments)
            .env_clear()
            .envs([
                ("LANG", "ko_KR.UTF-8"),
                ("LC_ALL", "ko_KR.UTF-8"),
                ("LANGUAGE", "ko-KR"),
                ("TZ", "Asia/Seoul"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch gate should start");
        let output = gate
            .wait_with_output()
            .expect("invalid launch should terminate");
        assert_eq!(output.status.code(), Some(64), "unsafe argv: {arguments:?}");
        assert!(
            output.stdout.is_empty(),
            "unsafe argv must not execute a target"
        );
    }
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
