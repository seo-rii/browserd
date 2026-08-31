#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use browserd_cdp::CdpTransportConfig;
use browserd_chromium::{ChromiumArtifactIdentity, ChromiumConnectionConfig, Sha256Digest};
use browserd_core::{
    IsolationProfile, LaunchGeneration, OwnerFence, ShardFence, ShardId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::ChromiumCdpPipes;
use browserd_worker::{
    CdpPipeAcceptor, ChromiumConnectionOwner, ChromiumDriver, TargetManagerDrain,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe::{Receiver, Sender};

// Linux exposes at most 15 bytes of the Rust thread name through `/proc/*/comm`.
const OWNER_THREAD_COMM: &str = "browserd-chromi";

struct Drain(AtomicBool);

impl TargetManagerDrain for Drain {
    fn begin_drain(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn identity() -> ChromiumArtifactIdentity {
    let digest = Sha256Digest::from_hex(&"00".repeat(32)).expect("test digest should be valid");
    ChromiumArtifactIdentity {
        binary_digest: digest,
        product_version: "149.0.7827.55".to_owned(),
        chromium_revision: "r1234567".to_owned(),
        browser_protocol_schema_digest: digest,
        js_protocol_schema_digest: digest,
        launch_profile_digest: digest,
        extension_bundle_digest: digest,
        font_bundle_digest: digest,
        certificate_runtime_bundle_digest: digest,
    }
}

fn connection_config() -> ChromiumConnectionConfig {
    ChromiumConnectionConfig {
        transport: CdpTransportConfig {
            max_frame_bytes: 64 * 1024,
            max_pending_commands: 16,
            command_queue_capacity: 16,
            event_queue_capacity: 16,
            write_timeout: Duration::from_millis(500),
            default_command_timeout: Duration::from_millis(500),
        },
        version_probe_timeout: Duration::from_millis(500),
        max_version_field_bytes: 1_024,
    }
}

fn shard_fence() -> ShardFence {
    ShardFence::new(
        OwnerFence::new(
            WorkerId::new("chromium-owner-shutdown-worker")
                .expect("worker identity should be valid"),
            WorkerEpoch::new(17).expect("worker epoch should be valid"),
        ),
        ShardId::new(),
        LaunchGeneration::new(3).expect("launch generation should be valid"),
    )
}

#[tokio::test]
async fn shutdown_before_pipe_acceptance_is_immediate_and_idempotent() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, _manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain,
    )
    .expect("Chromium owner should be constructed");

    let first = tokio::time::timeout(
        Duration::from_millis(50),
        owner.shutdown_and_join(Duration::from_millis(25)),
    )
    .await;
    assert_eq!(first, Ok(Ok(())));
    assert_eq!(
        owner.shutdown_and_join(Duration::from_millis(25)).await,
        Ok(())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_shutdown_joins_the_owner_thread_once_for_concurrent_callers() {
    let baseline_owner_threads = std::fs::read_dir("/proc/self/task")
        .expect("Linux task directory should be available")
        .filter_map(Result::ok)
        .filter(|entry| {
            std::fs::read_to_string(entry.path().join("comm"))
                .is_ok_and(|name| name.trim() == OWNER_THREAD_COMM)
        })
        .count();

    let identity = identity();
    let connection_config = connection_config();
    let shard_fence = shard_fence();
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, _manager) =
        ChromiumConnectionOwner::new_bounded(identity, connection_config, shard_fence, 16, drain)
            .expect("Chromium owner should be constructed");

    let (command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe should be created");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe should be created");
    let pipes = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
        .expect("parent CDP capabilities should be valid");
    let mut command_reader =
        Receiver::from_owned_fd(command_reader).expect("command reader should become async");
    let mut event_writer =
        Sender::from_owned_fd(event_writer).expect("event writer should become async");

    let accept = tokio::spawn({
        let owner = Arc::clone(&owner);
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    let mut command_bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = command_reader
            .read(&mut byte)
            .await
            .expect("version command should be readable");
        if read == 0 || byte[0] == 0 {
            break;
        }
        command_bytes.push(byte[0]);
    }
    let version_command: Value =
        serde_json::from_slice(&command_bytes).expect("version command should be valid JSON");
    assert_eq!(version_command["method"], "Browser.getVersion");
    let version_response = json!({
        "id": version_command["id"]
            .as_u64()
            .expect("version command ID should exist"),
        "result": {
            "protocolVersion": "1.3",
            "product": "HeadlessChrome/149.0.7827.55",
            "revision": "r1234567",
            "userAgent": "browserd-owner-shutdown-test",
            "jsVersion": "14.9"
        }
    });
    let version_response =
        serde_json::to_vec(&version_response).expect("version response should encode");
    event_writer
        .write_all(&version_response)
        .await
        .expect("version response should write");
    event_writer
        .write_all(&[0])
        .await
        .expect("version response terminator should write");
    assert_eq!(
        accept.await.expect("accept task should join"),
        Ok(()),
        "the owner thread should accept the exact CDP capabilities"
    );

    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            let active_owner_threads = std::fs::read_dir("/proc/self/task")
                .expect("Linux task directory should remain available")
                .filter_map(Result::ok)
                .filter(|entry| {
                    std::fs::read_to_string(entry.path().join("comm"))
                        .is_ok_and(|name| name.trim() == OWNER_THREAD_COMM)
                })
                .count();
            if active_owner_threads == baseline_owner_threads + 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the dedicated Chromium owner thread should be observable before shutdown");

    let driver = owner.chromium_driver(IsolationProfile::SharedContext);
    assert_eq!(driver.qualify(), Ok(()));

    let mut shutdowns = Vec::new();
    for _ in 0..8 {
        let owner = Arc::clone(&owner);
        shutdowns.push(tokio::spawn(async move {
            owner.shutdown_and_join(Duration::from_millis(500)).await
        }));
    }
    let shutdown_results = tokio::time::timeout(Duration::from_secs(2), async move {
        let mut results = Vec::with_capacity(shutdowns.len());
        for shutdown in shutdowns {
            results.push(shutdown.await.expect("shutdown caller should not panic"));
        }
        results
    })
    .await
    .expect("concurrent owner shutdown must remain bounded");
    assert!(shutdown_results.into_iter().all(|result| result == Ok(())));
    assert_eq!(
        owner.shutdown_and_join(Duration::from_millis(100)).await,
        Ok(()),
        "an exact retry after the owner joined must be idempotent"
    );

    let remaining_owner_threads = std::fs::read_dir("/proc/self/task")
        .expect("Linux task directory should remain available")
        .filter_map(Result::ok)
        .filter(|entry| {
            std::fs::read_to_string(entry.path().join("comm"))
                .is_ok_and(|name| name.trim() == OWNER_THREAD_COMM)
        })
        .count();
    assert_eq!(
        remaining_owner_threads, baseline_owner_threads,
        "shutdown_and_join must not return while its owner thread is still alive"
    );
    assert!(driver.qualify().is_err());

    let mut byte = [0_u8; 1];
    let command_eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(command_eof, Ok(Ok(0))));
    let event_closed =
        tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"{}\0")).await;
    assert!(matches!(event_closed, Ok(Err(_))));
}
