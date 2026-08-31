#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use browserd_cdp::CdpTransportConfig;
use browserd_chromium::{ChromiumArtifactIdentity, ChromiumConnectionConfig, Sha256Digest};
use browserd_core::{
    IsolationProfile, LaunchGeneration, OwnerFence, PageId, SessionId, ShardFence, ShardId,
    TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::ChromiumCdpPipes;
use browserd_session::OwnershipFence;
use browserd_targets::{BootstrapBackend, BootstrapStage, PausedTarget, TargetKind};
use browserd_worker::{
    CdpChromiumDriver, CdpPipeAcceptor, ChromiumConnectionOwner, ChromiumDriver,
    ChromiumTargetManager, TargetManagerDrain,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe::{Receiver, Sender};

struct Drain(AtomicBool);

impl TargetManagerDrain for Drain {
    fn begin_drain(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn identity() -> ChromiumArtifactIdentity {
    let digest = Sha256Digest::from_hex(&"00".repeat(32)).expect("test digest must be valid");
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

fn fence() -> ShardFence {
    ShardFence::new(
        OwnerFence::new(
            WorkerId::new("chromium-target-worker").unwrap(),
            WorkerEpoch::new(11).unwrap(),
        ),
        ShardId::new(),
        LaunchGeneration::new(2).unwrap(),
    )
}

fn pipe_pair() -> (ChromiumCdpPipes, Receiver, Sender) {
    let (command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe should be created");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe should be created");
    let parent = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
        .expect("parent capabilities should be valid");
    let command_reader =
        Receiver::from_owned_fd(command_reader).expect("command reader should become async");
    let event_writer =
        Sender::from_owned_fd(event_writer).expect("event writer should become async");
    (parent, command_reader, event_writer)
}

async fn read_command(reader: &mut Receiver) -> Value {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = reader
            .read(&mut byte)
            .await
            .expect("command read should work");
        if read == 0 || byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    serde_json::from_slice(&bytes).expect("command should be valid JSON")
}

async fn write_message(writer: &mut Sender, message: Value) {
    let bytes = serde_json::to_vec(&message).expect("message should encode");
    writer
        .write_all(&bytes)
        .await
        .expect("message body should write");
    writer
        .write_all(&[0])
        .await
        .expect("message terminator should write");
}

async fn respond(writer: &mut Sender, command: &Value, result: Value) {
    write_message(
        writer,
        json!({
            "id": command["id"].as_u64().expect("command ID should exist"),
            "result": result,
        }),
    )
    .await;
}

async fn qualify(reader: &mut Receiver, writer: &mut Sender) {
    let command = read_command(reader).await;
    assert_eq!(command["method"], "Browser.getVersion");
    respond(
        writer,
        &command,
        json!({
            "protocolVersion": "1.3",
            "product": "HeadlessChrome/149.0.7827.55",
            "revision": "r1234567",
            "userAgent": "browserd-test",
            "jsVersion": "14.9",
        }),
    )
    .await;
}

fn attached(target_id: &str, session_id: &str, context_id: &str, kind: &str) -> Value {
    json!({
        "method": "Target.attachedToTarget",
        "params": {
            "sessionId": session_id,
            "waitingForDebugger": true,
            "targetInfo": {
                "targetId": target_id,
                "browserContextId": context_id,
                "type": kind,
            }
        }
    })
}

fn ownership_fence() -> OwnershipFence {
    OwnershipFence::new(WorkerId::new("chromium-target-worker").unwrap(), 11, 7, 3)
}

async fn bootstrap_empty(
    manager: Arc<ChromiumTargetManager<Drain>>,
    reader: &mut Receiver,
    writer: &mut Sender,
) {
    let bootstrap = tokio::spawn(async move { manager.bootstrap().await });
    for method in [
        "Target.setAutoAttach",
        "Target.setDiscoverTargets",
        "Target.getTargets",
    ] {
        let command = read_command(reader).await;
        assert_eq!(command["method"], method);
        let result = if method == "Target.getTargets" {
            json!({"targetInfos": []})
        } else {
            json!({})
        };
        respond(writer, &command, result).await;
    }
    assert_eq!(bootstrap.await.unwrap(), Ok(()));
}

#[allow(clippy::too_many_arguments)]
async fn create_owned_primary(
    driver: CdpChromiumDriver,
    tenant_id: TenantId,
    session_id: SessionId,
    ownership: OwnershipFence,
    context_id: &str,
    target_id: &str,
    flat_session_id: &str,
    reader: &mut Receiver,
    writer: &mut Sender,
) -> PageId {
    let create = tokio::task::spawn_blocking(move || {
        driver.create_context_owned(&tenant_id, &session_id, &ownership)
    });
    let context = read_command(reader).await;
    assert_eq!(context["method"], "Target.createBrowserContext");
    respond(writer, &context, json!({"browserContextId": context_id})).await;
    let target = read_command(reader).await;
    assert_eq!(target["method"], "Target.createTarget");
    write_message(
        writer,
        attached(target_id, flat_session_id, context_id, "page"),
    )
    .await;
    respond(writer, &target, json!({"targetId": target_id})).await;
    for _ in 0..6 {
        let command = read_command(reader).await;
        respond(writer, &command, json!({})).await;
    }
    create.await.unwrap().unwrap()
}

#[tokio::test]
async fn owned_target_routes_preserve_full_identity_and_forward_exact_detaches() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let backend = owner.target_manager_backend();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut command_reader, &mut event_writer).await;

    let driver = owner.chromium_driver(IsolationProfile::SharedContext);
    let first_tenant = TenantId::new();
    let first_session = SessionId::new();
    let first_ownership = ownership_fence();
    create_owned_primary(
        driver.clone(),
        first_tenant.clone(),
        first_session.clone(),
        first_ownership.clone(),
        "context-a",
        "initial",
        "flat-initial",
        &mut command_reader,
        &mut event_writer,
    )
    .await;
    let second_tenant = TenantId::new();
    let second_session = SessionId::new();
    let second_ownership =
        OwnershipFence::new(WorkerId::new("chromium-target-worker").unwrap(), 11, 8, 4);
    create_owned_primary(
        driver,
        second_tenant.clone(),
        second_session.clone(),
        second_ownership.clone(),
        "context-b",
        "catch-up",
        "flat-catch-up",
        &mut command_reader,
        &mut event_writer,
    )
    .await;

    assert!(manager.is_ready());
    assert_eq!(manager.ready_target_count(), 2);
    assert!(!drain.0.load(Ordering::SeqCst));

    let initial = backend.target_route("initial").unwrap().unwrap();
    assert_eq!(initial.session_id(), "flat-initial");
    assert_eq!(initial.browser_context_id(), "context-a");
    assert_eq!(initial.tenant_id(), &first_tenant);
    assert_eq!(initial.owner_session_id(), &first_session);
    assert_eq!(initial.ownership_fence(), &first_ownership);
    let catch_up = backend.target_route("catch-up").unwrap().unwrap();
    assert_eq!(catch_up.session_id(), "flat-catch-up");
    assert_eq!(catch_up.browser_context_id(), "context-b");
    assert_eq!(catch_up.tenant_id(), &second_tenant);
    assert_eq!(catch_up.owner_session_id(), &second_session);
    assert_eq!(catch_up.ownership_fence(), &second_ownership);

    write_message(
        &mut event_writer,
        json!({
            "method": "Target.targetDestroyed",
            "params": {"targetId": "catch-up"},
        }),
    )
    .await;
    tokio::time::timeout(Duration::from_millis(200), async {
        while manager.ready_target_count() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("targetDestroyed must remove the exact target from the manager");
    assert!(backend.target_route("catch-up").unwrap().is_none());
    assert!(manager.has_ready_target("initial"));
    assert!(manager.is_ready());

    write_message(
        &mut event_writer,
        json!({
            "method": "Target.detachedFromTarget",
            "params": {"sessionId": "flat-initial", "targetId": "initial"},
        }),
    )
    .await;
    tokio::time::timeout(Duration::from_millis(200), async {
        while manager.ready_target_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detachedFromTarget must remove the exact target from the manager");
    assert!(!manager.has_ready_target("initial"));
    assert!(manager.is_ready());
}

#[tokio::test]
async fn cleanup_accepts_terminal_event_order_but_rejects_a_mismatched_retired_session() {
    for (order, first_method, second_method) in [
        (
            "detach then destroy",
            "Target.detachedFromTarget",
            "Target.targetDestroyed",
        ),
        (
            "destroy then detach",
            "Target.targetDestroyed",
            "Target.detachedFromTarget",
        ),
    ] {
        let drain = Arc::new(Drain(AtomicBool::new(false)));
        let (owner, manager) = ChromiumConnectionOwner::new_bounded(
            identity(),
            connection_config(),
            fence(),
            8,
            drain.clone(),
        )
        .unwrap();
        let backend = owner.target_manager_backend();
        let (pipes, mut command_reader, mut event_writer) = pipe_pair();
        let accept = tokio::spawn({
            let owner = owner.clone();
            async move { owner.accept_cdp_pipes(pipes).await }
        });
        qualify(&mut command_reader, &mut event_writer).await;
        assert_eq!(accept.await.unwrap(), Ok(()));
        bootstrap_empty(manager.clone(), &mut command_reader, &mut event_writer).await;

        let tenant_id = TenantId::new();
        let session_id = SessionId::new();
        let ownership = ownership_fence();
        let target_id = if first_method == "Target.detachedFromTarget" {
            "detach-first-target"
        } else {
            "destroy-first-target"
        };
        let flat_session_id = if first_method == "Target.detachedFromTarget" {
            "flat-detach-first"
        } else {
            "flat-destroy-first"
        };
        create_owned_primary(
            owner.chromium_driver(IsolationProfile::SharedContext),
            tenant_id,
            session_id.clone(),
            ownership.clone(),
            "cleanup-context",
            target_id,
            flat_session_id,
            &mut command_reader,
            &mut event_writer,
        )
        .await;

        let cleanup = tokio::task::spawn_blocking({
            let driver = owner.chromium_driver(IsolationProfile::SharedContext);
            let session_id = session_id.clone();
            let ownership = ownership.clone();
            move || driver.close_context_fenced(&session_id, &ownership)
        });
        let dispose = read_command(&mut command_reader).await;
        assert_eq!(dispose["method"], "Target.disposeBrowserContext");

        for method in [first_method, second_method] {
            let params = if method == "Target.detachedFromTarget" {
                json!({"sessionId": flat_session_id, "targetId": target_id})
            } else {
                json!({"targetId": target_id})
            };
            write_message(
                &mut event_writer,
                json!({
                    "method": method,
                    "params": params,
                }),
            )
            .await;
        }
        respond(&mut event_writer, &dispose, json!({})).await;

        assert_eq!(cleanup.await.unwrap(), Ok(()), "{order}");
        let route_removed = tokio::time::timeout(Duration::from_millis(200), async {
            while manager.ready_target_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            route_removed.is_ok(),
            "{order} must remove the final target route"
        );
        assert!(
            matches!(backend.target_route(target_id), Ok(None)),
            "{order} must leave the owner actor live with no stale route"
        );
        assert!(!drain.0.load(Ordering::SeqCst), "{order} must not drain");
        assert!(!manager.is_tainted(), "{order} must not taint the manager");
        assert!(manager.is_ready(), "{order} must remain ready");

        write_message(
            &mut event_writer,
            json!({
                "method": "Target.detachedFromTarget",
                "params": {
                    "sessionId": "wrong-retired-session",
                    "targetId": target_id,
                },
            }),
        )
        .await;
        let mismatch_rejected = tokio::time::timeout(Duration::from_millis(200), async {
            while !drain.0.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            mismatch_rejected.is_ok(),
            "{order} must reject a mismatched retired session"
        );
        assert!(manager.is_tainted());
    }
}

#[tokio::test]
async fn unknown_target_lifecycle_event_drains_the_shard() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        fence(),
        8,
        drain.clone(),
    )
    .unwrap();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));

    write_message(
        &mut event_writer,
        json!({
            "method": "Target.targetDestroyed",
            "params": {"targetId": "never-attached"},
        }),
    )
    .await;
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an unknown target lifecycle event must drain immediately");
    assert!(manager.is_tainted());
}

#[tokio::test]
async fn close_target_requires_an_explicit_success_true_result() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        fence(),
        8,
        drain.clone(),
    )
    .unwrap();
    let mut backend = owner.target_manager_backend();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut command_reader, &mut event_writer).await;
    create_owned_primary(
        owner.chromium_driver(IsolationProfile::SharedContext),
        TenantId::new(),
        SessionId::new(),
        ownership_fence(),
        "context",
        "refused-close",
        "flat-refused",
        &mut command_reader,
        &mut event_writer,
    )
    .await;
    let close = tokio::task::spawn_blocking(move || {
        backend.close_paused_target(&PausedTarget::new("refused-close", TargetKind::Page));
    });
    let command = read_command(&mut command_reader).await;
    assert_eq!(command["method"], "Target.closeTarget");
    respond(&mut event_writer, &command, json!({"success": false})).await;
    close.await.unwrap();

    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a false close result must fail closed");
    assert!(manager.is_tainted());
}

#[tokio::test]
async fn concurrent_backend_calls_are_serialized_by_the_single_owner_actor() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) =
        ChromiumConnectionOwner::new_bounded(identity(), connection_config(), fence(), 8, drain)
            .unwrap();
    let backend = owner.target_manager_backend();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));

    bootstrap_empty(manager, &mut command_reader, &mut event_writer).await;
    create_owned_primary(
        owner.chromium_driver(IsolationProfile::SharedContext),
        TenantId::new(),
        SessionId::new(),
        ownership_fence(),
        "context",
        "one",
        "flat-one",
        &mut command_reader,
        &mut event_writer,
    )
    .await;

    let first = tokio::task::spawn_blocking({
        let mut backend = backend.clone();
        move || {
            backend.run_stage(
                &PausedTarget::new("one", TargetKind::Page),
                BootstrapStage::RunFeatureHooks,
            )
        }
    });
    let first_command = read_command(&mut command_reader).await;
    assert_eq!(first_command["method"], "Runtime.enable");
    let second = tokio::task::spawn_blocking({
        let mut backend = backend.clone();
        move || {
            backend.run_stage(
                &PausedTarget::new("one", TargetKind::Page),
                BootstrapStage::RunFeatureHooks,
            )
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut command_reader))
            .await
            .is_err(),
        "the owner must not dispatch a second command while the first is pending"
    );
    respond(&mut event_writer, &first_command, json!({})).await;
    let second_command = read_command(&mut command_reader).await;
    assert_eq!(second_command["method"], "Runtime.enable");
    assert_eq!(first_command["sessionId"], second_command["sessionId"]);
    respond(&mut event_writer, &second_command, json!({})).await;
    assert_eq!(first.await.unwrap(), Ok(()));
    assert_eq!(second.await.unwrap(), Ok(()));
}

#[tokio::test]
async fn attach_observed_while_a_stage_command_is_pending_is_not_lost() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) =
        ChromiumConnectionOwner::new_bounded(identity(), connection_config(), fence(), 8, drain)
            .unwrap();
    let backend = owner.target_manager_backend();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));

    bootstrap_empty(manager.clone(), &mut command_reader, &mut event_writer).await;
    create_owned_primary(
        owner.chromium_driver(IsolationProfile::SharedContext),
        TenantId::new(),
        SessionId::new(),
        ownership_fence(),
        "context",
        "one",
        "flat-one",
        &mut command_reader,
        &mut event_writer,
    )
    .await;
    assert_eq!(manager.ready_target_count(), 1);

    let stage = tokio::task::spawn_blocking({
        let mut backend = backend.clone();
        move || {
            backend.run_stage(
                &PausedTarget::new("one", TargetKind::Page),
                BootstrapStage::RunFeatureHooks,
            )
        }
    });
    let pending = read_command(&mut command_reader).await;
    assert_eq!(pending["method"], "Runtime.enable");
    write_message(
        &mut event_writer,
        attached("two", "flat-two", "context", "page"),
    )
    .await;
    respond(&mut event_writer, &pending, json!({})).await;
    assert_eq!(stage.await.unwrap(), Ok(()));

    let first_late_command = tokio::time::timeout(
        Duration::from_millis(200),
        read_command(&mut command_reader),
    )
    .await
    .expect("the attached target must reach the manager event pump");
    assert_eq!(first_late_command["method"], "Target.setAutoAttach");
    respond(&mut event_writer, &first_late_command, json!({})).await;
    for _ in 1..6 {
        let command = read_command(&mut command_reader).await;
        respond(&mut event_writer, &command, json!({})).await;
    }
    tokio::time::timeout(Duration::from_millis(200), async {
        while manager.ready_target_count() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the late target must finish its bootstrap barrier");
}

#[tokio::test]
async fn malformed_attached_event_taints_and_drains_immediately() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        fence(),
        8,
        drain.clone(),
    )
    .unwrap();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));

    write_message(
        &mut event_writer,
        json!({
            "method":"Target.attachedToTarget",
            "params": {
                "sessionId":"flat-broken",
                "waitingForDebugger":true,
                "targetInfo":{"targetId":"broken", "type":"page"}
            }
        }),
    )
    .await;
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("malformed ownership must drain without waiting for bootstrap");
    assert!(manager.is_tainted());
}

#[tokio::test]
async fn lost_command_response_taints_and_drains_instead_of_resuming() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        fence(),
        8,
        drain.clone(),
    )
    .unwrap();
    let backend = owner.target_manager_backend();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut command_reader, &mut event_writer).await;
    create_owned_primary(
        owner.chromium_driver(IsolationProfile::SharedContext),
        TenantId::new(),
        SessionId::new(),
        ownership_fence(),
        "context",
        "lost",
        "flat-lost",
        &mut command_reader,
        &mut event_writer,
    )
    .await;
    let stage = tokio::task::spawn_blocking({
        let mut backend = backend.clone();
        move || {
            backend.run_stage(
                &PausedTarget::new("lost", TargetKind::Page),
                BootstrapStage::RunFeatureHooks,
            )
        }
    });
    let command = read_command(&mut command_reader).await;
    assert_eq!(command["method"], "Runtime.enable");
    drop(event_writer);
    assert!(stage.await.unwrap().is_err());
    assert!(drain.0.load(Ordering::SeqCst));
    assert!(manager.is_tainted());
}

#[tokio::test]
async fn rejected_target_is_closed_while_still_paused_and_is_never_resumed() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        fence(),
        8,
        drain.clone(),
    )
    .unwrap();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));

    bootstrap_empty(manager.clone(), &mut command_reader, &mut event_writer).await;
    create_owned_primary(
        owner.chromium_driver(IsolationProfile::SharedContext),
        TenantId::new(),
        SessionId::new(),
        ownership_fence(),
        "context",
        "primary",
        "flat-primary",
        &mut command_reader,
        &mut event_writer,
    )
    .await;
    write_message(
        &mut event_writer,
        attached("prerender", "flat-prerender", "context", "prerender"),
    )
    .await;
    let close = tokio::time::timeout(
        Duration::from_millis(200),
        read_command(&mut command_reader),
    )
    .await
    .expect("a policy-rejected paused target must be closed before drain");
    assert_eq!(close["method"], "Target.closeTarget");
    assert_eq!(close["params"], json!({"targetId":"prerender"}));
    respond(&mut event_writer, &close, json!({"success":true})).await;
    tokio::time::timeout(Duration::from_millis(200), async {
        while !manager.is_tainted() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the rejected target must taint the ready shard");
    assert!(drain.0.load(Ordering::SeqCst));
    assert!(manager.is_tainted());
}

#[tokio::test]
async fn owner_event_forwarding_overflow_is_fail_closed() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        fence(),
        1,
        drain.clone(),
    )
    .unwrap();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut command_reader, &mut event_writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut command_reader, &mut event_writer).await;
    create_owned_primary(
        owner.chromium_driver(IsolationProfile::SharedContext),
        TenantId::new(),
        SessionId::new(),
        ownership_fence(),
        "context",
        "primary",
        "flat-primary",
        &mut command_reader,
        &mut event_writer,
    )
    .await;
    write_message(
        &mut event_writer,
        attached("first", "flat-first", "context", "page"),
    )
    .await;
    let blocked_bootstrap = read_command(&mut command_reader).await;
    assert_eq!(blocked_bootstrap["method"], "Target.setAutoAttach");
    write_message(
        &mut event_writer,
        attached("overflow", "flat-overflow", "context", "page"),
    )
    .await;
    write_message(
        &mut event_writer,
        attached("overflow-again", "flat-overflow-again", "context", "page"),
    )
    .await;
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded ingress overflow must drain immediately");
    assert!(manager.is_tainted());
}
