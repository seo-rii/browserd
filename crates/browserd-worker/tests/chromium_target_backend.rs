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

const PAGE_BOOTSTRAP_METHODS: [&str; 7] = [
    "Target.setAutoAttach",
    "Network.enable",
    "Runtime.enable",
    "Page.enable",
    "Page.getFrameTree",
    "Page.setInterceptFileChooserDialog",
    "Runtime.runIfWaitingForDebugger",
];

async fn respond_page_bootstrap(writer: &mut Sender, command: &Value) {
    let session = command["sessionId"]
        .as_str()
        .expect("page bootstrap must have a flattened route");
    // Keep the protocol FrameId distinct from the TargetId, and bind its default realm.
    let frame = format!("frame-{session}");
    if command["method"] == "Runtime.enable" {
        write_message(
            writer,
            json!({
                "method":"Runtime.executionContextCreated", "sessionId":session,
                "params":{"context":{
                    "id":1,"uniqueId":format!("realm-{session}"),"origin":"about:blank","name":"",
                    "auxData":{"isDefault":true,"type":"default","frameId":frame}
                }}
            }),
        )
        .await;
    }
    let result = if command["method"] == "Page.getFrameTree" {
        json!({"frameTree":{"frame":{"id":frame,"url":"about:blank"}}})
    } else {
        json!({})
    };
    respond(writer, command, result).await;
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
    for method in PAGE_BOOTSTRAP_METHODS {
        let command = read_command(reader).await;
        assert_eq!(command["method"], method);
        assert_eq!(command["sessionId"], flat_session_id);
        respond_page_bootstrap(writer, &command).await;
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
    assert_eq!(first_late_command["sessionId"], "flat-two");
    respond_page_bootstrap(&mut event_writer, &first_late_command).await;
    for method in PAGE_BOOTSTRAP_METHODS.iter().skip(1) {
        let command = read_command(&mut command_reader).await;
        assert_eq!(command["method"], *method);
        assert_eq!(command["sessionId"], "flat-two");
        respond_page_bootstrap(&mut event_writer, &command).await;
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

mod pooled_contexts {
    use super::*;
    use browserd_core::{
        EgressFence, LeaseId, PlacementFence, RouteGeneration, SessionIncarnation,
    };
    use browserd_sandbox::{
        ChromiumBinaryDigest, ChromiumProcessProfile, ContextEgressBinding,
        ContextEgressReleaseReceipt, ContextEgressRequest, ContextRoutePolicy,
        DedicatedEgressProxyBinding, DedicatedEgressSpec, EgressPolicyBinding, LaunchSpec,
    };
    use browserd_worker::{
        DependencyError, OwnerContextPolicy, WorkerSessionOptionsV1, WorkerViewport,
    };
    use std::time::Instant;

    struct Session {
        tenant: TenantId,
        id: SessionId,
        owner: OwnershipFence,
        binding: ContextEgressBinding,
    }

    fn session(shard: &ShardFence, tenant: TenantId, route: u64) -> Session {
        let id = SessionId::new();
        let owner = OwnershipFence::new(shard.owner().worker_id().clone(), 11, route + 6, 3);
        let request = ContextEgressRequest::new(
            tenant.clone(),
            owner.as_placement_fence(),
            DedicatedEgressSpec::new(
                EgressFence::new(
                    shard.clone(),
                    RouteGeneration::new(route).unwrap(),
                    id.clone(),
                    SessionIncarnation::new(3).unwrap(),
                ),
                EgressPolicyBinding::new("public", [3; 32]).unwrap(),
                Duration::from_secs(120),
            )
            .unwrap(),
        )
        .unwrap();
        let proxy: DedicatedEgressProxyBinding = serde_json::from_value(json!({
            "tenant_id":tenant,"egress_fence":request.egress().egress_fence(),
            "policy_binding":request.egress().policy_binding(),"namespace_identity":{"device":7,"inode":42},
            "reservation_generation":LeaseId::new(),"attachment_generation":LeaseId::new(),
            "proxy_address":format!("127.0.0.1:{}",4100+route)
        })).unwrap();
        Session {
            tenant,
            id,
            owner,
            binding: ContextEgressBinding::new(request, 19, 23, proxy, Duration::from_secs(60))
                .unwrap(),
        }
    }

    fn options() -> WorkerSessionOptionsV1 {
        WorkerSessionOptionsV1 {
            workload_class_hint: "interactive".to_owned(),
            viewport: WorkerViewport {
                width: 800,
                height: 600,
                device_scale_factor: 1,
            },
            locale: "en-US".to_owned(),
            timezone: "UTC".to_owned(),
            user_agent: None,
            network_policy_id: "public".to_owned(),
            network_class: "public".to_owned(),
            checkpoint_ref: None,
            dialog_policy: "auto_dismiss".to_owned(),
            feature_profile: "standard".to_owned(),
            ttl_seconds: 1800,
            idle_timeout_seconds: 600,
            metadata: Default::default(),
        }
    }

    async fn register(owner: &Arc<ChromiumConnectionOwner<Drain>>, session: &Session) {
        let backend = owner.target_manager_backend();
        let tenant = session.tenant.clone();
        let id = session.id.clone();
        let fence = session.owner.clone();
        let binding = session.binding.clone();
        let valid_until = Instant::now() + Duration::from_secs(30);
        assert_eq!(
            tokio::task::spawn_blocking(move || backend.register_context_egress(
                tenant,
                id,
                fence,
                binding,
                valid_until
            ))
            .await
            .unwrap(),
            Ok(())
        );
    }

    async fn create(
        owner: &Arc<ChromiumConnectionOwner<Drain>>,
        session: &Session,
        ordinal: u64,
        reader: &mut Receiver,
        writer: &mut Sender,
    ) {
        let driver = owner.chromium_driver(IsolationProfile::SharedContext);
        let tenant = session.tenant.clone();
        let id = session.id.clone();
        let fence = session.owner.clone();
        let create = tokio::task::spawn_blocking(move || {
            driver.create_context_owned_with_options(&tenant, &id, &fence, &options())
        });
        let context = format!("pooled-context-{ordinal}");
        let target = format!("pooled-page-{ordinal}");
        let flat = format!("pooled-flat-{ordinal}");
        let command = read_command(reader).await;
        assert_eq!(command["method"], "Target.createBrowserContext");
        assert_eq!(
            command["params"],
            json!({"disposeOnDetach":true,
            "proxyServer":format!("http://{}",session.binding.proxy_binding().proxy_address()),"proxyBypassList":"<-loopback>"})
        );
        respond(writer, &command, json!({"browserContextId":context})).await;
        let command = read_command(reader).await;
        assert_eq!(command["method"], "Browser.setDownloadBehavior");
        assert_eq!(
            command["params"],
            json!({"behavior":"deny","browserContextId":context,"eventsEnabled":true})
        );
        respond(writer, &command, json!({})).await;
        let command = read_command(reader).await;
        assert_eq!(command["method"], "Target.createTarget");
        assert_eq!(command["params"]["browserContextId"], context);
        write_message(writer, attached(&target, &flat, &context, "page")).await;
        respond(writer, &command, json!({"targetId":target})).await;
        for method in [
            "Target.setAutoAttach",
            "Emulation.setDeviceMetricsOverride",
            "Network.setUserAgentOverride",
            "Network.enable",
            "Runtime.enable",
            "Page.enable",
            "Page.getFrameTree",
            "Page.setInterceptFileChooserDialog",
            "Runtime.runIfWaitingForDebugger",
        ] {
            let command = read_command(reader).await;
            assert_eq!(command["method"], method);
            assert_eq!(command["sessionId"], flat);
            respond_page_bootstrap(writer, &command).await;
        }
        assert!(create.await.unwrap().is_ok());
    }

    async fn attach_worker(ordinal: u64, kind: &str, reader: &mut Receiver, writer: &mut Sender) {
        let target = format!("pooled-{kind}-{ordinal}");
        let flat = format!("flat-{kind}-{ordinal}");
        write_message(
            writer,
            attached(&target, &flat, &format!("pooled-context-{ordinal}"), kind),
        )
        .await;
        for method in [
            "Target.setAutoAttach",
            "Network.enable",
            "Runtime.runIfWaitingForDebugger",
        ] {
            let command = read_command(reader).await;
            assert_eq!(command["method"], method);
            assert_eq!(command["sessionId"], flat);
            respond(writer, &command, json!({})).await;
        }
    }

    async fn verify_sibling_cleanup(unknown: bool) {
        let drain = Arc::new(Drain(AtomicBool::new(false)));
        let shard = fence();
        let first = session(&shard, TenantId::new(), 1);
        let second = session(&shard, TenantId::new(), 2);
        let mut expected = identity();
        expected.launch_profile_digest = Sha256Digest::from_hex(&"03".repeat(32)).unwrap();
        let launch = LaunchSpec::production(
            first.tenant.clone(),
            first.binding.request().egress().clone(),
            ChromiumBinaryDigest::new([0; 32]),
        )
        .with_process_profile(
            ChromiumProcessProfile::native_locale(
                "en-US",
                "UTC",
                ChromiumBinaryDigest::new([3; 32]),
                ChromiumBinaryDigest::new([4; 32]),
                ChromiumBinaryDigest::new([5; 32]),
            )
            .unwrap(),
        )
        .unwrap()
        .with_context_route_policy(
            ContextRoutePolicy::new(PlacementFence::new(11, 7, 3), false, 8, 500).unwrap(),
        )
        .unwrap();
        let (owner, manager) = ChromiumConnectionOwner::new_bounded_for_pooled_launch(
            expected,
            connection_config(),
            shard,
            16,
            drain.clone(),
            launch,
            OwnerContextPolicy::shared(8, 500).unwrap(),
        )
        .unwrap();
        let (pipes, mut reader, mut writer) = pipe_pair();
        let pipes = pipes
            .with_egress_proxy_binding(first.binding.proxy_binding().clone())
            .unwrap();
        let accept = tokio::spawn({
            let owner = owner.clone();
            async move { owner.accept_cdp_pipes(pipes).await }
        });
        qualify(&mut reader, &mut writer).await;
        assert_eq!(accept.await.unwrap(), Ok(()));
        bootstrap_empty(manager.clone(), &mut reader, &mut writer).await;
        register(&owner, &first).await;
        create(&owner, &first, 1, &mut reader, &mut writer).await;
        register(&owner, &second).await;
        create(&owner, &second, 2, &mut reader, &mut writer).await;
        for ordinal in [1, 2] {
            for kind in ["shared_worker", "service_worker"] {
                attach_worker(ordinal, kind, &mut reader, &mut writer).await;
            }
        }
        let backend = owner.target_manager_backend();
        let early =
            ContextEgressReleaseReceipt::new(first.binding.request().clone(), 19, 23).unwrap();
        assert!(
            tokio::task::spawn_blocking(move || backend.confirm_context_egress_released(early))
                .await
                .unwrap()
                .is_err(),
            "active Chromium ownership prevents route release"
        );
        let driver = owner.chromium_driver(IsolationProfile::SharedContext);
        let id = first.id.clone();
        let fence = first.owner.clone();
        let close = tokio::task::spawn_blocking(move || driver.close_context_fenced(&id, &fence));
        let command = read_command(&mut reader).await;
        assert_eq!(command["method"], "Target.disposeBrowserContext");
        assert_eq!(
            command["params"],
            json!({"browserContextId":"pooled-context-1"})
        );
        respond(&mut writer, &command, json!({})).await;
        let command = read_command(&mut reader).await;
        assert_eq!(command["method"], "Target.getTargets");
        let mut targets = vec![
            json!({"targetId":"pooled-page-2","type":"page","browserContextId":"pooled-context-2"}),
            json!({"targetId":"pooled-shared_worker-2","type":"shared_worker"}),
            json!({"targetId":"pooled-service_worker-2","type":"service_worker","browserContextId":"pooled-context-2"}),
        ];
        if unknown {
            targets.push(json!({"targetId":"foreign-worker","type":"service_worker"}));
        }
        respond(&mut writer, &command, json!({"targetInfos":targets})).await;
        if unknown {
            assert_eq!(close.await.unwrap(), Err(DependencyError::OutcomeUncertain));
            tokio::time::timeout(Duration::from_secs(1), async {
                while !drain.0.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await
                }
            })
            .await
            .unwrap();
            assert!(manager.is_tainted());
            return;
        }
        let command = read_command(&mut reader).await;
        assert_eq!(command["method"], "Target.getBrowserContexts");
        respond(
            &mut writer,
            &command,
            json!({"browserContextIds":["pooled-context-2"]}),
        )
        .await;
        assert_eq!(close.await.unwrap(), Ok(()));
        assert!(manager.has_ready_target("pooled-page-2"));
        assert!(manager.has_ready_target("pooled-shared_worker-2"));
        assert!(!manager.has_ready_target("pooled-page-1"));
        assert!(!drain.0.load(Ordering::SeqCst));
        assert!(!manager.is_tainted());
        let backend = owner.target_manager_backend();
        let released =
            ContextEgressReleaseReceipt::new(first.binding.request().clone(), 19, 23).unwrap();
        assert_eq!(
            tokio::task::spawn_blocking(move || {
                backend.confirm_context_egress_released(released.clone())?;
                backend.confirm_context_egress_released(released)
            })
            .await
            .unwrap(),
            Ok(())
        );
        assert_eq!(owner.shutdown_cdp().await, Ok(()));
    }

    #[tokio::test]
    async fn native_options_sibling_pages_and_workers_survive_exact_context_retirement() {
        verify_sibling_cleanup(false).await;
    }

    #[tokio::test]
    async fn unowned_contextless_worker_in_disposal_proof_taints_the_shard() {
        verify_sibling_cleanup(true).await;
    }
}
