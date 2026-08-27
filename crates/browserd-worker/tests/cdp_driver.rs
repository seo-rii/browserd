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
use browserd_worker::{
    ActionExecutionResult, CdpPipeAcceptor, ChromiumConnectionOwner, ChromiumDriver,
    DependencyError, TargetManagerDrain,
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
    let digest = Sha256Digest::from_hex(&"00".repeat(32)).expect("digest should be valid");
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
            WorkerId::new("cdp-driver-worker").unwrap(),
            WorkerEpoch::new(17).unwrap(),
        ),
        ShardId::new(),
        LaunchGeneration::new(3).unwrap(),
    )
}

fn ownership_fence() -> OwnershipFence {
    OwnershipFence::new(WorkerId::new("cdp-driver-worker").unwrap(), 17, 23, 29)
}

fn pipe_pair() -> (ChromiumCdpPipes, Receiver, Sender) {
    let (command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe");
    let parent = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader).unwrap();
    (
        parent,
        Receiver::from_owned_fd(command_reader).unwrap(),
        Sender::from_owned_fd(event_writer).unwrap(),
    )
}

async fn read_command(reader: &mut Receiver) -> Value {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = reader.read(&mut byte).await.expect("command read");
        if read == 0 || byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    serde_json::from_slice(&bytes).expect("valid CDP command")
}

async fn write_message(writer: &mut Sender, message: Value) {
    let bytes = serde_json::to_vec(&message).unwrap();
    writer.write_all(&bytes).await.unwrap();
    writer.write_all(&[0]).await.unwrap();
}

async fn respond(writer: &mut Sender, command: &Value, result: Value) {
    write_message(
        writer,
        json!({
            "id": command["id"].as_u64().unwrap(),
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

async fn bootstrap_empty(
    manager: Arc<browserd_worker::ChromiumTargetManager<Drain>>,
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

async fn create_owned_context(
    driver: browserd_worker::CdpChromiumDriver,
    tenant_id: TenantId,
    session_id: SessionId,
    fence: OwnershipFence,
    reader: &mut Receiver,
    writer: &mut Sender,
) -> PageId {
    let create = tokio::task::spawn_blocking(move || {
        driver.create_context_owned(&tenant_id, &session_id, &fence)
    });
    let context = read_command(reader).await;
    assert_eq!(context["method"], "Target.createBrowserContext");
    assert_eq!(context["params"]["disposeOnDetach"], true);
    respond(
        writer,
        &context,
        json!({"browserContextId": "owned-context"}),
    )
    .await;

    let target = read_command(reader).await;
    assert_eq!(target["method"], "Target.createTarget");
    assert_eq!(target["params"]["browserContextId"], "owned-context");
    write_message(
        writer,
        json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "flat-primary",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "primary-target",
                    "browserContextId": "owned-context",
                    "type": "page"
                }
            }
        }),
    )
    .await;
    respond(writer, &target, json!({"targetId": "primary-target"})).await;

    let mut methods = Vec::new();
    for _ in 0..6 {
        let command = read_command(reader).await;
        assert_eq!(command["sessionId"], "flat-primary");
        methods.push(command["method"].as_str().unwrap().to_owned());
        respond(writer, &command, json!({})).await;
    }
    assert_eq!(
        methods.last().map(String::as_str),
        Some("Runtime.runIfWaitingForDebugger")
    );
    create
        .await
        .unwrap()
        .expect("owned context should be ready")
}

#[tokio::test]
async fn context_and_primary_page_are_bound_to_full_ownership_before_resume() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let driver = owner.chromium_driver(IsolationProfile::SharedContext);
    let backend = owner.target_manager_backend();
    let (pipes, mut reader, mut writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut reader, &mut writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut reader, &mut writer).await;

    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let ownership = ownership_fence();
    let page_id = create_owned_context(
        driver.clone(),
        tenant_id.clone(),
        session_id.clone(),
        ownership.clone(),
        &mut reader,
        &mut writer,
    )
    .await;

    let route = backend.target_route("primary-target").unwrap().unwrap();
    assert_eq!(route.tenant_id(), &tenant_id);
    assert_eq!(route.owner_session_id(), &session_id);
    assert_eq!(route.ownership_fence(), &ownership);
    assert_eq!(
        driver.list_pages_owned(&tenant_id, &session_id, &ownership),
        Ok(vec![page_id.clone()])
    );
    assert!(manager.has_ready_target("primary-target"));
    assert!(!drain.0.load(Ordering::SeqCst));

    let wrong_session = SessionId::new();
    assert_eq!(
        driver.activate_page(&wrong_session, &page_id),
        Err(DependencyError::Rejected)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut reader))
            .await
            .is_err(),
        "cross-session ownership must be rejected before a CDP effect"
    );

    let stale = OwnershipFence::new(WorkerId::new("cdp-driver-worker").unwrap(), 17, 24, 29);
    assert_eq!(
        driver.close_context_fenced(&session_id, &stale),
        Err(DependencyError::Rejected)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut reader))
            .await
            .is_err(),
        "a stale ownership fence must be rejected before context disposal"
    );

    let dispose = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        let ownership = ownership.clone();
        move || driver.close_context_fenced(&session_id, &ownership)
    });
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Target.disposeBrowserContext");
    assert_eq!(
        command["params"],
        json!({"browserContextId": "owned-context"})
    );
    respond(&mut writer, &command, json!({})).await;
    assert_eq!(dispose.await.unwrap(), Ok(()));
    assert_eq!(driver.close_context_fenced(&session_id, &ownership), Ok(()));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut reader))
            .await
            .is_err(),
        "an exact disposal retry must not issue a second browser effect"
    );
}

#[tokio::test]
async fn unknown_context_attach_is_rejected_before_any_resume_effect() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let (pipes, mut reader, mut writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut reader, &mut writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut reader, &mut writer).await;

    write_message(
        &mut writer,
        json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "flat-rogue",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "rogue-target",
                    "browserContextId": "unknown-context",
                    "type": "page"
                }
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
    .expect("unknown context must drain the shard");
    assert!(manager.is_tainted());
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(30), reader.read(&mut byte)).await;
    assert!(
        matches!(read, Err(_) | Ok(Ok(0))),
        "an unknown context must never emit a resume command"
    );
}

#[tokio::test]
async fn page_lifecycle_and_bounded_actions_use_the_owned_flattened_route() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let driver = owner.chromium_driver(IsolationProfile::SharedContext);
    let (pipes, mut reader, mut writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut reader, &mut writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut reader, &mut writer).await;

    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let ownership = ownership_fence();
    let page_id = create_owned_context(
        driver.clone(),
        tenant_id.clone(),
        session_id.clone(),
        ownership.clone(),
        &mut reader,
        &mut writer,
    )
    .await;

    let create_page = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        move || driver.create_page(&session_id)
    });
    let target = read_command(&mut reader).await;
    assert_eq!(target["method"], "Target.createTarget");
    assert_eq!(target["params"]["browserContextId"], "owned-context");
    write_message(
        &mut writer,
        json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "flat-second",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "second-target",
                    "browserContextId": "owned-context",
                    "type": "page"
                }
            }
        }),
    )
    .await;
    respond(&mut writer, &target, json!({"targetId": "second-target"})).await;
    for _ in 0..6 {
        let command = read_command(&mut reader).await;
        assert_eq!(command["sessionId"], "flat-second");
        respond(&mut writer, &command, json!({})).await;
    }
    let second_page_id = create_page.await.unwrap().unwrap();
    assert_ne!(second_page_id, page_id);
    let mut pages = driver
        .list_pages_owned(&tenant_id, &session_id, &ownership)
        .unwrap();
    pages.sort();
    let mut expected_pages = vec![page_id.clone(), second_page_id.clone()];
    expected_pages.sort();
    assert_eq!(pages, expected_pages);

    let close_second = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        let second_page_id = second_page_id.clone();
        move || driver.close_page(&session_id, &second_page_id)
    });
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Target.closeTarget");
    assert_eq!(command["params"], json!({"targetId": "second-target"}));
    respond(&mut writer, &command, json!({"success": true})).await;
    assert_eq!(close_second.await.unwrap(), Ok(()));
    assert_eq!(driver.close_page(&session_id, &second_page_id), Ok(()));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut reader))
            .await
            .is_err(),
        "an in-progress exact close retry must not issue another effect"
    );
    write_message(
        &mut writer,
        json!({
            "method": "Target.targetDestroyed",
            "params": {"targetId": "second-target"}
        }),
    )
    .await;
    tokio::time::timeout(Duration::from_millis(200), async {
        while manager.has_ready_target("second-target") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the exact destroyed page must leave target readiness");
    assert_eq!(
        driver.list_pages_owned(&tenant_id, &session_id, &ownership),
        Ok(vec![page_id.clone()])
    );

    let activate = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        let page_id = page_id.clone();
        move || driver.activate_page(&session_id, &page_id)
    });
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Target.activateTarget");
    assert_eq!(command["params"], json!({"targetId": "primary-target"}));
    respond(&mut writer, &command, json!({})).await;
    assert_eq!(activate.await.unwrap(), Ok(()));

    let navigate = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        let page_id = page_id.clone();
        move || {
            driver.execute_action(
                &session_id,
                Some(&page_id),
                br#"{"type":"navigate","url":"https://example.test/path"}"#,
            )
        }
    });
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Page.navigate");
    assert_eq!(command["sessionId"], "flat-primary");
    assert_eq!(command["params"]["url"], "https://example.test/path");
    respond(
        &mut writer,
        &command,
        json!({"frameId": "frame", "loaderId": "loader"}),
    )
    .await;
    assert!(matches!(
        navigate.await.unwrap(),
        ActionExecutionResult::Succeeded(_)
    ));

    assert!(matches!(
        driver.execute_action(
            &session_id,
            Some(&page_id),
            br#"{"type":"evaluate","expression":"steal()"}"#,
        ),
        ActionExecutionResult::FailedKnown(_)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut reader))
            .await
            .is_err(),
        "unsupported actions must be rejected before CDP"
    );

    let close = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        let page_id = page_id.clone();
        move || driver.close_page(&session_id, &page_id)
    });
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Target.closeTarget");
    respond(&mut writer, &command, json!({"success": false})).await;
    assert_eq!(close.await.unwrap(), Err(DependencyError::OutcomeUncertain));
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("uncertain close must drain the shard");
    assert!(drain.0.load(Ordering::SeqCst));
}
