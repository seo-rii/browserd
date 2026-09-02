#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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
    DependencyError, TargetManagerDrain, WorkerSessionOptionsV1, WorkerViewport,
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

fn session_options() -> WorkerSessionOptionsV1 {
    WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1_440,
            height: 900,
            device_scale_factor: 2,
        },
        locale: "ko-KR".to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: Some("browserd-options-test/1.0".to_owned()),
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 1_800,
        idle_timeout_seconds: 600,
        metadata: Default::default(),
    }
}

fn options_bootstrap_commands() -> [(&'static str, Value); 10] {
    [
        (
            "Target.setAutoAttach",
            json!({
                "autoAttach": true,
                "waitForDebuggerOnStart": true,
                "flatten": true,
            }),
        ),
        (
            "Emulation.setDeviceMetricsOverride",
            json!({
                "width": 1_440,
                "height": 900,
                "deviceScaleFactor": 2,
                "mobile": false,
            }),
        ),
        ("Emulation.setLocaleOverride", json!({"locale": "ko-KR"})),
        (
            "Emulation.setTimezoneOverride",
            json!({"timezoneId": "Asia/Seoul"}),
        ),
        (
            "Network.setUserAgentOverride",
            json!({"userAgent": "browserd-options-test/1.0"}),
        ),
        ("Network.enable", json!({})),
        ("Runtime.enable", json!({})),
        ("Page.enable", json!({})),
        (
            "Page.setInterceptFileChooserDialog",
            json!({"enabled": true}),
        ),
        ("Runtime.runIfWaitingForDebugger", json!({})),
    ]
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

async fn has_no_command_bytes(reader: &mut Receiver, allow_eof: bool) -> bool {
    match tokio::time::timeout(Duration::from_millis(30), reader.read_u8()).await {
        Err(_) => true,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => allow_eof,
        Ok(Err(_)) | Ok(Ok(_)) => false,
    }
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

fn frame_navigated(session_id: &str, frame_id: &str, loader_id: &str, url: &str) -> Value {
    json!({
        "method": "Page.frameNavigated",
        "sessionId": session_id,
        "params": {
            "frame": {
                "id": frame_id,
                "loaderId": loader_id,
                "url": url,
                "domainAndRegistry": "example.test",
                "securityOrigin": "https://example.test",
                "mimeType": "text/html",
                "secureContextType": "Secure",
                "crossOriginIsolatedContextType": "NotIsolated",
                "gatedAPIFeatures": []
            },
            "type": "Navigation"
        }
    })
}

fn lifecycle_event(session_id: &str, method: &str) -> Value {
    json!({
        "method": method,
        "sessionId": session_id,
        "params": {"timestamp": 1.0}
    })
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

async fn create_owned_options_context(
    driver: browserd_worker::CdpChromiumDriver,
    tenant_id: TenantId,
    session_id: SessionId,
    fence: OwnershipFence,
    reader: &mut Receiver,
    writer: &mut Sender,
) -> PageId {
    let options = session_options();
    let create = tokio::task::spawn_blocking(move || {
        driver.create_context_owned_with_options(&tenant_id, &session_id, &fence, &options)
    });

    let context = read_command(reader).await;
    assert_eq!(context["method"], "Target.createBrowserContext");
    assert_eq!(context["params"]["disposeOnDetach"], true);
    respond(
        writer,
        &context,
        json!({"browserContextId": "options-context"}),
    )
    .await;

    let target = read_command(reader).await;
    assert_eq!(target["method"], "Target.createTarget");
    assert_eq!(target["params"]["browserContextId"], "options-context");
    write_message(
        writer,
        json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "flat-options-primary",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "options-primary",
                    "browserContextId": "options-context",
                    "type": "page"
                }
            }
        }),
    )
    .await;
    respond(writer, &target, json!({"targetId": "options-primary"})).await;

    let expected = options_bootstrap_commands();
    for (index, (method, params)) in expected.iter().enumerate() {
        let command = read_command(reader).await;
        assert_eq!(command["sessionId"], "flat-options-primary");
        assert_eq!(command["method"].as_str(), Some(*method));
        assert_eq!(&command["params"], params);
        if index + 1 == expected.len() {
            assert_eq!(*method, "Runtime.runIfWaitingForDebugger");
            assert!(
                !create.is_finished(),
                "context creation must remain blocked until resume is acknowledged"
            );
        }
        respond(writer, &command, json!({})).await;
    }

    create
        .await
        .unwrap()
        .expect("the options-aware primary target should become ready")
}

#[tokio::test]
async fn process_scoped_emulation_is_rejected_in_shared_context_isolation() {
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
    bootstrap_empty(manager, &mut reader, &mut writer).await;

    let options = session_options();
    let create = tokio::task::spawn_blocking(move || {
        driver.create_context_owned_with_options(
            &TenantId::new(),
            &SessionId::new(),
            &ownership_fence(),
            &options,
        )
    });
    let command = tokio::time::timeout(Duration::from_millis(30), read_command(&mut reader)).await;
    if let Ok(command) = &command {
        write_message(
            &mut writer,
            json!({
                "id": command["id"].as_u64().unwrap(),
                "error": {"code": -32000, "message": "test rejection"}
            }),
        )
        .await;
    }
    let result = create.await.unwrap();

    assert!(
        command.is_err(),
        "shared-context isolation must reject process-scoped emulation before a CDP effect"
    );
    assert_eq!(result, Err(DependencyError::Rejected));
    assert!(!drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn primary_target_owns_process_emulation_and_children_fail_closed() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let driver = owner.chromium_driver(IsolationProfile::DedicatedProcess);
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
    let second_driver = driver.clone();
    let primary_close_driver = driver.clone();
    let primary_session_id = session_id.clone();
    let primary_page_id = create_owned_options_context(
        driver.clone(),
        tenant_id.clone(),
        session_id.clone(),
        ownership.clone(),
        &mut reader,
        &mut writer,
    )
    .await;
    assert!(manager.has_ready_target("options-primary"));
    assert!(!drain.0.load(Ordering::SeqCst));

    let second_tenant_id = TenantId::new();
    let second_session_id = SessionId::new();
    let second_ownership = ownership_fence();
    let second_options = session_options();
    let second_create = tokio::task::spawn_blocking(move || {
        second_driver.create_context_owned_with_options(
            &second_tenant_id,
            &second_session_id,
            &second_ownership,
            &second_options,
        )
    });
    assert!(
        has_no_command_bytes(&mut reader, false).await,
        "a second options context must be rejected before a CDP effect"
    );
    assert_eq!(second_create.await.unwrap(), Err(DependencyError::Rejected));

    let close_page_id = primary_page_id.clone();
    let primary_close = tokio::task::spawn_blocking(move || {
        primary_close_driver.close_page(&primary_session_id, &close_page_id)
    });
    assert!(
        has_no_command_bytes(&mut reader, false).await,
        "the process-emulation owner must not be closed while the shard stays live"
    );
    assert_eq!(primary_close.await.unwrap(), Err(DependencyError::Rejected));

    let extra_page = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        move || driver.create_page(&session_id)
    });
    let extra_page_command =
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut reader)).await;
    if let Ok(command) = &extra_page_command {
        write_message(
            &mut writer,
            json!({
                "id": command["id"].as_u64().unwrap(),
                "error": {"code": -32000, "message": "test rejection"}
            }),
        )
        .await;
    }
    let extra_page_result = extra_page.await.unwrap();
    assert!(
        extra_page_command.is_err(),
        "a single-primary options context must reject create_page before a CDP effect"
    );
    assert_eq!(extra_page_result, Err(DependencyError::Rejected));

    write_message(
        &mut writer,
        json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "flat-options-popup",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "options-popup",
                    "browserContextId": "options-context",
                    "type": "page"
                }
            }
        }),
    )
    .await;
    let close = read_command(&mut reader).await;
    assert_eq!(close["method"], "Target.closeTarget");
    assert_eq!(close["params"], json!({"targetId": "options-popup"}));
    assert!(close.get("sessionId").is_none());

    let (list_started, list_started_rx) = tokio::sync::oneshot::channel();
    let list = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let tenant_id = tenant_id.clone();
        let session_id = session_id.clone();
        let ownership = ownership.clone();
        move || {
            let _ = list_started.send(());
            driver.list_pages_owned(&tenant_id, &session_id, &ownership)
        }
    });
    list_started_rx.await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    respond(&mut writer, &close, json!({"success": true})).await;
    assert_eq!(
        list.await.unwrap(),
        Ok(vec![primary_page_id]),
        "a paused child rejected by the bootstrap barrier must never be externally listed"
    );
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a child target without a verified emulation path must drain the shard");
    assert!(manager.is_tainted());
    assert!(!manager.has_ready_target("options-popup"));
    assert!(
        has_no_command_bytes(&mut reader, true).await,
        "an unverified child target must never receive bootstrap or resume commands"
    );
}

#[tokio::test]
async fn options_context_dispose_allows_owner_detach_before_the_response() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let driver = owner.chromium_driver(IsolationProfile::DedicatedProcess);
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
    create_owned_options_context(
        driver.clone(),
        tenant_id,
        session_id.clone(),
        ownership.clone(),
        &mut reader,
        &mut writer,
    )
    .await;
    assert!(manager.has_ready_target("options-primary"));

    let dispose = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        let ownership = ownership.clone();
        move || driver.close_context_fenced(&session_id, &ownership)
    });
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Target.disposeBrowserContext");

    let mut event_then_response = serde_json::to_vec(&json!({
        "method": "Target.detachedFromTarget",
        "params": {
            "sessionId": "flat-options-primary",
            "targetId": "options-primary"
        }
    }))
    .unwrap();
    event_then_response.push(0);
    event_then_response.extend(
        serde_json::to_vec(&json!({
            "id": command["id"].as_u64().unwrap(),
            "result": {}
        }))
        .unwrap(),
    );
    event_then_response.push(0);
    writer.write_all(&event_then_response).await.unwrap();

    assert_eq!(dispose.await.unwrap(), Ok(()));
    tokio::time::timeout(Duration::from_millis(200), async {
        while manager.has_ready_target("options-primary") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the detached primary route should leave readiness");
    assert!(!drain.0.load(Ordering::SeqCst));
    assert!(!manager.is_tainted());
    assert!(manager.is_ready());
    assert_eq!(driver.close_context_fenced(&session_id, &ownership), Ok(()));
    assert!(
        has_no_command_bytes(&mut reader, false).await,
        "an exact disposal retry must not issue a second browser effect"
    );
}

#[tokio::test]
async fn target_attach_during_context_dispose_is_immediately_fail_closed() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let driver = owner.chromium_driver(IsolationProfile::DedicatedProcess);
    let (pipes, mut reader, mut writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut reader, &mut writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut reader, &mut writer).await;

    let session_id = SessionId::new();
    let ownership = ownership_fence();
    create_owned_options_context(
        driver.clone(),
        TenantId::new(),
        session_id.clone(),
        ownership.clone(),
        &mut reader,
        &mut writer,
    )
    .await;

    let dispose = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        let ownership = ownership.clone();
        move || driver.close_context_fenced(&session_id, &ownership)
    });
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Target.disposeBrowserContext");
    write_message(
        &mut writer,
        json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "flat-dispose-race",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "dispose-race-target",
                    "browserContextId": "options-context",
                    "type": "page"
                }
            }
        }),
    )
    .await;

    assert_eq!(
        dispose.await.unwrap(),
        Err(DependencyError::OutcomeUncertain)
    );
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an attach after the dispose effect must immediately drain the shard");
    assert!(manager.is_tainted());
    assert!(!manager.has_ready_target("dispose-race-target"));
    assert!(
        has_no_command_bytes(&mut reader, true).await,
        "the racing paused target must never be bootstrapped or resumed"
    );
}

#[tokio::test]
async fn emulation_protocol_failure_closes_the_paused_target_without_resuming() {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let driver = owner.chromium_driver(IsolationProfile::DedicatedProcess);
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
    let options = session_options();
    let create = tokio::task::spawn_blocking(move || {
        driver.create_context_owned_with_options(&tenant_id, &session_id, &ownership, &options)
    });
    let context = read_command(&mut reader).await;
    respond(
        &mut writer,
        &context,
        json!({"browserContextId": "failed-options-context"}),
    )
    .await;
    let target = read_command(&mut reader).await;
    write_message(
        &mut writer,
        json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "flat-failed-options",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "failed-options-primary",
                    "browserContextId": "failed-options-context",
                    "type": "page"
                }
            }
        }),
    )
    .await;
    respond(
        &mut writer,
        &target,
        json!({"targetId": "failed-options-primary"}),
    )
    .await;

    for (expected, _) in options_bootstrap_commands().iter().take(3) {
        let command = read_command(&mut reader).await;
        assert_eq!(command["sessionId"], "flat-failed-options");
        assert_eq!(command["method"], *expected);
        respond(&mut writer, &command, json!({})).await;
    }
    let timezone = read_command(&mut reader).await;
    assert_eq!(timezone["method"], "Emulation.setTimezoneOverride");
    assert_eq!(timezone["sessionId"], "flat-failed-options");
    write_message(
        &mut writer,
        json!({
            "id": timezone["id"].as_u64().unwrap(),
            "error": {"code": -32000, "message": "timezone rejected"}
        }),
    )
    .await;

    let close = read_command(&mut reader).await;
    assert_eq!(close["method"], "Target.closeTarget");
    assert_eq!(
        close["params"],
        json!({"targetId": "failed-options-primary"})
    );
    assert!(close.get("sessionId").is_none());
    respond(&mut writer, &close, json!({"success": true})).await;
    assert!(create.await.unwrap().is_err());
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an emulation failure must drain the shard");
    assert!(manager.is_tainted());
    assert!(!manager.has_ready_target("failed-options-primary"));
    assert!(
        has_no_command_bytes(&mut reader, true).await,
        "commands after the rejected emulation stage, including resume, must not run"
    );
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

    assert!(matches!(
        driver.execute_action_until(
            &session_id,
            Some(&page_id),
            br#"{"type":"reload"}"#,
            Instant::now(),
        ),
        ActionExecutionResult::FailedKnown(reason) if reason == "action_timeout"
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut reader))
            .await
            .is_err(),
        "an expired action budget must be rejected before CDP dispatch"
    );
    assert!(!drain.0.load(Ordering::SeqCst));
    assert!(!manager.is_tainted());

    let navigate = tokio::task::spawn_blocking({
        let driver = driver.clone();
        let session_id = session_id.clone();
        let page_id = page_id.clone();
        move || {
            driver.execute_action(
                &session_id,
                Some(&page_id),
                br#"{"type":"navigate","url":"https://example.test/path","wait_until":"load"}"#,
            )
        }
    });
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Page.navigate");
    assert_eq!(command["sessionId"], "flat-primary");
    assert_eq!(
        command["params"],
        json!({"url": "https://example.test/path"})
    );
    respond(
        &mut writer,
        &command,
        json!({"frameId": "frame", "loaderId": "loader"}),
    )
    .await;
    write_message(
        &mut writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader",
            "https://example.test/path",
        ),
    )
    .await;
    write_message(
        &mut writer,
        lifecycle_event("flat-primary", "Page.domContentEventFired"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !navigate.is_finished(),
        "wait_until=load must outlast DOMContentLoaded"
    );
    write_message(
        &mut writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    assert_eq!(
        navigate.await.unwrap(),
        ActionExecutionResult::Succeeded(br#"{"ok":true}"#.to_vec())
    );

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

#[tokio::test]
async fn action_deadline_after_cdp_submission_is_unknown_and_fail_closed() {
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

    let session_id = SessionId::new();
    let page_id = create_owned_context(
        driver.clone(),
        TenantId::new(),
        session_id.clone(),
        ownership_fence(),
        &mut reader,
        &mut writer,
    )
    .await;
    let action = tokio::task::spawn_blocking(move || {
        driver.execute_action_until(
            &session_id,
            Some(&page_id),
            br#"{"type":"reload"}"#,
            Instant::now() + Duration::from_millis(100),
        )
    });
    let command = tokio::time::timeout(Duration::from_millis(500), read_command(&mut reader))
        .await
        .expect("the action must reach the CDP submission boundary");
    assert_eq!(command["method"], "Page.reload");
    assert_eq!(command["sessionId"], "flat-primary");

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), action)
            .await
            .expect("the absolute action deadline must end the call")
            .unwrap(),
        ActionExecutionResult::OutcomeUnknown
    );
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a deadline after CDP submission must drain the shard");
    assert!(manager.is_tainted());
}

struct OwnedPage {
    _owner: Arc<ChromiumConnectionOwner<Drain>>,
    manager: Arc<browserd_worker::ChromiumTargetManager<Drain>>,
    drain: Arc<Drain>,
    driver: browserd_worker::CdpChromiumDriver,
    reader: Receiver,
    writer: Sender,
    session_id: SessionId,
    page_id: PageId,
}

async fn owned_page() -> OwnedPage {
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
    let session_id = SessionId::new();
    let page_id = create_owned_context(
        driver.clone(),
        TenantId::new(),
        session_id.clone(),
        ownership_fence(),
        &mut reader,
        &mut writer,
    )
    .await;
    OwnedPage {
        _owner: owner,
        manager,
        drain,
        driver,
        reader,
        writer,
        session_id,
        page_id,
    }
}

fn spawn_action(
    page: &OwnedPage,
    payload: &'static [u8],
    deadline: Option<Instant>,
) -> tokio::task::JoinHandle<ActionExecutionResult> {
    let driver = page.driver.clone();
    let session_id = page.session_id.clone();
    let page_id = page.page_id.clone();
    tokio::task::spawn_blocking(move || match deadline {
        Some(deadline) => {
            driver.execute_action_until(&session_id, Some(&page_id), payload, deadline)
        }
        None => driver.execute_action(&session_id, Some(&page_id), payload),
    })
}

fn succeeded() -> ActionExecutionResult {
    ActionExecutionResult::Succeeded(br#"{"ok":true}"#.to_vec())
}

#[tokio::test]
async fn navigate_domcontentloaded_completes_on_the_committed_loader_without_load() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/a","wait_until":"domcontentloaded"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.navigate");
    assert_eq!(command["sessionId"], "flat-primary");
    respond(
        &mut page.writer,
        &command,
        json!({"frameId": "frame", "loaderId": "loader-a"}),
    )
    .await;

    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.domContentEventFired"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !navigate.is_finished(),
        "lifecycle events before the loader commits belong to the previous document"
    );

    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-a",
            "https://example.test/a",
        ),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !navigate.is_finished(),
        "a committed loader has not reached DOMContentLoaded yet"
    );

    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.domContentEventFired"),
    )
    .await;
    assert_eq!(navigate.await.unwrap(), succeeded());
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "awaiting a lifecycle must not issue further CDP effects"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn navigate_lifecycle_events_that_precede_the_response_are_honored() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/b","wait_until":"load"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.navigate");

    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-b",
            "https://example.test/b",
        ),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.domContentEventFired"),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !navigate.is_finished(),
        "the navigate response still bounds completion"
    );

    respond(
        &mut page.writer,
        &command,
        json!({"frameId": "frame", "loaderId": "loader-b"}),
    )
    .await;
    assert_eq!(navigate.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn navigate_superseded_by_another_loader_is_a_known_failure() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/c","wait_until":"load"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.navigate");
    respond(
        &mut page.writer,
        &command,
        json!({"frameId": "frame", "loaderId": "loader-c"}),
    )
    .await;
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-c",
            "https://example.test/c",
        ),
    )
    .await;
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-redirect",
            "https://example.test/elsewhere",
        ),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;

    assert_eq!(
        navigate.await.unwrap(),
        ActionExecutionResult::FailedKnown("navigation_interrupted".to_owned())
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn navigate_lifecycle_deadline_after_the_response_is_a_known_timeout() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/d","wait_until":"load"}"#,
        Some(Instant::now() + Duration::from_millis(150)),
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.navigate");
    respond(
        &mut page.writer,
        &command,
        json!({"frameId": "frame", "loaderId": "loader-d"}),
    )
    .await;
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-d",
            "https://example.test/d",
        ),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), navigate)
            .await
            .expect("the action deadline must end the lifecycle wait")
            .unwrap(),
        ActionExecutionResult::FailedKnown("navigation_timeout".to_owned())
    );

    let uncommitted = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/e","wait_until":"domcontentloaded"}"#,
        Some(Instant::now() + Duration::from_millis(150)),
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.navigate");
    respond(
        &mut page.writer,
        &command,
        json!({"frameId": "frame", "loaderId": "loader-e"}),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), uncommitted)
            .await
            .expect("the action deadline must end the commit wait")
            .unwrap(),
        ActionExecutionResult::FailedKnown("navigation_timeout".to_owned())
    );

    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn same_document_navigate_completes_without_lifecycle_events() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/f#section","wait_until":"load"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.navigate");
    respond(&mut page.writer, &command, json!({"frameId": "frame"})).await;
    assert_eq!(navigate.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn navigate_without_a_typed_wait_until_is_rejected_before_cdp() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/g"}"#,
        None,
    );
    assert_eq!(
        navigate.await.unwrap(),
        ActionExecutionResult::FailedKnown("unsupported_action".to_owned())
    );
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "an untyped navigate must fail before any CDP dispatch"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn reload_completes_only_after_the_reloaded_document_loads() {
    let mut page = owned_page().await;
    let reload = spawn_action(&page, br#"{"type":"reload"}"#, None);
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.reload");
    assert_eq!(command["sessionId"], "flat-primary");
    // Page.reload acknowledges the request but carries no loaderId of its own.
    respond(&mut page.writer, &command, json!({})).await;

    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-r1",
            "https://example.test/a",
        ),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.domContentEventFired"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !reload.is_finished(),
        "a reload must await the full load of the document it commits"
    );

    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    assert_eq!(reload.await.unwrap(), succeeded());
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "awaiting the reload lifecycle must not issue further CDP effects"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn reload_awaits_a_loader_distinct_from_the_prior_document() {
    let mut page = owned_page().await;
    // Establish a fully-loaded prior document so its terminal lifecycle state cannot be
    // mistaken for the reload's own fresh document.
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/a","wait_until":"load"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.navigate");
    respond(
        &mut page.writer,
        &command,
        json!({"frameId": "frame", "loaderId": "loader-prior"}),
    )
    .await;
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-prior",
            "https://example.test/a",
        ),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.domContentEventFired"),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    assert_eq!(navigate.await.unwrap(), succeeded());

    let reload = spawn_action(&page, br#"{"type":"reload"}"#, None);
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.reload");
    respond(&mut page.writer, &command, json!({})).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !reload.is_finished(),
        "the prior document's completed load must not satisfy the reload"
    );

    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-reloaded",
            "https://example.test/a",
        ),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    assert_eq!(reload.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn reload_lifecycle_deadline_is_a_known_timeout() {
    let mut page = owned_page().await;
    let reload = spawn_action(
        &page,
        br#"{"type":"reload"}"#,
        Some(Instant::now() + Duration::from_millis(150)),
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.reload");
    respond(&mut page.writer, &command, json!({})).await;
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-slow",
            "https://example.test/a",
        ),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), reload)
            .await
            .expect("the action deadline must end the reload lifecycle wait")
            .unwrap(),
        ActionExecutionResult::FailedKnown("navigation_timeout".to_owned())
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}
