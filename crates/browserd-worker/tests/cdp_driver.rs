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

fn network_event(session_id: &str, method: &str, request_id: &str) -> Value {
    json!({
        "method": method,
        "sessionId": session_id,
        "params": {"requestId": request_id}
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
async fn active_health_round_trips_the_exact_chromium_identity_and_fails_closed_on_drift() {
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

    let health = tokio::task::spawn_blocking({
        let driver = driver.clone();
        move || driver.qualify()
    });
    let command = tokio::time::timeout(Duration::from_millis(500), read_command(&mut reader))
        .await
        .expect("active health must perform a real CDP roundtrip");
    assert_eq!(command["method"], "Browser.getVersion");
    assert_eq!(command["params"], json!({}));
    assert!(command.get("sessionId").is_none());
    assert!(!health.is_finished());
    respond(
        &mut writer,
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
    assert_eq!(health.await.unwrap(), Ok(()));
    assert!(!drain.0.load(Ordering::SeqCst));

    let drift = tokio::task::spawn_blocking(move || driver.qualify());
    let command = read_command(&mut reader).await;
    assert_eq!(command["method"], "Browser.getVersion");
    respond(
        &mut writer,
        &command,
        json!({
            "protocolVersion": "1.3",
            "product": "HeadlessChrome/149.0.7827.55",
            "revision": "r1234567",
            "userAgent": "changed-runtime-identity",
            "jsVersion": "14.9",
        }),
    )
    .await;
    assert_eq!(drift.await.unwrap(), Err(DependencyError::OutcomeUncertain));
    tokio::time::timeout(Duration::from_millis(200), async {
        while !drain.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime identity drift must drain the shard");
    assert!(manager.is_tainted());
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
            br#"{"type":"not_a_supported_action"}"#,
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

fn spawn_action_owned(
    page: &OwnedPage,
    payload: Vec<u8>,
    deadline: Option<Instant>,
) -> tokio::task::JoinHandle<ActionExecutionResult> {
    let driver = page.driver.clone();
    let session_id = page.session_id.clone();
    let page_id = page.page_id.clone();
    tokio::task::spawn_blocking(move || match deadline {
        Some(deadline) => {
            driver.execute_action_until(&session_id, Some(&page_id), &payload, deadline)
        }
        None => driver.execute_action(&session_id, Some(&page_id), &payload),
    })
}

fn succeeded() -> ActionExecutionResult {
    ActionExecutionResult::Succeeded(br#"{"ok":true}"#.to_vec())
}

fn succeeded_bytes(result: ActionExecutionResult) -> Vec<u8> {
    match result {
        ActionExecutionResult::Succeeded(bytes) => Some(bytes),
        _ => None,
    }
    .expect("action must succeed with a result")
}

/// Mints a single node handle for `backend` via query_all and returns its opaque token.
async fn mint_node(page: &mut OwnedPage, backend: i64) -> String {
    let query = spawn_action(page, br#"{"type":"query_all","selector":"*"}"#, None);
    let document = read_command(&mut page.reader).await;
    respond(&mut page.writer, &document, json!({"root": {"nodeId": 1}})).await;
    let search = read_command(&mut page.reader).await;
    respond(&mut page.writer, &search, json!({"nodeIds": [1]})).await;
    let describe = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &describe,
        json!({"node": {"backendNodeId": backend}}),
    )
    .await;
    let minted: serde_json::Value =
        serde_json::from_slice(&succeeded_bytes(query.await.unwrap())).unwrap();
    minted["node_refs"][0]
        .as_str()
        .expect("a minted token")
        .to_owned()
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
    // Commit the navigate's own loader first and let the lifecycle wait observe it, so the
    // superseding loader that follows is deterministically seen as an interruption rather
    // than racing the navigate response.
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
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !navigate.is_finished(),
        "the committed loader has not reached load yet"
    );
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

fn navigation_history(current_index: i64, entries: &[(i64, &str)]) -> Value {
    json!({
        "currentIndex": current_index,
        "entries": entries
            .iter()
            .map(|(id, url)| json!({
                "id": id,
                "url": url,
                "userTypedURL": url,
                "title": url,
                "transitionType": "link",
            }))
            .collect::<Vec<_>>(),
    })
}

#[tokio::test]
async fn go_back_traverses_to_the_prior_entry_and_awaits_load() {
    let mut page = owned_page().await;
    let go_back = spawn_action(&page, br#"{"type":"go_back"}"#, None);

    let history = read_command(&mut page.reader).await;
    assert_eq!(history["method"], "Page.getNavigationHistory");
    respond(
        &mut page.writer,
        &history,
        navigation_history(
            1,
            &[
                (10, "https://example.test/a"),
                (11, "https://example.test/b"),
            ],
        ),
    )
    .await;

    let traverse = read_command(&mut page.reader).await;
    assert_eq!(traverse["method"], "Page.navigateToHistoryEntry");
    assert_eq!(traverse["params"]["entryId"], 10);
    respond(&mut page.writer, &traverse, json!({})).await;

    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "loader-back",
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
        !go_back.is_finished(),
        "a cross-document traversal must await the entry's full load"
    );

    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    assert_eq!(go_back.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn go_forward_past_the_last_entry_is_a_known_failure() {
    let mut page = owned_page().await;
    let go_forward = spawn_action(&page, br#"{"type":"go_forward"}"#, None);

    let history = read_command(&mut page.reader).await;
    assert_eq!(history["method"], "Page.getNavigationHistory");
    respond(
        &mut page.writer,
        &history,
        navigation_history(
            1,
            &[
                (10, "https://example.test/a"),
                (11, "https://example.test/b"),
            ],
        ),
    )
    .await;

    assert_eq!(
        go_forward.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "a traversal with no destination entry must not issue navigateToHistoryEntry"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn go_back_to_a_same_document_entry_completes_without_a_load() {
    let mut page = owned_page().await;
    let go_back = spawn_action(&page, br#"{"type":"go_back"}"#, None);

    let history = read_command(&mut page.reader).await;
    assert_eq!(history["method"], "Page.getNavigationHistory");
    respond(
        &mut page.writer,
        &history,
        navigation_history(
            1,
            &[
                (10, "https://example.test/a"),
                (11, "https://example.test/a#section"),
            ],
        ),
    )
    .await;

    let traverse = read_command(&mut page.reader).await;
    assert_eq!(traverse["method"], "Page.navigateToHistoryEntry");
    assert_eq!(traverse["params"]["entryId"], 10);
    respond(&mut page.writer, &traverse, json!({})).await;

    // A same-document entry fires navigatedWithinDocument and commits no new loader.
    write_message(
        &mut page.writer,
        json!({
            "method": "Page.navigatedWithinDocument",
            "sessionId": "flat-primary",
            "params": {"frameId": "frame", "url": "https://example.test/a"}
        }),
    )
    .await;
    assert_eq!(go_back.await.unwrap(), succeeded());
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "a same-document traversal issues no further CDP effects"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn press_key_dispatches_a_named_key_down_and_up() {
    let mut page = owned_page().await;
    let press = spawn_action(&page, br#"{"type":"press_key","key":"Enter"}"#, None);

    let down = read_command(&mut page.reader).await;
    assert_eq!(down["method"], "Input.dispatchKeyEvent");
    assert_eq!(down["params"]["type"], "keyDown");
    assert_eq!(down["params"]["key"], "Enter");
    assert_eq!(down["params"]["code"], "Enter");
    assert_eq!(down["params"]["windowsVirtualKeyCode"], 13);
    assert_eq!(down["params"]["text"], "\r");
    respond(&mut page.writer, &down, json!({})).await;

    let up = read_command(&mut page.reader).await;
    assert_eq!(up["method"], "Input.dispatchKeyEvent");
    assert_eq!(up["params"]["type"], "keyUp");
    assert_eq!(up["params"]["key"], "Enter");
    respond(&mut page.writer, &up, json!({})).await;

    assert_eq!(press.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn press_key_with_an_unresolvable_name_is_rejected_before_dispatch() {
    let mut page = owned_page().await;
    let press = spawn_action(&page, br#"{"type":"press_key","key":"NotAKey"}"#, None);
    assert_eq!(
        press.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "an unresolvable key must fail before any CDP dispatch"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn scroll_dispatches_a_wheel_event() {
    let mut page = owned_page().await;
    let scroll = spawn_action(
        &page,
        br#"{"type":"scroll","delta_x":0,"delta_y":240}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Input.dispatchMouseEvent");
    assert_eq!(command["params"]["type"], "mouseWheel");
    assert_eq!(command["params"]["deltaX"], 0);
    assert_eq!(command["params"]["deltaY"], 240);
    respond(&mut page.writer, &command, json!({})).await;

    assert_eq!(scroll.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn query_all_mints_an_opaque_ref_per_match() {
    let mut page = owned_page().await;
    let query = spawn_action(&page, br#"{"type":"query_all","selector":"a.link"}"#, None);

    let document = read_command(&mut page.reader).await;
    assert_eq!(document["method"], "DOM.getDocument");
    respond(&mut page.writer, &document, json!({"root": {"nodeId": 1}})).await;

    let search = read_command(&mut page.reader).await;
    assert_eq!(search["method"], "DOM.querySelectorAll");
    assert_eq!(search["params"]["nodeId"], 1);
    assert_eq!(search["params"]["selector"], "a.link");
    respond(&mut page.writer, &search, json!({"nodeIds": [2, 3]})).await;

    for (node_id, backend) in [(2, 100), (3, 101)] {
        let describe = read_command(&mut page.reader).await;
        assert_eq!(describe["method"], "DOM.describeNode");
        assert_eq!(describe["params"]["nodeId"], node_id);
        respond(
            &mut page.writer,
            &describe,
            json!({"node": {"backendNodeId": backend}}),
        )
        .await;
    }

    let bytes = match query.await.unwrap() {
        ActionExecutionResult::Succeeded(bytes) => Some(bytes),
        _ => None,
    }
    .expect("query_all must succeed with a result");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let node_refs = parsed["node_refs"]
        .as_array()
        .expect("result carries a node_refs array");
    assert_eq!(node_refs.len(), 2);
    assert!(
        node_refs
            .iter()
            .all(|token| token.as_str().is_some_and(|token| !token.is_empty())),
        "each match mints a non-empty opaque token"
    );
    assert_ne!(node_refs[0], node_refs[1], "handles are unique per match");
    // BRD-026: a complete result reports its count, the bound, and no truncation, plus the
    // document provenance the handles were minted against.
    assert_eq!(parsed["returned_count"], 2);
    assert_eq!(parsed["limit"], 256);
    assert_eq!(parsed["truncated"], false);
    assert!(parsed["document_epoch"].is_u64());
    assert!(parsed["url_revision"].is_u64());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn query_all_reports_truncation_when_matches_exceed_the_limit() {
    let mut page = owned_page().await;
    let query = spawn_action(&page, br#"{"type":"query_all","selector":"div"}"#, None);

    let document = read_command(&mut page.reader).await;
    assert_eq!(document["method"], "DOM.getDocument");
    respond(&mut page.writer, &document, json!({"root": {"nodeId": 1}})).await;

    // One more match than the owner will mint handles for, so the result must be truncated.
    let total = 257;
    let node_ids: Vec<i64> = (2..2 + total).collect();
    let search = read_command(&mut page.reader).await;
    assert_eq!(search["method"], "DOM.querySelectorAll");
    respond(&mut page.writer, &search, json!({ "nodeIds": node_ids })).await;

    // The owner describes only the first 256 matches.
    for offset in 0..256 {
        let describe = read_command(&mut page.reader).await;
        assert_eq!(describe["method"], "DOM.describeNode");
        respond(
            &mut page.writer,
            &describe,
            json!({"node": {"backendNodeId": 1_000 + offset}}),
        )
        .await;
    }

    let bytes = succeeded_bytes(query.await.unwrap());
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let node_refs = parsed["node_refs"]
        .as_array()
        .expect("result carries a node_refs array");
    assert_eq!(node_refs.len(), 256);
    assert_eq!(parsed["returned_count"], 256);
    assert_eq!(parsed["limit"], 256);
    assert_eq!(parsed["truncated"], true);
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn get_text_reads_a_minted_node() {
    let mut page = owned_page().await;

    // Mint a handle for one match.
    let query = spawn_action(&page, br#"{"type":"query_all","selector":"h1"}"#, None);
    let document = read_command(&mut page.reader).await;
    assert_eq!(document["method"], "DOM.getDocument");
    respond(&mut page.writer, &document, json!({"root": {"nodeId": 1}})).await;
    let search = read_command(&mut page.reader).await;
    assert_eq!(search["method"], "DOM.querySelectorAll");
    respond(&mut page.writer, &search, json!({"nodeIds": [7]})).await;
    let describe = read_command(&mut page.reader).await;
    assert_eq!(describe["method"], "DOM.describeNode");
    respond(
        &mut page.writer,
        &describe,
        json!({"node": {"backendNodeId": 900}}),
    )
    .await;
    let minted: serde_json::Value =
        serde_json::from_slice(&succeeded_bytes(query.await.unwrap())).unwrap();
    let token = minted["node_refs"][0]
        .as_str()
        .expect("a minted token")
        .to_owned();

    // Consume it: resolve the backend node and read its rendered text.
    let get_text = spawn_action_owned(
        &page,
        format!(r#"{{"type":"get_text","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    assert_eq!(resolve["params"]["backendNodeId"], 900);
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-1"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["objectId"], "obj-1");
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"type": "string", "value": "Hello world"}}),
    )
    .await;
    // BRD-010: the remote object minted by the resolve is released after a successful read.
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    assert_eq!(release["params"]["objectId"], "obj-1");
    respond(&mut page.writer, &release, json!({})).await;

    let text: serde_json::Value =
        serde_json::from_slice(&succeeded_bytes(get_text.await.unwrap())).unwrap();
    assert_eq!(text["text"], "Hello world");
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn get_attribute_reads_a_named_attribute_by_argument() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 900).await;

    let get_attr = spawn_action_owned(
        &page,
        format!(r#"{{"type":"get_attribute","node_ref":"{token}","name":"href"}}"#).into_bytes(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    assert_eq!(resolve["params"]["backendNodeId"], 900);
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-1"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["arguments"][0]["value"], "href");
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"type": "string", "value": "https://example.test/x"}}),
    )
    .await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;

    let parsed: serde_json::Value =
        serde_json::from_slice(&succeeded_bytes(get_attr.await.unwrap())).unwrap();
    assert_eq!(parsed["value"], "https://example.test/x");
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn get_html_without_a_node_reads_the_whole_document() {
    let mut page = owned_page().await;
    let get_html = spawn_action(&page, br#"{"type":"get_html","node_ref":null}"#, None);
    let evaluate = read_command(&mut page.reader).await;
    assert_eq!(evaluate["method"], "Runtime.evaluate");
    assert_eq!(
        evaluate["params"]["expression"],
        "document.documentElement.outerHTML"
    );
    respond(
        &mut page.writer,
        &evaluate,
        json!({"result": {"type": "string", "value": "<html></html>"}}),
    )
    .await;

    let parsed: serde_json::Value =
        serde_json::from_slice(&succeeded_bytes(get_html.await.unwrap())).unwrap();
    assert_eq!(parsed["html"], "<html></html>");
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn extract_table_returns_rows_of_cell_text() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 500).await;

    let extract = spawn_action_owned(
        &page,
        format!(r#"{{"type":"extract_table","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-t"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"type": "object", "value": [["a", "b"], ["c", "d"]]}}),
    )
    .await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;

    let parsed: serde_json::Value =
        serde_json::from_slice(&succeeded_bytes(extract.await.unwrap())).unwrap();
    assert_eq!(parsed["rows"], json!([["a", "b"], ["c", "d"]]));
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn click_dispatches_at_the_resolved_content_box_center() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 300).await;

    let click = spawn_action_owned(
        &page,
        format!(r#"{{"type":"click","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let quads = read_command(&mut page.reader).await;
    assert_eq!(quads["method"], "DOM.getContentQuads");
    assert_eq!(quads["params"]["backendNodeId"], 300);
    respond(
        &mut page.writer,
        &quads,
        json!({"quads": [[10, 20, 30, 20, 30, 40, 10, 40]]}),
    )
    .await;

    let press = read_command(&mut page.reader).await;
    assert_eq!(press["method"], "Input.dispatchMouseEvent");
    assert_eq!(press["params"]["type"], "mousePressed");
    assert_eq!(press["params"]["x"].as_f64(), Some(20.0));
    assert_eq!(press["params"]["y"].as_f64(), Some(30.0));
    respond(&mut page.writer, &press, json!({})).await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["params"]["type"], "mouseReleased");
    assert_eq!(release["params"]["x"].as_f64(), Some(20.0));
    respond(&mut page.writer, &release, json!({})).await;

    assert_eq!(click.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn click_of_a_node_without_a_content_box_is_rejected() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 301).await;

    let click = spawn_action_owned(
        &page,
        format!(r#"{{"type":"click","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let quads = read_command(&mut page.reader).await;
    assert_eq!(quads["method"], "DOM.getContentQuads");
    respond(&mut page.writer, &quads, json!({"quads": []})).await;

    assert_eq!(
        click.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "a node with no content box dispatches no pointer events"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn hover_moves_the_pointer_to_the_node_center() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 400).await;

    let hover = spawn_action_owned(
        &page,
        format!(r#"{{"type":"hover","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let quads = read_command(&mut page.reader).await;
    assert_eq!(quads["method"], "DOM.getContentQuads");
    respond(
        &mut page.writer,
        &quads,
        json!({"quads": [[0, 0, 40, 0, 40, 20, 0, 20]]}),
    )
    .await;
    let moved = read_command(&mut page.reader).await;
    assert_eq!(moved["method"], "Input.dispatchMouseEvent");
    assert_eq!(moved["params"]["type"], "mouseMoved");
    assert_eq!(moved["params"]["x"].as_f64(), Some(20.0));
    assert_eq!(moved["params"]["y"].as_f64(), Some(10.0));
    respond(&mut page.writer, &moved, json!({})).await;

    assert_eq!(hover.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn double_click_dispatches_two_click_sequences() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 401).await;

    let double = spawn_action_owned(
        &page,
        format!(r#"{{"type":"double_click","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let quads = read_command(&mut page.reader).await;
    assert_eq!(quads["method"], "DOM.getContentQuads");
    respond(
        &mut page.writer,
        &quads,
        json!({"quads": [[0, 0, 20, 0, 20, 20, 0, 20]]}),
    )
    .await;
    for expected_count in [1, 1, 2, 2] {
        let event = read_command(&mut page.reader).await;
        assert_eq!(event["method"], "Input.dispatchMouseEvent");
        assert_eq!(event["params"]["clickCount"], expected_count);
        respond(&mut page.writer, &event, json!({})).await;
    }

    assert_eq!(double.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn double_click_release_failure_after_a_landed_press_is_outcome_unknown() {
    // BRD-005: the first click's press lands (a mouse-down effect is exposed), then its release
    // is rejected. The compound action must be outcome-unknown, not a clean known failure that
    // implies nothing happened, because a button-down effect may persist.
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 402).await;

    let double = spawn_action_owned(
        &page,
        format!(r#"{{"type":"double_click","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let quads = read_command(&mut page.reader).await;
    assert_eq!(quads["method"], "DOM.getContentQuads");
    respond(
        &mut page.writer,
        &quads,
        json!({"quads": [[0, 0, 20, 0, 20, 20, 0, 20]]}),
    )
    .await;

    let press = read_command(&mut page.reader).await;
    assert_eq!(press["method"], "Input.dispatchMouseEvent");
    assert_eq!(press["params"]["type"], "mousePressed");
    assert_eq!(press["params"]["clickCount"], 1);
    respond(&mut page.writer, &press, json!({})).await;

    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Input.dispatchMouseEvent");
    assert_eq!(release["params"]["type"], "mouseReleased");
    write_message(
        &mut page.writer,
        json!({
            "id": release["id"].as_u64().unwrap(),
            "error": {"code": -32000, "message": "release rejected"}
        }),
    )
    .await;

    assert_eq!(double.await.unwrap(), ActionExecutionResult::OutcomeUnknown);
}

#[tokio::test]
async fn focus_focuses_the_resolved_node() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 410).await;

    let focus = spawn_action_owned(
        &page,
        format!(r#"{{"type":"focus","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "DOM.focus");
    assert_eq!(command["params"]["backendNodeId"], 410);
    respond(&mut page.writer, &command, json!({})).await;

    assert_eq!(focus.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn check_sets_the_checked_state_through_the_element() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 411).await;

    let check = spawn_action_owned(
        &page,
        format!(r#"{{"type":"check","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-c"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["arguments"][0]["value"], true);
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"type": "boolean", "value": true}}),
    )
    .await;

    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;

    assert_eq!(check.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn fill_sets_the_value_through_the_element() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 420).await;

    let fill = spawn_action_owned(
        &page,
        format!(r#"{{"type":"fill","node_ref":"{token}","value":"hello world"}}"#).into_bytes(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-f"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["arguments"][0]["value"], "hello world");
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"type": "boolean", "value": true}}),
    )
    .await;

    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;

    assert_eq!(fill.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn select_option_passes_the_requested_values() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 421).await;

    let select = spawn_action_owned(
        &page,
        format!(r#"{{"type":"select_option","node_ref":"{token}","values":["a","b"]}}"#)
            .into_bytes(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-s"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["arguments"][0]["value"], json!(["a", "b"]));
    // The helper reports whether it applied to a supported `<select>`, not the selected values.
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"type": "boolean", "value": true}}),
    )
    .await;

    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;

    assert_eq!(select.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn fill_on_an_unsupported_element_is_rejected_without_claiming_success() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 430).await;

    let fill = spawn_action_owned(
        &page,
        format!(r#"{{"type":"fill","node_ref":"{token}","value":"x"}}"#).into_bytes(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-div"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    // The helper reports the element is not fillable (e.g. a plain <div>): no DOM change applied.
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"type": "boolean", "value": false}}),
    )
    .await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;

    // The action is a clean rejection, never a silent success on the wrong element.
    assert_eq!(
        fill.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn evaluate_returns_the_expression_value() {
    let mut page = owned_page().await;
    let eval = spawn_action(&page, br#"{"type":"evaluate","expression":"1 + 2"}"#, None);
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Runtime.evaluate");
    assert_eq!(command["params"]["expression"], "1 + 2");
    assert_eq!(command["params"]["awaitPromise"], true);
    respond(
        &mut page.writer,
        &command,
        json!({"result": {"type": "number", "value": 3}}),
    )
    .await;

    let parsed: serde_json::Value =
        serde_json::from_slice(&succeeded_bytes(eval.await.unwrap())).unwrap();
    assert_eq!(parsed["value"], 3);
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn wait_for_polls_until_the_condition_holds() {
    let mut page = owned_page().await;
    let wait = spawn_action(
        &page,
        br#"{"type":"wait_for","condition":{"type":"selector_attached","selector":".ready"}}"#,
        None,
    );

    let first = read_command(&mut page.reader).await;
    assert_eq!(first["method"], "Runtime.evaluate");
    assert!(
        first["params"]["expression"]
            .as_str()
            .is_some_and(|expression| expression.contains("querySelector")),
        "the condition compiles to a querySelector predicate"
    );
    respond(
        &mut page.writer,
        &first,
        json!({"result": {"type": "boolean", "value": false}}),
    )
    .await;

    // The next poll fires after the interval; report the condition satisfied.
    let second = read_command(&mut page.reader).await;
    assert_eq!(second["method"], "Runtime.evaluate");
    respond(
        &mut page.writer,
        &second,
        json!({"result": {"type": "boolean", "value": true}}),
    )
    .await;

    assert_eq!(wait.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn wait_for_times_out_when_the_condition_never_holds() {
    let mut page = owned_page().await;
    let wait = spawn_action(
        &page,
        br#"{"type":"wait_for","condition":{"type":"load_state","state":"load"}}"#,
        Some(Instant::now() + Duration::from_millis(150)),
    );
    let poll = read_command(&mut page.reader).await;
    assert_eq!(poll["method"], "Runtime.evaluate");
    respond(
        &mut page.writer,
        &poll,
        json!({"result": {"type": "boolean", "value": false}}),
    )
    .await;

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("the action deadline must end the wait")
            .unwrap(),
        ActionExecutionResult::FailedKnown("navigation_timeout".to_owned())
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn network_quiet_completes_once_in_flight_requests_settle() {
    let mut page = owned_page().await;
    let wait = spawn_action(
        &page,
        br#"{"type":"wait_for","condition":{"type":"network_quiet","quiet_ms":80}}"#,
        Some(Instant::now() + Duration::from_secs(5)),
    );
    // A request opens before the quiet window can elapse, so the page is not idle. No CDP command
    // is issued for network quiet: the owner decides it from the in-flight ledger the events feed.
    write_message(
        &mut page.writer,
        network_event("flat-primary", "Network.requestWillBeSent", "req-1"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(140)).await;
    assert!(
        !wait.is_finished(),
        "an in-flight request keeps the page from reaching network quiet"
    );

    // Settling the only in-flight request lets the quiet window elapse and complete the wait.
    write_message(
        &mut page.writer,
        network_event("flat-primary", "Network.loadingFinished", "req-1"),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("quiescence must complete the wait once requests settle")
            .unwrap(),
        succeeded()
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn network_quiet_times_out_while_a_request_stays_in_flight() {
    let mut page = owned_page().await;
    let wait = spawn_action(
        &page,
        br#"{"type":"wait_for","condition":{"type":"network_quiet","quiet_ms":50}}"#,
        Some(Instant::now() + Duration::from_millis(200)),
    );
    // The request never completes, so the page never goes quiet and the action deadline ends it.
    write_message(
        &mut page.writer,
        network_event("flat-primary", "Network.requestWillBeSent", "req-1"),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("the action deadline must end the wait")
            .unwrap(),
        ActionExecutionResult::FailedKnown("navigation_timeout".to_owned())
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn network_quiet_treats_a_redirect_as_the_same_in_flight_request() {
    let mut page = owned_page().await;
    let wait = spawn_action(
        &page,
        br#"{"type":"wait_for","condition":{"type":"network_quiet","quiet_ms":80}}"#,
        Some(Instant::now() + Duration::from_secs(5)),
    );
    // A redirect re-emits `requestWillBeSent` with the same request id; it must count as one still
    // in-flight request, not a second one and not an early completion.
    write_message(
        &mut page.writer,
        network_event("flat-primary", "Network.requestWillBeSent", "req-1"),
    )
    .await;
    write_message(
        &mut page.writer,
        network_event("flat-primary", "Network.requestWillBeSent", "req-1"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(140)).await;
    assert!(
        !wait.is_finished(),
        "the redirected request is still in flight"
    );

    // A single terminal event settles the redirected request and lets quiescence be reached.
    write_message(
        &mut page.writer,
        network_event("flat-primary", "Network.loadingFinished", "req-1"),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("a single loadingFinished settles the redirected request")
            .unwrap(),
        succeeded()
    );
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn handle_dialog_accepts_with_prompt_text() {
    let mut page = owned_page().await;
    let handle = spawn_action(
        &page,
        br#"{"type":"handle_dialog","accept":true,"prompt_text":"Ada"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.handleJavaScriptDialog");
    assert_eq!(command["params"]["accept"], true);
    assert_eq!(command["params"]["promptText"], "Ada");
    respond(&mut page.writer, &command, json!({})).await;

    assert_eq!(handle.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn snapshot_returns_a_normalized_tree_with_opaque_node_refs() {
    let mut page = owned_page().await;
    let snapshot = spawn_action(&page, br#"{"type":"snapshot"}"#, None);

    // The capture joins accessibility semantics, layout bounds, and viewport metrics.
    let ax = read_command(&mut page.reader).await;
    assert_eq!(ax["method"], "Accessibility.getFullAXTree");
    respond(
        &mut page.writer,
        &ax,
        json!({"nodes": [
            {
                "ignored": false,
                "backendDOMNodeId": 100,
                "role": {"value": "button"},
                "name": {"value": "Login"},
                "properties": [{"name": "focusable", "value": {"value": true}}]
            },
            {"ignored": true, "backendDOMNodeId": 200, "role": {"value": "generic"}}
        ]}),
    )
    .await;

    let dom = read_command(&mut page.reader).await;
    assert_eq!(dom["method"], "DOMSnapshot.captureSnapshot");
    respond(
        &mut page.writer,
        &dom,
        json!({
            "documents": [{
                "nodes": {"backendNodeId": [100, 200]},
                "layout": {"nodeIndex": [0], "bounds": [[1040.0, 30.0, 120.0, 40.0]]}
            }],
            "strings": []
        }),
    )
    .await;

    let metrics = read_command(&mut page.reader).await;
    assert_eq!(metrics["method"], "Page.getLayoutMetrics");
    respond(
        &mut page.writer,
        &metrics,
        json!({"cssLayoutViewport": {"clientWidth": 1280, "clientHeight": 720}}),
    )
    .await;

    let tree: serde_json::Value =
        serde_json::from_slice(&succeeded_bytes(snapshot.await.unwrap())).unwrap();
    assert!(
        tree["snapshot_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("snap_")),
        "the envelope carries an opaque snapshot id"
    );
    assert_eq!(tree["consistency"], "near_consistent");
    assert_eq!(
        tree["viewport"],
        json!({"width": 1280, "height": 720, "device_scale_factor": 1})
    );
    assert_eq!(tree["total_nodes"], 1);
    assert_eq!(tree["returned_nodes"], 1);
    assert_eq!(tree["truncated"], false);
    // The ignored node is dropped; the one semantic node is normalized with its bounds and states.
    assert_eq!(tree["nodes"].as_array().map(Vec::len), Some(1));
    let node = &tree["nodes"][0];
    assert_eq!(node["role"], "button");
    assert_eq!(node["name"], "Login");
    assert_eq!(node["states"], json!(["focusable"]));
    assert_eq!(
        node["bounds"],
        json!({"x": 1040.0, "y": 30.0, "width": 120.0, "height": 40.0})
    );
    // No raw CDP identifier leaks; the node is addressed only by its opaque handle.
    assert!(node.get("backendDOMNodeId").is_none());
    let node_ref = node["node_ref"]
        .as_str()
        .expect("a node carries an opaque ref");

    // The snapshot's node_ref resolves for a follow-up action on the same document.
    let get_text = spawn_action_owned(
        &page,
        format!(r#"{{"type":"get_text","node_ref":"{node_ref}"}}"#).into_bytes(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(
        resolve["method"], "DOM.resolveNode",
        "a valid snapshot node_ref is accepted and resolved rather than rejected before CDP"
    );
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-1"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"value": "Login"}}),
    )
    .await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;
    assert!(
        matches!(get_text.await.unwrap(), ActionExecutionResult::Succeeded(_)),
        "a read action driven by the snapshot node_ref completes"
    );

    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn evaluate_that_throws_is_rejected() {
    let mut page = owned_page().await;
    let eval = spawn_action(&page, br#"{"type":"evaluate","expression":"boom()"}"#, None);
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Runtime.evaluate");
    respond(
        &mut page.writer,
        &command,
        json!({"result": {"type": "object"}, "exceptionDetails": {"text": "Uncaught"}}),
    )
    .await;

    assert_eq!(
        eval.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn get_text_with_an_unknown_ref_is_rejected_before_cdp() {
    let mut page = owned_page().await;
    let get_text = spawn_action(
        &page,
        br#"{"type":"get_text","node_ref":"deadbeefdeadbeef"}"#,
        None,
    );
    assert_eq!(
        get_text.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "an unresolved node ref must fail before any CDP dispatch"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}
