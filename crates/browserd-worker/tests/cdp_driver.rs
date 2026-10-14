#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "cdp_driver/review_control_runtime.rs"]
mod review_control_runtime;
#[path = "cdp_driver/review_document_fence.rs"]
mod review_document_fence;
#[path = "cdp_driver/review_network_activity.rs"]
mod review_network_activity;
#[path = "cdp_driver/review_snapshot_contract.rs"]
mod review_snapshot_contract;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use browserd_cdp::CdpTransportConfig;
use browserd_chromium::{ChromiumArtifactIdentity, ChromiumConnectionConfig, Sha256Digest};
use browserd_core::{
    EgressFence, IsolationProfile, LaunchGeneration, OwnerFence, PageId, RouteGeneration,
    SessionId, SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, ChromiumCdpPipes, ChromiumProcessProfile, DedicatedEgressSpec,
    EgressPolicyBinding, LaunchSpec,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActionExecutionResult, ApprovedActionError, CdpPipeAcceptor, ChromiumConnectionOwner,
    ChromiumDriver, DependencyError, ShardRuntimeError, TargetManagerDrain, WorkerSessionOptionsV1,
    WorkerViewport,
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

fn options_bootstrap_commands() -> [(&'static str, Value); 11] {
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
            json!({"userAgent": "browserd-options-test/1.0", "acceptLanguage": "ko-KR"}),
        ),
        ("Network.enable", json!({})),
        ("Runtime.enable", json!({})),
        ("Page.enable", json!({})),
        ("Page.getFrameTree", json!({})),
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
    if message["method"] == "Page.frameNavigated" {
        let event = json!({"method":"Runtime.executionContextCreated", "sessionId":message["sessionId"], "params":{"context":{"id":1,"uniqueId":uuid::Uuid::new_v4().to_string(),"auxData":{"isDefault":true,"frameId":message["params"]["frame"]["id"]}}}});
        writer
            .write_all(&serde_json::to_vec(&event).unwrap())
            .await
            .unwrap();
        writer.write_all(&[0]).await.unwrap();
    }
}

async fn respond(writer: &mut Sender, command: &Value, mut result: Value) {
    if command["method"] == "Page.getFrameTree" && result.get("frameTree").is_none() {
        let session = command["sessionId"].as_str().unwrap();
        let frame = format!("frame-{session}");
        write_message(writer, json!({"method":"Runtime.executionContextCreated","sessionId":session,"params":{"context":{"id":1,"uniqueId":format!("realm-{session}"),"auxData":{"isDefault":true,"frameId":frame}}}})).await;
        result = json!({"frameTree":{"frame":{"id":frame,"url":"about:blank"}}});
    }
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

fn paused_child(context_id: &str) -> Value {
    json!({
        "method":"Target.attachedToTarget",
        "sessionId":"flat-primary",
        "params":{
            "sessionId":"flat-child", "waitingForDebugger":true,
            "targetInfo":{"targetId":"child-target", "browserContextId":context_id, "type":"iframe"}
        }
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
    for _ in 0..7 {
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
    create_owned_options_context_with_commands(
        driver,
        tenant_id,
        session_id,
        fence,
        reader,
        writer,
        options_bootstrap_commands().into(),
    )
    .await
}

async fn create_owned_options_context_with_commands(
    driver: browserd_worker::CdpChromiumDriver,
    tenant_id: TenantId,
    session_id: SessionId,
    fence: OwnershipFence,
    reader: &mut Receiver,
    writer: &mut Sender,
    expected: Vec<(&'static str, Value)>,
) -> PageId {
    create_owned_options_context_fixture(
        driver,
        tenant_id,
        session_id,
        fence,
        reader,
        writer,
        expected,
        session_options(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn create_owned_options_context_fixture(
    driver: browserd_worker::CdpChromiumDriver,
    tenant_id: TenantId,
    session_id: SessionId,
    fence: OwnershipFence,
    reader: &mut Receiver,
    writer: &mut Sender,
    expected: Vec<(&'static str, Value)>,
    options: WorkerSessionOptionsV1,
) -> PageId {
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

fn native_process_profile() -> ChromiumProcessProfile {
    ChromiumProcessProfile::native_locale(
        "ko-KR",
        "Asia/Seoul",
        ChromiumBinaryDigest::new([4; 32]),
        ChromiumBinaryDigest::new([5; 32]),
        ChromiumBinaryDigest::new([6; 32]),
    )
    .expect("native process profile should be valid")
    .with_user_agent(session_options().user_agent)
    .expect("native process user agent should be valid")
}

fn native_bootstrap_commands() -> Vec<(&'static str, Value)> {
    options_bootstrap_commands()
        .into_iter()
        .filter(|(method, _)| {
            !matches!(
                *method,
                "Emulation.setLocaleOverride" | "Emulation.setTimezoneOverride"
            )
        })
        .map(|(method, mut params)| {
            if method == "Target.setAutoAttach" {
                params["filter"] = json!([{"type":"service_worker","exclude":true},{"type":"shared_worker","exclude":true},{}]);
            }
            (method, params)
        })
        .collect()
}

struct BoundProfileOwner {
    owner: Arc<ChromiumConnectionOwner<Drain>>,
    manager: Arc<browserd_worker::ChromiumTargetManager<Drain>>,
    driver: browserd_worker::CdpChromiumDriver,
    reader: Receiver,
    writer: Sender,
    drain: Arc<Drain>,
}

fn bound_profile_launch(shard: ShardFence, profile: ChromiumProcessProfile) -> LaunchSpec {
    let dedicated = DedicatedEgressSpec::new(
        EgressFence::new(
            shard.clone(),
            RouteGeneration::new(1).unwrap(),
            SessionId::new(),
            SessionIncarnation::new(1).unwrap(),
        ),
        EgressPolicyBinding::new("strict", [7; 32]).unwrap(),
        Duration::from_secs(30),
    )
    .unwrap();
    LaunchSpec::production(
        TenantId::new(),
        dedicated,
        ChromiumBinaryDigest::new([0; 32]),
    )
    .with_process_profile(profile)
    .unwrap()
}

async fn bound_profile_owner(profile: ChromiumProcessProfile) -> BoundProfileOwner {
    let shard = shard_fence();
    let mut expected = identity();
    if matches!(profile, ChromiumProcessProfile::NativeLocaleV1 { .. }) {
        expected.launch_profile_digest = Sha256Digest::from_hex(&"04".repeat(32)).unwrap();
    }
    let launch = bound_profile_launch(shard.clone(), profile);
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded_for_launch(
        expected,
        connection_config(),
        shard,
        16,
        drain.clone(),
        launch,
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
    BoundProfileOwner {
        owner,
        manager,
        driver,
        reader,
        writer,
        drain,
    }
}

#[test]
fn bound_process_rejects_binary_identity_drift_before_pipes() {
    for profile in [ChromiumProcessProfile::BaselineV1, native_process_profile()] {
        let mut expected = identity();
        expected.binary_digest = Sha256Digest::from_hex(&"01".repeat(32)).unwrap();
        expected.launch_profile_digest = Sha256Digest::from_hex(&"04".repeat(32)).unwrap();
        let shard = shard_fence();
        let launch = bound_profile_launch(shard.clone(), profile);
        let result = ChromiumConnectionOwner::new_bounded_for_launch(
            expected,
            connection_config(),
            shard,
            16,
            Arc::new(Drain(AtomicBool::new(false))),
            launch,
        );
        assert!(matches!(result, Err(ShardRuntimeError::Rejected)));
    }
}

#[test]
fn bound_process_rejects_catalog_identity_drift_before_pipes() {
    let shard = shard_fence();
    let launch = bound_profile_launch(shard.clone(), native_process_profile());
    let result = ChromiumConnectionOwner::new_bounded_for_launch(
        identity(),
        connection_config(),
        shard,
        16,
        Arc::new(Drain(AtomicBool::new(false))),
        launch,
    );
    assert!(matches!(result, Err(ShardRuntimeError::Rejected)));
}

#[tokio::test]
async fn bound_baseline_process_rejects_session_options_before_cdp() {
    let mut bound = bound_profile_owner(ChromiumProcessProfile::BaselineV1).await;
    let create = tokio::task::spawn_blocking({
        let driver = bound.driver.clone();
        move || {
            driver.create_context_owned_with_options(
                &TenantId::new(),
                &SessionId::new(),
                &ownership_fence(),
                &session_options(),
            )
        }
    });
    assert_eq!(create.await.unwrap(), Err(DependencyError::Rejected));
    assert!(has_no_command_bytes(&mut bound.reader, false).await);
    assert!(!bound.manager.is_tainted());
    assert!(!bound.drain.0.load(Ordering::SeqCst));
    bound
        .owner
        .shutdown_and_join(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn bound_native_process_rejects_absent_or_mismatched_options_before_cdp() {
    let mut bound = bound_profile_owner(native_process_profile()).await;
    let mut wrong_locale = session_options();
    wrong_locale.locale = "ko".to_owned();
    let mut wrong_timezone = session_options();
    wrong_timezone.timezone = "UTC".to_owned();
    let mut wrong_user_agent = session_options();
    wrong_user_agent.user_agent = Some("other-user-agent/1.0".to_owned());
    let mut missing_user_agent = session_options();
    missing_user_agent.user_agent = None;
    for options in [
        None,
        Some(wrong_locale),
        Some(wrong_timezone),
        Some(wrong_user_agent),
        Some(missing_user_agent),
    ] {
        let create = tokio::task::spawn_blocking({
            let driver = bound.driver.clone();
            move || match options {
                None => driver.create_context_owned(
                    &TenantId::new(),
                    &SessionId::new(),
                    &ownership_fence(),
                ),
                Some(options) => driver.create_context_owned_with_options(
                    &TenantId::new(),
                    &SessionId::new(),
                    &ownership_fence(),
                    &options,
                ),
            }
        });
        assert_eq!(create.await.unwrap(), Err(DependencyError::Rejected));
        assert!(has_no_command_bytes(&mut bound.reader, false).await);
    }
    assert!(!bound.manager.is_tainted());
    assert!(!bound.drain.0.load(Ordering::SeqCst));
    bound
        .owner
        .shutdown_and_join(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn bound_native_process_bootstraps_without_inspector_locale_or_timezone_ownership() {
    let mut bound = bound_profile_owner(native_process_profile()).await;
    let session = SessionId::new();
    let tenant = TenantId::new();
    let expected = native_bootstrap_commands();
    let page = create_owned_options_context_with_commands(
        bound.driver.clone(),
        tenant.clone(),
        session.clone(),
        ownership_fence(),
        &mut bound.reader,
        &mut bound.writer,
        expected,
    )
    .await;
    let pages = tokio::task::spawn_blocking({
        let driver = bound.driver.clone();
        move || driver.list_pages_owned(&tenant, &session, &ownership_fence())
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(pages, vec![page]);
    assert_eq!(bound.manager.ready_target_count(), 1);
    assert!(!bound.manager.is_tainted());
    assert!(!bound.drain.0.load(Ordering::SeqCst));
    bound
        .owner
        .shutdown_and_join(Duration::from_secs(1))
        .await
        .unwrap();
}

async fn native_owned_context() -> (BoundProfileOwner, TenantId, SessionId, PageId) {
    let mut bound = bound_profile_owner(native_process_profile()).await;
    let tenant = TenantId::new();
    let session = SessionId::new();
    let page = create_owned_options_context_with_commands(
        bound.driver.clone(),
        tenant.clone(),
        session.clone(),
        ownership_fence(),
        &mut bound.reader,
        &mut bound.writer,
        native_bootstrap_commands(),
    )
    .await;
    (bound, tenant, session, page)
}

fn native_worker_attached(kind: &str, suffix: &str, parent: Option<&str>) -> Value {
    let mut event = json!({
        "method":"Target.attachedToTarget",
        "params":{
            "sessionId":format!("flat-native-{suffix}"), "waitingForDebugger":true,
            "targetInfo":{"targetId":format!("native-{suffix}"),"browserContextId":"options-context","type":kind}
        }
    });
    if let Some(parent) = parent {
        event["sessionId"] = json!(parent);
    }
    event
}

async fn native_worker_bootstrap(
    bound: &mut BoundProfileOwner,
    kind: &str,
    suffix: &str,
    parent: Option<&str>,
) {
    write_message(
        &mut bound.writer,
        native_worker_attached(kind, suffix, parent),
    )
    .await;
    for (method, params) in [
        (
            "Target.setAutoAttach",
            json!({"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true,"filter":[{"type":"service_worker","exclude":true},{"type":"shared_worker","exclude":true},{}]}),
        ),
        ("Network.enable", json!({})),
        ("Runtime.runIfWaitingForDebugger", json!({})),
    ] {
        let command = read_command(&mut bound.reader).await;
        assert_eq!(
            command["method"], method,
            "workers must not receive page or emulation commands"
        );
        assert_eq!(command["sessionId"], format!("flat-native-{suffix}"));
        assert_eq!(command["params"], params);
        respond(&mut bound.writer, &command, json!({})).await;
    }
    tokio::time::timeout(Duration::from_millis(300), async {
        while !bound.manager.has_ready_target(&format!("native-{suffix}")) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("acknowledged worker bootstrap should become ready");
}

#[tokio::test]
async fn native_workers_use_only_acknowledged_network_and_recursive_attach_before_resume() {
    let (mut bound, tenant, session, page) = native_owned_context().await;
    native_worker_bootstrap(
        &mut bound,
        "worker",
        "dedicated",
        Some("flat-options-primary"),
    )
    .await;
    native_worker_bootstrap(
        &mut bound,
        "worker",
        "nested",
        Some("flat-native-dedicated"),
    )
    .await;
    native_worker_bootstrap(&mut bound, "shared_worker", "shared", None).await;
    native_worker_bootstrap(&mut bound, "service_worker", "service", None).await;
    let pages = tokio::task::spawn_blocking({
        let driver = bound.driver.clone();
        move || driver.list_pages_owned(&tenant, &session, &ownership_fence())
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        pages,
        vec![page],
        "workers have context ownership without becoming public pages"
    );
    assert_eq!(bound.manager.ready_target_count(), 5);
    // Exact duplicate events consume neither a new route nor another bootstrap.
    write_message(
        &mut bound.writer,
        native_worker_attached("worker", "dedicated", Some("flat-options-primary")),
    )
    .await;
    assert!(has_no_command_bytes(&mut bound.reader, false).await);
    assert!(!bound.manager.is_tainted());
    bound
        .owner
        .shutdown_and_join(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn active_command_unknown_worker_parent_closes_admission_before_reply() {
    for kind in ["worker", "shared_worker", "service_worker"] {
        let (mut bound, _, session, page) = native_owned_context().await;
        let title = tokio::task::spawn_blocking({
            let driver = bound.driver.clone();
            let session = session.clone();
            let page = page.clone();
            move || driver.execute_action(&session, Some(&page), br#"{"type":"get_title"}"#)
        });
        let command = read_command(&mut bound.reader).await;
        assert_eq!(command["method"], "Runtime.evaluate");
        // Keep the command pending so the event is handled inside command_event_first.
        write_message(
            &mut bound.writer,
            native_worker_attached(kind, "unknown-parent", Some("flat-unowned-parent")),
        )
        .await;
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(200), title)
                .await
                .expect("unknown worker parent must interrupt the active command")
                .unwrap(),
            ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
        );
        assert!(bound.manager.is_tainted());
        assert!(bound.drain.0.load(Ordering::SeqCst));
        assert!(
            !bound.manager.has_ready_target("native-unknown-parent"),
            "a worker without exact parent ownership must never become ready"
        );
        let followup = tokio::task::spawn_blocking({
            let driver = bound.driver.clone();
            move || driver.execute_action(&session, Some(&page), br#"{"type":"get_title"}"#)
        });
        assert_eq!(
            followup.await.unwrap(),
            ActionExecutionResult::OutcomeUnknown
        );
        assert_eq!(
            bound
                .owner
                .shutdown_and_join(Duration::from_millis(200))
                .await,
            Err(ShardRuntimeError::OutcomeUncertain)
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(200), bound.reader.read(&mut byte))
                .await
                .expect("unknown worker parent must terminate the CDP writer")
                .unwrap(),
            0,
            "neither worker bootstrap nor the followup action may reach CDP"
        );
    }
}

#[tokio::test]
async fn native_worker_quota_releases_only_on_exact_retirement_and_rejects_overflow() {
    let (mut bound, _, _, _) = native_owned_context().await;
    for number in 0..16 {
        native_worker_bootstrap(
            &mut bound,
            if number % 2 == 0 {
                "worker"
            } else {
                "shared_worker"
            },
            &number.to_string(),
            None,
        )
        .await;
    }
    write_message(&mut bound.writer, json!({"method":"Target.detachedFromTarget","params":{"targetId":"native-0","sessionId":"flat-native-0"}})).await;
    tokio::time::timeout(Duration::from_millis(300), async {
        while bound.manager.has_ready_target("native-0") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exact retirement should remove readiness");
    // The late second lifecycle notification must not release another worker's charge.
    write_message(
        &mut bound.writer,
        json!({"method":"Target.targetDestroyed","params":{"targetId":"native-0"}}),
    )
    .await;
    native_worker_bootstrap(&mut bound, "worker", "replacement", None).await;
    write_message(
        &mut bound.writer,
        native_worker_attached("worker", "overflow", None),
    )
    .await;
    tokio::time::timeout(Duration::from_millis(300), async {
        while !bound.manager.is_tainted() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker quota exhaustion must drain without resuming the new target");
    assert!(has_no_command_bytes(&mut bound.reader, true).await);
    assert!(!bound.manager.has_ready_target("native-overflow"));
    assert!(bound.drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn known_forbidden_target_kinds_close_while_paused_without_an_admission_permit() {
    for kind in ["prerender", "background_page", "other"] {
        let mut page = owned_page().await;
        write_message(&mut page.writer, json!({
            "method":"Target.attachedToTarget",
            "params":{"sessionId":"flat-forbidden","waitingForDebugger":true,
                "targetInfo":{"targetId":"forbidden","browserContextId":"owned-context","type":kind}}
        })).await;
        let close = read_command(&mut page.reader).await;
        assert_eq!(close["method"], "Target.closeTarget");
        assert_eq!(close["params"]["targetId"], "forbidden");
        // An exact destruction can arrive before the close ACK. It must not try to
        // release a quota permit that this known forbidden target never received.
        write_message(
            &mut page.writer,
            json!({"method":"Target.targetDestroyed","params":{"targetId":"forbidden"}}),
        )
        .await;
        respond(&mut page.writer, &close, json!({"success":true})).await;
        tokio::time::timeout(Duration::from_millis(300), async {
            while !page.manager.is_tainted() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("known unsupported kind must drain after exact paused cleanup");
        assert!(has_no_command_bytes(&mut page.reader, true).await);
        assert!(!page.manager.has_ready_target("forbidden"));
    }
}

#[tokio::test]
async fn unknown_target_kind_still_drains_without_admission_or_resume() {
    let mut page = owned_page().await;
    write_message(&mut page.writer, json!({
        "method":"Target.attachedToTarget",
        "params":{"sessionId":"flat-unknown","waitingForDebugger":true,
            "targetInfo":{"targetId":"unknown-kind","browserContextId":"owned-context","type":"future-unrecognized-kind"}}
    })).await;
    tokio::time::timeout(Duration::from_millis(300), async {
        while !page.manager.is_tainted() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unknown target kind must fail closed immediately");
    assert!(has_no_command_bytes(&mut page.reader, true).await);
    assert!(!page.manager.has_ready_target("unknown-kind"));
}

#[tokio::test]
async fn native_worker_network_hook_failure_closes_without_resuming() {
    let (mut bound, _, _, _) = native_owned_context().await;
    write_message(
        &mut bound.writer,
        native_worker_attached("service_worker", "failed-network", None),
    )
    .await;
    let recursive = read_command(&mut bound.reader).await;
    assert_eq!(recursive["method"], "Target.setAutoAttach");
    respond(&mut bound.writer, &recursive, json!({})).await;
    let network = read_command(&mut bound.reader).await;
    assert_eq!(network["method"], "Network.enable");
    write_message(
        &mut bound.writer,
        json!({"id":network["id"],"error":{"code":-32000,"message":"network hooks unavailable"}}),
    )
    .await;
    let close = read_command(&mut bound.reader).await;
    assert_eq!(close["method"], "Target.closeTarget");
    assert_eq!(close["params"]["targetId"], "native-failed-network");
    respond(&mut bound.writer, &close, json!({"success":true})).await;
    tokio::time::timeout(Duration::from_millis(300), async {
        while !bound.manager.is_tainted() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed worker bootstrap must drain");
    assert!(has_no_command_bytes(&mut bound.reader, true).await);
    assert!(!bound.manager.has_ready_target("native-failed-network"));
}

async fn disposed_native_context_with_service(
    detach_before_ack: bool,
) -> (BoundProfileOwner, TenantId, SessionId) {
    let (mut bound, tenant, session, _) = native_owned_context().await;
    native_worker_bootstrap(&mut bound, "service_worker", "surviving-service", None).await;
    let dispose = tokio::task::spawn_blocking({
        let driver = bound.driver.clone();
        let session = session.clone();
        move || driver.close_context_fenced(&session, &ownership_fence())
    });
    let command = read_command(&mut bound.reader).await;
    assert_eq!(command["method"], "Target.disposeBrowserContext");
    write_message(
        &mut bound.writer,
        json!({"method":"Target.targetDestroyed","params":{"targetId":"options-primary"}}),
    )
    .await;
    if detach_before_ack {
        write_message(&mut bound.writer, json!({"method":"Target.detachedFromTarget","params":{"targetId":"native-surviving-service","sessionId":"flat-native-surviving-service"}})).await;
    }
    respond(&mut bound.writer, &command, json!({})).await;
    assert_eq!(dispose.await.unwrap(), Ok(()));
    (bound, tenant, session)
}

#[tokio::test]
async fn disposed_known_worker_without_context_id_waits_for_exact_absence_proof() {
    let (mut bound, tenant, session) = disposed_native_context_with_service(false).await;
    let verify = tokio::task::spawn_blocking({
        let backend = bound.owner.target_manager_backend();
        move || {
            backend.verify_context_disposed_until(
                &tenant,
                &session,
                &ownership_fence(),
                Instant::now() + Duration::from_secs(1),
            )
        }
    });
    let first = read_command(&mut bound.reader).await;
    assert_eq!(first["method"], "Target.getTargets");
    respond(
        &mut bound.writer,
        &first,
        json!({"targetInfos":[{"targetId":"native-surviving-service","type":"service_worker"}]}),
    )
    .await;
    let retry = read_command(&mut bound.reader).await;
    assert_eq!(retry["method"], "Target.getTargets");
    assert!(
        bound.manager.has_ready_target("native-surviving-service"),
        "transient missing context metadata must not release the owned route"
    );
    respond(&mut bound.writer, &retry, json!({"targetInfos":[]})).await;
    let contexts = read_command(&mut bound.reader).await;
    assert_eq!(contexts["method"], "Target.getBrowserContexts");
    assert!(bound.manager.has_ready_target("native-surviving-service"));
    respond(
        &mut bound.writer,
        &contexts,
        json!({"browserContextIds":[]}),
    )
    .await;
    assert_eq!(verify.await.unwrap(), Ok(()));
    assert!(!bound.manager.has_ready_target("native-surviving-service"));
    assert!(!bound.manager.is_tainted());
    // A delayed exact notification after snapshot-proven retirement is harmless.
    write_message(&mut bound.writer, json!({"method":"Target.detachedFromTarget","params":{"targetId":"native-surviving-service","sessionId":"flat-native-surviving-service"}})).await;
    assert!(has_no_command_bytes(&mut bound.reader, false).await);
    bound
        .owner
        .shutdown_and_join(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn worker_detached_before_dispose_ack_keeps_its_pinned_cleanup_identity() {
    let (mut bound, tenant, session) = disposed_native_context_with_service(true).await;
    let verify = tokio::task::spawn_blocking({
        let backend = bound.owner.target_manager_backend();
        move || {
            backend.verify_context_disposed_until(
                &tenant,
                &session,
                &ownership_fence(),
                Instant::now() + Duration::from_secs(1),
            )
        }
    });
    let first = read_command(&mut bound.reader).await;
    assert_eq!(first["method"], "Target.getTargets");
    respond(
        &mut bound.writer,
        &first,
        json!({"targetInfos":[{"targetId":"native-surviving-service","type":"service_worker"}]}),
    )
    .await;
    let retry = read_command(&mut bound.reader).await;
    assert_eq!(retry["method"], "Target.getTargets");
    respond(&mut bound.writer, &retry, json!({"targetInfos":[]})).await;
    let contexts = read_command(&mut bound.reader).await;
    assert_eq!(contexts["method"], "Target.getBrowserContexts");
    respond(
        &mut bound.writer,
        &contexts,
        json!({"browserContextIds":[]}),
    )
    .await;
    assert_eq!(verify.await.unwrap(), Ok(()));
    assert!(!bound.manager.has_ready_target("native-surviving-service"));
    assert!(!bound.manager.is_tainted());
    bound
        .owner
        .shutdown_and_join(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn disposed_unknown_contextless_worker_is_rejected_without_retry_or_release() {
    let (mut bound, tenant, session) = disposed_native_context_with_service(false).await;
    let verify = tokio::task::spawn_blocking({
        let backend = bound.owner.target_manager_backend();
        move || {
            backend.verify_context_disposed_until(
                &tenant,
                &session,
                &ownership_fence(),
                Instant::now() + Duration::from_secs(1),
            )
        }
    });
    let first = read_command(&mut bound.reader).await;
    respond(
        &mut bound.writer,
        &first,
        json!({"targetInfos":[{"targetId":"never-owned-worker","type":"service_worker"}]}),
    )
    .await;
    assert_eq!(
        verify.await.unwrap(),
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    assert!(has_no_command_bytes(&mut bound.reader, true).await);
    assert!(
        bound.manager.has_ready_target("native-surviving-service"),
        "an unknown target cannot release another target's reservation"
    );
}

#[tokio::test]
async fn disposed_worker_cleanup_deadline_does_not_confirm_retirement() {
    let (mut bound, tenant, session) = disposed_native_context_with_service(false).await;
    let started = Instant::now();
    let verify = tokio::task::spawn_blocking({
        let backend = bound.owner.target_manager_backend();
        move || {
            backend.verify_context_disposed_until(
                &tenant,
                &session,
                &ownership_fence(),
                started + Duration::from_millis(200),
            )
        }
    });
    let first = read_command(&mut bound.reader).await;
    respond(
        &mut bound.writer,
        &first,
        json!({"targetInfos":[{"targetId":"native-surviving-service","type":"service_worker"}]}),
    )
    .await;
    let retry = read_command(&mut bound.reader).await;
    assert_eq!(retry["method"], "Target.getTargets");
    // Withhold the last response: the original absolute deadline still bounds the probe.
    assert_eq!(
        verify.await.unwrap(),
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        bound.manager.has_ready_target("native-surviving-service"),
        "timeout is not retirement evidence; cleanup ownership must remain held"
    );
    assert!(has_no_command_bytes(&mut bound.reader, true).await);
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
    for _ in 0..7 {
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
    tenant_id: TenantId,
}

async fn owned_page() -> OwnedPage {
    owned_page_with_options(false).await
}

async fn owned_page_with_options(options: bool) -> OwnedPage {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        connection_config(),
        shard_fence(),
        16,
        drain.clone(),
    )
    .unwrap();
    let driver = owner.chromium_driver(if options {
        IsolationProfile::DedicatedProcess
    } else {
        IsolationProfile::SharedContext
    });
    let (pipes, mut reader, mut writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = owner.clone();
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut reader, &mut writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(manager.clone(), &mut reader, &mut writer).await;
    let session_id = SessionId::new();
    let tenant_id = TenantId::new();
    let page_id = if options {
        create_owned_options_context(
            driver.clone(),
            tenant_id.clone(),
            session_id.clone(),
            ownership_fence(),
            &mut reader,
            &mut writer,
        )
        .await
    } else {
        create_owned_context(
            driver.clone(),
            tenant_id.clone(),
            session_id.clone(),
            ownership_fence(),
            &mut reader,
            &mut writer,
        )
        .await
    };
    OwnedPage {
        _owner: owner,
        manager,
        drain,
        driver,
        reader,
        writer,
        session_id,
        page_id,
        tenant_id,
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

#[tokio::test]
async fn generic_fill_secret_rejects_unprepared_references_before_cdp() {
    let mut page = owned_page().await;
    let result = spawn_action(
        &page,
        br#"{"type":"fill_secret","node_ref":"opaque-node","secret_ref":"login-password"}"#,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        result,
        ActionExecutionResult::FailedKnown("secret_preparation_required".to_owned())
    );
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    assert!(!page.manager.is_tainted());
    assert!(!page.drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn generic_set_files_requires_prepared_artifacts_and_never_dispatches_paths() {
    let mut page = owned_page().await;
    let node = mint_node(&mut page, 42).await;
    let payload = serde_json::to_vec(&json!({"type":"set_files","node_ref":node,
        "artifact_ids":[browserd_core::ArtifactId::new().to_string()]}))
    .unwrap();
    let result = spawn_action_owned(&page, payload, None).await.unwrap();
    assert_eq!(
        result,
        ActionExecutionResult::FailedKnown("artifact_preparation_required".to_owned())
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), read_command(&mut page.reader))
            .await
            .is_err()
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
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

/// Admits the mutation only after a readonly check in the exact default realm.
async fn respond_node_document_preflight(
    page: &mut OwnedPage,
    session: &str,
    object_id: &str,
    valid: bool,
) {
    let preflight = read_command(&mut page.reader).await;
    assert_eq!(preflight["method"], "Runtime.callFunctionOn");
    assert_eq!(preflight["sessionId"], session);
    assert_eq!(
        preflight["params"]["uniqueContextId"],
        format!("realm-{session}")
    );
    assert_eq!(
        preflight["params"]["arguments"],
        json!([{"objectId":object_id}])
    );
    assert_eq!(preflight["params"]["throwOnSideEffect"], true);
    assert_eq!(preflight["params"]["awaitPromise"], false);
    assert_eq!(
        preflight["params"]["functionDeclaration"],
        "function (node) { return node.isConnected && node.ownerDocument === document; }"
    );
    respond(
        &mut page.writer,
        &preflight,
        json!({"result":{"value":valid}}),
    )
    .await;
}

/// The fake target deliberately has a different ID from its frame.
async fn attach_owned_oopif(page: &mut OwnedPage) {
    write_message(&mut page.writer, json!({"method":"Page.frameAttached","sessionId":"flat-primary","params":{"frameId":"frame-flat-child","parentFrameId":"frame-flat-primary"}})).await;
    write_message(&mut page.writer, paused_child("owned-context")).await;
    for method in [
        "Target.setAutoAttach",
        "Network.enable",
        "Runtime.enable",
        "Page.enable",
        "Page.getFrameTree",
        "Page.setInterceptFileChooserDialog",
        "Runtime.runIfWaitingForDebugger",
    ] {
        let command = read_command(&mut page.reader).await;
        assert_eq!(command["method"], method);
        assert_eq!(command["sessionId"], "flat-child");
        respond(&mut page.writer, &command, json!({})).await;
    }
}

async fn mint_oopif_node(page: &mut OwnedPage) -> String {
    let query = spawn_action(
        page,
        br##"{"type":"query_all","selector":"input","frame_path":["#remote"]}"##,
        None,
    );
    for (session, method, result) in [
        (
            "flat-primary",
            "DOM.getDocument",
            json!({"root":{"nodeId":1}}),
        ),
        (
            "flat-primary",
            "DOM.querySelectorAll",
            json!({"nodeIds":[2]}),
        ),
        (
            "flat-primary",
            "DOM.describeNode",
            json!({"node":{"backendNodeId":12,"nodeName":"IFRAME","frameId":"frame-flat-child"}}),
        ),
        (
            "flat-child",
            "DOM.getDocument",
            json!({"root":{"nodeId":100}}),
        ),
        (
            "flat-child",
            "DOM.querySelectorAll",
            json!({"nodeIds":[101]}),
        ),
        (
            "flat-child",
            "DOM.describeNode",
            json!({"node":{"backendNodeId":500}}),
        ),
    ] {
        let command = read_command(&mut page.reader).await;
        assert_eq!(command["method"], method);
        assert_eq!(command["sessionId"], session);
        respond(&mut page.writer, &command, result).await;
    }
    let value: Value = serde_json::from_slice(&succeeded_bytes(query.await.unwrap())).unwrap();
    value["node_refs"][0].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn oopif_node_routes_by_frame_binding_and_unique_realm_not_target_id() {
    let mut page = owned_page().await;
    attach_owned_oopif(&mut page).await;
    let node = mint_oopif_node(&mut page).await;
    let action = spawn_action_owned(
        &page,
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"한국어"})).unwrap(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    assert_eq!(resolve["sessionId"], "flat-child");
    assert_eq!(resolve["params"]["backendNodeId"], 500);
    assert_eq!(resolve["params"]["executionContextId"], 1);
    respond(
        &mut page.writer,
        &resolve,
        json!({"object":{"objectId":"child-input"}}),
    )
    .await;
    respond_node_document_preflight(&mut page, "flat-child", "child-input", true).await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["sessionId"], "flat-child");
    assert_eq!(call["params"]["uniqueContextId"], "realm-flat-child");
    assert_eq!(call["params"]["arguments"][0]["objectId"], "child-input");
    respond(&mut page.writer, &call, json!({"result":{"value":true}})).await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;
    assert_eq!(action.await.unwrap(), succeeded());
    // A completed child operation must leave no implicit guard on node-free work.
    let title = spawn_action(&page, br#"{"type":"get_title"}"#, None);
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["sessionId"], "flat-primary");
    respond(
        &mut page.writer,
        &command,
        json!({"result":{"value":"top"}}),
    )
    .await;
    assert!(matches!(
        title.await.unwrap(),
        ActionExecutionResult::Succeeded(_)
    ));
}

#[tokio::test]
async fn oopif_realm_reuse_cannot_revive_old_node_and_does_not_leak_guard() {
    let mut page = owned_page().await;
    attach_owned_oopif(&mut page).await;
    let node = mint_oopif_node(&mut page).await;
    write_message(
        &mut page.writer,
        json!({"method":"Runtime.executionContextsCleared","sessionId":"flat-child","params":{}}),
    )
    .await;
    write_message(&mut page.writer,json!({"method":"Runtime.executionContextCreated","sessionId":"flat-child","params":{"context":{"id":1,"uniqueId":"replacement-realm","auxData":{"isDefault":true,"frameId":"frame-flat-child"}}}})).await;
    let sync = spawn_action(&page, br#"{"type":"get_title"}"#, None);
    let command = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &command,
        json!({"result":{"value":"sync"}}),
    )
    .await;
    let _ = sync.await.unwrap();
    let action = spawn_action_owned(
        &page,
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"test"})).unwrap(),
        None,
    );
    assert_eq!(
        action.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn child_effect_interrupted_by_parent_navigation_is_unknown() {
    let mut page = owned_page().await;
    attach_owned_oopif(&mut page).await;
    let node = mint_oopif_node(&mut page).await;
    let action = spawn_action_owned(
        &page,
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"test"})).unwrap(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &resolve,
        json!({"object":{"objectId":"child-input"}}),
    )
    .await;
    respond_node_document_preflight(&mut page, "flat-child", "child-input", true).await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    // This first navigation event is the intended interruption. Do not use
    // write_message's ordinary new-realm follow-up after the owner has drained.
    let mut event = serde_json::to_vec(&frame_navigated(
        "flat-primary",
        "frame-flat-primary",
        "replacement-loader",
        "https://example.test/replaced",
    ))
    .unwrap();
    event.push(0);
    page.writer.write_all(&event).await.unwrap();
    assert_eq!(action.await.unwrap(), ActionExecutionResult::OutcomeUnknown);
}

#[tokio::test]
async fn adopted_child_node_is_rejected_before_any_mutating_call() {
    let mut page = owned_page().await;
    attach_owned_oopif(&mut page).await;
    let node = mint_oopif_node(&mut page).await;
    let action = spawn_action_owned(
        &page,
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"must not apply"}))
            .unwrap(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    respond(
        &mut page.writer,
        &resolve,
        json!({"object":{"objectId":"adopted-input"}}),
    )
    .await;
    respond_node_document_preflight(&mut page, "flat-child", "adopted-input", false).await;
    // The only follow-up must release the wrapper. No helper with mutation arguments,
    // fallback route or Input command may run against the adopted node.
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    assert_eq!(release["sessionId"], "flat-child");
    assert_eq!(release["params"]["objectId"], "adopted-input");
    respond(&mut page.writer, &release, json!({})).await;
    assert_eq!(
        action.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    assert!(!page.manager.is_tainted());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    let title = spawn_action(&page, br#"{"type":"get_title"}"#, None);
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["sessionId"], "flat-primary");
    respond(
        &mut page.writer,
        &command,
        json!({"result":{"value":"still owned"}}),
    )
    .await;
    assert!(matches!(
        title.await.unwrap(),
        ActionExecutionResult::Succeeded(_)
    ));
}

#[tokio::test]
async fn child_mutation_exception_after_document_preflight_is_still_unknown() {
    let mut page = owned_page().await;
    attach_owned_oopif(&mut page).await;
    let node = mint_oopif_node(&mut page).await;
    let action = spawn_action_owned(
        &page,
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"test"})).unwrap(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &resolve,
        json!({"object":{"objectId":"child-input"}}),
    )
    .await;
    respond_node_document_preflight(&mut page, "flat-child", "child-input", true).await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["arguments"][1]["value"], "test");
    assert!(
        call["params"]["functionDeclaration"]
            .as_str()
            .unwrap()
            .contains("node.ownerDocument !== document")
    );
    respond(
        &mut page.writer,
        &call,
        json!({"exceptionDetails":{"text":"guard changed after preflight"}}),
    )
    .await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;
    assert_eq!(action.await.unwrap(), ActionExecutionResult::OutcomeUnknown);
}

#[tokio::test]
async fn worker_default_contexts_without_frame_ids_do_not_invalidate_page_nodes() {
    let mut page = owned_page().await;
    let node = mint_node(&mut page, 42).await;
    for kind in ["worker", "shared_worker", "service_worker"] {
        let flat = format!("flat-{kind}");
        write_message(&mut page.writer, json!({"method":"Target.attachedToTarget","params":{"sessionId":flat,"waitingForDebugger":true,"targetInfo":{"targetId":format!("target-{kind}"),"browserContextId":"owned-context","type":kind}}})).await;
        for method in [
            "Target.setAutoAttach",
            "Network.enable",
            "Runtime.enable",
            "Runtime.runIfWaitingForDebugger",
        ] {
            let command = read_command(&mut page.reader).await;
            assert_eq!(command["method"], method);
            assert_eq!(command["sessionId"], flat);
            if method == "Runtime.enable" {
                write_message(&mut page.writer, json!({"method":"Runtime.executionContextCreated","sessionId":flat,"params":{"context":{"id":1,"uniqueId":format!("worker-realm-{kind}"),"auxData":{"isDefault":true,"type":"worker"}}}})).await;
            }
            respond(&mut page.writer, &command, json!({})).await;
        }
        write_message(&mut page.writer, json!({"method":"Runtime.executionContextDestroyed","sessionId":flat,"params":{"executionContextId":1}})).await;
        write_message(
            &mut page.writer,
            json!({"method":"Runtime.executionContextsCleared","sessionId":flat,"params":{}}),
        )
        .await;
    }
    let read = spawn_action_owned(
        &page,
        serde_json::to_vec(&json!({"type":"get_text","node_ref":node})).unwrap(),
        None,
    );
    for (method, result) in [
        (
            "DOM.resolveNode",
            json!({"object":{"objectId":"page-node"}}),
        ),
        (
            "Runtime.callFunctionOn",
            json!({"result":{"value":"still owned"}}),
        ),
        ("Runtime.releaseObject", json!({})),
    ] {
        let command = read_command(&mut page.reader).await;
        assert_eq!(command["method"], method);
        assert_eq!(command["sessionId"], "flat-primary");
        respond(&mut page.writer, &command, result).await;
    }
    assert!(matches!(
        read.await.unwrap(),
        ActionExecutionResult::Succeeded(_)
    ));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn reused_numeric_context_id_for_another_frame_cannot_keep_a_stale_realm_live() {
    let mut page = owned_page().await;
    let node = mint_node(&mut page, 42).await;
    write_message(&mut page.writer, json!({"method":"Page.frameAttached","sessionId":"flat-primary","params":{"frameId":"child-frame","parentFrameId":"frame-flat-primary"}})).await;
    write_message(&mut page.writer, json!({"method":"Runtime.executionContextCreated","sessionId":"flat-primary","params":{"context":{"id":1,"uniqueId":"different-document-realm","auxData":{"isDefault":true,"frameId":"child-frame"}}}})).await;
    let sync = spawn_action(&page, br#"{"type":"get_title"}"#, None);
    let command = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &command,
        json!({"result":{"value":"sync"}}),
    )
    .await;
    let _ = sync.await.unwrap();
    let action = spawn_action_owned(
        &page,
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"unused"})).unwrap(),
        None,
    );
    assert_eq!(
        action.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    assert!(!page.manager.is_tainted());
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
async fn navigate_load_bootstraps_a_paused_child_without_reentering_page_actions() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/oopif","wait_until":"load"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &command,
        json!({"frameId":"frame", "loaderId":"oopif-loader"}),
    )
    .await;
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "oopif-loader",
            "https://example.test/oopif",
        ),
    )
    .await;
    write_message(&mut page.writer, paused_child("owned-context")).await;
    let backend = page._owner.target_manager_backend();
    let unrelated_request =
        tokio::task::spawn_blocking(move || backend.target_route("primary-target"));
    for method in [
        "Target.setAutoAttach",
        "Network.enable",
        "Runtime.enable",
        "Page.enable",
        "Page.getFrameTree",
        "Page.setInterceptFileChooserDialog",
        "Runtime.runIfWaitingForDebugger",
    ] {
        let command =
            tokio::time::timeout(Duration::from_millis(300), read_command(&mut page.reader))
                .await
                .expect("child bootstrap must progress before the parent's load event");
        assert_eq!(command["method"], method);
        assert_eq!(command["sessionId"], "flat-child");
        if method == "Target.setAutoAttach" {
            assert_eq!(command["params"]["waitForDebuggerOnStart"], true);
            assert_eq!(command["params"]["flatten"], true);
        }
        assert!(!navigate.is_finished());
        assert!(
            !unrelated_request.is_finished(),
            "only target-bootstrap requests may run inside an active page action"
        );
        respond(&mut page.writer, &command, json!({})).await;
    }
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    assert_eq!(navigate.await.unwrap(), succeeded());
    assert!(unrelated_request.await.unwrap().unwrap().is_some());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn navigate_load_bootstraps_a_child_before_the_navigate_response() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/oopif","wait_until":"load"}"#,
        None,
    );
    let navigate_command = read_command(&mut page.reader).await;
    write_message(&mut page.writer, paused_child("owned-context")).await;
    for method in [
        "Target.setAutoAttach",
        "Network.enable",
        "Runtime.enable",
        "Page.enable",
        "Page.getFrameTree",
        "Page.setInterceptFileChooserDialog",
        "Runtime.runIfWaitingForDebugger",
    ] {
        let command =
            tokio::time::timeout(Duration::from_millis(300), read_command(&mut page.reader))
                .await
                .expect("a child attached before the navigate response must be bootstrapped");
        assert_eq!(command["method"], method);
        assert_eq!(command["sessionId"], "flat-child");
        respond(&mut page.writer, &command, json!({})).await;
    }
    respond(
        &mut page.writer,
        &navigate_command,
        json!({"frameId":"frame", "loaderId":"oopif-loader"}),
    )
    .await;
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame",
            "oopif-loader",
            "https://example.test/oopif",
        ),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-primary", "Page.loadEventFired"),
    )
    .await;
    assert_eq!(navigate.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn navigate_child_bootstrap_obeys_the_original_action_deadline() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/oopif","wait_until":"load"}"#,
        Some(Instant::now() + Duration::from_millis(200)),
    );
    let navigate_command = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &navigate_command,
        json!({"frameId":"frame", "loaderId":"oopif-loader"}),
    )
    .await;
    write_message(&mut page.writer, paused_child("owned-context")).await;
    let child_command = read_command(&mut page.reader).await;
    assert_eq!(child_command["method"], "Target.setAutoAttach");
    // No response: target bootstrap must not extend the parent's absolute deadline.
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(350), navigate)
            .await
            .expect("the original action deadline must bound child bootstrap")
            .unwrap(),
        ActionExecutionResult::OutcomeUnknown
    );
    assert!(page.manager.is_tainted());
    assert!(page.drain.0.load(Ordering::SeqCst));
    assert!(has_no_command_bytes(&mut page.reader, true).await);
}

#[tokio::test]
async fn navigate_child_bootstrap_is_interrupted_by_owner_shutdown() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/oopif","wait_until":"load"}"#,
        None,
    );
    let navigate_command = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &navigate_command,
        json!({"frameId":"frame", "loaderId":"oopif-loader"}),
    )
    .await;
    write_message(&mut page.writer, paused_child("owned-context")).await;
    let child_command = read_command(&mut page.reader).await;
    assert_eq!(child_command["method"], "Target.setAutoAttach");
    assert!(
        page._owner
            .shutdown_and_join(Duration::from_millis(200))
            .await
            .is_err(),
        "shutdown after submitted effects remains an uncertain outcome"
    );
    assert_eq!(
        navigate.await.unwrap(),
        ActionExecutionResult::OutcomeUnknown
    );
    assert!(has_no_command_bytes(&mut page.reader, true).await);
}

#[tokio::test]
async fn navigate_load_never_bootstraps_a_child_from_an_unknown_context() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/oopif","wait_until":"load"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &command,
        json!({"frameId":"frame", "loaderId":"oopif-loader"}),
    )
    .await;
    write_message(&mut page.writer, paused_child("foreign-context")).await;
    assert_eq!(
        navigate.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(page.manager.is_tainted());
    assert!(page.drain.0.load(Ordering::SeqCst));
    let backend = page._owner.target_manager_backend();
    let route = tokio::task::spawn_blocking(move || backend.target_route("primary-target"))
        .await
        .unwrap();
    assert_eq!(route, Err(ShardRuntimeError::OutcomeUncertain));
    assert_eq!(
        page._owner
            .shutdown_and_join(Duration::from_millis(200))
            .await,
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), page.reader.read(&mut byte))
            .await
            .expect("foreign attachment must terminate the CDP writer")
            .unwrap(),
        0,
        "foreign attachment must not emit any bootstrap or resume effect"
    );
}

#[tokio::test]
async fn active_command_unknown_context_attach_rejects_followup_requests() {
    let mut page = owned_page().await;
    let evaluate = spawn_action(&page, br#"{"type":"evaluate","expression":"1 + 2"}"#, None);
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Runtime.evaluate");
    // The response never arrives: fail closure must happen while this command waits.
    write_message(&mut page.writer, paused_child("foreign-context")).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), evaluate)
            .await
            .expect("foreign attachment must interrupt the active command")
            .unwrap(),
        ActionExecutionResult::OutcomeUnknown
    );
    assert!(page.manager.is_tainted());
    assert!(page.drain.0.load(Ordering::SeqCst));
    assert_eq!(
        spawn_action(&page, br#"{"type":"evaluate","expression":"4 + 5"}"#, None)
            .await
            .unwrap(),
        ActionExecutionResult::OutcomeUnknown
    );
    assert_eq!(
        page._owner
            .shutdown_and_join(Duration::from_millis(200))
            .await,
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), page.reader.read(&mut byte))
            .await
            .expect("foreign attachment must terminate the CDP writer")
            .unwrap(),
        0,
        "neither foreign bootstrap nor the followup action may reach CDP"
    );
}

#[tokio::test]
async fn active_child_bootstrap_unknown_context_attach_terminates_the_owner() {
    let mut page = owned_page().await;
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/oopif","wait_until":"load"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &command,
        json!({"frameId":"frame", "loaderId":"oopif-loader"}),
    )
    .await;
    write_message(&mut page.writer, paused_child("owned-context")).await;
    let bootstrap = read_command(&mut page.reader).await;
    assert_eq!(bootstrap["method"], "Target.setAutoAttach");
    assert_eq!(bootstrap["sessionId"], "flat-child");
    // A foreign target interrupts the owned child's in-flight bootstrap command.
    let mut foreign = paused_child("foreign-context");
    foreign["params"]["sessionId"] = json!("flat-foreign-child");
    foreign["params"]["targetInfo"]["targetId"] = json!("foreign-child-target");
    write_message(&mut page.writer, foreign).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), navigate)
            .await
            .expect("foreign attachment must interrupt nested child bootstrap")
            .unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(page.manager.is_tainted());
    assert!(page.drain.0.load(Ordering::SeqCst));
    assert_eq!(
        spawn_action(&page, br#"{"type":"evaluate","expression":"4 + 5"}"#, None)
            .await
            .unwrap(),
        ActionExecutionResult::OutcomeUnknown
    );
    assert_eq!(
        page._owner
            .shutdown_and_join(Duration::from_millis(200))
            .await,
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), page.reader.read(&mut byte))
            .await
            .expect("foreign attachment must terminate the CDP writer")
            .unwrap(),
        0,
        "no further owned or foreign bootstrap effect may reach CDP"
    );
}

#[tokio::test]
async fn options_navigation_applies_iframe_language_and_user_agent_before_resume() {
    let mut page = tokio::time::timeout(Duration::from_secs(10), owned_page_with_options(true))
        .await
        .expect("options-aware owner setup must be bounded");
    let navigate = spawn_action(
        &page,
        br#"{"type":"navigate","url":"https://example.test/oopif","wait_until":"load"}"#,
        None,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["sessionId"], "flat-options-primary");
    respond(
        &mut page.writer,
        &command,
        json!({"frameId":"frame", "loaderId":"oopif-loader"}),
    )
    .await;
    write_message(&mut page.writer, paused_child("options-context")).await;
    for (method, params) in [
        (
            "Target.setAutoAttach",
            json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}),
        ),
        (
            "Network.setUserAgentOverride",
            json!({"userAgent": "browserd-options-test/1.0", "acceptLanguage": "ko-KR"}),
        ),
        ("Network.enable", json!({})),
        ("Runtime.enable", json!({})),
        ("Page.enable", json!({})),
        ("Page.getFrameTree", json!({})),
        (
            "Page.setInterceptFileChooserDialog",
            json!({"enabled": true}),
        ),
        ("Runtime.runIfWaitingForDebugger", json!({})),
    ] {
        let command =
            tokio::time::timeout(Duration::from_millis(300), read_command(&mut page.reader))
                .await
                .expect("owned iframe must pass its barrier under options-aware navigation");
        assert_eq!(command["method"], method);
        assert_eq!(command["params"], params);
        assert_eq!(command["sessionId"], "flat-child");
        respond(&mut page.writer, &command, json!({})).await;
    }
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-options-primary",
            "frame",
            "oopif-loader",
            "https://example.test/oopif",
        ),
    )
    .await;
    write_message(
        &mut page.writer,
        lifecycle_event("flat-options-primary", "Page.loadEventFired"),
    )
    .await;
    assert_eq!(navigate.await.unwrap(), succeeded());
    assert!(!page.manager.is_tainted());
    let driver = page.driver.clone();
    let tenant = page.tenant_id.clone();
    let session = page.session_id.clone();
    let pages = tokio::task::spawn_blocking(move || {
        driver.list_pages_owned(&tenant, &session, &ownership_fence())
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(pages, vec![page.page_id]);
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
    assert_eq!(call["params"]["arguments"][0]["objectId"], "obj-1");
    assert_eq!(call["params"]["uniqueContextId"], "realm-flat-primary");
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
    assert_eq!(call["params"]["arguments"][1]["value"], "href");
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

/// Drives the resolve + actionability-helper + release sequence `node_pointer_target` issues,
/// reporting the actionable point `(x, y)`.
async fn respond_actionable_point(page: &mut OwnedPage, x: f64, y: f64) {
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-point"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["awaitPromise"], true);
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"value": {"ok": true, "x": x, "y": y}}}),
    )
    .await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;
}

/// Drives the same sequence but reports the element as not actionable (off-screen/occluded/no box).
async fn respond_unactionable_point(page: &mut OwnedPage) {
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    respond(
        &mut page.writer,
        &resolve,
        json!({"object": {"objectId": "obj-point"}}),
    )
    .await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["awaitPromise"], true);
    respond(
        &mut page.writer,
        &call,
        json!({"result": {"value": {"ok": false}}}),
    )
    .await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;
}

#[tokio::test]
async fn click_dispatches_at_the_actionable_point() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 300).await;

    let click = spawn_action_owned(
        &page,
        format!(r#"{{"type":"click","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    respond_actionable_point(&mut page, 20.0, 30.0).await;

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
async fn click_of_an_unactionable_node_is_rejected() {
    let mut page = owned_page().await;
    let token = mint_node(&mut page, 301).await;

    let click = spawn_action_owned(
        &page,
        format!(r#"{{"type":"click","node_ref":"{token}"}}"#).into_bytes(),
        None,
    );
    // The element is off-screen/occluded/zero-area, so no actionable point is produced.
    respond_unactionable_point(&mut page).await;

    assert_eq!(
        click.await.unwrap(),
        ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
    );
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "an unactionable node dispatches no pointer events"
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
    respond_actionable_point(&mut page, 20.0, 10.0).await;
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
    respond_actionable_point(&mut page, 10.0, 10.0).await;
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
    respond_actionable_point(&mut page, 10.0, 10.0).await;

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
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    assert_eq!(resolve["params"]["backendNodeId"], 410);
    respond(
        &mut page.writer,
        &resolve,
        json!({"object":{"objectId":"obj-focus"}}),
    )
    .await;
    respond_node_document_preflight(&mut page, "flat-primary", "obj-focus", true).await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["awaitPromise"], false);
    assert!(
        call["params"]["functionDeclaration"]
            .as_str()
            .unwrap()
            .contains("ownerDocument")
    );
    respond(&mut page.writer, &call, json!({"result":{"value":true}})).await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;

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
    respond_node_document_preflight(&mut page, "flat-primary", "obj-c", true).await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["arguments"][1]["value"], true);
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
    respond_node_document_preflight(&mut page, "flat-primary", "obj-f", true).await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["arguments"][1]["value"], "hello world");
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
    respond_node_document_preflight(&mut page, "flat-primary", "obj-s", true).await;
    let call = read_command(&mut page.reader).await;
    assert_eq!(call["method"], "Runtime.callFunctionOn");
    assert_eq!(call["params"]["arguments"][1]["value"], json!(["a", "b"]));
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
    respond_node_document_preflight(&mut page, "flat-primary", "obj-div", true).await;
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
                "frameId": 0,
                "nodes": {"backendNodeId": [100, 200]},
                "layout": {"nodeIndex": [0], "bounds": [[1040.0, 30.0, 120.0, 40.0]]}
            }],
            "strings": ["frame-flat-primary"]
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
async fn evaluate_that_throws_is_unknown_and_keeps_observation_available() {
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

    assert_eq!(eval.await.unwrap(), ActionExecutionResult::OutcomeUnknown);
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
    let title = spawn_action(&page, br#"{"type":"get_title"}"#, None);
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Runtime.evaluate");
    assert_eq!(command["params"]["expression"], "globalThis.document.title");
    respond(
        &mut page.writer,
        &command,
        json!({"result":{"value":"still observable"}}),
    )
    .await;
    assert!(matches!(
        title.await.unwrap(),
        ActionExecutionResult::Succeeded(_)
    ));
}

async fn privileged_owned_context() -> (BoundProfileOwner, TenantId, SessionId, PageId) {
    let mut bound = bound_profile_owner(native_process_profile()).await;
    bound.driver = bound.driver.with_privileged_evaluate(true);
    let tenant = TenantId::new();
    let session = SessionId::new();
    let mut options = session_options();
    options.feature_profile = "privileged".to_owned();
    let page = create_owned_options_context_fixture(
        bound.driver.clone(),
        tenant.clone(),
        session.clone(),
        ownership_fence(),
        &mut bound.reader,
        &mut bound.writer,
        native_bootstrap_commands(),
        options,
    )
    .await;
    (bound, tenant, session, page)
}

fn spawn_privileged_evaluate(
    driver: browserd_worker::CdpChromiumDriver,
    tenant: TenantId,
    session: SessionId,
    page: PageId,
    fence: OwnershipFence,
    payload: &'static [u8],
    mut callback: impl FnMut(&browserd_worker::LiveApprovalContext) -> Result<(), ApprovedActionError>
    + Send
    + 'static,
) -> tokio::task::JoinHandle<Result<ActionExecutionResult, ApprovedActionError>> {
    tokio::task::spawn_blocking(move || {
        driver.execute_privileged_evaluate_until(
            &tenant,
            &session,
            &page,
            &fence,
            payload,
            Instant::now() + Duration::from_secs(2),
            &mut callback,
        )
    })
}

async fn respond_evaluate_origin(bound: &mut BoundProfileOwner, origin: &str) {
    let command = read_command(&mut bound.reader).await;
    assert_eq!(command["method"], "Page.getFrameTree");
    assert_eq!(command["sessionId"], "flat-options-primary");
    respond(&mut bound.writer, &command, json!({"frameTree":{"frame":{
        "id":"frame-flat-options-primary", "url":format!("{origin}/owned"), "securityOrigin":origin,
    }}})).await;
}

#[tokio::test]
async fn privileged_evaluate_and_privileged_contexts_default_to_denied() {
    let (mut bound, tenant, session, page) = native_owned_context().await;
    let called = Arc::new(AtomicBool::new(false));
    let result = spawn_privileged_evaluate(
        bound.driver.clone(),
        tenant,
        session,
        page,
        ownership_fence(),
        br#"{"type":"evaluate","expression":"1"}"#,
        {
            let called = called.clone();
            move |_| {
                called.store(true, Ordering::SeqCst);
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(result, Err(ApprovedActionError::DispatchRevoked));
    assert!(!called.load(Ordering::SeqCst));
    let create = tokio::task::spawn_blocking({
        let driver = bound.driver.clone();
        move || {
            let mut options = session_options();
            options.feature_profile = "privileged".to_owned();
            driver.create_context_owned_with_options(
                &TenantId::new(),
                &SessionId::new(),
                &ownership_fence(),
                &options,
            )
        }
    })
    .await
    .unwrap();
    assert_eq!(create, Err(DependencyError::Rejected));
    assert!(has_no_command_bytes(&mut bound.reader, false).await);
}

#[tokio::test]
async fn privileged_evaluate_rejects_standard_context_and_foreign_bindings_before_callback() {
    let (mut bound, tenant, session, page) = native_owned_context().await;
    let called = Arc::new(AtomicBool::new(false));
    let result = spawn_privileged_evaluate(
        bound.driver.clone().with_privileged_evaluate(true),
        tenant,
        session,
        page,
        ownership_fence(),
        br#"{"type":"evaluate","expression":"1"}"#,
        {
            let called = called.clone();
            move |_| {
                called.store(true, Ordering::SeqCst);
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(result, Err(ApprovedActionError::DispatchRevoked));
    assert!(!called.load(Ordering::SeqCst));
    assert!(has_no_command_bytes(&mut bound.reader, false).await);

    let (mut bound, tenant, session, page) = privileged_owned_context().await;
    for (tenant, fence, payload) in [
        (
            TenantId::new(),
            ownership_fence(),
            br#"{"type":"evaluate","expression":"1"}"#.as_slice(),
        ),
        (
            tenant.clone(),
            OwnershipFence::new(ownership_fence().worker_id().clone(), 17, 24, 29),
            br#"{"type":"evaluate","expression":"1"}"#.as_slice(),
        ),
        (
            tenant.clone(),
            ownership_fence(),
            br#"{"type":"get_title"}"#.as_slice(),
        ),
    ] {
        let called = Arc::new(AtomicBool::new(false));
        let result = spawn_privileged_evaluate(
            bound.driver.clone(),
            tenant,
            session.clone(),
            page.clone(),
            fence,
            payload,
            {
                let called = called.clone();
                move |_| {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result, Err(ApprovedActionError::DispatchRevoked));
        assert!(!called.load(Ordering::SeqCst));
        assert!(has_no_command_bytes(&mut bound.reader, false).await);
    }
}

#[tokio::test]
async fn privileged_evaluate_callback_denial_never_dispatches_expression() {
    let (mut bound, tenant, session, page) = privileged_owned_context().await;
    let called = Arc::new(AtomicBool::new(false));
    let action = spawn_privileged_evaluate(
        bound.driver.clone(),
        tenant,
        session,
        page,
        ownership_fence(),
        br#"{"type":"evaluate","expression":"globalThis.counter++"}"#,
        {
            let called = called.clone();
            move |live| {
                assert_eq!(live.current_origin.as_str(), "https://owned.test:8443");
                called.store(true, Ordering::SeqCst);
                Err(ApprovedActionError::DispatchRevoked)
            }
        },
    );
    respond_evaluate_origin(&mut bound, "https://owned.test:8443").await;
    assert_eq!(
        action.await.unwrap(),
        Err(ApprovedActionError::DispatchRevoked)
    );
    assert!(called.load(Ordering::SeqCst));
    assert!(has_no_command_bytes(&mut bound.reader, false).await);
    assert!(!bound.manager.is_tainted());
}

async fn spawn_manual_evaluate(
    bound: &mut BoundProfileOwner,
    tenant: &TenantId,
    session: &SessionId,
    page: &PageId,
    origin: &str,
    payload: &'static [u8],
    mut callback: impl FnMut(&browserd_worker::LiveApprovalContext) -> Result<(), ApprovedActionError>
    + Send
    + 'static,
) -> tokio::task::JoinHandle<Result<ActionExecutionResult, ApprovedActionError>> {
    let proposal = browserd_policy::CanonicalActionProposal::new(
        tenant.clone(),
        browserd_core::PrincipalId::new(),
        session.clone(),
        ownership_fence().session_incarnation(),
        page.clone(),
        1,
        1,
        browserd_policy::Origin::parse(origin).unwrap(),
        1,
        browserd_policy::ActionType::Evaluate,
        browserd_policy::ActionArgumentsHash::digest(payload),
        None,
        browserd_policy::CredentialRefsHash::digest(std::iter::empty::<&str>()),
        u64::MAX,
    );
    let inspect = tokio::task::spawn_blocking({
        let driver = bound.driver.clone();
        let session = session.clone();
        let page = page.clone();
        let proposal = proposal.clone();
        move || driver.inspect_approval_context(&session, &page, &proposal)
    });
    respond_evaluate_origin(bound, origin).await;
    let observed = inspect.await.unwrap().unwrap();
    assert_eq!(observed.current_origin.as_str(), origin);
    let driver = bound.driver.clone();
    let session = session.clone();
    let page = page.clone();
    tokio::task::spawn_blocking(move || {
        driver.execute_approved_action_until(
            &session,
            &page,
            payload,
            &proposal,
            &observed,
            Instant::now() + Duration::from_secs(2),
            &mut callback,
        )
    })
}

#[tokio::test]
async fn manual_evaluate_approval_uses_cdp_security_origin_and_exact_execution_realm() {
    let (mut bound, tenant, session, page) = native_owned_context().await;
    let action = spawn_manual_evaluate(
        &mut bound,
        &tenant,
        &session,
        &page,
        "https://owned.test:8443",
        br#"{"type":"evaluate","expression":"window.counter++"}"#,
        |live| {
            assert_eq!(live.current_origin.as_str(), "https://owned.test:8443");
            Ok(())
        },
    )
    .await;
    respond_evaluate_origin(&mut bound, "https://owned.test:8443").await;
    let effect = read_command(&mut bound.reader).await;
    assert_eq!(effect["method"], "Runtime.evaluate");
    assert_eq!(
        effect["params"]["uniqueContextId"],
        "realm-flat-options-primary"
    );
    respond(&mut bound.writer, &effect, json!({"result":{"value":1}})).await;
    assert_eq!(
        action.await.unwrap(),
        Ok(ActionExecutionResult::Succeeded(br#"{"value":1}"#.to_vec()))
    );
}

#[tokio::test]
async fn automatic_and_manual_evaluate_admission_include_only_literal_origin_ips() {
    let (mut bound, tenant, session, page) = privileged_owned_context().await;
    for (origin, expected_ip) in [
        ("http://127.0.0.1:8181", Some("127.0.0.1")),
        ("http://[::1]:8181", Some("::1")),
        ("https://owned.test", None),
    ] {
        for manual in [false, true] {
            let expected_ips: Vec<std::net::IpAddr> = expected_ip
                .map(|ip| ip.parse().unwrap())
                .into_iter()
                .collect();
            let callback = move |observed: &browserd_worker::LiveApprovalContext| {
                assert_eq!(observed.current_origin.as_str(), origin);
                assert_eq!(observed.resolved_ips, expected_ips);
                Err(ApprovedActionError::DispatchRevoked)
            };
            let action = if manual {
                spawn_manual_evaluate(
                    &mut bound,
                    &tenant,
                    &session,
                    &page,
                    origin,
                    br#"{"type":"evaluate","expression":"window.counter++"}"#,
                    callback,
                )
                .await
            } else {
                spawn_privileged_evaluate(
                    bound.driver.clone(),
                    tenant.clone(),
                    session.clone(),
                    page.clone(),
                    ownership_fence(),
                    br#"{"type":"evaluate","expression":"window.counter++"}"#,
                    callback,
                )
            };
            respond_evaluate_origin(&mut bound, origin).await;
            assert_eq!(
                action.await.unwrap(),
                Err(ApprovedActionError::DispatchRevoked)
            );
            assert!(has_no_command_bytes(&mut bound.reader, false).await);
        }
    }
}

#[tokio::test]
async fn automatic_and_manual_evaluate_reject_recreated_numeric_realm_during_callback() {
    for manual in [false, true] {
        let (mut bound, tenant, session, page) = privileged_owned_context().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let mut entered_tx = Some(entered_tx);
        let callback = move |_: &browserd_worker::LiveApprovalContext| {
            entered_tx.take().unwrap().send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            Ok(())
        };
        let action = if manual {
            spawn_manual_evaluate(
                &mut bound,
                &tenant,
                &session,
                &page,
                "https://owned.test",
                br#"{"type":"evaluate","expression":"window.counter++"}"#,
                callback,
            )
            .await
        } else {
            spawn_privileged_evaluate(
                bound.driver.clone(),
                tenant.clone(),
                session.clone(),
                page.clone(),
                ownership_fence(),
                br#"{"type":"evaluate","expression":"window.counter++"}"#,
                callback,
            )
        };
        respond_evaluate_origin(&mut bound, "https://owned.test").await;
        entered_rx.await.unwrap();
        write_message(&mut bound.writer, json!({"method":"Runtime.executionContextDestroyed","sessionId":"flat-options-primary",
            "params":{"executionContextId":1,"executionContextUniqueId":"realm-flat-options-primary"}})).await;
        write_message(&mut bound.writer, json!({"method":"Runtime.executionContextCreated","sessionId":"flat-options-primary",
            "params":{"context":{"id":1,"uniqueId":"replacement-realm","auxData":{"isDefault":true,"frameId":"frame-flat-options-primary"}}}})).await;
        tokio::time::sleep(Duration::from_millis(15)).await;
        release_tx.send(()).unwrap();
        assert_eq!(
            action.await.unwrap(),
            Ok(ActionExecutionResult::OutcomeUnknown)
        );
        assert!(
            has_no_command_bytes(&mut bound.reader, true).await,
            "same numeric context ID must not revive the admitted realm"
        );
    }
}

#[tokio::test]
async fn guarded_evaluate_realm_clear_after_dispatch_is_unknown() {
    let (mut bound, tenant, session, page) = privileged_owned_context().await;
    let action = spawn_privileged_evaluate(
        bound.driver.clone(),
        tenant,
        session,
        page,
        ownership_fence(),
        br#"{"type":"evaluate","expression":"window.counter++"}"#,
        |_| Ok(()),
    );
    respond_evaluate_origin(&mut bound, "https://owned.test").await;
    let effect = read_command(&mut bound.reader).await;
    assert_eq!(effect["method"], "Runtime.evaluate");
    assert_eq!(
        effect["params"]["uniqueContextId"],
        "realm-flat-options-primary"
    );
    write_message(&mut bound.writer, json!({"method":"Runtime.executionContextsCleared","sessionId":"flat-options-primary","params":{}})).await;
    assert_eq!(
        action.await.unwrap(),
        Ok(ActionExecutionResult::OutcomeUnknown)
    );
    // The owner delivers the action result before its terminal loop closes shard admission.
    // Observe that separate drain transition; the failed connection cannot serve a health barrier.
    tokio::time::timeout(Duration::from_secs(1), async {
        while !bound.manager.is_tainted() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the post-dispatch realm loss must close shard admission");
    assert!(bound.manager.is_tainted());
    assert!(has_no_command_bytes(&mut bound.reader, true).await);
}

#[tokio::test]
async fn privileged_evaluate_rejects_opaque_and_noncanonical_origins_before_admission() {
    let (mut bound, tenant, session, page) = privileged_owned_context().await;
    for origin in ["null", "https://owned.test:443", "data:text/html,test"] {
        let called = Arc::new(AtomicBool::new(false));
        let action = spawn_privileged_evaluate(
            bound.driver.clone(),
            tenant.clone(),
            session.clone(),
            page.clone(),
            ownership_fence(),
            br#"{"type":"evaluate","expression":"window.counter++"}"#,
            {
                let called = called.clone();
                move |_| {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
        );
        respond_evaluate_origin(&mut bound, origin).await;
        assert_eq!(
            action.await.unwrap(),
            Err(ApprovedActionError::DispatchRevoked)
        );
        assert!(!called.load(Ordering::SeqCst));
        assert!(has_no_command_bytes(&mut bound.reader, false).await);
    }
}

#[tokio::test]
async fn privileged_evaluate_throw_is_unknown_without_replay_and_owner_remains_observable() {
    let (mut bound, tenant, session, page) = privileged_owned_context().await;
    let admissions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let action = spawn_privileged_evaluate(
        bound.driver.clone(),
        tenant,
        session.clone(),
        page.clone(),
        ownership_fence(),
        br#"{"type":"evaluate","expression":"globalThis.counter++; throw new Error('private')"}"#,
        {
            let admissions = admissions.clone();
            move |_| {
                admissions.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        },
    );
    respond_evaluate_origin(&mut bound, "https://owned.test").await;
    let effect = read_command(&mut bound.reader).await;
    assert_eq!(effect["method"], "Runtime.evaluate");
    assert_eq!(
        effect["params"]["uniqueContextId"],
        "realm-flat-options-primary"
    );
    respond(
        &mut bound.writer,
        &effect,
        json!({"exceptionDetails":{"text":"private exception body"},"result":{"type":"object"}}),
    )
    .await;
    assert_eq!(
        action.await.unwrap(),
        Ok(ActionExecutionResult::OutcomeUnknown)
    );
    assert_eq!(admissions.load(Ordering::SeqCst), 1);
    let read = tokio::task::spawn_blocking({
        let driver = bound.driver.clone();
        move || {
            driver.execute_action(
                &session,
                Some(&page),
                br#"{"type":"evaluate","expression":"globalThis.counter"}"#,
            )
        }
    });
    let observation = read_command(&mut bound.reader).await;
    assert_eq!(
        observation["params"]["expression"], "globalThis.counter",
        "the mutation must not be replayed"
    );
    respond(
        &mut bound.writer,
        &observation,
        json!({"result":{"value":1}}),
    )
    .await;
    assert_eq!(
        read.await.unwrap(),
        ActionExecutionResult::Succeeded(br#"{"value":1}"#.to_vec())
    );
    assert!(!bound.manager.is_tainted());
}

#[tokio::test]
async fn privileged_evaluate_document_change_during_callback_never_dispatches_stale_expression() {
    let (mut bound, tenant, session, page) = privileged_owned_context().await;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let mut entered_tx = Some(entered_tx);
    let action = spawn_privileged_evaluate(
        bound.driver.clone(),
        tenant,
        session,
        page,
        ownership_fence(),
        br#"{"type":"evaluate","expression":"globalThis.counter++"}"#,
        move |_| {
            entered_tx.take().unwrap().send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            Ok(())
        },
    );
    respond_evaluate_origin(&mut bound, "https://owned.test").await;
    entered_rx.await.unwrap();
    write_message(&mut bound.writer, json!({"method":"Page.frameNavigated","sessionId":"flat-options-primary","params":{"frame":{
        "id":"frame-flat-options-primary", "loaderId":"replacement-loader", "url":"https://changed.test/", "securityOrigin":"https://changed.test",
    }}})).await;
    // The actor remains free to process browser events while the synchronous callback holds
    // the driver gate. Let that event reach its ownership ledger before releasing admission.
    tokio::time::sleep(Duration::from_millis(15)).await;
    release_tx.send(()).unwrap();
    assert_eq!(
        action.await.unwrap(),
        Ok(ActionExecutionResult::OutcomeUnknown)
    );
    assert!(has_no_command_bytes(&mut bound.reader, true).await);
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

#[derive(Default)]
struct CaptureStore {
    chunk_limit: Option<usize>,
    begins: std::sync::atomic::AtomicUsize,
    aborts: Arc<std::sync::atomic::AtomicUsize>,
    chunks: Arc<std::sync::Mutex<Vec<usize>>>,
}

struct CaptureSink {
    chunk_limit: usize,
    request: browserd_worker::GeneratedArtifactRequest,
    aborts: Arc<std::sync::atomic::AtomicUsize>,
    chunks: Arc<std::sync::Mutex<Vec<usize>>>,
    bytes: Vec<u8>,
}

#[async_trait::async_trait]
impl browserd_worker::GeneratedArtifactSink for CaptureSink {
    fn max_chunk_bytes(&self) -> usize {
        self.chunk_limit
    }
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DependencyError> {
        if chunk.len() > self.chunk_limit {
            return Err(DependencyError::Rejected);
        }
        self.chunks.lock().unwrap().push(chunk.len());
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }
    async fn finish(&mut self) -> Result<browserd_worker::ArtifactStoreReceipt, DependencyError> {
        use sha2::Digest as _;
        browserd_worker::ArtifactStoreReceipt::new_generated(
            self.request.key().clone(),
            self.bytes.len() as u64,
            browserd_artifacts::ArtifactChecksum::new(sha2::Sha256::digest(&self.bytes).into()),
            self.request.content_type(),
            browserd_artifacts::ArtifactObjectGeneration::new([7; 32]),
        )
        .map_err(|_| DependencyError::Rejected)
    }
    async fn abort(&mut self) -> Result<(), DependencyError> {
        self.aborts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl browserd_worker::SandboxClient for CaptureStore {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn cleanup(
        &self,
        _: &SessionId,
        _: browserd_sandbox::CleanupReason,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn heartbeat(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn store_artifact(
        &self,
        _: &browserd_worker::ArtifactStoreRequest,
    ) -> Result<browserd_worker::ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn begin_generated_artifact(
        &self,
        request: &browserd_worker::GeneratedArtifactRequest,
    ) -> Result<Box<dyn browserd_worker::GeneratedArtifactSink>, DependencyError> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CaptureSink {
            chunk_limit: self.chunk_limit.unwrap_or(64 * 1024),
            request: request.clone(),
            aborts: self.aborts.clone(),
            chunks: self.chunks.clone(),
            bytes: Vec::new(),
        }))
    }
}

fn spawn_capture(
    page: &OwnedPage,
    command: browserd_features::CaptureCommand,
    store: Arc<CaptureStore>,
    maximum: u64,
) -> tokio::task::JoinHandle<Result<browserd_worker::GeneratedCaptureResult, DependencyError>> {
    let driver = page.driver.clone();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let request = browserd_worker::GeneratedArtifactRequest::new(
        browserd_artifacts::ArtifactKey::new(
            page.tenant_id.clone(),
            session.clone(),
            browserd_core::ArtifactId::new(),
        ),
        ownership_fence(),
        command.content_type(),
        "test-capture",
        maximum,
    )
    .unwrap();
    tokio::task::spawn_blocking(move || {
        driver.execute_capture_until(
            &session,
            &page_id,
            command,
            request,
            store,
            Instant::now() + Duration::from_secs(5),
        )
    })
}

fn capture_metrics(width: u32, height: u32) -> Value {
    json!({"cssLayoutViewport":{"pageX":0,"pageY":0,"clientWidth":width,"clientHeight":height},
        "cssContentSize":{"x":0,"y":0,"width":width,"height":height}})
}

#[tokio::test]
async fn screenshot_geometry_preflight_rejects_before_capture_or_artifact_allocation() {
    let mut page = owned_page().await;
    let store = Arc::new(CaptureStore::default());
    let capture = spawn_capture(
        &page,
        browserd_features::CaptureCommand::Screenshot {
            options: Default::default(),
        },
        store.clone(),
        8 * 1024 * 1024,
    );
    let metrics = read_command(&mut page.reader).await;
    assert_eq!(metrics["method"], "Page.getLayoutMetrics");
    respond(
        &mut page.writer,
        &metrics,
        capture_metrics(100_000, 100_000),
    )
    .await;
    assert!(capture.await.unwrap().is_err());
    assert_eq!(store.begins.load(Ordering::SeqCst), 0);
    assert!(has_no_command_bytes(&mut page.reader, false).await);
}

#[tokio::test]
async fn pdf_uses_stream_transfer_bounded_reads_exact_receipt_and_closes_stream() {
    use base64::Engine as _;
    let mut page = owned_page().await;
    let store = Arc::new(CaptureStore::default());
    let capture = spawn_capture(
        &page,
        browserd_features::CaptureCommand::Pdf {
            options: Default::default(),
        },
        store.clone(),
        1024 * 1024,
    );
    let metrics = read_command(&mut page.reader).await;
    respond(&mut page.writer, &metrics, capture_metrics(800, 600)).await;
    let print = read_command(&mut page.reader).await;
    assert_eq!(print["method"], "Page.printToPDF");
    assert_eq!(print["params"]["transferMode"], "ReturnAsStream");
    assert_eq!(store.begins.load(Ordering::SeqCst), 1);
    respond(
        &mut page.writer,
        &print,
        json!({"data":"","stream":"pdf-stream"}),
    )
    .await;
    for (bytes, eof) in [
        (b"%PDF-1.7\n".as_slice(), false),
        (b"%%EOF".as_slice(), true),
    ] {
        let read = read_command(&mut page.reader).await;
        assert_eq!(read["method"], "IO.read");
        assert_eq!(read["params"]["size"], 64 * 1024);
        respond(&mut page.writer,&read,json!({"data":base64::engine::general_purpose::STANDARD.encode(bytes),"base64Encoded":true,"eof":eof})).await;
    }
    let close = read_command(&mut page.reader).await;
    assert_eq!(close["method"], "IO.close");
    respond(&mut page.writer, &close, json!({})).await;
    let result = capture.await.unwrap().unwrap();
    assert_eq!(result.receipt.as_ref().unwrap().size_bytes(), 14);
    assert_eq!(*store.chunks.lock().unwrap(), vec![9, 5]);
    assert_eq!(store.aborts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pdf_stream_byte_limit_aborts_partial_artifact_and_closes_handle() {
    use base64::Engine as _;
    let mut page = owned_page().await;
    let store = Arc::new(CaptureStore::default());
    let capture = spawn_capture(
        &page,
        browserd_features::CaptureCommand::Pdf {
            options: Default::default(),
        },
        store.clone(),
        64 * 1024,
    );
    let metrics = read_command(&mut page.reader).await;
    respond(&mut page.writer, &metrics, capture_metrics(800, 600)).await;
    let print = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &print,
        json!({"data":"","stream":"too-big"}),
    )
    .await;
    // Each response fits the transport cap, but the cumulative stream exceeds the reservation.
    for _ in 0..3 {
        let read = read_command(&mut page.reader).await;
        respond(&mut page.writer,&read,json!({"data":base64::engine::general_purpose::STANDARD.encode(vec![1;32*1024]),"base64Encoded":true,"eof":false})).await;
    }
    let close = read_command(&mut page.reader).await;
    assert_eq!(close["method"], "IO.close");
    respond(&mut page.writer, &close, json!({})).await;
    assert!(capture.await.unwrap().is_err());
    assert_eq!(*store.chunks.lock().unwrap(), vec![32 * 1024, 32 * 1024]);
    assert_eq!(store.aborts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn screenshot_inline_reserves_before_capture_and_releases_without_object() {
    use base64::Engine as _;
    let mut page = owned_page().await;
    let store = Arc::new(CaptureStore::default());
    let capture = spawn_capture(
        &page,
        browserd_features::CaptureCommand::Screenshot {
            options: browserd_features::ScreenshotOptions {
                delivery: browserd_features::CaptureDelivery::Inline,
                ..Default::default()
            },
        },
        store.clone(),
        1024 * 1024,
    );
    let metrics = read_command(&mut page.reader).await;
    respond(&mut page.writer, &metrics, capture_metrics(800, 600)).await;
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.captureScreenshot");
    assert_eq!(store.begins.load(Ordering::SeqCst), 1);
    let data = base64::engine::general_purpose::STANDARD.encode(b"png-fixture");
    respond(&mut page.writer, &command, json!({"data":data})).await;
    let result = capture.await.unwrap().unwrap();
    assert!(result.receipt.is_none());
    assert!(result.cleanup.is_none());
    assert_eq!(
        serde_json::from_slice::<Value>(&result.result).unwrap()["screenshot_inline"],
        data
    );
    assert_eq!(store.aborts.load(Ordering::SeqCst), 1);
    assert!(store.chunks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn screenshot_inline_overflow_reuses_reserved_sink_as_artifact() {
    use base64::Engine as _;
    let mut page = owned_page().await;
    let store = Arc::new(CaptureStore::default());
    let capture = spawn_capture(
        &page,
        browserd_features::CaptureCommand::Screenshot {
            options: browserd_features::ScreenshotOptions {
                delivery: browserd_features::CaptureDelivery::Inline,
                ..Default::default()
            },
        },
        store.clone(),
        1024 * 1024,
    );
    let metrics = read_command(&mut page.reader).await;
    respond(&mut page.writer, &metrics, capture_metrics(800, 600)).await;
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.captureScreenshot");
    assert_eq!(store.begins.load(Ordering::SeqCst), 1);
    let bytes = vec![7; browserd_features::MAX_INLINE_CAPTURE_BYTES + 1];
    respond(
        &mut page.writer,
        &command,
        json!({"data":base64::engine::general_purpose::STANDARD.encode(&bytes)}),
    )
    .await;
    let result = capture.await.unwrap().unwrap();
    assert_eq!(
        result.receipt.as_ref().unwrap().size_bytes(),
        bytes.len() as u64
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&result.result).unwrap()["capture"]["screenshot_inline_fallback"],
        true
    );
    assert_eq!(store.begins.load(Ordering::SeqCst), 1);
    assert_eq!(store.aborts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn scrape_dom_preflight_rejects_before_serialization_or_artifact_allocation() {
    let mut page = owned_page().await;
    let store = Arc::new(CaptureStore::default());
    let capture = spawn_capture(
        &page,
        browserd_features::CaptureCommand::Scrape {
            options: Default::default(),
        },
        store.clone(),
        1024 * 1024,
    );
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Runtime.evaluate");
    assert!(
        command["params"]["expression"]
            .as_str()
            .unwrap()
            .contains("return true; const out=")
    );
    assert_eq!(store.begins.load(Ordering::SeqCst), 0);
    respond(
        &mut page.writer,
        &command,
        json!({"exceptionDetails":{"text":"node_budget"},"result":{"type":"object"}}),
    )
    .await;
    assert!(capture.await.unwrap().is_err());
    assert_eq!(store.begins.load(Ordering::SeqCst), 0);
    assert!(has_no_command_bytes(&mut page.reader, false).await);
}

#[tokio::test]
async fn viewer_shares_stream_and_acknowledges_frame_before_any_observer_poll() {
    let mut page = owned_page().await;
    let driver = page.driver.clone();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let start = tokio::task::spawn_blocking(move || {
        driver.viewer_start(&session, &page_id, &ownership_fence())
    });
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.startScreencast");
    respond(&mut page.writer, &command, json!({})).await;
    start.await.unwrap().unwrap();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let driver = page.driver.clone();
    tokio::task::spawn_blocking(move || {
        driver.viewer_start(&session, &page_id, &ownership_fence())
    })
    .await
    .unwrap()
    .unwrap();
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    write_message(&mut page.writer, json!({"method":"Page.screencastFrame","sessionId":command["sessionId"],"params":{"sessionId":1,"data":"/9j/2Q==","metadata":{"offsetTop":0,"pageScaleFactor":1,"deviceWidth":800,"deviceHeight":600,"scrollOffsetX":0,"scrollOffsetY":0}}})).await;
    let ack = read_command(&mut page.reader).await;
    assert_eq!(ack["method"], "Page.screencastFrameAck");
    assert_eq!(ack["params"]["sessionId"], 1);
    respond(&mut page.writer, &ack, json!({})).await;
    let driver = page.driver.clone();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let (first, second) = tokio::task::spawn_blocking(move || {
        (
            driver
                .viewer_frame(&session, &page_id, &ownership_fence())
                .unwrap()
                .unwrap(),
            driver
                .viewer_frame(&session, &page_id, &ownership_fence())
                .unwrap()
                .unwrap(),
        )
    })
    .await
    .unwrap();
    assert_eq!(
        first, second,
        "each observer independently reads the shared latest frame"
    );
    assert!(first.frame_transform_id > 0);
    assert_eq!(
        serde_json::from_slice::<Value>(&first.metadata).unwrap()["width"].as_u64(),
        Some(800)
    );
    let driver = page.driver.clone();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let old_transform = first.frame_transform_id;
    let epoch = tokio::task::spawn_blocking(move || {
        let epoch = driver.viewer_rebind(&session, &page_id, &ownership_fence()).unwrap();
        assert!(driver.viewer_frame(&session, &page_id, &ownership_fence()).unwrap().is_none());
        let message = serde_json::from_value(json!({"type":"insert_text","lease_epoch":1,"input_sequence":1,"page_id":page_id,"frame_transform_id":old_transform,"text":"must not dispatch"})).unwrap();
        assert_eq!(driver.viewer_input(&session,&page_id,&ownership_fence(),old_transform,&message),Err(DependencyError::Rejected));
        epoch
    }).await.unwrap();
    assert!(epoch > old_transform);
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    write_message(&mut page.writer, json!({"method":"Page.screencastFrame","sessionId":command["sessionId"],"params":{"sessionId":2,"data":"/9j/2Q==","metadata":{"offsetTop":0,"pageScaleFactor":1,"deviceWidth":800,"deviceHeight":600,"scrollOffsetX":0,"scrollOffsetY":0}}})).await;
    let ack = read_command(&mut page.reader).await;
    assert_eq!(ack["method"], "Page.screencastFrameAck");
    respond(&mut page.writer, &ack, json!({})).await;
    let driver = page.driver.clone();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let new_frame = tokio::task::spawn_blocking(move || {
        driver
            .viewer_frame(&session, &page_id, &ownership_fence())
            .unwrap()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(new_frame.frame_transform_id, epoch);
    assert!(new_frame.frame_id > first.frame_id);
    let driver = page.driver.clone();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let message=serde_json::from_value(json!({"type":"key","lease_epoch":1,"input_sequence":2,"page_id":page_id,"frame_transform_id":epoch,"phase":"down","key":"Enter","code":"Enter"})).unwrap();
    let input = tokio::task::spawn_blocking(move || {
        driver.viewer_input(&session, &page_id, &ownership_fence(), epoch, &message)
    });
    let key = read_command(&mut page.reader).await;
    assert_eq!(key["method"], "Input.dispatchKeyEvent");
    assert_eq!(key["params"]["type"], "keyDown");
    assert_eq!(key["params"]["text"], "\r");
    respond(&mut page.writer, &key, json!({})).await;
    input.await.unwrap().unwrap();
}

#[tokio::test]
async fn rejected_viewer_image_still_invalidates_changed_geometry() {
    let mut page = owned_page().await;
    let driver = page.driver.clone();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let start = tokio::task::spawn_blocking(move || {
        driver.viewer_start(&session, &page_id, &ownership_fence())
    });
    let command = read_command(&mut page.reader).await;
    respond(&mut page.writer, &command, json!({})).await;
    start.await.unwrap().unwrap();
    for (sequence, data, width) in [(1, "/9j/2Q==", 800), (2, "invalid-base64", 400)] {
        write_message(&mut page.writer,json!({"method":"Page.screencastFrame","sessionId":command["sessionId"],"params":{"sessionId":sequence,"data":data,"metadata":{"offsetTop":0,"pageScaleFactor":1,"deviceWidth":width,"deviceHeight":600,"scrollOffsetX":0,"scrollOffsetY":0}}})).await;
        let ack = read_command(&mut page.reader).await;
        assert_eq!(ack["method"], "Page.screencastFrameAck");
        respond(&mut page.writer, &ack, json!({})).await;
    }
    let driver = page.driver.clone();
    let session = page.session_id.clone();
    let page_id = page.page_id.clone();
    let frame = tokio::task::spawn_blocking(move || {
        driver.viewer_frame(&session, &page_id, &ownership_fence())
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        frame.is_none(),
        "bad image data must not preserve an obsolete input transform"
    );
}

#[tokio::test]
async fn screenshot_honors_generated_sink_chunk_limit() {
    use base64::Engine as _;
    let mut page = owned_page().await;
    let store = Arc::new(CaptureStore {
        chunk_limit: Some(5),
        ..Default::default()
    });
    let capture = spawn_capture(
        &page,
        browserd_features::CaptureCommand::Screenshot {
            options: Default::default(),
        },
        store.clone(),
        1024,
    );
    let metrics = read_command(&mut page.reader).await;
    respond(&mut page.writer, &metrics, capture_metrics(800, 600)).await;
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.captureScreenshot");
    respond(
        &mut page.writer,
        &command,
        json!({"data":base64::engine::general_purpose::STANDARD.encode(b"thirteenbytes")}),
    )
    .await;
    assert!(capture.await.unwrap().is_ok());
    assert_eq!(*store.chunks.lock().unwrap(), vec![5, 5, 3]);
}

#[tokio::test]
async fn pdf_honors_generated_sink_chunk_limit() {
    use base64::Engine as _;
    let mut page = owned_page().await;
    let store = Arc::new(CaptureStore {
        chunk_limit: Some(5),
        ..Default::default()
    });
    let capture = spawn_capture(
        &page,
        browserd_features::CaptureCommand::Pdf {
            options: Default::default(),
        },
        store.clone(),
        1024,
    );
    let metrics = read_command(&mut page.reader).await;
    respond(&mut page.writer, &metrics, capture_metrics(800, 600)).await;
    let print = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &print,
        json!({"data":"","stream":"small-chunks"}),
    )
    .await;
    let mut sizes = Vec::new();
    for (chunk, eof) in [(b"%PDF-".as_slice(), false), (b"end".as_slice(), true)] {
        let read = read_command(&mut page.reader).await;
        sizes.push(read["params"]["size"].as_u64().unwrap());
        respond(&mut page.writer,&read,json!({"data":base64::engine::general_purpose::STANDARD.encode(chunk),"base64Encoded":true,"eof":eof})).await;
    }
    let close = read_command(&mut page.reader).await;
    respond(&mut page.writer, &close, json!({})).await;
    assert!(capture.await.unwrap().is_ok());
    assert_eq!(
        sizes,
        vec![5, 5],
        "IO.read must honor adapter chunks before requesting bytes"
    );
    assert_eq!(*store.chunks.lock().unwrap(), vec![5, 3]);
}

// Strict production routing is separate from the legacy functional CDP fixtures above.
// These tests use only private pipes and a pinned current-netns identity; no proxy,
// namespace mutation, browser process, or production egress route is created.
mod routed_launch_contract {
    use super::*;
    use browserd_sandbox::{
        DedicatedEgressProxyBinding, PinnedNetworkNamespace, ShardEgressReservation,
        ShardIngressLease, ShardIngressReceipt,
    };

    const PROXY_ADDRESS: &str = "127.0.0.1:20123";

    #[tokio::test]
    async fn routed_download_opt_in_rejects_missing_scratch_before_any_cdp_command() {
        let shard = shard_fence();
        let launch = bound_profile_launch(shard.clone(), ChromiumProcessProfile::BaselineV1);
        let (owner, _manager) = ChromiumConnectionOwner::new_bounded_for_routed_launch(
            identity(),
            connection_config(),
            shard,
            16,
            Arc::new(Drain(AtomicBool::new(false))),
            launch.clone(),
        )
        .unwrap();
        owner.enable_downloads().unwrap();
        let (binding, _namespace) = route_binding(&launch);
        let (pipes, mut reader, _writer) = pipe_pair();
        assert_eq!(
            owner
                .accept_cdp_pipes(pipes.with_egress_proxy_binding(binding).unwrap())
                .await,
            Err(ShardRuntimeError::Rejected)
        );
        assert!(has_no_command_bytes(&mut reader, true).await);
    }

    #[tokio::test]
    async fn download_opt_in_is_immutable_after_pipe_acceptance_and_requires_routed_launch() {
        let fixture = routed_owner().await;
        assert_eq!(
            fixture.owner.enable_downloads(),
            Err(ShardRuntimeError::Rejected)
        );
        let (owner, _manager) = ChromiumConnectionOwner::new_bounded(
            identity(),
            connection_config(),
            shard_fence(),
            16,
            Arc::new(Drain(AtomicBool::new(false))),
        )
        .unwrap();
        assert_eq!(owner.enable_downloads(), Err(ShardRuntimeError::Rejected));
    }

    struct RoutedOwner {
        owner: Arc<ChromiumConnectionOwner<Drain>>,
        manager: Arc<browserd_worker::ChromiumTargetManager<Drain>>,
        driver: browserd_worker::CdpChromiumDriver,
        launch: LaunchSpec,
        reader: Receiver,
        writer: Sender,
        drain: Arc<Drain>,
        _namespace: PinnedNetworkNamespace,
    }

    fn route_binding(launch: &LaunchSpec) -> (DedicatedEgressProxyBinding, PinnedNetworkNamespace) {
        let namespace = PinnedNetworkNamespace::from_owned_fd(
            std::fs::File::open("/proc/thread-self/ns/net")
                .expect("current namespace descriptor")
                .into(),
        )
        .expect("pinned network namespace");
        let lease = ShardIngressLease::from_attachment(
            ShardEgressReservation::from_launch_spec(launch),
            namespace.identity(),
            ShardIngressReceipt::with_proxy_address(PROXY_ADDRESS.parse().unwrap())
                .expect("nonzero loopback proxy address"),
        );
        (
            DedicatedEgressProxyBinding::from_lease(&lease).expect("full route binding"),
            namespace,
        )
    }

    fn context_fence(launch: &LaunchSpec) -> OwnershipFence {
        OwnershipFence::new(
            launch.worker_id().clone(),
            launch.worker_epoch(),
            23,
            launch
                .dedicated_egress()
                .egress_fence()
                .session_incarnation()
                .get(),
        )
    }

    async fn routed_owner() -> RoutedOwner {
        let shard = shard_fence();
        let launch = bound_profile_launch(shard.clone(), ChromiumProcessProfile::BaselineV1);
        let drain = Arc::new(Drain(AtomicBool::new(false)));
        let (owner, manager) = ChromiumConnectionOwner::new_bounded_for_routed_launch(
            identity(),
            connection_config(),
            shard,
            16,
            drain.clone(),
            launch.clone(),
        )
        .expect("strict routed owner");
        let (binding, namespace) = route_binding(&launch);
        let (pipes, mut reader, mut writer) = pipe_pair();
        let pipes = pipes
            .with_egress_proxy_binding(binding)
            .expect("bind exact pipe attachment");
        let accept = tokio::spawn({
            let owner = owner.clone();
            async move { owner.accept_cdp_pipes(pipes).await }
        });
        qualify(&mut reader, &mut writer).await;
        assert_eq!(accept.await.unwrap(), Ok(()));
        bootstrap_empty(manager.clone(), &mut reader, &mut writer).await;
        let driver = owner.chromium_driver(IsolationProfile::DedicatedProcess);
        RoutedOwner {
            owner,
            manager,
            driver,
            launch,
            reader,
            writer,
            drain,
            _namespace: namespace,
        }
    }

    async fn next_command(fixture: &mut RoutedOwner) -> Value {
        tokio::time::timeout(Duration::from_secs(1), read_command(&mut fixture.reader))
            .await
            .expect("bounded routed CDP command")
    }

    async fn begin_context(
        fixture: &mut RoutedOwner,
    ) -> (
        tokio::task::JoinHandle<Result<PageId, DependencyError>>,
        Value,
    ) {
        let create = tokio::task::spawn_blocking({
            let driver = fixture.driver.clone();
            let tenant = fixture.launch.tenant_id().clone();
            let session = fixture
                .launch
                .dedicated_egress()
                .egress_fence()
                .session_id()
                .clone();
            let fence = context_fence(&fixture.launch);
            move || driver.create_context_owned(&tenant, &session, &fence)
        });
        let command = next_command(fixture).await;
        assert_eq!(command["method"], "Target.createBrowserContext");
        assert_eq!(
            command["params"],
            json!({
                "disposeOnDetach": true,
                "proxyServer": format!("http://{PROXY_ADDRESS}"),
                "proxyBypassList": "<-loopback>",
            })
        );
        assert!(command.get("sessionId").is_none());
        respond(
            &mut fixture.writer,
            &command,
            json!({"browserContextId":"routed-context"}),
        )
        .await;
        let deny = next_command(fixture).await;
        assert_eq!(deny["method"], "Browser.setDownloadBehavior");
        assert_eq!(
            deny["params"],
            json!({
                "behavior":"deny",
                "browserContextId":"routed-context",
                "eventsEnabled":true,
            })
        );
        assert!(deny.get("sessionId").is_none());
        assert!(
            !create.is_finished(),
            "context cannot publish before download denial is acknowledged"
        );
        (create, deny)
    }

    async fn create_context(fixture: &mut RoutedOwner) -> PageId {
        let (create, deny) = begin_context(fixture).await;
        respond(&mut fixture.writer, &deny, json!({})).await;
        let target = next_command(fixture).await;
        assert_eq!(target["method"], "Target.createTarget");
        assert_eq!(target["params"]["browserContextId"], "routed-context");
        write_message(
            &mut fixture.writer,
            json!({
                "method":"Target.attachedToTarget",
                "params":{
                    "sessionId":"routed-flat-primary",
                    "waitingForDebugger":true,
                    "targetInfo":{
                        "targetId":"routed-primary",
                        "browserContextId":"routed-context",
                        "type":"page",
                    }
                }
            }),
        )
        .await;
        respond(
            &mut fixture.writer,
            &target,
            json!({"targetId":"routed-primary"}),
        )
        .await;
        for method in [
            "Target.setAutoAttach",
            "Network.enable",
            "Runtime.enable",
            "Page.enable",
            "Page.getFrameTree",
            "Page.setInterceptFileChooserDialog",
            "Runtime.runIfWaitingForDebugger",
        ] {
            let command = next_command(fixture).await;
            assert_eq!(command["method"], method);
            assert_eq!(command["sessionId"], "routed-flat-primary");
            respond(&mut fixture.writer, &command, json!({})).await;
        }
        create.await.unwrap().expect("routed primary page")
    }

    async fn assert_drained(fixture: &RoutedOwner) {
        tokio::time::timeout(Duration::from_millis(250), async {
            while !fixture.drain.0.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("download ownership failure must close admission immediately");
        assert!(fixture.manager.is_tainted());
        assert!(!fixture.manager.is_ready());
    }

    #[tokio::test]
    async fn routed_launch_requires_proxy_binding_before_any_cdp() {
        let shard = shard_fence();
        let launch = bound_profile_launch(shard.clone(), ChromiumProcessProfile::BaselineV1);
        let (owner, _manager) = ChromiumConnectionOwner::new_bounded_for_routed_launch(
            identity(),
            connection_config(),
            shard,
            16,
            Arc::new(Drain(AtomicBool::new(false))),
            launch,
        )
        .unwrap();
        let (pipes, mut reader, _writer) = pipe_pair();
        let result =
            tokio::time::timeout(Duration::from_millis(250), owner.accept_cdp_pipes(pipes))
                .await
                .expect("missing binding must reject before waiting on Browser.getVersion");
        assert!(result.is_err());
        assert!(has_no_command_bytes(&mut reader, true).await);
    }

    #[tokio::test]
    async fn routed_launch_rejects_same_proxy_address_with_different_full_binding() {
        let shard = shard_fence();
        let launch = bound_profile_launch(shard.clone(), ChromiumProcessProfile::BaselineV1);
        let expected_egress = launch.dedicated_egress().egress_fence();
        for mismatch in [
            "tenant",
            "worker",
            "worker_epoch",
            "shard",
            "launch_generation",
            "route_generation",
            "session",
            "session_incarnation",
            "policy",
        ] {
            let owner_fence = OwnerFence::new(
                if mismatch == "worker" {
                    WorkerId::new("different-worker").unwrap()
                } else {
                    shard.owner().worker_id().clone()
                },
                if mismatch == "worker_epoch" {
                    WorkerEpoch::new(18).unwrap()
                } else {
                    shard.owner().worker_epoch()
                },
            );
            let other_shard = ShardFence::new(
                owner_fence,
                if mismatch == "shard" {
                    ShardId::new()
                } else {
                    shard.shard_id().clone()
                },
                if mismatch == "launch_generation" {
                    LaunchGeneration::new(4).unwrap()
                } else {
                    shard.launch_generation()
                },
            );
            let other_egress = DedicatedEgressSpec::new(
                EgressFence::new(
                    other_shard,
                    if mismatch == "route_generation" {
                        RouteGeneration::new(2).unwrap()
                    } else {
                        expected_egress.route_generation()
                    },
                    if mismatch == "session" {
                        SessionId::new()
                    } else {
                        expected_egress.session_id().clone()
                    },
                    if mismatch == "session_incarnation" {
                        SessionIncarnation::new(2).unwrap()
                    } else {
                        expected_egress.session_incarnation()
                    },
                ),
                if mismatch == "policy" {
                    EgressPolicyBinding::new("strict", [8; 32]).unwrap()
                } else {
                    launch.dedicated_egress().policy_binding().clone()
                },
                launch.dedicated_egress().initial_lease_ttl(),
            )
            .unwrap();
            let other_launch = LaunchSpec::production(
                if mismatch == "tenant" {
                    TenantId::new()
                } else {
                    launch.tenant_id().clone()
                },
                other_egress,
                launch.chromium_binary_digest(),
            );
            let (binding, _namespace) = route_binding(&other_launch);
            let (owner, _manager) = ChromiumConnectionOwner::new_bounded_for_routed_launch(
                identity(),
                connection_config(),
                shard.clone(),
                16,
                Arc::new(Drain(AtomicBool::new(false))),
                launch.clone(),
            )
            .unwrap();
            let (pipes, mut reader, _writer) = pipe_pair();
            let pipes = pipes.with_egress_proxy_binding(binding).unwrap();
            let result =
                tokio::time::timeout(Duration::from_millis(250), owner.accept_cdp_pipes(pipes))
                    .await
                    .expect("mismatched binding must reject without probing Chromium");
            assert!(
                result.is_err(),
                "same proxy address cannot authorize a different {mismatch}"
            );
            assert!(
                has_no_command_bytes(&mut reader, true).await,
                "{mismatch} mismatch must not issue Browser.getVersion"
            );
        }
    }

    #[tokio::test]
    async fn routed_context_rejects_tenant_session_or_incarnation_mismatch_before_cdp() {
        let mut fixture = routed_owner().await;
        for mismatch in ["tenant", "session", "incarnation"] {
            let tenant = if mismatch == "tenant" {
                TenantId::new()
            } else {
                fixture.launch.tenant_id().clone()
            };
            let expected = fixture.launch.dedicated_egress().egress_fence();
            let session = if mismatch == "session" {
                SessionId::new()
            } else {
                expected.session_id().clone()
            };
            let fence = if mismatch == "incarnation" {
                OwnershipFence::new(
                    fixture.launch.worker_id().clone(),
                    fixture.launch.worker_epoch(),
                    23,
                    expected.session_incarnation().get() + 1,
                )
            } else {
                context_fence(&fixture.launch)
            };
            let create = tokio::task::spawn_blocking({
                let driver = fixture.driver.clone();
                move || driver.create_context_owned(&tenant, &session, &fence)
            });
            assert_eq!(create.await.unwrap(), Err(DependencyError::Rejected));
            assert!(
                has_no_command_bytes(&mut fixture.reader, false).await,
                "{mismatch} mismatch must reject before createBrowserContext"
            );
        }
    }

    #[tokio::test]
    async fn routed_context_sets_exact_proxy_and_download_deny_before_target_creation() {
        let mut fixture = routed_owner().await;
        let _page = create_context(&mut fixture).await;
        assert!(fixture.manager.has_ready_target("routed-primary"));
        assert!(!fixture.drain.0.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn routed_download_deny_failure_never_publishes_a_page_and_drains() {
        let mut fixture = routed_owner().await;
        let (create, deny) = begin_context(&mut fixture).await;
        write_message(
            &mut fixture.writer,
            json!({
                "id":deny["id"],
                "error":{"code":-32000,"message":"download deny unavailable"},
            }),
        )
        .await;
        assert!(create.await.unwrap().is_err());
        assert_drained(&fixture).await;
        assert!(!fixture.manager.has_ready_target("routed-primary"));
        assert!(
            has_no_command_bytes(&mut fixture.reader, true).await,
            "deny failure must never create or resume a page"
        );
        assert!(
            fixture
                .owner
                .shutdown_and_join(Duration::from_millis(250))
                .await
                .is_err(),
            "stopping the owner cannot prove exact cleanup of the already-created context"
        );
    }

    #[tokio::test]
    async fn routed_download_begin_in_deny_only_context_closes_admission() {
        let mut fixture = routed_owner().await;
        let _page = create_context(&mut fixture).await;
        write_message(
            &mut fixture.writer,
            json!({
                "method":"Browser.downloadWillBegin",
                "params":{
                    "frameId":"unmapped-frame",
                    "guid":"unmapped-download",
                    "url":"https://example.test/file",
                    "suggestedFilename":"untrusted.bin",
                }
            }),
        )
        .await;
        assert_drained(&fixture).await;
        let health = tokio::task::spawn_blocking({
            let driver = fixture.driver.clone();
            move || driver.qualify()
        });
        assert!(health.await.unwrap().is_err());
        assert!(has_no_command_bytes(&mut fixture.reader, true).await);
    }

    #[tokio::test]
    async fn routed_unknown_download_progress_interrupts_an_active_command_and_drains() {
        let mut fixture = routed_owner().await;
        let _page = create_context(&mut fixture).await;
        let health = tokio::task::spawn_blocking({
            let driver = fixture.driver.clone();
            move || driver.qualify()
        });
        let probe = next_command(&mut fixture).await;
        assert_eq!(probe["method"], "Browser.getVersion");
        // No preceding WillBegin or event session id: never guess a context from
        // this browser-wide GUID, even though this fixture owns only one session.
        write_message(
            &mut fixture.writer,
            json!({
                "method":"Browser.downloadProgress",
                "params":{
                    "guid":"unknown-or-late-download",
                    "totalBytes":7,
                    "receivedBytes":7,
                    "state":"completed",
                    "filePath":"/untrusted-event-path/must-not-be-imported",
                }
            }),
        )
        .await;
        let result = tokio::time::timeout(Duration::from_millis(250), health)
            .await
            .expect("download event must interrupt the probe before its 500ms timeout")
            .unwrap();
        assert!(result.is_err());
        assert_drained(&fixture).await;
        assert!(has_no_command_bytes(&mut fixture.reader, true).await);
    }
}

mod checkpoint_contract {
    use super::*;
    use browserd_worker::{CheckpointError, CheckpointSnapshot};

    struct Fixture {
        _owner: Arc<ChromiumConnectionOwner<Drain>>,
        driver: browserd_worker::CdpChromiumDriver,
        tenant: TenantId,
        session: SessionId,
        page: PageId,
        reader: Receiver,
        writer: Sender,
    }

    async fn fixture() -> Fixture {
        let drain = Arc::new(Drain(AtomicBool::new(false)));
        let (owner, manager) = ChromiumConnectionOwner::new_bounded(
            identity(),
            connection_config(),
            shard_fence(),
            16,
            drain,
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
        bootstrap_empty(manager, &mut reader, &mut writer).await;
        let tenant = TenantId::new();
        let session = SessionId::new();
        let page = create_owned_context(
            driver.clone(),
            tenant.clone(),
            session.clone(),
            ownership_fence(),
            &mut reader,
            &mut writer,
        )
        .await;
        Fixture {
            _owner: owner,
            driver,
            tenant,
            session,
            page,
            reader,
            writer,
        }
    }

    fn empty_snapshot() -> CheckpointSnapshot {
        CheckpointSnapshot {
            artifact_identity: identity(),
            cookies: Vec::new(),
            origins: Vec::new(),
        }
    }

    #[tokio::test]
    async fn checkpoint_capture_is_context_fenced_and_exports_full_verified_identity() {
        let mut fixture = fixture().await;
        let driver = fixture.driver.clone();
        let session = fixture.session.clone();
        let rejected = tokio::task::spawn_blocking(move || {
            driver.capture_checkpoint_until(
                &TenantId::new(),
                &session,
                &ownership_fence(),
                &[],
                Instant::now() + Duration::from_secs(2),
            )
        })
        .await
        .unwrap();
        assert!(matches!(rejected, Err(CheckpointError::Rejected)));
        assert!(has_no_command_bytes(&mut fixture.reader, false).await);
        let driver = fixture.driver.clone();
        let tenant = fixture.tenant.clone();
        let session = fixture.session.clone();
        let capture = tokio::task::spawn_blocking(move || {
            driver.capture_checkpoint_until(
                &tenant,
                &session,
                &ownership_fence(),
                &[],
                Instant::now() + Duration::from_secs(2),
            )
        });
        let command = read_command(&mut fixture.reader).await;
        assert_eq!(command["method"], "Storage.getCookies");
        assert_eq!(
            command["params"],
            json!({"browserContextId":"owned-context"})
        );
        assert!(command.get("sessionId").is_none());
        respond(&mut fixture.writer, &command, json!({"cookies":[]})).await;
        let snapshot = capture.await.unwrap().unwrap();
        assert_eq!(snapshot.artifact_identity, identity());
        assert!(snapshot.cookies.is_empty() && snapshot.origins.is_empty());
    }

    #[tokio::test]
    async fn checkpoint_restore_identity_rejects_before_cdp_and_cookie_effect_errors_are_unknown() {
        let mut fixture = fixture().await;
        let mut changed = empty_snapshot();
        changed
            .artifact_identity
            .chromium_revision
            .push_str("-different");
        let driver = fixture.driver.clone();
        let tenant = fixture.tenant.clone();
        let session = fixture.session.clone();
        let page = fixture.page.clone();
        let rejected = tokio::task::spawn_blocking(move || {
            driver.restore_checkpoint_until(
                &tenant,
                &session,
                &page,
                &ownership_fence(),
                changed,
                Instant::now() + Duration::from_secs(2),
            )
        })
        .await
        .unwrap();
        assert_eq!(rejected, Err(CheckpointError::Rejected));
        assert!(has_no_command_bytes(&mut fixture.reader, false).await);
        let driver = fixture.driver.clone();
        let tenant = fixture.tenant.clone();
        let session = fixture.session.clone();
        let page = fixture.page.clone();
        let restore = tokio::task::spawn_blocking(move || {
            driver.restore_checkpoint_until(
                &tenant,
                &session,
                &page,
                &ownership_fence(),
                empty_snapshot(),
                Instant::now() + Duration::from_secs(2),
            )
        });
        let tree = read_command(&mut fixture.reader).await;
        assert_eq!(tree["method"], "Page.getFrameTree");
        respond(
            &mut fixture.writer,
            &tree,
            json!({"frameTree":{"frame":{"id":"main","url":"about:blank"}}}),
        )
        .await;
        let cookies = read_command(&mut fixture.reader).await;
        assert_eq!(cookies["method"], "Storage.getCookies");
        respond(&mut fixture.writer, &cookies, json!({"cookies":[]})).await;
        let write = read_command(&mut fixture.reader).await;
        assert_eq!(write["method"], "Storage.setCookies");
        assert_eq!(
            write["params"],
            json!({"browserContextId":"owned-context","cookies":[]})
        );
        write_message(&mut fixture.writer,json!({"id":write["id"],"error":{"code":-32000,"message":"untrusted checkpoint error body"}})).await;
        assert_eq!(
            restore.await.unwrap(),
            Err(CheckpointError::OutcomeUncertain)
        );
    }
}

#[path = "support/typed_approvals.rs"]
mod typed_approvals;

/// Inspects the approval context of a node-free click proposal bound to `page`'s owned session.
fn spawn_approval_inspection(
    page: &OwnedPage,
) -> tokio::task::JoinHandle<Result<browserd_worker::LiveApprovalContext, DependencyError>> {
    let driver = page.driver.clone();
    let session_id = page.session_id.clone();
    let page_id = page.page_id.clone();
    let proposal = browserd_policy::CanonicalActionProposal::new(
        page.tenant_id.clone(),
        browserd_core::PrincipalId::new(),
        page.session_id.clone(),
        ownership_fence().session_incarnation(),
        page.page_id.clone(),
        1,
        1,
        browserd_policy::Origin::parse("https://example.test").unwrap(),
        1,
        browserd_policy::ActionType::Click,
        browserd_policy::ActionArgumentsHash::digest(br#"{"type":"click"}"#),
        None,
        browserd_policy::CredentialRefsHash::digest(std::iter::empty::<&str>()),
        u64::MAX,
    );
    tokio::task::spawn_blocking(move || {
        driver.inspect_approval_context(&session_id, &page_id, &proposal)
    })
}

fn approval_frame_tree(security_origin: &str) -> Value {
    json!({
        "frameTree": {
            "frame": {
                "id": "frame-flat-primary",
                "loaderId": "loader-a",
                "url": "https://example.test/",
                "domainAndRegistry": "example.test",
                "securityOrigin": security_origin,
                "mimeType": "text/html",
                "secureContextType": "Secure",
                "crossOriginIsolatedContextType": "NotIsolated",
                "gatedAPIFeatures": []
            },
            "childFrames": []
        }
    })
}

/// Answers one origin read: page script reports `script_origin`, the browser's frame tree `tree`.
async fn answer_origin_read(
    page: &mut OwnedPage,
    command: &Value,
    script_origin: &str,
    tree: Value,
) {
    let answer = if command["method"] == "Runtime.evaluate" {
        json!({"result": {"type": "string", "value": script_origin}})
    } else {
        tree
    };
    respond(&mut page.writer, command, answer).await;
}

#[tokio::test]
async fn approval_origin_is_the_main_frame_security_origin_not_page_script() {
    let mut page = owned_page().await;
    let inspection = spawn_approval_inspection(&page);
    let command = read_command(&mut page.reader).await;
    // Page script owns `globalThis`, so a script-read origin is whatever the page planted
    // (`globalThis = {location: {origin: "https://bank.example"}}`); the fake answers such a read
    // with the spoof and only the frame tree with the browser's own security origin.
    answer_origin_read(
        &mut page,
        &command,
        "https://bank.example",
        approval_frame_tree("https://example.test"),
    )
    .await;

    let live = inspection
        .await
        .unwrap()
        .expect("the live approval context should be observed");
    assert_eq!(
        live.current_origin,
        browserd_policy::Origin::parse("https://example.test").unwrap()
    );
    assert_eq!(command["method"], "Page.getFrameTree");
    assert_eq!(command["sessionId"], "flat-primary");
    assert_eq!(
        (
            live.target_incarnation,
            live.frame_document_epoch,
            live.url_revision
        ),
        (1, 1, 1)
    );
    assert!(
        has_no_command_bytes(&mut page.reader, false).await,
        "observing the origin must not evaluate page script"
    );
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn approval_origin_refuses_opaque_non_canonical_and_non_main_frame_origins() {
    let mut page = owned_page().await;
    let mut cases: Vec<_> = [
        "null",
        "://",
        "file://",
        "https://EXAMPLE.test",
        "https://example.test/",
        "https://example.test:443",
    ]
    .into_iter()
    .map(|origin| (origin, approval_frame_tree(origin)))
    .collect();
    // A root that names a parent, or is not the guarded main frame, is not the page's document.
    let mut child_root = approval_frame_tree("https://example.test");
    child_root["frameTree"]["frame"]["parentId"] = json!("outer-frame");
    cases.push(("https://example.test", child_root));
    let mut other_root = approval_frame_tree("https://example.test");
    other_root["frameTree"]["frame"]["id"] = json!("frame-other");
    cases.push(("https://example.test", other_root));
    let mut methods = Vec::new();
    for (origin, tree) in cases {
        let inspection = spawn_approval_inspection(&page);
        let command = read_command(&mut page.reader).await;
        answer_origin_read(&mut page, &command, origin, tree.clone()).await;
        assert_eq!(
            inspection.await.unwrap(),
            Err(DependencyError::Rejected),
            "{tree} must not bind an approval"
        );
        methods.push(command["method"].clone());
    }
    assert!(methods.iter().all(|method| method == "Page.getFrameTree"));
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn approval_origin_read_across_a_navigation_is_refused() {
    let mut page = owned_page().await;
    let inspection = spawn_approval_inspection(&page);
    let command = read_command(&mut page.reader).await;
    // The main frame commits a new document while the origin read is outstanding, so the
    // answered origin may belong to either document.
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame-flat-primary",
            "loader-b",
            "https://bank.example/",
        ),
    )
    .await;
    answer_origin_read(
        &mut page,
        &command,
        "https://bank.example",
        approval_frame_tree("https://bank.example"),
    )
    .await;
    assert_eq!(inspection.await.unwrap(), Err(DependencyError::Rejected));
    assert_eq!(command["method"], "Page.getFrameTree");
    // Read-only observation stays a known refusal; it must not fail the shard closed.
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());

    // Once settled, the origin is reported together with the new document's epochs.
    let inspection = spawn_approval_inspection(&page);
    let command = read_command(&mut page.reader).await;
    answer_origin_read(
        &mut page,
        &command,
        "https://bank.example",
        approval_frame_tree("https://bank.example"),
    )
    .await;
    let live = inspection
        .await
        .unwrap()
        .expect("the settled document should be observed");
    assert_eq!(
        live.current_origin,
        browserd_policy::Origin::parse("https://bank.example").unwrap()
    );
    assert_eq!((live.frame_document_epoch, live.url_revision), (2, 2));
}
