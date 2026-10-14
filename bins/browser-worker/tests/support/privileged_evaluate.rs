#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use browserd_core::PrincipalId;
use browserd_observability::{AuditWal, AuditWalPolicy};
use browserd_session::{LeasePolicy, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionJournalConfig, ActionStatus, AuthenticatedPeer, CreateSessionCommand, InternalEndpoint,
    PrivilegedEvaluateGrant, PrivilegedEvaluatePolicy, SessionOptionSupport, WorkerActionCommand,
    WorkerClock, WorkerConfig, WorkerControlPlane, WorkerError, WorkerNavigateWaitUntil,
};

const SUCCESS: &str = "globalThis.productionFixture = 1; 42";
const MUTATE_THEN_THROW: &str =
    "globalThis.productionFixture = 2; throw new Error('fixture after effect')";
const ORIGIN: &str = "https://evaluate.test";
const URL: &str = "https://evaluate.test/document";

struct Clock;

impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}

async fn event(writer: &mut Sender, value: Value) {
    writer
        .write_all(&serde_json::to_vec(&value).expect("event JSON"))
        .await
        .expect("event write");
    writer.write_all(&[0]).await.expect("event terminator");
}

async fn realm(writer: &mut Sender, unique_id: &str, origin: &str) {
    event(
        writer,
        json!({
            "method":"Runtime.executionContextCreated", "sessionId":"flat-evaluate",
            "params":{"context":{
                "id":1,"uniqueId":unique_id,"origin":origin,"name":"",
                "auxData":{"isDefault":true,"type":"default","frameId":"frame-evaluate"}
            }}
        }),
    )
    .await;
}

async fn next_command(reader: &mut Receiver) -> Option<Value> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut byte))
            .await
            .expect("bounded CDP peer progress")
            .expect("CDP command read");
        if read == 0 {
            assert!(bytes.is_empty(), "CDP owner must not truncate a command");
            return None;
        }
        if byte[0] == 0 {
            return Some(serde_json::from_slice(&bytes).expect("CDP command JSON"));
        }
        assert!(bytes.len() < 128 * 1024, "bounded fixture command");
        bytes.push(byte[0]);
    }
}

async fn native_evaluate_peer(
    peer: oneshot::Receiver<(Receiver, Sender)>,
    audit: Arc<AuditWal>,
    tenant: TenantId,
    principal: PrincipalId,
    effects: Arc<AtomicUsize>,
    sandbox: Arc<ScriptedSandbox>,
) {
    let (mut reader, mut writer) = peer.await.expect("native session pipe handoff");
    let session_launch = sandbox
        .created_specs
        .lock()
        .unwrap()
        .get(1)
        .expect("session launch follows the isolated qualification launch")
        .clone();
    let mut navigated = false;
    let mut disposed = false;
    let mut resumed = false;
    let mut device_metrics = false;
    let mut language = false;
    while let Some(command) = next_command(&mut reader).await {
        let method = command["method"].as_str().expect("method");
        let result = match method {
            "Browser.getVersion" => json!({
                "protocolVersion":"1.3", "product":"HeadlessChrome/149.0.7827.55",
                "revision":"r1234567", "userAgent":"browserd-production-factory-test",
                "jsVersion":"14.9"
            }),
            "Target.setAutoAttach" | "Target.setDiscoverTargets" => json!({}),
            "Target.getTargets" => json!({"targetInfos":[]}),
            "Target.getBrowserContexts" => {
                assert!(disposed);
                json!({"browserContextIds":[]})
            }
            "Target.createBrowserContext" => {
                assert_eq!(command["params"]["proxyServer"], "http://127.0.0.1:32100");
                json!({"browserContextId":"context-evaluate"})
            }
            "Browser.setDownloadBehavior" => {
                assert_eq!(command["params"]["behavior"], "deny");
                json!({})
            }
            "Target.createTarget" => {
                assert_eq!(command["params"]["browserContextId"], "context-evaluate");
                event(
                    &mut writer,
                    json!({"method":"Target.attachedToTarget","params":{
                        "sessionId":"flat-evaluate","waitingForDebugger":true,
                        "targetInfo":{"targetId":"target-evaluate","browserContextId":"context-evaluate","type":"page"}
                    }}),
                )
                .await;
                json!({"targetId":"target-evaluate"})
            }
            "Network.enable" | "Page.enable" | "Page.setInterceptFileChooserDialog" => {
                assert_eq!(command["sessionId"], "flat-evaluate");
                json!({})
            }
            "Runtime.enable" => {
                realm(&mut writer, "realm-initial", "about:blank").await;
                json!({})
            }
            "Page.getFrameTree" => {
                assert_eq!(command["sessionId"], "flat-evaluate");
                json!({"frameTree":{"frame":{
                    "id":"frame-evaluate", "loaderId":if navigated {"loader-document"} else {"loader-initial"},
                    "url":if navigated {URL} else {"about:blank"},
                    "securityOrigin":if navigated {ORIGIN} else {"://"}
                }}})
            }
            "Emulation.setDeviceMetricsOverride" => {
                assert!(!resumed);
                assert_eq!(command["params"]["width"], 1280);
                device_metrics = true;
                json!({})
            }
            "Network.setUserAgentOverride" => {
                assert!(!resumed);
                assert_eq!(command["params"]["acceptLanguage"], "ko-KR");
                assert_eq!(command["params"]["userAgent"], "");
                language = true;
                json!({})
            }
            "Runtime.runIfWaitingForDebugger" => {
                assert!(device_metrics && language, "native options precede resume");
                resumed = true;
                json!({})
            }
            "Page.navigate" => {
                assert!(resumed);
                assert_eq!(command["params"]["url"], URL);
                navigated = true;
                event(
                    &mut writer,
                    json!({"method":"Page.frameNavigated","sessionId":"flat-evaluate","params":{
                        "frame":{"id":"frame-evaluate","loaderId":"loader-document","url":URL,"securityOrigin":ORIGIN},
                        "type":"Navigation"
                    }}),
                )
                .await;
                realm(&mut writer, "realm-document", ORIGIN).await;
                event(
                    &mut writer,
                    json!({"method":"Page.domContentEventFired","sessionId":"flat-evaluate","params":{"timestamp":1.0}}),
                )
                .await;
                json!({"frameId":"frame-evaluate","loaderId":"loader-document"})
            }
            "Runtime.evaluate" => {
                assert!(resumed && navigated);
                assert_eq!(command["sessionId"], "flat-evaluate");
                assert_eq!(command["params"]["uniqueContextId"], "realm-document");
                assert!(command["params"].get("contextId").is_none());
                let index = effects.fetch_add(1, Ordering::SeqCst);
                let pending = audit.pending().expect("durable audit records");
                let intents = pending
                    .iter()
                    .filter(|pending| pending.event().kind() == "browser.evaluate.dispatch")
                    .collect::<Vec<_>>();
                assert_eq!(
                    intents.len(),
                    index + 1,
                    "audit must precede each wire effect"
                );
                for intent in intents {
                    let metadata: Value = serde_json::from_slice(intent.event().payload()).unwrap();
                    assert_eq!(metadata["tenant_id"], json!(tenant));
                    assert_eq!(metadata["principal_id"], json!(principal));
                    assert_eq!(metadata["worker_id"], "native-profile-factory");
                    assert_eq!(metadata["worker_epoch"], 31);
                    assert_eq!(metadata["placement_version"], 3);
                    assert_eq!(metadata["session_incarnation"], 1);
                    assert!(metadata.get("expression").is_none());
                }
                match index {
                    0 => {
                        assert_eq!(command["params"]["expression"], SUCCESS);
                        json!({"result":{"type":"number","value":42}})
                    }
                    1 => {
                        assert_eq!(command["params"]["expression"], MUTATE_THEN_THROW);
                        json!({
                            "result":{"type":"object","subtype":"error"},
                            "exceptionDetails":{"text":"fixture after effect"}
                        })
                    }
                    _ => panic!("a denied or idempotent action reached Runtime.evaluate"),
                }
            }
            "Target.disposeBrowserContext" => {
                assert_eq!(command["params"]["browserContextId"], "context-evaluate");
                disposed = true;
                event(
                    &mut writer,
                    json!({"method":"Target.targetDestroyed","params":{"targetId":"target-evaluate"}}),
                )
                .await;
                json!({})
            }
            _ => panic!("unexpected command in native evaluate chain: {method}"),
        };
        respond(&mut writer, &command, result).await;
    }
    // Production cleanup races actor shutdown with exact sandbox termination. Once the latter
    // proves the entire launch dead, CDP disposal is unnecessary and the owner closes its pipes.
    let exact_termination_completed = sandbox.kills.load(Ordering::SeqCst) == 2
        && sandbox
            .cancelled_specs
            .lock()
            .unwrap()
            .iter()
            .filter(|spec| **spec == session_launch)
            .count()
            == 1;
    assert!(
        disposed || exact_termination_completed,
        "pipe release requires context disposal or completed exact-launch termination"
    );
    assert_eq!(effects.load(Ordering::SeqCst), 2);
}

#[test]
fn privileged_evaluate_runs_through_production_router_actor_and_cdp_with_durable_admission() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("multi-thread production runtime");
    let native = NativeCatalogFixture::new();
    let directory = tempdir().expect("worker durable files");
    let journal = directory.path().join("actions");
    fs::create_dir(&journal).expect("action journal directory");
    let audit = Arc::new(
        AuditWal::open(
            directory.path().join("audit.wal"),
            AuditWalPolicy::new(1 << 20, 4096).expect("audit bounds"),
        )
        .expect("real audit WAL"),
    );
    let tenant = TenantId::new();
    let principal = PrincipalId::new();
    let policy = PrivilegedEvaluatePolicy::new(vec![PrivilegedEvaluateGrant {
        tenant_id: tenant.clone(),
        principal_id: principal.clone(),
    }])
    .expect("exact operator grant");
    let config = native
        .config(native.artifact.identity.clone())
        .with_native_profiles(native.catalog())
        .expect("verified native catalog")
        .with_privileged_evaluate(policy.is_enabled());
    let (readiness_tx, readiness_rx) = oneshot::channel();
    let (session_tx, session_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch: 17,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        missing_binding: false,
        created_specs: Mutex::new(Vec::new()),
        pinned_namespaces: Mutex::new(Vec::new()),
        peers: Mutex::new(VecDeque::from([readiness_tx, session_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let factory = Arc::new(
        ProductionSessionShardFactory::new(config, sandbox.clone(), runtime.handle().clone())
            .expect("production factory"),
    );
    let readiness = runtime.spawn(run_scripted_protocol(readiness_rx, CleanupProbe::Clean));
    assert_eq!(factory.qualify_daemon(), Ok(()));
    wait_protocol(&runtime, readiness).expect("production baseline qualification protocol");
    let worker_id = WorkerId::new("native-profile-factory").unwrap();
    let router = Arc::new(
        SessionShardRouter::new(worker_id.clone(), 31, factory, Arc::new(RejectArtifacts), 2)
            .expect("production router"),
    );
    let peer = AuthenticatedPeer::new("gateway-evaluate-fixture").unwrap();
    let worker_config = WorkerConfig::new(
        worker_id,
        31,
        InternalEndpoint::unix(directory.path().join("worker.sock")).unwrap(),
        peer.clone(),
        2,
        4,
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(5)).unwrap(),
        SessionTimeoutPolicy::new(Duration::from_secs(1800), Duration::from_secs(600)).unwrap(),
        Duration::from_secs(60),
        ActionJournalConfig::with_default_limits(journal).unwrap(),
    )
    .unwrap()
    .with_session_option_support(SessionOptionSupport::single_host_default());
    let worker =
        WorkerControlPlane::new_with_clock(worker_config, router.clone(), router, Arc::new(Clock))
            .with_audit_wal(audit.clone())
            .with_privileged_evaluate_policy(policy);
    let effects = Arc::new(AtomicUsize::new(0));
    let protocol = runtime.spawn(native_evaluate_peer(
        session_rx,
        audit.clone(),
        tenant.clone(),
        principal.clone(),
        effects.clone(),
        sandbox.clone(),
    ));
    let mut options = native_session_options();
    options.feature_profile = "privileged".to_owned();
    let created = worker
        .create_session_with_options(
            &peer,
            CreateSessionCommand {
                tenant_id: tenant,
                idempotency_key: "production-evaluate".to_owned(),
                canonical_request_hash: options.canonical_request_hash(
                    browserd_worker::WorkerIsolationProfile::DedicatedProcess,
                ),
                placement_version: 3,
                session_incarnation: 1,
            },
            &options,
            SessionTime::new(0),
        )
        .expect("CP create must traverse real production factory and actor");
    let submit = |key: &str, requester: &PrincipalId, command: WorkerActionCommand, now: u64| {
        let payload = serde_json::to_vec(&command).expect("typed action JSON");
        worker
            .submit_action(
                &peer,
                requester.clone(),
                &created.session_id,
                &created.fence,
                key,
                Sha256::digest(&payload).into(),
                command.kind(),
                command.required_feature(),
                Some(created.primary_page_id.clone()),
                payload,
                None,
                SessionTime::new(now),
            )
            .expect("CP typed action submission")
    };
    let run = |now| {
        worker
            .run_next_action(
                &peer,
                &created.session_id,
                &created.fence,
                SessionTime::new(now),
            )
            .expect("CP action completion")
    };
    submit(
        "navigate",
        &principal,
        WorkerActionCommand::Navigate {
            url: URL.to_owned(),
            wait_until: WorkerNavigateWaitUntil::Domcontentloaded,
        },
        1,
    );
    assert_eq!(run(2).unwrap().status, ActionStatus::Succeeded);
    let evaluate = |expression: &str| WorkerActionCommand::Evaluate {
        expression: expression.to_owned(),
    };
    let succeeded = submit("success", &principal, evaluate(SUCCESS), 3);
    let success = run(4).unwrap();
    assert_eq!(success.status, ActionStatus::Succeeded);
    assert_eq!(
        success.result.as_deref(),
        Some(br#"{"value":42}"#.as_slice())
    );
    assert_eq!(
        submit("success", &principal, evaluate(SUCCESS), 4),
        succeeded
    );
    assert!(run(4).is_none());
    assert_eq!(effects.load(Ordering::SeqCst), 1);

    submit("ungranted", &PrincipalId::new(), evaluate(SUCCESS), 5);
    assert_eq!(run(6).unwrap().status, ActionStatus::FailedKnown);
    assert_eq!(
        effects.load(Ordering::SeqCst),
        1,
        "principal denial has no CDP effect"
    );

    let uncertain = submit("throw", &principal, evaluate(MUTATE_THEN_THROW), 7);
    let unknown = run(8).unwrap();
    assert_eq!(unknown.status, ActionStatus::OutcomeUnknown);
    assert_eq!(unknown.result, None);
    assert_eq!(
        submit("throw", &principal, evaluate(MUTATE_THEN_THROW), 8),
        uncertain
    );
    assert!(run(8).is_none());
    assert_eq!(effects.load(Ordering::SeqCst), 2);

    worker
        .close_session(
            &peer,
            &created.session_id,
            &created.fence,
            SessionTime::new(9),
        )
        .expect("exact context and shard cleanup");
    wait_protocol(&runtime, protocol).expect("native evaluate protocol completion");
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 2);
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 2);
    let launches = sandbox.created_specs.lock().unwrap();
    assert_eq!(
        sandbox
            .cancelled_specs
            .lock()
            .unwrap()
            .iter()
            .filter(|spec| **spec == launches[1])
            .count(),
        1,
        "cleanup must terminate the exact session launch once"
    );
    assert!(matches!(
        launches[1].process_profile(),
        ChromiumProcessProfile::NativeLocaleV1 { .. }
    ));
}
