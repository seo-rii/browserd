#![allow(clippy::expect_used)]
use super::*;
use browserd_viewer::{TicketPolicy, TicketRegistry, ViewerConnection};
use browserd_worker::{
    ViewerClientMessage, WorkerSessionFence, WorkerViewerCloseRequest, WorkerViewerController,
    WorkerViewerMessageRequest, WorkerViewerOpenRequest,
};

fn fixture() -> Result<ReadyWorker, Box<dyn std::error::Error>> {
    let driver = Arc::new(FakeDriver {
        qualified: true,
        ..FakeDriver::default()
    });
    let sandbox = Arc::new(FakeSandbox {
        qualified: true,
        ..FakeSandbox::default()
    });
    let config = config_with_policies(
        4,
        4,
        LeasePolicy::new(Duration::from_secs(60), Duration::from_secs(10))
            .expect("viewer fixture or operation"),
        SessionTimeoutPolicy::new(Duration::from_secs(120), Duration::from_secs(60))
            .expect("viewer fixture or operation"),
    )
    .ok_or("config")
    .expect("viewer fixture or operation");
    let peer = AuthenticatedPeer::new("gateway-internal").expect("viewer fixture or operation");
    Ok((
        WorkerControlPlane::new_with_clock(
            config,
            driver.clone(),
            sandbox.clone(),
            Arc::new(TestClock),
        ),
        peer,
        driver,
        sandbox,
    ))
}

fn grant(
    created: &CreateSessionOutcome,
    tenant: &TenantId,
    admin: bool,
) -> Result<(WorkerSessionFence, ViewerConnection), Box<dyn std::error::Error>> {
    let registry = TicketRegistry::new(
        TicketPolicy::new(Duration::from_secs(30), ["https://viewer.test"])
            .expect("viewer fixture or operation"),
    );
    let ticket = registry
        .issue(
            tenant.clone(),
            created.session_id.clone(),
            created.fence.session_incarnation(),
            ViewerScopes::new(true, true, admin),
            0,
            Duration::from_secs(10),
        )
        .expect("viewer fixture or operation");
    let connection = registry
        .consume(
            &ticket,
            tenant,
            &created.session_id,
            created.fence.session_incarnation(),
            "https://viewer.test",
            1,
        )
        .expect("viewer fixture or operation");
    Ok((
        WorkerSessionFence {
            tenant_id: tenant.clone(),
            session_id: created.session_id.clone(),
            worker_epoch: created.fence.worker_epoch(),
            placement_version: created.fence.placement_version(),
            session_incarnation: created.fence.session_incarnation(),
        },
        connection,
    ))
}

fn message(
    fence: &WorkerSessionFence,
    connection: &ViewerConnection,
    value: serde_json::Value,
) -> Result<WorkerViewerMessageRequest, serde_json::Error> {
    Ok(WorkerViewerMessageRequest {
        fence: fence.clone(),
        connection_id: connection.id().clone(),
        message: serde_json::from_value::<ViewerClientMessage>(value)
            .expect("viewer fixture or operation"),
    })
}

#[test]
fn viewer_control_serializes_with_agent_and_discards_stale_or_replayed_input()
-> Result<(), Box<dyn std::error::Error>> {
    let (worker, peer, driver, _) = fixture().expect("viewer fixture or operation");
    let tenant = TenantId::new();
    let created = worker
        .create_session(
            &peer,
            create_command(tenant.clone(), "viewer-control", 1),
            SessionTime::new(0),
        )
        .expect("viewer fixture or operation");
    let (fence, connection) = grant(&created, &tenant, false).expect("viewer fixture or operation");
    worker
        .viewer_open(
            &peer,
            &WorkerViewerOpenRequest {
                fence: fence.clone(),
                connection: connection.clone(),
            },
            SessionTime::new(1),
        )
        .expect("viewer fixture or operation");
    let controlled = worker
        .viewer_message(
            &peer,
            &message(
                &fence,
                &connection,
                serde_json::json!({"type":"request_control","force":false}),
            )
            .expect("viewer fixture or operation"),
            SessionTime::new(2),
        )
        .expect("viewer fixture or operation");
    assert_eq!(
        controlled.control.controller,
        WorkerViewerController::ThisConnection
    );
    let epoch = controlled.control.lease_epoch;
    let input = |sequence, transform| serde_json::json!({"type":"insert_text","lease_epoch":epoch,"input_sequence":sequence,"page_id":created.primary_page_id,"frame_transform_id":transform,"text":"한글"});
    assert!(
        worker
            .viewer_message(
                &peer,
                &message(&fence, &connection, input(1, 999)).expect("viewer fixture or operation"),
                SessionTime::new(3)
            )
            .is_err()
    );
    assert_eq!(driver.viewer_inputs.load(Ordering::SeqCst), 0);
    worker
        .viewer_message(
            &peer,
            &message(&fence, &connection, input(1, 1)).expect("viewer fixture or operation"),
            SessionTime::new(4),
        )
        .expect("viewer fixture or operation");
    assert!(
        worker
            .viewer_message(
                &peer,
                &message(&fence, &connection, input(1, 1)).expect("viewer fixture or operation"),
                SessionTime::new(5)
            )
            .is_err()
    );
    assert_eq!(driver.viewer_inputs.load(Ordering::SeqCst), 1);
    worker
        .submit_action(
            &peer,
            PrincipalId::new(),
            &created.session_id,
            &created.fence,
            "blocked-agent",
            [3; 32],
            ActionKind::Mutating,
            Some(BuiltinFeature::CoreInput),
            Some(created.primary_page_id.clone()),
            b"click".to_vec(),
            None,
            SessionTime::new(6),
        )
        .expect("viewer fixture or operation");
    assert!(
        worker
            .run_next_action(
                &peer,
                &created.session_id,
                &created.fence,
                SessionTime::new(7)
            )
            .is_err()
    );
    worker
        .viewer_close(
            &peer,
            &WorkerViewerCloseRequest {
                fence: fence.clone(),
                connection_id: connection.id().clone(),
            },
            SessionTime::new(8),
        )
        .expect("viewer fixture or operation");
    assert_eq!(
        worker
            .get_session(&peer, &created.session_id, &created.fence)
            .expect("viewer fixture or operation")
            .control,
        browserd_session::SessionControl::Agent
    );
    assert!(
        worker
            .viewer_open(
                &peer,
                &WorkerViewerOpenRequest { fence, connection },
                SessionTime::new(9)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn expired_viewer_control_returns_to_agent_but_failed_cleanup_stays_blocked()
-> Result<(), Box<dyn std::error::Error>> {
    for cleanup_fails in [false, true] {
        let (worker, peer, driver, _) = fixture().expect("viewer fixture or operation");
        let tenant = TenantId::new();
        let created = worker
            .create_session(
                &peer,
                create_command(tenant.clone(), "viewer-expiry", 1),
                SessionTime::new(0),
            )
            .expect("viewer fixture or operation");
        let (fence, connection) =
            grant(&created, &tenant, false).expect("viewer fixture or operation");
        worker
            .viewer_open(
                &peer,
                &WorkerViewerOpenRequest {
                    fence: fence.clone(),
                    connection: connection.clone(),
                },
                SessionTime::new(1),
            )
            .expect("viewer fixture or operation");
        worker
            .viewer_message(
                &peer,
                &message(
                    &fence,
                    &connection,
                    serde_json::json!({"type":"request_control","force":false}),
                )
                .expect("viewer fixture or operation"),
                SessionTime::new(2),
            )
            .expect("viewer fixture or operation");
        driver
            .viewer_cleanup_fails
            .store(cleanup_fails, Ordering::SeqCst);
        let expired = worker.expire_viewers(&peer, SessionTime::new(31_003));
        assert_eq!(expired.is_err(), cleanup_fails);
        let control = worker
            .get_session(&peer, &created.session_id, &created.fence)
            .expect("viewer fixture or operation")
            .control;
        assert_eq!(
            control,
            if cleanup_fails {
                browserd_session::SessionControl::Human
            } else {
                browserd_session::SessionControl::Agent
            }
        );
    }
    Ok(())
}

#[test]
fn close_before_open_retires_the_connection_and_foreign_namespace_is_denied()
-> Result<(), Box<dyn std::error::Error>> {
    let (worker, peer, _, _) = fixture().expect("viewer fixture or operation");
    let tenant = TenantId::new();
    let created = worker
        .create_session(
            &peer,
            create_command(tenant.clone(), "viewer-late-open", 1),
            SessionTime::new(0),
        )
        .expect("viewer fixture or operation");
    let (fence, connection) = grant(&created, &tenant, false).expect("viewer fixture or operation");
    worker
        .viewer_close(
            &peer,
            &WorkerViewerCloseRequest {
                fence: fence.clone(),
                connection_id: connection.id().clone(),
            },
            SessionTime::new(1),
        )
        .expect("viewer fixture or operation");
    assert!(
        worker
            .viewer_open(
                &peer,
                &WorkerViewerOpenRequest {
                    fence: fence.clone(),
                    connection: connection.clone()
                },
                SessionTime::new(2)
            )
            .is_err()
    );
    let mut foreign = fence;
    foreign.tenant_id = TenantId::new();
    assert!(
        worker
            .viewer_open(
                &peer,
                &WorkerViewerOpenRequest {
                    fence: foreign,
                    connection
                },
                SessionTime::new(3)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn durable_control_backpressure_blocks_grants_and_keeps_release_blocked_until_ack() {
    use browserd_worker::ControlEventJournal;
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("journal root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let journal = Arc::new(
        ControlEventJournal::open(&root.path().join("events.json"), 1, 8, 65536).expect("journal"),
    );
    let (worker, peer, _, _) = fixture().expect("fixture");
    let worker = worker.with_control_event_journal(journal.clone());
    let tenant = TenantId::new();
    let created = worker
        .create_session(
            &peer,
            create_command(tenant.clone(), "viewer-durable", 1),
            SessionTime::new(0),
        )
        .expect("create");
    let (fence, connection) = grant(&created, &tenant, false).expect("grant");
    worker
        .viewer_open(
            &peer,
            &WorkerViewerOpenRequest {
                fence: fence.clone(),
                connection: connection.clone(),
            },
            SessionTime::new(1),
        )
        .expect("open");
    let blocking = journal
        .record(fence.clone(), 1, false, None)
        .expect("fill journal");
    let acquire = message(
        &fence,
        &connection,
        serde_json::json!({"type":"request_control","force":false}),
    )
    .expect("request");
    assert_eq!(
        worker.viewer_message(&peer, &acquire, SessionTime::new(2)),
        Err(WorkerError::DurabilityUnavailable)
    );
    assert_eq!(
        worker
            .get_session(&peer, &created.session_id, &created.fence)
            .expect("session")
            .control,
        browserd_session::SessionControl::Agent
    );
    journal.ack(&blocking).expect("ack unrelated transition");
    worker
        .viewer_message(&peer, &acquire, SessionTime::new(3))
        .expect("durable grant");
    let pending = worker.pending_control_events(&peer, 1).expect("pending");
    assert_eq!(pending.len(), 1);
    assert!(pending[0].human);
    let release = message(
        &fence,
        &connection,
        serde_json::json!({"type":"release_control"}),
    )
    .expect("request");
    assert_eq!(
        worker.viewer_message(&peer, &release, SessionTime::new(4)),
        Err(WorkerError::DurabilityUnavailable)
    );
    assert_eq!(
        worker
            .get_session(&peer, &created.session_id, &created.fence)
            .expect("session")
            .control,
        browserd_session::SessionControl::Human
    );
    worker
        .ack_control_event(&peer, &pending[0])
        .expect("ack grant");
    worker
        .expire_viewers(&peer, SessionTime::new(5))
        .expect("retry pending release");
    let pending = worker
        .pending_control_events(&peer, 1)
        .expect("pending release");
    assert!(!pending[0].human);
    assert_eq!(pending[0].sequence, 3);
    assert_eq!(
        worker
            .get_session(&peer, &created.session_id, &created.fence)
            .expect("session")
            .control,
        browserd_session::SessionControl::Agent
    );
}

#[test]
fn runtime_viewer_kill_stops_acquisition_and_input_but_keeps_release_and_read() {
    use browserd_core::{RuntimeSafetyCache, SafetySwitchMutation, SafetySwitchSnapshot};
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = *browserd_core::SessionId::new().as_uuid();
    let initial = SafetySwitchSnapshot::default()
        .apply(&SafetySwitchMutation::SetForceDedicatedProcess(false))
        .expect("intent")
        .apply(&SafetySwitchMutation::SetMaxContextsPerShard(4))
        .expect("density");
    cache
        .install(namespace, initial.clone(), Duration::from_secs(30))
        .expect("authority");
    let (worker, peer, driver, _) = fixture().expect("fixture");
    let worker = worker
        .with_runtime_safety_cache(cache.clone(), "17".repeat(32))
        .expect("runtime");
    let tenant = TenantId::new();
    let created = worker
        .create_session(
            &peer,
            create_command(tenant.clone(), "runtime-viewer", 1),
            SessionTime::new(0),
        )
        .expect("create");
    let (fence, connection) = grant(&created, &tenant, false).expect("grant");
    worker
        .viewer_open(
            &peer,
            &WorkerViewerOpenRequest {
                fence: fence.clone(),
                connection: connection.clone(),
            },
            SessionTime::new(1),
        )
        .expect("open");
    let request = message(
        &fence,
        &connection,
        serde_json::json!({"type":"request_control","force":false}),
    )
    .expect("request");
    let disabled = initial
        .apply(&SafetySwitchMutation::DisableViewerControl(true))
        .expect("disable");
    cache
        .install(namespace, disabled.clone(), Duration::from_secs(30))
        .expect("update");
    assert!(
        worker
            .viewer_message(&peer, &request, SessionTime::new(2))
            .is_err()
    );
    let enabled = disabled
        .apply(&SafetySwitchMutation::DisableViewerControl(false))
        .expect("enable");
    cache
        .install(namespace, enabled.clone(), Duration::from_secs(30))
        .expect("update");
    let controlled = worker
        .viewer_message(&peer, &request, SessionTime::new(3))
        .expect("acquire");
    cache
        .install(
            namespace,
            enabled
                .apply(&SafetySwitchMutation::DisableViewerControl(true))
                .expect("disable"),
            Duration::from_secs(30),
        )
        .expect("update");
    let input=message(&fence,&connection,serde_json::json!({"type":"insert_text","lease_epoch":controlled.control.lease_epoch,"input_sequence":1,"page_id":created.primary_page_id,"frame_transform_id":1,"text":"blocked"})).expect("input");
    assert!(
        worker
            .viewer_message(&peer, &input, SessionTime::new(4))
            .is_err()
    );
    assert_eq!(driver.viewer_inputs.load(Ordering::SeqCst), 0);
    worker
        .viewer_message(
            &peer,
            &message(
                &fence,
                &connection,
                serde_json::json!({"type":"release_control"}),
            )
            .expect("release"),
            SessionTime::new(5),
        )
        .expect("release remains available");
    let view = worker
        .viewer_poll(
            &peer,
            &browserd_worker::WorkerViewerPollRequest {
                fence,
                connection_id: connection.id().clone(),
                after_frame_id: 0,
            },
            SessionTime::new(6),
        )
        .expect("read remains available");
    assert_eq!(view.control.controller, WorkerViewerController::Agent);
}
