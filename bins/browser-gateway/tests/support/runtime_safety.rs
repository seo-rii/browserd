use super::*;
use browserd_core::{IsolationProfile, SafetySwitchMutation};
use browserd_operations::CanonicalRequestHash;

const SHARED_PROFILE: [u8; 32] = [6; 32];
const DEDICATED_PROFILE: [u8; 32] = [7; 32];

fn fixture() -> Fixture {
    let profiles = BTreeMap::from([
        (
            SHARED_PROFILE,
            (WorkerIsolationProfile::SharedContext, vector(1)),
        ),
        (
            DEDICATED_PROFILE,
            (WorkerIsolationProfile::DedicatedProcess, vector(3)),
        ),
    ]);
    let peers = vec![
        Arc::new(Peer::with_profiles("fleet-a", 2, profiles.clone())),
        Arc::new(Peer::with_profiles("fleet-b", 8, profiles)),
    ];
    let config = GatewayFleetAdmissionConfig::new(
        "fixture",
        peers
            .iter()
            .map(|peer| {
                GatewayFleetWorker::new(
                    peer.id.clone(),
                    format!("/private/{}.sock", peer.id),
                    "fixture",
                    vec![[8; 32]],
                    vec![SHARED_PROFILE, DEDICATED_PROFILE],
                    budget(8),
                    None,
                )
                .unwrap()
            })
            .collect(),
        vec![
            GatewayFleetProfile::new(
                SHARED_PROFILE,
                [8; 32],
                GatewaySessionIsolation::SharedContext,
                GatewaySessionWorkload::Interactive,
                budget(1),
                1,
            )
            .unwrap(),
            GatewayFleetProfile::new(
                DEDICATED_PROFILE,
                [8; 32],
                GatewaySessionIsolation::DedicatedProcess,
                GatewaySessionWorkload::Interactive,
                budget(3),
                3,
            )
            .unwrap(),
        ],
        GatewayFleetTenantPolicy::new(1, budget(16), 16, 16, 64).unwrap(),
        vec![],
        GatewayFleetAdmissionLimits::new(128, 64, 32, 16, budget(32)).unwrap(),
    )
    .unwrap();
    Fixture::configured(peers, config)
}

fn actor_config() -> CoordinationActorConfig {
    CoordinationActorConfig::new(64, 8, Duration::from_secs(2), Duration::from_secs(2)).unwrap()
}

fn safety(fixture: &Fixture, initialize: bool) -> SafetyAuthorityBlockingClient {
    let client = SafetyAuthorityBlockingClient::spawn(
        Arc::new(MemorySafetyAuthority::default()),
        actor_config(),
    )
    .unwrap();
    if initialize {
        client
            .initialize(
                SafetyInitializeRequest::new(
                    identity(fixture),
                    Uuid::new_v4(),
                    "initialize conservative fleet safety",
                )
                .unwrap(),
            )
            .unwrap();
    }
    client
}

fn identity(fixture: &Fixture) -> SafetyActorIdentity {
    SafetyActorIdentity::new(
        fixture.principal.tenant_id().clone(),
        "fleet-safety-operator",
    )
    .unwrap()
}

fn mutate(
    fixture: &Fixture,
    safety: &SafetyAuthorityBlockingClient,
    mutation: SafetySwitchMutation,
) {
    let version = safety.read().unwrap().snapshot().version();
    safety
        .mutate(
            SafetyMutationRequest::new(
                identity(fixture),
                Uuid::new_v4(),
                version,
                mutation,
                "change fleet runtime safety",
            )
            .unwrap(),
        )
        .unwrap();
}

fn router(
    fixture: &Fixture,
    safety: &SafetyAuthorityBlockingClient,
) -> DurableApiRouter<GatewayWorkerRuntime<Peer>> {
    fixture.router(Arc::new(
        fixture
            .runtime_builder()
            .with_runtime_safety(safety.clone()),
    ))
}

fn shared_body() -> browserd_api::SessionCreateRequest {
    decode_session_create(&BODY.replace("dedicated_process", "shared_context")).unwrap()
}

fn create(
    fixture: &Fixture,
    router: &DurableApiRouter<GatewayWorkerRuntime<Peer>>,
    key: &str,
) -> browserd_api::OperationEnvelope {
    let response = router
        .execute(
            &fixture.principal,
            ApiRequest::CreateSession {
                body: shared_body(),
                idempotency_key: key.to_owned(),
                received_at: Instant::now(),
            },
        )
        .unwrap();
    let ApiResponse::SessionCreate(envelope) = response else {
        panic!("create response")
    };
    envelope.data().operation().clone()
}

fn admission(
    fixture: &Fixture,
    operation: &browserd_api::OperationEnvelope,
) -> Option<GatewaySessionAdmissionSnapshot> {
    GatewayActionBlockingClient::spawn(fixture.store.clone(), actor_config())
        .unwrap()
        .get_session_admission(&GatewaySessionAdmissionKey::new(
            fixture.principal.tenant_id().clone(),
            operation.id().clone(),
        ))
        .unwrap()
}

fn assert_original_request(
    fixture: &Fixture,
    operation: &browserd_api::OperationEnvelope,
) -> [u8; 32] {
    let original = serde_json::to_value(shared_body()).unwrap();
    let expected_hash = *CanonicalRequestHash::from_json(&original).as_bytes();
    let stored = fixture
        .pg
        .get(fixture.principal.tenant_id(), operation.id())
        .unwrap()
        .unwrap();
    assert_eq!(stored.intent().canonical_request(), &original);
    assert_eq!(stored.request_hash().as_bytes(), expected_hash);
    if let Some(session) = operation.session() {
        assert_eq!(session.requested_isolation, IsolationProfile::SharedContext);
    }
    expected_hash
}

#[test]
fn force_dedicated_new_admission_charges_actual_profile_without_rewriting_client_intent() {
    let fixture = fixture();
    let safety = safety(&fixture, true);
    let api = router(&fixture, &safety);
    let operation = create(&fixture, &api, &Uuid::new_v4().to_string());
    assert_eq!(operation.state(), CreateOperationState::Succeeded);
    assert_eq!(
        operation.session().unwrap().effective_isolation,
        IsolationProfile::DedicatedProcess
    );
    let hash = assert_original_request(&fixture, &operation);
    let admission = admission(&fixture, &operation).unwrap();
    assert_eq!(admission.request().canonical_request_hash(), hash);
    assert_eq!(admission.request().profile_digest(), DEDICATED_PROFILE);
    assert_eq!(
        admission.request().isolation(),
        GatewaySessionIsolation::DedicatedProcess
    );
    assert_eq!(admission.request().resources(), budget(3));
    let reservation = admission.reservation().unwrap();
    assert_eq!(reservation.resources(), budget(3));
    assert_eq!(fixture.peers[0].commits.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.peers[1].commits.load(Ordering::SeqCst), 1);
    let rows = fixture.peers[1].rows.lock().unwrap();
    let token = &rows.values().next().unwrap().token;
    assert_eq!(token.request.request.canonical_request_hash, hash);
    assert_eq!(token.request.profile_digest, DEDICATED_PROFILE);
    assert_eq!(token.request.resources, vector(3));
    assert_eq!(
        token.request.request.requested_isolation,
        WorkerIsolationProfile::SharedContext
    );
    drop(rows);
    assert_eq!(fixture.peers[1].capacity().raw_free, vector(5));
}

#[test]
fn density_one_floor_remains_dedicated_after_force_flag_is_relaxed() {
    let fixture = fixture();
    let safety = safety(&fixture, true);
    mutate(
        &fixture,
        &safety,
        SafetySwitchMutation::SetForceDedicatedProcess(false),
    );
    assert_eq!(
        safety.read().unwrap().snapshot().max_contexts_per_shard(),
        1
    );
    let operation = create(
        &fixture,
        &router(&fixture, &safety),
        &Uuid::new_v4().to_string(),
    );
    assert_eq!(operation.state(), CreateOperationState::Succeeded);
    assert_eq!(
        operation.session().unwrap().effective_isolation,
        IsolationProfile::DedicatedProcess
    );
    assert_original_request(&fixture, &operation);
    let admission = admission(&fixture, &operation).unwrap();
    assert_eq!(admission.request().profile_digest(), DEDICATED_PROFILE);
    assert_eq!(admission.request().resources(), budget(3));
}

#[test]
fn relaxed_safety_retry_preserves_original_reservation_and_new_admission_uses_new_floor() {
    let fixture = fixture();
    let safety = safety(&fixture, true);
    fixture.peers[1].lost_commit.store(true, Ordering::SeqCst);
    let key = Uuid::new_v4().to_string();
    let api = router(&fixture, &safety);
    let first = create(&fixture, &api, &key);
    assert_eq!(first.state(), CreateOperationState::Creating);
    let hash = assert_original_request(&fixture, &first);
    let token = fixture.peers[1]
        .rows
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .token
        .clone();
    let reservation = admission(&fixture, &first)
        .unwrap()
        .reservation()
        .unwrap()
        .clone();
    assert_eq!(token.request.profile_digest, DEDICATED_PROFILE);
    assert_eq!(token.request.resources, vector(3));
    assert_eq!(fixture.peers[1].commits.load(Ordering::SeqCst), 1);
    drop(api);
    mutate(
        &fixture,
        &safety,
        SafetySwitchMutation::SetForceDedicatedProcess(false),
    );
    mutate(
        &fixture,
        &safety,
        SafetySwitchMutation::SetMaxContextsPerShard(8),
    );
    std::thread::sleep(Duration::from_millis(200));
    let api = router(&fixture, &safety);
    let recovered = create(&fixture, &api, &key);
    assert_eq!(recovered.id(), first.id());
    assert_eq!(recovered.state(), CreateOperationState::Succeeded);
    assert_eq!(
        recovered.session().unwrap().effective_isolation,
        IsolationProfile::DedicatedProcess
    );
    assert_eq!(assert_original_request(&fixture, &recovered), hash);
    let recovered_admission = admission(&fixture, &recovered).unwrap();
    let recovered_reservation = recovered_admission.reservation().unwrap();
    assert_eq!(
        recovered_reservation.reservation_id(),
        reservation.reservation_id()
    );
    assert_eq!(recovered_reservation.worker(), reservation.worker());
    assert_eq!(recovered_reservation.profile_digest(), DEDICATED_PROFILE);
    assert_eq!(recovered_reservation.resources(), budget(3));
    assert_eq!(
        fixture.peers[1]
            .rows
            .lock()
            .unwrap()
            .get(&token.request.reservation_id)
            .unwrap()
            .token,
        token
    );
    assert_eq!(fixture.peers[1].commits.load(Ordering::SeqCst), 1);
    let fresh = create(&fixture, &api, &Uuid::new_v4().to_string());
    assert_eq!(fresh.state(), CreateOperationState::Succeeded);
    assert_eq!(
        fresh.session().unwrap().effective_isolation,
        IsolationProfile::SharedContext
    );
    assert_original_request(&fixture, &fresh);
    let fresh_admission = admission(&fixture, &fresh).unwrap();
    assert_eq!(fresh_admission.request().profile_digest(), SHARED_PROFILE);
    assert_eq!(fresh_admission.request().resources(), budget(1));
    assert_eq!(fixture.peers[1].commits.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.peers[1].capacity().raw_free, vector(4));
}

#[test]
fn uninitialized_safety_blocks_new_fleet_admission_before_worker_observation_or_commit() {
    let fixture = fixture();
    let safety = safety(&fixture, false);
    let operation = create(
        &fixture,
        &router(&fixture, &safety),
        &Uuid::new_v4().to_string(),
    );
    assert_eq!(operation.state(), CreateOperationState::Creating);
    assert_original_request(&fixture, &operation);
    assert!(admission(&fixture, &operation).is_none());
    for peer in &fixture.peers {
        assert_eq!(peer.capacity_reads.load(Ordering::SeqCst), 0);
        assert!(peer.rows.lock().unwrap().is_empty());
        assert_eq!(peer.commits.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn stopped_network_class_blocks_new_admission_before_capacity_or_browser_effects() {
    let fixture = fixture();
    let safety = safety(&fixture, true);
    mutate(
        &fixture,
        &safety,
        SafetySwitchMutation::SetStoppedNetworkClass {
            network_class: "public".to_owned(),
            stopped: true,
        },
    );
    let operation = create(
        &fixture,
        &router(&fixture, &safety),
        &Uuid::new_v4().to_string(),
    );
    assert_eq!(operation.state(), CreateOperationState::Failed);
    assert_eq!(operation.failure().unwrap().code, "network_policy_denied");
    assert!(operation.session().is_none());
    assert_original_request(&fixture, &operation);
    assert!(admission(&fixture, &operation).is_none());
    for peer in &fixture.peers {
        assert_eq!(peer.capacity_reads.load(Ordering::SeqCst), 0);
        assert!(peer.rows.lock().unwrap().is_empty());
        assert_eq!(peer.commits.load(Ordering::SeqCst), 0);
    }
}
