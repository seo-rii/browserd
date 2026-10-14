use super::*;
use browserd_coordination::{
    DirectoryEntry, DirectoryKey, DispatchLeaseToken, GatewayActionSubmissionLease,
    GatewayFleetAdmissionConfig, GatewayFleetAdmissionLimits, GatewayFleetProfile,
    GatewayFleetTenantPolicy, GatewayFleetTenantRule, GatewayFleetWorker,
    GatewayFleetWorkerIdentity, GatewayFleetWorkerObservation, GatewaySessionAdmissionCursor,
    GatewaySessionAdmissionKey, GatewaySessionAdmissionRequest, GatewaySessionAdmissionSnapshot,
    GatewaySessionAdmissionState, GatewaySessionCleanupProof, GatewaySessionIsolation,
    GatewaySessionPlacementAuthority, GatewaySessionWorkerReadyProof,
    GatewaySessionWorkerRenewalProof, GatewaySessionWorkerReservationProof, GatewaySessionWorkload,
    WorkerCapacity, WorkerReadiness,
};
use browserd_core::{LeaseId, OperationId, PageId};

const PROFILE: [u8; 32] = [3; 32];
const COMPAT: [u8; 32] = [4; 32];
fn units(n: u64) -> WorkerCapacity {
    WorkerCapacity::new(n, n, n, n, n, n)
}
fn config(
    workers: usize,
    slots: u64,
    rules: Vec<GatewayFleetTenantRule>,
) -> GatewayFleetAdmissionConfig {
    GatewayFleetAdmissionConfig::new(
        "local",
        (0..workers)
            .map(|i| {
                GatewayFleetWorker::new(
                    WorkerId::new(format!("fleet-{i:03}")).expect("worker"),
                    format!("/tmp/fleet-{i:03}.sock"),
                    "local",
                    vec![COMPAT],
                    vec![PROFILE],
                    units(slots),
                    None,
                )
                .expect("worker config")
            })
            .collect(),
        vec![
            GatewayFleetProfile::new(
                PROFILE,
                COMPAT,
                GatewaySessionIsolation::SharedContext,
                GatewaySessionWorkload::Light,
                units(1),
                1,
            )
            .expect("profile"),
        ],
        GatewayFleetTenantPolicy::new(1, units(1024), 1024, 1024, 2048).expect("tenant policy"),
        rules,
        GatewayFleetAdmissionLimits::new(4096, 2048, 2048, 1024, units(4096)).expect("limits"),
    )
    .expect("config")
}
fn request(tenant: TenantId) -> GatewaySessionAdmissionRequest {
    let now = Utc::now();
    GatewaySessionAdmissionRequest::new(
        GatewaySessionAdmissionKey::new(tenant, OperationId::new()),
        PrincipalId::new(),
        [5; 32],
        PROFILE,
        COMPAT,
        GatewaySessionIsolation::SharedContext,
        units(1),
        now,
        now + chrono::Duration::minutes(4),
    )
    .expect("request")
}
struct Fixture {
    base: RedisFixture,
    store: Arc<RedisGatewayActionStore>,
    config: GatewayFleetAdmissionConfig,
    identity: GatewayFleetWorkerIdentity,
}
async fn fixture(label: &str, config: GatewayFleetAdmissionConfig) -> Option<Fixture> {
    let base = redis_fixture(label).await?;
    let store = Arc::new(
        RedisGatewayActionStore::connect(base.config.clone().with_fleet_admission(config.clone()))
            .await
            .expect("managed connect"),
    );
    let identity =
        GatewayFleetWorkerIdentity::new(config.workers()[0].worker_id().clone(), 7, LeaseId::new())
            .expect("identity");
    Some(Fixture {
        base,
        store,
        config,
        identity,
    })
}
async fn observe(
    f: &Fixture,
    identity: GatewayFleetWorkerIdentity,
    revision: u64,
    watermark: u64,
    free: u64,
    readiness: WorkerReadiness,
) {
    let worker = f
        .config
        .workers()
        .iter()
        .find(|w| w.worker_id() == identity.worker_id())
        .expect("inventory");
    let observation = GatewayFleetWorkerObservation::new(
        identity,
        revision,
        watermark,
        worker.capacity_ceiling(),
        units(free),
        readiness,
        COMPAT,
        None,
    )
    .expect("observation");
    f.store
        .observe_fleet_worker(observation, Duration::from_secs(120))
        .await
        .expect("observe");
}
async fn reserve(f: &Fixture, tenant: TenantId) -> GatewaySessionAdmissionSnapshot {
    let input = request(tenant);
    f.store
        .enqueue_session_admission(input)
        .await
        .expect("enqueue");
    f.store
        .reserve_next_session(Duration::from_secs(60))
        .await
        .expect("reserve")
        .expect("candidate")
}
async fn record(
    f: &Fixture,
    reserved: &GatewaySessionAdmissionSnapshot,
    debit: u64,
) -> GatewaySessionAdmissionSnapshot {
    f.store
        .record_session_reservation(
            reserved,
            GatewaySessionWorkerReservationProof {
                reservation: reserved.reservation().expect("reservation").clone(),
                worker_reservation_nonce: LeaseId::new(),
                remaining_ttl_millis: 60_000,
                capacity_revision: debit + 1,
                debit_sequence: debit,
            },
        )
        .await
        .expect("record positive reserve")
}
async fn activate(
    f: &Fixture,
    tenant: TenantId,
) -> (
    GatewaySessionAdmissionSnapshot,
    GatewaySessionPlacementAuthority,
    GatewaySessionWorkerReadyProof,
) {
    let reserved = reserve(f, tenant).await;
    let recorded = record(f, &reserved, 1).await;
    let armed = f
        .store
        .arm_session_create(
            &recorded,
            &DispatchLeaseToken::new(),
            Duration::from_secs(30),
        )
        .await
        .expect("arm");
    let res = armed.reservation().expect("reservation");
    let proof = GatewaySessionWorkerReadyProof {
        reservation: res.clone(),
        entry: DirectoryEntry::new(
            DirectoryKey::new(res.key().tenant_id().clone(), SessionId::new()),
            res.directory_fence().clone(),
            f.config
                .workers()
                .iter()
                .find(|w| w.worker_id() == res.worker().worker_id())
                .expect("worker")
                .endpoint(),
        )
        .expect("entry"),
        primary_page_id: PageId::new(),
        effective_isolation: GatewaySessionIsolation::SharedContext,
        remaining_ownership_ttl_millis: 30_000,
        capacity_revision: 3,
        debit_sequence: 1,
        restored_checkpoint: None,
    };
    let authority = f
        .store
        .commit_session_placement(&armed, proof.clone())
        .await
        .expect("ready commit");
    (armed, authority, proof)
}
async fn connection(f: &Fixture) -> redis::aio::MultiplexedConnection {
    redis::Client::open(f.base.endpoint.as_str())
        .expect("endpoint")
        .get_multiplexed_async_connection()
        .await
        .expect("connection")
}
async fn floor(f: &Fixture, value: u64) {
    redis::cmd("HSET")
        .arg(format!("{}:gateway-action:recovery-format", f.base.prefix))
        .arg("clock_floor")
        .arg(value)
        .query_async::<()>(&mut connection(f).await)
        .await
        .expect("trusted clock fixture");
}

#[tokio::test]
async fn redis_fleet_managed_namespace_blocks_legacy_admission_even_absent_authority_and_other_config()
 {
    let Some(f) = fixture("fleet-managed", config(1, 8, vec![])).await else {
        return;
    };
    let claim = claim_with_kind(
        TenantId::new(),
        SessionId::new(),
        ActionId::new(),
        "legacy",
        1,
        ActionKind::ReadOnly,
        placement(1, 1),
    );
    assert!(matches!(
        f.base.store.claim_action(claim, Utc::now()).await,
        Err(GatewayActionCoordinationError::ManagedActionAdmissionRequired)
    ));
    let changed = config(1, 9, vec![]);
    assert!(matches!(
        RedisGatewayActionStore::connect(f.base.config.clone().with_fleet_admission(changed)).await,
        Err(GatewayActionCoordinationError::AdmissionConflict)
    ));
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_ready_lost_reply_restart_and_projection_ack_preserve_exact_placement() {
    let Some(f) = fixture("fleet-ready", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let (armed, authority, proof) = activate(&f, TenantId::new()).await;
    let reopened = RedisGatewayActionStore::connect(
        f.base.config.clone().with_fleet_admission(f.config.clone()),
    )
    .await
    .expect("reopen");
    assert_eq!(
        reopened
            .commit_session_placement(&armed, proof)
            .await
            .expect("lost response retry"),
        authority
    );
    assert_eq!(
        reopened
            .resolve_session_placement(authority.entry().key())
            .await
            .expect("resolve"),
        Some(authority.clone())
    );
    let current = reopened
        .get_session_admission(armed.request().key())
        .await
        .expect("get")
        .expect("active");
    assert!(current.pending_create_projection());
    let ack = reopened
        .ack_session_create_projection(&current)
        .await
        .expect("PG receipt ACK");
    assert!(!ack.pending_create_projection());
    assert_eq!(
        reopened
            .ack_session_create_projection(&current)
            .await
            .expect("ACK lost response"),
        ack
    );
    let claim = claim_with_kind(
        authority.entry().key().tenant_id().clone(),
        authority.entry().key().session_id().clone(),
        ActionId::new(),
        "after-ready",
        1,
        ActionKind::ReadOnly,
        authority.authority().action_placement().expect("placement"),
    );
    assert!(matches!(
        reopened
            .claim_action_authorized(claim, authority.authority(), Utc::now())
            .await,
        Ok(GatewayActionClaimOutcome::Created(_))
    ));
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_close_atomically_denies_new_authorized_claim_and_owned_arm() {
    let Some(f) = fixture("fleet-action-race", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let (_, authority, _) = activate(&f, TenantId::new()).await;
    let key = authority.entry().key();
    let placement = authority.authority().action_placement().expect("placement");
    let now = Utc::now();
    let lease = GatewayActionSubmissionLease::new(
        Uuid::now_v7(),
        1,
        now + chrono::Duration::seconds(20),
        now + chrono::Duration::seconds(30),
    )
    .expect("lease");
    let claim = claim_with_kind(
        key.tenant_id().clone(),
        key.session_id().clone(),
        ActionId::new(),
        "queued-action",
        1,
        ActionKind::ReadOnly,
        placement.clone(),
    )
    .with_submission_lease(lease.clone());
    let row = f
        .store
        .claim_action_authorized(claim.clone(), authority.authority(), now)
        .await
        .expect("claim")
        .into_snapshot();
    let closed = f.store.begin_session_close(&authority).await.expect("seal");
    assert!(matches!(
        f.store
            .arm_dispatch_owned_authorized(
                key.tenant_id(),
                key.session_id(),
                row.action_id(),
                row.revision(),
                &placement,
                DispatchId::new(),
                &lease,
                authority.authority(),
                now
            )
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    let fresh = claim_with_kind(
        key.tenant_id().clone(),
        key.session_id().clone(),
        ActionId::new(),
        "new-action",
        1,
        ActionKind::ReadOnly,
        placement,
    );
    assert!(matches!(
        f.store
            .claim_action_authorized(fresh, authority.authority(), now)
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    assert_eq!(
        f.store
            .claim_action_authorized(claim, authority.authority(), now)
            .await
            .expect("historical duplicate")
            .into_snapshot(),
        row
    );
    assert!(matches!(
        f.store
            .validate_session_authority(authority.authority())
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    assert_eq!(
        f.store
            .resolve_session_placement(key)
            .await
            .expect("historical authority"),
        Some(closed)
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_observe_before_reserve_receipt_does_not_double_charge_and_release_never_adds_raw_free()
 {
    let Some(f) = fixture("fleet-shadow", config(1, 2, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 2, WorkerReadiness::Ready).await;
    let first = reserve(&f, TenantId::new()).await;
    observe(&f, f.identity.clone(), 2, 1, 1, WorkerReadiness::Ready).await;
    let recorded = record(&f, &first, 1).await;
    let second = reserve(&f, TenantId::new()).await;
    assert_ne!(recorded.request().key(), second.request().key());
    f.store
        .release_session_reservation(
            &recorded,
            GatewaySessionCleanupProof::NoEffectCancelled {
                reservation: recorded.reservation().expect("res").clone(),
                capacity_revision: 3,
            },
        )
        .await
        .expect("confirmed no effect");
    // Raw free remains 1; second unacknowledged debit still occupies that one unit.
    assert!(
        f.store
            .reserve_next_session(Duration::from_secs(30))
            .await
            .expect("no arithmetic credit")
            .is_none()
    );
    observe(&f, f.identity.clone(), 4, 2, 2, WorkerReadiness::Ready).await;
    assert!(
        f.store
            .reserve_next_session(Duration::from_secs(30))
            .await
            .expect("fresh capacity fact")
            .is_some()
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_record_before_observe_reconciles_once_and_stale_or_drain_observations_cannot_reopen()
 {
    let Some(f) = fixture("fleet-observe", config(1, 2, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 2, WorkerReadiness::Ready).await;
    let first = reserve(&f, TenantId::new()).await;
    record(&f, &first, 1).await;
    observe(&f, f.identity.clone(), 2, 1, 1, WorkerReadiness::Ready).await;
    observe(&f, f.identity.clone(), 2, 1, 1, WorkerReadiness::Ready).await;
    reserve(&f, TenantId::new()).await;
    observe(&f, f.identity.clone(), 3, 2, 0, WorkerReadiness::Draining).await;
    let stale = GatewayFleetWorkerObservation::new(
        f.identity.clone(),
        4,
        2,
        units(2),
        units(2),
        WorkerReadiness::Ready,
        COMPAT,
        None,
    )
    .expect("fact");
    assert!(matches!(
        f.store
            .observe_fleet_worker(stale, Duration::from_secs(30))
            .await,
        Err(GatewayActionCoordinationError::InvalidFleetObservation)
    ));
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_only_reserved_expiry_releases_capacity_exposed_unknown_stays_pinned() {
    let Some(f) = fixture("fleet-expiry", config(1, 2, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 2, WorkerReadiness::Ready).await;
    let unexposed = reserve(&f, TenantId::new()).await;
    let recorded = record(&f, &unexposed, 1).await;
    let armed = f
        .store
        .arm_session_create(
            &recorded,
            &DispatchLeaseToken::new(),
            Duration::from_secs(30),
        )
        .await
        .expect("arm");
    let reserved = reserve(&f, TenantId::new()).await;
    let expires = reserved
        .reservation()
        .expect("res")
        .provider_deadline_millis();
    floor(&f, expires + 1).await;
    assert!(
        f.store
            .reserve_next_session(Duration::from_secs(30))
            .await
            .expect("bounded expiry sweep")
            .is_none()
    );
    let current = f
        .store
        .get_session_admission(reserved.request().key())
        .await
        .expect("get")
        .expect("row");
    assert_eq!(current.state(), GatewaySessionAdmissionState::Expired);
    assert_eq!(current.reservation(), reserved.reservation());
    assert_eq!(
        f.store
            .get_session_admission(armed.request().key())
            .await
            .expect("get")
            .expect("row")
            .state(),
        GatewaySessionAdmissionState::CommitArmed
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_weighted_drr_survives_restart_and_preserves_fifo() {
    let a = TenantId::new();
    let b = TenantId::new();
    let rules = vec![
        GatewayFleetTenantRule::new(
            b.clone(),
            GatewayFleetTenantPolicy::new(2, units(1024), 1024, 1024, 2048).expect("policy"),
        )
        .expect("rule"),
    ];
    let Some(f) = fixture("fleet-fairness", config(1, 128, rules)).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 128, WorkerReadiness::Ready).await;
    let mut expected_a = Vec::new();
    let mut expected_b = Vec::new();
    for _ in 0..20 {
        for tenant in [&a, &b] {
            let req = request(tenant.clone());
            if tenant == &a {
                expected_a.push(req.key().clone());
            } else {
                expected_b.push(req.key().clone());
            }
            f.store.enqueue_session_admission(req).await.expect("queue");
        }
    }
    let mut counts = [0_usize; 2];
    for index in 0..18 {
        let store = if index == 9 {
            Arc::new(
                RedisGatewayActionStore::connect(
                    f.base.config.clone().with_fleet_admission(f.config.clone()),
                )
                .await
                .expect("restart"),
            )
        } else {
            f.store.clone()
        };
        let row = store
            .reserve_next_session(Duration::from_secs(60))
            .await
            .expect("fair turn")
            .expect("row");
        let i = usize::from(row.request().key().tenant_id() == &b);
        let expected = if i == 0 { &expected_a } else { &expected_b };
        assert_eq!(row.request().key(), &expected[counts[i]]);
        counts[i] += 1;
    }
    assert_eq!(counts, [6, 12]);
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_ineligible_tenant_credit_caps_burst_at_64_after_restart() {
    let Some(f) = fixture("fleet-credit-cap", config(1, 128, vec![])).await else {
        return;
    };
    let mut tenants = [TenantId::new(), TenantId::new()];
    tenants.sort();
    let mut first_fifo = Vec::new();
    for _ in 0..65 {
        let request = request(tenants[0].clone());
        first_fifo.push(request.key().clone());
        f.store
            .enqueue_session_admission(request)
            .await
            .expect("first tenant queue");
    }
    let second = request(tenants[1].clone());
    let second_key = second.key().clone();
    f.store
        .enqueue_session_admission(second)
        .await
        .expect("second tenant queue");
    // Neither tenant has an eligible worker. Repeated passes may retain only bounded credit.
    for _ in 0..70 {
        assert!(
            f.store
                .reserve_next_session(Duration::from_secs(60))
                .await
                .expect("ineligible scheduling pass")
                .is_none()
        );
    }
    let reopened = RedisGatewayActionStore::connect(
        f.base.config.clone().with_fleet_admission(f.config.clone()),
    )
    .await
    .expect("reopen accumulated credit");
    observe(&f, f.identity.clone(), 1, 0, 128, WorkerReadiness::Ready).await;
    for expected in first_fifo.iter().take(64) {
        let row = reopened
            .reserve_next_session(Duration::from_secs(60))
            .await
            .expect("bounded credited burst")
            .expect("reservation");
        assert_eq!(row.request().key(), expected);
    }
    let next = reopened
        .reserve_next_session(Duration::from_secs(60))
        .await
        .expect("next tenant turn")
        .expect("reservation");
    assert_eq!(
        next.request().key(),
        &second_key,
        "the first tenant's 65th queued request must wait for the competing tenant"
    );
    assert_eq!(
        reopened
            .get_session_admission(&first_fifo[64])
            .await
            .expect("remaining first request")
            .expect("stored admission")
            .state(),
        GatewaySessionAdmissionState::Queued
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_least_loaded_worker_uses_headroom_after_shadow_debits() {
    let Some(f) = fixture("fleet-least-loaded", config(2, 8, vec![])).await else {
        return;
    };
    let second = GatewayFleetWorkerIdentity::new(
        f.config.workers()[1].worker_id().clone(),
        7,
        LeaseId::new(),
    )
    .expect("second worker");
    observe(&f, f.identity.clone(), 1, 0, 1, WorkerReadiness::Ready).await;
    observe(&f, second.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let first = reserve(&f, TenantId::new()).await;
    assert_eq!(first.reservation().expect("reservation").worker(), &second);

    // The new observation has not acknowledged that reservation. Although its raw free is
    // greater, one outstanding shadow debit makes both candidates' available headroom equal.
    observe(&f, second, 2, 0, 2, WorkerReadiness::Ready).await;
    let next = reserve(&f, TenantId::new()).await;
    assert_eq!(
        next.reservation().expect("reservation").worker(),
        &f.identity
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_equal_normalized_headroom_rotates_after_restart() {
    let Some(f) = fixture("fleet-equal-headroom", config(2, 8, vec![])).await else {
        return;
    };
    let second = GatewayFleetWorkerIdentity::new(
        f.config.workers()[1].worker_id().clone(),
        7,
        LeaseId::new(),
    )
    .expect("second worker");
    f.store
        .observe_fleet_worker(
            GatewayFleetWorkerObservation::new(
                f.identity.clone(),
                1,
                0,
                units(4),
                units(2),
                WorkerReadiness::Ready,
                COMPAT,
                None,
            )
            .expect("half-free first worker"),
            Duration::from_secs(120),
        )
        .await
        .expect("observe first worker");
    observe(&f, second.clone(), 1, 0, 4, WorkerReadiness::Ready).await;
    let first = reserve(&f, TenantId::new()).await;
    assert_eq!(
        first.reservation().expect("reservation").worker(),
        &f.identity,
        "2/4 and 4/8 headroom tie; raw free alone must not pick the second worker"
    );
    let queued = f
        .store
        .release_session_reservation(
            &first,
            GatewaySessionCleanupProof::NoEffectCancelled {
                reservation: first.reservation().expect("reservation").clone(),
                capacity_revision: 2,
            },
        )
        .await
        .expect("positive no-effect removes only the outstanding shadow debit");
    assert_eq!(queued.state(), GatewaySessionAdmissionState::Queued);
    let reopened = RedisGatewayActionStore::connect(
        f.base.config.clone().with_fleet_admission(f.config.clone()),
    )
    .await
    .expect("reopen scheduler");
    let next = reopened
        .reserve_next_session(Duration::from_secs(60))
        .await
        .expect("reserve after restart")
        .expect("same queued operation");
    assert_eq!(next.request().key(), first.request().key());
    assert_eq!(next.reservation().expect("reservation").worker(), &second);
    assert!(
        next.reservation().expect("reservation").generation()
            > first.reservation().expect("reservation").generation()
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_headroom_compares_full_u64_values_without_float_rounding() {
    let Some(f) = fixture("fleet-headroom-u64", config(2, u64::MAX, vec![])).await else {
        return;
    };
    let second = GatewayFleetWorkerIdentity::new(
        f.config.workers()[1].worker_id().clone(),
        7,
        LeaseId::new(),
    )
    .expect("second worker");
    observe(
        &f,
        f.identity.clone(),
        1,
        0,
        u64::MAX - 2,
        WorkerReadiness::Ready,
    )
    .await;
    observe(
        &f,
        second.clone(),
        1,
        0,
        u64::MAX - 1,
        WorkerReadiness::Ready,
    )
    .await;
    let first = reserve(&f, TenantId::new()).await;
    assert_eq!(
        first.reservation().expect("reservation").worker(),
        &second,
        "one unit of headroom near u64::MAX must remain distinguishable"
    );
    let next = reserve(&f, TenantId::new()).await;
    assert_eq!(
        next.reservation().expect("reservation").worker(),
        &f.identity,
        "the previous debit creates an exact tie and rotates to the first worker"
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_candidate_and_tenant_windows_rotate_without_unbounded_scan() {
    let Some(f) = fixture("fleet-window", config(40, 128, vec![])).await else {
        return;
    };
    let last = GatewayFleetWorkerIdentity::new(
        f.config.workers()[39].worker_id().clone(),
        7,
        LeaseId::new(),
    )
    .expect("lastworker");
    observe(&f, last.clone(), 1, 0, 128, WorkerReadiness::Ready).await;
    let mut tenants = Vec::new();
    for _ in 0..70 {
        let tenant = TenantId::new();
        tenants.push(tenant.clone());
        f.store
            .enqueue_session_admission(request(tenant))
            .await
            .expect("enqueue");
    }
    assert!(
        f.store
            .reserve_next_session(Duration::from_secs(60))
            .await
            .expect("first32")
            .is_none()
    );
    let row = f
        .store
        .reserve_next_session(Duration::from_secs(60))
        .await
        .expect("rotated32")
        .expect("candidate");
    assert_eq!(row.reservation().expect("res").worker(), &last);
    let mut cursor = GatewaySessionAdmissionCursor::default();
    let mut count = 0;
    loop {
        let page = f
            .store
            .scan_session_admissions(cursor, 13)
            .await
            .expect("bounded scan");
        assert!(page.examined() <= 13);
        count += page.examined();
        cursor = page.next_cursor().clone();
        if page.is_complete() {
            break;
        }
    }
    assert_eq!(count, 70);
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_u64_fifo_sequence_above_float_precision_and_atomic_duplicate_enqueue() {
    let Some(f) = fixture("fleet-u64", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let key = format!("{}:fleet:v1:state", f.base.prefix);
    let mut connection = connection(&f).await;
    let raw: String = redis::cmd("HGET")
        .arg(&key)
        .arg("totals")
        .query_async(&mut connection)
        .await
        .expect("totals");
    let mut totals: serde_json::Value = serde_json::from_str(&raw).expect("json");
    totals["sequence"] = serde_json::json!(9_007_199_254_740_992_u64);
    redis::cmd("HSET")
        .arg(&key)
        .arg("totals")
        .arg(serde_json::to_string(&totals).expect("json"))
        .query_async::<()>(&mut connection)
        .await
        .expect("exact sequence seed");
    let input = request(TenantId::new());
    let (a, b) = tokio::join!(
        f.store.enqueue_session_admission(input.clone()),
        f.store.enqueue_session_admission(input.clone())
    );
    let a = a.expect("enqueue");
    assert_eq!(a, b.expect("duplicate"));
    assert_eq!(a.queue_sequence(), 9_007_199_254_740_993);
    let second = f
        .store
        .enqueue_session_admission(request(input.key().tenant_id().clone()))
        .await
        .expect("next");
    assert_eq!(second.queue_sequence(), a.queue_sequence() + 1);
    assert_eq!(
        f.store
            .reserve_next_session(Duration::from_secs(60))
            .await
            .expect("reserve")
            .expect("row")
            .request()
            .key(),
        input.key()
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_renewal_fixed_anchor_and_clock_floor_prevent_expired_authority_revival() {
    let Some(f) = fixture("fleet-renew", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let (_, authority, _) = activate(&f, TenantId::new()).await;
    let nonce = LeaseId::new();
    let intent = f
        .store
        .begin_session_renewal(&authority, nonce.clone(), Duration::from_secs(40))
        .await
        .expect("intent");
    let proof = GatewaySessionWorkerRenewalProof {
        authority: authority.authority().clone(),
        worker: f.identity.clone(),
        renewal_nonce: nonce,
        granted_ttl_millis: 40_000,
    };
    let renewed = f
        .store
        .finish_session_renewal(&intent, proof.clone())
        .await
        .expect("renew");
    assert_eq!(
        renewed.expires_at_millis(),
        intent.anchored_expires_at_millis()
    );
    assert_eq!(renewed.authority(), authority.authority());
    assert_eq!(
        f.store
            .finish_session_renewal(&intent, proof)
            .await
            .expect("reply lost retry"),
        renewed
    );
    floor(&f, renewed.expires_at_millis() + 1).await;
    assert!(matches!(
        f.store
            .validate_session_authority(renewed.authority())
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    assert!(matches!(
        f.store
            .begin_session_renewal(&renewed, LeaseId::new(), Duration::from_secs(30))
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_v4_upgrade_preserves_action_history_and_does_not_invent_session_authority() {
    let Some(base) = redis_fixture("fleet-v4").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let original = base
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "historical",
                1,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            Utc::now(),
        )
        .await
        .expect("old claim")
        .into_snapshot();
    let mut connection = redis::Client::open(base.endpoint.as_str())
        .expect("endpoint")
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let marker = format!("{}:gateway-action:recovery-format", base.prefix);
    redis::cmd("HSET")
        .arg(&marker)
        .arg("version")
        .arg("4")
        .query_async::<()>(&mut connection)
        .await
        .expect("v4 fixture");
    assert!(matches!(
        RedisGatewayActionStore::connect(base.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationRequired)
    ));
    let first =
        RedisGatewayActionStore::migrate_recovery_format(base.config.clone(), true, Utc::now())
            .await
            .expect("offline step");
    if !first.complete() {
        for _ in 0..8 {
            if RedisGatewayActionStore::migrate_recovery_format(
                base.config.clone(),
                true,
                Utc::now(),
            )
            .await
            .expect("resume")
            .complete()
            {
                break;
            }
        }
    }
    let managed = RedisGatewayActionStore::connect(
        base.config
            .clone()
            .with_fleet_admission(config(1, 8, vec![])),
    )
    .await
    .expect("migrated connect");
    assert_eq!(
        managed
            .get_effective_action(&tenant, &session, original.action_id())
            .await
            .expect("history"),
        Some(original)
    );
    assert!(
        managed
            .resolve_session_placement(&DirectoryKey::new(tenant, session))
            .await
            .expect("no fabricated authority")
            .is_none()
    );
    delete_fixture(&base).await;
}

#[tokio::test]
async fn redis_fleet_wrong_worker_proof_and_insufficient_ready_ttl_leave_armed_capacity_unchanged()
{
    let Some(f) = fixture("fleet-proof", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let row = reserve(&f, TenantId::new()).await;
    let recorded = record(&f, &row, 1).await;
    let dispatch = DispatchLeaseToken::new();
    let armed = f
        .store
        .arm_session_create(&recorded, &dispatch, Duration::from_secs(30))
        .await
        .expect("arm");
    assert_eq!(
        f.store
            .arm_session_create(&recorded, &dispatch, Duration::from_secs(30))
            .await
            .expect("lost arm reply"),
        armed
    );
    let res = armed.reservation().expect("res");
    let original = DirectoryEntry::new(
        DirectoryKey::new(res.key().tenant_id().clone(), SessionId::new()),
        res.directory_fence().clone(),
        f.config.workers()[0].endpoint(),
    )
    .expect("entry");
    let mut proof = GatewaySessionWorkerReadyProof {
        reservation: res.clone(),
        entry: original.clone(),
        primary_page_id: PageId::new(),
        effective_isolation: GatewaySessionIsolation::SharedContext,
        remaining_ownership_ttl_millis: 29_999,
        capacity_revision: 3,
        debit_sequence: 1,
        restored_checkpoint: None,
    };
    assert!(
        f.store
            .commit_session_placement(&armed, proof.clone())
            .await
            .is_err()
    );
    proof.remaining_ownership_ttl_millis = 30_000;
    proof.entry = DirectoryEntry::new(
        original.key().clone(),
        original.fence().clone(),
        "/tmp/foreign.sock",
    )
    .expect("foreign endpoint");
    assert!(
        f.store
            .commit_session_placement(&armed, proof.clone())
            .await
            .is_err()
    );
    assert_eq!(
        f.store
            .get_session_admission(armed.request().key())
            .await
            .expect("get"),
        Some(armed.clone())
    );
    assert!(
        f.store
            .resolve_session_placement(original.key())
            .await
            .expect("absent")
            .is_none()
    );
    proof.entry = original;
    let ready = f
        .store
        .commit_session_placement(&armed, proof)
        .await
        .expect("exact final proof");
    let before = f
        .store
        .get_session_admission(armed.request().key())
        .await
        .expect("get")
        .expect("active");
    let mut wrong = before.reservation().expect("res").clone();
    let mut wire = serde_json::to_value(&wrong).expect("wire");
    wire["reservation_id"] = serde_json::to_value(LeaseId::new()).expect("id");
    wrong = serde_json::from_value(wire).expect("valid wrong identity");
    assert!(
        f.store
            .release_session_reservation(
                &before,
                GatewaySessionCleanupProof::ContextDisposed {
                    reservation: wrong,
                    entry: ready.entry().clone(),
                    capacity_revision: 4
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.store
            .get_session_admission(armed.request().key())
            .await
            .expect("unchanged"),
        Some(before)
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_scan_keeps_acknowledged_active_and_closing_after_restart() {
    let Some(f) = fixture("fleet-live-scan", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let (armed, authority, _) = activate(&f, TenantId::new()).await;
    let active = f
        .store
        .get_session_admission(armed.request().key())
        .await
        .expect("get active")
        .expect("stored admission");
    let active = f
        .store
        .ack_session_create_projection(&active)
        .await
        .expect("PG projection ACK");
    assert!(!active.pending_create_projection());

    for expected_state in [
        GatewaySessionAdmissionState::Active,
        GatewaySessionAdmissionState::Closing,
    ] {
        if expected_state == GatewaySessionAdmissionState::Closing {
            f.store
                .begin_session_close(&authority)
                .await
                .expect("seal admission before disposal");
        }
        let reopened = RedisGatewayActionStore::connect(
            f.base.config.clone().with_fleet_admission(f.config.clone()),
        )
        .await
        .expect("reopen for independent maintenance");
        let page = reopened
            .scan_session_admissions(GatewaySessionAdmissionCursor::default(), 1)
            .await
            .expect("bounded live maintenance scan");
        assert_eq!(page.examined(), 1);
        assert_eq!(page.admissions().len(), 1);
        let found = &page.admissions()[0];
        assert_eq!(found.request().key(), armed.request().key());
        assert_eq!(found.state(), expected_state);
        assert!(!found.pending_create_projection());
        assert!(!page.is_complete());
        let end = reopened
            .scan_session_admissions(page.next_cursor().clone(), 1)
            .await
            .expect("bounded scan completion");
        assert_eq!(end.examined(), 0);
        assert!(end.admissions().is_empty());
        assert!(end.is_complete());
    }
    let closing = f
        .store
        .get_session_admission(armed.request().key())
        .await
        .expect("get closing")
        .expect("stored admission");
    let released = f
        .store
        .release_session_reservation(
            &closing,
            GatewaySessionCleanupProof::ContextDisposed {
                reservation: closing.reservation().expect("reservation").clone(),
                entry: authority.entry().clone(),
                capacity_revision: 4,
            },
        )
        .await
        .expect("positive disposal releases capacity");
    assert_eq!(released.state(), GatewaySessionAdmissionState::Released);
    let reopened = RedisGatewayActionStore::connect(
        f.base.config.clone().with_fleet_admission(f.config.clone()),
    )
    .await
    .expect("reopen released history");
    let page = reopened
        .scan_session_admissions(GatewaySessionAdmissionCursor::default(), 1)
        .await
        .expect("released rows are examined but not maintained");
    assert_eq!(page.examined(), 1);
    assert!(page.admissions().is_empty());
    assert!(!page.is_complete());
    let end = reopened
        .scan_session_admissions(page.next_cursor().clone(), 1)
        .await
        .expect("empty filtered page still advances cursor");
    assert!(end.is_complete());
    assert_eq!(end.examined(), 0);
    assert_eq!(
        reopened
            .get_session_admission(armed.request().key())
            .await
            .expect("historical release remains readable"),
        Some(released)
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_retained_quota_stays_bounded_and_failed_admission_does_not_consume_fifo_sequence()
 {
    let worker = GatewayFleetWorker::new(
        WorkerId::new("bounded-worker").expect("worker"),
        "/tmp/bounded.sock",
        "local",
        vec![COMPAT],
        vec![PROFILE],
        units(8),
        None,
    )
    .expect("worker");
    let limited = GatewayFleetAdmissionConfig::new(
        "local",
        vec![worker],
        vec![
            GatewayFleetProfile::new(
                PROFILE,
                COMPAT,
                GatewaySessionIsolation::SharedContext,
                GatewaySessionWorkload::Light,
                units(1),
                1,
            )
            .expect("profile"),
        ],
        GatewayFleetTenantPolicy::new(1, units(8), 2, 2, 2).expect("policy"),
        vec![],
        GatewayFleetAdmissionLimits::new(2, 2, 2, 2, units(8)).expect("limits"),
    )
    .expect("config");
    let Some(f) = fixture("fleet-cap", limited).await else {
        return;
    };
    let tenant = TenantId::new();
    let a = f
        .store
        .enqueue_session_admission(request(tenant.clone()))
        .await
        .expect("a");
    let b = f
        .store
        .enqueue_session_admission(request(tenant))
        .await
        .expect("b");
    assert!(matches!(
        f.store
            .enqueue_session_admission(request(TenantId::new()))
            .await,
        Err(GatewayActionCoordinationError::AdmissionCapacity)
    ));
    assert_eq!(b.queue_sequence(), a.queue_sequence() + 1);
    let page = f
        .store
        .scan_session_admissions(GatewaySessionAdmissionCursor::default(), 64)
        .await
        .expect("bounded retained");
    assert_eq!(page.examined(), 2);
    for limit in [0, 65] {
        assert!(
            f.store
                .scan_session_admissions(GatewaySessionAdmissionCursor::default(), limit)
                .await
                .is_err()
        );
    }
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_concurrent_closure_and_authorized_claim_have_one_atomic_winner() {
    let Some(f) = fixture("fleet-linearization", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let (_, authority, _) = activate(&f, TenantId::new()).await;
    let key = authority.entry().key();
    let claim = claim_with_kind(
        key.tenant_id().clone(),
        key.session_id().clone(),
        ActionId::new(),
        "race",
        1,
        ActionKind::ReadOnly,
        authority.authority().action_placement().expect("placement"),
    );
    let (closed, claim_result) = tokio::join!(
        f.store.begin_session_close(&authority),
        f.store
            .claim_action_authorized(claim.clone(), authority.authority(), Utc::now())
    );
    closed.expect("closed");
    match claim_result {
        Ok(GatewayActionClaimOutcome::Created(row)) => assert_eq!(
            f.store
                .get_effective_action(key.tenant_id(), key.session_id(), row.action_id())
                .await
                .expect("earlier claim durable"),
            Some(row)
        ),
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable) => assert!(
            f.store
                .get_effective_action(
                    key.tenant_id(),
                    key.session_id(),
                    claim.proposed_action_id()
                )
                .await
                .expect("rejected claim absent")
                .is_none()
        ),
        other => panic!("unexpected atomic outcome: {other:?}"),
    }
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_new_worker_boot_blocks_live_authority_but_preserves_historical_receipts() {
    let Some(f) = fixture("fleet-live-boot", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let (armed, authority, proof) = activate(&f, TenantId::new()).await;
    let key = authority.entry().key();
    let placement = authority.authority().action_placement().expect("placement");
    let now = Utc::now();
    let lease = GatewayActionSubmissionLease::new(
        Uuid::now_v7(),
        1,
        now + chrono::Duration::seconds(20),
        now + chrono::Duration::seconds(30),
    )
    .expect("lease");
    let claim = claim_with_kind(
        key.tenant_id().clone(),
        key.session_id().clone(),
        ActionId::new(),
        "before-worker-restart",
        1,
        ActionKind::ReadOnly,
        placement.clone(),
    )
    .with_submission_lease(lease.clone());
    let action = f
        .store
        .claim_action_authorized(claim.clone(), authority.authority(), now)
        .await
        .expect("claim")
        .into_snapshot();
    observe(&f, f.identity.clone(), 2, 1, 7, WorkerReadiness::Draining).await;
    f.store
        .validate_session_authority(authority.authority())
        .await
        .expect("draining does not invalidate existing exact worker authority");
    let restarted = GatewayFleetWorkerIdentity::new(
        f.identity.worker_id().clone(),
        f.identity.worker_epoch() + 1,
        LeaseId::new(),
    )
    .expect("restarted worker");
    observe(&f, restarted, 1, 0, 8, WorkerReadiness::Ready).await;
    assert!(matches!(
        f.store
            .validate_session_authority(authority.authority())
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    assert!(matches!(
        f.store
            .arm_dispatch_owned_authorized(
                key.tenant_id(),
                key.session_id(),
                action.action_id(),
                action.revision(),
                &placement,
                DispatchId::new(),
                &lease,
                authority.authority(),
                now,
            )
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    let fresh = claim_with_kind(
        key.tenant_id().clone(),
        key.session_id().clone(),
        ActionId::new(),
        "after-worker-restart",
        1,
        ActionKind::ReadOnly,
        placement,
    );
    assert!(matches!(
        f.store
            .claim_action_authorized(fresh, authority.authority(), now)
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    assert_eq!(
        f.store
            .claim_action_authorized(claim, authority.authority(), now)
            .await
            .expect("historical action retry")
            .into_snapshot(),
        action
    );
    assert_eq!(
        f.store
            .commit_session_placement(&armed, proof)
            .await
            .expect("historical Ready retry"),
        authority
    );
    assert_eq!(
        f.store
            .resolve_session_placement(key)
            .await
            .expect("history"),
        Some(authority.clone())
    );
    let current = f
        .store
        .get_session_admission(armed.request().key())
        .await
        .expect("admission")
        .expect("active");
    assert_eq!(current.state(), GatewaySessionAdmissionState::Active);
    assert_eq!(
        current
            .reservation()
            .expect("original reservation")
            .worker(),
        &f.identity
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_new_worker_boot_rejects_first_ready_commit_without_releasing_exposed_reservation()
 {
    let Some(f) = fixture("fleet-commit-boot", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let reserved = reserve(&f, TenantId::new()).await;
    let recorded = record(&f, &reserved, 1).await;
    let armed = f
        .store
        .arm_session_create(
            &recorded,
            &DispatchLeaseToken::new(),
            Duration::from_secs(30),
        )
        .await
        .expect("arm");
    let res = armed.reservation().expect("reservation");
    let proof = GatewaySessionWorkerReadyProof {
        reservation: res.clone(),
        entry: DirectoryEntry::new(
            DirectoryKey::new(res.key().tenant_id().clone(), SessionId::new()),
            res.directory_fence().clone(),
            f.config.workers()[0].endpoint(),
        )
        .expect("entry"),
        primary_page_id: PageId::new(),
        effective_isolation: GatewaySessionIsolation::SharedContext,
        remaining_ownership_ttl_millis: 30_000,
        capacity_revision: 3,
        debit_sequence: 1,
        restored_checkpoint: None,
    };
    let restarted = GatewayFleetWorkerIdentity::new(
        f.identity.worker_id().clone(),
        f.identity.worker_epoch() + 1,
        LeaseId::new(),
    )
    .expect("restarted worker");
    observe(&f, restarted, 1, 0, 8, WorkerReadiness::Ready).await;
    assert!(matches!(
        f.store
            .commit_session_placement(&armed, proof.clone())
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    assert_eq!(
        f.store
            .get_session_admission(armed.request().key())
            .await
            .expect("admission"),
        Some(armed)
    );
    assert!(
        f.store
            .resolve_session_placement(proof.entry.key())
            .await
            .expect("no placement")
            .is_none()
    );
    let mut conn = connection(&f).await;
    let totals: String = redis::cmd("HGET")
        .arg(format!("{}:fleet:v1:state", f.base.prefix))
        .arg("totals")
        .query_async(&mut conn)
        .await
        .expect("durable totals");
    let totals: serde_json::Value = serde_json::from_str(&totals).expect("totals JSON");
    assert_eq!(totals["live"], 1);
    assert_eq!(totals["resources"], serde_json::json!([1, 1, 1, 1, 1, 1]));
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_live_guard_requires_exact_action_session_and_rejects_loss() {
    let Some(f) = fixture("fleet-live-session", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let (_, authority, _) = activate(&f, TenantId::new()).await;
    let key = authority.entry().key();
    let session_key = format!(
        "{}:gateway-action:{{{}:{}}}:session",
        f.base.prefix,
        key.tenant_id(),
        key.session_id()
    );
    let mut conn = connection(&f).await;
    let placement: String = redis::cmd("HGET")
        .arg(&session_key)
        .arg("placement")
        .query_async(&mut conn)
        .await
        .expect("action session placement");
    f.store
        .validate_session_authority(authority.authority())
        .await
        .expect("live exact binding");
    redis::cmd("HDEL")
        .arg(&session_key)
        .arg("placement")
        .query_async::<()>(&mut conn)
        .await
        .expect("missing binding fixture");
    assert!(matches!(
        f.store
            .validate_session_authority(authority.authority())
            .await,
        Err(GatewayActionCoordinationError::InvalidRedisResponse)
    ));
    redis::cmd("HSET")
        .arg(&session_key)
        .arg("placement")
        .arg("different-placement")
        .query_async::<()>(&mut conn)
        .await
        .expect("different binding fixture");
    assert!(matches!(
        f.store
            .validate_session_authority(authority.authority())
            .await,
        Err(GatewayActionCoordinationError::InvalidRedisResponse)
    ));
    redis::cmd("HSET")
        .arg(&session_key)
        .arg("placement")
        .arg(placement)
        .query_async::<()>(&mut conn)
        .await
        .expect("restore fixture binding");
    let loss = SessionLossClaim::new(
        key.tenant_id().clone(),
        key.session_id().clone(),
        authority.authority().action_placement().expect("placement"),
        Uuid::now_v7(),
    );
    f.store
        .ensure_session_lost(&loss, Utc::now())
        .await
        .expect("durable loss");
    assert!(matches!(
        f.store
            .validate_session_authority(authority.authority())
            .await,
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
    ));
    assert_eq!(
        f.store
            .resolve_session_placement(key)
            .await
            .expect("history still available"),
        Some(authority)
    );
    delete_fixture(&f.base).await;
}

#[tokio::test]
async fn redis_fleet_acknowledged_debit_identity_survives_restart_and_cannot_bind_another_reservation()
 {
    for observe_first in [false, true] {
        let Some(f) = fixture("fleet-confirmed-debit", config(1, 8, vec![])).await else {
            return;
        };
        observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
        let first = reserve(&f, TenantId::new()).await;
        if observe_first {
            observe(&f, f.identity.clone(), 2, 1, 7, WorkerReadiness::Ready).await;
        }
        let recorded = record(&f, &first, 1).await;
        if !observe_first {
            observe(&f, f.identity.clone(), 2, 1, 7, WorkerReadiness::Ready).await;
        }
        let second = reserve(&f, TenantId::new()).await;
        let reopened = RedisGatewayActionStore::connect(
            f.base.config.clone().with_fleet_admission(f.config.clone()),
        )
        .await
        .expect("reopen");
        let duplicate = GatewaySessionWorkerReservationProof {
            reservation: second.reservation().expect("second").clone(),
            worker_reservation_nonce: LeaseId::new(),
            remaining_ttl_millis: 60_000,
            capacity_revision: 3,
            debit_sequence: 1,
        };
        assert!(matches!(
            reopened
                .record_session_reservation(&second, duplicate)
                .await,
            Err(GatewayActionCoordinationError::AdmissionConflict)
        ));
        assert_eq!(
            reopened
                .get_session_admission(second.request().key())
                .await
                .expect("unchanged second"),
            Some(second.clone())
        );
        assert_eq!(
            reopened
                .get_session_admission(recorded.request().key())
                .await
                .expect("unchanged first"),
            Some(recorded.clone())
        );
        let state_key = format!("{}:fleet:v1:state", f.base.prefix);
        let confirmed_field = format!(
            "confirmed:{}:{}:{}:1",
            f.identity.worker_id(),
            f.identity.worker_epoch(),
            f.identity.boot_id()
        );
        let mut conn = connection(&f).await;
        let retained: bool = redis::cmd("HEXISTS")
            .arg(&state_key)
            .arg(&confirmed_field)
            .query_async(&mut conn)
            .await
            .expect("binding retained");
        assert!(retained);
        reopened
            .release_session_reservation(
                &recorded,
                GatewaySessionCleanupProof::NoEffectCancelled {
                    reservation: recorded.reservation().expect("first").clone(),
                    capacity_revision: 4,
                },
            )
            .await
            .expect("exact cleanup retires live binding");
        let retained: bool = redis::cmd("HEXISTS")
            .arg(&state_key)
            .arg(&confirmed_field)
            .query_async(&mut conn)
            .await
            .expect("binding retired");
        assert!(
            !retained,
            "cleanup bounds debit identity metadata even after shadow ACK"
        );
        let _ = record(&f, &second, 2).await;
        delete_fixture(&f.base).await;
    }
}

#[tokio::test]
async fn redis_fleet_concurrent_duplicate_debit_proofs_have_one_winner() {
    let Some(f) = fixture("fleet-debit-race", config(1, 8, vec![])).await else {
        return;
    };
    observe(&f, f.identity.clone(), 1, 0, 8, WorkerReadiness::Ready).await;
    let first = reserve(&f, TenantId::new()).await;
    let second = reserve(&f, TenantId::new()).await;
    let proof = |row: &GatewaySessionAdmissionSnapshot| GatewaySessionWorkerReservationProof {
        reservation: row.reservation().expect("reservation").clone(),
        worker_reservation_nonce: LeaseId::new(),
        remaining_ttl_millis: 60_000,
        capacity_revision: 2,
        debit_sequence: 1,
    };
    let (left, right) = tokio::join!(
        f.store.record_session_reservation(&first, proof(&first)),
        f.store.record_session_reservation(&second, proof(&second)),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(GatewayActionCoordinationError::AdmissionConflict))
            || matches!(
                right,
                Err(GatewayActionCoordinationError::AdmissionConflict)
            )
    );
    delete_fixture(&f.base).await;
}
