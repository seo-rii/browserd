#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use browserd_actions::{ActionKind, CanonicalRequestHash, DispatchId};
use browserd_coordination::*;
use browserd_core::{
    ActionId, LeaseId, OperationId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use chrono::{DateTime, Utc};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};
use std::time::Duration;

const START: i64 = 1_800_000_000_000;
const TTL: Duration = Duration::from_secs(30);
fn instant(ms: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ms).unwrap()
}
fn units(n: u64) -> WorkerCapacity {
    WorkerCapacity::new(n, n, n, n, n, n)
}
struct Clock(AtomicI64);
impl Clock {
    fn set(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }
    fn current(&self) -> DateTime<Utc> {
        instant(self.0.load(Ordering::SeqCst))
    }
}
impl GatewayFleetAdmissionClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        self.current()
    }
}
struct Fixture {
    store: MemoryGatewayActionStore,
    database: MemoryCoordinationDatabase,
    config: GatewayFleetAdmissionConfig,
    clock: Arc<Clock>,
    worker: GatewayFleetWorkerIdentity,
    capacity: WorkerCapacity,
}
impl Fixture {
    fn new(capacity: u64, live: usize, rules: Vec<GatewayFleetTenantRule>) -> Self {
        let worker = GatewayFleetWorkerIdentity::new(
            WorkerId::new("fleet-memory-worker").unwrap(),
            1,
            LeaseId::new(),
        )
        .unwrap();
        let capacity = units(capacity);
        let inventory = GatewayFleetWorker::new(
            worker.worker_id().clone(),
            "unix:///configured-worker",
            "local",
            vec![[2; 32]],
            vec![[1; 32], [3; 32]],
            capacity,
            None,
        )
        .unwrap();
        let profiles = vec![
            GatewayFleetProfile::new(
                [1; 32],
                [2; 32],
                GatewaySessionIsolation::SharedContext,
                GatewaySessionWorkload::Light,
                units(1),
                1,
            )
            .unwrap(),
            GatewayFleetProfile::new(
                [3; 32],
                [2; 32],
                GatewaySessionIsolation::SharedContext,
                GatewaySessionWorkload::Heavy,
                units(1),
                7,
            )
            .unwrap(),
        ];
        let config = GatewayFleetAdmissionConfig::new(
            "local",
            vec![inventory],
            profiles,
            GatewayFleetTenantPolicy::new(1, units(1000), live, 1000, 1000).unwrap(),
            rules,
            GatewayFleetAdmissionLimits::new(1000, 1000, live, 128, units(1000)).unwrap(),
        )
        .unwrap();
        let database = MemoryCoordinationDatabase::default();
        let clock = Arc::new(Clock(AtomicI64::new(START)));
        let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default())
            .with_fleet_admission_clock(clock.clone())
            .with_fleet_admission_config(config.clone())
            .unwrap();
        Self {
            store,
            database,
            config,
            clock,
            worker,
            capacity,
        }
    }
    fn request(&self, tenant: TenantId) -> GatewaySessionAdmissionRequest {
        self.request_profile(tenant, [1; 32])
    }
    fn request_profile(
        &self,
        tenant: TenantId,
        profile: [u8; 32],
    ) -> GatewaySessionAdmissionRequest {
        GatewaySessionAdmissionRequest::new(
            GatewaySessionAdmissionKey::new(tenant, OperationId::new()),
            PrincipalId::new(),
            [7; 32],
            profile,
            [2; 32],
            GatewaySessionIsolation::SharedContext,
            units(1),
            instant(START),
            instant(START + 300_000),
        )
        .unwrap()
    }
    fn observation(
        &self,
        revision: u64,
        watermark: u64,
        free: u64,
        readiness: WorkerReadiness,
    ) -> GatewayFleetWorkerObservation {
        GatewayFleetWorkerObservation::new(
            self.worker.clone(),
            revision,
            watermark,
            self.capacity,
            units(free),
            readiness,
            [2; 32],
            None,
        )
        .unwrap()
    }
    async fn observe(&self) {
        self.store
            .observe_fleet_worker(
                self.observation(1, 0, self.capacity.components()[4], WorkerReadiness::Ready),
                Duration::from_secs(300),
            )
            .await
            .unwrap();
    }
    async fn reserve(&self, tenant: TenantId) -> GatewaySessionAdmissionSnapshot {
        self.store
            .enqueue_session_admission(self.request(tenant))
            .await
            .unwrap();
        self.store.reserve_next_session(TTL).await.unwrap().unwrap()
    }
    fn reservation_proof(
        &self,
        reserved: &GatewaySessionAdmissionSnapshot,
        seq: u64,
    ) -> GatewaySessionWorkerReservationProof {
        GatewaySessionWorkerReservationProof {
            reservation: reserved.reservation().unwrap().clone(),
            worker_reservation_nonce: LeaseId::new(),
            remaining_ttl_millis: 30_000,
            capacity_revision: 2,
            debit_sequence: seq,
        }
    }
    async fn arm(
        &self,
        reserved: &GatewaySessionAdmissionSnapshot,
    ) -> GatewaySessionAdmissionSnapshot {
        let confirmed = self
            .store
            .record_session_reservation(reserved, self.reservation_proof(reserved, 1))
            .await
            .unwrap();
        self.store
            .arm_session_create(&confirmed, &DispatchLeaseToken::new(), TTL)
            .await
            .unwrap()
    }
    fn ready_proof(
        &self,
        armed: &GatewaySessionAdmissionSnapshot,
    ) -> GatewaySessionWorkerReadyProof {
        let reservation = armed.reservation().unwrap().clone();
        GatewaySessionWorkerReadyProof {
            entry: DirectoryEntry::new(
                DirectoryKey::new(armed.request().key().tenant_id().clone(), SessionId::new()),
                reservation.directory_fence().clone(),
                "unix:///configured-worker",
            )
            .unwrap(),
            primary_page_id: PageId::new(),
            effective_isolation: GatewaySessionIsolation::SharedContext,
            remaining_ownership_ttl_millis: 60_000,
            capacity_revision: 3,
            debit_sequence: reservation.worker_debit_sequence().unwrap(),
            reservation,
            restored_checkpoint: None,
        }
    }
    async fn active(
        &self,
        tenant: TenantId,
    ) -> (
        GatewaySessionAdmissionSnapshot,
        GatewaySessionPlacementAuthority,
    ) {
        let reserved = self.reserve(tenant).await;
        let armed = self.arm(&reserved).await;
        let authority = self
            .store
            .commit_session_placement(&armed, self.ready_proof(&armed))
            .await
            .unwrap();
        let active = self
            .store
            .get_session_admission(armed.request().key())
            .await
            .unwrap()
            .unwrap();
        (active, authority)
    }
    fn claim(&self, authority: &GatewaySessionPlacementAuthority, key: &str) -> ClaimGatewayAction {
        ClaimGatewayAction::new(
            authority.entry().key().tenant_id().clone(),
            authority.entry().key().session_id().clone(),
            ActionId::new(),
            key,
            CanonicalRequestHash::new([9; 32]),
            ActionKind::Mutating,
            authority.authority().action_placement().unwrap(),
        )
        .unwrap()
        .with_submission_lease(
            GatewayActionSubmissionLease::new(
                uuid::Uuid::now_v7(),
                1,
                instant(START + 300_000),
                instant(START + 300_000),
            )
            .unwrap(),
        )
    }
}
fn created(outcome: GatewayActionClaimOutcome) -> GatewayActionSnapshot {
    match outcome {
        GatewayActionClaimOutcome::Created(value) => value,
        GatewayActionClaimOutcome::Existing(_) => panic!("expected a fresh action"),
    }
}

async fn observed_worker_loads(
    f: &Fixture,
    loads: &[(WorkerCapacity, WorkerCapacity)],
) -> (
    MemoryGatewayActionStore,
    MemoryCoordinationDatabase,
    GatewayFleetAdmissionConfig,
    Vec<GatewayFleetWorkerIdentity>,
) {
    let identities: Vec<_> = loads
        .iter()
        .enumerate()
        .map(|(index, _)| {
            GatewayFleetWorkerIdentity::new(
                WorkerId::new(format!("fleet-load-{index:03}")).unwrap(),
                1,
                LeaseId::new(),
            )
            .unwrap()
        })
        .collect();
    let inventory: Vec<_> = identities
        .iter()
        .zip(loads)
        .map(|(identity, (capacity, _))| {
            GatewayFleetWorker::new(
                identity.worker_id().clone(),
                "unix:///configured-worker",
                "local",
                vec![[2; 32]],
                vec![[1; 32], [3; 32]],
                *capacity,
                None,
            )
            .unwrap()
        })
        .collect();
    let mut wire = serde_json::to_value(&f.config).unwrap();
    wire["workers"] = serde_json::to_value(inventory).unwrap();
    let config: GatewayFleetAdmissionConfig = serde_json::from_value(wire).unwrap();
    let database = MemoryCoordinationDatabase::default();
    let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default())
        .with_fleet_admission_clock(f.clock.clone())
        .with_fleet_admission_config(config.clone())
        .unwrap();
    for (identity, (capacity, free)) in identities.iter().zip(loads) {
        store
            .observe_fleet_worker(
                GatewayFleetWorkerObservation::new(
                    identity.clone(),
                    1,
                    0,
                    *capacity,
                    *free,
                    WorkerReadiness::Ready,
                    [2; 32],
                    None,
                )
                .unwrap(),
                Duration::from_secs(300),
            )
            .await
            .unwrap();
    }
    (store, database, config, identities)
}

#[tokio::test]
async fn least_loaded_worker_uses_available_capacity_after_pending_shadow() {
    let f = Fixture::new(8, 8, vec![]);
    let (store, _, _, identities) =
        observed_worker_loads(&f, &[(units(8), units(1)), (units(8), units(8))]).await;
    let tenant = TenantId::new();
    store
        .enqueue_session_admission(f.request(tenant.clone()))
        .await
        .unwrap();
    let first = store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(first.reservation().unwrap().worker(), &identities[1]);

    // Worker 1 reports more raw free capacity, but its pending shadow creates an
    // exact 7/8 tie. The stored successor must then select worker 0.
    for (index, identity) in identities.iter().enumerate() {
        store
            .observe_fleet_worker(
                GatewayFleetWorkerObservation::new(
                    identity.clone(),
                    2,
                    0,
                    units(8),
                    units(if index == 0 { 7 } else { 8 }),
                    WorkerReadiness::Ready,
                    [2; 32],
                    None,
                )
                .unwrap(),
                Duration::from_secs(300),
            )
            .await
            .unwrap();
    }
    store
        .enqueue_session_admission(f.request(tenant))
        .await
        .unwrap();
    let second = store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(second.reservation().unwrap().worker(), &identities[0]);
}

#[tokio::test]
async fn least_loaded_worker_compares_normalized_bottleneck_instead_of_absolute_free() {
    let f = Fixture::new(128, 8, vec![]);
    let (store, _, _, identities) =
        observed_worker_loads(&f, &[(units(8), units(4)), (units(128), units(32))]).await;
    store
        .enqueue_session_admission(f.request(TenantId::new()))
        .await
        .unwrap();
    let row = store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(row.reservation().unwrap().worker(), &identities[0]);
}

#[tokio::test]
async fn equal_headroom_rotates_selected_successor_and_survives_adapter_restart() {
    let f = Fixture::new(8, 8, vec![]);
    let (store, database, config, identities) =
        observed_worker_loads(&f, &[(units(8), units(8)), (units(8), units(8))]).await;
    store
        .enqueue_session_admission(f.request(TenantId::new()))
        .await
        .unwrap();
    let first = store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(first.reservation().unwrap().worker(), &identities[0]);
    store
        .release_session_reservation(
            &first,
            GatewaySessionCleanupProof::NoEffectCancelled {
                reservation: first.reservation().unwrap().clone(),
                capacity_revision: 2,
            },
        )
        .await
        .unwrap();
    drop(store);
    let restarted = MemoryGatewayActionStore::attach(database, StoreConfig::default())
        .with_fleet_admission_clock(f.clock.clone())
        .with_fleet_admission_config(config)
        .unwrap();
    let second = restarted.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(second.reservation().unwrap().worker(), &identities[1]);
    restarted
        .release_session_reservation(
            &second,
            GatewaySessionCleanupProof::NoEffectCancelled {
                reservation: second.reservation().unwrap().clone(),
                capacity_revision: 2,
            },
        )
        .await
        .unwrap();
    let third = restarted.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(third.reservation().unwrap().worker(), &identities[0]);
}

#[tokio::test]
async fn immutable_configuration_and_request_roundtrip_reject_unknown_or_changed_authority() {
    let f = Fixture::new(8, 8, vec![]);
    let tenant = TenantId::new();
    let request = f.request(tenant);
    let queued = f
        .store
        .enqueue_session_admission(request.clone())
        .await
        .unwrap();
    assert_eq!(
        f.store
            .enqueue_session_admission(request.clone())
            .await
            .unwrap(),
        queued
    );
    let mut wire = serde_json::to_value(&request).unwrap();
    wire["untrusted"] = true.into();
    assert!(serde_json::from_value::<GatewaySessionAdmissionRequest>(wire).is_err());
    let mut wire = serde_json::to_value(&request).unwrap();
    wire["canonical_request_hash"] = serde_json::to_value([0u8; 32]).unwrap();
    assert!(serde_json::from_value::<GatewaySessionAdmissionRequest>(wire).is_err());
    let mut wire = serde_json::to_value(&request).unwrap();
    wire["profile_digest"] = serde_json::to_value([3u8; 32]).unwrap();
    let changed = serde_json::from_value(wire).unwrap();
    assert_eq!(
        f.store
            .enqueue_session_admission(changed)
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::AdmissionConflict
    );
    let encoded = serde_json::to_vec(&f.config).unwrap();
    let decoded: GatewayFleetAdmissionConfig = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.digest(), f.config.digest());
    let mut wire = serde_json::to_value(&f.config).unwrap();
    wire["workers"][0]["compatibility_digests"] =
        serde_json::to_value([[2u8; 32], [2u8; 32]]).unwrap();
    assert!(serde_json::from_value::<GatewayFleetAdmissionConfig>(wire).is_err());
}

#[tokio::test]
async fn weighted_drr_preserves_each_tenants_fifo_and_residual_quantum() {
    let mut tenants = [TenantId::new(), TenantId::new()];
    tenants.sort();
    let high = tenants[0].clone();
    let low = tenants[1].clone();
    let rule = GatewayFleetTenantRule::new(
        high.clone(),
        GatewayFleetTenantPolicy::new(4, units(1000), 128, 1000, 1000).unwrap(),
    )
    .unwrap();
    let f = Fixture::new(128, 128, vec![rule]);
    f.observe().await;
    let mut expected = [
        std::collections::VecDeque::new(),
        std::collections::VecDeque::new(),
    ];
    for _ in 0..32 {
        for (index, tenant) in tenants.iter().enumerate() {
            let row = f
                .store
                .enqueue_session_admission(f.request(tenant.clone()))
                .await
                .unwrap();
            expected[index].push_back(row.request().key().clone());
        }
    }
    let mut order = Vec::new();
    for _ in 0..100 {
        if let Some(row) = f.store.reserve_next_session(TTL).await.unwrap() {
            let index = usize::from(row.request().key().tenant_id() == &low);
            assert_eq!(
                Some(row.request().key()),
                expected[index].pop_front().as_ref()
            );
            order.push(index);
            if order.len() == 20 {
                break;
            }
        }
    }
    assert_eq!(order.len(), 20);
    assert_eq!(order.iter().filter(|&&index| index == 0).count(), 16);
    assert_eq!(order.iter().filter(|&&index| index == 1).count(), 4);
}

#[tokio::test]
async fn heavy_head_waits_for_credit_without_light_jobs_overtaking_its_fifo() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let tenant = TenantId::new();
    let heavy = f
        .store
        .enqueue_session_admission(f.request_profile(tenant.clone(), [3; 32]))
        .await
        .unwrap();
    let light = f
        .store
        .enqueue_session_admission(f.request(tenant))
        .await
        .unwrap();
    for _ in 0..6 {
        assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
    }
    let first = f.store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(first.request().key(), heavy.request().key());
    let mut second = None;
    for _ in 0..3 {
        if let Some(row) = f.store.reserve_next_session(TTL).await.unwrap() {
            second = Some(row);
            break;
        }
    }
    assert_eq!(second.unwrap().request().key(), light.request().key());
}

#[tokio::test]
async fn reserved_expires_once_but_armed_unknown_holds_quota_until_positive_cleanup() {
    let f = Fixture::new(4, 1, vec![]);
    f.observe().await;
    let tenant = TenantId::new();
    let first = f.reserve(tenant.clone()).await;
    f.clock.set(START + 30_000);
    let expired = f
        .store
        .get_session_admission(first.request().key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired.state(), GatewaySessionAdmissionState::Expired);
    assert_eq!(expired.reservation(), first.reservation());
    assert_eq!(
        f.store
            .get_session_admission(first.request().key())
            .await
            .unwrap()
            .unwrap(),
        expired
    );
    let second = f.reserve(tenant.clone()).await;
    let armed = f.arm(&second).await;
    f.clock.set(START + 120_000);
    f.store
        .enqueue_session_admission(f.request(tenant))
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
    assert_eq!(
        f.store
            .get_session_admission(armed.request().key())
            .await
            .unwrap()
            .unwrap()
            .state(),
        GatewaySessionAdmissionState::CommitArmed
    );
    let proof = GatewaySessionCleanupProof::NoEffectCancelled {
        reservation: armed.reservation().unwrap().clone(),
        capacity_revision: 4,
    };
    let released = f
        .store
        .release_session_reservation(&armed, proof.clone())
        .await
        .unwrap();
    assert_eq!(released.state(), GatewaySessionAdmissionState::Queued);
    assert_eq!(
        f.store
            .release_session_reservation(&armed, proof)
            .await
            .unwrap(),
        released
    );
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_some());
}

#[tokio::test]
async fn proof_mismatch_and_insufficient_ownership_ttl_preserve_armed_charge() {
    let f = Fixture::new(2, 1, vec![]);
    f.observe().await;
    let reserved = f.reserve(TenantId::new()).await;
    let armed = f.arm(&reserved).await;
    let mut proof = f.ready_proof(&armed);
    proof.remaining_ownership_ttl_millis = 29_999;
    assert_eq!(
        f.store
            .commit_session_placement(&armed, proof)
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::AdmissionConflict
    );
    let mut proof = f.ready_proof(&armed);
    proof.debit_sequence += 1;
    assert!(
        f.store
            .commit_session_placement(&armed, proof)
            .await
            .is_err()
    );
    assert_eq!(
        f.store
            .get_session_admission(armed.request().key())
            .await
            .unwrap()
            .unwrap(),
        armed
    );
    f.store
        .enqueue_session_admission(f.request(TenantId::new()))
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
}

#[tokio::test]
async fn capacity_observation_before_reservation_proof_retires_shadow_without_overcredit() {
    let f = Fixture::new(2, 2, vec![]);
    f.observe().await;
    let tenant = TenantId::new();
    let first = f.reserve(tenant.clone()).await;
    f.store
        .observe_fleet_worker(
            f.observation(2, 1, 1, WorkerReadiness::Ready),
            Duration::from_secs(300),
        )
        .await
        .unwrap();
    let confirmed = f
        .store
        .record_session_reservation(&first, f.reservation_proof(&first, 1))
        .await
        .unwrap();
    f.store
        .enqueue_session_admission(f.request(tenant.clone()))
        .await
        .unwrap();
    let second = f.store.reserve_next_session(TTL).await.unwrap().unwrap();
    f.store
        .release_session_reservation(
            &confirmed,
            GatewaySessionCleanupProof::NoEffectCancelled {
                reservation: confirmed.reservation().unwrap().clone(),
                capacity_revision: 3,
            },
        )
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
    assert_eq!(
        f.store
            .get_session_admission(second.request().key())
            .await
            .unwrap()
            .unwrap(),
        second
    );
}

#[tokio::test]
async fn reservation_proof_before_observation_keeps_unacknowledged_debit() {
    let f = Fixture::new(1, 4, vec![]);
    f.observe().await;
    let tenant = TenantId::new();
    let first = f.reserve(tenant.clone()).await;
    f.store
        .record_session_reservation(&first, f.reservation_proof(&first, 1))
        .await
        .unwrap();
    f.store
        .enqueue_session_admission(f.request(tenant))
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
    f.store
        .observe_fleet_worker(
            f.observation(2, 1, 0, WorkerReadiness::Ready),
            Duration::from_secs(300),
        )
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
}

#[tokio::test]
async fn acknowledged_debit_sequence_cannot_be_bound_to_two_live_reservations() {
    let f = Fixture::new(4, 4, vec![]);
    f.observe().await;
    let first = f.reserve(TenantId::new()).await;
    f.store
        .observe_fleet_worker(
            f.observation(2, 1, 3, WorkerReadiness::Ready),
            Duration::from_secs(300),
        )
        .await
        .unwrap();
    f.store
        .record_session_reservation(&first, f.reservation_proof(&first, 1))
        .await
        .unwrap();
    let second = f.reserve(TenantId::new()).await;
    assert_eq!(
        f.store
            .record_session_reservation(&second, f.reservation_proof(&second, 1))
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::AdmissionConflict
    );
    assert_eq!(
        f.store
            .get_session_admission(second.request().key())
            .await
            .unwrap()
            .unwrap(),
        second
    );
}

#[tokio::test]
async fn stale_boot_cannot_arm_or_publish_and_exposed_old_boot_obligations_still_hold_quota() {
    let f = Fixture::new(8, 1, vec![]);
    f.observe().await;
    let reserved = f.reserve(TenantId::new()).await;
    let armed = f.arm(&reserved).await;
    let next =
        GatewayFleetWorkerIdentity::new(f.worker.worker_id().clone(), 2, LeaseId::new()).unwrap();
    let observation = GatewayFleetWorkerObservation::new(
        next,
        1,
        0,
        f.capacity,
        f.capacity,
        WorkerReadiness::Ready,
        [2; 32],
        None,
    )
    .unwrap();
    f.store
        .observe_fleet_worker(observation, Duration::from_secs(300))
        .await
        .unwrap();
    assert_eq!(
        f.store
            .commit_session_placement(&armed, f.ready_proof(&armed))
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::SessionAuthorityUnavailable
    );
    f.store
        .enqueue_session_admission(f.request(TenantId::new()))
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
    f.store
        .release_session_reservation(
            &armed,
            GatewaySessionCleanupProof::NoEffectCancelled {
                reservation: armed.reservation().unwrap().clone(),
                capacity_revision: 3,
            },
        )
        .await
        .unwrap();
    let next = f.store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(next.reservation().unwrap().worker().worker_epoch(), 2);
}

#[tokio::test]
async fn stale_capacity_revision_and_same_epoch_drain_reversal_are_rejected() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    f.store
        .observe_fleet_worker(
            f.observation(2, 0, 8, WorkerReadiness::Draining),
            Duration::from_secs(300),
        )
        .await
        .unwrap();
    assert_eq!(
        f.store
            .observe_fleet_worker(
                f.observation(1, 0, 8, WorkerReadiness::Ready),
                Duration::from_secs(300)
            )
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::InvalidFleetObservation
    );
    assert_eq!(
        f.store
            .observe_fleet_worker(
                f.observation(3, 0, 8, WorkerReadiness::Ready),
                Duration::from_secs(300)
            )
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::InvalidFleetObservation
    );
    f.store
        .enqueue_session_admission(f.request(TenantId::new()))
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
}

#[tokio::test]
async fn ready_commit_retry_and_projection_recovery_preserve_restored_checkpoint() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let reserved = f.reserve(TenantId::new()).await;
    let armed = f.arm(&reserved).await;
    let mut proof = f.ready_proof(&armed);
    proof.restored_checkpoint = Some(
        GatewaySessionRestoredCheckpoint::new(uuid::Uuid::new_v4().to_string(), SessionId::new())
            .unwrap(),
    );
    let authority = f
        .store
        .commit_session_placement(&armed, proof.clone())
        .await
        .unwrap();
    assert_eq!(
        f.store
            .commit_session_placement(&armed, proof.clone())
            .await
            .unwrap(),
        authority
    );
    let restarted = MemoryGatewayActionStore::attach(f.database.clone(), StoreConfig::default())
        .with_fleet_admission_clock(f.clock.clone())
        .with_fleet_admission_config(f.config.clone())
        .unwrap();
    let page = restarted
        .scan_session_admissions(GatewaySessionAdmissionCursor::default(), 1)
        .await
        .unwrap();
    assert_eq!(page.examined(), 1);
    assert_eq!(
        page.admissions()[0]
            .ready_proof()
            .unwrap()
            .restored_checkpoint,
        proof.restored_checkpoint
    );
    let active = page.admissions()[0].clone();
    assert!(active.pending_create_projection());
    let projected = restarted
        .ack_session_create_projection(&active)
        .await
        .unwrap();
    assert!(!projected.pending_create_projection());
    assert_eq!(
        restarted
            .ack_session_create_projection(&active)
            .await
            .unwrap(),
        projected
    );
}

#[tokio::test]
async fn managed_namespace_rejects_legacy_admission_even_through_unconfigured_adapter() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let (_, authority) = f.active(TenantId::new()).await;
    let legacy = MemoryGatewayActionStore::attach(f.database.clone(), StoreConfig::default());
    assert_eq!(
        legacy
            .claim_action(f.claim(&authority, "bypass"), f.clock.current())
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::ManagedActionAdmissionRequired
    );
    let claim = f.claim(&authority, "managed");
    let action = created(
        f.store
            .claim_action_authorized(claim, authority.authority(), f.clock.current())
            .await
            .unwrap(),
    );
    assert_eq!(
        legacy
            .arm_dispatch_owned(
                action.tenant_id(),
                action.session_id(),
                action.action_id(),
                action.revision(),
                action.placement(),
                DispatchId::new(),
                action.submission_lease().unwrap(),
                f.clock.current()
            )
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::ManagedActionAdmissionRequired
    );
    let arbitrary = ClaimGatewayAction::new(
        TenantId::new(),
        SessionId::new(),
        ActionId::new(),
        "unbound",
        CanonicalRequestHash::new([5; 32]),
        ActionKind::ReadOnly,
        authority.authority().action_placement().unwrap(),
    )
    .unwrap();
    assert_eq!(
        legacy
            .claim_action(arbitrary, f.clock.current())
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::ManagedActionAdmissionRequired
    );
}

#[tokio::test]
async fn renewal_changes_only_lease_and_anchors_before_reply_while_historical_action_stays_exact() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let (_, authority) = f.active(TenantId::new()).await;
    let action = created(
        f.store
            .claim_action_authorized(
                f.claim(&authority, "original"),
                authority.authority(),
                f.clock.current(),
            )
            .await
            .unwrap(),
    );
    f.clock.set(START + 10_000);
    let nonce = LeaseId::new();
    let intent = f
        .store
        .begin_session_renewal(&authority, nonce.clone(), TTL)
        .await
        .unwrap();
    f.clock.set(START + 15_000);
    let proof = GatewaySessionWorkerRenewalProof {
        authority: authority.authority().clone(),
        worker: f.worker.clone(),
        renewal_nonce: nonce.clone(),
        granted_ttl_millis: 60_000,
    };
    let renewed = f
        .store
        .finish_session_renewal(&intent, proof.clone())
        .await
        .unwrap();
    assert_eq!(renewed.authority(), authority.authority());
    assert_eq!(renewed.expires_at_millis(), (START + 40_000) as u64);
    assert_eq!(renewed.lease_revision(), authority.lease_revision() + 1);
    f.clock.set(START + 20_000);
    assert_eq!(
        f.store
            .finish_session_renewal(&intent, proof)
            .await
            .unwrap(),
        renewed
    );
    assert_eq!(
        f.store
            .begin_session_renewal(&authority, nonce, TTL)
            .await
            .unwrap(),
        intent
    );
    assert_eq!(
        f.store
            .get_effective_action(action.tenant_id(), action.session_id(), action.action_id())
            .await
            .unwrap()
            .unwrap(),
        action
    );
    f.store
        .arm_dispatch_owned_authorized(
            action.tenant_id(),
            action.session_id(),
            action.action_id(),
            action.revision(),
            action.placement(),
            DispatchId::new(),
            action.submission_lease().unwrap(),
            authority.authority(),
            f.clock.current(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn provider_time_floor_prevents_expired_ready_or_pending_renewal_from_reviving() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let (_, authority) = f.active(TenantId::new()).await;
    let intent = f
        .store
        .begin_session_renewal(&authority, LeaseId::new(), TTL)
        .await
        .unwrap();
    f.clock.set(START + 31_000);
    assert_eq!(
        f.store
            .validate_session_authority(authority.authority())
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::SessionAuthorityUnavailable
    );
    f.clock.set(START - 1000);
    assert_eq!(
        f.store
            .validate_session_authority(authority.authority())
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::SessionAuthorityUnavailable
    );
    let proof = GatewaySessionWorkerRenewalProof {
        authority: authority.authority().clone(),
        worker: f.worker.clone(),
        renewal_nonce: intent.renewal_nonce().clone(),
        granted_ttl_millis: 60_000,
    };
    assert_eq!(
        f.store
            .finish_session_renewal(&intent, proof)
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::SessionAuthorityUnavailable
    );
    assert_eq!(
        f.store
            .resolve_session_placement(authority.entry().key())
            .await
            .unwrap()
            .unwrap()
            .expires_at_millis(),
        authority.expires_at_millis()
    );
}

#[tokio::test]
async fn caller_dates_do_not_advance_provider_floor_or_extend_placement() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let (_, authority) = f.active(TenantId::new()).await;
    let request = GatewaySessionAdmissionRequest::new(
        GatewaySessionAdmissionKey::new(TenantId::new(), OperationId::new()),
        PrincipalId::new(),
        [7; 32],
        [1; 32],
        [2; 32],
        GatewaySessionIsolation::SharedContext,
        units(1),
        instant(START + 86_400_000),
        instant(START + 86_700_000),
    )
    .unwrap();
    f.store.enqueue_session_admission(request).await.unwrap();
    f.store
        .validate_session_authority(authority.authority())
        .await
        .unwrap();
    f.store
        .claim_action_authorized(
            f.claim(&authority, "future-metadata"),
            authority.authority(),
            instant(START + 100_000),
        )
        .await
        .unwrap();
    f.store
        .validate_session_authority(authority.authority())
        .await
        .unwrap();
    assert_eq!(
        f.store
            .resolve_session_placement(authority.entry().key())
            .await
            .unwrap()
            .unwrap(),
        authority
    );
}

#[tokio::test]
async fn close_blocks_fresh_claim_and_arm_but_keeps_idempotent_history_and_cleanup() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let (active, authority) = f.active(TenantId::new()).await;
    let claim = f.claim(&authority, "existing");
    let action = created(
        f.store
            .claim_action_authorized(claim.clone(), authority.authority(), f.clock.current())
            .await
            .unwrap(),
    );
    let closing = f.store.begin_session_close(&authority).await.unwrap();
    assert_eq!(closing.status(), GatewaySessionPlacementStatus::Closing);
    assert!(matches!(
        f.store
            .claim_action_authorized(claim, authority.authority(), f.clock.current())
            .await
            .unwrap(),
        GatewayActionClaimOutcome::Existing(_)
    ));
    assert_eq!(
        f.store
            .claim_action_authorized(
                f.claim(&authority, "new"),
                authority.authority(),
                f.clock.current()
            )
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::SessionAuthorityUnavailable
    );
    assert_eq!(
        f.store
            .arm_dispatch_owned_authorized(
                action.tenant_id(),
                action.session_id(),
                action.action_id(),
                action.revision(),
                action.placement(),
                DispatchId::new(),
                action.submission_lease().unwrap(),
                authority.authority(),
                f.clock.current()
            )
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::SessionAuthorityUnavailable
    );
    let current = f
        .store
        .get_session_admission(active.request().key())
        .await
        .unwrap()
        .unwrap();
    let proof = GatewaySessionCleanupProof::ContextDisposed {
        reservation: current.reservation().unwrap().clone(),
        entry: authority.entry().clone(),
        capacity_revision: 4,
    };
    let released = f
        .store
        .release_session_reservation(&current, proof.clone())
        .await
        .unwrap();
    assert_eq!(released.state(), GatewaySessionAdmissionState::Released);
    assert_eq!(
        f.store
            .release_session_reservation(&current, proof)
            .await
            .unwrap(),
        released
    );
    assert_eq!(
        f.store
            .get_effective_action(action.tenant_id(), action.session_id(), action.action_id())
            .await
            .unwrap()
            .unwrap(),
        action
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_scheduler_and_claim_close_have_one_atomic_authority() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let request = f.request(TenantId::new());
    f.store.enqueue_session_admission(request).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = f.store.clone();
        tasks.push(tokio::spawn(async move {
            store.reserve_next_session(TTL).await.unwrap()
        }));
    }
    let mut selected = Vec::new();
    for task in tasks {
        if let Some(row) = task.await.unwrap() {
            selected.push(row);
        }
    }
    assert_eq!(selected.len(), 1);
    let armed = f.arm(&selected[0]).await;
    let authority = f
        .store
        .commit_session_placement(&armed, f.ready_proof(&armed))
        .await
        .unwrap();
    let claim = f.claim(&authority, "racing");
    let close_store = f.store.clone();
    let close_authority = authority.clone();
    let close =
        tokio::spawn(async move { close_store.begin_session_close(&close_authority).await });
    let result = f
        .store
        .claim_action_authorized(claim, authority.authority(), f.clock.current())
        .await;
    close.await.unwrap().unwrap();
    match result {
        Ok(GatewayActionClaimOutcome::Created(action)) => {
            assert!(
                f.store
                    .get_effective_action(
                        action.tenant_id(),
                        action.session_id(),
                        action.action_id()
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        Err(GatewayActionCoordinationError::SessionAuthorityUnavailable) => {}
        other => panic!("unexpected atomic race result: {other:?}"),
    }
}

#[tokio::test]
async fn retained_catalog_scan_bounds_examined_rows_and_advances_past_filtered_released_records() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let (active, authority) = f.active(TenantId::new()).await;
    let projected = f
        .store
        .ack_session_create_projection(&active)
        .await
        .unwrap();
    f.store
        .release_session_reservation(
            &projected,
            GatewaySessionCleanupProof::ContextDisposed {
                reservation: projected.reservation().unwrap().clone(),
                entry: authority.entry().clone(),
                capacity_revision: 4,
            },
        )
        .await
        .unwrap();
    let queued = f
        .store
        .enqueue_session_admission(f.request(TenantId::new()))
        .await
        .unwrap();
    let mut cursor = GatewaySessionAdmissionCursor::default();
    let mut seen = Vec::new();
    let mut examined = 0;
    for _ in 0..4 {
        let page = f.store.scan_session_admissions(cursor, 1).await.unwrap();
        assert!(page.examined() <= 1);
        examined += page.examined();
        seen.extend_from_slice(page.admissions());
        cursor = page.next_cursor().clone();
        if page.is_complete() {
            break;
        }
    }
    assert_eq!(examined, 2);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].request().key(), queued.request().key());
    assert_eq!(
        f.store
            .scan_session_admissions(GatewaySessionAdmissionCursor::default(), 65)
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::InvalidSessionAdmission
    );
}

#[tokio::test]
async fn post_projection_active_and_closing_are_visible_to_lifecycle_maintenance_after_restart() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let (active, authority) = f.active(TenantId::new()).await;
    let projected = f
        .store
        .ack_session_create_projection(&active)
        .await
        .unwrap();
    assert!(!projected.pending_create_projection());
    let restarted = MemoryGatewayActionStore::attach(f.database.clone(), StoreConfig::default())
        .with_fleet_admission_clock(f.clock.clone())
        .with_fleet_admission_config(f.config.clone())
        .unwrap();
    let page = restarted
        .scan_session_admissions(GatewaySessionAdmissionCursor::default(), 1)
        .await
        .unwrap();
    assert_eq!(page.examined(), 1);
    assert_eq!(page.admissions(), std::slice::from_ref(&projected));
    assert_eq!(projected.state(), GatewaySessionAdmissionState::Active);

    restarted.begin_session_close(&authority).await.unwrap();
    let closing = restarted
        .get_session_admission(projected.request().key())
        .await
        .unwrap()
        .unwrap();
    assert!(!closing.pending_create_projection());
    assert_eq!(closing.state(), GatewaySessionAdmissionState::Closing);
    let page = restarted
        .scan_session_admissions(GatewaySessionAdmissionCursor::default(), 1)
        .await
        .unwrap();
    assert_eq!(page.examined(), 1);
    assert_eq!(page.admissions(), std::slice::from_ref(&closing));
}

#[test]
fn blocking_actor_restart_keeps_same_database_authority_and_managed_guard() {
    let f = Fixture::new(8, 8, vec![]);
    let client = GatewayActionBlockingClient::spawn(
        Arc::new(f.store.clone()),
        CoordinationActorConfig::default(),
    )
    .unwrap();
    client
        .observe_fleet_worker(
            f.observation(1, 0, 8, WorkerReadiness::Ready),
            Duration::from_secs(300),
        )
        .unwrap();
    let queued = client
        .enqueue_session_admission(f.request(TenantId::new()))
        .unwrap();
    let reserved = client.reserve_next_session(TTL).unwrap().unwrap();
    let recorded = client
        .record_session_reservation(&reserved, f.reservation_proof(&reserved, 1))
        .unwrap();
    let armed = client
        .arm_session_create(&recorded, &DispatchLeaseToken::new(), TTL)
        .unwrap();
    let authority = client
        .commit_session_placement(&armed, f.ready_proof(&armed))
        .unwrap();
    drop(client);
    let store = MemoryGatewayActionStore::attach(f.database, StoreConfig::default())
        .with_fleet_admission_clock(f.clock)
        .with_fleet_admission_config(f.config)
        .unwrap();
    let restarted =
        GatewayActionBlockingClient::spawn(Arc::new(store), CoordinationActorConfig::default())
            .unwrap();
    assert_eq!(
        restarted
            .get_session_admission(queued.request().key())
            .unwrap()
            .unwrap()
            .state(),
        GatewaySessionAdmissionState::Active
    );
    assert_eq!(
        restarted
            .resolve_session_placement(authority.entry().key())
            .unwrap()
            .unwrap(),
        authority
    );
    restarted
        .validate_session_authority(authority.authority())
        .unwrap();
}

#[tokio::test]
async fn expired_activation_has_exact_rejection_and_late_created_context_cleanup() {
    let f = Fixture::new(8, 1, vec![]);
    f.observe().await;
    let reserved = f.reserve(TenantId::new()).await;
    let armed = f.arm(&reserved).await;
    let proof = f.ready_proof(&armed);
    f.clock.set(START + 31_000);
    assert_eq!(
        f.store
            .commit_session_placement(&armed, proof.clone())
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::SessionActivationExpired
    );
    assert!(
        f.store
            .resolve_session_placement(proof.entry.key())
            .await
            .unwrap()
            .is_none()
    );
    let released = f
        .store
        .release_session_reservation(
            &armed,
            GatewaySessionCleanupProof::ContextDisposed {
                reservation: armed.reservation().unwrap().clone(),
                entry: proof.entry.clone(),
                capacity_revision: 4,
            },
        )
        .await
        .unwrap();
    assert_eq!(released.state(), GatewaySessionAdmissionState::Released);
    f.store
        .enqueue_session_admission(f.request(TenantId::new()))
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_some());
}

#[tokio::test]
async fn per_tenant_quota_does_not_block_another_tenants_head() {
    let mut tenants = [TenantId::new(), TenantId::new()];
    tenants.sort();
    let rule = GatewayFleetTenantRule::new(
        tenants[0].clone(),
        GatewayFleetTenantPolicy::new(4, units(1), 1, 1000, 1000).unwrap(),
    )
    .unwrap();
    let f = Fixture::new(8, 2, vec![rule]);
    f.observe().await;
    for _ in 0..2 {
        f.store
            .enqueue_session_admission(f.request(tenants[0].clone()))
            .await
            .unwrap();
    }
    f.store
        .enqueue_session_admission(f.request(tenants[1].clone()))
        .await
        .unwrap();
    let first = f.store.reserve_next_session(TTL).await.unwrap().unwrap();
    let second = f.store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(first.request().key().tenant_id(), &tenants[0]);
    assert_eq!(second.request().key().tenant_id(), &tenants[1]);
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
}

#[tokio::test]
async fn bounded_tenant_head_pass_progresses_to_the_sixty_fifth_tenant() {
    let f = Fixture::new(8, 8, vec![]);
    f.observe().await;
    let mut tenants: Vec<_> = (0..65).map(|_| TenantId::new()).collect();
    tenants.sort();
    for tenant in &tenants[..64] {
        f.store
            .enqueue_session_admission(f.request_profile(tenant.clone(), [3; 32]))
            .await
            .unwrap();
    }
    let expected = f
        .store
        .enqueue_session_admission(f.request(tenants[64].clone()))
        .await
        .unwrap();
    assert!(f.store.reserve_next_session(TTL).await.unwrap().is_none());
    let row = f.store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(row.request().key(), expected.request().key());
}

#[tokio::test]
async fn bounded_worker_window_rotates_to_a_ready_candidate_after_the_first_thirty_two() {
    let f = Fixture::new(8, 8, vec![]);
    let mut wire = serde_json::to_value(&f.config).unwrap();
    let original = wire["workers"][0].clone();
    let mut workers = Vec::new();
    for index in 0..33 {
        let mut worker = original.clone();
        worker["worker_id"] =
            serde_json::to_value(WorkerId::new(format!("fleet-window-{index:03}")).unwrap())
                .unwrap();
        workers.push(worker);
    }
    wire["workers"] = workers.into();
    let config: GatewayFleetAdmissionConfig = serde_json::from_value(wire).unwrap();
    let store = MemoryGatewayActionStore::default()
        .with_fleet_admission_clock(f.clock.clone())
        .with_fleet_admission_config(config)
        .unwrap();
    let identity = GatewayFleetWorkerIdentity::new(
        WorkerId::new("fleet-window-032").unwrap(),
        1,
        LeaseId::new(),
    )
    .unwrap();
    store
        .observe_fleet_worker(
            GatewayFleetWorkerObservation::new(
                identity.clone(),
                1,
                0,
                units(8),
                units(8),
                WorkerReadiness::Ready,
                [2; 32],
                None,
            )
            .unwrap(),
            Duration::from_secs(300),
        )
        .await
        .unwrap();
    store
        .enqueue_session_admission(f.request(TenantId::new()))
        .await
        .unwrap();
    assert!(store.reserve_next_session(TTL).await.unwrap().is_none());
    let row = store.reserve_next_session(TTL).await.unwrap().unwrap();
    assert_eq!(row.reservation().unwrap().worker(), &identity);
}

#[tokio::test]
async fn dedicated_worker_requires_inventory_assignment_and_actual_matching_observation() {
    let f = Fixture::new(8, 8, vec![]);
    let tenant = TenantId::new();
    let assignment = GatewayFleetExclusiveTenant::new(tenant.clone(), [6; 32]).unwrap();
    let mut wire = serde_json::to_value(&f.config).unwrap();
    wire["profiles"][0]["isolation"] = "dedicated_worker".into();
    let no_assignment: GatewayFleetAdmissionConfig = serde_json::from_value(wire.clone()).unwrap();
    let unassigned = MemoryGatewayActionStore::default()
        .with_fleet_admission_clock(f.clock.clone())
        .with_fleet_admission_config(no_assignment)
        .unwrap();
    unassigned
        .observe_fleet_worker(f.observation(1, 0, 8, WorkerReadiness::Ready), TTL)
        .await
        .unwrap();
    let mut request = serde_json::to_value(f.request(tenant.clone())).unwrap();
    request["isolation"] = "dedicated_worker".into();
    let request: GatewaySessionAdmissionRequest = serde_json::from_value(request).unwrap();
    unassigned
        .enqueue_session_admission(request.clone())
        .await
        .unwrap();
    assert!(
        unassigned
            .reserve_next_session(TTL)
            .await
            .unwrap()
            .is_none()
    );
    wire["workers"][0]["exclusive_tenant"] = serde_json::to_value(&assignment).unwrap();
    let assigned_config: GatewayFleetAdmissionConfig = serde_json::from_value(wire).unwrap();
    let assigned = MemoryGatewayActionStore::default()
        .with_fleet_admission_clock(f.clock.clone())
        .with_fleet_admission_config(assigned_config)
        .unwrap();
    assert_eq!(
        assigned
            .observe_fleet_worker(f.observation(1, 0, 8, WorkerReadiness::Ready), TTL)
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::InvalidFleetObservation
    );
    let observation = GatewayFleetWorkerObservation::new(
        f.worker.clone(),
        1,
        0,
        f.capacity,
        f.capacity,
        WorkerReadiness::Ready,
        [2; 32],
        Some(assignment),
    )
    .unwrap();
    assigned
        .observe_fleet_worker(observation, TTL)
        .await
        .unwrap();
    assigned.enqueue_session_admission(request).await.unwrap();
    let reserved = assigned.reserve_next_session(TTL).await.unwrap().unwrap();
    let recorded = assigned
        .record_session_reservation(&reserved, f.reservation_proof(&reserved, 1))
        .await
        .unwrap();
    let armed = assigned
        .arm_session_create(&recorded, &DispatchLeaseToken::new(), TTL)
        .await
        .unwrap();
    let mut proof = f.ready_proof(&armed);
    proof.effective_isolation = GatewaySessionIsolation::DedicatedProcess;
    assert_eq!(
        assigned
            .commit_session_placement(&armed, proof)
            .await
            .unwrap_err(),
        GatewayActionCoordinationError::AdmissionConflict
    );
    let mut proof = f.ready_proof(&armed);
    proof.effective_isolation = GatewaySessionIsolation::DedicatedWorker;
    let authority = assigned
        .commit_session_placement(&armed, proof)
        .await
        .unwrap();
    assigned
        .validate_session_authority(authority.authority())
        .await
        .unwrap();
}

struct BlockingClock {
    entered: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    once: std::sync::atomic::AtomicBool,
}
impl GatewayFleetAdmissionClock for BlockingClock {
    fn now(&self) -> DateTime<Utc> {
        if !self.once.swap(true, Ordering::SeqCst) {
            let (lock, signal) = &*self.entered;
            *lock.lock().unwrap() = true;
            signal.notify_all();
            let (lock, signal) = &*self.release;
            let guard = lock.lock().unwrap();
            let (held, timeout) = signal
                .wait_timeout_while(guard, Duration::from_secs(2), |ready| !*ready)
                .unwrap();
            assert!(!timeout.timed_out(), "owned operation was never released");
            drop(held);
        }
        instant(START)
    }
}
#[test]
fn actor_mutation_timeout_and_client_disconnect_do_not_drop_an_admitted_job() {
    let f = Fixture::new(8, 8, vec![]);
    let entered = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let clock = Arc::new(BlockingClock {
        entered: entered.clone(),
        release: release.clone(),
        once: std::sync::atomic::AtomicBool::new(false),
    });
    let store = MemoryGatewayActionStore::attach(f.database.clone(), StoreConfig::default())
        .with_fleet_admission_clock(clock)
        .with_fleet_admission_config(f.config.clone())
        .unwrap();
    let config =
        CoordinationActorConfig::new(2, 1, Duration::from_millis(30), Duration::from_millis(30))
            .unwrap();
    let actor = GatewayActionBlockingClient::spawn(Arc::new(store.clone()), config).unwrap();
    let request = f.request(TenantId::new());
    let key = request.key().clone();
    let submit = std::thread::spawn(move || {
        let result = actor.enqueue_session_admission(request);
        drop(actor);
        result
    });
    let (lock, signal) = &*entered;
    let guard = lock.lock().unwrap();
    let (held, timeout) = signal
        .wait_timeout_while(guard, Duration::from_secs(1), |ready| !*ready)
        .unwrap();
    assert!(!timeout.timed_out());
    drop(held);
    assert_eq!(
        submit.join().unwrap().unwrap_err(),
        GatewayActionCoordinationError::ActorMutationTimedOut
    );
    let (lock, signal) = &*release;
    *lock.lock().unwrap() = true;
    signal.notify_all();
    let restarted =
        GatewayActionBlockingClient::spawn(Arc::new(store), CoordinationActorConfig::default())
            .unwrap();
    let observed = restarted.get_session_admission(&key).unwrap().unwrap();
    assert_eq!(observed.state(), GatewaySessionAdmissionState::Queued);
    assert_eq!(observed.revision(), 1);
}
