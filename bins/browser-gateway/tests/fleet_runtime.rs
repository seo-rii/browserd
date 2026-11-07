#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use browser_gateway::{
    GatewayFleetInventory, GatewayFleetPeer, GatewayWorkerClient, GatewayWorkerPending,
    GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_api::{ApiRequest, ApiResponse, ApiService, DurableApiRouter, decode_session_create};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::*;
use browserd_core::{
    CreateOperationState, LeaseId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_worker::*;
use jsonwebtoken::Algorithm;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[path = "support/runtime_safety.rs"]
mod runtime_safety;

const BODY: &str = r#"{"isolation":"dedicated_process","workload_class_hint":"interactive","viewport":{"width":1280,"height":720,"device_scale_factor":1},"locale":"ko-KR","timezone":"Asia/Seoul","user_agent":null,"network_policy_id":"public-web-default","network_class":"public","checkpoint_ref":null,"dialog_policy":"auto_dismiss","feature_profile":"standard","ttl_seconds":1800,"idle_timeout_seconds":600,"metadata":{}}"#;
fn budget(n: u64) -> WorkerCapacity {
    WorkerCapacity::new(100 * n, 100 * n, n, 100 * n, n, 8 * n)
}
fn vector(n: u64) -> FleetResourceVector {
    FleetResourceVector {
        memory_bytes: 100 * n,
        cpu_millis: 100 * n,
        pids: n,
        disk_bytes: 100 * n,
        contexts: n,
        targets: 8 * n,
    }
}
struct Never;
impl GatewayWorkerPending for Never {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        panic!("no action replay")
    }
}
struct Peer {
    id: WorkerId,
    boot: LeaseId,
    epoch: AtomicU64,
    ready: AtomicBool,
    capacity_revision: AtomicU64,
    free: u64,
    profiles: BTreeMap<[u8; 32], (WorkerIsolationProfile, FleetResourceVector)>,
    rows: Mutex<BTreeMap<LeaseId, WorkerReservationReceipt>>,
    commits: AtomicUsize,
    reads: AtomicUsize,
    capacity_reads: AtomicUsize,
    lost_commit: AtomicBool,
    bad_nonce: AtomicBool,
}
impl Peer {
    fn new(id: &str, free: u64) -> Self {
        Self::with_profiles(
            id,
            free,
            BTreeMap::from([(
                [7; 32],
                (WorkerIsolationProfile::DedicatedProcess, vector(1)),
            )]),
        )
    }
    fn with_profiles(
        id: &str,
        free: u64,
        profiles: BTreeMap<[u8; 32], (WorkerIsolationProfile, FleetResourceVector)>,
    ) -> Self {
        Self {
            id: WorkerId::new(id).unwrap(),
            boot: LeaseId::new(),
            epoch: AtomicU64::new(7),
            ready: AtomicBool::new(true),
            capacity_revision: AtomicU64::new(1),
            free,
            profiles,
            rows: Mutex::new(BTreeMap::new()),
            commits: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            capacity_reads: AtomicUsize::new(0),
            lost_commit: AtomicBool::new(false),
            bad_nonce: AtomicBool::new(false),
        }
    }
    fn set_ready(&self, ready: bool) {
        if self.ready.swap(ready, Ordering::SeqCst) != ready {
            self.capacity_revision.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn capacity(&self) -> WorkerCapacityReceipt {
        let rows = self.rows.lock().unwrap();
        let count = rows.len() as u64;
        let used = rows
            .values()
            .try_fold(FleetResourceVector::ZERO, |used, row| {
                used.checked_add(row.token.request.resources)
            })
            .expect("bounded fixture debits");
        WorkerCapacityReceipt {
            worker_id: self.id.clone(),
            worker_epoch: self.epoch.load(Ordering::SeqCst),
            worker_boot_nonce: self.boot.clone(),
            compatibility_digest: [8; 32],
            capacity_revision: self.capacity_revision.load(Ordering::SeqCst),
            acknowledged_debit_sequence: count,
            capacity: vector(8),
            raw_free: vector(self.free)
                .checked_sub(used)
                .expect("fixture never overcommits its admitted capacity"),
            ready: self.ready.load(Ordering::SeqCst),
            draining: false,
            exclusive_assignment: None,
        }
    }
    fn session(&self, fence: &WorkerSessionFence) -> Result<WorkerSessionReceipt, WorkerRpcError> {
        let rows = self.rows.lock().unwrap();
        let created = rows
            .values()
            .filter_map(|r| r.session.as_ref())
            .find(|s| s.session_id == fence.session_id)
            .ok_or(WorkerRpcError::Protocol)?;
        if created.tenant_id != fence.tenant_id
            || created.worker_epoch != fence.worker_epoch
            || created.placement_version != fence.placement_version
            || created.session_incarnation != fence.session_incarnation
        {
            return Err(WorkerRpcError::Protocol);
        }
        Ok(WorkerSessionReceipt {
            fence: fence.clone(),
            lifecycle: WorkerSessionLifecycle::Ready,
            primary_page_id: created.primary_page_id.clone(),
        })
    }
}
impl GatewayWorkerClient for Peer {
    type PendingAction = Never;
    fn create_session(
        &self,
        _: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        panic!("managed mode cannot use legacy create")
    }
    fn enqueue_action(&self, _: WorkerRpcRequest) -> Result<Never, WorkerRpcEnqueueError> {
        panic!("no browser action")
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        match request {
            WorkerRpcRequest::CapacityStatus {
                expected_worker_epoch,
            } => {
                self.capacity_reads.fetch_add(1, Ordering::SeqCst);
                assert!(
                    expected_worker_epoch == 0
                        || expected_worker_epoch == self.epoch.load(Ordering::SeqCst)
                );
                Ok(WorkerRpcResponse::Capacity(self.capacity()))
            }
            WorkerRpcRequest::ReserveSession(request) => {
                assert_eq!(request.expected_worker_boot_nonce, self.boot);
                assert!(request.request.is_valid());
                let (isolation, resources) = self
                    .profiles
                    .get(&request.profile_digest)
                    .expect("configured immutable profile");
                assert!(request.request.requested_isolation.satisfied_by(*isolation));
                assert_eq!(request.resources, *resources);
                let existing = self
                    .rows
                    .lock()
                    .unwrap()
                    .get(&request.reservation_id)
                    .cloned();
                if let Some(row) = existing {
                    return Ok(WorkerRpcResponse::SessionReservation(Box::new(row)));
                }
                let seq = self.rows.lock().unwrap().len() as u64 + 1;
                let token = WorkerReservationToken {
                    request,
                    worker_id: self.id.clone(),
                    worker_reservation_nonce: LeaseId::new(),
                    debit_sequence: seq,
                };
                let mut cap = self.capacity();
                cap.capacity_revision = self.capacity_revision.fetch_add(1, Ordering::SeqCst) + 1;
                cap.acknowledged_debit_sequence = seq;
                cap.raw_free = cap
                    .raw_free
                    .checked_sub(token.request.resources)
                    .expect("positive exact profile debit");
                let row = WorkerReservationReceipt {
                    token,
                    phase: WorkerReservationPhase::Reserved,
                    capacity: cap,
                    remaining_ttl_millis: 30_000,
                    session: None,
                    session_lease_remaining_millis: None,
                    disposed_session: None,
                };
                self.rows
                    .lock()
                    .unwrap()
                    .insert(row.token.request.reservation_id.clone(), row.clone());
                Ok(WorkerRpcResponse::SessionReservation(Box::new(row)))
            }
            WorkerRpcRequest::InspectSessionReservation(token) => {
                let mut row = self
                    .rows
                    .lock()
                    .unwrap()
                    .get(&token.request.reservation_id)
                    .cloned()
                    .ok_or(WorkerRpcError::Protocol)?;
                assert_eq!(row.token, token);
                if self.bad_nonce.load(Ordering::SeqCst) {
                    row.token.worker_reservation_nonce = LeaseId::new()
                }
                Ok(WorkerRpcResponse::SessionReservation(Box::new(row)))
            }
            WorkerRpcRequest::CommitReservedSession(token) => {
                let mut rows = self.rows.lock().unwrap();
                let row = rows
                    .get_mut(&token.request.reservation_id)
                    .ok_or(WorkerRpcError::Protocol)?;
                assert_eq!(row.token, token);
                if row.phase == WorkerReservationPhase::Reserved {
                    self.commits.fetch_add(1, Ordering::SeqCst);
                    let r = &token.request.request;
                    row.session = Some(WorkerCreateSessionReceipt {
                        operation_id: r.operation_id.clone(),
                        tenant_id: r.tenant_id.clone(),
                        session_id: SessionId::new(),
                        session_incarnation: r.session_incarnation,
                        effective_isolation: self
                            .profiles
                            .get(&token.request.profile_digest)
                            .expect("immutable reserved profile")
                            .0,
                        primary_page_id: PageId::new(),
                        worker_epoch: r.expected_worker_epoch,
                        placement_version: r.placement_version,
                        existing: false,
                        restored_checkpoint: None,
                    });
                    row.phase = WorkerReservationPhase::Active;
                    row.session_lease_remaining_millis = Some(60_000);
                }
                if self.lost_commit.swap(false, Ordering::SeqCst) {
                    return Err(WorkerRpcError::Protocol);
                }
                Ok(WorkerRpcResponse::SessionReservation(Box::new(row.clone())))
            }
            WorkerRpcRequest::RenewReservedSession {
                token,
                renewal_nonce,
                expected_lease_revision,
                ..
            } => {
                let row = self
                    .rows
                    .lock()
                    .unwrap()
                    .get(&token.request.reservation_id)
                    .cloned()
                    .ok_or(WorkerRpcError::Protocol)?;
                assert_eq!(row.token, token);
                let s = row.session.unwrap();
                let session = self.session(&WorkerSessionFence {
                    tenant_id: s.tenant_id,
                    session_id: s.session_id,
                    worker_epoch: s.worker_epoch,
                    placement_version: s.placement_version,
                    session_incarnation: s.session_incarnation,
                })?;
                Ok(WorkerRpcResponse::ReservedSessionRenewed(Box::new(
                    WorkerReservedSessionRenewReceipt {
                        token,
                        renewal_nonce,
                        expected_lease_revision,
                        granted_ttl_millis: 60_000,
                        session,
                    },
                )))
            }
            WorkerRpcRequest::GetSession { fence } => {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(WorkerRpcResponse::Session(self.session(&fence)?))
            }
            _ => Err(WorkerRpcError::InvalidRequest),
        }
    }
}
fn principal(tenant: TenantId) -> AuthenticatedPrincipal {
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("test", Algorithm::HS256, b"fleet-fixture-auth-key")
        .unwrap();
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let token = ServiceTokenSigner::new("test", Algorithm::HS256, b"fleet-fixture-auth-key")
        .sign(&ServiceClaims::new(
            "issuer",
            "audience",
            PrincipalId::new(),
            tenant,
            ["session:create".to_owned(), "session:read".to_owned()]
                .into_iter()
                .collect(),
            Uuid::new_v4().to_string(),
            1,
            100,
            None,
        ))
        .unwrap();
    verifier.verify_at(&token, None, 10).unwrap()
}
fn config(peers: &[Arc<Peer>], cost: u16) -> GatewayFleetAdmissionConfig {
    GatewayFleetAdmissionConfig::new(
        "fixture",
        peers
            .iter()
            .map(|p| {
                GatewayFleetWorker::new(
                    p.id.clone(),
                    format!("/private/{}.sock", p.id),
                    "fixture",
                    vec![[8; 32]],
                    vec![[7; 32]],
                    budget(8),
                    None,
                )
                .unwrap()
            })
            .collect(),
        vec![
            GatewayFleetProfile::new(
                [7; 32],
                [8; 32],
                GatewaySessionIsolation::DedicatedProcess,
                GatewaySessionWorkload::Interactive,
                budget(1),
                cost,
            )
            .unwrap(),
        ],
        GatewayFleetTenantPolicy::new(1, budget(16), 16, 16, 64).unwrap(),
        vec![],
        GatewayFleetAdmissionLimits::new(128, 64, 32, 16, budget(32)).unwrap(),
    )
    .unwrap()
}
struct Fixture {
    peers: Vec<Arc<Peer>>,
    config: GatewayFleetAdmissionConfig,
    pg: CoordinationBlockingClient,
    store: Arc<MemoryGatewayActionStore>,
    principal: AuthenticatedPrincipal,
}
impl Fixture {
    fn new() -> Self {
        Self::with_cost(1)
    }
    fn with_cost(cost: u16) -> Self {
        let peers = vec![
            Arc::new(Peer::new("fleet-a", 2)),
            Arc::new(Peer::new("fleet-b", 8)),
        ];
        let config = config(&peers, cost);
        Self::configured(peers, config)
    }
    fn configured(peers: Vec<Arc<Peer>>, config: GatewayFleetAdmissionConfig) -> Self {
        let actor =
            CoordinationActorConfig::new(64, 8, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let pg =
            CoordinationBlockingClient::spawn(Arc::new(MemoryCreateSessionStore::default()), actor)
                .unwrap();
        let store = Arc::new(
            MemoryGatewayActionStore::default()
                .with_fleet_admission_config(config.clone())
                .unwrap(),
        );
        Self {
            peers,
            config,
            pg,
            store,
            principal: principal(TenantId::new()),
        }
    }
    fn runtime(&self) -> Arc<GatewayWorkerRuntime<Peer>> {
        Arc::new(self.runtime_builder())
    }
    fn runtime_builder(&self) -> GatewayWorkerRuntime<Peer> {
        let inventory = GatewayFleetInventory::new(
            Arc::new(self.config.clone()),
            self.peers
                .iter()
                .map(|p| {
                    GatewayFleetPeer::new(
                        p.id.clone(),
                        format!("/private/{}.sock", p.id),
                        7,
                        p.clone(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        GatewayWorkerRuntime::with_action_coordination(
            self.peers[0].clone(),
            GatewayWorkerPlacement::new(self.peers[0].id.clone(), 7, 1, 1).unwrap(),
            self.store.clone(),
            CoordinationActorConfig::new(64, 8, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap(),
        )
        .unwrap()
        .with_fleet(inventory, self.pg.clone())
    }
    fn router(
        &self,
        runtime: Arc<GatewayWorkerRuntime<Peer>>,
    ) -> DurableApiRouter<GatewayWorkerRuntime<Peer>> {
        DurableApiRouter::with_dispatch_lease_duration(
            runtime,
            self.pg.clone(),
            Duration::from_millis(150),
        )
        .unwrap()
    }
    fn create(
        &self,
        router: &DurableApiRouter<GatewayWorkerRuntime<Peer>>,
        key: &str,
    ) -> browserd_api::OperationEnvelope {
        let response = router
            .execute(
                &self.principal,
                ApiRequest::CreateSession {
                    body: decode_session_create(BODY).unwrap(),
                    idempotency_key: key.to_owned(),
                    received_at: Instant::now(),
                },
            )
            .unwrap();
        let ApiResponse::SessionCreate(value) = response else {
            panic!("create response")
        };
        value.data().operation().clone()
    }
}
#[test]
fn durable_least_loaded_placement_survives_gateway_restart_and_never_uses_singleton() {
    let f = Fixture::new();
    let key = Uuid::new_v4().to_string();
    let runtime = f.runtime();
    let api = f.router(runtime);
    let result = f.create(&api, &key);
    assert_eq!(result.state(), CreateOperationState::Succeeded);
    let session = result.session().unwrap().id.clone();
    assert_eq!(f.peers[0].commits.load(Ordering::SeqCst), 0);
    assert_eq!(f.peers[1].commits.load(Ordering::SeqCst), 1);
    drop(api);
    let runtime = f.runtime();
    let api = f.router(runtime.clone());
    let response = api
        .execute(&f.principal, ApiRequest::GetSession(session.clone()))
        .unwrap();
    assert!(matches!(response, ApiResponse::Session(_)));
    assert_eq!(f.peers[0].reads.load(Ordering::SeqCst), 0);
    assert!(f.peers[1].reads.load(Ordering::SeqCst) > 0);
    assert_eq!(runtime.maintain_fleet_leases(16).unwrap().leases_renewed, 1);
    let again = f.create(&api, &key);
    assert_eq!(again.session().unwrap().id, session);
    assert_eq!(f.peers[1].commits.load(Ordering::SeqCst), 1);
    let foreign = principal(TenantId::new());
    assert!(
        api.execute(&foreign, ApiRequest::GetSession(session))
            .is_err()
    );
}
#[test]
fn lost_commit_reply_recovers_exact_reserved_worker_without_second_browser() {
    let f = Fixture::new();
    let key = Uuid::new_v4().to_string();
    f.peers[1].lost_commit.store(true, Ordering::SeqCst);
    let api = f.router(f.runtime());
    let first = f.create(&api, &key);
    assert_eq!(first.state(), CreateOperationState::Creating);
    assert_eq!(f.peers[1].commits.load(Ordering::SeqCst), 1);
    drop(api);
    std::thread::sleep(Duration::from_millis(200));
    let api = f.router(f.runtime());
    let second = f.create(&api, &key);
    assert_eq!(second.id(), first.id());
    assert_eq!(second.state(), CreateOperationState::Succeeded);
    assert_eq!(f.peers[0].commits.load(Ordering::SeqCst), 0);
    assert_eq!(f.peers[1].commits.load(Ordering::SeqCst), 1);
}
#[test]
fn mismatched_worker_reservation_never_commits_or_reassigns() {
    let f = Fixture::new();
    let key = Uuid::new_v4().to_string();
    f.peers[1].bad_nonce.store(true, Ordering::SeqCst);
    let api = f.router(f.runtime());
    let first = f.create(&api, &key);
    assert_eq!(first.state(), CreateOperationState::Creating);
    std::thread::sleep(Duration::from_millis(200));
    let second = f.create(&api, &key);
    assert_eq!(first.id(), second.id());
    assert_eq!(second.state(), CreateOperationState::Creating);
    assert!(
        f.peers
            .iter()
            .all(|p| p.commits.load(Ordering::SeqCst) == 0)
    );
    assert_eq!(f.peers[0].rows.lock().unwrap().len(), 0);
}
#[test]
fn unready_fleet_defers_unexposed_operation_then_reuses_same_identity() {
    let f = Fixture::new();
    let key = Uuid::new_v4().to_string();
    for peer in &f.peers {
        peer.set_ready(false)
    }
    let runtime = f.runtime();
    assert_eq!(runtime.refresh_fleet_workers(32).unwrap(), 0);
    let api = f.router(runtime);
    let first = f.create(&api, &key);
    assert_eq!(first.state(), CreateOperationState::Queued);
    let deferred =
        f.pg.get(f.principal.tenant_id(), first.id())
            .unwrap()
            .unwrap();
    assert!(deferred.dispatch_lease().is_none());
    assert!(f.peers.iter().all(|p| p.rows.lock().unwrap().is_empty()));
    for peer in &f.peers {
        peer.set_ready(true)
    }
    let second = f.create(&api, &key);
    assert_eq!(second.id(), first.id());
    assert_eq!(second.state(), CreateOperationState::Succeeded);
}

#[test]
fn private_inventory_rejects_ambiguous_routes_and_nonprivate_or_linked_files() {
    use std::os::unix::fs::PermissionsExt;
    let peers = vec![Arc::new(Peer::new("fleet-a", 8))];
    let admission = config(&peers, 1);
    let root = std::env::temp_dir().join(format!("browserd-fleet-config-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("fleet.json");
    let mut value = serde_json::json!({"schema_version":1,"admission":admission,"peers":[{"worker_id":peers[0].id,"socket_path":"/private/fleet-a.sock","peer_uid":nix::unistd::Uid::effective().as_raw(),"expected_worker_epoch":7}]});
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let loaded = browser_gateway::GatewayFleetConfig::load(&path).unwrap();
    assert_eq!(loaded.peers().len(), 1);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(browser_gateway::GatewayFleetConfig::load(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&path, root.join("alias")).unwrap();
    assert!(browser_gateway::GatewayFleetConfig::load(&path).is_err());
    std::fs::remove_file(root.join("alias")).unwrap();
    value["peers"][0]["socket_path"] = serde_json::json!("/private/foreign.sock");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(browser_gateway::GatewayFleetConfig::load(&path).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn lone_cost_64_head_progresses_in_one_dispatch_with_one_worker_observation_pass() {
    let f = Fixture::with_cost(64);
    let api = f.router(f.runtime());
    let key = Uuid::new_v4().to_string();
    let result = f.create(&api, &key);
    assert_eq!(result.state(), CreateOperationState::Succeeded);
    assert_eq!(f.peers[0].commits.load(Ordering::SeqCst), 0);
    assert_eq!(f.peers[1].commits.load(Ordering::SeqCst), 1);
    for peer in &f.peers {
        assert_eq!(peer.capacity_reads.load(Ordering::SeqCst), 1);
    }
    let operation =
        f.pg.get(f.principal.tenant_id(), result.id())
            .unwrap()
            .unwrap();
    assert_eq!(operation.dispatch_generation(), 1);
    assert_eq!(
        operation.intent().admission_deadline() - operation.intent().accepted_at(),
        chrono::Duration::seconds(30)
    );
}
