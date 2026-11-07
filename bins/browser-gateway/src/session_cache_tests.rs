#![allow(clippy::expect_used)]
use super::*;

struct NeverPending;
impl GatewayWorkerPending for NeverPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        Err(WorkerRpcCompletionError::Disconnected)
    }
}
struct NoWorker;
impl GatewayWorkerClient for NoWorker {
    type PendingAction = NeverPending;
    fn create_session(
        &self,
        _: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        Err(WorkerRpcError::InvalidRequest)
    }
    fn request(&self, _: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        Err(WorkerRpcError::InvalidRequest)
    }
    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<NeverPending, WorkerRpcEnqueueError> {
        Err(WorkerRpcEnqueueError::Closed(Box::new(request)))
    }
}
fn runtime() -> GatewayWorkerRuntime<NoWorker> {
    GatewayWorkerRuntime::new(
        Arc::new(NoWorker),
        GatewayWorkerPlacement::new(WorkerId::new("cache-worker").expect("worker"), 7, 3, 5)
            .expect("placement"),
    )
    .expect("runtime")
}
fn record(
    tenant: &TenantId,
    index: u128,
    lifecycle: SessionLifecycle,
    retired_at: DateTime<Utc>,
) -> GatewaySessionRecord {
    let session = SessionId::from_uuid(Uuid::from_u128(
        0x0000_0000_0000_7000_8000_0000_0000_0000 | (index + 1),
    ))
    .expect("session");
    let placement = GatewayActionPlacement::new(
        DirectoryFence::new(WorkerId::new("cache-worker").expect("worker"), 7, 3, 1)
            .expect("fence"),
        5,
    )
    .expect("placement");
    GatewaySessionRecord {
        fence: WorkerSessionFence {
            tenant_id: tenant.clone(),
            session_id: session.clone(),
            worker_epoch: 7,
            placement_version: 3,
            session_incarnation: 1,
        },
        action_placement: placement,
        resource: SessionResource {
            id: session,
            lifecycle,
            incarnation: 1,
            requested_isolation: IsolationProfile::DedicatedProcess,
            effective_isolation: IsolationProfile::DedicatedProcess,
            metadata: BTreeMap::new(),
        },
        admission_lane: Arc::new(SessionAdmissionLane::default()),
        retired_at: Some(retired_at),
    }
}
#[test]
fn bounded_cache_gc_advances_past_live_prefix_and_reclaims_only_retired_records() {
    let runtime = runtime();
    let tenant = TenantId::new();
    let before = Utc::now() - ChronoDuration::hours(25);
    {
        let mut sessions = runtime.sessions.lock().expect("sessions");
        for index in 0..128 {
            let record = record(
                &tenant,
                index,
                if index < 32 {
                    SessionLifecycle::Ready
                } else {
                    SessionLifecycle::Closed
                },
                before,
            );
            sessions.insert((tenant.clone(), record.resource.id.clone()), record);
        }
    }
    for _ in 0..8 {
        let count = runtime.sessions.lock().expect("sessions").len();
        let _ = runtime.reclaim_retired_sessions(Utc::now(), ChronoDuration::hours(24));
        let current = runtime.sessions.lock().expect("sessions").len();
        assert!(count - current <= 32);
    }
    let sessions = runtime.sessions.lock().expect("sessions");
    assert_eq!(sessions.len(), 32);
    assert!(
        sessions
            .values()
            .all(|record| record.resource.lifecycle == SessionLifecycle::Ready)
    );
}
#[test]
fn cache_gc_keeps_admitted_and_unpublished_records_until_their_owners_release_them() {
    let runtime = runtime();
    let tenant = TenantId::new();
    let before = Utc::now() - ChronoDuration::hours(25);
    let closing = record(&tenant, 0, SessionLifecycle::Closed, before);
    let permit = closing.admission_lane.acquire().expect("admission");
    let published = record(&tenant, 1, SessionLifecycle::Closed, before);
    let unpublished = record(&tenant, 2, SessionLifecycle::Creating, before);
    {
        let mut sessions = runtime.sessions.lock().expect("sessions");
        for record in [closing, published, unpublished] {
            sessions.insert((tenant.clone(), record.resource.id.clone()), record);
        }
    }
    let _ = runtime.reclaim_retired_sessions(Utc::now(), ChronoDuration::hours(24));
    assert_eq!(runtime.sessions.lock().expect("sessions").len(), 2);
    drop(permit);
    let _ = runtime.reclaim_retired_sessions(Utc::now(), ChronoDuration::hours(24));
    let sessions = runtime.sessions.lock().expect("sessions");
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions
            .values()
            .next()
            .expect("unpublished")
            .resource
            .lifecycle,
        SessionLifecycle::Creating
    );
}
