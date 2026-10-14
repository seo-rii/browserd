#![allow(clippy::expect_used)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{ActionKind, CanonicalRequestHash};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, EventCursor, EventOutbox,
    EventOutboxBlockingClient, EventOutboxError, GatewayActionCoordination, GatewayActionPlacement,
    GatewayEventProjection, MemoryCoordinationDatabase, MemoryEventOutbox,
    MemoryGatewayActionStore, OutboxAggregate, OutboxAppend, OutboxEvent, OutboxPage, StoreConfig,
};
use browserd_core::{ActionId, SessionId, TenantId, WorkerId};
use browserd_worker::{
    WorkerControlEvent, WorkerCreateSessionReceipt, WorkerCreateSessionRequest,
    WorkerRpcCompletionError, WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcRequest,
    WorkerRpcResponse, WorkerSessionFence,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

const HEALTHY: usize = 0;
const UNAVAILABLE: usize = 1;
const LOSE_COMMIT_RESPONSE_ONCE: usize = 2;

#[derive(Default)]
struct UnreachableWorker {
    calls: AtomicUsize,
}

struct NeverPending;

impl GatewayWorkerPending for NeverPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        Err(WorkerRpcCompletionError::Disconnected)
    }
}

impl GatewayWorkerClient for UnreachableWorker {
    type PendingAction = NeverPending;

    fn create_session(
        &self,
        _request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(WorkerRpcError::Runtime)
    }

    fn request(&self, _request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(WorkerRpcError::Runtime)
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(WorkerRpcEnqueueError::Closed(Box::new(request)))
    }
}

#[derive(Default)]
struct FaultSink {
    committed: MemoryEventOutbox,
    mode: AtomicUsize,
    legacy_appends: AtomicUsize,
}

#[async_trait]
impl EventOutbox for FaultSink {
    async fn append(
        &self,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        self.legacy_appends.fetch_add(1, Ordering::SeqCst);
        self.committed.append(append, now).await
    }

    async fn append_projection(
        &self,
        projection: GatewayEventProjection,
        now: DateTime<Utc>,
    ) -> Result<(), EventOutboxError> {
        if self.mode.load(Ordering::SeqCst) == UNAVAILABLE {
            return Err(EventOutboxError::PostgresUnavailable);
        }
        self.committed.append_projection(projection, now).await?;
        if self
            .mode
            .compare_exchange(
                LOSE_COMMIT_RESPONSE_ONCE,
                HEALTHY,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            // The sink committed, but the gateway did not receive its reply and cannot ACK source.
            return Err(EventOutboxError::PostgresUnavailable);
        }
        Ok(())
    }

    async fn read_from(
        &self,
        tenant: &TenantId,
        after: EventCursor,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.committed.read_from(tenant, after, limit, now).await
    }

    async fn read_after_event_id(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.committed
            .read_after_event_id(tenant, after, limit, now)
            .await
    }

    async fn mark_delivered(
        &self,
        tenant: &TenantId,
        cursor: EventCursor,
    ) -> Result<(), EventOutboxError> {
        self.committed.mark_delivered(tenant, cursor).await
    }

    async fn delivered_cursor(&self, tenant: &TenantId) -> Result<EventCursor, EventOutboxError> {
        self.committed.delivered_cursor(tenant).await
    }
}

struct Fixture {
    runtime: tokio::runtime::Runtime,
    database: MemoryCoordinationDatabase,
    store: MemoryGatewayActionStore,
    worker: Arc<UnreachableWorker>,
    sink: Arc<FaultSink>,
    tenant: TenantId,
    session: SessionId,
    actions: Vec<ActionId>,
}

impl Fixture {
    fn new(mode: usize) -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let database = MemoryCoordinationDatabase::default();
        let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
        let worker = Arc::new(UnreachableWorker::default());
        let sink = Arc::new(FaultSink::default());
        sink.mode.store(mode, Ordering::SeqCst);
        let tenant = TenantId::new();
        let session = SessionId::new();
        let placement = GatewayActionPlacement::new(
            DirectoryFence::new(
                WorkerId::new("event-recovery-test").expect("worker ID"),
                1,
                1,
                1,
            )
            .expect("directory fence"),
            1,
        )
        .expect("placement");
        let mut actions = Vec::new();
        runtime.block_on(async {
            for key in ["first-terminal", "second-terminal"] {
                let action = ActionId::new();
                let claimed = store
                    .claim_action(
                        ClaimGatewayAction::new(
                            tenant.clone(),
                            session.clone(),
                            action.clone(),
                            key,
                            CanonicalRequestHash::new([1; 32]),
                            ActionKind::ReadOnly,
                            placement.clone(),
                        )
                        .expect("claim"),
                        Utc::now(),
                    )
                    .await
                    .expect("claim action")
                    .into_snapshot();
                store
                    .cancel_before_dispatch(
                        &tenant,
                        &session,
                        &action,
                        claimed.revision(),
                        &placement,
                        Utc::now(),
                    )
                    .await
                    .expect("durable terminal transition");
                actions.push(action);
            }
        });
        Self {
            runtime,
            database,
            store,
            worker,
            sink,
            tenant,
            session,
            actions,
        }
    }

    fn gateway(&self) -> GatewayWorkerRuntime<UnreachableWorker> {
        let store = Arc::new(MemoryGatewayActionStore::attach(
            self.database.clone(),
            StoreConfig::default(),
        ));
        let sink: Arc<dyn EventOutbox> = self.sink.clone();
        GatewayWorkerRuntime::with_action_coordination(
            self.worker.clone(),
            GatewayWorkerPlacement::new(
                WorkerId::new("event-recovery-test").expect("worker ID"),
                1,
                1,
                1,
            )
            .expect("worker placement"),
            store,
            CoordinationActorConfig::default(),
        )
        .expect("reattached gateway")
        .with_terminal_event_outbox(EventOutboxBlockingClient::spawn(sink, 1).expect("sink client"))
    }

    fn pending_sequence(&self) -> Option<u64> {
        self.runtime
            .block_on(
                self.store
                    .peek_event_projection(&self.tenant, &self.session),
            )
            .expect("pending intent")
            .map(|projection| projection.sequence())
    }

    fn events(&self) -> OutboxPage {
        self.runtime
            .block_on(
                self.sink
                    .read_from(&self.tenant, EventCursor::start(), 10, Utc::now()),
            )
            .expect("sink events")
    }

    fn assert_recovered(&self) {
        assert_eq!(self.pending_sequence(), None);
        let page = self.events();
        assert_eq!(page.events().len(), 2);
        for (event, action) in page.events().iter().zip(&self.actions) {
            assert_eq!(
                event.aggregate(),
                &OutboxAggregate::Action {
                    session_id: self.session.clone(),
                    action_id: action.clone()
                }
            );
        }
        assert_eq!(page.next_cursor().position(), 2);
        assert_eq!(
            self.worker.calls.load(Ordering::SeqCst),
            0,
            "notification recovery must never replay browser effects"
        );
        assert_eq!(
            self.sink.legacy_appends.load(Ordering::SeqCst),
            0,
            "relay must use the permanent projection watermark"
        );
    }
}

#[test]
fn committed_sink_response_loss_retries_after_gateway_restart_without_duplicate_events() {
    let fixture = Fixture::new(LOSE_COMMIT_RESPONSE_ONCE);
    let first_gateway = fixture.gateway();
    assert!(first_gateway.reconcile_terminal_events(1).is_err());
    assert_eq!(
        fixture.pending_sequence(),
        Some(1),
        "source cannot ACK an uncertain sink commit"
    );
    let first_page = fixture.events();
    assert_eq!(first_page.events().len(), 1);
    let committed_id = first_page.events()[0].event_id();
    drop(first_gateway);

    let restarted = fixture.gateway();
    assert_eq!(
        restarted
            .reconcile_terminal_events(1)
            .expect("retry exact committed projection"),
        1
    );
    assert_eq!(fixture.pending_sequence(), Some(2));
    assert_eq!(fixture.events().events()[0].event_id(), committed_id);
    assert_eq!(
        restarted
            .reconcile_terminal_events(1)
            .expect("deliver second projection"),
        1
    );
    assert_eq!(
        restarted.reconcile_terminal_events(1).expect("empty pass"),
        0
    );
    fixture.assert_recovered();
}

#[test]
fn unavailable_sink_retains_ordered_source_intents_until_recovery_without_a_live_session() {
    let fixture = Fixture::new(UNAVAILABLE);
    let first_gateway = fixture.gateway();
    for _ in 0..2 {
        assert!(first_gateway.reconcile_terminal_events(1).is_err());
        assert_eq!(fixture.pending_sequence(), Some(1));
        assert!(fixture.events().events().is_empty());
    }
    drop(first_gateway);
    fixture.sink.mode.store(HEALTHY, Ordering::SeqCst);
    let restarted = fixture.gateway();
    assert_eq!(
        restarted
            .reconcile_terminal_events(1)
            .expect("first recovered projection"),
        1
    );
    assert_eq!(
        restarted
            .reconcile_terminal_events(1)
            .expect("second recovered projection"),
        1
    );
    fixture.assert_recovered();
}

struct ControlSource {
    events: Mutex<VecDeque<WorkerControlEvent>>,
    acknowledgements: AtomicUsize,
}

impl GatewayWorkerClient for ControlSource {
    type PendingAction = NeverPending;
    fn create_session(
        &self,
        _: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        Err(WorkerRpcError::InvalidRequest)
    }
    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<NeverPending, WorkerRpcEnqueueError> {
        Err(WorkerRpcEnqueueError::Closed(Box::new(request)))
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let mut events = self.events.lock().expect("source events");
        match request {
            WorkerRpcRequest::PendingControlEvents { limit } => Ok(
                WorkerRpcResponse::ControlEvents(events.iter().take(limit).cloned().collect()),
            ),
            WorkerRpcRequest::AckControlEvent { event } if events.front() == Some(&event) => {
                events.pop_front();
                self.acknowledgements.fetch_add(1, Ordering::SeqCst);
                Ok(WorkerRpcResponse::Empty)
            }
            _ => Err(WorkerRpcError::InvalidRequest),
        }
    }
}

#[test]
fn control_relay_retries_committed_sink_after_gateway_restart_without_live_session() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let tenant = TenantId::new();
    let session = SessionId::new();
    let worker = Arc::new(ControlSource {
        acknowledgements: AtomicUsize::new(0),
        events: Mutex::new(
            (1..=2)
                .map(|sequence| WorkerControlEvent {
                    // Journal events from the previous worker incarnation remain deliverable.
                    fence: WorkerSessionFence {
                        tenant_id: tenant.clone(),
                        session_id: session.clone(),
                        worker_epoch: 1,
                        placement_version: 1,
                        session_incarnation: 1,
                    },
                    sequence,
                    control_epoch: sequence,
                    human: sequence == 1,
                    page_id: (sequence == 1).then(browserd_core::PageId::new),
                })
                .collect(),
        ),
    });
    let sink = Arc::new(FaultSink::default());
    sink.mode.store(LOSE_COMMIT_RESPONSE_ONCE, Ordering::SeqCst);
    let gateway = || {
        let outbox: Arc<dyn EventOutbox> = sink.clone();
        GatewayWorkerRuntime::new(
            worker.clone(),
            GatewayWorkerPlacement::new(
                WorkerId::new("control-recovery").expect("worker"),
                2,
                1,
                1,
            )
            .expect("placement"),
        )
        .expect("gateway")
        .with_terminal_event_outbox(EventOutboxBlockingClient::spawn(outbox, 1).expect("sink"))
    };
    let first = gateway();
    assert!(first.reconcile_viewer_control_events(128).is_err());
    assert_eq!(worker.acknowledgements.load(Ordering::SeqCst), 0);
    let committed = runtime
        .block_on(sink.read_from(&tenant, EventCursor::start(), 10, Utc::now()))
        .expect("committed events");
    assert_eq!(committed.events().len(), 1);
    let original_id = committed.events()[0].event_id();
    drop(first);
    let restarted = gateway();
    assert_eq!(
        restarted
            .reconcile_viewer_control_events(128)
            .expect("retry"),
        2
    );
    assert_eq!(worker.acknowledgements.load(Ordering::SeqCst), 2);
    let events = runtime
        .block_on(sink.read_from(&tenant, EventCursor::start(), 10, Utc::now()))
        .expect("delivered events");
    assert_eq!(events.events().len(), 2);
    assert_eq!(events.events()[0].event_id(), original_id);
    assert!(
        events
            .events()
            .iter()
            .all(|event| event.kind() == browserd_coordination::OutboxEventKind::ControlChanged)
    );
    assert_eq!(sink.legacy_appends.load(Ordering::SeqCst), 0);
}
