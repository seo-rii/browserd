#![allow(clippy::expect_used)]
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use browser_gateway::{
    GatewayFleetInventory, GatewayFleetPeer, GatewayWorkerClient, GatewayWorkerPending,
    GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_coordination::{
    CoordinationActorConfig, CoordinationBlockingClient, EventCursor, EventOutbox,
    EventOutboxBlockingClient, EventOutboxError, GatewayFleetAdmissionConfig,
    GatewayFleetAdmissionLimits, GatewayFleetProfile, GatewayFleetTenantPolicy, GatewayFleetWorker,
    GatewaySessionIsolation, GatewaySessionWorkload, MemoryCreateSessionStore, MemoryEventOutbox,
    OutboxAppend, OutboxEvent, OutboxPage, PostgresEventOutbox, StoreConfig, WorkerCapacity,
};
use browserd_core::{
    ActionId, ArtifactId, LeaseId, NotificationAck, NotificationActionState,
    NotificationArtifactState, NotificationCommit, NotificationControlState,
    NotificationDescriptor, NotificationSessionLifecycleState, NotificationSessionScope,
    NotificationSourceFamily, NotificationSourceScope, PlacementFence, SessionId, TenantId,
    WorkerId, WorkerNotificationEvent,
};
use browserd_worker::{
    FleetResourceVector, WorkerCapacityReceipt, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerNotificationPage, WorkerRpcCompletionError,
    WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcRequest, WorkerRpcResponse,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

const HEALTHY: usize = 0;
const UNAVAILABLE: usize = 1;
const LOSE_SINK_REPLY: usize = 2;
const LOSE_ACK_BEFORE: usize = 1;
const LOSE_ACK_AFTER: usize = 2;
type ScriptedPage = (Option<String>, WorkerNotificationPage);

struct Never;
impl GatewayWorkerPending for Never {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        Err(WorkerRpcCompletionError::Disconnected)
    }
}
struct Worker {
    id: WorkerId,
    boot: LeaseId,
    pending: Mutex<HashMap<NotificationSourceFamily, VecDeque<NotificationCommit>>>,
    receipts: Mutex<Vec<NotificationAck>>,
    scripted: Mutex<HashMap<NotificationSourceFamily, VecDeque<ScriptedPage>>>,
    queries: Mutex<Vec<(NotificationSourceFamily, Option<String>)>>,
    ack_calls: AtomicUsize,
    browser_effects: AtomicUsize,
    offline: AtomicBool,
    wrong_response: AtomicBool,
    ack_fault: AtomicUsize,
}
impl Worker {
    fn new(id: &str, commits: Vec<NotificationCommit>) -> Self {
        let mut pending: HashMap<_, VecDeque<_>> = HashMap::new();
        for commit in commits {
            pending
                .entry(commit.scope().family())
                .or_default()
                .push_back(commit);
        }
        Self {
            id: WorkerId::new(id).expect("worker"),
            boot: LeaseId::new(),
            pending: Mutex::new(pending),
            receipts: Mutex::new(Vec::new()),
            scripted: Mutex::new(HashMap::new()),
            queries: Mutex::new(Vec::new()),
            ack_calls: AtomicUsize::new(0),
            browser_effects: AtomicUsize::new(0),
            offline: AtomicBool::new(false),
            wrong_response: AtomicBool::new(false),
            ack_fault: AtomicUsize::new(0),
        }
    }
}
fn resources() -> FleetResourceVector {
    FleetResourceVector {
        memory_bytes: 100,
        cpu_millis: 100,
        pids: 1,
        disk_bytes: 100,
        contexts: 1,
        targets: 8,
    }
}
fn capacity() -> WorkerCapacity {
    WorkerCapacity::new(100, 100, 1, 100, 1, 8)
}
impl GatewayWorkerClient for Worker {
    type PendingAction = Never;
    fn create_session(
        &self,
        _request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        self.browser_effects.fetch_add(1, Ordering::SeqCst);
        Err(WorkerRpcError::InvalidRequest)
    }
    fn enqueue_action(&self, request: WorkerRpcRequest) -> Result<Never, WorkerRpcEnqueueError> {
        self.browser_effects.fetch_add(1, Ordering::SeqCst);
        Err(WorkerRpcEnqueueError::Closed(Box::new(request)))
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        if self.offline.load(Ordering::SeqCst) {
            return Err(WorkerRpcError::Runtime);
        }
        match request {
            WorkerRpcRequest::CapacityStatus { .. } => {
                Ok(WorkerRpcResponse::Capacity(WorkerCapacityReceipt {
                    worker_id: self.id.clone(),
                    worker_epoch: 7,
                    worker_boot_nonce: self.boot.clone(),
                    compatibility_digest: [8; 32],
                    capacity_revision: 1,
                    acknowledged_debit_sequence: 0,
                    capacity: resources(),
                    raw_free: resources(),
                    ready: false,
                    draining: true,
                    exclusive_assignment: None,
                }))
            }
            WorkerRpcRequest::PendingNotifications {
                expected_worker_id,
                expected_worker_epoch,
                family,
                cursor,
                limit,
            } => {
                assert_eq!(expected_worker_id, self.id);
                assert_eq!(expected_worker_epoch, 7);
                assert!((1..=32).contains(&limit));
                self.queries
                    .lock()
                    .expect("queries")
                    .push((family, cursor.clone()));
                let scripted = self
                    .scripted
                    .lock()
                    .expect("scripts")
                    .get_mut(&family)
                    .and_then(VecDeque::pop_front);
                let page = if let Some((expected, page)) = scripted {
                    assert_eq!(cursor, expected);
                    page
                } else {
                    let commits = self
                        .pending
                        .lock()
                        .expect("pending")
                        .get(&family)
                        .and_then(VecDeque::front)
                        .cloned()
                        .into_iter()
                        .collect::<Vec<_>>();
                    WorkerNotificationPage {
                        examined: usize::from(!commits.is_empty()),
                        commits,
                        cursor: None,
                        is_complete: true,
                    }
                };
                Ok(WorkerRpcResponse::Notifications {
                    worker_id: if self.wrong_response.load(Ordering::SeqCst) {
                        WorkerId::new("wrong-peer").expect("worker")
                    } else {
                        self.id.clone()
                    },
                    worker_epoch: 7,
                    page: Box::new(page),
                })
            }
            WorkerRpcRequest::AckNotification {
                expected_worker_id,
                expected_worker_epoch,
                ack,
            } => {
                assert_eq!(expected_worker_id, self.id);
                assert_eq!(expected_worker_epoch, 7);
                self.ack_calls.fetch_add(1, Ordering::SeqCst);
                let fault = self.ack_fault.swap(HEALTHY, Ordering::SeqCst);
                if fault == LOSE_ACK_BEFORE {
                    return Err(WorkerRpcError::Runtime);
                }
                let mut pending = self.pending.lock().expect("pending");
                let mut receipts = self.receipts.lock().expect("receipts");
                if !receipts.contains(&ack) {
                    let source = pending
                        .get_mut(&ack.scope().family())
                        .ok_or(WorkerRpcError::InvalidRequest)?;
                    if source.front().map(NotificationCommit::ack).as_ref() != Some(ack.as_ref()) {
                        return Err(WorkerRpcError::InvalidRequest);
                    }
                    source.pop_front();
                    receipts.push((*ack).clone());
                }
                if fault == LOSE_ACK_AFTER {
                    return Err(WorkerRpcError::Runtime);
                }
                Ok(WorkerRpcResponse::NotificationAck {
                    worker_id: self.id.clone(),
                    worker_epoch: 7,
                    ack,
                })
            }
            _ => {
                self.browser_effects.fetch_add(1, Ordering::SeqCst);
                Err(WorkerRpcError::InvalidRequest)
            }
        }
    }
}

struct Sink {
    inner: Arc<dyn EventOutbox>,
    mode: AtomicUsize,
    imports: AtomicUsize,
}
#[async_trait]
impl EventOutbox for Sink {
    async fn append(
        &self,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        self.inner.append(append, now).await
    }
    async fn append_notification_commit(
        &self,
        commit: NotificationCommit,
        now: DateTime<Utc>,
    ) -> Result<NotificationAck, EventOutboxError> {
        self.imports.fetch_add(1, Ordering::SeqCst);
        if self.mode.load(Ordering::SeqCst) == UNAVAILABLE {
            return Err(EventOutboxError::PostgresUnavailable);
        }
        let ack = self.inner.append_notification_commit(commit, now).await?;
        if self
            .mode
            .compare_exchange(LOSE_SINK_REPLY, HEALTHY, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Err(EventOutboxError::PostgresUnavailable);
        }
        Ok(ack)
    }
    async fn read_from(
        &self,
        tenant: &TenantId,
        after: EventCursor,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.inner.read_from(tenant, after, limit, now).await
    }
    async fn read_after_event_id(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.inner
            .read_after_event_id(tenant, after, limit, now)
            .await
    }
    async fn mark_delivered(
        &self,
        tenant: &TenantId,
        cursor: EventCursor,
    ) -> Result<(), EventOutboxError> {
        self.inner.mark_delivered(tenant, cursor).await
    }
    async fn delivered_cursor(&self, tenant: &TenantId) -> Result<EventCursor, EventOutboxError> {
        self.inner.delivered_cursor(tenant).await
    }
}
fn commit(
    tenant: &TenantId,
    worker: &str,
    family: NotificationSourceFamily,
    epoch: u64,
) -> NotificationCommit {
    let event = match family {
        NotificationSourceFamily::ActionJournal => WorkerNotificationEvent::ActionStateChanged {
            action_id: ActionId::new(),
            state: NotificationActionState::Accepted,
            resolution: None,
        },
        NotificationSourceFamily::SessionLifecycle => {
            WorkerNotificationEvent::SessionLifecycleChanged {
                state: NotificationSessionLifecycleState::Ready,
            }
        }
        NotificationSourceFamily::ArtifactRegistry => {
            WorkerNotificationEvent::ArtifactStateChanged {
                artifact_id: ArtifactId::new(),
                state: NotificationArtifactState::Available,
            }
        }
        NotificationSourceFamily::ControlJournal => {
            WorkerNotificationEvent::BrowserControlChanged {
                state: NotificationControlState::Agent,
            }
        }
    };
    NotificationCommit::new(
        NotificationSourceScope::new(
            tenant.clone(),
            WorkerId::new(worker).expect("worker"),
            Uuid::new_v4(),
            family,
        )
        .expect("source"),
        1,
        Utc::now().timestamp_millis().try_into().expect("timestamp"),
        vec![
            NotificationDescriptor::fresh(
                NotificationSessionScope::new(SessionId::new(), PlacementFence::new(epoch, 9, 11))
                    .expect("full original fence"),
                event,
            )
            .expect("event"),
        ],
    )
    .expect("immutable commit")
}
fn memory_sink() -> Arc<Sink> {
    Arc::new(Sink {
        inner: Arc::new(MemoryEventOutbox::default()),
        mode: AtomicUsize::new(HEALTHY),
        imports: AtomicUsize::new(0),
    })
}
fn gateway(worker: Arc<Worker>, sink: Arc<Sink>) -> GatewayWorkerRuntime<Worker> {
    GatewayWorkerRuntime::new(
        worker.clone(),
        GatewayWorkerPlacement::new(worker.id.clone(), 7, 1, 1).expect("placement"),
    )
    .expect("gateway")
    .with_terminal_event_outbox(EventOutboxBlockingClient::spawn(sink, 2).expect("sink client"))
}
fn events(sink: &Arc<Sink>, tenant: &TenantId) -> Vec<OutboxEvent> {
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(sink.read_from(tenant, EventCursor::start(), 100, Utc::now()))
        .expect("events")
        .events()
        .to_vec()
}

#[test]
fn notification_import_lost_reply_restart_retries_the_original_event_and_exact_source_ack() {
    let tenant = TenantId::new();
    let commit = commit(
        &tenant,
        "notification-worker",
        NotificationSourceFamily::ActionJournal,
        1,
    );
    let worker = Arc::new(Worker::new("notification-worker", vec![commit.clone()]));
    let sink = memory_sink();
    sink.mode.store(LOSE_SINK_REPLY, Ordering::SeqCst);
    let first = gateway(worker.clone(), sink.clone());
    assert!(first.reconcile_worker_notifications(32).is_err());
    assert_eq!(worker.ack_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        events(&sink, &tenant)[0].event_id(),
        commit.descriptors()[0].event_id()
    );
    drop(first);
    let restarted = gateway(worker.clone(), sink.clone());
    assert_eq!(
        restarted
            .reconcile_worker_notifications(32)
            .expect("retry same durable import"),
        1
    );
    assert_eq!(events(&sink, &tenant).len(), 1);
    assert_eq!(
        worker.receipts.lock().expect("ACK").as_slice(),
        &[commit.ack()]
    );
    assert_eq!(worker.browser_effects.load(Ordering::SeqCst), 0);
}

#[test]
fn notification_source_ack_lost_before_or_after_commit_never_duplicates_events_or_browser_effects()
{
    for fault in [LOSE_ACK_BEFORE, LOSE_ACK_AFTER] {
        let tenant = TenantId::new();
        let commit = commit(
            &tenant,
            "notification-worker",
            NotificationSourceFamily::ActionJournal,
            1,
        );
        let worker = Arc::new(Worker::new("notification-worker", vec![commit.clone()]));
        let sink = memory_sink();
        worker.ack_fault.store(fault, Ordering::SeqCst);
        let first = gateway(worker.clone(), sink.clone());
        assert!(first.reconcile_worker_notifications(32).is_err());
        drop(first);
        let restarted = gateway(worker.clone(), sink.clone());
        restarted
            .reconcile_worker_notifications(32)
            .expect("recover unknown ACK");
        let observed = events(&sink, &tenant);
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].event_id(), commit.descriptors()[0].event_id());
        assert_eq!(
            worker.receipts.lock().expect("receipt").as_slice(),
            &[commit.ack()]
        );
        assert_eq!(worker.browser_effects.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn unavailable_notification_sink_never_acknowledges_the_source() {
    let tenant = TenantId::new();
    let worker = Arc::new(Worker::new(
        "notification-worker",
        vec![commit(
            &tenant,
            "notification-worker",
            NotificationSourceFamily::ActionJournal,
            1,
        )],
    ));
    let sink = memory_sink();
    sink.mode.store(UNAVAILABLE, Ordering::SeqCst);
    let runtime = gateway(worker.clone(), sink.clone());
    assert!(runtime.reconcile_worker_notifications(32).is_err());
    assert_eq!(worker.ack_calls.load(Ordering::SeqCst), 0);
    assert!(events(&sink, &tenant).is_empty());
    sink.mode.store(HEALTHY, Ordering::SeqCst);
    runtime
        .reconcile_worker_notifications(32)
        .expect("lifecycle family");
    runtime
        .reconcile_worker_notifications(32)
        .expect("artifact family");
    runtime
        .reconcile_worker_notifications(32)
        .expect("control family");
    assert_eq!(
        runtime
            .reconcile_worker_notifications(32)
            .expect("original pending source"),
        1
    );
}

#[test]
fn wrong_response_original_worker_or_future_session_fence_never_reaches_the_sink() {
    for fault in ["response", "source", "future-fence"] {
        let tenant = TenantId::new();
        let source = if fault == "source" {
            "other-worker"
        } else {
            "notification-worker"
        };
        let epoch = if fault == "future-fence" { 8 } else { 1 };
        let worker = Arc::new(Worker::new(
            "notification-worker",
            vec![commit(
                &tenant,
                source,
                NotificationSourceFamily::ActionJournal,
                epoch,
            )],
        ));
        worker
            .wrong_response
            .store(fault == "response", Ordering::SeqCst);
        let sink = memory_sink();
        let runtime = gateway(worker.clone(), sink.clone());
        assert!(
            runtime.reconcile_worker_notifications(32).is_err(),
            "{fault}"
        );
        assert_eq!(sink.imports.load(Ordering::SeqCst), 0);
        assert_eq!(worker.ack_calls.load(Ordering::SeqCst), 0);
        assert!(events(&sink, &tenant).is_empty());
    }
}

#[test]
fn independent_families_rotate_after_failure_and_do_not_require_a_live_session() {
    let tenant = TenantId::new();
    let worker = Arc::new(Worker::new(
        "notification-worker",
        vec![
            commit(
                &tenant,
                "wrong-source",
                NotificationSourceFamily::ActionJournal,
                1,
            ),
            commit(
                &tenant,
                "notification-worker",
                NotificationSourceFamily::SessionLifecycle,
                1,
            ),
            commit(
                &tenant,
                "notification-worker",
                NotificationSourceFamily::ArtifactRegistry,
                1,
            ),
        ],
    ));
    let sink = memory_sink();
    let runtime = gateway(worker.clone(), sink.clone());
    assert!(runtime.reconcile_worker_notifications(32).is_err());
    assert_eq!(
        runtime
            .reconcile_worker_notifications(32)
            .expect("lifecycle progresses"),
        1
    );
    assert_eq!(
        runtime
            .reconcile_worker_notifications(32)
            .expect("artifact progresses"),
        1
    );
    assert_eq!(events(&sink, &tenant).len(), 2);
    assert_eq!(worker.browser_effects.load(Ordering::SeqCst), 0);
}

#[test]
fn empty_notification_scope_page_preserves_catalog_progress_until_next_family_pass() {
    let tenant = TenantId::new();
    let commit = commit(
        &tenant,
        "notification-worker",
        NotificationSourceFamily::ActionJournal,
        1,
    );
    let worker = Arc::new(Worker::new("notification-worker", vec![commit.clone()]));
    worker.scripted.lock().expect("scripts").insert(
        NotificationSourceFamily::ActionJournal,
        VecDeque::from([
            (
                None,
                WorkerNotificationPage {
                    commits: vec![],
                    cursor: Some("visited-empty-scope".to_owned()),
                    examined: 1,
                    is_complete: false,
                },
            ),
            (
                Some("visited-empty-scope".to_owned()),
                WorkerNotificationPage {
                    commits: vec![commit],
                    cursor: None,
                    examined: 1,
                    is_complete: true,
                },
            ),
        ]),
    );
    let sink = memory_sink();
    let runtime = gateway(worker.clone(), sink.clone());
    assert_eq!(
        runtime
            .reconcile_worker_notifications(1)
            .expect("empty scope"),
        0
    );
    runtime
        .reconcile_worker_notifications(1)
        .expect("lifecycle");
    runtime.reconcile_worker_notifications(1).expect("artifact");
    runtime.reconcile_worker_notifications(1).expect("control");
    assert_eq!(
        runtime
            .reconcile_worker_notifications(1)
            .expect("continued catalog"),
        1
    );
    assert_eq!(worker.ack_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn postgres_notification_import_lost_reply_survives_gateway_and_pool_restart() {
    let Ok(url) = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL") else {
        return;
    };
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let postgres = runtime
        .block_on(PostgresEventOutbox::connect(
            &url,
            2,
            StoreConfig::default(),
        ))
        .expect("owned PostgreSQL fixture");
    runtime.block_on(postgres.migrate()).expect("schema");
    let sink = Arc::new(Sink {
        inner: Arc::new(postgres),
        mode: AtomicUsize::new(LOSE_SINK_REPLY),
        imports: AtomicUsize::new(0),
    });
    let tenant = TenantId::new();
    let commit = commit(
        &tenant,
        "notification-postgres",
        NotificationSourceFamily::ActionJournal,
        1,
    );
    let worker = Arc::new(Worker::new("notification-postgres", vec![commit.clone()]));
    let first = gateway(worker.clone(), sink.clone());
    assert!(first.reconcile_worker_notifications(32).is_err());
    assert_eq!(worker.ack_calls.load(Ordering::SeqCst), 0);
    drop(first);
    drop(sink);
    let postgres = runtime
        .block_on(PostgresEventOutbox::connect(
            &url,
            2,
            StoreConfig::default(),
        ))
        .expect("reopened PostgreSQL pool");
    runtime
        .block_on(postgres.migrate())
        .expect("idempotent migrations");
    let sink = Arc::new(Sink {
        inner: Arc::new(postgres),
        mode: AtomicUsize::new(HEALTHY),
        imports: AtomicUsize::new(0),
    });
    let restarted = gateway(worker.clone(), sink.clone());
    assert_eq!(
        restarted
            .reconcile_worker_notifications(32)
            .expect("same persisted source digest"),
        1
    );
    let observed = runtime
        .block_on(sink.read_from(&tenant, EventCursor::start(), 100, Utc::now()))
        .expect("events");
    assert_eq!(observed.events().len(), 1);
    assert_eq!(
        observed.events()[0].event_id(),
        commit.descriptors()[0].event_id()
    );
    assert_eq!(
        worker.receipts.lock().expect("receipt").as_slice(),
        &[commit.ack()]
    );
    assert_eq!(worker.browser_effects.load(Ordering::SeqCst), 0);
}

#[test]
fn unavailable_fleet_peer_rotates_to_other_peer_original_historical_notifications() {
    let tenant = TenantId::new();
    let first = Arc::new(Worker::new("notification-a", vec![]));
    first.offline.store(true, Ordering::SeqCst);
    let second = Arc::new(Worker::new(
        "notification-b",
        vec![commit(
            &tenant,
            "notification-b",
            NotificationSourceFamily::ArtifactRegistry,
            1,
        )],
    ));
    let peers = [first.clone(), second.clone()];
    let config = Arc::new(
        GatewayFleetAdmissionConfig::new(
            "fixture",
            peers
                .iter()
                .map(|worker| {
                    GatewayFleetWorker::new(
                        worker.id.clone(),
                        format!("/private/{}.sock", worker.id),
                        "fixture",
                        vec![[8; 32]],
                        vec![[7; 32]],
                        capacity(),
                        None,
                    )
                    .expect("worker policy")
                })
                .collect(),
            vec![
                GatewayFleetProfile::new(
                    [7; 32],
                    [8; 32],
                    GatewaySessionIsolation::DedicatedProcess,
                    GatewaySessionWorkload::Interactive,
                    capacity(),
                    1,
                )
                .expect("profile"),
            ],
            GatewayFleetTenantPolicy::new(1, capacity(), 1, 1, 64).expect("tenant policy"),
            vec![],
            GatewayFleetAdmissionLimits::new(128, 64, 32, 16, capacity()).expect("limits"),
        )
        .expect("fleet policy"),
    );
    let inventory = GatewayFleetInventory::new(
        config,
        peers
            .iter()
            .map(|worker| {
                GatewayFleetPeer::new(
                    worker.id.clone(),
                    format!("/private/{}.sock", worker.id),
                    7,
                    worker.clone(),
                )
                .expect("peer")
            })
            .collect(),
    )
    .expect("inventory");
    let creates = CoordinationBlockingClient::spawn(
        Arc::new(MemoryCreateSessionStore::default()),
        CoordinationActorConfig::default(),
    )
    .expect("create authority");
    let sink = memory_sink();
    let runtime = gateway(first, sink.clone()).with_fleet(inventory, creates);
    for _ in 0..4 {
        assert!(runtime.reconcile_worker_notifications(32).is_err());
    }
    assert_eq!(
        runtime
            .reconcile_worker_notifications(32)
            .expect("other peer action"),
        0
    );
    assert_eq!(
        runtime
            .reconcile_worker_notifications(32)
            .expect("other peer lifecycle"),
        0
    );
    assert_eq!(
        runtime
            .reconcile_worker_notifications(32)
            .expect("other peer artifact"),
        1
    );
    assert_eq!(events(&sink, &tenant).len(), 1);
    assert_eq!(second.browser_effects.load(Ordering::SeqCst), 0);
}
