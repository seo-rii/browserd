//! Shared Memory/actual-Postgres source-import behavior, including durable ACK recovery.
#![allow(clippy::expect_used)]

use browserd_coordination::{
    EventActionState, EventCursor, EventNotificationKind, EventOutbox, EventOutboxError,
    EventStateSummary, MemoryEventOutbox, NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE,
    NotificationImportConfig, OutboxAggregate, OutboxAppend, OutboxEventKind, PostgresEventOutbox,
    StoreConfig, encode_outbox_event,
};
use browserd_core::{
    ActionId, ApprovalId, ArtifactId, NotificationActionState, NotificationApprovalDecision,
    NotificationArtifactState, NotificationCommit, NotificationControlState,
    NotificationDescriptor, NotificationSessionExecutionState, NotificationSessionLifecycleState,
    NotificationSessionScope, NotificationSourceFamily, NotificationSourceScope, PlacementFence,
    SessionId, TenantId, WorkerId, WorkerNotificationEvent,
};
use chrono::{DateTime, TimeZone, Utc};
use sqlx::{
    Row, SqlSafeStr,
    postgres::{PgPool, PgPoolOptions},
};
use uuid::Uuid;

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + seconds, 0)
        .single()
        .expect("timestamp")
}

fn source(tenant: &TenantId, family: NotificationSourceFamily) -> NotificationSourceScope {
    NotificationSourceScope::new(
        tenant.clone(),
        WorkerId::new("notification-fixture").expect("worker"),
        Uuid::new_v4(),
        family,
    )
    .expect("source")
}

fn commit(
    scope: &NotificationSourceScope,
    sequence: u64,
    session: &SessionId,
    when: DateTime<Utc>,
    events: Vec<WorkerNotificationEvent>,
) -> NotificationCommit {
    let session_scope =
        NotificationSessionScope::new(session.clone(), PlacementFence::new(7, 11, 13))
            .expect("original fence");
    NotificationCommit::new(
        scope.clone(),
        sequence,
        u64::try_from(when.timestamp_millis()).expect("nonnegative time"),
        events
            .into_iter()
            .map(|event| {
                NotificationDescriptor::fresh(session_scope.clone(), event).expect("descriptor")
            })
            .collect(),
    )
    .expect("commit")
}

fn action_event(action: ActionId, state: NotificationActionState) -> WorkerNotificationEvent {
    WorkerNotificationEvent::ActionStateChanged {
        action_id: action,
        state,
        resolution: None,
    }
}

async fn all_worker_kinds(store: &dyn EventOutbox) {
    let tenant = TenantId::new();
    let session = SessionId::new();
    let action = ActionId::new();
    let approval = ApprovalId::new();
    let artifact = ArtifactId::new();
    let groups = [
        (
            NotificationSourceFamily::SessionLifecycle,
            vec![
                WorkerNotificationEvent::SessionLifecycleChanged {
                    state: NotificationSessionLifecycleState::Ready,
                },
                WorkerNotificationEvent::SessionExecutionChanged {
                    state: NotificationSessionExecutionState::Running,
                    action_id: Some(action.clone()),
                },
            ],
        ),
        (
            NotificationSourceFamily::ActionJournal,
            vec![
                action_event(action.clone(), NotificationActionState::PendingApproval),
                WorkerNotificationEvent::ActionApprovalRequired {
                    action_id: action.clone(),
                    approval_id: approval.clone(),
                },
                WorkerNotificationEvent::ApprovalDecided {
                    action_id: action.clone(),
                    approval_id: approval,
                    state: NotificationApprovalDecision::Approved,
                },
            ],
        ),
        (
            NotificationSourceFamily::ControlJournal,
            vec![WorkerNotificationEvent::BrowserControlChanged {
                state: NotificationControlState::Human,
            }],
        ),
        (
            NotificationSourceFamily::ArtifactRegistry,
            vec![
                WorkerNotificationEvent::DownloadCompleted {
                    artifact_id: artifact.clone(),
                },
                WorkerNotificationEvent::ArtifactStateChanged {
                    artifact_id: artifact,
                    state: NotificationArtifactState::Available,
                },
            ],
        ),
    ];
    let mut expected_ids = Vec::new();
    for (family, events) in groups {
        let item = commit(&source(&tenant, family), 1, &session, at(-90_000), events);
        expected_ids.extend(
            item.descriptors()
                .iter()
                .map(NotificationDescriptor::event_id),
        );
        assert_eq!(
            store
                .append_notification_commit(item.clone(), at(0))
                .await
                .expect("atomic import"),
            item.ack()
        );
    }
    let page = store
        .read_from(&tenant, EventCursor::start(), 10, at(0))
        .await
        .expect("events");
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.event_id())
            .collect::<Vec<_>>(),
        expected_ids
    );
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.public_wire().kind)
            .collect::<Vec<_>>(),
        vec![
            EventNotificationKind::SessionLifecycleChanged,
            EventNotificationKind::SessionExecutionChanged,
            EventNotificationKind::ActionStateChanged,
            EventNotificationKind::ActionApprovalRequired,
            EventNotificationKind::ApprovalDecided,
            EventNotificationKind::BrowserControlChanged,
            EventNotificationKind::DownloadCompleted,
            EventNotificationKind::ArtifactStateChanged,
        ]
    );
    for (index, event) in page.events().iter().enumerate() {
        assert_eq!(event.cursor().position(), index as u64 + 1);
        assert_eq!(event.created_at(), at(-90_000));
        assert_eq!(event.aggregate_revision(), 1);
        assert!(event.summary().is_some());
        let bytes = encode_outbox_event(event).expect("safe deterministic public body");
        assert!(
            !String::from_utf8(bytes)
                .expect("UTF8")
                .contains("notification-fixture")
        );
    }
    // The source occurred more than a day ago, but each newly imported event receives a full day.
    assert_eq!(
        store
            .read_from(&tenant, EventCursor::start(), 10, at(86_399))
            .await
            .expect("retained")
            .events()
            .len(),
        8
    );
    assert!(
        store
            .read_from(&tenant, EventCursor::start(), 10, at(86_401))
            .await
            .expect("pruned")
            .events()
            .is_empty()
    );
}

async fn gaps_conflicts_and_pruned_retry(store: &dyn EventOutbox) {
    let tenant = TenantId::new();
    let session = SessionId::new();
    let scope = source(&tenant, NotificationSourceFamily::ActionJournal);
    let first = commit(
        &scope,
        1,
        &session,
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    let second = commit(
        &scope,
        2,
        &session,
        at(1),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Queued,
        )],
    );
    assert_eq!(
        store
            .append_notification_commit(second.clone(), at(1))
            .await,
        Err(EventOutboxError::ProjectionGap)
    );
    let (left, right) = tokio::join!(
        store.append_notification_commit(first.clone(), at(0)),
        store.append_notification_commit(first.clone(), at(0)),
    );
    assert_eq!(left.expect("first concurrent import"), first.ack());
    assert_eq!(right.expect("second concurrent import"), first.ack());
    let changed = commit(
        &scope,
        1,
        &session,
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::FailedKnown,
        )],
    );
    assert_eq!(
        store.append_notification_commit(changed, at(1)).await,
        Err(EventOutboxError::NotificationDigestMismatch)
    );
    assert_eq!(
        store
            .append_notification_commit(second.clone(), at(1))
            .await
            .expect("contiguous import"),
        second.ack()
    );
    let page = store
        .read_from(&tenant, EventCursor::start(), 10, at(90_000))
        .await
        .expect("prune");
    assert!(page.events().is_empty());
    assert!(page.cursor_expired());
    assert_eq!(
        store
            .append_notification_commit(first.clone(), at(90_001))
            .await
            .expect("lost ACK replay"),
        first.ack()
    );
    assert_eq!(
        store
            .append_notification_commit(second.clone(), at(90_001))
            .await
            .expect("latest ACK replay"),
        second.ack()
    );
    assert!(
        store
            .read_from(&tenant, EventCursor::start(), 10, at(90_001))
            .await
            .expect("never resurrect")
            .events()
            .is_empty()
    );
    let third = commit(
        &scope,
        3,
        &session,
        at(90_002),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Succeeded,
        )],
    );
    store
        .append_notification_commit(third.clone(), at(90_002))
        .await
        .expect("permanent highwater continues");
    let page = store
        .read_from(&tenant, EventCursor::from_position(2), 10, at(90_002))
        .await
        .expect("new tail");
    assert_eq!(page.events().len(), 1);
    assert_eq!(
        page.events()[0].event_id(),
        third.descriptors()[0].event_id()
    );
    assert_eq!(page.next_cursor().position(), 3);
}

async fn bounded_receipts(store: &dyn EventOutbox) {
    let tenant = TenantId::new();
    let session = SessionId::new();
    let scope = source(&tenant, NotificationSourceFamily::ActionJournal);
    let mut original = Vec::new();
    for sequence in 1..=NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE as u64 + 1 {
        let item = commit(
            &scope,
            sequence,
            &session,
            at(0),
            vec![action_event(
                ActionId::new(),
                NotificationActionState::Accepted,
            )],
        );
        store
            .append_notification_commit(item.clone(), at(0))
            .await
            .expect("contiguous source");
        original.push(item);
    }
    store
        .read_from(&tenant, EventCursor::start(), 100, at(90_000))
        .await
        .expect("payload pruning");
    assert_eq!(
        store
            .append_notification_commit(original[0].clone(), at(90_000))
            .await,
        Err(EventOutboxError::NotificationReceiptExpired)
    );
    assert_eq!(
        store
            .append_notification_commit(original[1].clone(), at(90_000))
            .await
            .expect("oldest retained exact receipt"),
        original[1].ack()
    );
    assert!(
        store
            .read_from(&tenant, EventCursor::start(), 100, at(90_000))
            .await
            .expect("no old events")
            .events()
            .is_empty()
    );
    let last = original.last().expect("latest");
    assert_eq!(
        store
            .append_notification_commit(last.clone(), at(90_000))
            .await
            .expect("latest ACK"),
        last.ack()
    );
}

async fn partial_batch_conflict_rolls_back(store: &dyn EventOutbox) {
    let tenant = TenantId::new();
    let session = SessionId::new();
    let existing_action = ActionId::new();
    store
        .append(
            OutboxAppend::state_changed(
                tenant.clone(),
                OutboxAggregate::Action {
                    session_id: session.clone(),
                    action_id: existing_action.clone(),
                },
                1,
                OutboxEventKind::ActionStateChanged,
                EventStateSummary::Action {
                    state: EventActionState::Accepted,
                    resolution: None,
                },
            )
            .expect("legacy typed append"),
            at(0),
        )
        .await
        .expect("existing event");
    let scope = source(&tenant, NotificationSourceFamily::ActionJournal);
    let first_action = ActionId::new();
    let batch = commit(
        &scope,
        1,
        &session,
        at(0),
        vec![
            action_event(first_action.clone(), NotificationActionState::Accepted),
            action_event(existing_action, NotificationActionState::FailedKnown),
        ],
    );
    assert_eq!(
        store.append_notification_commit(batch, at(0)).await,
        Err(EventOutboxError::ConflictingEvent)
    );
    let page = store
        .read_from(&tenant, EventCursor::start(), 10, at(0))
        .await
        .expect("batch rolled back");
    assert_eq!(page.events().len(), 1);
    assert_eq!(page.next_cursor().position(), 1);
    let corrected = commit(
        &scope,
        1,
        &session,
        at(0),
        vec![action_event(
            first_action,
            NotificationActionState::Accepted,
        )],
    );
    store
        .append_notification_commit(corrected.clone(), at(0))
        .await
        .expect("failed batch did not advance watermark");
    let page = store
        .read_from(&tenant, EventCursor::start(), 10, at(0))
        .await
        .expect("retry");
    assert_eq!(page.events().len(), 2);
    assert_eq!(
        page.events()[1].event_id(),
        corrected.descriptors()[0].event_id()
    );
}

async fn original_source_scope_and_fence_are_bound(store: &dyn EventOutbox) {
    let tenant = TenantId::new();
    let other_tenant = TenantId::new();
    let session = SessionId::new();
    // WorkerId permits 255 bytes; durable import must support the complete valid domain.
    let scope = NotificationSourceScope::new(
        tenant.clone(),
        WorkerId::new("w".repeat(255)).expect("full worker identifier"),
        Uuid::new_v4(),
        NotificationSourceFamily::ActionJournal,
    )
    .expect("scope");
    let first = commit(
        &scope,
        1,
        &session,
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    store
        .append_notification_commit(first.clone(), at(0))
        .await
        .expect("original scope");
    let changed_fence = NotificationCommit::new(
        scope.clone(),
        1,
        first.occurred_at_unix_ms(),
        vec![
            NotificationDescriptor::new(
                first.descriptors()[0].event_id(),
                NotificationSessionScope::new(session.clone(), PlacementFence::new(8, 11, 13))
                    .expect("different original boot"),
                first.descriptors()[0].event().clone(),
            )
            .expect("valid descriptor"),
        ],
    )
    .expect("changed immutable scope");
    assert_eq!(
        store
            .append_notification_commit(changed_fence.clone(), at(0))
            .await,
        Err(EventOutboxError::NotificationDigestMismatch)
    );
    let other_scope = NotificationSourceScope::new(
        other_tenant.clone(),
        scope.original_worker_id().clone(),
        scope.source_id(),
        scope.family(),
    )
    .expect("independent tenant");
    let other = commit(
        &other_scope,
        1,
        &session,
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    store
        .append_notification_commit(other, at(0))
        .await
        .expect("same source UUID in other tenant is independent");
    let other_worker = NotificationSourceScope::new(
        tenant.clone(),
        WorkerId::new("other-worker").expect("worker"),
        scope.source_id(),
        scope.family(),
    )
    .expect("different original worker");
    let gap = commit(
        &other_worker,
        2,
        &SessionId::new(),
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    assert_eq!(
        store.append_notification_commit(gap, at(0)).await,
        Err(EventOutboxError::ProjectionGap)
    );
    let worker_first = commit(
        &other_worker,
        1,
        &SessionId::new(),
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    store
        .append_notification_commit(worker_first, at(0))
        .await
        .expect("different worker stream starts at one");
    assert_eq!(
        store
            .read_from(&tenant, EventCursor::start(), 10, at(0))
            .await
            .expect("tenant events")
            .events()
            .len(),
        2
    );
    assert_eq!(
        store
            .read_from(&other_tenant, EventCursor::start(), 10, at(0))
            .await
            .expect("other tenant events")
            .events()
            .len(),
        1
    );
    store
        .read_from(&tenant, EventCursor::start(), 10, at(90_000))
        .await
        .expect("prune");
    assert_eq!(
        store
            .append_notification_commit(changed_fence, at(90_000))
            .await,
        Err(EventOutboxError::NotificationDigestMismatch)
    );
}

async fn capacity_and_existing_retry(store: &dyn EventOutbox) {
    let tenant_a = TenantId::new();
    let session = SessionId::new();
    let scope = source(&tenant_a, NotificationSourceFamily::ActionJournal);
    let first = commit(
        &scope,
        1,
        &session,
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    store
        .append_notification_commit(first.clone(), at(0))
        .await
        .expect("first source");
    let excess_tenant = commit(
        &source(&tenant_a, NotificationSourceFamily::ActionJournal),
        1,
        &session,
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    assert_eq!(
        store.append_notification_commit(excess_tenant, at(0)).await,
        Err(EventOutboxError::NotificationSourceCapacity)
    );
    for _ in 0..2 {
        let tenant = TenantId::new();
        let item = commit(
            &source(&tenant, NotificationSourceFamily::ActionJournal),
            1,
            &session,
            at(0),
            vec![action_event(
                ActionId::new(),
                NotificationActionState::Accepted,
            )],
        );
        store
            .append_notification_commit(item, at(0))
            .await
            .expect("namespace source");
    }
    let extra = commit(
        &source(&TenantId::new(), NotificationSourceFamily::ActionJournal),
        1,
        &session,
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    assert_eq!(
        store.append_notification_commit(extra, at(0)).await,
        Err(EventOutboxError::NotificationSourceCapacity)
    );
    store
        .read_from(&tenant_a, EventCursor::start(), 10, at(90_000))
        .await
        .expect("prune");
    assert_eq!(
        store
            .append_notification_commit(first.clone(), at(90_001))
            .await
            .expect("retry at full lifetime quota"),
        first.ack()
    );
    let next = commit(
        &scope,
        2,
        &session,
        at(90_001),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Queued,
        )],
    );
    store
        .append_notification_commit(next, at(90_001))
        .await
        .expect("existing source progresses at capacity");
}

#[tokio::test]
async fn memory_all_worker_families_and_delayed_retention() {
    all_worker_kinds(&MemoryEventOutbox::default()).await;
}

#[tokio::test]
async fn memory_gaps_conflicts_and_payload_prune_preserve_exact_ack() {
    gaps_conflicts_and_pruned_retry(&MemoryEventOutbox::default()).await;
}

#[tokio::test]
async fn memory_receipts_are_bounded_and_missing_old_digest_fails_closed() {
    bounded_receipts(&MemoryEventOutbox::default()).await;
}

#[tokio::test]
async fn memory_partial_batch_never_advances_cursor_or_watermark() {
    partial_batch_conflict_rolls_back(&MemoryEventOutbox::default()).await;
}

#[tokio::test]
async fn memory_original_worker_tenant_and_full_fence_are_isolated() {
    original_source_scope_and_fence_are_bound(&MemoryEventOutbox::default()).await;
}

#[test]
fn lifetime_notification_quota_configuration_is_bounded() {
    assert_eq!(
        NotificationImportConfig::new(0, 1),
        Err(EventOutboxError::InvalidNotificationImportConfig)
    );
    assert_eq!(
        NotificationImportConfig::new(1, 0),
        Err(EventOutboxError::InvalidNotificationImportConfig)
    );
    assert_eq!(
        NotificationImportConfig::new(1, 2),
        Err(EventOutboxError::InvalidNotificationImportConfig)
    );
    assert_eq!(
        NotificationImportConfig::new(usize::MAX, 1),
        Err(EventOutboxError::InvalidNotificationImportConfig)
    );
}

#[tokio::test]
async fn memory_immutable_lifetime_quotas_allow_existing_source_retries() {
    let store = MemoryEventOutbox::default()
        .with_notification_import_config(NotificationImportConfig::new(3, 1).expect("quota"))
        .expect("config");
    capacity_and_existing_retry(&store).await;
    assert!(matches!(
        store.clone().with_notification_import_config(
            NotificationImportConfig::new(4, 1).expect("other quota")
        ),
        Err(EventOutboxError::InvalidNotificationImportConfig)
    ));
}

struct PostgresFixture {
    admin: PgPool,
    store: PostgresEventOutbox,
    schema: String,
}
impl PostgresFixture {
    async fn create(config: NotificationImportConfig) -> Option<Self> {
        let Ok(url) = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL") else {
            eprintln!("skipping actual Postgres notification import: fixture URL is unset");
            return None;
        };
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("owned fixture reachable");
        let schema = format!("notification_import_{}", Uuid::new_v4().simple());
        // Identifier is a fixed prefix followed only by generated hexadecimal UUID bytes.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")).into_sql_str())
            .execute(&admin)
            .await
            .expect("isolated schema");
        let pool = Self::pool(&url, &schema).await;
        let store = PostgresEventOutbox::new(pool, StoreConfig::default())
            .with_notification_import_config(config);
        store
            .migrate()
            .await
            .expect("independent histories migrate");
        Some(Self {
            admin,
            store,
            schema,
        })
    }

    async fn pool(url: &str, schema: &str) -> PgPool {
        assert!(
            schema
                .strip_prefix("notification_import_")
                .is_some_and(|suffix| suffix.len() == 32
                    && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
        );
        let schema = schema.to_owned();
        PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |connection, _metadata| {
                let sql = format!("SET search_path TO {schema}");
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(sql).into_sql_str())
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(url)
            .await
            .expect("isolated pool")
    }

    async fn reconnect(&self, config: NotificationImportConfig) -> PostgresEventOutbox {
        let url = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL").expect("fixture URL");
        PostgresEventOutbox::new(Self::pool(&url, &self.schema).await, StoreConfig::default())
            .with_notification_import_config(config)
    }

    async fn finish(self) {
        self.store.pool().close().await;
        // schema is the same private, UUID-generated identifier accepted by pool().
        sqlx::query(
            sqlx::AssertSqlSafe(format!("DROP SCHEMA {} CASCADE", self.schema)).into_sql_str(),
        )
        .execute(&self.admin)
        .await
        .expect("owned schema cleanup");
        self.admin.close().await;
    }
}

#[tokio::test]
async fn postgres_all_worker_families_and_delayed_retention() {
    let Some(fixture) = PostgresFixture::create(NotificationImportConfig::default()).await else {
        return;
    };
    all_worker_kinds(&fixture.store).await;
    fixture.finish().await;
}

#[tokio::test]
async fn postgres_gaps_conflicts_and_payload_prune_preserve_exact_ack() {
    let Some(fixture) = PostgresFixture::create(NotificationImportConfig::default()).await else {
        return;
    };
    gaps_conflicts_and_pruned_retry(&fixture.store).await;
    partial_batch_conflict_rolls_back(&fixture.store).await;
    original_source_scope_and_fence_are_bound(&fixture.store).await;
    fixture.finish().await;
}

#[tokio::test]
async fn postgres_timestamp_precision_cannot_shorten_import_retention() {
    let Some(fixture) = PostgresFixture::create(NotificationImportConfig::default()).await else {
        return;
    };
    let tenant = TenantId::new();
    let imported_at = at(0) + chrono::Duration::nanoseconds(1);
    let item = commit(
        &source(&tenant, NotificationSourceFamily::ActionJournal),
        1,
        &SessionId::new(),
        at(-90_000),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    fixture
        .store
        .append_notification_commit(item, imported_at)
        .await
        .expect("precise import");
    assert_eq!(
        fixture
            .store
            .read_from(&tenant, EventCursor::start(), 10, at(86_400))
            .await
            .expect("full day has not elapsed")
            .events()
            .len(),
        1
    );
    assert!(
        fixture
            .store
            .read_from(
                &tenant,
                EventCursor::start(),
                10,
                at(86_400) + chrono::Duration::microseconds(1)
            )
            .await
            .expect("rounded retention elapsed")
            .events()
            .is_empty()
    );
    fixture.finish().await;
}

#[tokio::test]
async fn postgres_bounded_receipts_survive_payload_retention() {
    let Some(fixture) = PostgresFixture::create(NotificationImportConfig::default()).await else {
        return;
    };
    bounded_receipts(&fixture.store).await;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM browserd_notification_import_receipt")
            .fetch_one(fixture.store.pool())
            .await
            .expect("receipt count");
    assert_eq!(count, NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE as i64);
    fixture.finish().await;
}

#[tokio::test]
async fn postgres_lifetime_quota_and_configuration_survive_reconnect() {
    let config = NotificationImportConfig::new(3, 1).expect("quota");
    let Some(fixture) = PostgresFixture::create(config).await else {
        return;
    };
    capacity_and_existing_retry(&fixture.store).await;
    let incompatible = fixture
        .reconnect(NotificationImportConfig::new(4, 1).expect("other quota"))
        .await;
    let next = commit(
        &source(&TenantId::new(), NotificationSourceFamily::ActionJournal),
        1,
        &SessionId::new(),
        at(0),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    assert_eq!(
        incompatible.append_notification_commit(next, at(0)).await,
        Err(EventOutboxError::InvalidNotificationImportConfig)
    );
    incompatible.pool().close().await;
    fixture.finish().await;
}

#[tokio::test]
async fn postgres_restart_after_pruning_keeps_original_ack_without_resurrection() {
    let Some(fixture) = PostgresFixture::create(NotificationImportConfig::default()).await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let scope = source(&tenant, NotificationSourceFamily::ActionJournal);
    let first = commit(
        &scope,
        1,
        &session,
        at(-90_000),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Accepted,
        )],
    );
    fixture
        .store
        .append_notification_commit(first.clone(), at(0))
        .await
        .expect("import before ACK loss");
    fixture
        .store
        .read_from(&tenant, EventCursor::start(), 10, at(90_000))
        .await
        .expect("prune");
    let restarted = fixture.reconnect(NotificationImportConfig::default()).await;
    restarted
        .migrate()
        .await
        .expect("reopen existing migration histories");
    assert_eq!(
        restarted
            .append_notification_commit(first.clone(), at(90_001))
            .await
            .expect("durable exact ACK"),
        first.ack()
    );
    assert!(
        restarted
            .read_from(&tenant, EventCursor::start(), 10, at(90_001))
            .await
            .expect("no resurrection")
            .events()
            .is_empty()
    );
    let next = commit(
        &scope,
        2,
        &session,
        at(90_002),
        vec![action_event(
            ActionId::new(),
            NotificationActionState::Queued,
        )],
    );
    restarted
        .append_notification_commit(next.clone(), at(90_002))
        .await
        .expect("durable next sequence");
    let page = restarted
        .read_from(&tenant, EventCursor::from_position(1), 10, at(90_002))
        .await
        .expect("next tail");
    assert_eq!(page.next_cursor().position(), 2);
    assert_eq!(
        page.events()[0].event_id(),
        next.descriptors()[0].event_id()
    );
    restarted.pool().close().await;
    fixture.finish().await;
}

#[tokio::test]
async fn postgres_second_insert_failure_rolls_back_rows_cursor_watermark_receipts_and_quota() {
    let Some(fixture) = PostgresFixture::create(NotificationImportConfig::default()).await else {
        return;
    };
    sqlx::query("ALTER TABLE browserd_event_outbox ADD CONSTRAINT reject_second_notification CHECK (state_summary->>'state' IS DISTINCT FROM 'failed_known')").execute(fixture.store.pool()).await.expect("owned schema fault injection");
    let tenant = TenantId::new();
    let scope = source(&tenant, NotificationSourceFamily::ActionJournal);
    let batch = commit(
        &scope,
        1,
        &SessionId::new(),
        at(0),
        vec![
            action_event(ActionId::new(), NotificationActionState::Accepted),
            action_event(ActionId::new(), NotificationActionState::FailedKnown),
        ],
    );
    assert_eq!(
        fixture
            .store
            .append_notification_commit(batch.clone(), at(0))
            .await,
        Err(EventOutboxError::PostgresUnavailable)
    );
    for table in [
        "browserd_event_outbox",
        "browserd_event_outbox_cursor",
        "browserd_notification_source_watermark",
        "browserd_notification_import_receipt",
    ] {
        // Every interpolated table identifier comes exclusively from the fixed literal list above.
        let count: i64 = sqlx::query_scalar(
            sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")).into_sql_str(),
        )
        .fetch_one(fixture.store.pool())
        .await
        .expect("rollback row count");
        assert_eq!(count, 0, "{table} must roll back");
    }
    let namespace = sqlx::query("SELECT config_sha256,source_count FROM browserd_notification_import_namespace WHERE singleton=TRUE").fetch_one(fixture.store.pool()).await.expect("namespace");
    assert_eq!(namespace.get::<i64, _>("source_count"), 0);
    assert!(
        namespace
            .get::<Option<Vec<u8>>, _>("config_sha256")
            .is_none()
    );
    sqlx::query("ALTER TABLE browserd_event_outbox DROP CONSTRAINT reject_second_notification")
        .execute(fixture.store.pool())
        .await
        .expect("remove injected failure");
    assert_eq!(
        fixture
            .store
            .append_notification_commit(batch.clone(), at(0))
            .await
            .expect("original source retry after rollback"),
        batch.ack()
    );
    let page = fixture
        .store
        .read_from(&tenant, EventCursor::start(), 10, at(0))
        .await
        .expect("whole batch");
    assert_eq!(page.events().len(), 2);
    assert_eq!(page.next_cursor().position(), 2);
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.event_id())
            .collect::<Vec<_>>(),
        batch
            .descriptors()
            .iter()
            .map(NotificationDescriptor::event_id)
            .collect::<Vec<_>>()
    );
    fixture.finish().await;
}
