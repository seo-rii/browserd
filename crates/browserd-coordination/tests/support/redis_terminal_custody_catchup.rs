use super::redis_action_custody::cases::Action;
use super::redis_action_retention::set_deadline;
use super::*;
use browserd_actions::{TerminalCustodyReceipt, TerminalCustodyRequirement};
use browserd_coordination::{
    GatewayActionRecoveryCursor, GatewayActionRetentionCursor, GatewayActionSnapshot,
    GatewayCustodyCursor,
};

async fn connection(f: &RedisFixture) -> redis::aio::MultiplexedConnection {
    redis::Client::open(f.endpoint.as_str())
        .expect("endpoint")
        .get_multiplexed_async_connection()
        .await
        .expect("connection")
}
fn namespace(f: &RedisFixture, tenant: &TenantId, session: &SessionId) -> String {
    format!("{}:gateway-action:{{{tenant}:{session}}}", f.prefix)
}
async fn missing(
    f: &RedisFixture,
    requirement: Option<TerminalCustodyRequirement>,
    unknown: bool,
) -> (Action, GatewayActionSnapshot, TerminalCustodyReceipt) {
    let action = Action::new(f.store.as_ref()).await;
    let detail = if unknown {
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch)
    } else {
        TerminalDetail::Succeeded(ResultDigest::new([17; 32]))
    };
    let receipt = action.receipt(detail, None);
    let row = if unknown {
        f.store
            .record_worker_terminal_with_custody(
                &action.tenant,
                &action.session,
                &action.action,
                action.armed.revision(),
                &action.placement,
                &action.dispatch,
                action.armed.action_sequence(),
                detail,
                None,
                requirement,
                Utc::now(),
            )
            .await
            .expect("worker terminal without receipt")
    } else {
        f.store
            .record_worker_result_with_custody(
                &action.tenant,
                &action.session,
                &action.action,
                action.armed.revision(),
                &action.placement,
                &action.dispatch,
                action.armed.action_sequence(),
                BrowserResult::Succeeded(ResultDigest::new([17; 32])),
                Some(b"preserved-result".to_vec()),
                None,
                requirement,
                Utc::now(),
            )
            .await
            .expect("worker result without receipt")
    };
    (action, row, receipt)
}
async fn attach(
    store: &RedisGatewayActionStore,
    action: &Action,
    revision: u64,
    receipt: TerminalCustodyReceipt,
) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
    store
        .attach_terminal_custody(
            &action.tenant,
            &action.session,
            &action.action,
            revision,
            &action.placement,
            receipt,
        )
        .await
}
async fn scan(
    store: &RedisGatewayActionStore,
) -> browserd_coordination::GatewayTerminalCustodyCatchupPage {
    store
        .scan_terminal_custody_catchup(GatewayActionRecoveryCursor::default(), 256)
        .await
        .expect("catalog catchup")
}
async fn strip_origin(f: &RedisFixture, action: &Action) -> String {
    let key = format!("{}:actions", namespace(f, &action.tenant, &action.session));
    let mut connection = connection(f).await;
    let raw: String = redis::cmd("HGET")
        .arg(&key)
        .arg(action.action.to_string())
        .query_async(&mut connection)
        .await
        .expect("payload");
    let mut value: serde_json::Value = serde_json::from_str(&raw).expect("json");
    value
        .as_object_mut()
        .expect("object")
        .remove("custody_requirement");
    value
        .as_object_mut()
        .expect("object")
        .remove("original_worker_terminal_revision");
    let legacy = serde_json::to_string(&value).expect("legacy JSON");
    redis::cmd("HSET")
        .arg(key)
        .arg(action.action.to_string())
        .arg(&legacy)
        .query_async::<()>(&mut connection)
        .await
        .expect("legacy fields absent");
    legacy
}

#[tokio::test]
async fn redis_missing_custody_survives_horizon_restart_and_exact_attachment_changes_no_result_or_event()
 {
    let Some(f) = redis_fixture("catchup-restart").await else {
        return;
    };
    let (action, terminal, receipt) =
        missing(&f, Some(TerminalCustodyRequirement::Required), false).await;
    assert_eq!(
        terminal.original_worker_terminal_revision(),
        Some(terminal.revision())
    );
    action.events(f.store.as_ref()).await;
    set_deadline(&f, &terminal, 1).await;
    assert_eq!(
        f.store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await
            .expect("missing receipt pins")
            .deferred(),
        1
    );
    let reopened = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("restart");
    let page = scan(&reopened).await;
    assert_eq!(page.examined(), 1);
    assert_eq!(page.actions().len(), 1);
    let before = page.actions()[0].clone();
    let attached = attach(&reopened, &action, before.revision(), receipt.clone())
        .await
        .expect("attach exact worker custody");
    assert_eq!(attached.revision(), before.revision());
    assert_eq!(attached.updated_at(), before.updated_at());
    assert_eq!(attached.retain_until(), before.retain_until());
    assert_eq!(
        attached.last_source_event_sequence(),
        before.last_source_event_sequence()
    );
    assert_eq!(attached.result_content(), before.result_content());
    assert_eq!(attached.terminal(), before.terminal());
    assert_eq!(attached.resolution(), before.resolution());
    assert!(!attached.requires_terminal_custody_catchup());
    assert_eq!(
        attach(&reopened, &action, before.revision(), receipt)
            .await
            .expect("lost attach response exact retry"),
        attached
    );
    assert!(
        reopened
            .peek_event_projection(&action.tenant, &action.session)
            .await
            .expect("no source append")
            .is_none()
    );
    assert!(scan(&reopened).await.actions().is_empty());
    let copy = reopened
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("copy queue")
        .entries()[0]
        .clone();
    reopened
        .ack_pending_custody(&copy, Utc::now())
        .await
        .expect("copy ack");
    assert_eq!(
        reopened
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await
            .expect("release pins")
            .deferred(),
        1
    );
    super::redis_action_custody::cases::release_entry(&reopened, &copy).await;
    assert_eq!(
        reopened
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await
            .expect("released exact terminal eligible")
            .reclaimed(),
        1
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_only_original_explicit_unsupported_allows_custody_free_retirement() {
    let Some(f) = redis_fixture("catchup-unsupported").await else {
        return;
    };
    let (unsupported, row, _) =
        missing(&f, Some(TerminalCustodyRequirement::Unsupported), false).await;
    let (legacy, legacy_row, _) = missing(&f, None, false).await;
    assert!(!row.requires_terminal_custody_catchup());
    assert!(legacy_row.requires_terminal_custody_catchup());
    unsupported.events(f.store.as_ref()).await;
    legacy.events(f.store.as_ref()).await;
    set_deadline(&f, &row, 1).await;
    set_deadline(&f, &legacy_row, 2).await;
    let sweep = f
        .store
        .maintain_action_retention(GatewayActionRetentionCursor::default(), 2)
        .await
        .expect("bounded GC");
    assert_eq!((sweep.reclaimed(), sweep.deferred()), (1, 1));
    assert!(matches!(
        f.store
            .record_worker_result_with_custody(
                &legacy.tenant,
                &legacy.session,
                &legacy.action,
                legacy_row.revision(),
                &legacy.placement,
                &legacy.dispatch,
                legacy.armed.action_sequence(),
                BrowserResult::Succeeded(ResultDigest::new([17; 32])),
                Some(b"preserved-result".to_vec()),
                None,
                Some(TerminalCustodyRequirement::Unsupported),
                Utc::now()
            )
            .await,
        Err(GatewayActionCoordinationError::InvalidCustodyReceipt)
    ));
    let page = scan(&f.store).await;
    assert_eq!(page.actions().len(), 1);
    assert_eq!(page.actions()[0].action_id(), &legacy.action);
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_late_custody_uses_original_worker_revision_after_gateway_annotation() {
    let Some(f) = redis_fixture("catchup-historical").await else {
        return;
    };
    let (action, unknown, receipt) =
        missing(&f, Some(TerminalCustodyRequirement::Required), true).await;
    let annotation = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        PrincipalId::new(),
        42,
        "operator reconciled independently",
    );
    let resolved = f
        .store
        .resolve_unknown(
            &action.tenant,
            &action.session,
            &action.action,
            unknown.revision(),
            &action.placement,
            annotation.clone(),
            Utc::now(),
        )
        .await
        .expect("gateway annotation");
    action.events(f.store.as_ref()).await;
    let attached = attach(&f.store, &action, resolved.revision(), receipt.clone())
        .await
        .expect("historical unresolved WAL custody");
    assert_eq!(attached.resolution(), Some(&annotation));
    assert_eq!(attached.revision(), resolved.revision());
    assert_eq!(
        attached.last_source_event_sequence(),
        resolved.last_source_event_sequence()
    );
    assert_eq!(attached.retain_until(), resolved.retain_until());
    let page = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 256)
        .await
        .expect("scan copy obligations");
    let entry = page
        .entries()
        .iter()
        .find(|entry| {
            let receipt = entry.receipt();
            receipt.tenant_id() == &action.tenant
                && receipt.session_id() == &action.session
                && receipt.action_id() == &action.action
        })
        .expect("copy for exact action scope");
    assert!(!entry.is_release());
    assert_eq!(entry.action_revision(), unknown.revision());
    assert_eq!(entry.receipt(), &receipt);
    assert!(
        f.store
            .peek_event_projection(&action.tenant, &action.session)
            .await
            .expect("no event")
            .is_none()
    );
    let restart = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("restart historical proof");
    assert_eq!(
        restart
            .get_effective_action(&action.tenant, &action.session, &action.action)
            .await
            .expect("read")
            .expect("row"),
        attached
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_legacy_missing_anchor_cannot_fabricate_historical_custody_authority() {
    let Some(f) = redis_fixture("catchup-no-anchor").await else {
        return;
    };
    let (action, unknown, receipt) = missing(&f, None, true).await;
    let resolved = f
        .store
        .resolve_unknown(
            &action.tenant,
            &action.session,
            &action.action,
            unknown.revision(),
            &action.placement,
            ResolutionAnnotation::new(
                ResolutionKind::ConfirmedExecuted,
                PrincipalId::new(),
                42,
                "verified",
            ),
            Utc::now(),
        )
        .await
        .expect("resolution");
    let raw = strip_origin(&f, &action).await;
    assert!(matches!(
        attach(&f.store, &action, resolved.revision(), receipt).await,
        Err(GatewayActionCoordinationError::InvalidCustodyReceipt)
    ));
    let after: String = redis::cmd("HGET")
        .arg(format!(
            "{}:actions",
            namespace(&f, &action.tenant, &action.session)
        ))
        .arg(action.action.to_string())
        .query_async(&mut connection(&f).await)
        .await
        .expect("unchanged raw");
    assert_eq!(after, raw);
    assert_eq!(scan(&f.store).await.actions().len(), 1);
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_catchup_rejects_other_terminal_scope_and_stale_revision_without_mutation() {
    let Some(f) = redis_fixture("catchup-reject").await else {
        return;
    };
    let (action, row, receipt) =
        missing(&f, Some(TerminalCustodyRequirement::Required), false).await;
    let (_, _, foreign) = missing(&f, Some(TerminalCustodyRequirement::Required), false).await;
    assert!(matches!(
        attach(&f.store, &action, row.revision(), foreign).await,
        Err(GatewayActionCoordinationError::InvalidCustodyReceipt)
    ));
    let wrong = action.receipt(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        None,
    );
    assert!(matches!(
        attach(&f.store, &action, row.revision(), wrong).await,
        Err(GatewayActionCoordinationError::InvalidCustodyReceipt)
    ));
    assert!(matches!(
        attach(&f.store, &action, row.revision() - 1, receipt).await,
        Err(GatewayActionCoordinationError::StaleWrite(_))
    ));
    assert_eq!(
        f.store
            .get_effective_action(&action.tenant, &action.session, &action.action)
            .await
            .expect("unchanged")
            .expect("row"),
        row
    );
    assert!(
        f.store
            .scan_pending_custody(GatewayCustodyCursor::default(), 256)
            .await
            .expect("no forged ack")
            .entries()
            .is_empty()
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_catchup_cursor_counts_examined_catalog_rows_including_explicit_unsupported() {
    let Some(f) = redis_fixture("catchup-bounded").await else {
        return;
    };
    for index in 0..4 {
        missing(
            &f,
            Some(if index % 2 == 0 {
                TerminalCustodyRequirement::Unsupported
            } else {
                TerminalCustodyRequirement::Required
            }),
            false,
        )
        .await;
    }
    let mut cursor = GatewayActionRecoveryCursor::default();
    let mut examined = 0;
    let mut matches = 0;
    let mut complete = false;
    for _ in 0..5 {
        let page = f
            .store
            .scan_terminal_custody_catchup(cursor, 1)
            .await
            .expect("one examined row");
        assert!(page.examined() <= 1);
        assert!(page.actions().len() <= page.examined());
        examined += page.examined();
        matches += page.actions().len();
        cursor = page.next_cursor().clone();
        if page.is_complete() {
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!((examined, matches), (4, 2));
    for limit in [0, 257] {
        assert!(matches!(
            f.store
                .scan_terminal_custody_catchup(GatewayActionRecoveryCursor::default(), limit)
                .await,
            Err(GatewayActionCoordinationError::InvalidCustodyScanLimit)
        ));
    }
    delete_fixture(&f).await;
}

async fn force_v3(f: &RedisFixture) {
    redis::cmd("HSET")
        .arg(format!("{}:gateway-action:recovery-format", f.prefix))
        .arg("version")
        .arg("3")
        .arg("state")
        .arg("ready")
        .query_async::<()>(&mut connection(f).await)
        .await
        .expect("v3 format fixture");
}

#[tokio::test]
async fn redis_v3_catalog_upgrade_resumes_exact_cursor_without_resetting_horizons_or_outcomes() {
    let Some(f) = redis_fixture("catchup-v3-upgrade").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    for index in 0..64 {
        let row = f
            .store
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    ActionId::new(),
                    format!("skip-{index}"),
                    1,
                    ActionKind::ReadOnly,
                    placement(1, 1),
                ),
                at(1),
            )
            .await
            .expect("catalog row")
            .into_snapshot();
        f.store
            .cancel_before_dispatch(
                &tenant,
                &session,
                row.action_id(),
                row.revision(),
                row.placement(),
                at(2),
            )
            .await
            .expect("non-worker terminal");
    }
    let (action, terminal, _) = missing(&f, None, false).await;
    let legacy_raw = strip_origin(&f, &action).await;
    force_v3(&f).await;
    assert!(matches!(
        RedisGatewayActionStore::connect(f.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationRequired)
    ));
    let first =
        RedisGatewayActionStore::migrate_recovery_format(f.config.clone(), true, Utc::now())
            .await
            .expect("first catalog page");
    assert!(!first.complete());
    let marker = format!("{}:gateway-action:recovery-format", f.prefix);
    let fields: Vec<String> = redis::cmd("HMGET")
        .arg(&marker)
        .arg("version")
        .arg("state")
        .arg("cursor")
        .arg("catalog_validated")
        .query_async(&mut connection(&f).await)
        .await
        .expect("durable validation cursor");
    assert_eq!(fields[0], "5");
    assert_eq!(fields[1], "validating");
    assert!(!fields[2].is_empty());
    assert_eq!(fields[3], "64");
    let old_writer_allowed:i64=redis::Script::new("return redis.call('HGET', KEYS[1], 'version') == '3' and redis.call('HGET', KEYS[1], 'state') == 'ready' and 1 or 0")
        .key(&marker).invoke_async(&mut connection(&f).await).await.expect("v3 gate");
    assert_eq!(
        old_writer_allowed, 0,
        "old GC writer cannot race new catch-up pins"
    );
    assert!(matches!(
        RedisGatewayActionStore::connect(f.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationInProgress)
    ));
    let second =
        RedisGatewayActionStore::migrate_recovery_format(f.config.clone(), true, Utc::now())
            .await
            .expect("new process resumes catalog");
    assert!(second.complete());
    let reopened = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("format4 ready");
    let row = reopened
        .get_effective_action(&action.tenant, &action.session, &action.action)
        .await
        .expect("legacy result readable")
        .expect("row");
    assert_eq!(row.terminal(), terminal.terminal());
    assert_eq!(row.result_content(), terminal.result_content());
    assert_eq!(row.retain_until(), terminal.retain_until());
    assert_eq!(
        row.last_source_event_sequence(),
        terminal.last_source_event_sequence()
    );
    assert_eq!(row.original_worker_terminal_revision(), None);
    assert!(row.requires_terminal_custody_catchup());
    let raw: String = redis::cmd("HGET")
        .arg(format!(
            "{}:actions",
            namespace(&f, &action.tenant, &action.session)
        ))
        .arg(action.action.to_string())
        .query_async(&mut connection(&f).await)
        .await
        .expect("raw after upgrade");
    assert_eq!(
        raw, legacy_raw,
        "validation cannot invent missing custody evidence"
    );
    let repeated =
        RedisGatewayActionStore::migrate_recovery_format(f.config.clone(), true, Utc::now())
            .await
            .expect("idempotent completed upgrade");
    assert!(repeated.complete());
    let page = scan(&reopened).await;
    assert_eq!(page.examined(), 65);
    assert_eq!(page.actions().len(), 1);
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_v3_catalog_missing_payload_blocks_upgrade_without_advancing_cursor_or_deleting_other_rows()
 {
    let Some(f) = redis_fixture("catchup-v3-corrupt").await else {
        return;
    };
    let (action, terminal, _) = missing(&f, None, false).await;
    let (other, _, _) = missing(&f, None, false).await;
    force_v3(&f).await;
    let key = format!("{}:actions", namespace(&f, &action.tenant, &action.session));
    let raw: String = redis::cmd("HGET")
        .arg(&key)
        .arg(action.action.to_string())
        .query_async(&mut connection(&f).await)
        .await
        .expect("save exact fixture row");
    redis::cmd("HDEL")
        .arg(&key)
        .arg(action.action.to_string())
        .query_async::<()>(&mut connection(&f).await)
        .await
        .expect("missing row fixture");
    assert!(matches!(
        RedisGatewayActionStore::migrate_recovery_format(f.config.clone(), true, Utc::now()).await,
        Err(GatewayActionCoordinationError::InvalidRedisResponse)
    ));
    let marker = format!("{}:gateway-action:recovery-format", f.prefix);
    let fields: Vec<String> = redis::cmd("HMGET")
        .arg(marker)
        .arg("state")
        .arg("cursor")
        .arg("catalog_validated")
        .query_async(&mut connection(&f).await)
        .await
        .expect("failed page cursor");
    assert_eq!(fields, vec!["validating", "", "0"]);
    let other_exists: bool = redis::cmd("HEXISTS")
        .arg(format!(
            "{}:actions",
            namespace(&f, &other.tenant, &other.session)
        ))
        .arg(other.action.to_string())
        .query_async(&mut connection(&f).await)
        .await
        .expect("other payload intact");
    assert!(other_exists);
    redis::cmd("HSET")
        .arg(key)
        .arg(action.action.to_string())
        .arg(raw)
        .query_async::<()>(&mut connection(&f).await)
        .await
        .expect("repair exact fixture row");
    assert!(
        RedisGatewayActionStore::migrate_recovery_format(f.config.clone(), true, Utc::now())
            .await
            .expect("revalidate unchanged page")
            .complete()
    );
    let reopened = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("ready");
    assert_eq!(
        reopened
            .get_effective_action(&action.tenant, &action.session, &action.action)
            .await
            .expect("read")
            .expect("row"),
        terminal
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_interrupted_v3_backfill_keeps_assigned_deadline_and_resumes_its_inventory_cursor() {
    let Some(f) = redis_fixture("catchup-v3-interrupted").await else {
        return;
    };
    let (action, _, _) = missing(&f, None, false).await;
    strip_origin(&f, &action).await;
    super::redis_action_recovery::strip_v3_retention(&f).await;
    let marker = format!("{}:gateway-action:recovery-format", f.prefix);
    redis::cmd("HSET")
        .arg(&marker)
        .arg("version")
        .arg("2")
        .arg("state")
        .arg("ready")
        .query_async::<()>(&mut connection(&f).await)
        .await
        .expect("pre-backfill fixture");
    let metadata_key = format!(
        "{}:retention-v1",
        namespace(&f, &action.tenant, &action.session)
    );
    let mut assigned = None;
    for _ in 0..4096 {
        let progress =
            RedisGatewayActionStore::migrate_recovery_format(f.config.clone(), true, Utc::now())
                .await
                .expect("advance until assigned horizon");
        assert!(
            !progress.complete(),
            "backfill row must commit before ready cursor"
        );
        assigned = redis::cmd("HGET")
            .arg(&metadata_key)
            .arg(action.action.to_string())
            .query_async::<Option<String>>(&mut connection(&f).await)
            .await
            .expect("assigned metadata");
        if assigned.is_some() {
            break;
        }
    }
    let assigned = assigned.expect("backfill metadata assigned");
    let cursor: String = redis::cmd("HGET")
        .arg(&marker)
        .arg("cursor")
        .query_async(&mut connection(&f).await)
        .await
        .expect("persisted cursor");
    redis::cmd("HSET")
        .arg(&marker)
        .arg("version")
        .arg("3")
        .query_async::<()>(&mut connection(&f).await)
        .await
        .expect("old v3 migrator interruption");
    assert!(matches!(
        RedisGatewayActionStore::connect(f.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationInProgress)
    ));
    let mut done = false;
    for _ in 0..4096 {
        if RedisGatewayActionStore::migrate_recovery_format(f.config.clone(), true, Utc::now())
            .await
            .expect("resume original backfill cursor")
            .complete()
        {
            done = true;
            break;
        }
    }
    assert!(done);
    assert!(!cursor.is_empty());
    let after: String = redis::cmd("HGET")
        .arg(&metadata_key)
        .arg(action.action.to_string())
        .query_async(&mut connection(&f).await)
        .await
        .expect("preserved horizon");
    assert_eq!(after, assigned);
    let reopened = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("v4 ready");
    assert_eq!(scan(&reopened).await.actions().len(), 1);
    delete_fixture(&f).await;
}
