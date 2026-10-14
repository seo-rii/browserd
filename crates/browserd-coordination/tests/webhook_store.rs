#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use browserd_coordination::*;
use browserd_core::{PrincipalId, TenantId};
use chrono::{DateTime, Utc};
use std::{
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
#[path = "support/webhook_cases.rs"]
mod cases;
const START: i64 = 1_800_000_000_000;
struct Clock(AtomicI64);
impl Clock {
    fn set(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}
impl WebhookClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.0.load(Ordering::SeqCst)).unwrap()
    }
}
struct Fixture {
    store: MemoryWebhookStore,
    outbox: MemoryEventOutbox,
    clock: Arc<Clock>,
    tenant: TenantId,
    principal: PrincipalId,
}
impl Fixture {
    fn new(config: WebhookStoreConfig) -> Self {
        let outbox = MemoryEventOutbox::default();
        let clock = Arc::new(Clock(AtomicI64::new(START)));
        let store = MemoryWebhookStore::new(outbox.clone(), config)
            .unwrap()
            .with_clock(clock.clone());
        Self {
            store,
            outbox,
            clock,
            tenant: TenantId::new(),
            principal: PrincipalId::new(),
        }
    }
    fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }
    async fn registered(&self) -> WebhookEndpointSnapshot {
        self.store
            .put_endpoint(cases::put(
                &self.tenant,
                &self.principal,
                "register",
                None,
                "https://receiver.example/hooks",
            ))
            .await
            .unwrap()
    }
    async fn event(&self, revision: u64) -> OutboxEvent {
        cases::event(&self.outbox, &self.tenant, revision, self.now()).await
    }
}
#[tokio::test]
async fn memory_registry_delivery_key_rotation_deletion_and_idempotent_reply_conformance() {
    let f = Fixture::new(WebhookStoreConfig::default());
    cases::registry_and_delivery_contract(&f.store, &f.outbox, &f.tenant, f.now()).await;
}
#[test]
fn strict_url_and_body_serde_do_not_log_private_endpoints() {
    for url in [
        "http://receiver.example/",
        "https://user:pass@receiver.example/",
        "https://receiver.example/#secret",
    ] {
        assert!(
            WebhookEndpointSpec::new(
                url,
                cases::spec("https://example.test/")
                    .signing_key_ref()
                    .clone()
            )
            .is_err()
        );
    }
    let spec = cases::spec("https://receiver.example/private-token?secret=opaque");
    assert!(!format!("{spec:?}").contains("private-token"));
    assert!(!format!("{spec:?}").contains("opaque"));
    let mut value = serde_json::to_value(spec).unwrap();
    value["unknown"] = true.into();
    assert!(serde_json::from_value::<WebhookEndpointSpec>(value).is_err());
    let mut value = serde_json::to_value(cases::spec("https://receiver.example/")).unwrap();
    value["endpoint_url"] = "https://receiver.example:443/".into();
    assert!(serde_json::from_value::<WebhookEndpointSpec>(value).is_err());
}
#[tokio::test]
async fn expired_attempt_reuses_exact_body_and_floor_blocks_backwards_lease_revival() {
    let f = Fixture::new(WebhookStoreConfig::default());
    f.registered().await;
    f.event(1).await;
    let old = cases::claim(&f.store).await;
    f.clock.set(START + 31_000);
    let next = cases::claim(&f.store).await;
    assert_eq!(next.event_id(), old.event_id());
    assert_eq!(next.delivery_id(), old.delivery_id());
    assert_eq!(next.payload(), old.payload());
    assert_eq!(next.generation(), old.generation() + 1);
    assert!(next.send_timestamp_seconds() > old.send_timestamp_seconds());
    f.clock.set(START - 60_000);
    assert!(
        f.store
            .claim_due_attempts(
                WebhookDeliveryCursor::default(),
                16,
                4,
                Duration::from_secs(30)
            )
            .await
            .unwrap()
            .attempts()
            .is_empty()
    );
    assert_eq!(
        f.store
            .finish_attempt(&old, WebhookAttemptOutcome::Delivered { status_code: 200 })
            .await
            .unwrap_err(),
        WebhookStoreError::LeaseMismatch
    );
    let done = f
        .store
        .finish_attempt(&next, WebhookAttemptOutcome::Delivered { status_code: 200 })
        .await
        .unwrap();
    assert!(done.finished_at().timestamp_millis() >= START + 31_000);
}
#[tokio::test]
async fn unknown_delivery_and_deleted_pending_payload_never_expire_or_get_skipped() {
    let f = Fixture::new(WebhookStoreConfig::default());
    let registered = f.registered().await;
    f.event(1).await;
    let lease = cases::claim(&f.store).await;
    f.store
        .finish_attempt(&lease, WebhookAttemptOutcome::TransportUnknown)
        .await
        .unwrap();
    let deleted = f
        .store
        .delete_endpoint(
            registered.endpoint_ref(),
            cases::binding(&f.tenant, &f.principal, "delete"),
        )
        .await
        .unwrap();
    f.clock.set(START + 30 * 86_400_000);
    f.store
        .maintain(WebhookDeliveryCursor::default(), 16)
        .await
        .unwrap();
    assert!(
        f.store
            .claim_due_attempts(
                WebhookDeliveryCursor::default(),
                16,
                4,
                Duration::from_secs(30)
            )
            .await
            .unwrap()
            .attempts()
            .is_empty()
    );
    f.store
        .put_endpoint(cases::put(
            &f.tenant,
            &f.principal,
            "recreate",
            Some(deleted.endpoint_ref().revision()),
            "https://receiver.example/restored",
        ))
        .await
        .unwrap();
    let retry = cases::claim(&f.store).await;
    assert_eq!(retry.event_id(), lease.event_id());
    assert_eq!(retry.payload(), lease.payload());
}
#[tokio::test]
async fn provider_gap_requires_observed_explicit_tail_acknowledgement() {
    let f = Fixture::new(WebhookStoreConfig::default());
    f.registered().await;
    f.event(1).await;
    f.clock.set(START + 2 * 86_400_000);
    assert!(
        f.store
            .claim_due_attempts(
                WebhookDeliveryCursor::default(),
                16,
                4,
                Duration::from_secs(30)
            )
            .await
            .unwrap()
            .attempts()
            .is_empty()
    );
    let suspended = f.store.get_endpoint(&f.tenant).await.unwrap().unwrap();
    assert_eq!(
        suspended.suspension_reason(),
        Some(WebhookSuspensionReason::EventGap)
    );
    let gap = suspended.gap_observation().unwrap();
    assert_eq!(gap.pruned_through(), 1);
    assert_eq!(gap.tail(), 1);
    assert_eq!(
        f.store
            .resume_endpoint(
                suspended.endpoint_ref(),
                cases::binding(&f.tenant, &f.principal, "continue"),
                WebhookResumeMode::Continue
            )
            .await
            .unwrap_err(),
        WebhookStoreError::Gap
    );
    assert_eq!(
        f.store
            .resume_endpoint(
                suspended.endpoint_ref(),
                cases::binding(&f.tenant, &f.principal, "wrong-gap"),
                WebhookResumeMode::AcceptGapToTail {
                    expected_pruned_through: 0,
                    expected_tail: 1
                }
            )
            .await
            .unwrap_err(),
        WebhookStoreError::Conflict
    );
    let active = f
        .store
        .resume_endpoint(
            suspended.endpoint_ref(),
            cases::binding(&f.tenant, &f.principal, "ack-gap"),
            WebhookResumeMode::AcceptGapToTail {
                expected_pruned_through: gap.pruned_through(),
                expected_tail: gap.tail(),
            },
        )
        .await
        .unwrap();
    assert_eq!(active.cursor().position(), 1);
    assert_eq!(active.status(), WebhookEndpointStatus::Active);
    let event = f.event(2).await;
    assert_eq!(cases::claim(&f.store).await.event_id(), event.event_id());
}
#[tokio::test]
async fn finish_and_automatic_suspend_have_pre_reserved_audit_capacity() {
    let config = WebhookStoreConfig::new(1, 128, 3, 256, 16 * 1024 * 1024, 1).unwrap();
    let f = Fixture::new(config);
    let registered = f.registered().await;
    f.event(1).await;
    let lease = cases::claim(&f.store).await;
    assert_eq!(
        f.store
            .suspend_endpoint(
                registered.endpoint_ref(),
                cases::binding(&f.tenant, &f.principal, "operator")
            )
            .await
            .unwrap_err(),
        WebhookStoreError::AuditCapacity
    );
    let failed = f
        .store
        .finish_attempt(
            &lease,
            WebhookAttemptOutcome::TransientFailure {
                status_code: Some(503),
            },
        )
        .await
        .unwrap();
    assert_eq!(failed.endpoint().status(), WebhookEndpointStatus::Suspended);
    assert_eq!(
        failed.endpoint().suspension_reason(),
        Some(WebhookSuspensionReason::ConsecutiveFailures)
    );
    assert_eq!(
        f.store
            .finish_attempt(
                &lease,
                WebhookAttemptOutcome::TransientFailure {
                    status_code: Some(503)
                }
            )
            .await
            .unwrap(),
        failed
    );
    assert_eq!(
        f.store
            .resume_endpoint(
                failed.endpoint().endpoint_ref(),
                cases::binding(&f.tenant, &f.principal, "resume"),
                WebhookResumeMode::Continue
            )
            .await
            .unwrap_err(),
        WebhookStoreError::AuditCapacity
    );
}
#[tokio::test]
async fn examined_catalog_and_http_slot_caps_preserve_tail_progress_and_tenant_isolation() {
    let f = Fixture::new(WebhookStoreConfig::default());
    let mut tenants: Vec<_> = (0..20).map(|_| TenantId::new()).collect();
    tenants.sort();
    for tenant in &tenants {
        let snap = f
            .store
            .put_endpoint(cases::put(
                tenant,
                &f.principal,
                &tenant.to_string(),
                None,
                "https://receiver.example/hooks",
            ))
            .await
            .unwrap();
        if tenant == &tenants[19] {
            cases::event(&f.outbox, tenant, 1, f.now()).await;
        } else {
            f.store
                .suspend_endpoint(
                    snap.endpoint_ref(),
                    cases::binding(tenant, &f.principal, "suspend"),
                )
                .await
                .unwrap();
        }
    }
    let first = f
        .store
        .claim_due_attempts(
            WebhookDeliveryCursor::default(),
            16,
            4,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(first.examined(), 16);
    assert!(first.attempts().is_empty());
    assert!(!first.is_complete());
    let second = f
        .store
        .claim_due_attempts(first.next_cursor().clone(), 16, 1, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(second.examined(), 4);
    assert_eq!(second.attempts().len(), 1);
    assert_eq!(
        second.attempts()[0].endpoint_ref().tenant_id(),
        &tenants[19]
    );
    for tenant in &tenants[..5] {
        let snapshot = f.store.get_endpoint(tenant).await.unwrap().unwrap();
        f.store
            .resume_endpoint(
                snapshot.endpoint_ref(),
                cases::binding(tenant, &f.principal, "resume"),
                WebhookResumeMode::Continue,
            )
            .await
            .unwrap();
        cases::event(&f.outbox, tenant, 1, f.now()).await;
    }
    let page = f
        .store
        .claim_due_attempts(
            WebhookDeliveryCursor::default(),
            16,
            2,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(page.attempts().len(), 2);
    assert_eq!(page.examined(), 2);
    let next = f
        .store
        .claim_due_attempts(page.next_cursor().clone(), 16, 2, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(next.attempts().len(), 2);
    assert_eq!(next.attempts()[0].endpoint_ref().tenant_id(), &tenants[2]);
}
#[tokio::test]
async fn concurrent_claims_and_revision_mutations_do_not_double_lease_or_cross_tenants() {
    let f = Fixture::new(WebhookStoreConfig::default());
    let registered = f.registered().await;
    f.event(1).await;
    let (left, right) = tokio::join!(
        f.store.claim_due_attempts(
            WebhookDeliveryCursor::default(),
            16,
            4,
            Duration::from_secs(30)
        ),
        f.store.claim_due_attempts(
            WebhookDeliveryCursor::default(),
            16,
            4,
            Duration::from_secs(30)
        )
    );
    let mut leases = left.unwrap().attempts().to_vec();
    leases.extend_from_slice(right.unwrap().attempts());
    assert_eq!(leases.len(), 1);
    let wrong = WebhookEndpointRef::new(
        TenantId::new(),
        registered.endpoint_ref().endpoint_id(),
        registered.endpoint_ref().revision(),
    )
    .unwrap();
    assert_eq!(
        f.store
            .delete_endpoint(&wrong, cases::binding(&f.tenant, &f.principal, "wrong"))
            .await
            .unwrap_err(),
        WebhookStoreError::InvalidMutation
    );
    let (changed, finished) = tokio::join!(
        f.store.put_endpoint(cases::put(
            &f.tenant,
            &f.principal,
            "change",
            Some(registered.endpoint_ref().revision()),
            "https://receiver.example/new"
        )),
        f.store.finish_attempt(
            &leases[0],
            WebhookAttemptOutcome::Delivered { status_code: 200 }
        )
    );
    changed.unwrap();
    match finished {
        Ok(done) => assert_eq!(done.endpoint().cursor().position(), 1),
        Err(WebhookStoreError::LeaseMismatch) => assert_eq!(
            cases::claim(&f.store).await.event_id(),
            leases[0].event_id()
        ),
        other => panic!("unexpected finish result: {other:?}"),
    }
}
#[tokio::test]
async fn ack_metadata_retention_is_fixed_and_payload_tampering_cannot_advance_cursor() {
    let f = Fixture::new(WebhookStoreConfig::default());
    f.registered().await;
    f.event(1).await;
    let lease = cases::claim(&f.store).await;
    let mut wire = serde_json::to_value(&lease).unwrap();
    wire["payload"]["bytes"][0] = 0.into();
    assert!(serde_json::from_value::<WebhookAttemptLease>(wire).is_err());
    f.store
        .finish_attempt(
            &lease,
            WebhookAttemptOutcome::Delivered { status_code: 200 },
        )
        .await
        .unwrap();
    f.clock.set(START + 86_400_000 - 1);
    assert_eq!(
        f.store
            .finish_attempt(
                &lease,
                WebhookAttemptOutcome::Delivered { status_code: 200 }
            )
            .await
            .unwrap()
            .finished_at()
            .timestamp_millis(),
        START
    );
    f.clock.set(START + 86_400_000);
    let reclaimed = f
        .store
        .maintain(WebhookDeliveryCursor::default(), 16)
        .await
        .unwrap();
    assert!(reclaimed.reclaimed() > 0);
    assert_eq!(
        f.store
            .finish_attempt(
                &lease,
                WebhookAttemptOutcome::Delivered { status_code: 200 }
            )
            .await
            .unwrap_err(),
        WebhookStoreError::LeaseMismatch
    );
}

#[tokio::test]
async fn invalid_first_registration_does_not_debit_registry_capacity() {
    let f = Fixture::new(WebhookStoreConfig::new(1, 128, 4096, 256, 16 * 1024 * 1024, 8).unwrap());
    assert_eq!(
        f.store
            .put_endpoint(cases::put(
                &TenantId::new(),
                &f.principal,
                "invalid",
                Some(1),
                "https://receiver.example/hooks"
            ))
            .await
            .unwrap_err(),
        WebhookStoreError::Conflict
    );
    f.registered().await;
    assert_eq!(
        f.store
            .put_endpoint(cases::put(
                &TenantId::new(),
                &f.principal,
                "full",
                None,
                "https://receiver.example/hooks"
            ))
            .await
            .unwrap_err(),
        WebhookStoreError::Capacity
    );
}

#[tokio::test]
async fn new_adapter_on_same_outbox_retains_exact_registry_key_lease_and_capacity() {
    let config = WebhookStoreConfig::new(1, 128, 4096, 256, 16 * 1024 * 1024, 8).unwrap();
    let f = Fixture::new(config.clone());
    let first = f.registered().await;
    f.event(1).await;
    let lease = cases::claim(&f.store).await;
    let reopened = MemoryWebhookStore::new(f.outbox.clone(), config)
        .unwrap()
        .with_clock(f.clock.clone());
    assert_eq!(
        reopened.get_endpoint(&f.tenant).await.unwrap().unwrap(),
        first
    );
    assert_eq!(
        reopened
            .put_endpoint(cases::put(
                &f.tenant,
                &f.principal,
                "register",
                None,
                "https://receiver.example/hooks"
            ))
            .await
            .unwrap(),
        first
    );
    assert!(
        reopened
            .claim_due_attempts(
                WebhookDeliveryCursor::default(),
                16,
                4,
                Duration::from_secs(30)
            )
            .await
            .unwrap()
            .attempts()
            .is_empty()
    );
    assert_eq!(
        reopened
            .put_endpoint(cases::put(
                &TenantId::new(),
                &f.principal,
                "overflow",
                None,
                "https://receiver.example/"
            ))
            .await
            .unwrap_err(),
        WebhookStoreError::Capacity
    );
    assert!(matches!(
        MemoryWebhookStore::new(f.outbox.clone(), WebhookStoreConfig::default()),
        Err(WebhookStoreError::InvalidConfiguration)
    ));
    reopened
        .finish_attempt(
            &lease,
            WebhookAttemptOutcome::Delivered { status_code: 200 },
        )
        .await
        .unwrap();
    assert_eq!(
        f.store
            .get_endpoint(&f.tenant)
            .await
            .unwrap()
            .unwrap()
            .cursor()
            .position(),
        1
    );
}

#[test]
fn admitted_actor_mutation_survives_timeout_and_last_client_disconnect() {
    use std::sync::{Condvar, Mutex};
    struct GateClock {
        gate: Mutex<(bool, bool)>,
        changed: Condvar,
    }
    impl WebhookClock for GateClock {
        fn now(&self) -> DateTime<Utc> {
            let mut guard = self.gate.lock().unwrap();
            if !guard.0 {
                guard.0 = true;
                self.changed.notify_all();
                while !guard.1 {
                    guard = self.changed.wait(guard).unwrap();
                }
            }
            DateTime::from_timestamp_millis(START).unwrap()
        }
    }
    let clock = Arc::new(GateClock {
        gate: Mutex::new((false, false)),
        changed: Condvar::new(),
    });
    let outbox = MemoryEventOutbox::default();
    let store = MemoryWebhookStore::new(outbox, WebhookStoreConfig::default())
        .unwrap()
        .with_clock(clock.clone());
    let client = WebhookBlockingClient::spawn(
        Arc::new(store.clone()),
        CoordinationActorConfig::new(1, 1, Duration::from_millis(20), Duration::from_millis(30))
            .unwrap(),
    )
    .unwrap();
    let tenant = TenantId::new();
    let request = cases::put(
        &tenant,
        &PrincipalId::new(),
        "owned-timeout",
        None,
        "https://receiver.example/hooks",
    );
    let caller = std::thread::spawn(move || {
        let result = client.put_endpoint(request);
        drop(client);
        result
    });
    let guard = clock.gate.lock().unwrap();
    let (mut guard, timeout) = clock
        .changed
        .wait_timeout_while(guard, Duration::from_secs(1), |state| !state.0)
        .unwrap();
    assert!(!timeout.timed_out());
    drop(guard);
    assert_eq!(
        caller.join().unwrap(),
        Err(WebhookStoreError::MutationTimeout)
    );
    guard = clock.gate.lock().unwrap();
    guard.1 = true;
    clock.changed.notify_all();
    drop(guard);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let snapshot = runtime
        .block_on(store.get_endpoint(&tenant))
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.endpoint_ref().revision(), 1);
}
