#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use browser_gateway::{GatewayWebhookDelivery, WebhookTransport};
use browserd_api::{WebhookKeyError, WebhookSigningKeyProvider, WebhookSigningSecret};
use browserd_coordination::*;
use browserd_core::{ActionId, PrincipalId, SessionId, TenantId};
use chrono::{DateTime, Utc};
use tokio::sync::Semaphore;
use uuid::Uuid;

struct Clock(AtomicI64);
impl WebhookClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.0.load(Ordering::SeqCst)).unwrap()
    }
}
struct Keys;
impl WebhookSigningKeyProvider for Keys {
    fn active_master_version_id(&self) -> &str {
        "fixture"
    }
    fn derive(
        &self,
        _: &TenantId,
        _: &WebhookSigningKeyRef,
    ) -> Result<WebhookSigningSecret, WebhookKeyError> {
        Ok(WebhookSigningSecret::new([43; 32]))
    }
}
#[derive(Default)]
struct Observations {
    attempts: std::sync::Mutex<Vec<WebhookAttemptLease>>,
    active: AtomicUsize,
    maximum: AtomicUsize,
}
struct Transport {
    observations: Arc<Observations>,
    gate: Option<Arc<Semaphore>>,
    fail_once: AtomicBool,
}
#[async_trait]
impl WebhookTransport for Transport {
    async fn send(
        &self,
        attempt: &WebhookAttemptLease,
        _: &WebhookSigningSecret,
    ) -> WebhookAttemptOutcome {
        self.observations
            .attempts
            .lock()
            .unwrap()
            .push(attempt.clone());
        let active = self.observations.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.observations
            .maximum
            .fetch_max(active, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            gate.acquire().await.unwrap().forget();
        }
        self.observations.active.fetch_sub(1, Ordering::SeqCst);
        if self.fail_once.swap(false, Ordering::SeqCst) {
            WebhookAttemptOutcome::TransportUnknown
        } else {
            WebhookAttemptOutcome::Delivered { status_code: 204 }
        }
    }
}

struct LostReplies {
    inner: MemoryWebhookStore,
    lose_claim: AtomicBool,
    lose_finish: AtomicBool,
    claim_calls: AtomicUsize,
}
#[async_trait]
impl WebhookStore for LostReplies {
    async fn put_endpoint(
        &self,
        r: WebhookPutRequest,
    ) -> Result<WebhookEndpointSnapshot, WebhookStoreError> {
        self.inner.put_endpoint(r).await
    }
    async fn get_endpoint(
        &self,
        t: &TenantId,
    ) -> Result<Option<WebhookEndpointSnapshot>, WebhookStoreError> {
        self.inner.get_endpoint(t).await
    }
    async fn delete_endpoint(
        &self,
        r: &WebhookEndpointRef,
        b: WebhookMutationBinding,
    ) -> Result<WebhookEndpointSnapshot, WebhookStoreError> {
        self.inner.delete_endpoint(r, b).await
    }
    async fn suspend_endpoint(
        &self,
        r: &WebhookEndpointRef,
        b: WebhookMutationBinding,
    ) -> Result<WebhookEndpointSnapshot, WebhookStoreError> {
        self.inner.suspend_endpoint(r, b).await
    }
    async fn resume_endpoint(
        &self,
        r: &WebhookEndpointRef,
        b: WebhookMutationBinding,
        m: WebhookResumeMode,
    ) -> Result<WebhookEndpointSnapshot, WebhookStoreError> {
        self.inner.resume_endpoint(r, b, m).await
    }
    async fn claim_due_attempts(
        &self,
        c: WebhookDeliveryCursor,
        l: usize,
        m: usize,
        t: Duration,
    ) -> Result<WebhookAttemptPage, WebhookStoreError> {
        assert!(l <= 16 && m <= 4 && m > 0);
        self.claim_calls.fetch_add(1, Ordering::SeqCst);
        let page = self.inner.claim_due_attempts(c, l, m, t).await?;
        if self.lose_claim.swap(false, Ordering::SeqCst) {
            Err(WebhookStoreError::Unavailable)
        } else {
            Ok(page)
        }
    }
    async fn finish_attempt(
        &self,
        l: &WebhookAttemptLease,
        o: WebhookAttemptOutcome,
    ) -> Result<WebhookAttemptResult, WebhookStoreError> {
        let result = self.inner.finish_attempt(l, o).await?;
        if self.lose_finish.swap(false, Ordering::SeqCst) {
            Err(WebhookStoreError::Unavailable)
        } else {
            Ok(result)
        }
    }
    async fn maintain(
        &self,
        c: WebhookDeliveryCursor,
        l: usize,
    ) -> Result<WebhookMaintenancePage, WebhookStoreError> {
        self.inner.maintain(c, l).await
    }
}
struct Fixture {
    outbox: MemoryEventOutbox,
    store: Arc<LostReplies>,
    client: WebhookBlockingClient,
    clock: Arc<Clock>,
}
impl Fixture {
    fn new() -> Self {
        let outbox = MemoryEventOutbox::new(Duration::from_secs(86_400)).unwrap();
        let clock = Arc::new(Clock(AtomicI64::new(Utc::now().timestamp_millis())));
        let store = Arc::new(LostReplies {
            inner: MemoryWebhookStore::new(outbox.clone(), WebhookStoreConfig::default())
                .unwrap()
                .with_clock(clock.clone()),
            lose_claim: AtomicBool::new(false),
            lose_finish: AtomicBool::new(false),
            claim_calls: AtomicUsize::new(0),
        });
        let config =
            CoordinationActorConfig::new(32, 8, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        let client = WebhookBlockingClient::spawn(store.clone(), config).unwrap();
        Self {
            outbox,
            store,
            client,
            clock,
        }
    }
    async fn seed(&self) -> TenantId {
        let tenant = TenantId::new();
        self.client
            .put_endpoint(
                WebhookPutRequest::new(
                    WebhookMutationBinding::new(
                        tenant.clone(),
                        PrincipalId::new(),
                        Uuid::new_v4().to_string(),
                        [1; 32],
                    )
                    .unwrap(),
                    None,
                    WebhookEndpointSpec::new(
                        "https://receiver.test/hook",
                        WebhookSigningKeyRef::new("fixture", Uuid::new_v4()).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        self.outbox
            .append(
                OutboxAppend::action_terminal(tenant.clone(), SessionId::new(), ActionId::new(), 1),
                self.clock.now(),
            )
            .await
            .unwrap();
        tenant
    }
    fn sender(&self, t: Arc<dyn WebhookTransport>) -> GatewayWebhookDelivery {
        GatewayWebhookDelivery::new(self.client.clone(), Arc::new(Keys), t)
    }
}
fn transport(gate: Option<Arc<Semaphore>>, fail: bool) -> (Arc<Transport>, Arc<Observations>) {
    let observations = Arc::new(Observations::default());
    (
        Arc::new(Transport {
            observations: observations.clone(),
            gate,
            fail_once: AtomicBool::new(fail),
        }),
        observations,
    )
}

#[tokio::test]
async fn slots_bound_claims_and_network_while_polling_and_later_tenants_progress() {
    let f = Fixture::new();
    let mut tenants = Vec::new();
    for _ in 0..6 {
        tenants.push(f.seed().await);
    }
    let gate = Arc::new(Semaphore::new(0));
    let (transport, seen) = transport(Some(gate.clone()), false);
    let sender = f.sender(transport);
    let task = tokio::spawn({
        let sender = sender.clone();
        async move { sender.run_pass().await }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while seen.active.load(Ordering::SeqCst) != 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(sender.run_pass().await.unwrap().claimed, 0);
    assert_eq!(f.store.claim_calls.load(Ordering::SeqCst), 1);
    let poll = f
        .outbox
        .read_from(&tenants[0], EventCursor::start(), 10, f.clock.now())
        .await
        .unwrap();
    assert_eq!(poll.events().len(), 1);
    gate.add_permits(6);
    let first = task.await.unwrap().unwrap();
    assert_eq!(first.claimed, 4);
    assert_eq!(first.finished, 4);
    let next = sender.run_pass().await.unwrap();
    assert_eq!(next.claimed, 2);
    assert_eq!(next.finished, 2);
    assert_eq!(seen.maximum.load(Ordering::SeqCst), 4);
    let mut ids: Vec<_> = seen
        .attempts
        .lock()
        .unwrap()
        .iter()
        .map(|l| l.event_id())
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 6);
}

#[tokio::test]
async fn lost_claim_and_transport_unknown_retry_the_same_body_after_restart() {
    let f = Fixture::new();
    let tenant = f.seed().await;
    f.store.lose_claim.store(true, Ordering::SeqCst);
    let (transport, seen) = transport(None, true);
    let sender = f.sender(transport.clone());
    assert!(sender.run_pass().await.is_err());
    assert!(seen.attempts.lock().unwrap().is_empty());
    assert_eq!(sender.run_pass().await.unwrap().claimed, 0);
    f.clock.0.fetch_add(31_000, Ordering::SeqCst);
    assert_eq!(sender.run_pass().await.unwrap().finished, 1);
    drop(sender);
    f.clock.0.fetch_add(60_000, Ordering::SeqCst);
    let restarted = f.sender(transport);
    assert_eq!(restarted.run_pass().await.unwrap().finished, 1);
    let attempts = seen.attempts.lock().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].event_id(), attempts[1].event_id());
    assert_eq!(
        attempts[0].payload().as_bytes(),
        attempts[1].payload().as_bytes()
    );
    assert_eq!(attempts[0].signing_key_ref(), attempts[1].signing_key_ref());
    assert_ne!(attempts[0].attempt_id(), attempts[1].attempt_id());
    assert!(attempts[1].send_timestamp_seconds() > attempts[0].send_timestamp_seconds());
    assert_eq!(
        f.client.get_endpoint(&tenant).unwrap().unwrap().cursor(),
        attempts[1].event_cursor()
    );
}

#[tokio::test]
async fn committed_finish_with_lost_reply_does_not_resend_on_restart() {
    let f = Fixture::new();
    f.seed().await;
    f.store.lose_finish.store(true, Ordering::SeqCst);
    let (transport, seen) = transport(None, false);
    let sender = f.sender(transport.clone());
    assert_eq!(sender.run_pass().await.unwrap().finished, 0);
    drop(sender);
    f.clock.0.fetch_add(60_000, Ordering::SeqCst);
    assert_eq!(f.sender(transport).run_pass().await.unwrap().claimed, 0);
    assert_eq!(seen.attempts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn replaced_endpoint_rejects_late_delivery_ack() {
    let f = Fixture::new();
    let tenant = f.seed().await;
    let gate = Arc::new(Semaphore::new(0));
    let (transport, seen) = transport(Some(gate.clone()), false);
    let sender = f.sender(transport);
    let task = tokio::spawn(async move { sender.run_pass().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while seen.active.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let old = f.client.get_endpoint(&tenant).unwrap().unwrap();
    let changed = f
        .client
        .put_endpoint(
            WebhookPutRequest::new(
                WebhookMutationBinding::new(
                    tenant.clone(),
                    PrincipalId::new(),
                    Uuid::new_v4().to_string(),
                    [2; 32],
                )
                .unwrap(),
                Some(old.endpoint_ref().revision()),
                WebhookEndpointSpec::new(
                    "https://receiver.test/replaced",
                    WebhookSigningKeyRef::new("fixture", Uuid::new_v4()).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    gate.add_permits(1);
    assert_eq!(task.await.unwrap().unwrap().finished, 0);
    assert_eq!(f.client.get_endpoint(&tenant).unwrap().unwrap(), changed);
}

#[tokio::test]
async fn delivery_loop_starts_immediately_and_finishes_owned_attempt_on_shutdown() {
    let f = Fixture::new();
    f.seed().await;
    let gate = Arc::new(Semaphore::new(0));
    let (transport, seen) = transport(Some(gate.clone()), false);
    let sender = f.sender(transport);
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(sender.run(shutdown.clone()));
    tokio::time::timeout(Duration::from_secs(2), async {
        while seen.active.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    shutdown.cancel();
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    gate.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(f.store.claim_calls.load(Ordering::SeqCst), 1);
    assert_eq!(seen.attempts.lock().unwrap().len(), 1);
}
