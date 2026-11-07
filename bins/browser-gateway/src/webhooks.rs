//! Bounded webhook delivery, independent of browser readiness and event polling.

use std::sync::Arc;
use std::time::Duration;

use browserd_api::WebhookSigningKeyProvider;
use browserd_coordination::{
    WebhookAttemptOutcome, WebhookBlockingClient, WebhookDeliveryCursor, WebhookStoreError,
};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::WebhookTransport;

const MAX_SENDS: usize = 4;
const EXAMINED_LIMIT: usize = 16;
const ATTEMPT_TTL: Duration = Duration::from_secs(30);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebhookDeliveryPass {
    pub examined: usize,
    pub claimed: usize,
    pub finished: usize,
}

struct DeliveryCursors {
    delivery: WebhookDeliveryCursor,
    maintenance: WebhookDeliveryCursor,
}

/// Clones share the concurrency limit and cursor; concurrent passes never overlap.
#[derive(Clone)]
pub struct GatewayWebhookDelivery {
    store: WebhookBlockingClient,
    keys: Arc<dyn WebhookSigningKeyProvider>,
    transport: Arc<dyn WebhookTransport>,
    slots: Arc<Semaphore>,
    cursors: Arc<Mutex<DeliveryCursors>>,
}

impl GatewayWebhookDelivery {
    #[must_use]
    pub fn new(
        store: WebhookBlockingClient,
        keys: Arc<dyn WebhookSigningKeyProvider>,
        transport: Arc<dyn WebhookTransport>,
    ) -> Self {
        Self {
            store,
            keys,
            transport,
            slots: Arc::new(Semaphore::new(MAX_SENDS)),
            cursors: Arc::new(Mutex::new(DeliveryCursors {
                delivery: WebhookDeliveryCursor::default(),
                maintenance: WebhookDeliveryCursor::default(),
            })),
        }
    }

    pub async fn run_pass(&self) -> Result<WebhookDeliveryPass, WebhookStoreError> {
        let Ok(mut cursors) = self.cursors.try_lock() else {
            return Ok(WebhookDeliveryPass::default());
        };
        // Acquire HTTP capacity before committing attempts. A queued call owns these permits
        // until it returns, including when its async caller is cancelled.
        let mut permits = Vec::with_capacity(MAX_SENDS);
        for _ in 0..MAX_SENDS {
            let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
                break;
            };
            permits.push(permit);
        }
        if permits.is_empty() {
            return Ok(WebhookDeliveryPass::default());
        }
        let store = self.store.clone();
        let cursor = cursors.delivery.clone();
        let (page, mut permits) = tokio::task::spawn_blocking(move || {
            let page =
                store.claim_due_attempts(cursor, EXAMINED_LIMIT, permits.len(), ATTEMPT_TTL)?;
            Ok::<_, WebhookStoreError>((page, permits))
        })
        .await
        .map_err(|_| WebhookStoreError::Unavailable)??;
        if page.attempts().len() > permits.len() || page.examined() > EXAMINED_LIMIT {
            return Err(WebhookStoreError::InvalidPayload);
        }
        cursors.delivery = if page.is_complete() {
            WebhookDeliveryCursor::default()
        } else {
            page.next_cursor().clone()
        };
        let mut report = WebhookDeliveryPass {
            examined: page.examined(),
            claimed: page.attempts().len(),
            finished: 0,
        };
        let mut sends = JoinSet::new();
        for attempt in page.attempts() {
            let permit = permits.pop().ok_or(WebhookStoreError::Unavailable)?;
            let attempt = attempt.clone();
            let store = self.store.clone();
            let keys = Arc::clone(&self.keys);
            let transport = Arc::clone(&self.transport);
            sends.spawn(async move {
                let outcome = match keys.derive(
                    attempt.endpoint_ref().tenant_id(),
                    attempt.signing_key_ref(),
                ) {
                    Ok(secret) => {
                        tokio::time::timeout(SEND_TIMEOUT, transport.send(&attempt, &secret))
                            .await
                            .unwrap_or(WebhookAttemptOutcome::TransportUnknown)
                    }
                    Err(_) => WebhookAttemptOutcome::TransportUnknown,
                };
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    store.finish_attempt(&attempt, outcome)
                })
                .await
                .is_ok_and(|result| result.is_ok())
            });
        }
        drop(permits);
        while let Some(result) = sends.join_next().await {
            if matches!(result, Ok(true)) {
                report.finished += 1;
            }
        }
        let store = self.store.clone();
        let cursor = cursors.maintenance.clone();
        if let Ok(Ok(page)) =
            tokio::task::spawn_blocking(move || store.maintain(cursor, EXAMINED_LIMIT)).await
        {
            cursors.maintenance = if page.is_complete() {
                WebhookDeliveryCursor::default()
            } else {
                page.next_cursor().clone()
            };
        }
        Ok(report)
    }

    /// Run immediately, then skip missed ticks. Complete a started bounded pass on shutdown.
    pub async fn run(self, shutdown: CancellationToken) {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    if self.run_pass().await.is_err() {
                        eprintln!("browser gateway webhook delivery pass unavailable");
                    }
                }
            }
        }
    }
}
