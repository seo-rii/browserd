#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use browserd_coordination::*;
use browserd_core::{ActionId, PrincipalId, SessionId, TenantId};
use chrono::{DateTime, Utc};
use std::time::Duration;
use uuid::Uuid;

pub fn binding(tenant: &TenantId, principal: &PrincipalId, key: &str) -> WebhookMutationBinding {
    WebhookMutationBinding::new(tenant.clone(), principal.clone(), key, [7; 32]).unwrap()
}
pub fn spec(url: &str) -> WebhookEndpointSpec {
    WebhookEndpointSpec::new(
        url,
        WebhookSigningKeyRef::new("master-1", Uuid::new_v4()).unwrap(),
    )
    .unwrap()
}
pub fn put(
    tenant: &TenantId,
    principal: &PrincipalId,
    key: &str,
    revision: Option<u64>,
    url: &str,
) -> WebhookPutRequest {
    WebhookPutRequest::new(binding(tenant, principal, key), revision, spec(url)).unwrap()
}
pub async fn event(
    outbox: &dyn EventOutbox,
    tenant: &TenantId,
    revision: u64,
    now: DateTime<Utc>,
) -> OutboxEvent {
    outbox
        .append(
            OutboxAppend::action_terminal(
                tenant.clone(),
                SessionId::new(),
                ActionId::new(),
                revision,
            ),
            now,
        )
        .await
        .unwrap()
}
pub async fn claim(store: &dyn WebhookStore) -> WebhookAttemptLease {
    let page = store
        .claim_due_attempts(
            WebhookDeliveryCursor::default(),
            16,
            4,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_eq!(page.attempts().len(), 1);
    page.attempts()[0].clone()
}
pub async fn registry_and_delivery_contract(
    store: &dyn WebhookStore,
    outbox: &dyn EventOutbox,
    tenant: &TenantId,
    now: DateTime<Utc>,
) {
    let principal = PrincipalId::new();
    event(outbox, tenant, 1, now).await;
    let first = store
        .put_endpoint(put(
            tenant,
            &principal,
            "register",
            None,
            "https://receiver.example/hooks?tenant=opaque",
        ))
        .await
        .unwrap();
    assert_eq!(first.cursor().position(), 1);
    // A fresh candidate key after a lost response must not rotate the committed key.
    let repeated = store
        .put_endpoint(put(
            tenant,
            &principal,
            "register",
            None,
            "https://receiver.example/hooks?tenant=opaque",
        ))
        .await
        .unwrap();
    assert_eq!(repeated, first);
    assert_eq!(
        store
            .put_endpoint(put(
                tenant,
                &principal,
                "register",
                None,
                "https://receiver.example/changed"
            ))
            .await
            .unwrap_err(),
        WebhookStoreError::IdempotencyConflict
    );
    let second = event(outbox, tenant, 2, now).await;
    let lease = claim(store).await;
    assert_eq!(lease.endpoint_ref(), first.endpoint_ref());
    assert_eq!(lease.event_id(), second.event_id());
    assert_eq!(lease.event_cursor(), second.cursor());
    assert_eq!(
        lease.payload().as_bytes(),
        encode_outbox_event(&second).unwrap()
    );
    let outcome = WebhookAttemptOutcome::Delivered { status_code: 204 };
    let done = store.finish_attempt(&lease, outcome.clone()).await.unwrap();
    assert_eq!(done.endpoint().cursor().position(), 2);
    assert_eq!(store.finish_attempt(&lease, outcome).await.unwrap(), done);
    assert!(
        store
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
    let third = event(outbox, tenant, 3, now).await;
    let old = claim(store).await;
    let changed = store
        .put_endpoint(put(
            tenant,
            &principal,
            "change",
            Some(first.endpoint_ref().revision()),
            "https://receiver.example/new",
        ))
        .await
        .unwrap();
    assert_eq!(
        changed.endpoint_ref().endpoint_id(),
        first.endpoint_ref().endpoint_id()
    );
    assert_eq!(
        store
            .finish_attempt(&old, WebhookAttemptOutcome::Delivered { status_code: 200 })
            .await
            .unwrap_err(),
        WebhookStoreError::LeaseMismatch
    );
    let new = claim(store).await;
    assert_eq!(new.event_id(), third.event_id());
    assert_eq!(new.delivery_id(), old.delivery_id());
    assert_eq!(new.payload(), old.payload());
    assert_ne!(new.lease_token(), old.lease_token());
    assert_eq!(new.spec().endpoint_url(), "https://receiver.example/new");
    let deleted = store
        .delete_endpoint(
            changed.endpoint_ref(),
            binding(tenant, &principal, "delete"),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), WebhookEndpointStatus::Deleted);
    assert_eq!(
        store
            .delete_endpoint(
                changed.endpoint_ref(),
                binding(tenant, &principal, "delete")
            )
            .await
            .unwrap(),
        deleted
    );
    assert_eq!(
        store
            .finish_attempt(&new, WebhookAttemptOutcome::Delivered { status_code: 200 })
            .await
            .unwrap_err(),
        WebhookStoreError::LeaseMismatch
    );
    assert!(
        store
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
    let recreated = store
        .put_endpoint(put(
            tenant,
            &principal,
            "recreate",
            Some(deleted.endpoint_ref().revision()),
            "https://receiver.example/restored",
        ))
        .await
        .unwrap();
    assert_eq!(
        recreated.endpoint_ref().endpoint_id(),
        first.endpoint_ref().endpoint_id()
    );
    let retry = claim(store).await;
    assert_eq!(retry.event_id(), third.event_id());
    assert_eq!(retry.payload(), old.payload());
    store
        .finish_attempt(
            &retry,
            WebhookAttemptOutcome::Delivered { status_code: 200 },
        )
        .await
        .unwrap();
}
