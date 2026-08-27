#![allow(clippy::expect_used)]

mod common;

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use browserd_core::{SessionId, TenantId};
use browserd_viewer::{TicketError, TicketPolicy, TicketRegistry, ViewerScopes};

use common::{NOW, ORIGIN};

#[test]
fn ticket_is_bound_to_tenant_session_incarnation_origin_and_expiry() {
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let registry = TicketRegistry::new(
        TicketPolicy::new(Duration::from_secs(30), [ORIGIN]).expect("policy should be valid"),
    );
    let ticket = registry
        .issue(
            tenant_id.clone(),
            session_id.clone(),
            3,
            ViewerScopes::new(true, false, false),
            NOW,
            Duration::from_secs(10),
        )
        .expect("ticket should be issued");

    assert_eq!(
        registry.consume(&ticket, &TenantId::new(), &session_id, 3, ORIGIN, NOW + 1,),
        Err(TicketError::BindingMismatch)
    );
    assert_eq!(
        registry.consume(
            &ticket,
            &tenant_id,
            &session_id,
            3,
            "https://evil.example",
            NOW + 1,
        ),
        Err(TicketError::OriginDenied)
    );
    assert_eq!(
        registry.consume(&ticket, &tenant_id, &session_id, 4, ORIGIN, NOW + 1,),
        Err(TicketError::BindingMismatch)
    );
    assert_eq!(
        registry.consume(&ticket, &tenant_id, &session_id, 3, ORIGIN, NOW + 10_000,),
        Err(TicketError::Expired)
    );
}

#[test]
fn invalid_attempt_does_not_consume_a_valid_one_time_ticket() {
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let registry = TicketRegistry::new(
        TicketPolicy::new(Duration::from_secs(30), [ORIGIN]).expect("policy should be valid"),
    );
    let ticket = registry
        .issue(
            tenant_id.clone(),
            session_id.clone(),
            1,
            ViewerScopes::new(true, true, false),
            NOW,
            Duration::from_secs(5),
        )
        .expect("ticket should be issued");

    assert_eq!(
        registry.consume(&ticket, &tenant_id, &SessionId::new(), 1, ORIGIN, NOW + 1,),
        Err(TicketError::BindingMismatch)
    );
    let connection = registry
        .consume(&ticket, &tenant_id, &session_id, 1, ORIGIN, NOW + 1)
        .expect("valid consume should succeed");
    assert!(connection.scopes().can_read());
    assert!(connection.scopes().can_control());
    assert!(!connection.scopes().can_admin());
    assert_eq!(
        registry.consume(&ticket, &tenant_id, &session_id, 1, ORIGIN, NOW + 2,),
        Err(TicketError::AlreadyConsumed)
    );
}

#[test]
fn discarded_ticket_releases_its_registry_entry_idempotently() {
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let registry = TicketRegistry::new(
        TicketPolicy::new(Duration::from_secs(30), [ORIGIN]).expect("policy should be valid"),
    );
    let ticket = registry
        .issue(
            tenant_id.clone(),
            session_id.clone(),
            1,
            ViewerScopes::new(true, false, false),
            NOW,
            Duration::from_secs(5),
        )
        .expect("ticket should be issued");

    assert_eq!(registry.discard(&ticket), Ok(true));
    assert_eq!(registry.discard(&ticket), Ok(false));
    assert_eq!(
        registry.consume(&ticket, &tenant_id, &session_id, 1, ORIGIN, NOW + 1),
        Err(TicketError::UnknownTicket)
    );
}

#[test]
fn ticket_ttl_and_read_scope_are_fail_closed() {
    let registry = TicketRegistry::new(
        TicketPolicy::new(Duration::from_secs(30), [ORIGIN]).expect("policy should be valid"),
    );
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();

    assert_eq!(
        registry.issue(
            tenant_id.clone(),
            session_id.clone(),
            1,
            ViewerScopes::new(false, true, true),
            NOW,
            Duration::from_secs(1),
        ),
        Err(TicketError::ReadScopeRequired)
    );
    assert_eq!(
        registry.issue(
            tenant_id,
            session_id,
            1,
            ViewerScopes::new(true, false, false),
            NOW,
            Duration::from_secs(31),
        ),
        Err(TicketError::TtlOutOfRange)
    );
}

#[test]
fn concurrent_ticket_consumers_have_exactly_one_winner() {
    const CONSUMERS: usize = 32;

    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let registry = Arc::new(TicketRegistry::new(
        TicketPolicy::new(Duration::from_secs(30), [ORIGIN]).expect("policy should be valid"),
    ));
    let ticket = registry
        .issue(
            tenant_id.clone(),
            session_id.clone(),
            1,
            ViewerScopes::new(true, false, false),
            NOW,
            Duration::from_secs(5),
        )
        .expect("ticket should be issued");
    let start = Arc::new(Barrier::new(CONSUMERS + 1));
    let mut tasks = Vec::with_capacity(CONSUMERS);
    for _ in 0..CONSUMERS {
        let registry = registry.clone();
        let ticket = ticket.clone();
        let tenant_id = tenant_id.clone();
        let session_id = session_id.clone();
        let start = start.clone();
        tasks.push(thread::spawn(move || {
            start.wait();
            registry.consume(&ticket, &tenant_id, &session_id, 1, ORIGIN, NOW + 1)
        }));
    }
    start.wait();

    let results: Vec<_> = tasks
        .into_iter()
        .map(|task| task.join().expect("consumer should not panic"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(TicketError::AlreadyConsumed))
            .count(),
        CONSUMERS - 1
    );
}
