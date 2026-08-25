use std::time::Duration;

use browserd_egress::{MonotonicMillis, QuotaError, QuotaLedger, QuotaLimits};

fn limits() -> QuotaLimits {
    QuotaLimits {
        max_concurrent_connections: 2,
        max_connection_starts_per_window: 3,
        max_dns_queries_per_window: 2,
        max_egress_bytes_per_window: 100,
        max_total_egress_bytes: 150,
        max_response_bytes: Some(80),
        accounting_window: Duration::from_secs(1),
        idle_connection_timeout: Duration::from_secs(30),
    }
}

#[test]
fn concurrent_connections_are_accounted_and_released() {
    let mut ledger = QuotaLedger::new(limits());
    let now = MonotonicMillis::new(0);
    let first = ledger.open_connection(now);
    let second = ledger.open_connection(now);
    assert!(first.is_ok());
    assert!(second.is_ok());
    assert_eq!(
        ledger.open_connection(now),
        Err(QuotaError::ConcurrentConnections),
    );

    let Some(first) = first.ok() else {
        return;
    };
    assert!(ledger.close_connection(first));
    assert!(ledger.open_connection(now).is_ok());
    assert_eq!(ledger.usage().active_connections, 2);
}

#[test]
fn connection_creation_and_dns_rates_reset_only_after_the_window() {
    let mut ledger = QuotaLedger::new(limits());
    let start = MonotonicMillis::new(0);

    for _ in 0..3 {
        let opened = ledger.open_connection(start);
        assert!(opened.is_ok());
        let Some(opened) = opened.ok() else {
            continue;
        };
        assert!(ledger.close_connection(opened));
    }
    assert_eq!(
        ledger.open_connection(start),
        Err(QuotaError::ConnectionCreationRate),
    );

    assert_eq!(ledger.record_dns_query(start), Ok(()));
    assert_eq!(ledger.record_dns_query(start), Ok(()));
    assert_eq!(
        ledger.record_dns_query(start),
        Err(QuotaError::DnsQueryRate),
    );

    let next_window = MonotonicMillis::new(1_000);
    assert!(ledger.open_connection(next_window).is_ok());
    assert_eq!(ledger.record_dns_query(next_window), Ok(()));
}

#[test]
fn rejected_egress_bytes_do_not_partially_mutate_accounting() {
    let mut ledger = QuotaLedger::new(limits());
    let now = MonotonicMillis::new(0);
    let opened = ledger.open_connection(now);
    assert!(opened.is_ok());
    let Some(connection) = opened.ok() else {
        return;
    };

    assert_eq!(ledger.record_egress(connection, 60, now), Ok(()));
    assert_eq!(ledger.usage().total_egress_bytes, 60);
    assert_eq!(ledger.usage().window_egress_bytes, 60);

    assert_eq!(
        ledger.record_egress(connection, 41, now),
        Err(QuotaError::EgressBytesPerWindow),
    );
    assert_eq!(ledger.usage().total_egress_bytes, 60);
    assert_eq!(ledger.usage().window_egress_bytes, 60);
}

#[test]
fn total_session_egress_and_per_response_caps_are_independent() {
    let mut configured = limits();
    configured.max_egress_bytes_per_window = 1_000;
    let mut ledger = QuotaLedger::new(configured);
    let first_window = MonotonicMillis::new(0);
    let first = ledger.open_connection(first_window);
    assert!(first.is_ok());
    let Some(first) = first.ok() else {
        return;
    };

    assert_eq!(ledger.record_egress(first, 80, first_window), Ok(()));
    assert_eq!(
        ledger.record_egress(first, 1, first_window),
        Err(QuotaError::ResponseBytes),
    );
    assert!(ledger.close_connection(first));

    let second_window = MonotonicMillis::new(1_000);
    let second = ledger.open_connection(second_window);
    assert!(second.is_ok());
    let Some(second) = second.ok() else {
        return;
    };
    assert_eq!(ledger.record_egress(second, 70, second_window), Ok(()));
    assert_eq!(
        ledger.record_egress(second, 1, second_window),
        Err(QuotaError::TotalEgressBytes),
    );
    assert_eq!(ledger.usage().total_egress_bytes, 150);
}

#[test]
fn idle_connections_expire_and_release_concurrency_capacity() {
    let mut ledger = QuotaLedger::new(limits());
    let opened_at = MonotonicMillis::new(0);
    assert!(ledger.open_connection(opened_at).is_ok());
    assert!(ledger.open_connection(opened_at).is_ok());
    assert_eq!(ledger.usage().active_connections, 2);

    assert_eq!(ledger.expire_idle(MonotonicMillis::new(29_999)), 0);
    assert_eq!(ledger.expire_idle(MonotonicMillis::new(30_000)), 2);
    assert_eq!(ledger.usage().active_connections, 0);
}
