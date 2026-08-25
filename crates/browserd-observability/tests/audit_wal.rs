#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Barrier};
use std::thread;

use browserd_observability::{
    AckOutcome, AppendOutcome, AuditEvent, AuditEventId, AuditWal, AuditWalError, AuditWalPolicy,
};
use tempfile::tempdir;

fn event(id: &str, critical: bool, payload_size: usize) -> AuditEvent {
    AuditEvent::new(
        AuditEventId::new(id).expect("event ID should be valid"),
        "control.acquire",
        vec![b'x'; payload_size],
        critical,
    )
}

#[test]
fn audit_event_debug_never_renders_raw_payload_bytes() {
    let event = AuditEvent::new(
        AuditEventId::new("redacted-debug").expect("event ID should be valid"),
        "credential.inject",
        b"raw-secret-value".to_vec(),
        true,
    );
    let rendered = format!("{event:?}");

    assert!(!rendered.contains("payload: ["));
    assert!(!rendered.contains("raw-secret-value"));
    assert!(rendered.contains("payload_bytes"));
}

#[test]
fn critical_append_is_recovered_after_restart_until_durably_acked() {
    let directory = tempdir().expect("tempdir should be created");
    let path = directory.path().join("audit.wal");
    let policy = AuditWalPolicy::new(64 * 1024, 16 * 1024).expect("policy should be valid");
    let sequence = {
        let wal = AuditWal::open(&path, policy).expect("WAL should open");
        match wal
            .append(event("audit-1", true, 128))
            .expect("critical intent should be fsynced")
        {
            AppendOutcome::Durable(sequence) => sequence,
            other => panic!("unexpected append outcome: {other:?}"),
        }
    };

    let wal = AuditWal::open(&path, policy).expect("WAL should recover");
    let pending = wal.pending().expect("pending events should be readable");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sequence(), sequence);
    assert_eq!(pending[0].event().id().as_str(), "audit-1");
    assert_eq!(
        wal.ack(sequence).expect("ack should be durable"),
        AckOutcome::Acked
    );
    drop(wal);

    let recovered = AuditWal::open(&path, policy).expect("acked WAL should reopen");
    assert!(
        recovered
            .pending()
            .expect("pending should be readable")
            .is_empty()
    );
    assert_eq!(
        recovered
            .ack(sequence)
            .expect("duplicate ack should be harmless"),
        AckOutcome::AlreadyAbsent
    );
}

#[test]
fn ack_compaction_preserves_sequence_high_watermark_across_restart() {
    let directory = tempdir().expect("tempdir should be created");
    let path = directory.path().join("audit.wal");
    let policy = AuditWalPolicy::new(64 * 1024, 16 * 1024).expect("policy should be valid");
    let wal = AuditWal::open(&path, policy).expect("WAL should open");
    let first = match wal
        .append(event("first-sequence", true, 8))
        .expect("first should append")
    {
        AppendOutcome::Durable(sequence) => sequence,
        other => panic!("unexpected append outcome: {other:?}"),
    };
    let second = match wal
        .append(event("second-sequence", true, 8))
        .expect("second should append")
    {
        AppendOutcome::Durable(sequence) => sequence,
        other => panic!("unexpected append outcome: {other:?}"),
    };
    assert_eq!(second.get(), first.get() + 1);
    wal.ack(second).expect("highest sequence should be acked");
    drop(wal);

    let recovered = AuditWal::open(&path, policy).expect("WAL should recover");
    let third = match recovered
        .append(event("third-sequence", true, 8))
        .expect("third should append")
    {
        AppendOutcome::Durable(sequence) => sequence,
        other => panic!("unexpected append outcome: {other:?}"),
    };
    assert_eq!(third.get(), second.get() + 1);
}

#[test]
fn partial_tail_is_truncated_without_losing_complete_records() {
    let directory = tempdir().expect("tempdir should be created");
    let path = directory.path().join("audit.wal");
    let policy = AuditWalPolicy::new(64 * 1024, 16 * 1024).expect("policy should be valid");
    {
        let wal = AuditWal::open(&path, policy).expect("WAL should open");
        wal.append(event("complete", true, 64))
            .expect("complete event should append");
    }
    let complete_len = std::fs::metadata(&path)
        .expect("metadata should exist")
        .len();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("WAL should open for tail injection")
        .write_all(&[0, 0, 1, 0, 0, 0, 0, 0, 99, 88])
        .expect("partial frame should be injected");

    let wal = AuditWal::open(&path, policy).expect("partial tail should recover");
    assert_eq!(wal.pending().expect("pending should work").len(), 1);
    assert_eq!(
        std::fs::metadata(&path)
            .expect("metadata should exist")
            .len(),
        complete_len
    );
}

#[test]
fn full_wal_fails_closed_for_critical_and_drops_only_noncritical() {
    let directory = tempdir().expect("tempdir should be created");
    let path = directory.path().join("audit.wal");
    let policy = AuditWalPolicy::new(512, 400).expect("policy should be valid");
    let wal = AuditWal::open(&path, policy).expect("WAL should open");
    wal.append(event("first", true, 300))
        .expect("first critical event should fit");

    assert_eq!(
        wal.append(event("critical-full", true, 300)),
        Err(AuditWalError::FullCritical)
    );
    assert_eq!(
        wal.append(event("read-only-full", false, 300))
            .expect("noncritical overflow follows degraded policy"),
        AppendOutcome::DroppedNonCritical
    );
    assert_eq!(wal.pending().expect("pending should work").len(), 1);
}

#[test]
fn oversized_record_is_rejected_without_mutating_wal() {
    let directory = tempdir().expect("tempdir should be created");
    let path = directory.path().join("audit.wal");
    let policy = AuditWalPolicy::new(4096, 256).expect("policy should be valid");
    let wal = AuditWal::open(&path, policy).expect("WAL should open");
    let initial_len = std::fs::metadata(&path)
        .expect("metadata should exist")
        .len();

    assert_eq!(
        wal.append(event("too-large", true, 512)),
        Err(AuditWalError::RecordTooLarge)
    );
    assert_eq!(
        std::fs::metadata(path)
            .expect("metadata should exist")
            .len(),
        initial_len
    );
}

#[test]
fn concurrent_duplicate_append_has_one_durable_record() {
    const WRITERS: usize = 32;

    let directory = tempdir().expect("tempdir should be created");
    let path = directory.path().join("audit.wal");
    let policy = AuditWalPolicy::new(64 * 1024, 4096).expect("policy should be valid");
    let wal = Arc::new(AuditWal::open(&path, policy).expect("WAL should open"));
    let start = Arc::new(Barrier::new(WRITERS + 1));
    let mut tasks = Vec::with_capacity(WRITERS);
    for _ in 0..WRITERS {
        let wal = wal.clone();
        let start = start.clone();
        tasks.push(thread::spawn(move || {
            start.wait();
            wal.append(event("same-event", true, 64))
        }));
    }
    start.wait();

    let outcomes: Vec<_> = tasks
        .into_iter()
        .map(|task| {
            task.join()
                .expect("append thread should not panic")
                .expect("duplicate append should be idempotent")
        })
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AppendOutcome::Durable(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AppendOutcome::Existing(_)))
            .count(),
        WRITERS - 1
    );
    assert_eq!(wal.pending().expect("pending should work").len(), 1);
}
