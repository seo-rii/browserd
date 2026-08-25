#![allow(clippy::expect_used)]

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use browserd_viewer::{
    ControlError, ControlInput, InputDecision, InputDiscardReason, InputKind, ViewerScopes,
};

use common::{NOW, additional_connection, connected_fixture};

#[test]
fn release_and_input_race_has_one_linearized_cleanup_boundary() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let lease = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("control should be acquired");
    let manager = Arc::new(fixture.manager);
    let start = Arc::new(Barrier::new(3));
    let release = {
        let manager = manager.clone();
        let connection_id = fixture.connection.id().clone();
        let start = start.clone();
        let epoch = lease.lease().epoch();
        thread::spawn(move || {
            start.wait();
            manager.release(&connection_id, epoch)
        })
    };
    let input = {
        let manager = manager.clone();
        let connection_id = fixture.connection.id().clone();
        let page_id = fixture.page_id.clone();
        let start = start.clone();
        let epoch = lease.lease().epoch();
        let transform_epoch = fixture.transform_epoch;
        thread::spawn(move || {
            start.wait();
            manager.process_input(
                &connection_id,
                ControlInput::new(epoch, 1, page_id, transform_epoch, InputKind::MouseDown(1)),
                NOW + 3,
            )
        })
    };
    start.wait();

    let cleanup = release
        .join()
        .expect("release thread should not panic")
        .expect("release must eventually own the transition");
    let input = input
        .join()
        .expect("input thread should not panic")
        .expect("input should return a decision");
    assert!(matches!(
        input,
        InputDecision::Accepted(_) | InputDecision::Discarded(InputDiscardReason::NoActiveControl)
    ));
    if matches!(input, InputDecision::Accepted(_)) {
        assert_eq!(cleanup.released_mouse_buttons(), &[1]);
    } else {
        assert!(cleanup.released_mouse_buttons().is_empty());
    }
    let snapshot = manager.snapshot().expect("snapshot should work");
    assert!(snapshot.is_agent_control());
    assert_eq!(snapshot.epoch(), lease.lease().epoch() + 1);
}

#[test]
fn expiry_and_new_acquire_race_cannot_leave_two_controllers() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let next = additional_connection(&fixture, ViewerScopes::new(true, true, false));
    let first = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("first viewer should acquire");
    let deadline = first.lease().expires_at_millis();
    let manager = Arc::new(fixture.manager);
    let start = Arc::new(Barrier::new(3));
    let expiry = {
        let manager = manager.clone();
        let start = start.clone();
        thread::spawn(move || {
            start.wait();
            manager.expire(deadline)
        })
    };
    let acquire = {
        let manager = manager.clone();
        let connection_id = next.id().clone();
        let page_id = fixture.page_id.clone();
        let start = start.clone();
        thread::spawn(move || {
            start.wait();
            manager.acquire(&connection_id, page_id, deadline)
        })
    };
    start.wait();

    expiry
        .join()
        .expect("expiry thread should not panic")
        .expect("expiry should return a decision");
    let acquired = acquire
        .join()
        .expect("acquire thread should not panic")
        .expect("new viewer should acquire after the deadline");
    assert_eq!(acquired.lease().epoch(), first.lease().epoch() + 2);
    let snapshot = manager.snapshot().expect("snapshot should work");
    assert_eq!(
        snapshot.lease().map(|lease| lease.connection_id()),
        Some(next.id())
    );
    assert_eq!(
        manager
            .drain_cleanup_events()
            .expect("cleanup should work")
            .len(),
        1
    );
}

#[test]
fn release_and_competing_acquire_race_is_serializable() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let next = additional_connection(&fixture, ViewerScopes::new(true, true, false));
    let first = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("first viewer should acquire");
    let manager = Arc::new(fixture.manager);
    let start = Arc::new(Barrier::new(3));
    let release = {
        let manager = manager.clone();
        let connection_id = fixture.connection.id().clone();
        let start = start.clone();
        let epoch = first.lease().epoch();
        thread::spawn(move || {
            start.wait();
            manager.release(&connection_id, epoch)
        })
    };
    let acquire = {
        let manager = manager.clone();
        let connection_id = next.id().clone();
        let page_id = fixture.page_id.clone();
        let start = start.clone();
        thread::spawn(move || {
            start.wait();
            manager.acquire(&connection_id, page_id, NOW + 3)
        })
    };
    start.wait();

    release
        .join()
        .expect("release thread should not panic")
        .expect("release should succeed");
    let acquire = acquire.join().expect("acquire thread should not panic");
    let snapshot = manager.snapshot().expect("snapshot should work");
    match acquire {
        Ok(outcome) => {
            assert_eq!(outcome.lease().epoch(), first.lease().epoch() + 2);
            assert_eq!(
                snapshot.lease().map(|lease| lease.connection_id()),
                Some(next.id())
            );
        }
        Err(ControlError::AlreadyControlled) => assert!(snapshot.is_agent_control()),
        Err(error) => assert_eq!(error, ControlError::AlreadyControlled),
    }
    assert_eq!(
        manager
            .drain_cleanup_events()
            .expect("cleanup should work")
            .len(),
        1
    );
}
