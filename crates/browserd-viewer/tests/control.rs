#![allow(clippy::expect_used)]

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use browserd_viewer::{ControlError, ViewerScopes};

use common::{NOW, additional_connection, connected_fixture};

#[test]
fn read_and_control_scopes_are_separate() {
    let fixture = connected_fixture(ViewerScopes::new(true, false, false));
    assert_eq!(
        fixture
            .manager
            .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2,),
        Err(ControlError::ControlScopeRequired)
    );
    assert!(
        fixture
            .manager
            .snapshot()
            .expect("snapshot should work")
            .is_agent_control()
    );
}

#[test]
fn failed_acquire_time_overflow_does_not_advance_the_fencing_epoch() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    assert_eq!(
        fixture
            .manager
            .acquire(fixture.connection.id(), fixture.page_id.clone(), u64::MAX,),
        Err(ControlError::TimeOverflow)
    );
    let snapshot = fixture.manager.snapshot().expect("snapshot should work");
    assert_eq!(snapshot.epoch(), 0);
    assert!(snapshot.is_agent_control());
}

#[test]
fn attached_or_disconnected_connection_cannot_be_reattached() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    assert_eq!(
        fixture.manager.attach(fixture.connection.clone()),
        Err(ControlError::ConnectionAlreadyAttached)
    );
    fixture
        .manager
        .disconnect(fixture.connection.id())
        .expect("disconnect should succeed");
    assert_eq!(
        fixture.manager.attach(fixture.connection.clone()),
        Err(ControlError::ConnectionAlreadyAttached)
    );
}

#[test]
fn acquire_release_and_expiry_advance_fencing_epoch() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let acquired = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("control should be acquired");
    assert_eq!(acquired.lease().epoch(), 1);
    assert!(
        !fixture
            .manager
            .snapshot()
            .expect("snapshot should work")
            .is_agent_control()
    );

    fixture
        .manager
        .release(fixture.connection.id(), acquired.lease().epoch())
        .expect("release should succeed");
    assert_eq!(
        fixture
            .manager
            .snapshot()
            .expect("snapshot should work")
            .epoch(),
        2
    );
    assert!(
        fixture
            .manager
            .snapshot()
            .expect("snapshot should work")
            .is_agent_control()
    );

    let reacquired = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 3)
        .expect("control should be reacquired");
    assert_eq!(reacquired.lease().epoch(), 3);
    assert!(
        fixture
            .manager
            .expire(reacquired.lease().expires_at_millis() - 1)
            .expect("expiry check should work")
            .is_none()
    );
    assert!(
        fixture
            .manager
            .expire(reacquired.lease().expires_at_millis())
            .expect("exact deadline should expire")
            .is_some()
    );
    assert_eq!(
        fixture
            .manager
            .snapshot()
            .expect("snapshot should work")
            .epoch(),
        4
    );
}

#[test]
fn heartbeat_extends_only_the_current_unexpired_lease() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let acquired = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("control should be acquired");
    let renewed = fixture
        .manager
        .heartbeat(
            fixture.connection.id(),
            acquired.lease().epoch(),
            NOW + 30_000,
        )
        .expect("heartbeat before expiry should renew");
    assert_eq!(renewed.expires_at_millis(), NOW + 90_000);
    assert_eq!(
        fixture.manager.heartbeat(
            fixture.connection.id(),
            acquired.lease().epoch() - 1,
            NOW + 31_000,
        ),
        Err(ControlError::StaleLeaseEpoch)
    );
    assert_eq!(
        fixture.manager.heartbeat(
            fixture.connection.id(),
            acquired.lease().epoch(),
            renewed.expires_at_millis(),
        ),
        Err(ControlError::LeaseExpired)
    );
    assert!(
        fixture
            .manager
            .snapshot()
            .expect("snapshot should work")
            .is_agent_control()
    );
}

#[test]
fn single_controller_and_admin_force_control_are_enforced() {
    let first = connected_fixture(ViewerScopes::new(true, true, false));
    let second_registry_connection =
        additional_connection(&first, ViewerScopes::new(true, true, false));
    let admin = additional_connection(&first, ViewerScopes::new(true, true, true));
    let first_lease = first
        .manager
        .acquire(first.connection.id(), first.page_id.clone(), NOW + 2)
        .expect("first viewer should acquire");

    assert_eq!(
        first.manager.acquire(
            second_registry_connection.id(),
            first.page_id.clone(),
            NOW + 3,
        ),
        Err(ControlError::AlreadyControlled)
    );
    assert_eq!(
        first.manager.force_acquire(
            second_registry_connection.id(),
            first.page_id.clone(),
            NOW + 3,
        ),
        Err(ControlError::AdminScopeRequired)
    );
    let forced = first
        .manager
        .force_acquire(admin.id(), first.page_id.clone(), NOW + 3)
        .expect("admin should force control");
    assert_eq!(forced.lease().epoch(), first_lease.lease().epoch() + 2);
    assert_eq!(forced.replaced_controller(), Some(first.connection.id()));
    assert_eq!(
        first
            .manager
            .drain_cleanup_events()
            .expect("cleanup should work")
            .len(),
        1
    );
}

#[test]
fn failed_force_acquire_does_not_evict_the_current_controller() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let admin = additional_connection(&fixture, ViewerScopes::new(true, true, true));
    let first = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("first viewer should acquire");

    assert_eq!(
        fixture
            .manager
            .force_acquire(admin.id(), fixture.page_id.clone(), u64::MAX),
        Err(ControlError::TimeOverflow)
    );
    let snapshot = fixture.manager.snapshot().expect("snapshot should work");
    assert_eq!(snapshot.epoch(), first.lease().epoch());
    assert_eq!(
        snapshot.lease().map(|lease| lease.connection_id()),
        Some(fixture.connection.id())
    );
    assert!(
        fixture
            .manager
            .drain_cleanup_events()
            .expect("cleanup should work")
            .is_empty()
    );
}

#[test]
fn disconnect_returns_agent_control_and_cleans_connection() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let lease = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("control should be acquired");
    assert!(
        fixture
            .manager
            .disconnect(fixture.connection.id())
            .expect("disconnect should succeed")
            .is_some()
    );
    assert_eq!(
        fixture
            .manager
            .snapshot()
            .expect("snapshot should work")
            .epoch(),
        lease.lease().epoch() + 1
    );
    assert_eq!(
        fixture
            .manager
            .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 3,),
        Err(ControlError::ConnectionNotFound)
    );
}

#[test]
fn concurrent_acquire_has_exactly_one_controller() {
    const CONTENDERS: usize = 4;

    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let mut connections = vec![fixture.connection.clone()];
    for _ in 1..CONTENDERS {
        connections.push(additional_connection(
            &fixture,
            ViewerScopes::new(true, true, false),
        ));
    }
    let manager = Arc::new(fixture.manager);
    let start = Arc::new(Barrier::new(CONTENDERS + 1));
    let mut tasks = Vec::with_capacity(CONTENDERS);
    for connection in connections {
        let manager = manager.clone();
        let start = start.clone();
        let page_id = fixture.page_id.clone();
        tasks.push(thread::spawn(move || {
            start.wait();
            manager.acquire(connection.id(), page_id, NOW + 2)
        }));
    }
    start.wait();

    let results: Vec<_> = tasks
        .into_iter()
        .map(|task| task.join().expect("acquire thread should not panic"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ControlError::AlreadyControlled))
            .count(),
        CONTENDERS - 1
    );
}
