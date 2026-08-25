#![allow(clippy::expect_used)]

mod common;

use std::time::Duration;

use browserd_core::{SessionId, TenantId};
use browserd_viewer::{
    ControlError, ControlInput, ControlManager, ControlPolicy, InputDecision, InputDiscardReason,
    InputKind, ViewerScopes,
};

use common::{NOW, additional_connection, connected_fixture};

#[test]
fn control_manager_bounds_observers() {
    let fixture = connected_fixture(ViewerScopes::new(true, false, false));
    let second = additional_connection(&fixture, ViewerScopes::new(true, false, false));
    let manager = ControlManager::with_policy(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        ControlPolicy::new(1, Duration::from_secs(60), 240, Duration::from_secs(10))
            .expect("control policy should be valid"),
    );
    manager
        .attach(fixture.connection.clone())
        .expect("first observer should attach");
    assert_eq!(
        manager.attach(second),
        Err(ControlError::ObserverLimitExceeded)
    );
}

#[test]
fn input_rate_is_bounded_per_connection_and_recovers_after_window() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let manager = ControlManager::with_policy(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        ControlPolicy::new(4, Duration::from_secs(60), 2, Duration::from_secs(10))
            .expect("control policy should be valid"),
    );
    manager
        .attach(fixture.connection.clone())
        .expect("viewer should attach");
    let page_id = fixture.page_id.clone();
    let transform_epoch = manager
        .advance_transform(page_id.clone())
        .expect("transform should initialize");
    let lease = manager
        .acquire(fixture.connection.id(), page_id.clone(), NOW)
        .expect("control should be acquired");

    for sequence in 1..=2 {
        assert_eq!(
            manager
                .process_input(
                    fixture.connection.id(),
                    ControlInput::new(
                        lease.lease().epoch(),
                        sequence,
                        page_id.clone(),
                        transform_epoch,
                        InputKind::MouseMove,
                    ),
                    NOW + sequence,
                )
                .expect("input should be evaluated"),
            InputDecision::Accepted(browserd_viewer::InputEffect::None)
        );
    }
    assert_eq!(
        manager
            .process_input(
                fixture.connection.id(),
                ControlInput::new(
                    lease.lease().epoch(),
                    3,
                    page_id.clone(),
                    transform_epoch,
                    InputKind::MouseMove,
                ),
                NOW + 3,
            )
            .expect("input should be evaluated"),
        InputDecision::Discarded(InputDiscardReason::RateLimited)
    );
    assert_eq!(
        manager
            .process_input(
                fixture.connection.id(),
                ControlInput::new(
                    lease.lease().epoch(),
                    3,
                    page_id,
                    transform_epoch,
                    InputKind::MouseMove,
                ),
                NOW + 10_001,
            )
            .expect("window should recover"),
        InputDecision::Accepted(browserd_viewer::InputEffect::None)
    );
}

#[test]
fn invalid_control_policy_fails_closed() {
    assert_eq!(
        ControlPolicy::new(0, Duration::from_secs(60), 240, Duration::from_secs(10)),
        Err(ControlError::InvalidPolicy)
    );
    assert_eq!(
        ControlPolicy::new(4, Duration::ZERO, 240, Duration::from_secs(10)),
        Err(ControlError::InvalidPolicy)
    );
    assert_eq!(
        ControlPolicy::new(4, Duration::from_secs(60), 0, Duration::from_secs(10)),
        Err(ControlError::InvalidPolicy)
    );
    assert_eq!(
        ControlPolicy::new(4, Duration::from_secs(60), 240, Duration::ZERO),
        Err(ControlError::InvalidPolicy)
    );

    let _ = ControlManager::new(
        TenantId::new(),
        SessionId::new(),
        1,
        Duration::from_secs(60),
    )
    .expect("default policy should remain constructible");
}
