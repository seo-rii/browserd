#![allow(clippy::expect_used)]

mod common;

use browserd_core::PageId;
use browserd_viewer::{
    ControlInput, InputDecision, InputDiscardReason, InputEffect, InputKind, ViewerScopes,
};

use common::{NOW, connected_fixture};

#[test]
fn stale_lease_replay_page_and_transform_inputs_are_discarded() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let lease = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("control should be acquired");
    let epoch = lease.lease().epoch();

    assert_eq!(
        fixture
            .manager
            .process_input(
                fixture.connection.id(),
                ControlInput::new(
                    epoch - 1,
                    1,
                    fixture.page_id.clone(),
                    fixture.transform_epoch,
                    InputKind::MouseDown(1),
                ),
                NOW + 3,
            )
            .expect("input decision should be returned"),
        InputDecision::Discarded(InputDiscardReason::StaleLeaseEpoch)
    );
    assert_eq!(
        fixture
            .manager
            .process_input(
                fixture.connection.id(),
                ControlInput::new(
                    epoch,
                    1,
                    PageId::new(),
                    fixture.transform_epoch,
                    InputKind::MouseDown(1),
                ),
                NOW + 3,
            )
            .expect("input decision should be returned"),
        InputDecision::Discarded(InputDiscardReason::PageMismatch)
    );
    assert_eq!(
        fixture
            .manager
            .process_input(
                fixture.connection.id(),
                ControlInput::new(
                    epoch,
                    2,
                    fixture.page_id.clone(),
                    fixture.transform_epoch,
                    InputKind::MouseDown(1),
                ),
                NOW + 3,
            )
            .expect("input should be accepted"),
        InputDecision::Accepted(InputEffect::None)
    );
    assert_eq!(
        fixture
            .manager
            .process_input(
                fixture.connection.id(),
                ControlInput::new(
                    epoch,
                    2,
                    fixture.page_id.clone(),
                    fixture.transform_epoch,
                    InputKind::MouseUp(1),
                ),
                NOW + 4,
            )
            .expect("input decision should be returned"),
        InputDecision::Discarded(InputDiscardReason::ReplaySequence)
    );

    let next_transform = fixture
        .manager
        .advance_transform(fixture.page_id.clone())
        .expect("transform should advance");
    assert_eq!(next_transform, fixture.transform_epoch + 1);
    assert_eq!(
        fixture
            .manager
            .process_input(
                fixture.connection.id(),
                ControlInput::new(
                    epoch,
                    3,
                    fixture.page_id.clone(),
                    fixture.transform_epoch,
                    InputKind::MouseUp(1),
                ),
                NOW + 4,
            )
            .expect("input decision should be returned"),
        InputDecision::Discarded(InputDiscardReason::StaleTransform)
    );
}

#[test]
fn disconnect_cleanup_resets_mouse_keys_drag_and_composition() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let lease = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("control should be acquired");
    let epoch = lease.lease().epoch();
    for (sequence, kind) in [
        (1, InputKind::MouseDown(1)),
        (2, InputKind::MouseMove),
        (3, InputKind::KeyDown("Shift".into())),
        (4, InputKind::CompositionStart),
        (5, InputKind::CompositionUpdate("ㅎ".into())),
    ] {
        assert!(matches!(
            fixture.manager.process_input(
                fixture.connection.id(),
                ControlInput::new(
                    epoch,
                    sequence,
                    fixture.page_id.clone(),
                    fixture.transform_epoch,
                    kind,
                ),
                NOW + 3,
            ),
            Ok(InputDecision::Accepted(_))
        ));
    }

    let cleanup = fixture
        .manager
        .disconnect(fixture.connection.id())
        .expect("disconnect should succeed")
        .expect("controller disconnect should clean input state");
    assert_eq!(cleanup.released_mouse_buttons(), &[1]);
    assert_eq!(cleanup.released_keys(), &["Shift"]);
    assert!(cleanup.drag_cancelled());
    assert_eq!(cleanup.cancelled_composition(), Some("ㅎ"));
}

#[test]
fn korean_japanese_and_chinese_composition_round_trip_without_loss() {
    for (index, committed) in ["한글", "にほんご", "中文"].into_iter().enumerate() {
        let fixture = connected_fixture(ViewerScopes::new(true, true, false));
        let lease = fixture
            .manager
            .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
            .expect("control should be acquired");
        let epoch = lease.lease().epoch();
        let base = (index as u64) * 10;

        for (sequence, kind) in [
            (base + 1, InputKind::CompositionStart),
            (base + 2, InputKind::CompositionUpdate(committed.into())),
        ] {
            assert_eq!(
                fixture
                    .manager
                    .process_input(
                        fixture.connection.id(),
                        ControlInput::new(
                            epoch,
                            sequence,
                            fixture.page_id.clone(),
                            fixture.transform_epoch,
                            kind,
                        ),
                        NOW + 3,
                    )
                    .expect("composition input should be handled"),
                InputDecision::Accepted(InputEffect::None)
            );
        }
        assert_eq!(
            fixture
                .manager
                .process_input(
                    fixture.connection.id(),
                    ControlInput::new(
                        epoch,
                        base + 3,
                        fixture.page_id.clone(),
                        fixture.transform_epoch,
                        InputKind::CompositionCommit(committed.into()),
                    ),
                    NOW + 3,
                )
                .expect("composition commit should be handled"),
            InputDecision::Accepted(InputEffect::CompositionCommitted(committed.into()))
        );
    }
}

#[test]
fn composition_protocol_rejects_invalid_transitions_and_cancel_clears_state() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let lease = fixture
        .manager
        .acquire(fixture.connection.id(), fixture.page_id.clone(), NOW + 2)
        .expect("control should be acquired");
    let epoch = lease.lease().epoch();

    assert_eq!(
        fixture
            .manager
            .process_input(
                fixture.connection.id(),
                ControlInput::new(
                    epoch,
                    1,
                    fixture.page_id.clone(),
                    fixture.transform_epoch,
                    InputKind::CompositionUpdate("x".into()),
                ),
                NOW + 3,
            )
            .expect("invalid composition should be discarded"),
        InputDecision::Discarded(InputDiscardReason::CompositionNotActive)
    );
    for (sequence, kind) in [
        (2, InputKind::CompositionStart),
        (3, InputKind::CompositionUpdate("한".into())),
        (4, InputKind::CompositionCancel),
    ] {
        assert_eq!(
            fixture
                .manager
                .process_input(
                    fixture.connection.id(),
                    ControlInput::new(
                        epoch,
                        sequence,
                        fixture.page_id.clone(),
                        fixture.transform_epoch,
                        kind,
                    ),
                    NOW + 3,
                )
                .expect("composition transition should be handled"),
            InputDecision::Accepted(InputEffect::None)
        );
    }
    let state = fixture
        .manager
        .input_snapshot()
        .expect("snapshot should work");
    assert_eq!(state.composition_preedit(), None);
}
