#![allow(clippy::expect_used)]

mod common;

use std::sync::atomic::{AtomicBool, Ordering};

use browserd_core::PageId;
use browserd_viewer::{FrameBroadcaster, FrameError, FramePolicy, ViewerFrame, ViewerScopes};

use common::{additional_connection, connected_fixture};

#[test]
fn chromium_is_acknowledged_before_a_valid_frame_is_published() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let broadcaster = FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(4, 2, 1024, 4096).expect("frame policy should be valid"),
    );
    broadcaster
        .attach(&fixture.connection)
        .expect("read-scoped viewer should attach");
    let acknowledged = AtomicBool::new(false);

    let outcome = broadcaster
        .ingest(
            ViewerFrame::new(
                7,
                fixture.page_id.clone(),
                fixture.transform_epoch,
                br#"{"width":800,"height":600}"#.to_vec(),
                vec![0xff, 0xd8, 0xff, 0xd9],
            ),
            |frame_id| {
                assert_eq!(frame_id, 7);
                acknowledged.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect("valid frame should publish");

    assert!(acknowledged.load(Ordering::SeqCst));
    assert_eq!(outcome.observer_count(), 1);
    assert_eq!(outcome.dropped_frames(), 0);
    assert_eq!(
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("observer should exist")
            .expect("latest frame should be queued")
            .frame_id(),
        7
    );
}

#[test]
fn slow_observer_drops_old_frames_without_blocking_fast_observer() {
    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let fast = additional_connection(&fixture, ViewerScopes::new(true, false, false));
    let broadcaster = FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(4, 2, 1024, 4096).expect("frame policy should be valid"),
    );
    broadcaster
        .attach(&fixture.connection)
        .expect("slow observer should attach");
    broadcaster
        .attach(&fast)
        .expect("fast observer should attach");

    for frame_id in 1..=5 {
        let outcome = broadcaster
            .ingest(
                ViewerFrame::new(
                    frame_id,
                    fixture.page_id.clone(),
                    fixture.transform_epoch,
                    b"{}".to_vec(),
                    vec![frame_id as u8],
                ),
                |_| Ok(()),
            )
            .expect("frame should publish");
        if frame_id < 5 {
            assert_eq!(
                broadcaster
                    .next_frame(fast.id())
                    .expect("fast observer should exist")
                    .expect("fast observer should receive every frame")
                    .frame_id(),
                frame_id
            );
        } else {
            assert_eq!(outcome.dropped_frames(), 1);
        }
    }

    let slow_ids: Vec<_> = [
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("slow observer should exist")
            .expect("newer frame should remain")
            .frame_id(),
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("slow observer should exist")
            .expect("latest frame should remain")
            .frame_id(),
    ]
    .into_iter()
    .collect();
    assert_eq!(slow_ids, [4, 5]);
    assert_eq!(
        broadcaster
            .next_frame(fast.id())
            .expect("fast observer should exist")
            .expect("last frame should remain")
            .frame_id(),
        5
    );
}

#[test]
fn invalid_or_unacknowledged_frames_are_never_visible() {
    let fixture = connected_fixture(ViewerScopes::new(true, false, false));
    let broadcaster = FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(4, 1, 8, 8).expect("frame policy should be valid"),
    );
    broadcaster
        .attach(&fixture.connection)
        .expect("observer should attach");

    assert_eq!(
        broadcaster.ingest(
            ViewerFrame::new(
                1,
                PageId::new(),
                fixture.transform_epoch,
                b"{}".to_vec(),
                vec![1],
            ),
            |_| Ok(()),
        ),
        Err(FrameError::PageMismatch)
    );
    assert_eq!(
        broadcaster.ingest(
            ViewerFrame::new(
                1,
                fixture.page_id.clone(),
                fixture.transform_epoch,
                b"{}".to_vec(),
                vec![1],
            ),
            |_| Err(FrameError::ChromiumAckFailed),
        ),
        Err(FrameError::ChromiumAckFailed)
    );
    assert!(
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("observer should exist")
            .is_none()
    );
}

#[test]
fn transform_change_clears_queued_frames_and_rejects_stale_frames() {
    let fixture = connected_fixture(ViewerScopes::new(true, false, false));
    let broadcaster = FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(4, 2, 1024, 4096).expect("frame policy should be valid"),
    );
    broadcaster
        .attach(&fixture.connection)
        .expect("observer should attach");
    broadcaster
        .ingest(
            ViewerFrame::new(
                1,
                fixture.page_id.clone(),
                fixture.transform_epoch,
                b"{}".to_vec(),
                vec![1],
            ),
            |_| Ok(()),
        )
        .expect("frame should publish");

    let next_epoch = broadcaster
        .advance_transform(fixture.page_id.clone())
        .expect("transform should advance");
    assert_eq!(next_epoch, fixture.transform_epoch + 1);
    assert!(
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("observer should exist")
            .is_none()
    );
    assert_eq!(
        broadcaster.ingest(
            ViewerFrame::new(
                2,
                fixture.page_id.clone(),
                fixture.transform_epoch,
                b"{}".to_vec(),
                vec![2],
            ),
            |_| Ok(()),
        ),
        Err(FrameError::StaleTransform)
    );
}

#[test]
fn observer_count_and_frame_sizes_are_bounded() {
    let fixture = connected_fixture(ViewerScopes::new(true, false, false));
    let second = additional_connection(&fixture, ViewerScopes::new(true, false, false));
    let broadcaster = FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(1, 1, 2, 2).expect("frame policy should be valid"),
    );
    broadcaster
        .attach(&fixture.connection)
        .expect("first observer should attach");
    assert_eq!(
        broadcaster.attach(&second),
        Err(FrameError::ObserverLimitExceeded)
    );
    assert_eq!(
        broadcaster.ingest(
            ViewerFrame::new(
                1,
                fixture.page_id.clone(),
                fixture.transform_epoch,
                vec![0; 3],
                vec![0; 1],
            ),
            |_| Ok(()),
        ),
        Err(FrameError::MetadataTooLarge)
    );
    assert_eq!(
        broadcaster.ingest(
            ViewerFrame::new(
                1,
                fixture.page_id.clone(),
                fixture.transform_epoch,
                vec![0; 1],
                vec![0; 3],
            ),
            |_| Ok(()),
        ),
        Err(FrameError::PayloadTooLarge)
    );
}

#[test]
fn frame_policy_rejects_unbounded_settings() {
    assert_eq!(FramePolicy::new(0, 1, 1, 1), Err(FrameError::InvalidPolicy));
    assert_eq!(FramePolicy::new(1, 3, 1, 1), Err(FrameError::InvalidPolicy));
    assert_eq!(FramePolicy::new(1, 1, 0, 1), Err(FrameError::InvalidPolicy));
}
