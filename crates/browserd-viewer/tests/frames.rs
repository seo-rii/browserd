#![allow(clippy::expect_used)]

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use std::{panic::AssertUnwindSafe, panic::catch_unwind};

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
fn blocked_acknowledgement_does_not_block_observer_operations() {
    #[derive(Debug)]
    enum ObserverOperationResult {
        NextFrame(Result<Option<ViewerFrame>, FrameError>),
        Attach(Result<(), FrameError>),
        Detach(Result<(), FrameError>),
    }

    let fixture = connected_fixture(ViewerScopes::new(true, true, false));
    let detached = additional_connection(&fixture, ViewerScopes::new(true, false, false));
    let attached = additional_connection(&fixture, ViewerScopes::new(true, false, false));
    let broadcaster = Arc::new(FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(4, 2, 1024, 4096).expect("frame policy should be valid"),
    ));
    broadcaster
        .attach(&fixture.connection)
        .expect("primary observer should attach");
    broadcaster
        .attach(&detached)
        .expect("observer selected for detach should attach");
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
        .expect("initial frame should publish");

    let (acknowledgement_entered_tx, acknowledgement_entered_rx) = mpsc::sync_channel(1);
    let (release_acknowledgement_tx, release_acknowledgement_rx) = mpsc::sync_channel(1);
    let ingest_broadcaster = Arc::clone(&broadcaster);
    let page_id = fixture.page_id.clone();
    let transform_epoch = fixture.transform_epoch;
    let ingest = thread::spawn(move || {
        ingest_broadcaster.ingest(
            ViewerFrame::new(2, page_id, transform_epoch, b"{}".to_vec(), vec![2]),
            move |_| {
                acknowledgement_entered_tx
                    .send(())
                    .map_err(|_| FrameError::ChromiumAckFailed)?;
                release_acknowledgement_rx
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| FrameError::ChromiumAckFailed)?;
                Ok(())
            },
        )
    });
    acknowledgement_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("acknowledgement callback should start");

    let start_operations = Arc::new(Barrier::new(4));
    let (operation_tx, operation_rx) = mpsc::sync_channel(3);

    let next_broadcaster = Arc::clone(&broadcaster);
    let next_connection_id = fixture.connection.id().clone();
    let next_start = Arc::clone(&start_operations);
    let next_tx = operation_tx.clone();
    let next = thread::spawn(move || {
        next_start.wait();
        next_tx
            .send(ObserverOperationResult::NextFrame(
                next_broadcaster.next_frame(&next_connection_id),
            ))
            .expect("operation result receiver should remain available");
    });

    let attach_broadcaster = Arc::clone(&broadcaster);
    let attach_start = Arc::clone(&start_operations);
    let attach_tx = operation_tx.clone();
    let attach = thread::spawn(move || {
        attach_start.wait();
        attach_tx
            .send(ObserverOperationResult::Attach(
                attach_broadcaster.attach(&attached),
            ))
            .expect("operation result receiver should remain available");
    });

    let detach_broadcaster = Arc::clone(&broadcaster);
    let detach_connection_id = detached.id().clone();
    let detach_start = Arc::clone(&start_operations);
    let detach_tx = operation_tx;
    let detach = thread::spawn(move || {
        detach_start.wait();
        detach_tx
            .send(ObserverOperationResult::Detach(
                detach_broadcaster.detach(&detach_connection_id),
            ))
            .expect("operation result receiver should remain available");
    });

    start_operations.wait();
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut next_result = None;
    let mut attach_result = None;
    let mut detach_result = None;
    for _ in 0..3 {
        let Ok(result) =
            operation_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        else {
            break;
        };
        match result {
            ObserverOperationResult::NextFrame(result) => next_result = Some(result),
            ObserverOperationResult::Attach(result) => attach_result = Some(result),
            ObserverOperationResult::Detach(result) => detach_result = Some(result),
        }
    }

    release_acknowledgement_tx
        .send(())
        .expect("blocked acknowledgement should be releasable");
    next.join().expect("next-frame thread should finish");
    attach.join().expect("attach thread should finish");
    detach.join().expect("detach thread should finish");
    assert!(
        ingest.join().expect("ingest thread should finish").is_ok(),
        "ingest should publish after acknowledgement is released"
    );

    assert_eq!(
        next_result
            .expect("next_frame should complete while acknowledgement is blocked")
            .expect("primary observer should exist")
            .expect("initial frame should remain available")
            .frame_id(),
        1
    );
    assert_eq!(
        attach_result.expect("attach should complete while acknowledgement is blocked"),
        Ok(())
    );
    assert_eq!(
        detach_result.expect("detach should complete while acknowledgement is blocked"),
        Ok(())
    );
}

#[test]
fn concurrent_ingests_acknowledge_and_publish_in_frame_id_order() {
    let fixture = connected_fixture(ViewerScopes::new(true, false, false));
    let broadcaster = Arc::new(FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(1, 2, 1024, 4096).expect("frame policy should be valid"),
    ));
    broadcaster
        .attach(&fixture.connection)
        .expect("observer should attach");

    let acknowledged_frame_ids = Arc::new(Mutex::new(Vec::new()));
    let (first_acknowledgement_entered_tx, first_acknowledgement_entered_rx) =
        mpsc::sync_channel(1);
    let (release_first_acknowledgement_tx, release_first_acknowledgement_rx) =
        mpsc::sync_channel(1);
    let first_broadcaster = Arc::clone(&broadcaster);
    let first_page_id = fixture.page_id.clone();
    let transform_epoch = fixture.transform_epoch;
    let first_acknowledged_frame_ids = Arc::clone(&acknowledged_frame_ids);
    let first = thread::spawn(move || {
        first_broadcaster.ingest(
            ViewerFrame::new(1, first_page_id, transform_epoch, b"{}".to_vec(), vec![1]),
            move |frame_id| {
                first_acknowledgement_entered_tx
                    .send(())
                    .map_err(|_| FrameError::ChromiumAckFailed)?;
                release_first_acknowledgement_rx
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| FrameError::ChromiumAckFailed)?;
                first_acknowledged_frame_ids
                    .lock()
                    .map_err(|_| FrameError::StateUnavailable)?
                    .push(frame_id);
                Ok(())
            },
        )
    });
    first_acknowledgement_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first acknowledgement should start");

    let (second_ingest_started_tx, second_ingest_started_rx) = mpsc::sync_channel(1);
    let (second_acknowledgement_tx, second_acknowledgement_rx) = mpsc::sync_channel(1);
    let second_broadcaster = Arc::clone(&broadcaster);
    let second_page_id = fixture.page_id.clone();
    let second_acknowledged_frame_ids = Arc::clone(&acknowledged_frame_ids);
    let second = thread::spawn(move || {
        second_ingest_started_tx
            .send(())
            .expect("second ingest start receiver should remain available");
        second_broadcaster.ingest(
            ViewerFrame::new(2, second_page_id, transform_epoch, b"{}".to_vec(), vec![2]),
            move |frame_id| {
                second_acknowledged_frame_ids
                    .lock()
                    .map_err(|_| FrameError::StateUnavailable)?
                    .push(frame_id);
                second_acknowledgement_tx
                    .send(())
                    .map_err(|_| FrameError::ChromiumAckFailed)?;
                Ok(())
            },
        )
    });
    second_ingest_started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("second ingest should start");
    let second_acknowledgement_before_release =
        second_acknowledgement_rx.recv_timeout(Duration::from_millis(250));

    release_first_acknowledgement_tx
        .send(())
        .expect("first acknowledgement should be releasable");
    let first_outcome = first
        .join()
        .expect("first ingest thread should finish")
        .expect("first frame should publish");
    assert_eq!(first_outcome.observer_count(), 1);
    assert_eq!(first_outcome.dropped_frames(), 0);
    let second_outcome = second
        .join()
        .expect("second ingest thread should finish")
        .expect("second frame should publish");
    assert_eq!(second_outcome.observer_count(), 1);
    assert_eq!(second_outcome.dropped_frames(), 0);

    assert!(
        matches!(
            second_acknowledgement_before_release,
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "second acknowledgement must not overtake the first"
    );
    assert_eq!(
        *acknowledged_frame_ids
            .lock()
            .expect("acknowledgement order should remain available"),
        [1, 2]
    );
    let published_frame_ids = [
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("observer should exist")
            .expect("first frame should be published")
            .frame_id(),
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("observer should exist")
            .expect("second frame should be published")
            .frame_id(),
    ];
    assert_eq!(published_frame_ids, [1, 2]);
}

#[test]
fn transform_change_during_acknowledgement_rejects_the_reserved_frame() {
    let fixture = connected_fixture(ViewerScopes::new(true, false, false));
    let broadcaster = Arc::new(FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(1, 1, 1024, 4096).expect("frame policy should be valid"),
    ));
    broadcaster
        .attach(&fixture.connection)
        .expect("observer should attach");

    let (acknowledgement_entered_tx, acknowledgement_entered_rx) = mpsc::sync_channel(1);
    let (release_acknowledgement_tx, release_acknowledgement_rx) = mpsc::sync_channel(1);
    let ingest_broadcaster = Arc::clone(&broadcaster);
    let page_id = fixture.page_id.clone();
    let transform_epoch = fixture.transform_epoch;
    let ingest = thread::spawn(move || {
        ingest_broadcaster.ingest(
            ViewerFrame::new(1, page_id, transform_epoch, b"{}".to_vec(), vec![1]),
            move |_| {
                acknowledgement_entered_tx
                    .send(())
                    .map_err(|_| FrameError::ChromiumAckFailed)?;
                release_acknowledgement_rx
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| FrameError::ChromiumAckFailed)?;
                Ok(())
            },
        )
    });
    acknowledgement_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("acknowledgement callback should start");

    let (transform_result_tx, transform_result_rx) = mpsc::sync_channel(1);
    let transform_broadcaster = Arc::clone(&broadcaster);
    let replacement_page_id = PageId::new();
    let transform = thread::spawn(move || {
        transform_result_tx
            .send(transform_broadcaster.advance_transform(replacement_page_id))
            .expect("transform result receiver should remain available");
    });
    let transform_result = transform_result_rx.recv_timeout(Duration::from_secs(1));

    release_acknowledgement_tx
        .send(())
        .expect("blocked acknowledgement should be releasable");
    transform.join().expect("transform thread should finish");
    let ingest_result = ingest.join().expect("ingest thread should finish");

    assert_eq!(
        transform_result.expect("transform should advance while acknowledgement is blocked"),
        Ok(fixture.transform_epoch + 1)
    );
    assert_eq!(ingest_result, Err(FrameError::PageMismatch));
    assert!(
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("observer should remain attached")
            .is_none(),
        "a frame reserved before the transform changed must not be published"
    );
}

#[test]
fn panicking_acknowledgement_releases_the_ingest_reservation() {
    let fixture = connected_fixture(ViewerScopes::new(true, false, false));
    let broadcaster = FrameBroadcaster::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        1,
        fixture.page_id.clone(),
        fixture.transform_epoch,
        FramePolicy::new(1, 1, 1024, 4096).expect("frame policy should be valid"),
    );
    broadcaster
        .attach(&fixture.connection)
        .expect("observer should attach");

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = broadcaster.ingest(
            ViewerFrame::new(
                1,
                fixture.page_id.clone(),
                fixture.transform_epoch,
                b"{}".to_vec(),
                vec![1],
            ),
            |_| -> Result<(), FrameError> {
                std::panic::resume_unwind(Box::new("simulated chromium acknowledgement panic"))
            },
        );
    }));
    assert!(panic.is_err());

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
        .expect("a later frame should publish after the callback panic");
    assert_eq!(
        broadcaster
            .next_frame(fixture.connection.id())
            .expect("observer state should not be poisoned")
            .expect("the later frame should be visible")
            .frame_id(),
        1
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
