use browserd_targets::{
    DocumentEpoch, FrameId, PageEpochTracker, PageId, TargetIncarnation, UrlRevision,
};

fn tracker() -> PageEpochTracker {
    PageEpochTracker::new(
        PageId::new(),
        TargetIncarnation::new(10),
        FrameId::new("top-frame"),
    )
}

#[test]
fn same_document_navigation_only_increments_url_revision() {
    let mut tracker = tracker();
    let top = FrameId::new("top-frame");
    let before = tracker.frame_state(&top);
    assert!(before.is_some());
    let Some(before) = before else {
        return;
    };

    assert_eq!(tracker.url_revision(), UrlRevision::new(1));
    assert_eq!(
        tracker.record_same_document_navigation(),
        UrlRevision::new(2),
    );
    assert_eq!(tracker.url_revision(), UrlRevision::new(2));

    let after = tracker.frame_state(&top);
    assert!(after.is_some());
    let Some(after) = after else {
        return;
    };
    assert_eq!(after.document_epoch(), before.document_epoch());
    assert_eq!(after.target_incarnation(), before.target_incarnation(),);
}

#[test]
fn document_epochs_are_independent_for_every_frame() {
    let mut tracker = tracker();
    let top = FrameId::new("top-frame");
    let child_a = FrameId::new("child-a");
    let child_b = FrameId::new("child-b");
    assert_eq!(
        tracker.attach_frame(child_a.clone(), TargetIncarnation::new(20)),
        Ok(DocumentEpoch::new(1)),
    );
    assert_eq!(
        tracker.attach_frame(child_b.clone(), TargetIncarnation::new(30)),
        Ok(DocumentEpoch::new(1)),
    );

    assert_eq!(
        tracker.document_committed(&child_a),
        Ok(DocumentEpoch::new(2)),
    );
    assert_eq!(
        tracker
            .frame_state(&top)
            .map(|state| state.document_epoch()),
        Some(DocumentEpoch::new(1)),
    );
    assert_eq!(
        tracker
            .frame_state(&child_b)
            .map(|state| state.document_epoch()),
        Some(DocumentEpoch::new(1)),
    );
}

#[test]
fn oopif_target_replacement_fences_the_old_target_and_document() {
    let mut tracker = tracker();
    let oopif = FrameId::new("oopif-frame");
    assert_eq!(
        tracker.attach_frame(oopif.clone(), TargetIncarnation::new(40)),
        Ok(DocumentEpoch::new(1)),
    );

    assert_eq!(
        tracker.replace_oopif_target(&oopif, TargetIncarnation::new(41)),
        Ok(DocumentEpoch::new(2)),
    );
    let state = tracker.frame_state(&oopif);
    assert!(state.is_some());
    let Some(state) = state else {
        return;
    };
    assert_eq!(state.target_incarnation(), TargetIncarnation::new(41));
    assert_eq!(state.document_epoch(), DocumentEpoch::new(2));
}

#[test]
fn external_page_id_is_opaque_and_not_the_chromium_target_id() {
    let tracker = tracker();

    assert_eq!(tracker.page_id().as_uuid().get_version_num(), 4);
    assert_eq!(tracker.target_incarnation(), TargetIncarnation::new(10));
    assert_ne!(tracker.page_id().to_string(), "target-primary");
}
