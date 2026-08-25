use std::time::Duration;

use browserd_targets::{
    BackendNodeId, DocumentEpoch, NodeBinding, NodeHandleStore, NodeResolutionContext,
    NodeResolutionError, SessionIncarnation, SnapshotId, TargetIncarnation, TargetTime,
    UrlRevision, classify_selector_match_count,
};

fn binding(backend_node: u64) -> NodeBinding {
    NodeBinding {
        session_incarnation: SessionIncarnation::new(1),
        target_incarnation: TargetIncarnation::new(10),
        frame_document_epoch: DocumentEpoch::new(20),
        backend_node_id: BackendNodeId::new(backend_node),
        snapshot_id: SnapshotId::new(30),
        url_revision: UrlRevision::new(40),
    }
}

fn context() -> NodeResolutionContext {
    NodeResolutionContext {
        session_incarnation: SessionIncarnation::new(1),
        target_incarnation: TargetIncarnation::new(10),
        frame_document_epoch: DocumentEpoch::new(20),
        required_snapshot_id: None,
        current_url_revision: UrlRevision::new(40),
        attached: true,
        visible: true,
        obscured: false,
        disabled: false,
    }
}

#[test]
fn handles_are_opaque_unique_tokens_unrelated_to_backend_node_ids() {
    let mut store = NodeHandleStore::new(2, Duration::from_secs(60));
    let first = store.insert(binding(9_001), TargetTime::new(0));
    let second = store.insert(binding(9_001), TargetTime::new(1));

    assert_ne!(first, second);
    assert_ne!(first.as_token(), "9001");
    assert_ne!(second.as_token(), "9001");
}

#[test]
fn node_handles_expire_at_ttl_even_when_they_were_recently_used() {
    let mut store = NodeHandleStore::new(2, Duration::from_secs(1));
    let handle = store.insert(binding(100), TargetTime::new(0));

    assert!(
        store
            .resolve(&handle, &context(), TargetTime::new(999))
            .is_ok()
    );
    assert_eq!(
        store.resolve(&handle, &context(), TargetTime::new(1_000)),
        Err(NodeResolutionError::StaleNodeRef),
    );
}

#[test]
fn capacity_uses_lru_and_successful_resolution_refreshes_recency() {
    let mut store = NodeHandleStore::new(2, Duration::from_secs(60));
    let first = store.insert(binding(101), TargetTime::new(0));
    let second = store.insert(binding(102), TargetTime::new(1));
    assert!(
        store
            .resolve(&first, &context(), TargetTime::new(2))
            .is_ok()
    );
    let third = store.insert(binding(103), TargetTime::new(3));

    assert!(
        store
            .resolve(&first, &context(), TargetTime::new(4))
            .is_ok()
    );
    assert_eq!(
        store.resolve(&second, &context(), TargetTime::new(4)),
        Err(NodeResolutionError::StaleNodeRef),
    );
    assert!(
        store
            .resolve(&third, &context(), TargetTime::new(4))
            .is_ok()
    );
}

#[test]
fn session_target_and_snapshot_fences_are_stale_node_refs() {
    let cases = [
        NodeResolutionContext {
            session_incarnation: SessionIncarnation::new(2),
            ..context()
        },
        NodeResolutionContext {
            target_incarnation: TargetIncarnation::new(11),
            ..context()
        },
        NodeResolutionContext {
            required_snapshot_id: Some(SnapshotId::new(31)),
            ..context()
        },
    ];

    for resolution_context in cases {
        let mut store = NodeHandleStore::new(1, Duration::from_secs(60));
        let handle = store.insert(binding(200), TargetTime::new(0));
        assert_eq!(
            store.resolve(&handle, &resolution_context, TargetTime::new(1)),
            Err(NodeResolutionError::StaleNodeRef),
        );
    }
}

#[test]
fn frame_document_epoch_mismatch_is_exactly_stale_document_ref() {
    let mut store = NodeHandleStore::new(1, Duration::from_secs(60));
    let handle = store.insert(binding(300), TargetTime::new(0));
    let resolution_context = NodeResolutionContext {
        frame_document_epoch: DocumentEpoch::new(21),
        attached: false,
        visible: false,
        obscured: true,
        disabled: true,
        ..context()
    };

    assert_eq!(
        store.resolve(&handle, &resolution_context, TargetTime::new(1)),
        Err(NodeResolutionError::StaleDocumentRef),
    );
}

#[test]
fn attachment_and_actionability_failures_have_stable_precedence() {
    let cases = [
        (
            NodeResolutionContext {
                attached: false,
                visible: false,
                obscured: true,
                disabled: true,
                ..context()
            },
            NodeResolutionError::NodeDetached,
        ),
        (
            NodeResolutionContext {
                visible: false,
                obscured: true,
                disabled: true,
                ..context()
            },
            NodeResolutionError::NodeNotVisible,
        ),
        (
            NodeResolutionContext {
                obscured: true,
                disabled: true,
                ..context()
            },
            NodeResolutionError::NodeObscured,
        ),
        (
            NodeResolutionContext {
                disabled: true,
                ..context()
            },
            NodeResolutionError::NodeDisabled,
        ),
    ];

    for (resolution_context, expected) in cases {
        let mut store = NodeHandleStore::new(1, Duration::from_secs(60));
        let handle = store.insert(binding(400), TargetTime::new(0));
        assert_eq!(
            store.resolve(&handle, &resolution_context, TargetTime::new(1)),
            Err(expected),
        );
    }
}

#[test]
fn url_revision_and_snapshot_are_only_diagnostic_unless_snapshot_is_required() {
    let mut store = NodeHandleStore::new(1, Duration::from_secs(60));
    let handle = store.insert(binding(500), TargetTime::new(0));
    let resolution_context = NodeResolutionContext {
        current_url_revision: UrlRevision::new(999),
        required_snapshot_id: None,
        ..context()
    };

    assert!(
        store
            .resolve(&handle, &resolution_context, TargetTime::new(1))
            .is_ok()
    );
}

#[test]
fn strict_selector_requires_exactly_one_match() {
    assert_eq!(classify_selector_match_count(1), Ok(()));
    assert_eq!(
        classify_selector_match_count(2),
        Err(NodeResolutionError::AmbiguousSelector),
    );
}
