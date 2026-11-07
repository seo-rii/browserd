#![allow(clippy::expect_used)]

use std::time::Duration;

use browserd_core::{PlacementFence, SessionId, TenantId, WorkerId};
use browserd_targets::{
    BackendNodeId, DocumentEpoch, FlattenedSessionId, FrameEpochFence, FrameId, NodeBinding,
    NodeFrameScope, NodeHandle, NodeHandleStore, NodeOwnerBinding, NodeResolutionContext,
    NodeResolutionError, PageId, SessionIncarnation, SnapshotId, TargetIncarnation, TargetTime,
    UrlRevision, classify_selector_match_count,
};

fn scope() -> NodeFrameScope {
    NodeFrameScope {
        owner: NodeOwnerBinding {
            tenant_id: "0198abcd-ef01-7000-8000-000000000001"
                .parse()
                .expect("tenant fixture"),
            session_id: "0198abcd-ef01-7000-8000-000000000002"
                .parse()
                .expect("session fixture"),
            worker_id: WorkerId::new("node-worker").expect("worker fixture"),
            placement_fence: PlacementFence::new(1, 1, 1),
        },
        page_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            .parse()
            .expect("page fixture"),
        frame_id: FrameId::new("root-frame"),
        cdp_session_id: FlattenedSessionId::new("cdp-main-session"),
        ancestors: vec![],
    }
}

fn child_scope() -> NodeFrameScope {
    NodeFrameScope {
        frame_id: FrameId::new("leaf-frame"),
        cdp_session_id: FlattenedSessionId::new("cdp-oopif-session"),
        ancestors: vec![
            FrameEpochFence {
                frame_id: FrameId::new("root-frame"),
                target_incarnation: TargetIncarnation::new(10),
                frame_document_epoch: DocumentEpoch::new(5),
                cdp_session_id: FlattenedSessionId::new("cdp-main-session"),
            },
            FrameEpochFence {
                frame_id: FrameId::new("parent-frame"),
                target_incarnation: TargetIncarnation::new(15),
                frame_document_epoch: DocumentEpoch::new(8),
                cdp_session_id: FlattenedSessionId::new("cdp-parent-session"),
            },
        ],
        ..scope()
    }
}

fn binding(backend_node: u64) -> NodeBinding {
    NodeBinding {
        frame_scope: scope(),
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
        frame_scope: scope(),
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

#[test]
fn ownership_page_frame_and_flattened_route_each_isolate_a_handle() {
    let mutations: &[fn(&mut NodeResolutionContext)] = &[
        |current| current.frame_scope.owner.tenant_id = TenantId::new(),
        |current| current.frame_scope.owner.session_id = SessionId::new(),
        |current| {
            current.frame_scope.owner.worker_id = WorkerId::new("other-worker").expect("worker")
        },
        |current| current.frame_scope.owner.placement_fence.worker_epoch += 1,
        |current| current.frame_scope.owner.placement_fence.placement_version += 1,
        |current| {
            current
                .frame_scope
                .owner
                .placement_fence
                .session_incarnation += 1
        },
        |current| current.frame_scope.page_id = PageId::new(),
        |current| current.frame_scope.frame_id = FrameId::new("other-frame"),
        |current| current.frame_scope.cdp_session_id = FlattenedSessionId::new("other-cdp-session"),
    ];
    for mutate in mutations {
        let mut store = NodeHandleStore::new(1, Duration::from_secs(60));
        let handle = store.insert(binding(700), TargetTime::new(0));
        let mut current = context();
        mutate(&mut current);
        // Ownership/route mismatches precede document and actionability failures.
        current.frame_document_epoch = DocumentEpoch::new(999);
        current.attached = false;
        assert_eq!(
            store.resolve(&handle, &current, TargetTime::new(1)),
            Err(NodeResolutionError::StaleNodeRef)
        );
    }
}

#[test]
fn same_process_siblings_cannot_share_a_backend_id_or_document_epoch() {
    let mut store = NodeHandleStore::new(2, Duration::from_secs(60));
    let mut left = binding(701);
    left.frame_scope = child_scope();
    left.frame_scope.frame_id = FrameId::new("same-process-left");
    left.frame_scope.cdp_session_id = FlattenedSessionId::new("cdp-main-session");
    let mut right = left.clone();
    right.frame_scope.frame_id = FrameId::new("same-process-right");
    let left_handle = store.insert(left.clone(), TargetTime::new(0));
    let right_handle = store.insert(right.clone(), TargetTime::new(1));
    let mut current = context();
    current.frame_scope = right.frame_scope;
    assert_eq!(
        store.resolve(&left_handle, &current, TargetTime::new(2)),
        Err(NodeResolutionError::StaleNodeRef)
    );
    assert_eq!(
        store
            .resolve(&right_handle, &current, TargetTime::new(3))
            .expect("right frame")
            .backend_node_id(),
        BackendNodeId::new(701)
    );
}

#[test]
fn ancestry_is_an_exact_ordered_path_of_frame_target_and_flattened_routes() {
    let mutations: &[fn(&mut NodeFrameScope)] = &[
        |scope| scope.ancestors.swap(0, 1),
        |scope| {
            scope.ancestors.pop();
        },
        |scope| scope.ancestors[0].frame_id = FrameId::new("foreign-root"),
        |scope| scope.ancestors[1].target_incarnation = TargetIncarnation::new(900),
        |scope| {
            scope.ancestors[1].cdp_session_id = FlattenedSessionId::new("foreign-parent-session")
        },
    ];
    for mutate in mutations {
        let mut store = NodeHandleStore::new(1, Duration::from_secs(60));
        let mut original = binding(702);
        original.frame_scope = child_scope();
        let handle = store.insert(original, TargetTime::new(0));
        let mut current = context();
        current.frame_scope = child_scope();
        mutate(&mut current.frame_scope);
        current.frame_scope.ancestors[0].frame_document_epoch = DocumentEpoch::new(999);
        assert_eq!(
            store.resolve(&handle, &current, TargetTime::new(1)),
            Err(NodeResolutionError::StaleNodeRef)
        );
    }
}

#[test]
fn each_ancestor_navigation_invalidates_descendants_before_actionability() {
    for ancestor in 0..2 {
        let mut store = NodeHandleStore::new(1, Duration::from_secs(60));
        let mut original = binding(703);
        original.frame_scope = child_scope();
        let handle = store.insert(original, TargetTime::new(0));
        let mut current = context();
        current.frame_scope = child_scope();
        current.frame_scope.ancestors[ancestor].frame_document_epoch = DocumentEpoch::new(1000);
        current.attached = false;
        current.visible = false;
        current.obscured = true;
        current.disabled = true;
        assert_eq!(
            store.resolve(&handle, &current, TargetTime::new(1)),
            Err(NodeResolutionError::StaleDocumentRef)
        );
    }
}

#[test]
fn reused_frame_id_with_fresh_monotonic_document_generation_cannot_revive_a_token() {
    let mut store = NodeHandleStore::new(2, Duration::from_secs(60));
    let mut old = binding(704);
    old.frame_scope = child_scope();
    let old_handle = store.insert(old.clone(), TargetTime::new(0));
    let mut replacement = old;
    // Owner registry allocates this fresh generation even for reattachment to the same
    // FrameId, flattened CDP session and target incarnation, or execution-realm replacement.
    replacement.frame_document_epoch = DocumentEpoch::new(2000);
    let replacement_handle = store.insert(replacement.clone(), TargetTime::new(1));
    let mut current = context();
    current.frame_scope = replacement.frame_scope;
    current.frame_document_epoch = replacement.frame_document_epoch;
    assert_eq!(
        store.resolve(&old_handle, &current, TargetTime::new(2)),
        Err(NodeResolutionError::StaleDocumentRef)
    );
    assert!(
        store
            .resolve(&replacement_handle, &current, TargetTime::new(3))
            .is_ok()
    );
}

#[test]
fn oopif_target_or_flattened_session_replacement_fences_the_old_route() {
    for change_target in [true, false] {
        let mut store = NodeHandleStore::new(1, Duration::from_secs(60));
        let mut original = binding(705);
        original.frame_scope = child_scope();
        let handle = store.insert(original, TargetTime::new(0));
        let mut current = context();
        current.frame_scope = child_scope();
        if change_target {
            current.target_incarnation = TargetIncarnation::new(11);
        } else {
            current.frame_scope.cdp_session_id = FlattenedSessionId::new("cdp-replacement");
        }
        current.frame_document_epoch = DocumentEpoch::new(2001);
        assert_eq!(
            store.resolve(&handle, &current, TargetTime::new(1)),
            Err(NodeResolutionError::StaleNodeRef)
        );
    }
}

#[test]
fn lookup_returns_provenance_without_authorizing_or_refreshing_lru() {
    let mut store = NodeHandleStore::new(2, Duration::from_secs(60));
    let original = binding(706);
    let first = store.insert(original.clone(), TargetTime::new(0));
    let second = store.insert(binding(707), TargetTime::new(1));
    assert_eq!(
        store
            .lookup_binding(&first, TargetTime::new(2))
            .expect("lookup"),
        original
    );
    let mut foreign = context();
    foreign.frame_scope.owner.tenant_id = TenantId::new();
    assert_eq!(
        store.resolve(&first, &foreign, TargetTime::new(3)),
        Err(NodeResolutionError::StaleNodeRef)
    );
    store.insert(binding(708), TargetTime::new(4));
    assert_eq!(
        store.lookup_binding(&first, TargetTime::new(5)),
        Err(NodeResolutionError::StaleNodeRef)
    );
    assert!(
        store
            .resolve(&second, &context(), TargetTime::new(6))
            .is_ok()
    );
}

#[test]
fn lookup_cannot_extend_ttl_and_rejects_unknown_tokens_and_backward_clock() {
    let mut store = NodeHandleStore::new(1, Duration::from_secs(1));
    let handle = store.insert(binding(709), TargetTime::new(0));
    assert!(store.lookup_binding(&handle, TargetTime::new(999)).is_ok());
    assert_eq!(
        store.lookup_binding(&handle, TargetTime::new(998)),
        Err(NodeResolutionError::StaleNodeRef)
    );
    assert_eq!(
        store.lookup_binding(&handle, TargetTime::new(1000)),
        Err(NodeResolutionError::StaleNodeRef)
    );
    assert_eq!(
        store.lookup_binding(&NodeHandle::from_token("unminted"), TargetTime::new(1001)),
        Err(NodeResolutionError::StaleNodeRef)
    );
    for (capacity, ttl) in [(0, Duration::from_secs(1)), (1, Duration::ZERO)] {
        let mut disabled = NodeHandleStore::new(capacity, ttl);
        let handle = disabled.insert(binding(710), TargetTime::new(0));
        assert_eq!(
            disabled.lookup_binding(&handle, TargetTime::new(0)),
            Err(NodeResolutionError::StaleNodeRef)
        );
    }
}
