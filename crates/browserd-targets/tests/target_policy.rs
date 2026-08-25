use std::time::Duration;

use browserd_targets::{
    TargetAdmission, TargetAdmissionError, TargetInventory, TargetKind, TargetLimits, TargetPolicy,
    TargetTime,
};

fn limits() -> TargetLimits {
    TargetLimits {
        max_pages: 2,
        max_frames: 3,
        max_workers: 2,
        max_service_workers: 1,
        max_total_targets: 6,
        max_creations_per_window: 3,
        creation_window: Duration::from_secs(1),
    }
}

fn empty_inventory() -> TargetInventory {
    TargetInventory {
        pages: 0,
        frames: 0,
        workers: 0,
        service_workers: 0,
        total_targets: 0,
    }
}

#[test]
fn shared_context_default_allows_only_the_bounded_standard_target_types() {
    for kind in [
        TargetKind::Page,
        TargetKind::Iframe,
        TargetKind::DedicatedWorker,
        TargetKind::SharedWorker,
        TargetKind::ServiceWorker,
    ] {
        let mut admission = TargetAdmission::new(TargetPolicy::shared_context_default(), limits());
        assert!(
            admission
                .check_and_record(kind.clone(), empty_inventory(), TargetTime::new(0))
                .is_ok(),
            "standard type was unexpectedly rejected: {kind:?}",
        );
    }
}

#[test]
fn prerender_extension_devtools_and_unknown_targets_fail_closed_in_shared_context() {
    let cases = [
        (
            TargetKind::Prerender,
            TargetAdmissionError::PrerenderDisabled,
        ),
        (
            TargetKind::Extension,
            TargetAdmissionError::ExtensionForbiddenInSharedContext,
        ),
        (
            TargetKind::Devtools,
            TargetAdmissionError::DevtoolsForbidden,
        ),
        (
            TargetKind::Unknown("future-target".to_owned()),
            TargetAdmissionError::UnknownTargetType,
        ),
    ];

    for (kind, expected) in cases {
        let mut admission = TargetAdmission::new(TargetPolicy::shared_context_default(), limits());
        let result = admission.check_and_record(kind, empty_inventory(), TargetTime::new(0));
        assert_eq!(result, Err(expected.clone()));
        assert_eq!(
            expected.requires_shard_taint(),
            expected == TargetAdmissionError::UnknownTargetType,
        );
    }
}

#[test]
fn approved_extensions_are_only_admitted_by_a_dedicated_policy() {
    let mut admission = TargetAdmission::new(
        TargetPolicy::tenant_dedicated_with_approved_extensions(),
        limits(),
    );

    assert!(
        admission
            .check_and_record(TargetKind::Extension, empty_inventory(), TargetTime::new(0),)
            .is_ok()
    );
}

#[test]
fn each_target_class_and_total_target_count_has_an_independent_limit() {
    let cases = [
        (
            TargetKind::Page,
            TargetInventory {
                pages: 2,
                ..empty_inventory()
            },
            TargetAdmissionError::PageLimit,
        ),
        (
            TargetKind::Iframe,
            TargetInventory {
                frames: 3,
                ..empty_inventory()
            },
            TargetAdmissionError::FrameLimit,
        ),
        (
            TargetKind::DedicatedWorker,
            TargetInventory {
                workers: 2,
                ..empty_inventory()
            },
            TargetAdmissionError::WorkerLimit,
        ),
        (
            TargetKind::ServiceWorker,
            TargetInventory {
                service_workers: 1,
                ..empty_inventory()
            },
            TargetAdmissionError::ServiceWorkerLimit,
        ),
        (
            TargetKind::Page,
            TargetInventory {
                total_targets: 6,
                ..empty_inventory()
            },
            TargetAdmissionError::TotalTargetLimit,
        ),
    ];

    for (kind, inventory, expected) in cases {
        let mut admission = TargetAdmission::new(TargetPolicy::shared_context_default(), limits());
        assert_eq!(
            admission.check_and_record(kind, inventory, TargetTime::new(0)),
            Err(expected),
        );
    }
}

#[test]
fn target_creation_rate_is_enforced_in_addition_to_count_limits() {
    let mut admission = TargetAdmission::new(TargetPolicy::shared_context_default(), limits());
    let start = TargetTime::new(0);

    for _ in 0..3 {
        assert!(
            admission
                .check_and_record(TargetKind::Page, empty_inventory(), start)
                .is_ok()
        );
    }
    assert_eq!(
        admission.check_and_record(TargetKind::Page, empty_inventory(), start),
        Err(TargetAdmissionError::CreationRateLimit),
    );
    assert!(
        admission
            .check_and_record(TargetKind::Page, empty_inventory(), TargetTime::new(1_000),)
            .is_ok()
    );
}
