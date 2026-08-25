use std::sync::{Arc, Barrier};
use std::thread;

use browserd_core::{
    IsolationProfile, SafetySwitchError, SafetySwitchMutation, SafetySwitchRegistry,
};

#[test]
fn defaults_fail_closed_for_unqualified_shared_admission() {
    let switches = SafetySwitchRegistry::production_defaults();
    let snapshot = switches.snapshot();

    assert!(snapshot.force_dedicated_process());
    assert_eq!(snapshot.max_contexts_per_shard(), 1);
    assert_eq!(
        snapshot.effective_isolation(IsolationProfile::SharedContext),
        IsolationProfile::DedicatedProcess
    );
    assert!(!snapshot.shared_context_admission_allowed());
}

#[test]
fn an_explicit_qualification_can_open_shared_admission_with_a_bounded_density() {
    let switches = SafetySwitchRegistry::production_defaults();
    let result = switches.update(
        0,
        "operator-a",
        "qualification receipt verified",
        SafetySwitchMutation::SetSharedAdmission {
            qualified: true,
            force_dedicated_process: false,
            max_contexts_per_shard: 4,
        },
    );

    assert!(result.is_ok());
    if let Ok(first) = result {
        assert_eq!(first.previous_version(), 0);
        assert_eq!(first.version(), 1);
        assert_eq!(first.actor(), "operator-a");
        assert_eq!(first.reason(), "qualification receipt verified");
        assert!(first.snapshot().shared_context_admission_allowed());
        assert_eq!(first.snapshot().max_contexts_per_shard(), 4);
        assert_eq!(
            first
                .snapshot()
                .effective_isolation(IsolationProfile::SharedContext),
            IsolationProfile::SharedContext
        );
    }
}

#[test]
fn shared_admission_cannot_open_without_qualification_or_with_unsafe_density() {
    let switches = SafetySwitchRegistry::production_defaults();

    assert_eq!(
        switches.update(
            0,
            "operator",
            "unsafe attempt",
            SafetySwitchMutation::SetSharedAdmission {
                qualified: false,
                force_dedicated_process: false,
                max_contexts_per_shard: 2,
            },
        ),
        Err(SafetySwitchError::SharedContextNotQualified)
    );
    assert_eq!(
        switches.update(
            0,
            "operator",
            "bad density",
            SafetySwitchMutation::SetSharedAdmission {
                qualified: true,
                force_dedicated_process: false,
                max_contexts_per_shard: 9,
            },
        ),
        Err(SafetySwitchError::InvalidContextLimit { value: 9 })
    );
    assert_eq!(switches.snapshot().version(), 0);
}

#[test]
fn force_dedicated_can_be_reenabled_without_a_qualification_token() {
    let switches = SafetySwitchRegistry::production_defaults();
    assert!(
        switches
            .update(
                0,
                "operator",
                "qualified",
                SafetySwitchMutation::SetSharedAdmission {
                    qualified: true,
                    force_dedicated_process: false,
                    max_contexts_per_shard: 4,
                },
            )
            .is_ok()
    );

    let rollback = switches.update(
        1,
        "incident-controller",
        "target bootstrap regression",
        SafetySwitchMutation::ForceDedicatedProcess,
    );

    assert!(rollback.is_ok());
    let snapshot = switches.snapshot();
    assert!(snapshot.force_dedicated_process());
    assert_eq!(snapshot.max_contexts_per_shard(), 1);
    assert!(!snapshot.shared_context_admission_allowed());
}

#[test]
fn independent_feature_and_network_kill_switches_are_snapshotted() {
    let switches = SafetySwitchRegistry::production_defaults();
    let digest = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";
    let mutations = [
        SafetySwitchMutation::DisableEvaluate(true),
        SafetySwitchMutation::DisableViewerControl(true),
        SafetySwitchMutation::DisableDownloads(true),
        SafetySwitchMutation::DisableCheckpoint(true),
        SafetySwitchMutation::SetMaxTargetsPerSession(24),
        SafetySwitchMutation::SetChromiumBuildDisabled {
            digest: digest.to_owned(),
            disabled: true,
        },
        SafetySwitchMutation::SetDeniedDomain {
            domain: "example.invalid".to_owned(),
            denied: true,
        },
        SafetySwitchMutation::SetStoppedNetworkClass {
            network_class: "private".to_owned(),
            stopped: true,
        },
    ];

    for (version, mutation) in mutations.into_iter().enumerate() {
        assert!(
            switches
                .update(version as u64, "operator", "test mutation", mutation,)
                .is_ok()
        );
    }

    let snapshot = switches.snapshot();
    assert!(snapshot.evaluate_disabled());
    assert!(snapshot.viewer_control_disabled());
    assert!(snapshot.downloads_disabled());
    assert!(snapshot.checkpoint_disabled());
    assert_eq!(snapshot.max_targets_per_session(), 24);
    assert!(snapshot.chromium_build_disabled(digest));
    assert!(snapshot.domain_denied("EXAMPLE.INVALID."));
    assert!(snapshot.network_class_stopped("private"));
}

#[test]
fn compare_and_swap_allows_exactly_one_concurrent_operator_update() {
    let switches = Arc::new(SafetySwitchRegistry::production_defaults());
    let barrier = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();

    for index in 0..8 {
        let switches = Arc::clone(&switches);
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            switches.update(
                0,
                format!("operator-{index}"),
                "concurrent rollback",
                SafetySwitchMutation::DisableViewerControl(true),
            )
        }));
    }
    barrier.wait();

    let mut outcomes = Vec::new();
    for thread in threads {
        if let Ok(outcome) = thread.join() {
            outcomes.push(outcome);
        }
    }
    assert_eq!(outcomes.len(), 8);
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(SafetySwitchError::VersionConflict { .. })))
            .count(),
        7
    );
    assert_eq!(switches.snapshot().version(), 1);
}

#[test]
fn invalid_operator_input_does_not_advance_the_version() {
    let switches = SafetySwitchRegistry::production_defaults();

    assert_eq!(
        switches.update(0, "", "reason", SafetySwitchMutation::DisableEvaluate(true),),
        Err(SafetySwitchError::ActorRequired)
    );
    assert_eq!(
        switches.update(
            0,
            "operator",
            "",
            SafetySwitchMutation::DisableEvaluate(true),
        ),
        Err(SafetySwitchError::ReasonRequired)
    );
    assert_eq!(
        switches.update(
            0,
            "operator",
            "bad target count",
            SafetySwitchMutation::SetMaxTargetsPerSession(0),
        ),
        Err(SafetySwitchError::InvalidTargetLimit { value: 0 })
    );
    assert_eq!(switches.snapshot().version(), 0);
}
