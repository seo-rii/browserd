use std::time::Duration;

use browserd_core::{
    ActionResourceClass, IsolationEscalation, IsolationPolicy, IsolationProfile, ResourceRequest,
    ResourceValidationError, RuntimeLimits,
};

const KIB: u64 = 1_024;
const MIB: u64 = 1_024 * KIB;
const GIB: u64 = 1_024 * MIB;

#[test]
fn policy_minimum_escalates_but_never_downgrades_requested_isolation() {
    let tenant_minimum = IsolationPolicy::new(IsolationProfile::TenantDedicatedShard, false);
    let shared = tenant_minimum.decide(IsolationProfile::SharedContext, IsolationEscalation::None);
    let already_stronger = tenant_minimum.decide(
        IsolationProfile::DedicatedProcess,
        IsolationEscalation::None,
    );

    assert_eq!(
        shared.effective_profile(),
        IsolationProfile::TenantDedicatedShard
    );
    assert_eq!(
        already_stronger.effective_profile(),
        IsolationProfile::DedicatedProcess
    );
}

#[test]
fn abuse_escalation_is_monotonic() {
    let policy = IsolationPolicy::new(IsolationProfile::SharedContext, false);

    assert_eq!(
        policy
            .decide(
                IsolationProfile::SharedContext,
                IsolationEscalation::TenantDedicatedShard,
            )
            .effective_profile(),
        IsolationProfile::TenantDedicatedShard
    );
    assert_eq!(
        policy
            .decide(
                IsolationProfile::TenantDedicatedShard,
                IsolationEscalation::DedicatedProcess,
            )
            .effective_profile(),
        IsolationProfile::DedicatedProcess
    );
    assert_eq!(
        policy
            .decide(
                IsolationProfile::DedicatedProcess,
                IsolationEscalation::TenantDedicatedShard,
            )
            .effective_profile(),
        IsolationProfile::DedicatedProcess
    );
}

#[test]
fn force_dedicated_process_kill_switch_means_one_session_per_chromium() {
    let policy = IsolationPolicy::new(IsolationProfile::SharedContext, true);

    for requested in [
        IsolationProfile::SharedContext,
        IsolationProfile::TenantDedicatedShard,
        IsolationProfile::DedicatedProcess,
    ] {
        let decision = policy.decide(requested, IsolationEscalation::None);
        assert_eq!(
            decision.effective_profile(),
            IsolationProfile::DedicatedProcess
        );
        assert!(decision.single_session_per_chromium());
    }

    let dedicated_worker =
        policy.decide(IsolationProfile::DedicatedWorker, IsolationEscalation::None);
    assert_eq!(
        dedicated_worker.effective_profile(),
        IsolationProfile::DedicatedWorker
    );
    assert!(dedicated_worker.single_session_per_chromium());
}

#[test]
fn initial_runtime_limits_match_the_spec_benchmark_defaults() {
    let limits = RuntimeLimits::default();

    assert_eq!(limits.session.max_contexts_per_shard, 8);
    assert_eq!(limits.session.max_pages_per_session, 8);
    assert_eq!(limits.session.max_pages_per_shard, 32);
    assert_eq!(limits.session.max_frames_per_session, 64);
    assert_eq!(limits.session.max_workers_per_session, 16);
    assert_eq!(limits.session.max_service_workers_per_session, 8);
    assert_eq!(limits.session.max_targets_per_session, 96);
    assert_eq!(limits.session.max_targets_per_shard, 256);
    assert_eq!(limits.session.max_target_creations_per_10s, 64);
    assert_eq!(limits.session.default_ttl, Duration::from_secs(30 * 60));
    assert_eq!(
        limits.session.default_idle_timeout,
        Duration::from_secs(10 * 60)
    );
    assert_eq!(
        limits.session.create_operation_deadline,
        Duration::from_secs(30)
    );
    assert_eq!(
        limits.session.browser_max_age,
        Duration::from_secs(2 * 60 * 60)
    );
    assert_eq!(limits.session.max_contexts_per_browser_lifetime, 500);

    assert_eq!(
        limits.action.default_execution_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(
        limits.action.navigation_execution_timeout,
        Duration::from_secs(45)
    );
    assert_eq!(
        limits.action.pdf_scrape_execution_timeout,
        Duration::from_secs(60)
    );
    assert_eq!(limits.action.max_evaluate_source_bytes, 64 * KIB);
    assert_eq!(limits.action.max_evaluate_result_bytes, MIB);
    assert_eq!(limits.action.max_selector_bytes, 8 * KIB);
    assert_eq!(limits.action.max_pending_actions_per_session, 64);

    assert_eq!(limits.memory.soft_shard.absolute_bytes, 5 * GIB / 2);
    assert_eq!(limits.memory.soft_shard.budget_percent, 70);
    assert_eq!(limits.memory.hard_shard.absolute_bytes, 7 * GIB / 2);
    assert_eq!(limits.memory.hard_shard.budget_percent, 90);
    assert!(limits.memory.oom_group);
    assert_eq!(limits.memory.private_dev_shm_bytes, 512 * MIB);
    assert_eq!(limits.memory.profile_temp_filesystem_bytes, 2 * GIB);
    assert_eq!(limits.memory.rlimit_core_bytes, 0);

    assert_eq!(limits.artifact.max_upload_file_bytes, 50 * MIB);
    assert_eq!(limits.artifact.max_download_file_bytes, 100 * MIB);
    assert_eq!(limits.artifact.max_committed_bytes_per_session, 500 * MIB);
    assert_eq!(limits.artifact.max_in_flight_bytes_per_session, 128 * MIB);
    assert_eq!(limits.artifact.max_screenshot_width, 1_920);
    assert_eq!(limits.artifact.max_screenshot_height, 1_080);
    assert_eq!(
        limits.artifact.max_inline_snapshot_screenshot_bytes,
        512 * KIB
    );

    assert_eq!(limits.viewer.target_fps, 12);
    assert_eq!(limits.viewer.jpeg_quality, 70);
    assert_eq!(limits.viewer.rendered_width, 1_920);
    assert_eq!(limits.viewer.rendered_height, 1_080);
    assert!((1..=2).contains(&limits.viewer.frame_queue_capacity));
    assert_eq!(limits.viewer.control_lease, Duration::from_secs(60));
    assert_eq!(limits.viewer.max_observers_per_session, 4);
    assert_eq!(limits.viewer.max_input_messages_per_10s, 240);

    assert_eq!(limits.snapshot.max_nodes, 3_000);
    assert_eq!(limits.snapshot.max_string_bytes_per_node, 4 * KIB);
    assert_eq!(limits.snapshot.max_result_bytes, 4 * MIB);
    assert_eq!(limits.snapshot.max_generation_time, Duration::from_secs(10));
    assert!(limits.validate().is_ok());
}

#[test]
fn runtime_limit_validation_rejects_unsafe_cross_limit_relationships() {
    let mut soft_not_below_hard = RuntimeLimits::default();
    soft_not_below_hard.memory.soft_shard.absolute_bytes =
        soft_not_below_hard.memory.hard_shard.absolute_bytes;
    assert_eq!(
        soft_not_below_hard.validate(),
        Err(ResourceValidationError::SoftMemoryNotBelowHard)
    );

    let mut session_pages_exceed_shard = RuntimeLimits::default();
    session_pages_exceed_shard.session.max_pages_per_session =
        session_pages_exceed_shard.session.max_pages_per_shard + 1;
    assert_eq!(
        session_pages_exceed_shard.validate(),
        Err(ResourceValidationError::SessionPagesExceedShard)
    );

    let mut session_targets_exceed_shard = RuntimeLimits::default();
    session_targets_exceed_shard.session.max_targets_per_session =
        session_targets_exceed_shard.session.max_targets_per_shard + 1;
    assert_eq!(
        session_targets_exceed_shard.validate(),
        Err(ResourceValidationError::SessionTargetsExceedShard)
    );

    for invalid_queue_capacity in [0, 3] {
        let mut invalid = RuntimeLimits::default();
        invalid.viewer.frame_queue_capacity = invalid_queue_capacity;
        assert_eq!(
            invalid.validate(),
            Err(ResourceValidationError::ViewerFrameQueueOutOfRange)
        );
    }
}

#[test]
fn resource_request_is_a_vector_and_must_fit_hard_session_and_shard_limits() {
    let limits = RuntimeLimits::default();
    let valid = ResourceRequest {
        context_slots: 1,
        memory_reservation_bytes: 440 * MIB,
        page_slots: 8,
        target_slots: 96,
        viewer_slots: 1,
        process_slots: 0,
        action_class: ActionResourceClass::default(),
    };
    assert!(valid.validate_against(&limits).is_ok());

    let too_many_pages = ResourceRequest {
        page_slots: 9,
        ..valid.clone()
    };
    assert_eq!(
        too_many_pages.validate_against(&limits),
        Err(ResourceValidationError::PageSlotsExceeded)
    );

    let too_many_contexts = ResourceRequest {
        context_slots: 9,
        ..valid.clone()
    };
    assert_eq!(
        too_many_contexts.validate_against(&limits),
        Err(ResourceValidationError::ContextSlotsExceeded)
    );

    let too_many_targets = ResourceRequest {
        target_slots: 97,
        ..valid.clone()
    };
    assert_eq!(
        too_many_targets.validate_against(&limits),
        Err(ResourceValidationError::TargetSlotsExceeded)
    );

    let too_many_viewers = ResourceRequest {
        viewer_slots: 5,
        ..valid.clone()
    };
    assert_eq!(
        too_many_viewers.validate_against(&limits),
        Err(ResourceValidationError::ViewerSlotsExceeded)
    );

    let too_much_memory = ResourceRequest {
        memory_reservation_bytes: limits.memory.hard_shard.absolute_bytes + 1,
        ..valid
    };
    assert_eq!(
        too_much_memory.validate_against(&limits),
        Err(ResourceValidationError::MemoryReservationExceeded)
    );
}
