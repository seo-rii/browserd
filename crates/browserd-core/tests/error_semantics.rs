use browserd_core::{ErrorCode, ResponseRepresentation, RetryClass};

fn assert_mapping(code: ErrorCode, expected_http_statuses: &[u16], expected_retry: RetryClass) {
    let semantics = code.semantics();
    assert_eq!(semantics.http_statuses(), expected_http_statuses);
    assert_eq!(semantics.retry_class(), expected_retry);
}

#[test]
fn validation_auth_and_lookup_error_mappings_match_the_spec() {
    assert_mapping(ErrorCode::InvalidRequest, &[400], RetryClass::Never);
    assert_mapping(ErrorCode::Unauthenticated, &[401], RetryClass::Conditional);
    assert_mapping(ErrorCode::PermissionDenied, &[403], RetryClass::Never);
    assert_mapping(ErrorCode::SessionNotFound, &[404], RetryClass::Never);
    assert_mapping(ErrorCode::OperationNotFound, &[404], RetryClass::Never);
    assert_mapping(ErrorCode::PageNotFound, &[404], RetryClass::Never);
}

#[test]
fn stale_fencing_and_control_error_mappings_match_the_spec() {
    assert_mapping(ErrorCode::StaleNodeRef, &[409], RetryClass::ReadOnly);
    assert_mapping(ErrorCode::StaleDocumentRef, &[409], RetryClass::ReadOnly);
    assert_mapping(ErrorCode::SnapshotStale, &[409], RetryClass::ReadOnly);
    assert_mapping(ErrorCode::GenerationMismatch, &[412], RetryClass::Never);
    assert_mapping(
        ErrorCode::PlacementMismatch,
        &[409, 503],
        RetryClass::StatusLookupOnly,
    );
    assert_mapping(ErrorCode::IdempotencyConflict, &[409], RetryClass::Never);
    assert_mapping(ErrorCode::ApprovalStale, &[409], RetryClass::Never);
    assert_mapping(
        ErrorCode::SessionControlledByHuman,
        &[423],
        RetryClass::Safe,
    );
    assert_mapping(
        ErrorCode::ReconciliationRequired,
        &[409],
        RetryClass::MutationDisallowed,
    );
    assert_mapping(
        ErrorCode::ActionResolutionInvalid,
        &[409],
        RetryClass::Never,
    );
}

#[test]
fn timeout_quota_and_limit_error_mappings_match_the_spec() {
    assert_mapping(ErrorCode::ActionTimeout, &[504], RetryClass::Conditional);
    assert_mapping(ErrorCode::ActionAdmissionTimeout, &[503], RetryClass::Safe);
    assert_mapping(ErrorCode::TenantQuotaExceeded, &[429], RetryClass::Safe);
    assert_mapping(ErrorCode::RateLimited, &[429], RetryClass::Safe);
    assert_mapping(ErrorCode::NetworkPolicyDenied, &[403], RetryClass::Never);
    assert_mapping(
        ErrorCode::NetworkBudgetExceeded,
        &[429],
        RetryClass::PolicyDefined,
    );
    assert_mapping(ErrorCode::ArtifactTooLarge, &[413], RetryClass::Never);
    assert_mapping(ErrorCode::SnapshotTooLarge, &[413], RetryClass::Never);
    assert_mapping(
        ErrorCode::TargetLimitExceeded,
        &[429],
        RetryClass::Conditional,
    );
}

#[test]
fn capacity_runtime_and_internal_error_mappings_match_the_spec() {
    assert_mapping(ErrorCode::QueueTimeout, &[503], RetryClass::Safe);
    assert_mapping(ErrorCode::GlobalCapacityExceeded, &[503], RetryClass::Safe);
    assert_mapping(ErrorCode::BrowserStartFailed, &[503], RetryClass::Safe);
    assert_mapping(ErrorCode::ContextCreateFailed, &[503], RetryClass::Safe);
    assert_mapping(
        ErrorCode::TargetBootstrapFailed,
        &[503],
        RetryClass::Conditional,
    );
    assert_mapping(
        ErrorCode::BrowserCrashed,
        &[503],
        RetryClass::NotForLiveSession,
    );
    assert_mapping(ErrorCode::WorkerLost, &[503], RetryClass::NotForLiveSession);
    assert_mapping(
        ErrorCode::WorkerUnavailable,
        &[503],
        RetryClass::StatusLookupOnly,
    );
    assert_mapping(ErrorCode::SessionExpired, &[410], RetryClass::Never);
    assert_mapping(ErrorCode::AuditUnavailable, &[503], RetryClass::Safe);
    assert_mapping(ErrorCode::Internal, &[500], RetryClass::Conditional);
}

#[test]
fn outcome_unknown_is_a_non_retryable_terminal_action_response_not_an_error_envelope() {
    assert_mapping(ErrorCode::ActionOutcomeUnknown, &[200], RetryClass::Never);
    assert_eq!(
        ErrorCode::ActionOutcomeUnknown
            .semantics()
            .response_representation(),
        ResponseRepresentation::ActionTerminalStatus
    );

    for ordinary_error in [
        ErrorCode::InvalidRequest,
        ErrorCode::PermissionDenied,
        ErrorCode::ActionTimeout,
        ErrorCode::Internal,
    ] {
        assert_eq!(
            ordinary_error.semantics().response_representation(),
            ResponseRepresentation::ErrorEnvelope
        );
    }
}
