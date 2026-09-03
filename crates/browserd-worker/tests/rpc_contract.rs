use browserd_actions::{
    ActionKind, ActionSequence, ApprovalDecision as ActionApprovalDecision, KnownFailureReason,
    OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind, TerminalDetail,
};
use browserd_core::{
    ActionId, ApprovalId, ArtifactId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_worker::{
    WORKER_RPC_PROTOCOL_VERSION, WorkerActionApprovalRequirement, WorkerActionCommand,
    WorkerActionExecutionTimeout, WorkerActionReceipt, WorkerActionStatus,
    WorkerApprovalActionType, WorkerApprovalDecision, WorkerApprovalReceipt, WorkerApprovalState,
    WorkerArtifactReceipt, WorkerArtifactSource, WorkerArtifactState,
    WorkerCanonicalActionProposal, WorkerNavigateWaitUntil, WorkerPageReceipt, WorkerProbeReceipt,
    WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence,
};

fn fence() -> WorkerSessionFence {
    WorkerSessionFence {
        tenant_id: TenantId::new(),
        session_id: SessionId::new(),
        worker_epoch: 7,
        placement_version: 3,
        session_incarnation: 2,
    }
}

fn round_trip_request(request: WorkerRpcRequest) -> WorkerRpcRequest {
    let encoded = serde_json::to_vec(&request);
    assert!(encoded.is_ok());
    let Some(encoded) = encoded.ok() else {
        return request;
    };
    let decoded = serde_json::from_slice(&encoded);
    assert!(decoded.is_ok());
    decoded.unwrap_or(request)
}

#[test]
fn runtime_rpc_contract_carries_tenant_fences_and_complete_resource_snapshots() {
    assert_eq!(WORKER_RPC_PROTOCOL_VERSION, 18);
    let fence = fence();
    let page_id = PageId::new();
    let action_id = ActionId::new();
    let approval_id = ApprovalId::new();
    let principal_id = PrincipalId::new();
    let execution_timeout = WorkerActionExecutionTimeout::new(2_500);
    assert!(execution_timeout.is_some());
    let Some(execution_timeout) = execution_timeout else {
        return;
    };

    let requests = vec![
        WorkerRpcRequest::Probe {
            expected_worker_epoch: 7,
        },
        WorkerRpcRequest::ListPages {
            fence: fence.clone(),
        },
        WorkerRpcRequest::ActivatePage {
            fence: fence.clone(),
            page_id: page_id.clone(),
            now_unix_millis: 10,
        },
        WorkerRpcRequest::SubmitAction {
            fence: fence.clone(),
            action_id: action_id.clone(),
            action_sequence: ActionSequence::new(8),
            requester_principal_id: principal_id.clone(),
            idempotency_key: "action-1".to_owned(),
            canonical_request_hash: [4; 32],
            kind: ActionKind::Mutating,
            page_id: Some(page_id.clone()),
            action: WorkerActionCommand::Click {
                node_ref: "0000000000000001".to_owned(),
            },
            execution_timeout_ms: execution_timeout,
            approval: Some(Box::new(WorkerActionApprovalRequirement {
                target_incarnation: 4,
                frame_document_epoch: 9,
                current_origin: "https://example.test".to_owned(),
                url_revision: 12,
                action_type: WorkerApprovalActionType::Click,
                node_ref: Some("node-opaque".to_owned()),
                credential_refs: vec!["credential-1".to_owned()],
                require_four_eyes: true,
            })),
            now_unix_millis: 10,
        },
        WorkerRpcRequest::SubmitAction {
            fence: fence.clone(),
            action_id: action_id.clone(),
            action_sequence: ActionSequence::new(9),
            requester_principal_id: principal_id.clone(),
            idempotency_key: "action-2".to_owned(),
            canonical_request_hash: [5; 32],
            kind: ActionKind::Mutating,
            page_id: Some(page_id.clone()),
            action: WorkerActionCommand::Navigate {
                url: "https://example.test/path".to_owned(),
                wait_until: WorkerNavigateWaitUntil::Domcontentloaded,
            },
            execution_timeout_ms: execution_timeout,
            approval: None,
            now_unix_millis: 10,
        },
        WorkerRpcRequest::ResolveAction {
            fence: fence.clone(),
            action_id: action_id.clone(),
            resolution: ResolutionKind::ConfirmedNotExecuted,
            resolved_by: principal_id.clone(),
            basis: "operator verified no effect".to_owned(),
            now_unix_millis: 11,
        },
        WorkerRpcRequest::GetApproval {
            fence: fence.clone(),
            approval_id: approval_id.clone(),
        },
        WorkerRpcRequest::ListApprovals {
            fence: fence.clone(),
        },
        WorkerRpcRequest::DecideApproval {
            fence: fence.clone(),
            approval_id: approval_id.clone(),
            decision: WorkerApprovalDecision::Approve,
            principal_id: principal_id.clone(),
            reason: "change approved by operator".to_owned(),
            now_unix_millis: 12,
        },
    ];
    for request in requests {
        let decoded = round_trip_request(request.clone());
        assert_eq!(decoded, request);
    }

    let page = WorkerPageReceipt {
        fence: fence.clone(),
        page_id,
        active: true,
        target_incarnation: 4,
        document_epoch: 9,
        url_revision: 12,
    };
    let action = WorkerActionReceipt {
        fence: fence.clone(),
        action_id: action_id.clone(),
        action_sequence: ActionSequence::new(8),
        idempotency_key: "action-1".to_owned(),
        canonical_request_hash: [4; 32],
        kind: ActionKind::Mutating,
        status: WorkerActionStatus::OutcomeUnknown,
        dispatch_acknowledged: true,
        approval_decision: None,
        terminal_detail: Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::AmbiguousTransportLoss,
        )),
        result: None,
        resolution: Some(ResolutionAnnotation::new(
            ResolutionKind::ConfirmedNotExecuted,
            principal_id.clone(),
            11,
            "operator verified no effect",
        )),
    };
    let public_action = action.to_action_snapshot();
    assert!(public_action.is_ok());
    assert!(
        public_action
            .as_ref()
            .is_ok_and(|snapshot| snapshot.action_id() == &action_id
                && snapshot.action_sequence() == ActionSequence::new(8))
    );
    let mut corrupted_action = action.clone();
    corrupted_action.status = WorkerActionStatus::Succeeded;
    assert!(corrupted_action.to_action_snapshot().is_err());
    let artifact = WorkerArtifactReceipt {
        fence: fence.clone(),
        artifact_id: ArtifactId::new(),
        state: WorkerArtifactState::Available,
        size_bytes: 4,
        checksum_sha256: [8; 32],
        content_type: "application/octet-stream".to_owned(),
        source: WorkerArtifactSource::ClientUpload,
        origin: "browserd-worker-upload".to_owned(),
        object_generation: [9; 32],
    };
    let proposal = WorkerCanonicalActionProposal {
        tenant_id: fence.tenant_id.clone(),
        requester_principal_id: principal_id.clone(),
        session_id: fence.session_id.clone(),
        session_incarnation: fence.session_incarnation,
        page_id: page.page_id.clone(),
        target_incarnation: page.target_incarnation,
        frame_document_epoch: page.document_epoch,
        current_origin: "https://example.test".to_owned(),
        url_revision: page.url_revision,
        action_type: WorkerApprovalActionType::Click,
        canonical_arguments_hash: [2; 32],
        node_ref: Some("node-opaque".to_owned()),
        credential_refs_hash: [3; 32],
        expires_at_unix_millis: 20,
    };
    let canonical = proposal.to_canonical();
    assert!(canonical.is_ok());
    let proposal_hash = canonical
        .as_ref()
        .map(|canonical| *canonical.hash().as_bytes())
        .unwrap_or([0; 32]);
    let approval = WorkerApprovalReceipt {
        fence,
        approval_id,
        action_id,
        state: WorkerApprovalState::Approved { by: principal_id },
        proposal,
        proposal_hash,
    };
    assert!(approval.canonical_proposal().is_ok());
    let mut corrupted_approval = approval.clone();
    corrupted_approval.proposal_hash[0] ^= 0xff;
    assert!(corrupted_approval.canonical_proposal().is_err());
    let mut cross_tenant_approval = approval.clone();
    cross_tenant_approval.proposal.tenant_id = TenantId::new();
    assert!(cross_tenant_approval.canonical_proposal().is_err());
    let worker_id = WorkerId::new("worker-contract");
    assert!(worker_id.is_ok());
    let Some(worker_id) = worker_id.ok() else {
        return;
    };
    let responses = [
        WorkerRpcResponse::Probe(WorkerProbeReceipt {
            worker_id,
            worker_epoch: 7,
            ready: true,
        }),
        WorkerRpcResponse::Pages(vec![page.clone()]),
        WorkerRpcResponse::Page(page),
        WorkerRpcResponse::Action(action),
        WorkerRpcResponse::ArtifactStored(artifact.clone()),
        WorkerRpcResponse::Artifact(artifact),
        WorkerRpcResponse::Approvals(vec![approval.clone()]),
        WorkerRpcResponse::Approval(approval),
    ];
    for response in responses {
        let encoded = serde_json::to_vec(&response);
        assert!(encoded.is_ok());
        let decoded = encoded
            .ok()
            .and_then(|encoded| serde_json::from_slice::<WorkerRpcResponse>(&encoded).ok());
        assert_eq!(decoded, Some(response));
    }
}

#[test]
fn action_receipt_rejects_results_and_dispatch_acknowledgements_that_contradict_status() {
    let base = WorkerActionReceipt {
        fence: fence(),
        action_id: ActionId::new(),
        action_sequence: ActionSequence::new(1),
        idempotency_key: "action-contradictions".to_owned(),
        canonical_request_hash: [4; 32],
        kind: ActionKind::Mutating,
        status: WorkerActionStatus::Queued,
        dispatch_acknowledged: false,
        approval_decision: None,
        terminal_detail: None,
        result: None,
        resolution: None,
    };
    assert!(base.to_action_snapshot().is_ok());

    let mut valid_failed_after_dispatch = base.clone();
    valid_failed_after_dispatch.status = WorkerActionStatus::FailedKnown;
    valid_failed_after_dispatch.dispatch_acknowledged = true;
    valid_failed_after_dispatch.terminal_detail = Some(TerminalDetail::FailedKnown(
        KnownFailureReason::BrowserRejected,
    ));
    assert!(valid_failed_after_dispatch.to_action_snapshot().is_ok());

    let mut failed_with_result = valid_failed_after_dispatch.clone();
    failed_with_result.result = Some(b"impossible failure result".to_vec());
    assert!(failed_with_result.to_action_snapshot().is_err());

    let mut pending_after_dispatch = base.clone();
    pending_after_dispatch.status = WorkerActionStatus::PendingApproval;
    pending_after_dispatch.dispatch_acknowledged = true;
    assert!(pending_after_dispatch.to_action_snapshot().is_err());

    let mut queued_after_dispatch = base.clone();
    queued_after_dispatch.dispatch_acknowledged = true;
    assert!(queued_after_dispatch.to_action_snapshot().is_err());

    let mut cancelled_before_dispatch_after_ack = base.clone();
    cancelled_before_dispatch_after_ack.status = WorkerActionStatus::CancelledBeforeDispatch;
    cancelled_before_dispatch_after_ack.dispatch_acknowledged = true;
    cancelled_before_dispatch_after_ack.terminal_detail =
        Some(TerminalDetail::CancelledBeforeDispatch);
    assert!(
        cancelled_before_dispatch_after_ack
            .to_action_snapshot()
            .is_err()
    );

    let mut not_dispatched_after_ack = base.clone();
    not_dispatched_after_ack.status = WorkerActionStatus::FailedKnown;
    not_dispatched_after_ack.dispatch_acknowledged = true;
    not_dispatched_after_ack.terminal_detail = Some(TerminalDetail::FailedKnown(
        KnownFailureReason::NotDispatched,
    ));
    assert!(not_dispatched_after_ack.to_action_snapshot().is_err());

    let mut approval_denied_after_ack = base.clone();
    approval_denied_after_ack.status = WorkerActionStatus::FailedKnown;
    approval_denied_after_ack.dispatch_acknowledged = true;
    approval_denied_after_ack.approval_decision = Some(ActionApprovalDecision::Denied);
    approval_denied_after_ack.terminal_detail = Some(TerminalDetail::FailedKnown(
        KnownFailureReason::ApprovalDenied,
    ));
    assert!(approval_denied_after_ack.to_action_snapshot().is_err());

    let mut approval_timed_out_after_ack = base;
    approval_timed_out_after_ack.status = WorkerActionStatus::FailedKnown;
    approval_timed_out_after_ack.dispatch_acknowledged = true;
    approval_timed_out_after_ack.approval_decision = Some(ActionApprovalDecision::TimedOut);
    approval_timed_out_after_ack.terminal_detail = Some(TerminalDetail::FailedKnown(
        KnownFailureReason::ApprovalTimedOut,
    ));
    assert!(approval_timed_out_after_ack.to_action_snapshot().is_err());
}

#[test]
fn worker_request_rejects_missing_tenant_identity_and_unknown_fields() {
    let encoded = serde_json::json!({
        "method": "get_session",
        "params": {
            "fence": {
                "session_id": SessionId::new(),
                "worker_epoch": 7,
                "placement_version": 3,
                "session_incarnation": 2
            }
        }
    });
    assert!(serde_json::from_value::<WorkerRpcRequest>(encoded).is_err());

    let fence = fence();
    let encoded = serde_json::json!({
        "method": "get_session",
        "params": {
            "fence": fence,
            "unexpected": true
        }
    });
    assert!(serde_json::from_value::<WorkerRpcRequest>(encoded).is_err());
}

#[test]
fn navigate_command_requires_a_typed_wait_until_lifecycle() {
    let command = WorkerActionCommand::Navigate {
        url: "https://example.test/path".to_owned(),
        wait_until: WorkerNavigateWaitUntil::Load,
    };
    let encoded = serde_json::to_value(&command);
    assert_eq!(
        encoded.ok(),
        Some(serde_json::json!({
            "type": "navigate",
            "url": "https://example.test/path",
            "wait_until": "load",
        }))
    );
    assert!(command.is_valid());
    assert_eq!(command.kind(), ActionKind::Mutating);

    let decoded = serde_json::from_value::<WorkerActionCommand>(serde_json::json!({
        "type": "navigate",
        "url": "https://example.test/path",
        "wait_until": "domcontentloaded",
    }));
    assert_eq!(
        decoded.ok(),
        Some(WorkerActionCommand::Navigate {
            url: "https://example.test/path".to_owned(),
            wait_until: WorkerNavigateWaitUntil::Domcontentloaded,
        })
    );

    for untyped in [
        serde_json::json!({"type": "navigate", "url": "https://example.test/path"}),
        serde_json::json!({
            "type": "navigate",
            "url": "https://example.test/path",
            "wait_until": "networkidle",
        }),
        serde_json::json!({
            "type": "navigate",
            "url": "https://example.test/path",
            "wait_until": "load",
            "referrer": "https://example.test",
        }),
    ] {
        assert!(
            serde_json::from_value::<WorkerActionCommand>(untyped).is_err(),
            "navigate commands must carry exactly one typed lifecycle"
        );
    }

    let unsafe_scheme = WorkerActionCommand::Navigate {
        url: "file:///etc/passwd".to_owned(),
        wait_until: WorkerNavigateWaitUntil::Load,
    };
    assert!(!unsafe_scheme.is_valid());
}

#[test]
fn history_traversal_commands_are_typed_mutations() {
    for (command, tag) in [
        (WorkerActionCommand::GoBack, "go_back"),
        (WorkerActionCommand::GoForward, "go_forward"),
    ] {
        assert_eq!(
            serde_json::to_value(&command).ok(),
            Some(serde_json::json!({ "type": tag })),
        );
        assert_eq!(
            serde_json::from_value::<WorkerActionCommand>(serde_json::json!({ "type": tag })).ok(),
            Some(command.clone()),
        );
        assert!(command.is_valid());
        assert_eq!(command.kind(), ActionKind::Mutating);
    }
}

#[test]
fn raw_input_commands_are_bounded_typed_mutations() {
    let press = WorkerActionCommand::PressKey {
        key: "Enter".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&press).ok(),
        Some(serde_json::json!({"type": "press_key", "key": "Enter"})),
    );
    assert!(press.is_valid());
    assert_eq!(press.kind(), ActionKind::Mutating);

    let scroll = WorkerActionCommand::Scroll {
        delta_x: 0,
        delta_y: 240,
    };
    assert_eq!(
        serde_json::to_value(&scroll).ok(),
        Some(serde_json::json!({"type": "scroll", "delta_x": 0, "delta_y": 240})),
    );
    assert!(scroll.is_valid());
    assert_eq!(scroll.kind(), ActionKind::Mutating);

    assert!(
        !WorkerActionCommand::PressKey { key: String::new() }.is_valid(),
        "an empty key is out of bounds"
    );
    assert!(
        !WorkerActionCommand::PressKey {
            key: "a\nb".to_owned()
        }
        .is_valid(),
        "a control character in a key is out of bounds"
    );
    assert!(
        !WorkerActionCommand::Scroll {
            delta_x: 5_000_000,
            delta_y: 0
        }
        .is_valid(),
        "an oversized scroll delta is out of bounds"
    );
}

#[test]
fn query_all_is_a_bounded_read_only_selector() {
    let query = WorkerActionCommand::QueryAll {
        selector: "a.link".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&query).ok(),
        Some(serde_json::json!({"type": "query_all", "selector": "a.link"})),
    );
    assert!(query.is_valid());
    assert_eq!(query.kind(), ActionKind::ReadOnly);

    assert!(
        !WorkerActionCommand::QueryAll {
            selector: String::new()
        }
        .is_valid(),
        "an empty selector is out of bounds"
    );
    assert!(
        !WorkerActionCommand::QueryAll {
            selector: "a\nb".to_owned()
        }
        .is_valid(),
        "a control character in a selector is out of bounds"
    );
}

#[test]
fn get_text_is_a_bounded_read_only_node_reference() {
    let get_text = WorkerActionCommand::GetText {
        node_ref: "0000000000000001".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&get_text).ok(),
        Some(serde_json::json!({"type": "get_text", "node_ref": "0000000000000001"})),
    );
    assert!(get_text.is_valid());
    assert_eq!(get_text.kind(), ActionKind::ReadOnly);

    assert!(
        !WorkerActionCommand::GetText {
            node_ref: String::new()
        }
        .is_valid(),
        "an empty node reference is out of bounds"
    );
}

#[test]
fn node_reads_are_bounded_read_only_commands() {
    let whole_document = WorkerActionCommand::GetHtml { node_ref: None };
    assert_eq!(
        serde_json::to_value(&whole_document).ok(),
        Some(serde_json::json!({"type": "get_html", "node_ref": null})),
    );
    assert!(
        whole_document.is_valid(),
        "a whole-document get_html is valid"
    );
    assert_eq!(whole_document.kind(), ActionKind::ReadOnly);

    let attribute = WorkerActionCommand::GetAttribute {
        node_ref: "0000000000000001".to_owned(),
        name: "href".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&attribute).ok(),
        Some(serde_json::json!({
            "type": "get_attribute",
            "node_ref": "0000000000000001",
            "name": "href",
        })),
    );
    assert!(attribute.is_valid());
    assert_eq!(attribute.kind(), ActionKind::ReadOnly);

    assert!(
        !WorkerActionCommand::GetAttribute {
            node_ref: "0000000000000001".to_owned(),
            name: String::new(),
        }
        .is_valid(),
        "an empty attribute name is out of bounds"
    );
    assert!(
        !WorkerActionCommand::GetHtml {
            node_ref: Some(String::new()),
        }
        .is_valid(),
        "a present but empty node reference is out of bounds"
    );
}

#[test]
fn node_ref_mutations_are_typed_mutations() {
    for (command, tag) in [
        (
            WorkerActionCommand::Click {
                node_ref: "0000000000000001".to_owned(),
            },
            "click",
        ),
        (
            WorkerActionCommand::DoubleClick {
                node_ref: "0000000000000001".to_owned(),
            },
            "double_click",
        ),
        (
            WorkerActionCommand::Hover {
                node_ref: "0000000000000001".to_owned(),
            },
            "hover",
        ),
        (
            WorkerActionCommand::Focus {
                node_ref: "0000000000000001".to_owned(),
            },
            "focus",
        ),
        (
            WorkerActionCommand::Blur {
                node_ref: "0000000000000001".to_owned(),
            },
            "blur",
        ),
        (
            WorkerActionCommand::Check {
                node_ref: "0000000000000001".to_owned(),
            },
            "check",
        ),
        (
            WorkerActionCommand::Uncheck {
                node_ref: "0000000000000001".to_owned(),
            },
            "uncheck",
        ),
    ] {
        assert_eq!(
            serde_json::to_value(&command).ok(),
            Some(serde_json::json!({"type": tag, "node_ref": "0000000000000001"})),
        );
        assert!(command.is_valid());
        assert_eq!(command.kind(), ActionKind::Mutating);
    }
}

#[test]
fn form_value_mutations_are_typed_and_bounded() {
    let fill = WorkerActionCommand::Fill {
        node_ref: "0000000000000001".to_owned(),
        value: "hello".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&fill).ok(),
        Some(serde_json::json!({
            "type": "fill",
            "node_ref": "0000000000000001",
            "value": "hello",
        })),
    );
    assert!(fill.is_valid());
    assert!(
        WorkerActionCommand::Fill {
            node_ref: "0000000000000001".to_owned(),
            value: String::new(),
        }
        .is_valid(),
        "clearing a field with an empty value is valid"
    );
    assert_eq!(fill.kind(), ActionKind::Mutating);

    let select = WorkerActionCommand::SelectOption {
        node_ref: "0000000000000001".to_owned(),
        values: vec!["a".to_owned(), "b".to_owned()],
    };
    assert_eq!(
        serde_json::to_value(&select).ok(),
        Some(serde_json::json!({
            "type": "select_option",
            "node_ref": "0000000000000001",
            "values": ["a", "b"],
        })),
    );
    assert!(select.is_valid());
    assert_eq!(select.kind(), ActionKind::Mutating);
}

#[test]
fn node_ref_reads_are_read_only_and_bounded() {
    for (command, tag) in [
        (
            WorkerActionCommand::GetProperties {
                node_ref: "0000000000000001".to_owned(),
            },
            "get_properties",
        ),
        (
            WorkerActionCommand::GetComputedStyle {
                node_ref: "0000000000000001".to_owned(),
            },
            "get_computed_style",
        ),
        (
            WorkerActionCommand::ExtractTable {
                node_ref: "0000000000000001".to_owned(),
            },
            "extract_table",
        ),
    ] {
        assert_eq!(
            serde_json::to_value(&command).ok(),
            Some(serde_json::json!({"type": tag, "node_ref": "0000000000000001"})),
        );
        assert!(command.is_valid());
        assert_eq!(command.kind(), ActionKind::ReadOnly);
    }
}
