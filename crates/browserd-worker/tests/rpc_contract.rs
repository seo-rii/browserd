use browserd_actions::{ActionKind, ActionSequence, ResolutionAnnotation, ResolutionKind};
use browserd_core::{
    ActionId, ArtifactId, LeaseId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_worker::{
    WorkerActionApprovalRequirement, WorkerActionReceipt, WorkerActionStatus,
    WorkerApprovalActionType, WorkerApprovalDecision, WorkerApprovalReceipt, WorkerApprovalState,
    WorkerArtifactReceipt, WorkerArtifactSource, WorkerArtifactState, WorkerPageReceipt,
    WorkerProbeReceipt, WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence,
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
    let fence = fence();
    let page_id = PageId::new();
    let action_id = ActionId::new();
    let approval_id = LeaseId::new();
    let principal_id = PrincipalId::new();

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
            requester_principal_id: principal_id.clone(),
            idempotency_key: "action-1".to_owned(),
            canonical_request_hash: [4; 32],
            kind: ActionKind::Mutating,
            page_id: Some(page_id.clone()),
            payload: br#"{"type":"click"}"#.to_vec(),
            approval: Some(WorkerActionApprovalRequirement {
                target_incarnation: 4,
                frame_document_epoch: 9,
                current_origin: "https://example.test".to_owned(),
                url_revision: 12,
                action_type: WorkerApprovalActionType::Click,
                node_ref: Some("node-opaque".to_owned()),
                credential_refs: vec!["credential-1".to_owned()],
                require_four_eyes: true,
            }),
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
        kind: ActionKind::Mutating,
        status: WorkerActionStatus::OutcomeUnknown,
        result: None,
        resolution: Some(ResolutionAnnotation::new(
            ResolutionKind::ConfirmedNotExecuted,
            principal_id.clone(),
            11,
            "operator verified no effect",
        )),
    };
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
    let approval = WorkerApprovalReceipt {
        fence,
        approval_id,
        action_id,
        state: WorkerApprovalState::Approved { by: principal_id },
        proposal_hash: [6; 32],
    };
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
