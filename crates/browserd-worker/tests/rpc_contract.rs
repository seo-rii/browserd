use browserd_actions::{
    ActionKind, ActionSequence, ApprovalDecision as ActionApprovalDecision, CanonicalRequestHash,
    JournalSessionScope, KnownFailureReason, OutcomeUnknownReason, ResolutionAnnotation,
    ResolutionKind, TerminalCustodyReceipt, TerminalCustodyRequirement, TerminalDetail,
};
use browserd_core::{
    ActionId, ApprovalId, ArtifactId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_features::BuiltinFeature;
use browserd_worker::{
    WORKER_RPC_PROTOCOL_VERSION, WorkerActionApprovalRequirement, WorkerActionCommand,
    WorkerActionExecutionTimeout, WorkerActionReceipt, WorkerActionStatus,
    WorkerApprovalActionType, WorkerApprovalDecision, WorkerApprovalReceipt, WorkerApprovalState,
    WorkerArtifactReceipt, WorkerArtifactSource, WorkerArtifactState,
    WorkerCanonicalActionProposal, WorkerNavigateWaitUntil, WorkerPageReceipt, WorkerProbeReceipt,
    WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence, WorkerTerminalCustodyReceipt,
    WorkerWaitCondition,
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

#[test]
fn historical_custody_wire_preserves_original_scope_and_rejects_capability_contradictions()
-> Result<(), Box<dyn std::error::Error>> {
    let fence = fence();
    let worker_id = WorkerId::new("historical-custody-wire")?;
    let action_id = ActionId::new();
    let sequence = ActionSequence::new(u64::MAX);
    let scope = JournalSessionScope::new(
        fence.tenant_id.clone(),
        fence.session_id.clone(),
        worker_id.clone(),
        browserd_core::PlacementFence::new(
            fence.worker_epoch,
            fence.placement_version,
            fence.session_incarnation,
        ),
    )?;
    let custody = TerminalCustodyReceipt::new(
        scope.clone(),
        action_id.clone(),
        sequence,
        ActionKind::Mutating,
        CanonicalRequestHash::new([31; 32]),
        None,
        TerminalDetail::CancelledBeforeDispatch,
        None,
    )?;
    let proof = WorkerTerminalCustodyReceipt {
        worker_id: worker_id.clone(),
        worker_epoch: 8,
        receipt: Box::new(custody.clone()),
    };
    proof.validate_for(
        &worker_id,
        8,
        &scope,
        &action_id,
        sequence,
        ActionKind::Mutating,
    )?;
    assert_eq!(
        serde_json::from_slice::<WorkerTerminalCustodyReceipt>(&serde_json::to_vec(&proof)?)?,
        proof
    );
    for (epoch, action, seq, kind) in [
        (7, action_id.clone(), sequence, ActionKind::Mutating),
        (8, ActionId::new(), sequence, ActionKind::Mutating),
        (
            8,
            action_id.clone(),
            ActionSequence::new(u64::MAX - 1),
            ActionKind::Mutating,
        ),
        (8, action_id.clone(), sequence, ActionKind::ReadOnly),
    ] {
        assert!(
            proof
                .validate_for(&worker_id, epoch, &scope, &action, seq, kind)
                .is_err()
        );
    }
    let wrong_scope = JournalSessionScope::new(
        TenantId::new(),
        scope.session_id().clone(),
        worker_id.clone(),
        scope.fence(),
    )?;
    assert!(
        proof
            .validate_for(
                &worker_id,
                8,
                &wrong_scope,
                &action_id,
                sequence,
                ActionKind::Mutating
            )
            .is_err()
    );
    let request = WorkerRpcRequest::GetTerminalCustody {
        expected_serving_worker_id: worker_id,
        expected_serving_worker_epoch: 8,
        scope,
        action_id: action_id.clone(),
        action_sequence: sequence,
        kind: ActionKind::Mutating,
    };
    assert_eq!(
        serde_json::from_slice::<WorkerRpcRequest>(&serde_json::to_vec(&request)?)?,
        request
    );
    let mut receipt = WorkerActionReceipt {
        fence,
        action_id,
        action_sequence: sequence,
        idempotency_key: "custody-wire".to_owned(),
        canonical_request_hash: [11; 32],
        kind: ActionKind::Mutating,
        status: WorkerActionStatus::CancelledBeforeDispatch,
        dispatch_acknowledged: false,
        approval_decision: None,
        terminal_detail: Some(TerminalDetail::CancelledBeforeDispatch),
        result: None,
        resolution: None,
        custody: Some(Box::new(custody)),
        custody_requirement: Some(TerminalCustodyRequirement::Required),
    };
    receipt.to_action_snapshot()?;
    receipt.custody_requirement = Some(TerminalCustodyRequirement::Unsupported);
    assert!(receipt.to_action_snapshot().is_err());
    receipt.custody = None;
    receipt.to_action_snapshot()?;
    receipt.custody_requirement = None;
    receipt.to_action_snapshot()?; // Legacy absence is accepted on the wire; the store pins it.
    receipt.status = WorkerActionStatus::Running;
    receipt.terminal_detail = None;
    receipt.custody_requirement = Some(TerminalCustodyRequirement::Required);
    assert!(receipt.to_action_snapshot().is_err());
    Ok(())
}

#[test]
fn query_all_rpc_frame_path_is_optional_bounded_and_read_only()
-> Result<(), Box<dyn std::error::Error>> {
    let legacy = serde_json::json!({"type":"query_all","selector":"input"});
    let omitted: WorkerActionCommand = serde_json::from_value(legacy.clone())?;
    let empty: WorkerActionCommand = serde_json::from_value(serde_json::json!({
        "type":"query_all","selector":"input","frame_path":[],
    }))?;
    assert_eq!(omitted, empty);
    assert_eq!(serde_json::to_value(&empty)?, legacy);
    for frame_path in [
        vec![],
        vec!["iframe".to_owned(); 8],
        vec!["a".repeat(8192); 4],
        vec!["é".repeat(4096); 4],
        vec!["iframe#outer".to_owned(), "iframe#inner".to_owned()],
    ] {
        let command = WorkerActionCommand::QueryAll {
            selector: "input".to_owned(),
            frame_path: frame_path.clone(),
        };
        assert!(command.is_valid());
        assert_eq!(command.kind(), ActionKind::ReadOnly);
        assert_eq!(command.required_feature(), None);
        assert_eq!(
            serde_json::from_value::<WorkerActionCommand>(serde_json::to_value(&command)?)?,
            command
        );
        if !frame_path.is_empty() {
            assert_eq!(
                serde_json::to_value(&command)?["frame_path"],
                serde_json::json!(frame_path)
            );
        }
    }
    for frame_path in [
        vec![String::new()],
        vec!["iframe\n".to_owned()],
        vec!["a".repeat(8193)],
        vec!["é".repeat(4097)],
        vec!["iframe".to_owned(); 9],
        vec!["a".repeat(8192); 5],
        vec![
            "a".repeat(8192),
            "b".repeat(8192),
            "c".repeat(8192),
            "d".repeat(8192),
            "e".to_owned(),
        ],
    ] {
        assert!(
            !WorkerActionCommand::QueryAll {
                selector: "input".to_owned(),
                frame_path
            }
            .is_valid()
        );
    }
    for path in [
        serde_json::Value::Null,
        serde_json::json!("iframe"),
        serde_json::json!([1]),
    ] {
        assert!(
            serde_json::from_value::<WorkerActionCommand>(serde_json::json!({
                "type":"query_all","selector":"input","frame_path":path,
            }))
            .is_err()
        );
    }
    for forbidden in ["frame_ref", "frame_id", "cdp_session_id"] {
        let mut invalid = legacy.clone();
        invalid[forbidden] = serde_json::json!("caller-route");
        assert!(serde_json::from_value::<WorkerActionCommand>(invalid).is_err());
    }
    Ok(())
}

#[test]
fn checkpoint_rpc_defaults_to_cookies_and_admits_only_exact_bounded_origins()
-> Result<(), Box<dyn std::error::Error>> {
    let legacy: WorkerActionCommand =
        serde_json::from_value(serde_json::json!({"type":"checkpoint"}))?;
    assert_eq!(legacy, WorkerActionCommand::Checkpoint { origins: vec![] });
    for origins in [
        vec![],
        vec![
            "https://example.test".to_owned(),
            "http://example.test:8080".to_owned(),
        ],
        (0..16)
            .map(|i| format!("https://origin-{i}.test"))
            .collect(),
    ] {
        let command = WorkerActionCommand::Checkpoint {
            origins: origins.clone(),
        };
        assert!(command.is_valid());
        assert_eq!(command.kind(), ActionKind::ReadOnly);
        assert_eq!(command.required_feature(), Some(BuiltinFeature::Checkpoint));
        assert!(command.capture_command().is_none());
        let encoded = serde_json::to_value(&command)?;
        assert_eq!(
            encoded,
            serde_json::json!({"type":"checkpoint","origins":origins})
        );
        assert_eq!(
            serde_json::from_value::<WorkerActionCommand>(encoded)?,
            command
        );
    }
    for origins in [
        vec![String::new()],
        vec!["https://example.test/".to_owned()],
        vec!["https://example.test/path".to_owned()],
        vec!["https://example.test?".to_owned()],
        vec!["https://example.test#".to_owned()],
        vec!["https://user:pass@example.test".to_owned()],
        vec!["https://EXAMPLE.test".to_owned()],
        vec!["https://example.test:443".to_owned()],
        vec!["file:///tmp/private".to_owned()],
        vec!["null".to_owned()],
        vec![" https://example.test".to_owned()],
        vec!["https://example.test\n".to_owned()],
        vec![format!("https://{}", "a".repeat(2041))],
        vec!["https://example.test".to_owned(); 2],
        (0..17)
            .map(|i| format!("https://origin-{i}.test"))
            .collect(),
    ] {
        assert!(!WorkerActionCommand::Checkpoint { origins }.is_valid());
    }
    for value in [
        serde_json::json!({"type":"checkpoint","origins":null}),
        serde_json::json!({"type":"checkpoint","cookies":[]}),
        serde_json::json!({"type":"checkpoint","local_storage":{}}),
    ] {
        assert!(serde_json::from_value::<WorkerActionCommand>(value).is_err());
    }
    Ok(())
}

#[test]
fn checkpoint_restore_receipt_is_strict_and_legacy_create_receipts_default_to_none()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = serde_json::json!({
        "operation_id":browserd_core::OperationId::new(),"tenant_id":TenantId::new(),
        "session_id":SessionId::new(),"session_incarnation":1,"effective_isolation":"shared_context",
        "primary_page_id":PageId::new(),"worker_epoch":7,"placement_version":3,"existing":false,
    });
    let legacy: browserd_worker::WorkerCreateSessionReceipt =
        serde_json::from_value(value.clone())?;
    assert!(legacy.restored_checkpoint.is_none());
    let source = SessionId::new();
    value["restored_checkpoint"] =
        serde_json::json!({"checkpoint_ref":"opaque-checkpoint","source_session_id":source});
    let restored: browserd_worker::WorkerCreateSessionReceipt =
        serde_json::from_value(value.clone())?;
    assert_eq!(
        restored.restored_checkpoint,
        Some(browserd_worker::WorkerCheckpointRestoreReceipt {
            checkpoint_ref: "opaque-checkpoint".to_owned(),
            source_session_id: source,
        })
    );
    value["restored_checkpoint"]["cookies"] = serde_json::json!([]);
    assert!(serde_json::from_value::<browserd_worker::WorkerCreateSessionReceipt>(value).is_err());
    Ok(())
}

#[test]
fn fill_secret_rpc_carries_only_a_bounded_reference() -> Result<(), Box<dyn std::error::Error>> {
    for secret_ref in ["credential.login".to_owned(), "s".repeat(1024)] {
        let command = WorkerActionCommand::FillSecret {
            node_ref: "0000000000000001".to_owned(),
            secret_ref: secret_ref.clone(),
        };
        assert!(command.is_valid());
        assert_eq!(command.kind(), ActionKind::Mutating);
        assert_eq!(command.required_feature(), None);
        let value = serde_json::to_value(&command)?;
        assert_eq!(
            value,
            serde_json::json!({"type":"fill_secret","node_ref":"0000000000000001","secret_ref":secret_ref})
        );
        assert_eq!(
            serde_json::from_value::<WorkerActionCommand>(value).ok(),
            Some(command)
        );
    }
    for secret_ref in [
        "".to_owned(),
        " secret".to_owned(),
        "secret ".to_owned(),
        "\u{a0}secret".to_owned(),
        "sec\nret".to_owned(),
        "sec\u{7f}ret".to_owned(),
        "s".repeat(1025),
        "한".repeat(342),
    ] {
        assert!(
            !WorkerActionCommand::FillSecret {
                node_ref: "0000000000000001".to_owned(),
                secret_ref
            }
            .is_valid()
        );
    }
    for node_ref in [
        "".to_owned(),
        " node".to_owned(),
        "node ".to_owned(),
        "no\nde".to_owned(),
        "n".repeat(1025),
    ] {
        assert!(
            !WorkerActionCommand::FillSecret {
                node_ref,
                secret_ref: "credential.login".to_owned()
            }
            .is_valid()
        );
    }
    for field in [
        "value",
        "secret_value",
        "resolved_value",
        "password",
        "unexpected",
    ] {
        let mut value = serde_json::json!({"type":"fill_secret","node_ref":"0000000000000001","secret_ref":"credential.login"});
        value[field] = serde_json::json!("synthetic-plaintext-not-a-secret");
        assert!(serde_json::from_value::<WorkerActionCommand>(value).is_err());
    }
    assert!(serde_json::from_value::<WorkerActionCommand>(serde_json::json!({"type":"fill_secret","node_ref":"node","value":"synthetic-plaintext-not-a-secret"})).is_err());
    Ok(())
}

#[test]
fn set_files_is_a_bounded_typed_mutation_without_local_paths()
-> Result<(), Box<dyn std::error::Error>> {
    for count in [1, 128] {
        let command = WorkerActionCommand::SetFiles {
            node_ref: "0000000000000001".to_owned(),
            artifact_ids: (0..count).map(|_| ArtifactId::new()).collect(),
        };
        assert!(command.is_valid());
        assert_eq!(command.kind(), ActionKind::Mutating);
        assert_eq!(command.required_feature(), None);
        let encoded = serde_json::to_value(&command)?;
        assert_eq!(
            serde_json::from_value::<WorkerActionCommand>(encoded).ok(),
            Some(command)
        );
    }
    let id = ArtifactId::new();
    for (node_ref, artifact_ids) in [
        ("0000000000000001", Vec::new()),
        ("0000000000000001", vec![id.clone(), id]),
        (
            "0000000000000001",
            (0..129).map(|_| ArtifactId::new()).collect(),
        ),
        ("node\ninvalid", vec![ArtifactId::new()]),
        ("", vec![ArtifactId::new()]),
    ] {
        assert!(
            !WorkerActionCommand::SetFiles {
                node_ref: node_ref.to_owned(),
                artifact_ids
            }
            .is_valid()
        );
    }
    for field in ["paths", "files", "local_path", "unexpected"] {
        let mut encoded = serde_json::json!({"type":"set_files", "node_ref":"0000000000000001", "artifact_ids":[ArtifactId::new()]});
        encoded[field] = serde_json::json!(["/tmp/file"]);
        assert!(serde_json::from_value::<WorkerActionCommand>(encoded).is_err());
    }
    assert!(serde_json::from_value::<WorkerActionCommand>(serde_json::json!({"type":"set_files", "node_ref":"0000000000000001", "artifact_ids":["/tmp/file"]})).is_err());
    Ok(())
}

#[test]
fn named_upload_rpc_preserves_filename_and_keeps_legacy_store_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let named = WorkerRpcRequest::UploadNamedArtifact {
        fence: fence(),
        bytes: b"hello".to_vec(),
        content_type: "text/plain".to_owned(),
        display_filename: "첨부 문서.txt".to_owned(),
        now_unix_millis: 10,
    };
    assert_eq!(round_trip_request(named.clone()), named);
    let mut wire = serde_json::to_value(named)?;
    wire["params"]["local_path"] = serde_json::json!("/tmp/file");
    assert!(serde_json::from_value::<WorkerRpcRequest>(wire.clone()).is_err());
    wire["params"]
        .as_object_mut()
        .ok_or("params")?
        .remove("local_path");
    wire["params"]
        .as_object_mut()
        .ok_or("params")?
        .remove("display_filename");
    assert!(serde_json::from_value::<WorkerRpcRequest>(wire).is_err());
    let legacy = WorkerRpcRequest::StoreArtifact {
        fence: fence(),
        bytes: vec![1],
        content_type: "application/octet-stream".to_owned(),
        now_unix_millis: 10,
    };
    assert_eq!(round_trip_request(legacy.clone()), legacy);
    Ok(())
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
    assert_eq!(WORKER_RPC_PROTOCOL_VERSION, 33);
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
        custody: None,
        custody_requirement: None,
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
        display_filename: None,
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
        typed_binding: None,
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
        custody: None,
        custody_requirement: None,
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
        frame_path: Vec::new(),
    };
    assert_eq!(
        serde_json::to_value(&query).ok(),
        Some(serde_json::json!({"type": "query_all", "selector": "a.link"})),
    );
    assert!(query.is_valid());
    assert_eq!(query.kind(), ActionKind::ReadOnly);

    assert!(
        !WorkerActionCommand::QueryAll {
            selector: String::new(),
            frame_path: Vec::new(),
        }
        .is_valid(),
        "an empty selector is out of bounds"
    );
    assert!(
        !WorkerActionCommand::QueryAll {
            selector: "a\nb".to_owned(),
            frame_path: Vec::new(),
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
fn wait_for_carries_a_typed_bounded_condition() {
    let attached = WorkerActionCommand::WaitFor {
        condition: WorkerWaitCondition::SelectorAttached {
            selector: "#ready".to_owned(),
        },
    };
    assert_eq!(
        serde_json::to_value(&attached).ok(),
        Some(serde_json::json!({
            "type": "wait_for",
            "condition": {"type": "selector_attached", "selector": "#ready"},
        })),
    );
    assert!(attached.is_valid());
    assert_eq!(attached.kind(), ActionKind::Mutating);

    assert!(
        WorkerActionCommand::WaitFor {
            condition: WorkerWaitCondition::NetworkQuiet { quiet_ms: 500 },
        }
        .is_valid()
    );
    assert!(
        !WorkerActionCommand::WaitFor {
            condition: WorkerWaitCondition::SelectorVisible {
                selector: String::new(),
            },
        }
        .is_valid(),
        "an empty selector condition is out of bounds"
    );
}

#[test]
fn handle_dialog_is_a_typed_mutation() {
    let accept = WorkerActionCommand::HandleDialog {
        accept: true,
        prompt_text: Some("name".to_owned()),
    };
    assert_eq!(
        serde_json::to_value(&accept).ok(),
        Some(serde_json::json!({
            "type": "handle_dialog",
            "accept": true,
            "prompt_text": "name",
        })),
    );
    assert!(accept.is_valid());
    assert_eq!(accept.kind(), ActionKind::Mutating);

    let dismiss = WorkerActionCommand::HandleDialog {
        accept: false,
        prompt_text: None,
    };
    assert_eq!(
        serde_json::to_value(&dismiss).ok(),
        Some(serde_json::json!({
            "type": "handle_dialog",
            "accept": false,
            "prompt_text": null,
        })),
    );
    assert!(dismiss.is_valid());
}

#[test]
fn snapshot_is_a_read_only_observation() {
    let snapshot = WorkerActionCommand::Snapshot;
    assert_eq!(
        serde_json::to_value(&snapshot).ok(),
        Some(serde_json::json!({ "type": "snapshot" })),
    );
    assert!(snapshot.is_valid());
    assert_eq!(snapshot.kind(), ActionKind::ReadOnly);
}

#[test]
fn evaluate_is_a_bounded_mutation() {
    let evaluate = WorkerActionCommand::Evaluate {
        expression: "document.title".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&evaluate).ok(),
        Some(serde_json::json!({"type": "evaluate", "expression": "document.title"})),
    );
    assert!(evaluate.is_valid());
    assert_eq!(evaluate.kind(), ActionKind::Mutating);
    assert!(
        !WorkerActionCommand::Evaluate {
            expression: String::new(),
        }
        .is_valid(),
        "an empty expression is out of bounds"
    );
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

#[test]
fn evaluate_requires_the_privileged_feature_and_other_commands_do_not() {
    // The RPC layer maps `evaluate` to the privileged feature so the worker can gate it on the
    // session profile before dispatch (BRD-004 / SPEC D-18).
    assert_eq!(
        WorkerActionCommand::Evaluate {
            expression: "1 + 1".to_owned(),
        }
        .required_feature(),
        Some(BuiltinFeature::PrivilegedEvaluate),
    );
    for command in [
        WorkerActionCommand::GetTitle,
        WorkerActionCommand::Reload,
        WorkerActionCommand::Click {
            node_ref: "0000000000000001".to_owned(),
        },
    ] {
        assert_eq!(command.required_feature(), None);
    }
}

#[test]
fn isolation_requests_are_satisfied_only_by_equal_or_stronger_placement() {
    use browserd_worker::WorkerIsolationProfile::{
        DedicatedProcess, DedicatedWorker, SharedContext, TenantDedicatedShard,
    };
    // A placement equal to or stronger than the request satisfies it (a safe strengthening).
    assert!(SharedContext.satisfied_by(SharedContext));
    assert!(SharedContext.satisfied_by(DedicatedProcess));
    assert!(TenantDedicatedShard.satisfied_by(DedicatedWorker));
    assert!(DedicatedProcess.satisfied_by(DedicatedProcess));
    // A request for isolation stronger than the placement cannot be honored.
    assert!(!DedicatedProcess.satisfied_by(SharedContext));
    assert!(!DedicatedWorker.satisfied_by(DedicatedProcess));
    assert!(!TenantDedicatedShard.satisfied_by(SharedContext));
}

#[test]
fn session_option_support_flags_the_first_unsupported_option() {
    use browserd_worker::{SessionOptionSupport, WorkerSessionOptionsV1, WorkerViewport};
    let support = SessionOptionSupport::single_host_default();
    let supported = WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1_280,
            height: 720,
            device_scale_factor: 1,
        },
        locale: "en-US".to_owned(),
        timezone: "UTC".to_owned(),
        user_agent: None,
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 60,
        idle_timeout_seconds: 30,
        metadata: std::collections::BTreeMap::new(),
    };
    assert_eq!(support.unsupported_option(&supported), None);

    let privileged = WorkerSessionOptionsV1 {
        feature_profile: "privileged".to_owned(),
        ..supported.clone()
    };
    assert_eq!(
        support.unsupported_option(&privileged),
        Some("feature_profile")
    );

    let private_network = WorkerSessionOptionsV1 {
        network_class: "private".to_owned(),
        ..supported.clone()
    };
    assert_eq!(
        support.unsupported_option(&private_network),
        Some("network_class")
    );

    let with_checkpoint = WorkerSessionOptionsV1 {
        checkpoint_ref: Some("chk-1".to_owned()),
        ..supported
    };
    assert_eq!(
        support.unsupported_option(&with_checkpoint),
        Some("checkpoint_ref")
    );
}

#[test]
fn capture_commands_require_their_registered_feature() -> Result<(), serde_json::Error> {
    use browserd_features::BuiltinFeature;
    use browserd_worker::WorkerActionCommand;
    for (kind, feature) in [
        ("screenshot", BuiltinFeature::Screenshot),
        ("pdf", BuiltinFeature::Pdf),
        ("scrape", BuiltinFeature::Scrape),
    ] {
        let command: WorkerActionCommand =
            serde_json::from_value(serde_json::json!({"type":kind}))?;
        assert_eq!(command.required_feature(), Some(feature));
    }
    Ok(())
}

#[allow(clippy::unwrap_used)]
fn typed_approval_receipt() -> WorkerApprovalReceipt {
    use browserd_policy::{
        ApprovalActionKind, ApprovalContextScope, ApprovalNodeBinding, ApprovalWorkerFence,
        CredentialRefsHash, TypedActionPayload, TypedActionProposalBinding,
    };
    let fence = WorkerSessionFence {
        tenant_id: TenantId::new(),
        session_id: SessionId::new(),
        worker_epoch: 7,
        placement_version: 3,
        session_incarnation: 5,
    };
    let action_id = ActionId::new();
    let proposal = WorkerCanonicalActionProposal {
        tenant_id: fence.tenant_id.clone(),
        requester_principal_id: PrincipalId::new(),
        session_id: fence.session_id.clone(),
        session_incarnation: 5,
        page_id: PageId::new(),
        target_incarnation: 9,
        frame_document_epoch: 11,
        current_origin: "https://example.test".to_owned(),
        url_revision: 13,
        action_type: WorkerApprovalActionType::Click,
        canonical_arguments_hash: [2; 32],
        node_ref: Some("opaque-node".to_owned()),
        credential_refs_hash: *CredentialRefsHash::digest([]).as_bytes(),
        expires_at_unix_millis: 1000,
        typed_binding: Some(Box::new(TypedActionProposalBinding {
            schema_version: 2,
            action_id: action_id.clone(),
            sequence: 1,
            fence: ApprovalWorkerFence {
                worker_id: WorkerId::new("approval-worker").unwrap(),
                worker_epoch: 7,
                placement_version: 3,
                session_incarnation: 5,
            },
            policy_digest: [4; 32],
            target_binding_sha256: [5; 32],
            context_scope: ApprovalContextScope::HttpOrigin {
                origin: "https://example.test".to_owned(),
            },
            payload: TypedActionPayload::Browser {
                action: ApprovalActionKind::Click,
                arguments_sha256: [2; 32],
                node: Some(ApprovalNodeBinding {
                    node_ref: "opaque-node".to_owned(),
                    binding_sha256: [6; 32],
                    role: None,
                    name: None,
                }),
                navigation_destination: None,
            },
        })),
    };
    WorkerApprovalReceipt {
        fence,
        approval_id: ApprovalId::new(),
        action_id,
        state: WorkerApprovalState::Pending,
        proposal_hash: *proposal.to_canonical().unwrap().hash().as_bytes(),
        proposal,
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn typed_approval_wire_binds_action_full_numeric_fence_policy_and_payload() {
    let valid = typed_approval_receipt();
    assert_eq!(WORKER_RPC_PROTOCOL_VERSION, 33);
    assert_eq!(valid.canonical_proposal().unwrap().schema_version(), 2);
    let encoded = serde_json::to_value(&valid).unwrap();
    assert_eq!(
        serde_json::from_value::<WorkerApprovalReceipt>(encoded.clone()).unwrap(),
        valid
    );
    for field in [
        "action_id",
        "worker_epoch",
        "placement_version",
        "session_incarnation",
    ] {
        let mut changed = valid.clone();
        match field {
            "action_id" => changed.action_id = ActionId::new(),
            "worker_epoch" => changed.fence.worker_epoch += 1,
            "placement_version" => changed.fence.placement_version += 1,
            _ => changed.fence.session_incarnation += 1,
        }
        assert!(changed.canonical_proposal().is_err(), "{field}");
    }
    for field in [
        "policy_digest",
        "target_binding_sha256",
        "sequence",
        "arguments_sha256",
    ] {
        let mut changed = valid.clone();
        let binding = changed.proposal.typed_binding.as_mut().unwrap();
        match field {
            "policy_digest" => binding.policy_digest = [0; 32],
            "target_binding_sha256" => binding.target_binding_sha256 = [0; 32],
            "sequence" => binding.sequence = 0,
            _ => {
                if let browserd_policy::TypedActionPayload::Browser {
                    arguments_sha256, ..
                } = &mut binding.payload
                {
                    *arguments_sha256 = [99; 32];
                }
            }
        }
        assert!(changed.proposal.to_canonical().is_err(), "{field}");
    }
    let mut unknown = encoded.clone();
    unknown["proposal"]["typed_binding"]["payload"]["script"] =
        serde_json::json!("do_not_accept()");
    assert!(serde_json::from_value::<WorkerApprovalReceipt>(unknown).is_err());
    let mut null_binding = encoded;
    null_binding["proposal"]["typed_binding"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<WorkerApprovalReceipt>(null_binding).is_err());

    let mut legacy = valid.proposal;
    legacy.typed_binding = None;
    let encoded = serde_json::to_value(&legacy).unwrap();
    assert!(encoded.get("typed_binding").is_none());
    assert_eq!(
        serde_json::from_value::<WorkerCanonicalActionProposal>(encoded).unwrap(),
        legacy
    );
    assert_eq!(legacy.to_canonical().unwrap().schema_version(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn non_http_approval_scopes_require_valid_typed_payloads() {
    use browserd_policy::{ApprovalActionKind, ApprovalContextScope, TypedActionPayload};
    let mut checkpoint = typed_approval_receipt().proposal;
    checkpoint.current_origin = "browserd:context".to_owned();
    checkpoint.node_ref = None;
    checkpoint.action_type = WorkerApprovalActionType::Custom("browser:checkpoint".to_owned());
    let binding = checkpoint.typed_binding.as_mut().unwrap();
    binding.context_scope = ApprovalContextScope::BrowserContext;
    binding.payload = TypedActionPayload::Checkpoint {
        origins: vec!["https://example.test".to_owned()],
        build_identity_sha256: [8; 32],
    };
    assert!(checkpoint.to_canonical().is_ok());
    let mut legacy = checkpoint.clone();
    legacy.typed_binding = None;
    assert!(legacy.to_canonical().is_err());
    checkpoint.typed_binding.as_mut().unwrap().context_scope = ApprovalContextScope::OpaqueDocument;
    assert!(checkpoint.to_canonical().is_err());

    let mut opaque = typed_approval_receipt().proposal;
    opaque.current_origin = "null".to_owned();
    opaque.node_ref = None;
    opaque.action_type = WorkerApprovalActionType::Navigate;
    let binding = opaque.typed_binding.as_mut().unwrap();
    binding.context_scope = ApprovalContextScope::OpaqueDocument;
    binding.payload = TypedActionPayload::Browser {
        action: ApprovalActionKind::Navigate,
        arguments_sha256: [2; 32],
        node: None,
        navigation_destination: Some("https://example.test/".to_owned()),
    };
    assert!(opaque.to_canonical().is_ok());
    opaque.typed_binding = None;
    assert!(opaque.to_canonical().is_err());
}
