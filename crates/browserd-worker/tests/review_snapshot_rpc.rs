#![allow(clippy::expect_used)]
use async_trait::async_trait;
use browserd_actions::{
    ActionKind, ActionResultBudget, ActionSequence, MAX_SNAPSHOT_RESULT_CONTENT_BYTES,
    ResultDigest, TerminalDetail,
};
use browserd_core::{ActionId, SessionId, TenantId};
use browserd_worker::{
    MAX_WORKER_ACTION_RPC_FRAME_BYTES, WorkerActionReceipt, WorkerActionStatus, WorkerRpcClient,
    WorkerRpcConfig, WorkerRpcHandler, WorkerRpcRequest, WorkerRpcResponse, WorkerRpcServer,
    WorkerSessionFence,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn json_bytes(size: usize) -> Vec<u8> {
    let overhead = serde_json::to_vec(&serde_json::json!({"value":""}))
        .expect("JSON")
        .len();
    let remaining = size - overhead;
    let text = "🙂".repeat(remaining / 4) + &"x".repeat(remaining % 4);
    let bytes =
        serde_json::to_vec(&serde_json::json!({"value":text})).expect("actual UTF8 JSON bytes");
    assert_eq!(bytes.len(), size);
    bytes
}
fn receipt(body: Vec<u8>) -> WorkerActionReceipt {
    let digest = ResultDigest::new(Sha256::digest(&body).into());
    WorkerActionReceipt {
        fence: WorkerSessionFence {
            tenant_id: TenantId::new(),
            session_id: SessionId::new(),
            worker_epoch: 7,
            placement_version: 3,
            session_incarnation: 2,
        },
        action_id: ActionId::new(),
        action_sequence: ActionSequence::new(1),
        idempotency_key: "snapshot".into(),
        canonical_request_hash: [8; 32],
        kind: ActionKind::ReadOnly,
        status: WorkerActionStatus::Succeeded,
        dispatch_acknowledged: true,
        approval_decision: None,
        terminal_detail: Some(TerminalDetail::Succeeded(digest)),
        result: Some(body),
        resolution: None,
        custody: None,
        custody_requirement: None,
    }
}
struct SnapshotHandler(WorkerActionReceipt);
#[async_trait]
impl WorkerRpcHandler for SnapshotHandler {
    async fn handle(&self, request: WorkerRpcRequest) -> WorkerRpcResponse {
        if matches!(request,WorkerRpcRequest::GetAction{fence,action_id} if fence==self.0.fence && action_id==self.0.action_id)
        {
            WorkerRpcResponse::Action(self.0.clone())
        } else {
            WorkerRpcResponse::Empty
        }
    }
}

#[test]
fn receipt_budget_checks_real_utf8_bytes_digest_and_the_legacy_default() {
    let mut value = receipt(json_bytes(MAX_SNAPSHOT_RESULT_CONTENT_BYTES));
    assert!(value.to_action_snapshot().is_err());
    assert!(
        value
            .to_action_snapshot_with_result_budget(ActionResultBudget::Snapshot)
            .is_ok()
    );
    value.result.as_mut().expect("body")[15] ^= 1;
    assert!(
        value
            .to_action_snapshot_with_result_budget(ActionResultBudget::Snapshot)
            .is_err()
    );
    let oversized = receipt(json_bytes(MAX_SNAPSHOT_RESULT_CONTENT_BYTES + 1));
    assert!(
        oversized
            .to_action_snapshot_with_result_budget(ActionResultBudget::Snapshot)
            .is_err()
    );
    let mut wrong_kind = receipt(json_bytes(128));
    wrong_kind.kind = ActionKind::Mutating;
    assert!(
        wrong_kind
            .to_action_snapshot_with_result_budget(ActionResultBudget::Snapshot)
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_four_megabyte_snapshot_crosses_the_actual_bounded_worker_rpc_byte_array_envelope() {
    let dir = tempfile::tempdir().expect("private socket dir");
    let path = dir.path().join("worker.sock");
    let value = receipt(json_bytes(MAX_SNAPSHOT_RESULT_CONTENT_BYTES));
    let response = WorkerRpcResponse::Action(value.clone());
    let encoded = serde_json::to_vec(&response).expect("real RPC byte-array JSON");
    assert!(encoded.len() > 4 * 1024 * 1024);
    assert!(encoded.len() < MAX_WORKER_ACTION_RPC_FRAME_BYTES - 1024);
    let uid = nix::unistd::Uid::effective().as_raw();
    let config = WorkerRpcConfig::new(
        path.clone(),
        MAX_WORKER_ACTION_RPC_FRAME_BYTES,
        2,
        Duration::from_secs(10),
        Some(uid),
    )
    .expect("server bound");
    let server = WorkerRpcServer::bind(config, Arc::new(SnapshotHandler(value.clone())))
        .await
        .expect("private RPC server");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    let client = WorkerRpcClient::new(
        path.clone(),
        MAX_WORKER_ACTION_RPC_FRAME_BYTES,
        Duration::from_secs(10),
        Some(uid),
    )
    .expect("same bounded client");
    let received = client
        .get_action(value.fence.clone(), value.action_id.clone())
        .await;
    shutdown.cancel();
    task.await.expect("server task").expect("bounded shutdown");
    let received = received.expect("actual complete frame");
    assert_eq!(received, value);
    assert!(
        received
            .to_action_snapshot_with_result_budget(ActionResultBudget::Snapshot)
            .is_ok()
    );
    assert!(!path.exists());
}
