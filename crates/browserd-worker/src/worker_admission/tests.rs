#![allow(clippy::expect_used)]
use super::*;
use crate::{
    ActionJournalConfig, InternalEndpoint, UnavailableChromiumDriver, UnavailableSandboxClient,
    WORKER_SESSION_OPTIONS_VERSION, WorkerConfig, WorkerSessionOptionsV1,
};
use browserd_actions::ActionJournalLimits;
use browserd_core::OperationId;
use browserd_session::{LeasePolicy, SessionTimeoutPolicy};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

#[test]
fn terminal_receipt_survives_original_horizon_until_cleanup_ack_and_ack_returns_success() {
    let directory = tempfile::tempdir().expect("private fixture");
    let peer = AuthenticatedPeer::new("gateway-fixture").expect("peer");
    let id = WorkerId::new("worker-cleanup-retention").expect("worker");
    let resources = ResourceVector::new(1, 1, 1, 1, 1, 1);
    let policy = WorkerAdmissionPolicy::new(
        [1; 32],
        resources,
        vec![WorkerAdmissionBudget {
            profile_digest: [2; 32],
            isolation: WorkerIsolationProfile::SharedContext,
            resources,
        }],
        8,
        None,
    )
    .expect("policy");
    let config = WorkerConfig::new(
        id.clone(),
        7,
        InternalEndpoint::Loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 19339))),
        peer.clone(),
        1,
        8,
        LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3)).expect("lease"),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
            .expect("timeout"),
        Duration::from_secs(60),
        ActionJournalConfig::new(directory.path(), ActionJournalLimits::default())
            .expect("journal"),
    )
    .expect("config")
    .with_fleet_admission_policy(policy)
    .expect("admission");
    let worker = WorkerControlPlane::new(
        config,
        Arc::new(UnavailableChromiumDriver),
        Arc::new(UnavailableSandboxClient),
    );
    let options:WorkerSessionOptionsV1=serde_json::from_value(serde_json::json!({
        "workload_class_hint":"interactive","viewport":{"width":1280,"height":720,"device_scale_factor":1},
        "locale":"ko-KR","timezone":"Asia/Seoul","user_agent":null,"network_policy_id":"public-web-default","network_class":"public",
        "checkpoint_ref":null,"dialog_policy":"auto_dismiss","feature_profile":"standard","ttl_seconds":60,"idle_timeout_seconds":30,"metadata":{}
    })).expect("options");
    let now = Instant::now();
    let old = now
        .checked_sub(Duration::from_secs(86460))
        .expect("old monotonic time");
    let token = {
        let mut state = worker.lock_worker().expect("state");
        let token = WorkerReservationToken {
            worker_id: id,
            worker_reservation_nonce: LeaseId::new(),
            debit_sequence: 1,
            request: WorkerReservationRequest {
                request: WorkerCreateSessionRequest {
                    operation_id: OperationId::new(),
                    tenant_id: TenantId::new(),
                    idempotency_key: "cleanup-retention".into(),
                    canonical_request_hash: options
                        .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                    expected_worker_epoch: 7,
                    placement_version: 1,
                    session_incarnation: 1,
                    requested_isolation: WorkerIsolationProfile::SharedContext,
                    options_version: WORKER_SESSION_OPTIONS_VERSION,
                    options,
                    now_unix_millis: 0,
                },
                reservation_id: LeaseId::new(),
                expected_worker_boot_nonce: state.admission.boot_nonce.clone(),
                compatibility_digest: [1; 32],
                profile_digest: [2; 32],
                resources,
                ttl_millis: 1000,
            },
        };
        state.admission.debit_sequence = 1;
        state.admission.records.insert(
            token.request.reservation_id.clone(),
            ReservationRecord {
                token: token.clone(),
                phase: WorkerReservationPhase::Cancelled,
                deadline: old,
                transferred: false,
                session: None,
                disposed_session: None,
                cleanup_acknowledged: false,
                terminal_at: Some(old),
                lease_revision: 1,
                last_renewal: None,
                used_renewals: BTreeMap::new(),
            },
        );
        token
    };
    worker
        .capacity_status(&peer, 7)
        .expect("refresh beyond original horizon");
    assert_eq!(
        worker
            .inspect_session_reservation(&peer, &token)
            .expect("proof retained")
            .phase,
        WorkerReservationPhase::Cancelled
    );
    assert_eq!(
        worker
            .ack_session_reservation(&peer, &token)
            .expect("late exact cleanup acknowledgement")
            .phase,
        WorkerReservationPhase::Cancelled
    );
    worker
        .capacity_status(&peer, 7)
        .expect("reclaim acknowledged proof");
    assert!(worker.inspect_session_reservation(&peer, &token).is_err());
}
