#![allow(clippy::expect_used)]

use super::*;

#[test]
fn snapshot_oversize_is_known_terminal_and_leaves_session_execution_idle() {
    let (worker, peer, driver, _) = ready_worker(2).expect("worker fixture");
    let session = create_ready_session(&worker, &peer, "snapshot-budget").expect("ready session");
    driver
        .executions
        .lock()
        .expect("scripted driver")
        .push_back(ActionExecutionResult::Succeeded(vec![
            b'x';
            browserd_actions::MAX_SNAPSHOT_RESULT_CONTENT_BYTES
                + 1
        ]));
    let id = worker
        .submit_action(
            &peer,
            PrincipalId::new(),
            &session.session_id,
            &session.fence,
            "oversized-snapshot",
            [8; 32],
            ActionKind::ReadOnly,
            Some(BuiltinFeature::Snapshot),
            Some(session.primary_page_id.clone()),
            br#"{"type":"snapshot"}"#.to_vec(),
            None,
            SessionTime::new(2),
        )
        .expect("accepted trusted snapshot");
    worker
        .run_next_action(
            &peer,
            &session.session_id,
            &session.fence,
            SessionTime::new(3),
        )
        .expect("deterministic completion");
    let action = worker
        .get_action(&peer, &session.session_id, &id, &session.fence)
        .expect("owned terminal action");
    assert_eq!(action.status, ActionStatus::FailedKnown);
    assert_eq!(
        action.terminal_detail,
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::SnapshotTooLarge
        ))
    );
    assert!(action.result.is_none());
    let state = worker
        .get_session(&peer, &session.session_id, &session.fence)
        .expect("authoritative session");
    assert_eq!(state.execution, browserd_core::SessionExecution::Idle);
    assert_eq!(state.lifecycle, SessionLifecycle::Ready);
}

#[test]
fn document_changed_reason_is_retained_and_does_not_require_reconciliation() {
    let (worker, peer, driver, _) = ready_worker(2).expect("worker fixture");
    let session = create_ready_session(&worker, &peer, "document-fence").expect("ready session");
    driver
        .executions
        .lock()
        .expect("scripted driver")
        .push_back(ActionExecutionResult::FailedKnown(
            "document_changed".into(),
        ));
    let id = worker
        .submit_action(
            &peer,
            PrincipalId::new(),
            &session.session_id,
            &session.fence,
            "read-after-navigation",
            [9; 32],
            ActionKind::ReadOnly,
            None,
            Some(session.primary_page_id.clone()),
            br#"{"type":"get_url"}"#.to_vec(),
            None,
            SessionTime::new(2),
        )
        .expect("accepted read");
    worker
        .run_next_action(
            &peer,
            &session.session_id,
            &session.fence,
            SessionTime::new(3),
        )
        .expect("known document change");
    let action = worker
        .get_action(&peer, &session.session_id, &id, &session.fence)
        .expect("terminal action");
    assert_eq!(action.status, ActionStatus::FailedKnown);
    assert_eq!(
        action.terminal_detail,
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::DocumentChanged
        ))
    );
    let state = worker
        .get_session(&peer, &session.session_id, &session.fence)
        .expect("session");
    assert_eq!(state.execution, browserd_core::SessionExecution::Idle);
}
