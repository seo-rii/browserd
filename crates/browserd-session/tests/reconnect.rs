use std::time::Duration;

use browserd_session::{
    ClientBinding, LeasePolicy, OwnershipFence, ReconnectError, SessionId, SessionLifecycle,
    SessionMachine, SessionTime, SessionTimeoutPolicy, WorkerId,
};

fn running() -> Option<(SessionMachine, browserd_session::OwnershipFence)> {
    let policy = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20));
    assert!(policy.is_ok());
    let policy = policy.ok()?;
    let worker = WorkerId::new("worker-a").ok()?;
    let (mut machine, fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        policy,
        SessionTime::new(0),
    );
    assert_eq!(
        machine.start(&fence, SessionTime::new(0)),
        Ok(SessionLifecycle::Creating),
    );
    assert_eq!(
        machine.mark_running(&fence, SessionTime::new(1)),
        Ok(SessionLifecycle::Ready),
    );
    Some((machine, fence))
}

fn binding() -> ClientBinding {
    ClientBinding::new("principal-a", "channel-a")
}

#[test]
fn reconnect_token_is_opaque_unique_and_consumed_exactly_once() {
    let Some((mut machine, fence)) = running() else {
        return;
    };
    let first = machine.issue_reconnect_token(
        &fence,
        binding(),
        SessionTime::new(10),
        Duration::from_millis(30),
    );
    let second = machine.issue_reconnect_token(
        &fence,
        binding(),
        SessionTime::new(11),
        Duration::from_millis(30),
    );
    assert!(first.is_ok());
    assert!(second.is_ok());
    let Some(first) = first.ok() else {
        return;
    };
    let Some(second) = second.ok() else {
        return;
    };
    assert_ne!(first, second);
    assert!(!first.to_string().contains("session-a"));
    assert!(!first.to_string().contains("worker-a"));
    let session_id = machine.session_id().clone();

    assert_eq!(
        machine.consume_reconnect_token(&first, &session_id, &binding(), SessionTime::new(20),),
        Ok(fence.clone()),
    );
    assert_eq!(
        machine.consume_reconnect_token(&first, &session_id, &binding(), SessionTime::new(21),),
        Err(ReconnectError::TokenUsedOrUnknown),
    );
}

#[test]
fn failed_session_or_client_binding_does_not_consume_the_token() {
    let Some((mut machine, fence)) = running() else {
        return;
    };
    let token = machine.issue_reconnect_token(
        &fence,
        binding(),
        SessionTime::new(10),
        Duration::from_millis(30),
    );
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let session_id = machine.session_id().clone();

    assert_eq!(
        machine.consume_reconnect_token(
            &token,
            &SessionId::new(),
            &binding(),
            SessionTime::new(20),
        ),
        Err(ReconnectError::SessionMismatch),
    );
    assert_eq!(
        machine.consume_reconnect_token(
            &token,
            &session_id,
            &ClientBinding::new("principal-b", "channel-a"),
            SessionTime::new(21),
        ),
        Err(ReconnectError::BindingMismatch),
    );
    assert_eq!(
        machine.consume_reconnect_token(&token, &session_id, &binding(), SessionTime::new(22),),
        Ok(fence),
    );
}

#[test]
fn reconnect_token_expires_at_its_deadline_and_cannot_be_reused() {
    let Some((mut machine, fence)) = running() else {
        return;
    };
    let token = machine.issue_reconnect_token(
        &fence,
        binding(),
        SessionTime::new(10),
        Duration::from_millis(30),
    );
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let session_id = machine.session_id().clone();

    assert_eq!(
        machine.consume_reconnect_token(&token, &session_id, &binding(), SessionTime::new(40),),
        Err(ReconnectError::TokenExpired),
    );
    assert_eq!(
        machine.consume_reconnect_token(&token, &session_id, &binding(), SessionTime::new(41),),
        Err(ReconnectError::TokenUsedOrUnknown),
    );
}

#[test]
fn ownership_change_invalidates_previously_issued_reconnect_token() {
    let Some((mut machine, fence)) = running() else {
        return;
    };
    let token = machine.issue_reconnect_token(
        &fence,
        binding(),
        SessionTime::new(10),
        Duration::from_millis(30),
    );
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let session_id = machine.session_id().clone();
    let Some(worker_b) = WorkerId::new("worker-b").ok() else {
        return;
    };
    assert!(
        machine
            .transfer_owner(&fence, worker_b, 1, SessionTime::new(11))
            .is_ok()
    );

    assert_eq!(
        machine.consume_reconnect_token(&token, &session_id, &binding(), SessionTime::new(12),),
        Err(ReconnectError::StaleOwnershipFence),
    );
}

#[test]
fn expiry_is_checked_before_binding_and_consumes_the_dead_token() {
    let Some((mut machine, fence)) = running() else {
        return;
    };
    let token = machine.issue_reconnect_token(
        &fence,
        binding(),
        SessionTime::new(10),
        Duration::from_millis(30),
    );
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let session_id = machine.session_id().clone();

    assert_eq!(
        machine.consume_reconnect_token(
            &token,
            &session_id,
            &ClientBinding::new("principal-b", "channel-b"),
            SessionTime::new(40),
        ),
        Err(ReconnectError::TokenExpired),
    );
    assert_eq!(
        machine.consume_reconnect_token(&token, &session_id, &binding(), SessionTime::new(41),),
        Err(ReconnectError::TokenUsedOrUnknown),
    );
}

#[test]
fn beginning_session_close_revokes_unconsumed_reconnect_tokens() {
    let lease = LeasePolicy::new(Duration::from_millis(1_000), Duration::from_millis(20));
    let timeouts =
        SessionTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(100));
    assert!(lease.is_ok());
    assert!(timeouts.is_ok());
    let (Some(lease), Some(timeouts)) = (lease.ok(), timeouts.ok()) else {
        return;
    };
    let Some(worker) = WorkerId::new("worker-a").ok() else {
        return;
    };
    let (mut machine, fence) = SessionMachine::create_with_timeouts(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        lease,
        timeouts,
        SessionTime::new(0),
    );
    assert!(machine.start(&fence, SessionTime::new(0)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(1)).is_ok());
    let token = machine.issue_reconnect_token(
        &fence,
        binding(),
        SessionTime::new(10),
        Duration::from_millis(500),
    );
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let session_id = machine.session_id().clone();
    assert!(machine.expire_due(&fence, SessionTime::new(100)).is_ok());

    assert_eq!(
        machine.consume_reconnect_token(&token, &session_id, &binding(), SessionTime::new(101),),
        Err(ReconnectError::TokenUsedOrUnknown),
    );
}

#[test]
fn consume_rejects_session_deadline_even_before_expiry_sweeper_runs() {
    let lease = LeasePolicy::new(Duration::from_millis(1_000), Duration::from_millis(20));
    let timeouts =
        SessionTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(100));
    assert!(lease.is_ok());
    assert!(timeouts.is_ok());
    let (Some(lease), Some(timeouts)) = (lease.ok(), timeouts.ok()) else {
        return;
    };
    let Some(worker) = WorkerId::new("worker-a").ok() else {
        return;
    };
    let (mut machine, fence) = SessionMachine::create_with_timeouts(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        lease,
        timeouts,
        SessionTime::new(0),
    );
    assert!(machine.start(&fence, SessionTime::new(0)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(1)).is_ok());
    let token = machine.issue_reconnect_token(
        &fence,
        binding(),
        SessionTime::new(10),
        Duration::from_millis(500),
    );
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let session_id = machine.session_id().clone();
    assert_eq!(machine.lifecycle(), SessionLifecycle::Ready);

    assert_eq!(
        machine.consume_reconnect_token(
            &token,
            &session_id,
            &ClientBinding::new("wrong-principal", "wrong-channel"),
            SessionTime::new(100),
        ),
        Err(ReconnectError::InvalidLifecycle),
    );
    assert_eq!(
        machine.consume_reconnect_token(&token, &session_id, &binding(), SessionTime::new(101),),
        Err(ReconnectError::TokenUsedOrUnknown),
    );
}
