use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use browserd_session::{
    ExpireDecision, LeasePolicy, OwnershipFence, SessionId, SessionLifecycle, SessionMachine,
    SessionOperation, SessionTime, SharedSession, WorkerId,
};

#[test]
fn concurrent_renew_vs_expire_has_one_linearization_order_and_no_torn_state() {
    for _iteration in 0..64 {
        let policy = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20));
        assert!(policy.is_ok());
        let Some(policy) = policy.ok() else {
            return;
        };
        let Some(worker) = WorkerId::new("worker-a").ok() else {
            return;
        };
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

        let shared = SharedSession::new(machine);
        let gate = Arc::new(Barrier::new(3));
        let renew_session = shared.clone();
        let renew_gate = gate.clone();
        let renew_fence = fence.clone();
        let renew = thread::spawn(move || {
            renew_gate.wait();
            renew_session.renew_lease(&renew_fence, SessionTime::new(100))
        });
        let expire_session = shared.clone();
        let expire_gate = gate.clone();
        let expire = thread::spawn(move || {
            expire_gate.wait();
            expire_session.expire_due(&fence, SessionTime::new(100))
        });
        gate.wait();

        let renew_result = renew.join();
        let expire_result = expire.join();
        assert!(renew_result.is_ok());
        assert!(expire_result.is_ok());
        let Some(renew_result) = renew_result.ok() else {
            return;
        };
        let Some(expire_result) = expire_result.ok() else {
            return;
        };
        let snapshot = shared.snapshot();
        assert!(snapshot.is_ok());
        let Some(snapshot) = snapshot.ok() else {
            return;
        };

        if renew_result.is_ok() {
            assert_eq!(
                expire_result,
                Ok(ExpireDecision::NotDue {
                    expires_at: SessionTime::new(200),
                }),
            );
            assert_eq!(snapshot.lifecycle, SessionLifecycle::Ready);
            assert_eq!(snapshot.lease_expires_at, Some(SessionTime::new(200)));
        } else {
            assert_eq!(expire_result, Ok(ExpireDecision::OwnershipLost));
            assert!(matches!(
                renew_result,
                Err(browserd_session::SessionError::InvalidTransition {
                    from: SessionLifecycle::Failed,
                    operation: SessionOperation::RenewLease,
                })
            ));
            assert_eq!(snapshot.lifecycle, SessionLifecycle::Failed);
            assert!(!snapshot.accepting_targets);
        }
    }
}
