#![allow(clippy::expect_used)]
use super::*;
use std::sync::atomic::AtomicU64;

struct AdvancingClock(AtomicU64);
impl WorkerClock for AdvancingClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
    }
}

struct GatedHeartbeatSandbox {
    inner: FakeSandbox,
    entered: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl SandboxClient for GatedHeartbeatSandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.inner.qualify()
    }
    fn provision(
        &self,
        session: &browserd_core::SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.inner.provision(session, fence)
    }
    fn cleanup(
        &self,
        session: &browserd_core::SessionId,
        reason: browserd_sandbox::CleanupReason,
    ) -> Result<(), DependencyError> {
        self.inner.cleanup(session, reason)
    }
    fn heartbeat(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        self.entered
            .send(())
            .map_err(|_| DependencyError::Unavailable)?;
        self.release
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| DependencyError::Unavailable)
    }
    fn store_artifact(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        self.inner.store_artifact(request)
    }
}

#[test]
fn heartbeat_samples_the_renewal_clock_after_the_backend_wait() {
    for (completed_at, expected) in [(80, Some(180)), (150, None)] {
        let (entered, observed) = std::sync::mpsc::channel();
        let (released, release) = std::sync::mpsc::channel();
        let clock = Arc::new(AdvancingClock(AtomicU64::new(0)));
        let peer = AuthenticatedPeer::new("gateway-internal").expect("peer");
        let worker = Arc::new(WorkerControlPlane::new_with_clock(
            config(1).expect("configuration"),
            Arc::new(FakeDriver {
                qualified: true,
                ..Default::default()
            }),
            Arc::new(GatedHeartbeatSandbox {
                inner: FakeSandbox {
                    qualified: true,
                    ..Default::default()
                },
                entered,
                release: Mutex::new(release),
            }),
            clock.clone(),
        ));
        let created = worker
            .create_session(
                &peer,
                create_command(TenantId::new(), "heartbeat-clock", 1),
                SessionTime::new(0),
            )
            .expect("session created");
        assert_eq!(
            worker
                .get_session(&peer, &created.session_id, &created.fence)
                .expect("session snapshot")
                .lease_expires_at,
            Some(SessionTime::new(100))
        );
        assert_eq!(worker.heartbeat_deadline(&peer), Ok(None));
        clock.0.store(10, Ordering::SeqCst);
        let heartbeat = std::thread::spawn({
            let worker = worker.clone();
            let peer = peer.clone();
            move || worker.heartbeat(&peer, SessionTime::new(10))
        });
        let entered = observed.recv_timeout(Duration::from_secs(1));
        clock.0.store(completed_at, Ordering::SeqCst);
        released.send(()).expect("release backend");
        let result = heartbeat.join().expect("heartbeat joins");
        assert!(entered.is_ok());
        if let Some(expiry) = expected {
            assert_eq!(result, Ok(()));
            assert_eq!(
                worker
                    .get_session(&peer, &created.session_id, &created.fence)
                    .expect("renewed session snapshot")
                    .lease_expires_at,
                Some(SessionTime::new(expiry))
            );
            assert_eq!(
                worker.heartbeat_deadline(&peer),
                Ok(Some(SessionTime::new(expiry)))
            );
        } else {
            assert_eq!(
                result,
                Err(WorkerError::InvalidActionTransition),
                "a backend acknowledgment cannot revive a lease past its grace"
            );
            assert_eq!(
                worker
                    .get_session(&peer, &created.session_id, &created.fence)
                    .expect("unrenewed session snapshot")
                    .lease_expires_at,
                Some(SessionTime::new(100))
            );
            assert_eq!(
                worker.heartbeat_deadline(&peer),
                Ok(None),
                "a failed first renewal cannot publish a worker heartbeat deadline"
            );
        }
    }
}

#[test]
fn delayed_heartbeat_callers_preserve_completion_clock_and_lease_monotonicity() {
    let (entered, observed) = std::sync::mpsc::channel();
    let (released, release) = std::sync::mpsc::channel();
    let clock = Arc::new(AdvancingClock(AtomicU64::new(0)));
    let peer = AuthenticatedPeer::new("gateway-internal").expect("peer");
    let worker = Arc::new(WorkerControlPlane::new_with_clock(
        config(1).expect("configuration"),
        Arc::new(FakeDriver {
            qualified: true,
            ..Default::default()
        }),
        Arc::new(GatedHeartbeatSandbox {
            inner: FakeSandbox {
                qualified: true,
                ..Default::default()
            },
            entered,
            release: Mutex::new(release),
        }),
        clock.clone(),
    ));
    assert!(
        worker
            .create_session(
                &peer,
                create_command(TenantId::new(), "heartbeat-stale-clock", 1),
                SessionTime::new(0)
            )
            .is_ok()
    );
    for (caller_now, completed_at, expires_at) in [
        (100, 110, 210),
        (90, 120, 220),
        (80, 115, 220),
        (110, 121, 221),
    ] {
        let heartbeat = std::thread::spawn({
            let worker = worker.clone();
            let peer = peer.clone();
            move || worker.heartbeat(&peer, SessionTime::new(caller_now))
        });
        let backend_entered = observed.recv_timeout(Duration::from_secs(1));
        clock.0.store(completed_at, Ordering::SeqCst);
        released.send(()).expect("release backend");
        let result = heartbeat.join().expect("heartbeat joins");
        assert!(backend_entered.is_ok());
        assert_eq!(result, Ok(()));
        assert_eq!(
            worker.heartbeat_deadline(&peer),
            Ok(Some(SessionTime::new(expires_at)))
        );
    }
}
