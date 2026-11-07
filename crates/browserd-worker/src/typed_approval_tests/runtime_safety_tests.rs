use super::*;
use browserd_core::{RuntimeSafetyCache, SafetySwitchMutation, SafetySwitchSnapshot};

fn runtime() -> (Arc<RuntimeSafetyCache>, uuid::Uuid, SafetySwitchSnapshot) {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = uuid::Uuid::new_v4();
    let snapshot = SafetySwitchSnapshot::default()
        .apply(&SafetySwitchMutation::SetForceDedicatedProcess(false))
        .expect("intent")
        .apply(&SafetySwitchMutation::SetMaxContextsPerShard(4))
        .expect("ceiling");
    cache
        .install(namespace, snapshot.clone(), Duration::from_secs(30))
        .expect("current authority");
    (cache, namespace, snapshot)
}

#[test]
fn runtime_domain_update_wins_at_actual_manual_and_allow_driver_marker() {
    for automatic in [false, true] {
        let (cache, namespace, snapshot) = runtime();
        let f = Fixture::new_with_runtime(true, automatic, Some(cache.clone()));
        let command = WorkerActionCommand::Click {
            node_ref: "node".to_owned(),
        };
        let action = if automatic {
            f.submit(command)
        } else {
            let (action, approval) = f.prepare(command);
            f.approve(&approval);
            action
        };
        *f.driver.before_commit.lock().expect("hook") = Some(Arc::new(move || {
            cache
                .install(
                    namespace,
                    snapshot
                        .apply(&SafetySwitchMutation::SetDeniedDomain {
                            domain: "example.test".to_owned(),
                            denied: true,
                        })
                        .expect("domain deny"),
                    Duration::from_secs(30),
                )
                .expect("update before actual callback");
        }));
        assert_eq!(
            f.run().expect("worker dispatch").expect("terminal").status,
            ActionStatus::FailedKnown
        );
        assert_eq!(f.action(&action).status, ActionStatus::FailedKnown);
        assert_eq!(f.driver.effects.load(Ordering::Acquire), 0);
        assert_eq!(f.driver.generic.load(Ordering::Acquire), 0);
    }
}

#[test]
fn checkpoint_disabled_at_actual_capture_callback_never_reads_or_saves_state() {
    let (cache, namespace, snapshot) = runtime();
    let f = Fixture::new_with_runtime(true, false, Some(cache.clone()));
    let (_, approval) = f.prepare(WorkerActionCommand::Checkpoint {
        origins: vec![ORIGIN.to_owned()],
    });
    f.approve(&approval);
    *f.driver.before_commit.lock().expect("hook") = Some(Arc::new(move || {
        cache
            .install(
                namespace,
                snapshot
                    .apply(&SafetySwitchMutation::DisableCheckpoint(true))
                    .expect("disable"),
                Duration::from_secs(30),
            )
            .expect("update");
    }));
    assert_eq!(
        f.run().expect("dispatch").expect("terminal").status,
        ActionStatus::FailedKnown
    );
    assert_eq!(f.driver.effects.load(Ordering::Acquire), 0);
    assert_eq!(f.checkpoints.saves.load(Ordering::Acquire), 0);
}

#[test]
fn invalidated_authority_stops_new_dispatch_without_blocking_cleanup() {
    let (cache, _, _) = runtime();
    let f = Fixture::new_with_runtime(true, true, Some(cache.clone()));
    f.submit(WorkerActionCommand::Click {
        node_ref: "node".to_owned(),
    });
    cache.invalidate().expect("observer failure");
    assert!(!f.worker.is_ready());
    assert!(f.worker.control_plane_qualified());
    assert_eq!(
        f.run().expect("terminalize").expect("terminal").status,
        ActionStatus::FailedKnown
    );
    assert_eq!(f.driver.effects.load(Ordering::Acquire), 0);
    f.worker
        .close_session(
            &f.peer,
            &f.created.session_id,
            &f.created.fence,
            SessionTime::new(5),
        )
        .expect("positive cleanup remains usable");
}

#[test]
fn safety_update_after_admitted_effect_does_not_wait_for_browser_completion() {
    let (cache, namespace, snapshot) = runtime();
    let f = Fixture::new_with_runtime(true, true, Some(cache.clone()));
    f.submit(WorkerActionCommand::Click {
        node_ref: "node".to_owned(),
    });
    *f.driver.after_commit.lock().expect("hook") = Some(Arc::new(move || {
        let (sent, received) = std::sync::mpsc::channel();
        let next = snapshot
            .apply(&SafetySwitchMutation::DisableDownloads(true))
            .expect("next");
        let cache = cache.clone();
        let installer = std::thread::spawn(move || {
            let result = cache.install(namespace, next, Duration::from_secs(30));
            sent.send(result).expect("result");
        });
        received
            .recv_timeout(Duration::from_secs(2))
            .expect("cache released before long browser operation")
            .expect("install");
        installer.join().expect("installer");
    }));
    assert_eq!(
        f.run().expect("dispatch").expect("terminal").status,
        ActionStatus::Succeeded
    );
    assert_eq!(f.driver.effects.load(Ordering::Acquire), 1);
}
