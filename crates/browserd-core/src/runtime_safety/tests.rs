use super::*;
use crate::SafetySwitchMutation;
use std::sync::{Arc, mpsc};
use std::thread;

#[test]
fn unready_expiry_and_invalidation_never_reopen_old_flow_tokens() {
    let cache = RuntimeSafetyCache::new();
    assert_eq!(
        cache.with_fresh_snapshot(|_| ()),
        Err(RuntimeSafetyError::Unavailable)
    );
    let namespace = Uuid::new_v4();
    let snapshot = SafetySwitchSnapshot::default();
    cache
        .install(namespace, snapshot.clone(), Duration::from_secs(30))
        .expect("install");
    let original = cache.generation().expect("original");
    cache
        .install(namespace, snapshot.clone(), Duration::from_secs(30))
        .expect("healthy refresh");
    assert!(!original.cancellation_token().is_cancelled());
    assert!(cache.generation().expect("refreshed").expires_at() >= original.expires_at());
    cache.invalidate().expect("invalidate");
    assert!(original.cancellation_token().is_cancelled());
    assert!(cache.generation().is_err());
    cache
        .install(namespace, snapshot, Duration::from_secs(30))
        .expect("restore exact pin");
    assert!(original.cancellation_token().is_cancelled());
    assert!(
        !cache
            .generation()
            .expect("restored")
            .cancellation_token()
            .is_cancelled()
    );
    cache
        .installed
        .lock()
        .expect("test deadline")
        .as_mut()
        .expect("installed")
        .expires_at = Instant::now();
    assert_eq!(
        cache.with_fresh_snapshot(|_| ()),
        Err(RuntimeSafetyError::Expired)
    );
}

#[test]
fn rollback_equivocation_namespace_replacement_cancel_and_preserve_permanent_pin() {
    let cache = RuntimeSafetyCache::new();
    let namespace = Uuid::new_v4();
    let baseline = SafetySwitchSnapshot::default();
    let advanced = baseline
        .apply(&SafetySwitchMutation::DisableViewerControl(true))
        .expect("advance");
    cache
        .install(namespace, advanced.clone(), Duration::from_secs(30))
        .expect("install");
    let generation = cache.generation().expect("current");
    assert_eq!(
        cache.install(namespace, baseline.clone(), Duration::from_secs(30)),
        Err(RuntimeSafetyError::VersionRollback)
    );
    assert!(generation.cancellation_token().is_cancelled());
    assert_eq!(
        cache.install(Uuid::new_v4(), advanced.clone(), Duration::from_secs(30)),
        Err(RuntimeSafetyError::NamespaceConflict)
    );
    let conflict = baseline
        .apply(&SafetySwitchMutation::DisableCheckpoint(true))
        .expect("same version other body");
    assert_eq!(
        cache.install(namespace, conflict, Duration::from_secs(30)),
        Err(RuntimeSafetyError::Equivocation)
    );
    cache
        .install(namespace, advanced.clone(), Duration::from_secs(30))
        .expect("exact restore");
    let original = cache.generation().expect("restored");
    cache
        .install(
            namespace,
            advanced
                .apply(&SafetySwitchMutation::DisableDownloads(true))
                .expect("next"),
            Duration::from_secs(30),
        )
        .expect("advance");
    assert!(original.cancellation_token().is_cancelled());
    assert_eq!(cache.generation().expect("new").version(), 2);
    assert_eq!(
        cache.install(namespace, advanced, Duration::from_secs(31)),
        Err(RuntimeSafetyError::InvalidFreshness)
    );
    assert!(cache.generation().is_err());
}

#[test]
fn update_and_admission_are_serialized_but_long_effect_runs_without_cache_lock() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = Uuid::new_v4();
    let snapshot = SafetySwitchSnapshot::default();
    cache
        .install(namespace, snapshot.clone(), Duration::from_secs(30))
        .expect("install");
    let denied = snapshot
        .apply(&SafetySwitchMutation::DisableDownloads(true))
        .expect("deny");
    cache
        .install(namespace, denied.clone(), Duration::from_secs(30))
        .expect("update wins");
    let mut effects = 0;
    cache
        .with_fresh_snapshot(|snapshot| {
            if !snapshot.downloads_disabled() {
                effects += 1;
            }
        })
        .expect("admit");
    assert_eq!(effects, 0);
    let enabled = denied
        .apply(&SafetySwitchMutation::DisableDownloads(false))
        .expect("enable");
    cache
        .install(namespace, enabled.clone(), Duration::from_secs(30))
        .expect("enable");
    let (admitted_tx, admitted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let runner = thread::spawn({
        let cache = Arc::clone(&cache);
        move || {
            cache
                .with_fresh_snapshot(|snapshot| {
                    assert!(!snapshot.downloads_disabled());
                })
                .expect("commit");
            admitted_tx.send(()).expect("admitted");
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("effect wait");
        }
    });
    admitted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("admitted");
    cache
        .install(
            namespace,
            enabled
                .apply(&SafetySwitchMutation::DisableDownloads(true))
                .expect("deny"),
            Duration::from_secs(30),
        )
        .expect("long effect does not block update");
    release_tx.send(()).expect("finish");
    runner.join().expect("effect");
}
