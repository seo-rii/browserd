use std::sync::{Arc, Barrier};
use std::thread;

use browserd_worker::DurableWorkerEpoch;

#[test]
fn durable_epoch_is_atomic_monotonic_and_survives_reopen() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let path = Arc::new(directory.path().join("worker.epoch"));
    let barrier = Arc::new(Barrier::new(51));
    let mut handles = Vec::new();
    for _iteration in 0..50 {
        let path = path.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            DurableWorkerEpoch::increment(&*path)
        }));
    }
    barrier.wait();
    let mut epochs = Vec::new();
    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());
        let Some(result) = joined.ok() else {
            return;
        };
        assert!(result.is_ok());
        let Some(epoch) = result.ok() else {
            return;
        };
        epochs.push(epoch);
    }
    epochs.sort_unstable();
    assert_eq!(epochs, (1..=50).collect::<Vec<_>>());
    assert_eq!(DurableWorkerEpoch::increment(&*path), Ok(51));
    assert_eq!(
        std::fs::read_to_string(&*path).ok().as_deref(),
        Some("51\n")
    );
}

#[test]
fn corrupt_or_overflowed_epoch_fails_closed_without_overwrite() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let path = directory.path().join("worker.epoch");
    assert!(std::fs::write(&path, b"not-an-epoch\n").is_ok());
    assert!(DurableWorkerEpoch::increment(&path).is_err());
    assert_eq!(
        std::fs::read_to_string(&path).ok().as_deref(),
        Some("not-an-epoch\n")
    );
    assert!(std::fs::write(&path, format!("{}\n", u64::MAX)).is_ok());
    assert!(DurableWorkerEpoch::increment(&path).is_err());
    assert_eq!(
        std::fs::read_to_string(&path).ok(),
        Some(format!("{}\n", u64::MAX))
    );
}
