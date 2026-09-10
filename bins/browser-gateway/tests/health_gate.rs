use browser_gateway::DependencyHealthGate;

#[test]
fn a_transient_failure_below_the_threshold_stays_ready() {
    let mut gate = DependencyHealthGate::new(2, 3, true);
    // Two isolated failures separated by a success never reach three in a row.
    assert!(gate.record(false));
    assert!(gate.record(false));
    assert!(gate.record(true));
    assert!(gate.record(false));
    assert!(gate.record(false));
    assert!(
        gate.ready(),
        "isolated failures must not flip a ready dependency"
    );
}

#[test]
fn sustained_failures_fail_closed_after_the_threshold() {
    let mut gate = DependencyHealthGate::new(2, 3, true);
    assert!(gate.record(false));
    assert!(gate.record(false));
    assert!(
        !gate.record(false),
        "the third consecutive failure flips to unready"
    );
    assert!(!gate.ready());
}

#[test]
fn recovery_requires_the_healthy_threshold_of_consecutive_successes() {
    let mut gate = DependencyHealthGate::new(2, 1, true);
    // One failure (unhealthy_threshold = 1) flips it closed.
    assert!(!gate.record(false));
    // A single success is not enough to recover with healthy_threshold = 2.
    assert!(!gate.record(true));
    // The second consecutive success recovers.
    assert!(gate.record(true));
    assert!(gate.ready());
}

#[test]
fn a_success_resets_the_failure_streak() {
    let mut gate = DependencyHealthGate::new(1, 3, true);
    assert!(gate.record(false));
    assert!(gate.record(false));
    // A success resets the streak, so the next two failures do not reach three in a row.
    assert!(gate.record(true));
    assert!(gate.record(false));
    assert!(gate.record(false));
    assert!(gate.ready());
}

#[test]
fn thresholds_below_one_are_clamped_so_the_gate_can_always_move() {
    let mut gate = DependencyHealthGate::new(0, 0, true);
    assert!(
        !gate.record(false),
        "a single failure flips a clamped gate closed"
    );
    assert!(
        gate.record(true),
        "a single success recovers a clamped gate"
    );
}
