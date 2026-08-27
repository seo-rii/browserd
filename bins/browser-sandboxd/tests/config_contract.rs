#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::time::Duration;

use browser_sandboxd::EgressClientConfig;

#[test]
fn egress_control_is_loopback_bounded_and_uid_pinned() {
    assert!(
        EgressClientConfig::new(
            "http://127.0.0.1:4301".parse().expect("URL should parse"),
            PathBuf::from("/run/browserd/egress-install.sock"),
            41,
            1000,
            "worker-token-that-is-long-enough-for-production",
            "supervisor-token-that-is-long-enough-production",
            Duration::from_millis(250),
            16 * 1024,
        )
        .is_ok()
    );
    assert!(
        EgressClientConfig::new(
            "http://192.0.2.1:4301".parse().expect("URL should parse"),
            PathBuf::from("/run/browserd/egress-install.sock"),
            41,
            1000,
            "worker-token-that-is-long-enough-for-production",
            "supervisor-token-that-is-long-enough-production",
            Duration::from_millis(250),
            16 * 1024,
        )
        .is_err()
    );
    assert!(
        EgressClientConfig::new(
            "http://127.0.0.1:4301".parse().expect("URL should parse"),
            PathBuf::from("relative.sock"),
            0,
            1000,
            "short",
            "short",
            Duration::ZERO,
            0,
        )
        .is_err()
    );
}
