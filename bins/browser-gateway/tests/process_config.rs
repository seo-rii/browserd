#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[path = "../src/config.rs"]
mod config;

use config::{GatewayProcessConfig, GatewayProcessConfigError};

fn valid_environment() -> HashMap<&'static str, String> {
    HashMap::from([
        ("BROWSERD_BIND", "127.0.0.1:8080".to_owned()),
        ("BROWSERD_TRUST_TLS_TERMINATOR", "false".to_owned()),
        ("BROWSERD_AUTH_ISSUER", "browserd-gateway".to_owned()),
        ("BROWSERD_AUTH_AUDIENCE", "browserd-api".to_owned()),
        ("BROWSERD_AUTH_KEY_ID", "active-key".to_owned()),
        (
            "BROWSERD_AUTH_HMAC_SECRET",
            "0123456789abcdef0123456789abcdef".to_owned(),
        ),
        (
            "BROWSERD_WORKER_SOCKET",
            "/run/browserd/worker.sock".to_owned(),
        ),
        ("BROWSERD_WORKER_UID", "1001".to_owned()),
        ("BROWSERD_WORKER_EPOCH", "7".to_owned()),
        ("BROWSERD_PLACEMENT_VERSION", "11".to_owned()),
        (
            "BROWSERD_POSTGRES_URL",
            "postgresql://browserd:secret@db.internal/browserd".to_owned(),
        ),
        (
            "BROWSERD_REDIS_URL",
            "redis://:secret@redis.internal/0".to_owned(),
        ),
        ("BROWSERD_REDIS_PREFIX", "browserd-prod".to_owned()),
        (
            "BROWSERD_VIEWER_ORIGINS",
            "https://viewer.example,https://ops.example".to_owned(),
        ),
        ("BROWSERD_WORKER_RPC_QUEUE", "64".to_owned()),
        ("BROWSERD_WORKER_RPC_IN_FLIGHT", "8".to_owned()),
        ("BROWSERD_WORKER_RPC_TIMEOUT_MS", "5000".to_owned()),
        ("BROWSERD_COORDINATION_QUEUE", "128".to_owned()),
        ("BROWSERD_COORDINATION_IN_FLIGHT", "8".to_owned()),
        ("BROWSERD_COORDINATION_QUERY_TIMEOUT_MS", "2000".to_owned()),
        (
            "BROWSERD_COORDINATION_MUTATION_TIMEOUT_MS",
            "10000".to_owned(),
        ),
        ("BROWSERD_CREATE_LEASE_MS", "30000".to_owned()),
        ("BROWSERD_POSTGRES_MAX_CONNECTIONS", "8".to_owned()),
    ])
}

fn parse(
    environment: &HashMap<&str, String>,
) -> Result<GatewayProcessConfig, GatewayProcessConfigError> {
    GatewayProcessConfig::from_lookup(|name| environment.get(name).cloned())
}

#[test]
fn parses_a_complete_fail_closed_production_configuration() {
    let environment = valid_environment();
    let config = parse(&environment).expect("complete configuration should parse");
    assert_eq!(config.bind_address().to_string(), "127.0.0.1:8080");
    assert!(!config.trust_tls_terminator());
    assert_eq!(config.auth_issuer(), "browserd-gateway");
    assert_eq!(config.auth_audience(), "browserd-api");
    assert_eq!(config.auth_key_id(), "active-key");
    assert_eq!(config.auth_hmac_secret().len(), 32);
    assert_eq!(
        config.worker_socket(),
        Path::new("/run/browserd/worker.sock")
    );
    assert_eq!(config.worker_uid(), 1001);
    assert_eq!(config.worker_epoch(), 7);
    assert_eq!(config.placement_version(), 11);
    assert_eq!(
        config.postgres_url(),
        "postgresql://browserd:secret@db.internal/browserd"
    );
    assert_eq!(config.redis_url(), "redis://:secret@redis.internal/0");
    assert_eq!(config.redis_prefix(), "browserd-prod");
    assert_eq!(config.viewer_origins().len(), 2);
    assert_eq!(config.worker_rpc_queue(), 64);
    assert_eq!(config.worker_rpc_in_flight(), 8);
    assert_eq!(config.worker_rpc_timeout(), Duration::from_secs(5));
    assert_eq!(config.coordination_queue(), 128);
    assert_eq!(config.coordination_in_flight(), 8);
    assert_eq!(config.coordination_query_timeout(), Duration::from_secs(2));
    assert_eq!(
        config.coordination_mutation_timeout(),
        Duration::from_secs(10)
    );
    assert_eq!(config.create_lease_duration(), Duration::from_secs(30));
    assert_eq!(config.postgres_max_connections(), 8);

    let debug = format!("{config:?}");
    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("browserd:secret"));
    assert!(!debug.contains(":secret@redis"));
}

#[test]
fn rejects_public_bind_without_tls_trust_and_every_missing_security_identity() {
    let required = [
        "BROWSERD_AUTH_ISSUER",
        "BROWSERD_AUTH_AUDIENCE",
        "BROWSERD_AUTH_KEY_ID",
        "BROWSERD_AUTH_HMAC_SECRET",
        "BROWSERD_WORKER_SOCKET",
        "BROWSERD_WORKER_UID",
        "BROWSERD_WORKER_EPOCH",
        "BROWSERD_PLACEMENT_VERSION",
        "BROWSERD_POSTGRES_URL",
        "BROWSERD_REDIS_URL",
        "BROWSERD_REDIS_PREFIX",
        "BROWSERD_VIEWER_ORIGINS",
    ];
    for name in required {
        let mut environment = valid_environment();
        environment.remove(name);
        assert!(parse(&environment).is_err(), "{name} must be required");
    }

    let mut environment = valid_environment();
    environment.insert("BROWSERD_BIND", "0.0.0.0:8080".to_owned());
    assert_eq!(
        parse(&environment),
        Err(GatewayProcessConfigError::UntrustedPublicBind)
    );
    environment.insert("BROWSERD_TRUST_TLS_TERMINATOR", "true".to_owned());
    assert!(parse(&environment).is_ok());
}

#[test]
fn rejects_weak_ambiguous_or_unbounded_values() {
    for (name, value) in [
        ("BROWSERD_TRUST_TLS_TERMINATOR", "TRUE"),
        ("BROWSERD_AUTH_HMAC_SECRET", "too-short"),
        ("BROWSERD_WORKER_SOCKET", "worker.sock"),
        ("BROWSERD_WORKER_UID", "not-a-uid"),
        ("BROWSERD_WORKER_EPOCH", "0"),
        ("BROWSERD_PLACEMENT_VERSION", "0"),
        ("BROWSERD_POSTGRES_URL", "http://db.internal/browserd"),
        ("BROWSERD_REDIS_URL", "http://redis.internal/0"),
        ("BROWSERD_REDIS_PREFIX", "browserd prod"),
        ("BROWSERD_VIEWER_ORIGINS", "https://viewer.example,"),
        ("BROWSERD_WORKER_RPC_QUEUE", "0"),
        ("BROWSERD_WORKER_RPC_IN_FLIGHT", "65"),
        ("BROWSERD_WORKER_RPC_TIMEOUT_MS", "0"),
        ("BROWSERD_COORDINATION_QUEUE", "0"),
        ("BROWSERD_COORDINATION_IN_FLIGHT", "65"),
        ("BROWSERD_COORDINATION_QUERY_TIMEOUT_MS", "0"),
        ("BROWSERD_COORDINATION_MUTATION_TIMEOUT_MS", "0"),
        ("BROWSERD_CREATE_LEASE_MS", "0"),
        ("BROWSERD_POSTGRES_MAX_CONNECTIONS", "0"),
    ] {
        let mut environment = valid_environment();
        environment.insert(name, value.to_owned());
        assert!(parse(&environment).is_err(), "{name}={value} must fail");
    }
}

#[test]
fn production_binary_validates_auth_routing_and_coordination_before_public_bind() {
    let occupied =
        TcpListener::bind("0.0.0.0:0").expect("test must reserve a public listener address");
    let occupied_address = occupied
        .local_addr()
        .expect("reserved listener must expose its address");

    for missing in [
        "BROWSERD_AUTH_ISSUER",
        "BROWSERD_WORKER_SOCKET",
        "BROWSERD_POSTGRES_URL",
        "BROWSERD_VIEWER_ORIGINS",
    ] {
        let mut environment = valid_environment();
        environment.insert("BROWSERD_BIND", occupied_address.to_string());
        environment.insert("BROWSERD_TRUST_TLS_TERMINATOR", "true".to_owned());
        environment.remove(missing);

        let mut command = Command::new(env!("CARGO_BIN_EXE_browser-gateway"));
        command.env_clear();
        for (name, value) in &environment {
            command.env(name, value);
        }
        let output = command
            .output()
            .expect("gateway process must return before attempting the occupied bind");
        assert!(
            !output.status.success(),
            "missing {missing} must fail closed"
        );

        let stderr = String::from_utf8(output.stderr).expect("gateway stderr must be UTF-8");
        assert!(
            stderr.contains(&format!(
                "required environment variable is missing: {missing}"
            )),
            "missing {missing} reached listener bind instead of configuration validation: {stderr}"
        );
        assert!(
            !stderr.contains("failed to bind browser gateway"),
            "missing {missing} must be rejected before the public listener bind: {stderr}"
        );
    }
}
