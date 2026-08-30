#![allow(clippy::expect_used)]

use std::collections::HashMap;

use browser_gateway::config::{GatewayProcessConfig, GatewayProcessConfigError};

fn production_environment() -> HashMap<&'static str, String> {
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
            "https://viewer.example".to_owned(),
        ),
    ])
}

#[test]
fn production_configuration_requires_durable_redis_coordination() {
    for missing in ["BROWSERD_REDIS_URL", "BROWSERD_REDIS_PREFIX"] {
        let mut environment = production_environment();
        environment.remove(missing);

        assert!(
            matches!(
                GatewayProcessConfig::from_lookup(|name| environment.get(name).cloned()),
                Err(GatewayProcessConfigError::Missing(name)) if name == missing
            ),
            "{missing} must be required before the gateway can install a production runtime"
        );
    }
}

#[test]
fn gateway_main_composes_durable_dependencies_and_probes_them_before_serving() {
    let source = include_str!("../src/main.rs");
    let serve = source
        .find("axum::serve")
        .expect("the gateway binary must eventually serve its router");

    for required in [
        "GatewayAuthenticator::from_hmac_parts",
        "WorkerRpcClient::new",
        ".probe(",
        "PostgresCreateSessionStore::connect",
        ".migrate()",
        "CoordinationBlockingClient::spawn",
        "RedisGatewayActionStore::connect",
        "GatewayWorkerRuntime::with_action_coordination",
        "DurableApiRouter::with_dispatch_lease_duration",
        "GatewayViewer::new",
        "GatewayReadiness::new",
        "set_worker_ready(true)",
        "set_coordination_ready(true)",
    ] {
        let Some(composed) = source.find(required) else {
            assert!(
                source.contains(required),
                "production gateway composition is missing {required}"
            );
            continue;
        };
        assert!(
            composed < serve,
            "{required} must be initialized before the public server starts"
        );
    }
}

#[test]
fn gateway_main_never_installs_in_memory_or_reject_all_placeholders() {
    let source = include_str!("../src/main.rs");

    for forbidden in [
        "InMemoryApiService",
        "RejectAllAuth",
        "RejectAllViewer",
        "NotReady",
        "GatewayWorkerRuntime::new(",
    ] {
        assert!(
            !source.contains(forbidden),
            "production gateway main must not contain placeholder {forbidden}"
        );
    }
}
