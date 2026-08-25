use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use browserd_core::WorkerId;
use browserd_session::{LeasePolicy, SessionTimeoutPolicy};
use browserd_worker::{
    AuthenticatedPeer, DurableWorkerEpoch, InternalEndpoint, UnavailableChromiumDriver,
    UnavailableSandboxClient, WorkerConfig, WorkerControlPlane,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("browser-worker startup refused: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let worker_id = env::var("BROWSERD_WORKER_ID")
        .map_err(|_| "BROWSERD_WORKER_ID is required".to_owned())
        .and_then(|value| WorkerId::new(value).map_err(|_| "invalid worker identity".to_owned()))?;
    let epoch_path = env::var_os("BROWSERD_WORKER_EPOCH_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| "BROWSERD_WORKER_EPOCH_FILE is required".to_owned())?;
    if !epoch_path.is_absolute() {
        return Err("epoch file must be absolute".to_owned());
    }
    let worker_epoch = DurableWorkerEpoch::increment(epoch_path)
        .map_err(|_| "durable worker epoch unavailable".to_owned())?;
    let endpoint = parse_endpoint(
        &env::var("BROWSERD_INTERNAL_ENDPOINT")
            .map_err(|_| "BROWSERD_INTERNAL_ENDPOINT is required".to_owned())?,
    )?;
    let trusted_peer = env::var("BROWSERD_INTERNAL_PEER")
        .map_err(|_| "BROWSERD_INTERNAL_PEER is required".to_owned())
        .and_then(|value| {
            AuthenticatedPeer::new(value)
                .map_err(|_| "invalid authenticated peer identity".to_owned())
        })?;
    let lease_policy = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3))
        .map_err(|_| "invalid ownership lease policy".to_owned())?;
    let timeout_policy =
        SessionTimeoutPolicy::new(Duration::from_secs(30 * 60), Duration::from_secs(10 * 60))
            .map_err(|_| "invalid session timeout policy".to_owned())?;
    let config = WorkerConfig::new(
        worker_id,
        worker_epoch,
        endpoint,
        trusted_peer,
        256,
        128,
        lease_policy,
        timeout_policy,
    )
    .map_err(|_| "invalid worker configuration".to_owned())?;
    let worker = WorkerControlPlane::new(
        config,
        Arc::new(UnavailableChromiumDriver),
        Arc::new(UnavailableSandboxClient),
    );
    if !worker.is_ready() {
        return Err("readiness qualification unavailable".to_owned());
    }
    Err("internal transport adapter unavailable".to_owned())
}

fn parse_endpoint(value: &str) -> Result<InternalEndpoint, String> {
    if let Some(path) = value.strip_prefix("unix:") {
        return InternalEndpoint::unix(path).map_err(|_| "invalid internal endpoint".to_owned());
    }
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| "invalid internal endpoint".to_owned())?;
    InternalEndpoint::loopback(address).map_err(|_| "invalid internal endpoint".to_owned())
}
