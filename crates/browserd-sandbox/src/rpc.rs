use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use browserd_core::{ShardId, WorkerId};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;

use crate::{
    CleanupReason, CreateShardOutcome, InspectResources, KillShardOutcome, LaunchSpec,
    RenewLeaseError, SandboxBackend, SandboxError, SandboxSupervisor, WorkerOwnership,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxRpcConfig {
    max_frame_bytes: usize,
    max_connections: usize,
    request_timeout: Duration,
    lease_sweep_interval: Duration,
    allowed_uid: Option<u32>,
}

impl SandboxRpcConfig {
    pub fn new(
        max_frame_bytes: usize,
        max_connections: usize,
        request_timeout: Duration,
        lease_sweep_interval: Duration,
        allowed_uid: Option<u32>,
    ) -> Result<Self, SandboxRpcError> {
        if max_frame_bytes == 0
            || max_connections == 0
            || request_timeout.is_zero()
            || lease_sweep_interval.is_zero()
            || lease_sweep_interval > request_timeout
            || allowed_uid.is_none()
        {
            return Err(SandboxRpcError::InvalidConfig);
        }
        Ok(Self {
            max_frame_bytes,
            max_connections,
            request_timeout,
            lease_sweep_interval,
            allowed_uid,
        })
    }

    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcFailureCode {
    InvalidLease,
    MissingCapability,
    OwnershipMismatch,
    ShardNotFound,
    WorkerEpochMismatch,
    LeaseExpired,
    IncompleteCleanup,
    Backend,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RpcFailure {
    code: RpcFailureCode,
    message: String,
}

impl From<SandboxError> for RpcFailure {
    fn from(error: SandboxError) -> Self {
        let code = match error {
            SandboxError::ZeroLeaseTtl
            | SandboxError::InvalidLeaseOrdering
            | SandboxError::InvalidOwnerLease => RpcFailureCode::InvalidLease,
            SandboxError::MissingCapability { .. } => RpcFailureCode::MissingCapability,
            SandboxError::OwnershipMismatch => RpcFailureCode::OwnershipMismatch,
            SandboxError::ShardNotFound => RpcFailureCode::ShardNotFound,
            SandboxError::WorkerEpochMismatch { .. } => RpcFailureCode::WorkerEpochMismatch,
            SandboxError::IncompleteCleanup { .. } => RpcFailureCode::IncompleteCleanup,
            SandboxError::Backend(_) => RpcFailureCode::Backend,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

impl From<RenewLeaseError> for RpcFailure {
    fn from(error: RenewLeaseError) -> Self {
        let code = match error {
            RenewLeaseError::ShardNotFound => RpcFailureCode::ShardNotFound,
            RenewLeaseError::WorkerEpochMismatch { .. } => RpcFailureCode::WorkerEpochMismatch,
            RenewLeaseError::LeaseExpired => RpcFailureCode::LeaseExpired,
            RenewLeaseError::InvalidNewExpiry => RpcFailureCode::InvalidLease,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum RpcRequest {
    CreateShard {
        shard_id: ShardId,
        worker_id: WorkerId,
        worker_epoch: u64,
        lease_ttl_ms: u64,
    },
    RenewOwnerLease {
        shard_id: ShardId,
        worker_epoch: u64,
        lease_ttl_ms: u64,
    },
    KillShard {
        shard_id: ShardId,
        worker_epoch: u64,
        reason: CleanupReason,
    },
    InspectResources {
        shard_id: ShardId,
        worker_epoch: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", content = "value", rename_all = "snake_case")]
enum RpcSuccess {
    CreateShard(CreateShardOutcome),
    Renewed,
    KillShard(KillShardOutcome),
    InspectResources(InspectResources),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
enum RpcResponse {
    Success(RpcSuccess),
    Failure(RpcFailure),
}

#[derive(Clone, Debug)]
pub struct SandboxRpcClient {
    socket_path: PathBuf,
    max_frame_bytes: usize,
    request_timeout: Duration,
}

impl SandboxRpcClient {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        max_frame_bytes: usize,
        request_timeout: Duration,
    ) -> Result<Self, SandboxRpcError> {
        let socket_path = socket_path.into();
        if !socket_path.is_absolute() || max_frame_bytes == 0 || request_timeout.is_zero() {
            return Err(SandboxRpcError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            max_frame_bytes,
            request_timeout,
        })
    }

    pub async fn create_shard(
        &self,
        spec: LaunchSpec,
        lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, SandboxRpcError> {
        let lease_ttl_ms =
            u64::try_from(lease_ttl.as_millis()).map_err(|_| SandboxRpcError::InvalidLease)?;
        if lease_ttl_ms == 0 {
            return Err(SandboxRpcError::InvalidLease);
        }
        let response = self
            .exchange(RpcRequest::CreateShard {
                shard_id: spec.shard_id,
                worker_id: spec.worker_id,
                worker_epoch: spec.worker_epoch,
                lease_ttl_ms,
            })
            .await?;
        match response {
            RpcSuccess::CreateShard(outcome) => Ok(outcome),
            _ => Err(SandboxRpcError::Protocol),
        }
    }

    pub async fn renew_owner_lease(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        lease_ttl: Duration,
    ) -> Result<(), SandboxRpcError> {
        let lease_ttl_ms =
            u64::try_from(lease_ttl.as_millis()).map_err(|_| SandboxRpcError::InvalidLease)?;
        if lease_ttl_ms == 0 {
            return Err(SandboxRpcError::InvalidLease);
        }
        let response = self
            .exchange(RpcRequest::RenewOwnerLease {
                shard_id: shard_id.clone(),
                worker_epoch,
                lease_ttl_ms,
            })
            .await?;
        match response {
            RpcSuccess::Renewed => Ok(()),
            _ => Err(SandboxRpcError::Protocol),
        }
    }

    pub async fn kill_shard(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, SandboxRpcError> {
        let response = self
            .exchange(RpcRequest::KillShard {
                shard_id: shard_id.clone(),
                worker_epoch,
                reason,
            })
            .await?;
        match response {
            RpcSuccess::KillShard(outcome) => Ok(outcome),
            _ => Err(SandboxRpcError::Protocol),
        }
    }

    pub async fn inspect_resources(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
    ) -> Result<InspectResources, SandboxRpcError> {
        let response = self
            .exchange(RpcRequest::InspectResources {
                shard_id: shard_id.clone(),
                worker_epoch,
            })
            .await?;
        match response {
            RpcSuccess::InspectResources(resources) => Ok(resources),
            _ => Err(SandboxRpcError::Protocol),
        }
    }

    async fn exchange(&self, request: RpcRequest) -> Result<RpcSuccess, SandboxRpcError> {
        let operation = async {
            let stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(self.max_frame_bytes)
                .new_codec();
            let mut framed = Framed::new(stream, codec);
            let encoded = serde_json::to_vec(&request)
                .map_err(|error| SandboxRpcError::Serialization(error.to_string()))?;
            if encoded.len() > self.max_frame_bytes {
                return Err(SandboxRpcError::FrameTooLarge);
            }
            framed
                .send(Bytes::from(encoded))
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let response = framed
                .next()
                .await
                .ok_or(SandboxRpcError::ConnectionClosed)?
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            serde_json::from_slice::<RpcResponse>(&response)
                .map_err(|error| SandboxRpcError::Serialization(error.to_string()))
        };
        let response = tokio::time::timeout(self.request_timeout, operation)
            .await
            .map_err(|_| SandboxRpcError::TimedOut)??;
        match response {
            RpcResponse::Success(success) => Ok(success),
            RpcResponse::Failure(failure) => Err(SandboxRpcError::Remote {
                code: failure.code,
                message: failure.message,
            }),
        }
    }
}

pub struct SandboxRpcServer<B> {
    supervisor: Arc<SandboxSupervisor<B>>,
    config: SandboxRpcConfig,
}

impl<B> SandboxRpcServer<B>
where
    B: SandboxBackend,
{
    #[must_use]
    pub fn new(supervisor: Arc<SandboxSupervisor<B>>, config: SandboxRpcConfig) -> Self {
        Self { supervisor, config }
    }

    pub async fn serve(
        self,
        listener: UnixListener,
        shutdown: CancellationToken,
    ) -> Result<(), SandboxRpcError> {
        let permits = Arc::new(Semaphore::new(self.config.max_connections));
        let sweeper_supervisor = Arc::clone(&self.supervisor);
        let sweeper_shutdown = CancellationToken::new();
        let sweeper_task_shutdown = sweeper_shutdown.clone();
        let sweep_interval = self.config.lease_sweep_interval;
        let sweeper = tokio::spawn(async move {
            let mut interval = tokio::time::interval(sweep_interval);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = sweeper_task_shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let _expired = sweeper_supervisor.expire_leases(Instant::now()).await;
                    }
                }
            }
        });
        let mut connections = JoinSet::new();
        let terminal = loop {
            tokio::select! {
                () = shutdown.cancelled() => break Ok(()),
                Some(joined) = connections.join_next(), if !connections.is_empty() => {
                    if joined.is_err() {
                        break Err(SandboxRpcError::ConnectionTaskFailed);
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _address) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(SandboxRpcError::Io(error.to_string())),
                    };
                    if let Some(allowed_uid) = self.config.allowed_uid {
                        let peer = match stream.peer_cred() {
                            Ok(peer) => peer,
                            Err(_) => continue,
                        };
                        if peer.uid() != allowed_uid {
                            continue;
                        }
                    }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        continue;
                    };
                    let supervisor = Arc::clone(&self.supervisor);
                    let config = self.config;
                    connections.spawn(async move {
                        let _permit = permit;
                        let codec = LengthDelimitedCodec::builder()
                            .max_frame_length(config.max_frame_bytes)
                            .new_codec();
                        let mut framed = Framed::new(stream, codec);
                        let request = match tokio::time::timeout(
                            config.request_timeout,
                            framed.next(),
                        )
                        .await
                        {
                            Ok(Some(Ok(request))) => request,
                            Ok(Some(Err(_))) | Ok(None) | Err(_) => return,
                        };
                        let Ok(request) = serde_json::from_slice::<RpcRequest>(&request) else {
                            return;
                        };
                        let response = match request {
                                RpcRequest::CreateShard {
                                    shard_id,
                                    worker_id,
                                    worker_epoch,
                                    lease_ttl_ms,
                                } => {
                                    let lease_ttl = Duration::from_millis(lease_ttl_ms);
                                    if lease_ttl.is_zero()
                                        || lease_ttl > supervisor.config.supervisor_lease_ttl
                                    {
                                        RpcResponse::Failure(RpcFailure {
                                            code: RpcFailureCode::InvalidLease,
                                            message: "owner lease exceeds the supervisor TTL".to_owned(),
                                        })
                                    } else {
                                        let now = Instant::now();
                                        let spec = LaunchSpec::production(
                                            shard_id,
                                            worker_id.clone(),
                                            worker_epoch,
                                        );
                                        match supervisor
                                            .create_shard(
                                                spec,
                                                WorkerOwnership::new(
                                                    worker_id,
                                                    worker_epoch,
                                                    now + lease_ttl,
                                                ),
                                            )
                                            .await
                                        {
                                            Ok(outcome) => RpcResponse::Success(
                                                RpcSuccess::CreateShard(outcome),
                                            ),
                                            Err(error) => RpcResponse::Failure(error.into()),
                                        }
                                    }
                                }
                                RpcRequest::RenewOwnerLease {
                                    shard_id,
                                    worker_epoch,
                                    lease_ttl_ms,
                                } => {
                                    let now = Instant::now();
                                    match supervisor
                                        .renew_owner_lease(
                                            &shard_id,
                                            worker_epoch,
                                            now,
                                            now + Duration::from_millis(lease_ttl_ms),
                                        )
                                        .await
                                    {
                                        Ok(()) => RpcResponse::Success(RpcSuccess::Renewed),
                                        Err(error) => RpcResponse::Failure(error.into()),
                                    }
                                }
                                RpcRequest::KillShard {
                                    shard_id,
                                    worker_epoch,
                                    reason,
                                } => match supervisor
                                    .kill_shard(&shard_id, worker_epoch, reason)
                                    .await
                                {
                                    Ok(outcome) => {
                                        RpcResponse::Success(RpcSuccess::KillShard(outcome))
                                    }
                                    Err(error) => RpcResponse::Failure(error.into()),
                                },
                                RpcRequest::InspectResources {
                                    shard_id,
                                    worker_epoch,
                                } => match supervisor
                                    .inspect_resources(&shard_id, worker_epoch)
                                    .await
                                {
                                    Ok(resources) => RpcResponse::Success(
                                        RpcSuccess::InspectResources(resources),
                                    ),
                                    Err(error) => RpcResponse::Failure(error.into()),
                                },
                        };
                        let Ok(response) = serde_json::to_vec(&response) else {
                            return;
                        };
                        if response.len() > config.max_frame_bytes {
                            return;
                        }
                        let _result = tokio::time::timeout(
                            config.request_timeout,
                            framed.send(Bytes::from(response)),
                        )
                        .await;
                    });
                }
            }
        };

        while connections.join_next().await.is_some() {}
        sweeper_shutdown.cancel();
        let _sweeper_result = sweeper.await;
        terminal
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SandboxRpcError {
    #[error("sandbox RPC configuration is invalid")]
    InvalidConfig,
    #[error("sandbox owner lease is invalid")]
    InvalidLease,
    #[error("sandbox RPC frame exceeds its configured limit")]
    FrameTooLarge,
    #[error("sandbox RPC request timed out")]
    TimedOut,
    #[error("sandbox RPC peer closed the connection")]
    ConnectionClosed,
    #[error("sandbox RPC protocol response did not match the request")]
    Protocol,
    #[error("sandbox RPC serialization failed: {0}")]
    Serialization(String),
    #[error("sandbox RPC I/O failed: {0}")]
    Io(String),
    #[error("sandbox RPC failed remotely ({code:?}): {message}")]
    Remote {
        code: RpcFailureCode,
        message: String,
    },
    #[error("sandbox RPC connection task failed")]
    ConnectionTaskFailed,
}
