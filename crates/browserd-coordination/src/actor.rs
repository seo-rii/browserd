use std::sync::Arc;
use std::sync::mpsc::{self, SyncSender};
use std::time::Duration;

use browserd_core::{CreateOperationState, OperationId, TenantId};
use chrono::{DateTime, Utc};

use crate::{
    ClaimCreateOperation, ClaimOutcome, CoordinationError, CreateOperationSnapshot,
    CreateSessionCoordination, OperationMutation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinationActorConfig {
    queue_capacity: usize,
    max_in_flight: usize,
    query_timeout: Duration,
    mutation_timeout: Duration,
}

impl CoordinationActorConfig {
    pub fn new(
        queue_capacity: usize,
        max_in_flight: usize,
        query_timeout: Duration,
        mutation_timeout: Duration,
    ) -> Result<Self, CoordinationError> {
        if queue_capacity == 0
            || max_in_flight == 0
            || max_in_flight > 64
            || query_timeout.is_zero()
            || mutation_timeout.is_zero()
            || mutation_timeout < query_timeout
        {
            return Err(CoordinationError::InvalidActorConfig);
        }
        Ok(Self {
            queue_capacity,
            max_in_flight,
            query_timeout,
            mutation_timeout,
        })
    }

    #[must_use]
    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }

    #[must_use]
    pub const fn max_in_flight(self) -> usize {
        self.max_in_flight
    }

    #[must_use]
    pub const fn query_timeout(self) -> Duration {
        self.query_timeout
    }

    #[must_use]
    pub const fn mutation_timeout(self) -> Duration {
        self.mutation_timeout
    }
}

impl Default for CoordinationActorConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 256,
            max_in_flight: 16,
            query_timeout: Duration::from_secs(5),
            mutation_timeout: Duration::from_secs(30),
        }
    }
}

enum Command {
    Claim {
        claim: ClaimCreateOperation,
        now: DateTime<Utc>,
        response: SyncSender<Result<ClaimOutcome, CoordinationError>>,
    },
    Get {
        tenant_id: TenantId,
        operation_id: OperationId,
        response: SyncSender<Result<Option<CreateOperationSnapshot>, CoordinationError>>,
    },
    CompareAndSet {
        tenant_id: TenantId,
        operation_id: OperationId,
        expected_revision: u64,
        expected_state: CreateOperationState,
        mutation: OperationMutation,
        now: DateTime<Utc>,
        response: SyncSender<Result<CreateOperationSnapshot, CoordinationError>>,
    },
    AcquireDispatchLease {
        tenant_id: TenantId,
        operation_id: OperationId,
        expected_revision: u64,
        token: crate::DispatchLeaseToken,
        ttl: Duration,
        now: DateTime<Utc>,
        response: SyncSender<Result<CreateOperationSnapshot, CoordinationError>>,
    },
    ScanReconcilable {
        limit: usize,
        now: DateTime<Utc>,
        response: SyncSender<Result<Vec<CreateOperationSnapshot>, CoordinationError>>,
    },
    RenewDispatchLease {
        tenant_id: TenantId,
        operation_id: OperationId,
        expected_revision: u64,
        token: crate::DispatchLeaseToken,
        ttl: Duration,
        now: DateTime<Utc>,
        response: SyncSender<Result<CreateOperationSnapshot, CoordinationError>>,
    },
    Purge {
        now: DateTime<Utc>,
        response: SyncSender<Result<u64, CoordinationError>>,
    },
    Drain {
        response: SyncSender<Result<(), CoordinationError>>,
    },
}

#[derive(Clone)]
pub struct CoordinationBlockingClient {
    sender: SyncSender<Command>,
    query_timeout: Duration,
    mutation_timeout: Duration,
}

impl CoordinationBlockingClient {
    pub fn spawn<S>(
        store: Arc<S>,
        config: CoordinationActorConfig,
    ) -> Result<Self, CoordinationError>
    where
        S: CreateSessionCoordination + 'static,
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.max_in_flight())
            .enable_all()
            .build()
            .map_err(|_| CoordinationError::ActorSpawn)?;
        let (sender, receiver) = mpsc::sync_channel(config.queue_capacity());
        let permits = Arc::new(tokio::sync::Semaphore::new(config.max_in_flight()));
        std::thread::Builder::new()
            .name("browserd-coordination".to_owned())
            .spawn(move || {
                while let Ok(permit) = runtime.block_on(Arc::clone(&permits).acquire_owned()) {
                    let Ok(command) = receiver.recv() else {
                        break;
                    };
                    let command = match command {
                        Command::Drain { response } => {
                            let remaining = u32::try_from(config.max_in_flight().saturating_sub(1))
                                .unwrap_or_default();
                            let drained = if remaining == 0 {
                                Ok(None)
                            } else {
                                runtime
                                    .block_on(Arc::clone(&permits).acquire_many_owned(remaining))
                                    .map(Some)
                            };
                            let _ = response.send(
                                drained
                                    .map(|_permits| ())
                                    .map_err(|_| CoordinationError::ActorDisconnected),
                            );
                            drop(permit);
                            continue;
                        }
                        command => command,
                    };
                    let store = Arc::clone(&store);
                    runtime.spawn(async move {
                        match command {
                            Command::Claim {
                                claim,
                                now,
                                response,
                            } => {
                                let result = store.claim_create(claim, now).await;
                                let _ = response.send(result);
                            }
                            Command::Get {
                                tenant_id,
                                operation_id,
                                response,
                            } => {
                                let result = store.get(&tenant_id, &operation_id).await;
                                let _ = response.send(result);
                            }
                            Command::CompareAndSet {
                                tenant_id,
                                operation_id,
                                expected_revision,
                                expected_state,
                                mutation,
                                now,
                                response,
                            } => {
                                let result = store
                                    .compare_and_set(
                                        &tenant_id,
                                        &operation_id,
                                        expected_revision,
                                        expected_state,
                                        mutation,
                                        now,
                                    )
                                    .await;
                                let _ = response.send(result);
                            }
                            Command::Purge { now, response } => {
                                let result = store.purge_expired(now).await;
                                let _ = response.send(result);
                            }
                            Command::Drain { .. } => unreachable!("drain is handled by dispatcher"),
                            Command::AcquireDispatchLease {
                                tenant_id,
                                operation_id,
                                expected_revision,
                                token,
                                ttl,
                                now,
                                response,
                            } => {
                                let result = store
                                    .acquire_dispatch_lease(
                                        &tenant_id,
                                        &operation_id,
                                        expected_revision,
                                        token,
                                        ttl,
                                        now,
                                    )
                                    .await;
                                let _ = response.send(result);
                            }
                            Command::ScanReconcilable {
                                limit,
                                now,
                                response,
                            } => {
                                let result = store.scan_reconcilable(limit, now).await;
                                let _ = response.send(result);
                            }
                            Command::RenewDispatchLease {
                                tenant_id,
                                operation_id,
                                expected_revision,
                                token,
                                ttl,
                                now,
                                response,
                            } => {
                                let result = store
                                    .renew_dispatch_lease(
                                        &tenant_id,
                                        &operation_id,
                                        expected_revision,
                                        token,
                                        ttl,
                                        now,
                                    )
                                    .await;
                                let _ = response.send(result);
                            }
                        }
                        drop(permit);
                    });
                }
            })
            .map_err(|_| CoordinationError::ActorSpawn)?;
        Ok(Self {
            sender,
            query_timeout: config.query_timeout(),
            mutation_timeout: config.mutation_timeout(),
        })
    }

    pub fn claim_create(
        &self,
        claim: ClaimCreateOperation,
        now: DateTime<Utc>,
    ) -> Result<ClaimOutcome, CoordinationError> {
        self.submit(
            |response| Command::Claim {
                claim,
                now,
                response,
            },
            ResponsePolicy::MutationBounded,
        )
    }

    pub fn get(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<Option<CreateOperationSnapshot>, CoordinationError> {
        self.submit(
            |response| Command::Get {
                tenant_id: tenant_id.clone(),
                operation_id: operation_id.clone(),
                response,
            },
            ResponsePolicy::Bounded,
        )
    }

    pub fn compare_and_set(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        expected_state: CreateOperationState,
        mutation: OperationMutation,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        self.submit(
            |response| Command::CompareAndSet {
                tenant_id: tenant_id.clone(),
                operation_id: operation_id.clone(),
                expected_revision,
                expected_state,
                mutation,
                now,
                response,
            },
            ResponsePolicy::MutationBounded,
        )
    }

    pub fn acquire_dispatch_lease(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        token: crate::DispatchLeaseToken,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        self.submit(
            |response| Command::AcquireDispatchLease {
                tenant_id: tenant_id.clone(),
                operation_id: operation_id.clone(),
                expected_revision,
                token,
                ttl,
                now,
                response,
            },
            ResponsePolicy::MutationBounded,
        )
    }

    pub fn scan_reconcilable(
        &self,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<Vec<CreateOperationSnapshot>, CoordinationError> {
        self.submit(
            |response| Command::ScanReconcilable {
                limit,
                now,
                response,
            },
            ResponsePolicy::Bounded,
        )
    }

    pub fn renew_dispatch_lease(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        token: crate::DispatchLeaseToken,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        self.submit(
            |response| Command::RenewDispatchLease {
                tenant_id: tenant_id.clone(),
                operation_id: operation_id.clone(),
                expected_revision,
                token,
                ttl,
                now,
                response,
            },
            ResponsePolicy::MutationBounded,
        )
    }

    pub fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64, CoordinationError> {
        self.submit(
            |response| Command::Purge { now, response },
            ResponsePolicy::MutationBounded,
        )
    }

    pub fn drain(&self) -> Result<(), CoordinationError> {
        self.submit(
            |response| Command::Drain { response },
            ResponsePolicy::MutationBounded,
        )
    }

    fn submit<T>(
        &self,
        build: impl FnOnce(SyncSender<Result<T, CoordinationError>>) -> Command,
        response_policy: ResponsePolicy,
    ) -> Result<T, CoordinationError> {
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(build(response_sender))
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => CoordinationError::ActorQueueFull,
                mpsc::TrySendError::Disconnected(_) => CoordinationError::ActorDisconnected,
            })?;
        match response_policy {
            ResponsePolicy::Bounded => {
                response_receiver
                    .recv_timeout(self.query_timeout)
                    .map_err(|error| match error {
                        mpsc::RecvTimeoutError::Timeout => CoordinationError::ActorTimeout,
                        mpsc::RecvTimeoutError::Disconnected => {
                            CoordinationError::ActorDisconnected
                        }
                    })?
            }
            ResponsePolicy::MutationBounded => response_receiver
                .recv_timeout(self.mutation_timeout)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => CoordinationError::ActorMutationTimeout,
                    mpsc::RecvTimeoutError::Disconnected => CoordinationError::ActorDisconnected,
                })?,
        }
    }
}

#[derive(Clone, Copy)]
enum ResponsePolicy {
    Bounded,
    MutationBounded,
}
