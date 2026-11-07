use std::sync::Arc;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::time::Duration;

use crate::CoordinationActorConfig;

use super::{
    SafetyAuditAck, SafetyAuditIntent, SafetyAuthority, SafetyAuthorityError,
    SafetyAuthoritySnapshot, SafetyInitializeRequest, SafetyMutationReceipt, SafetyMutationRequest,
};

type Reply<T> = SyncSender<Result<T, SafetyAuthorityError>>;
enum Command {
    Initialize(SafetyInitializeRequest, Reply<SafetyMutationReceipt>),
    Read(Reply<SafetyAuthoritySnapshot>),
    Mutate(SafetyMutationRequest, Reply<SafetyMutationReceipt>),
    Pending(usize, Reply<Vec<SafetyAuditIntent>>),
    Ack(SafetyAuditAck, Reply<()>),
    Prune(Reply<usize>),
    Drain(Reply<()>),
}

#[derive(Clone)]
pub struct SafetyAuthorityBlockingClient {
    sender: SyncSender<Command>,
    query_timeout: Duration,
    mutation_timeout: Duration,
}
impl SafetyAuthorityBlockingClient {
    pub fn spawn<S>(
        store: Arc<S>,
        config: CoordinationActorConfig,
    ) -> Result<Self, SafetyAuthorityError>
    where
        S: SafetyAuthority + ?Sized + 'static,
    {
        if config.queue_capacity() > 4_096 {
            return Err(SafetyAuthorityError::InvalidConfig);
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.max_in_flight())
            .enable_all()
            .build()
            .map_err(|_| SafetyAuthorityError::ActorSpawn)?;
        let (sender, receiver) = mpsc::sync_channel(config.queue_capacity());
        let permits = Arc::new(tokio::sync::Semaphore::new(config.max_in_flight()));
        std::thread::Builder::new()
            .name("browserd-safety-authority".to_owned())
            .spawn(move || {
                while let Ok(permit) = runtime.block_on(Arc::clone(&permits).acquire_owned()) {
                    let Ok(command) = receiver.recv() else {
                        break;
                    };
                    if let Command::Drain(response) = command {
                        let remaining = u32::try_from(config.max_in_flight().saturating_sub(1))
                            .unwrap_or_default();
                        let drained =
                            runtime.block_on(Arc::clone(&permits).acquire_many_owned(remaining));
                        let _ = response.send(
                            drained
                                .map(|_remaining| ())
                                .map_err(|_| SafetyAuthorityError::ActorDisconnected),
                        );
                        drop(permit);
                        continue;
                    }
                    let store = Arc::clone(&store);
                    runtime.spawn(async move {
                        match command {
                            Command::Initialize(request, response) => {
                                let _ = response.send(store.initialize(request).await);
                            }
                            Command::Read(response) => {
                                let _ = response.send(store.read().await);
                            }
                            Command::Mutate(request, response) => {
                                let _ = response.send(store.mutate(request).await);
                            }
                            Command::Pending(limit, response) => {
                                let _ = response.send(store.pending_audits(limit).await);
                            }
                            Command::Ack(ack, response) => {
                                let _ = response.send(store.ack_audit(ack).await);
                            }
                            Command::Prune(response) => {
                                let _ = response.send(store.prune_receipts().await);
                            }
                            Command::Drain(_) => {
                                unreachable!("drain is handled by the owning actor")
                            }
                        }
                        drop(permit);
                    });
                }
                // Already admitted commands remain owned even if the final caller drops its sender.
                let total = u32::try_from(config.max_in_flight()).unwrap_or_default();
                let _ = runtime.block_on(permits.acquire_many_owned(total));
            })
            .map_err(|_| SafetyAuthorityError::ActorSpawn)?;
        Ok(Self {
            sender,
            query_timeout: config.query_timeout(),
            mutation_timeout: config.mutation_timeout(),
        })
    }
    fn request<T>(
        &self,
        timeout: Duration,
        command: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, SafetyAuthorityError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(command(sender))
            .map_err(|error| match error {
                TrySendError::Full(_) => SafetyAuthorityError::QueueFull,
                TrySendError::Disconnected(_) => SafetyAuthorityError::ActorDisconnected,
            })?;
        receiver
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => SafetyAuthorityError::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => SafetyAuthorityError::ActorDisconnected,
            })?
    }
    pub fn initialize(
        &self,
        request: SafetyInitializeRequest,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError> {
        self.request(self.mutation_timeout, |reply| {
            Command::Initialize(request, reply)
        })
    }
    pub fn read(&self) -> Result<SafetyAuthoritySnapshot, SafetyAuthorityError> {
        self.request(self.query_timeout, Command::Read)
    }
    pub fn mutate(
        &self,
        request: SafetyMutationRequest,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError> {
        self.request(self.mutation_timeout, |reply| {
            Command::Mutate(request, reply)
        })
    }
    pub fn pending_audits(
        &self,
        limit: usize,
    ) -> Result<Vec<SafetyAuditIntent>, SafetyAuthorityError> {
        self.request(self.query_timeout, |reply| Command::Pending(limit, reply))
    }
    pub fn ack_audit(&self, ack: SafetyAuditAck) -> Result<(), SafetyAuthorityError> {
        self.request(self.mutation_timeout, |reply| Command::Ack(ack, reply))
    }
    pub fn prune_receipts(&self) -> Result<usize, SafetyAuthorityError> {
        self.request(self.mutation_timeout, Command::Prune)
    }
    pub fn drain(&self) -> Result<(), SafetyAuthorityError> {
        self.request(self.mutation_timeout, Command::Drain)
    }
}
