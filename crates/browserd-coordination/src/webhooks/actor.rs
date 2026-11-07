use super::*;
use crate::CoordinationActorConfig;
use std::sync::{
    Arc,
    mpsc::{self, SyncSender},
};

enum Command {
    Put(
        Box<WebhookPutRequest>,
        SyncSender<Result<WebhookEndpointSnapshot, Error>>,
    ),
    Get(
        TenantId,
        SyncSender<Result<Option<WebhookEndpointSnapshot>, Error>>,
    ),
    Delete(
        WebhookEndpointRef,
        WebhookMutationBinding,
        SyncSender<Result<WebhookEndpointSnapshot, Error>>,
    ),
    Suspend(
        WebhookEndpointRef,
        WebhookMutationBinding,
        SyncSender<Result<WebhookEndpointSnapshot, Error>>,
    ),
    Resume(
        WebhookEndpointRef,
        WebhookMutationBinding,
        WebhookResumeMode,
        SyncSender<Result<WebhookEndpointSnapshot, Error>>,
    ),
    Claim(
        WebhookDeliveryCursor,
        usize,
        usize,
        Duration,
        SyncSender<Result<WebhookAttemptPage, Error>>,
    ),
    Finish(
        Box<WebhookAttemptLease>,
        WebhookAttemptOutcome,
        SyncSender<Result<WebhookAttemptResult, Error>>,
    ),
    Maintain(
        WebhookDeliveryCursor,
        usize,
        SyncSender<Result<WebhookMaintenancePage, Error>>,
    ),
}
impl Command {
    async fn run(self, store: &dyn WebhookStore) {
        match self {
            Self::Put(request, response) => {
                let _ = response.send(store.put_endpoint(*request).await);
            }
            Self::Get(tenant, response) => {
                let _ = response.send(store.get_endpoint(&tenant).await);
            }
            Self::Delete(expected, binding, response) => {
                let _ = response.send(store.delete_endpoint(&expected, binding).await);
            }
            Self::Suspend(expected, binding, response) => {
                let _ = response.send(store.suspend_endpoint(&expected, binding).await);
            }
            Self::Resume(expected, binding, mode, response) => {
                let _ = response.send(store.resume_endpoint(&expected, binding, mode).await);
            }
            Self::Claim(cursor, limit, max, ttl, response) => {
                let _ = response.send(store.claim_due_attempts(cursor, limit, max, ttl).await);
            }
            Self::Finish(lease, outcome, response) => {
                let _ = response.send(store.finish_attempt(&lease, outcome).await);
            }
            Self::Maintain(cursor, limit, response) => {
                let _ = response.send(store.maintain(cursor, limit).await);
            }
        }
    }
}
#[derive(Clone)]
pub struct WebhookBlockingClient {
    sender: SyncSender<Command>,
    query_timeout: Duration,
    mutation_timeout: Duration,
}
impl WebhookBlockingClient {
    pub fn spawn(
        store: Arc<dyn WebhookStore>,
        config: CoordinationActorConfig,
    ) -> Result<Self, Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.max_in_flight())
            .enable_all()
            .build()
            .map_err(|_| Error::Unavailable)?;
        let (sender, receiver) = mpsc::sync_channel::<Command>(config.queue_capacity());
        let permits = Arc::new(tokio::sync::Semaphore::new(config.max_in_flight()));
        let count =
            u32::try_from(config.max_in_flight()).map_err(|_| Error::InvalidConfiguration)?;
        std::thread::Builder::new()
            .name("browserd-webhooks".into())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    let Ok(permit) = runtime.block_on(permits.clone().acquire_owned()) else {
                        break;
                    };
                    let store = store.clone();
                    runtime.spawn(async move {
                        command.run(store.as_ref()).await;
                        drop(permit);
                    });
                }
                // Drain admitted jobs before dropping the runtime, including after caller disconnect.
                if let Ok(held) = runtime.block_on(permits.acquire_many_owned(count)) {
                    drop(held);
                }
            })
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            sender,
            query_timeout: config.query_timeout(),
            mutation_timeout: config.mutation_timeout(),
        })
    }
    fn submit<T>(
        &self,
        mutation: bool,
        build: impl FnOnce(SyncSender<Result<T, Error>>) -> Command,
    ) -> Result<T, Error> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.sender.try_send(build(response)).map_err(|e| match e {
            mpsc::TrySendError::Full(_) => Error::Busy,
            mpsc::TrySendError::Disconnected(_) => Error::Unavailable,
        })?;
        receiver
            .recv_timeout(if mutation {
                self.mutation_timeout
            } else {
                self.query_timeout
            })
            .map_err(|e| match e {
                mpsc::RecvTimeoutError::Timeout if mutation => Error::MutationTimeout,
                mpsc::RecvTimeoutError::Timeout => Error::QueryTimeout,
                mpsc::RecvTimeoutError::Disconnected => Error::Unavailable,
            })?
    }
    pub fn put_endpoint(
        &self,
        request: WebhookPutRequest,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        self.submit(true, |r| Command::Put(Box::new(request), r))
    }
    pub fn get_endpoint(
        &self,
        tenant: &TenantId,
    ) -> Result<Option<WebhookEndpointSnapshot>, Error> {
        self.submit(false, |r| Command::Get(tenant.clone(), r))
    }
    pub fn delete_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        self.submit(true, |r| Command::Delete(expected.clone(), binding, r))
    }
    pub fn suspend_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        self.submit(true, |r| Command::Suspend(expected.clone(), binding, r))
    }
    pub fn resume_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
        mode: WebhookResumeMode,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        self.submit(true, |r| {
            Command::Resume(expected.clone(), binding, mode, r)
        })
    }
    pub fn claim_due_attempts(
        &self,
        cursor: WebhookDeliveryCursor,
        limit: usize,
        max_attempts: usize,
        ttl: Duration,
    ) -> Result<WebhookAttemptPage, Error> {
        self.submit(true, |r| {
            Command::Claim(cursor, limit, max_attempts, ttl, r)
        })
    }
    pub fn finish_attempt(
        &self,
        lease: &WebhookAttemptLease,
        outcome: WebhookAttemptOutcome,
    ) -> Result<WebhookAttemptResult, Error> {
        self.submit(true, |r| {
            Command::Finish(Box::new(lease.clone()), outcome, r)
        })
    }
    pub fn maintain(
        &self,
        cursor: WebhookDeliveryCursor,
        limit: usize,
    ) -> Result<WebhookMaintenancePage, Error> {
        self.submit(true, |r| Command::Maintain(cursor, limit, r))
    }
}
