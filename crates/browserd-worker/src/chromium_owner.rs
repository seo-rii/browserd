use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc as std_mpsc};
use std::time::Duration;

use async_trait::async_trait;
use browserd_cdp::{CdpClient, CdpCommandError, CdpIncoming};
use browserd_chromium::{
    ChromiumArtifactIdentity, ChromiumConnection, ChromiumConnectionConfig,
    ChromiumConnectionError, VerifiedChromiumDriverOwner,
};
use browserd_core::{IsolationProfile, PageId, SessionId, ShardFence, TenantId};
use browserd_sandbox::ChromiumCdpPipes;
use browserd_session::OwnershipFence;
use browserd_targets::{
    BootstrapBackend, BootstrapStage, BootstrapStageFailure, PausedTarget, ShardTaintReason,
    TargetKind,
};
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::cdp_driver::CdpChromiumDriver;
use crate::{
    CdpPipeAcceptor, ProductionTargetManager, ShardRuntimeError, TargetBootstrapSnapshot,
    TargetManagerBackend, TargetManagerDrain, TargetManagerEvent, TargetManagerIngress,
    target_manager::TargetReadiness,
};

const MAX_CDP_IDENTIFIER_BYTES: usize = 1_024;
const MAX_OWNER_COMMAND_CAPACITY: usize = 1_024;
const MAX_CONTEXTS_PER_SHARD: usize = 1_024;
const MAX_PAGES_PER_CONTEXT: usize = 256;
const MAX_CLOSED_PAGE_TOMBSTONES: usize = 4_096;
const MAX_RETIRED_TARGETS: usize = 4_096;

/// The immutable flattened CDP route for one attached target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChromiumTargetRoute {
    session_id: String,
    browser_context_id: String,
    tenant_id: TenantId,
    owner_session_id: SessionId,
    ownership_fence: OwnershipFence,
}

impl ChromiumTargetRoute {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn browser_context_id(&self) -> &str {
        &self.browser_context_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn owner_session_id(&self) -> &SessionId {
        &self.owner_session_id
    }

    #[must_use]
    pub const fn ownership_fence(&self) -> &OwnershipFence {
        &self.ownership_fence
    }
}

/// Synchronous TargetManager facade backed by the one Chromium owner actor.
#[derive(Clone)]
pub struct ChromiumTargetManagerBackend {
    mailbox: Arc<OwnerMailbox>,
    readiness: Arc<OnceLock<TargetReadiness>>,
    target_ready_timeout: Duration,
}

pub type ChromiumTargetManager<D> = ProductionTargetManager<ChromiumTargetManagerBackend, D>;

impl ChromiumTargetManagerBackend {
    pub(crate) fn qualify(&self) -> Result<(), OwnerActorError> {
        self.mailbox
            .request(|response| OwnerRequest::Health { response })
    }

    pub fn target_route(
        &self,
        target_id: &str,
    ) -> Result<Option<ChromiumTargetRoute>, ShardRuntimeError> {
        if !valid_identifier(target_id) {
            return Err(ShardRuntimeError::Rejected);
        }
        self.mailbox
            .request(|response| OwnerRequest::TargetRoute {
                target_id: target_id.to_owned(),
                response,
            })
            .map_err(map_actor_runtime_error)
    }

    pub(crate) fn create_context_owned(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        fence: OwnershipFence,
    ) -> Result<PageId, OwnerActorError> {
        let created = self
            .mailbox
            .request(|response| OwnerRequest::CreateContext {
                tenant_id,
                session_id,
                fence,
                response,
            })?;
        self.wait_until_target_ready(&created.target_id)?;
        Ok(created.page_id)
    }

    pub(crate) fn dispose_context(
        &self,
        session_id: SessionId,
        fence: OwnershipFence,
    ) -> Result<(), OwnerActorError> {
        self.mailbox
            .request(|response| OwnerRequest::DisposeContext {
                session_id,
                fence,
                response,
            })
    }

    pub(crate) fn create_page(&self, session_id: SessionId) -> Result<PageId, OwnerActorError> {
        let created = self.mailbox.request(|response| OwnerRequest::CreatePage {
            session_id,
            response,
        })?;
        self.wait_until_target_ready(&created.target_id)?;
        Ok(created.page_id)
    }

    pub(crate) fn list_pages_owned(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        fence: OwnershipFence,
    ) -> Result<Vec<PageId>, OwnerActorError> {
        self.mailbox.request(|response| OwnerRequest::ListPages {
            tenant_id,
            session_id,
            fence,
            response,
        })
    }

    pub(crate) fn close_page(
        &self,
        session_id: SessionId,
        page_id: PageId,
    ) -> Result<(), OwnerActorError> {
        self.mailbox.request(|response| OwnerRequest::ClosePage {
            session_id,
            page_id,
            response,
        })
    }

    pub(crate) fn activate_page(
        &self,
        session_id: SessionId,
        page_id: PageId,
    ) -> Result<(), OwnerActorError> {
        self.mailbox.request(|response| OwnerRequest::ActivatePage {
            session_id,
            page_id,
            response,
        })
    }

    pub(crate) fn execute_page_command(
        &self,
        session_id: SessionId,
        page_id: PageId,
        command: PageCommand,
        execution_fence: Option<PageExecutionFence>,
    ) -> Result<Value, OwnerActorError> {
        self.mailbox
            .request(|response| OwnerRequest::ExecutePageCommand {
                session_id,
                page_id,
                command,
                execution_fence,
                response,
            })
    }

    pub(crate) fn observe_page(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
    ) -> Result<ObservedPage, OwnerActorError> {
        self.mailbox.request(|response| OwnerRequest::ObservePage {
            tenant_id,
            session_id,
            session_incarnation,
            page_id,
            response,
        })
    }

    pub(crate) fn validate_session(&self, session_id: SessionId) -> Result<(), OwnerActorError> {
        self.mailbox
            .request(|response| OwnerRequest::ValidateSession {
                session_id,
                response,
            })
    }

    fn wait_until_target_ready(&self, target_id: &str) -> Result<(), OwnerActorError> {
        self.readiness
            .get()
            .ok_or(OwnerActorError::Unavailable)?
            .wait_until_ready(target_id, self.target_ready_timeout)
            .map_err(|_| {
                self.mailbox.mark_terminal();
                self.mailbox.fail_closed();
                OwnerActorError::OutcomeUncertain
            })
    }
}

impl BootstrapBackend for ChromiumTargetManagerBackend {
    fn run_stage(
        &mut self,
        target: &PausedTarget,
        stage: BootstrapStage,
    ) -> Result<(), BootstrapStageFailure> {
        self.mailbox
            .request(|response| OwnerRequest::RunStage {
                target: target.clone(),
                stage,
                response,
            })
            .map_err(map_actor_stage_error)
    }

    fn close_paused_target(&mut self, target: &PausedTarget) {
        let result = self.mailbox.request(|response| OwnerRequest::CloseTarget {
            target_id: target.target_id().to_owned(),
            response,
        });
        if result.is_err() {
            self.mailbox.fail_closed();
        }
    }

    fn taint_shard(&mut self, _reason: ShardTaintReason) {
        self.mailbox.fail_closed();
    }
}

impl TargetManagerBackend for ChromiumTargetManagerBackend {
    fn enable_auto_attach_and_snapshot(
        &mut self,
    ) -> Result<TargetBootstrapSnapshot, ShardRuntimeError> {
        self.mailbox
            .request(|response| OwnerRequest::EnableAutoAttachAndSnapshot { response })
            .map_err(map_actor_runtime_error)
    }
}

/// Exactly-once owner of the verified CDP reader/writer and its bounded command/event actor.
pub struct ChromiumConnectionOwner<D> {
    expected: ChromiumArtifactIdentity,
    config: ChromiumConnectionConfig,
    ingress: Arc<TargetManagerIngress<D>>,
    mailbox: Arc<OwnerMailbox>,
    readiness: Arc<OnceLock<TargetReadiness>>,
    target_ready_timeout: Duration,
    shard_fence: ShardFence,
    driver_effect_gate: Arc<Mutex<()>>,
    accepted: AtomicBool,
    shutdown_started: AtomicBool,
    thread: Arc<OwnerThreadControl>,
}

struct OwnerThreadControl {
    completion: watch::Sender<Option<Result<(), ShardRuntimeError>>>,
    join: Mutex<OwnerJoinState>,
    shutdown: CancellationToken,
}

struct OwnerJoinState {
    handle: Option<std::thread::JoinHandle<()>>,
    result: Option<Result<(), ShardRuntimeError>>,
}

impl<D: TargetManagerDrain> ChromiumConnectionOwner<D> {
    /// Constructs the mutually dependent CDP owner and TargetManager around one bounded ingress.
    pub fn new_bounded(
        expected: ChromiumArtifactIdentity,
        config: ChromiumConnectionConfig,
        fence: ShardFence,
        event_capacity: usize,
        drain: Arc<D>,
    ) -> Result<(Arc<Self>, Arc<ChromiumTargetManager<D>>), ShardRuntimeError> {
        if !config.is_valid() {
            return Err(ShardRuntimeError::Rejected);
        }
        let command_capacity = config.transport.command_queue_capacity;
        if command_capacity == 0 || command_capacity > MAX_OWNER_COMMAND_CAPACITY {
            return Err(ShardRuntimeError::Rejected);
        }
        let request_timeout = config
            .transport
            .default_command_timeout
            .checked_mul(4)
            .unwrap_or(Duration::MAX)
            .saturating_add(Duration::from_millis(100));
        let target_ready_timeout = config
            .transport
            .default_command_timeout
            .checked_mul(8)
            .unwrap_or(Duration::MAX)
            .saturating_add(Duration::from_millis(100));
        let mailbox = Arc::new(OwnerMailbox::new(request_timeout));
        let readiness = Arc::new(OnceLock::new());
        let backend = ChromiumTargetManagerBackend {
            mailbox: mailbox.clone(),
            readiness: readiness.clone(),
            target_ready_timeout,
        };
        let (manager, ingress) =
            ProductionTargetManager::new_bounded(fence.clone(), backend, event_capacity, drain)?;
        readiness
            .set(manager.readiness())
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        let ingress = Arc::new(ingress);
        mailbox.bind_failure_sink(Arc::new(IngressFailure {
            ingress: ingress.clone(),
        }))?;
        let (completion, _completion_receiver) = watch::channel(None);
        let owner = Arc::new(Self {
            expected,
            config,
            ingress,
            mailbox,
            readiness,
            target_ready_timeout,
            shard_fence: fence,
            driver_effect_gate: Arc::new(Mutex::new(())),
            accepted: AtomicBool::new(false),
            shutdown_started: AtomicBool::new(false),
            thread: Arc::new(OwnerThreadControl {
                completion,
                join: Mutex::new(OwnerJoinState {
                    handle: None,
                    result: None,
                }),
                shutdown: CancellationToken::new(),
            }),
        });
        Ok((owner, Arc::new(manager)))
    }

    #[must_use]
    pub fn target_manager_backend(&self) -> ChromiumTargetManagerBackend {
        ChromiumTargetManagerBackend {
            mailbox: self.mailbox.clone(),
            readiness: self.readiness.clone(),
            target_ready_timeout: self.target_ready_timeout,
        }
    }

    #[must_use]
    pub fn chromium_driver(&self, isolation: IsolationProfile) -> CdpChromiumDriver {
        CdpChromiumDriver::new(
            self.target_manager_backend(),
            self.driver_effect_gate.clone(),
            self.expected.product_version.clone(),
            isolation,
        )
    }

    pub async fn shutdown_and_join(&self, timeout: Duration) -> Result<(), ShardRuntimeError> {
        if timeout.is_zero() {
            return Err(ShardRuntimeError::Rejected);
        }
        self.thread.shutdown.cancel();
        if self
            .shutdown_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let _ = self.mailbox.begin_shutdown();
        }
        let mut completion = self.thread.completion.subscribe();
        let thread_result = tokio::time::timeout(timeout, async {
            loop {
                if let Some(result) = *completion.borrow() {
                    break result;
                }
                completion
                    .changed()
                    .await
                    .map_err(|_| ShardRuntimeError::OutcomeUncertain)?;
            }
        })
        .await
        .map_err(|_| ShardRuntimeError::OutcomeUncertain)?;
        let mut join = self
            .thread
            .join
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        if let Some(result) = join.result {
            return result;
        }
        let handle = join
            .handle
            .take()
            .ok_or(ShardRuntimeError::OutcomeUncertain)?;
        let join_result = handle
            .join()
            .map_err(|_| ShardRuntimeError::OutcomeUncertain);
        let result = thread_result.and(join_result);
        join.result = Some(result);
        result
    }
}

#[async_trait]
impl<D: TargetManagerDrain> CdpPipeAcceptor for ChromiumConnectionOwner<D> {
    async fn accept_cdp_pipes(&self, pipes: ChromiumCdpPipes) -> Result<(), ShardRuntimeError> {
        if self
            .accepted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ShardRuntimeError::Rejected);
        }

        let expected = self.expected.clone();
        let config = self.config.clone();
        let command_capacity = config.transport.command_queue_capacity;
        let ingress = self.ingress.clone();
        let mailbox = Arc::downgrade(&self.mailbox);
        let shard_fence = self.shard_fence.clone();
        let shutdown = self.thread.shutdown.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let completion = self.thread.completion.clone();
        let thread = std::thread::Builder::new()
            .name("browserd-chromium-owner".to_owned())
            .spawn(move || {
                let input = OwnerThreadInput {
                    pipes,
                    expected,
                    config,
                    command_capacity,
                    ingress,
                    mailbox,
                    shard_fence,
                    ready: ready_tx,
                    shutdown,
                };
                let result = catch_unwind(AssertUnwindSafe(|| run_owner_thread(input)))
                    .unwrap_or(Err(ShardRuntimeError::OutcomeUncertain));
                completion.send_replace(Some(result));
            });
        let thread = match thread {
            Ok(thread) => thread,
            Err(_) => {
                self.mailbox.mark_terminal();
                self.ingress.fail_closed(TargetManagerEvent::TransportLost);
                return Err(ShardRuntimeError::Unavailable);
            }
        };
        self.thread
            .join
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .handle = Some(thread);
        match ready_rx.await {
            Ok(result) => result,
            Err(_) => {
                self.mailbox.mark_terminal();
                self.ingress.fail_closed(TargetManagerEvent::TransportLost);
                Err(ShardRuntimeError::OutcomeUncertain)
            }
        }
    }
}

struct OwnerThreadInput<D> {
    pipes: ChromiumCdpPipes,
    expected: ChromiumArtifactIdentity,
    config: ChromiumConnectionConfig,
    command_capacity: usize,
    ingress: Arc<TargetManagerIngress<D>>,
    mailbox: Weak<OwnerMailbox>,
    shard_fence: ShardFence,
    ready: oneshot::Sender<Result<(), ShardRuntimeError>>,
    shutdown: CancellationToken,
}

fn run_owner_thread<D: TargetManagerDrain>(
    input: OwnerThreadInput<D>,
) -> Result<(), ShardRuntimeError> {
    let OwnerThreadInput {
        pipes,
        expected,
        config,
        command_capacity,
        ingress,
        mailbox,
        shard_fence,
        ready,
        shutdown,
    } = input;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        if let Some(mailbox) = mailbox.upgrade() {
            mailbox.mark_terminal();
            mailbox.fail_closed();
        }
        let _ignored = ready.send(Err(ShardRuntimeError::Unavailable));
        return Err(ShardRuntimeError::Unavailable);
    };
    runtime.block_on(async move {
        let connection = ChromiumConnection::connect(pipes, &expected, config.clone()).await;
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                if let Some(mailbox) = mailbox.upgrade() {
                    mailbox.mark_terminal();
                    mailbox.fail_closed();
                }
                let error = map_connection_error(error);
                let _ignored = ready.send(Err(error));
                return Err(error);
            }
        };
        let (client, events, driver) = connection.into_verified_parts();
        let (commands, receiver) = mpsc::channel(command_capacity);
        let Some(mailbox_handle) = mailbox.upgrade() else {
            let _ignored = ready.send(Err(ShardRuntimeError::Cancelled));
            driver.shutdown().await;
            return Err(ShardRuntimeError::Cancelled);
        };
        if mailbox_handle.install(commands).is_err() {
            mailbox_handle.mark_terminal();
            mailbox_handle.fail_closed();
            let _ignored = ready.send(Err(ShardRuntimeError::Rejected));
            driver.shutdown().await;
            return Err(ShardRuntimeError::Rejected);
        }
        drop(mailbox_handle);
        if ready.send(Ok(())).is_err() {
            if let Some(mailbox) = mailbox.upgrade() {
                mailbox.mark_terminal();
                mailbox.fail_closed();
            }
            driver.shutdown().await;
            return Err(ShardRuntimeError::Cancelled);
        }
        ChromiumOwnerActor::new(
            client,
            events,
            driver,
            ingress,
            mailbox,
            shard_fence,
            config.transport.default_command_timeout,
        )
        .run(receiver, shutdown)
        .await
    })
}

trait FailureSink: Send + Sync {
    fn fail_closed(&self);
}

struct IngressFailure<D> {
    ingress: Arc<TargetManagerIngress<D>>,
}

impl<D: TargetManagerDrain> FailureSink for IngressFailure<D> {
    fn fail_closed(&self) {
        self.ingress.fail_closed(TargetManagerEvent::TransportLost);
    }
}

enum OwnerEndpoint {
    Pending,
    Ready(mpsc::Sender<OwnerRequest>),
    Terminal,
}

struct OwnerMailbox {
    endpoint: Mutex<OwnerEndpoint>,
    failure: Mutex<Option<Arc<dyn FailureSink>>>,
    request_timeout: Duration,
}

impl OwnerMailbox {
    fn new(request_timeout: Duration) -> Self {
        Self {
            endpoint: Mutex::new(OwnerEndpoint::Pending),
            failure: Mutex::new(None),
            request_timeout,
        }
    }

    fn bind_failure_sink(&self, sink: Arc<dyn FailureSink>) -> Result<(), ShardRuntimeError> {
        let mut failure = self
            .failure
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        if failure.is_some() {
            return Err(ShardRuntimeError::Rejected);
        }
        *failure = Some(sink);
        Ok(())
    }

    fn install(&self, sender: mpsc::Sender<OwnerRequest>) -> Result<(), OwnerActorError> {
        let mut endpoint = self
            .endpoint
            .lock()
            .map_err(|_| OwnerActorError::Unavailable)?;
        if !matches!(*endpoint, OwnerEndpoint::Pending) {
            return Err(OwnerActorError::Rejected);
        }
        *endpoint = OwnerEndpoint::Ready(sender);
        Ok(())
    }

    fn mark_terminal(&self) {
        if let Ok(mut endpoint) = self.endpoint.lock() {
            *endpoint = OwnerEndpoint::Terminal;
        }
    }

    fn begin_shutdown(&self) -> Result<(), ShardRuntimeError> {
        let mut endpoint = self
            .endpoint
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        let sender = match &*endpoint {
            OwnerEndpoint::Ready(sender) => sender.clone(),
            OwnerEndpoint::Pending => return Err(ShardRuntimeError::Unavailable),
            OwnerEndpoint::Terminal => return Ok(()),
        };
        let result = sender
            .try_send(OwnerRequest::Shutdown)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ShardRuntimeError::OutcomeUncertain,
                mpsc::error::TrySendError::Closed(_) => ShardRuntimeError::OutcomeUncertain,
            });
        *endpoint = OwnerEndpoint::Terminal;
        drop(endpoint);
        if result.is_err() {
            self.fail_closed();
        }
        result
    }

    fn fail_closed(&self) {
        if let Ok(failure) = self.failure.lock()
            && let Some(failure) = failure.as_ref()
        {
            failure.fail_closed();
        }
    }

    fn request<T>(
        &self,
        build: impl FnOnce(std_mpsc::SyncSender<Result<T, OwnerActorError>>) -> OwnerRequest,
    ) -> Result<T, OwnerActorError> {
        let sender = {
            let endpoint = self
                .endpoint
                .lock()
                .map_err(|_| OwnerActorError::Unavailable)?;
            match &*endpoint {
                OwnerEndpoint::Ready(sender) => sender.clone(),
                OwnerEndpoint::Pending => return Err(OwnerActorError::Unavailable),
                OwnerEndpoint::Terminal => return Err(OwnerActorError::OutcomeUncertain),
            }
        };
        let (response, receiver) = std_mpsc::sync_channel(1);
        match sender.try_send(build(response)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.mark_terminal();
                self.fail_closed();
                return Err(OwnerActorError::StateOverflow);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.mark_terminal();
                self.fail_closed();
                return Err(OwnerActorError::OutcomeUncertain);
            }
        }
        receiver.recv_timeout(self.request_timeout).map_err(|_| {
            self.mark_terminal();
            self.fail_closed();
            OwnerActorError::OutcomeUncertain
        })?
    }
}

enum OwnerRequest {
    Shutdown,
    Health {
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
    },
    EnableAutoAttachAndSnapshot {
        response: std_mpsc::SyncSender<Result<TargetBootstrapSnapshot, OwnerActorError>>,
    },
    RunStage {
        target: PausedTarget,
        stage: BootstrapStage,
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
    },
    CloseTarget {
        target_id: String,
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
    },
    TargetRoute {
        target_id: String,
        response: std_mpsc::SyncSender<Result<Option<ChromiumTargetRoute>, OwnerActorError>>,
    },
    CreateContext {
        tenant_id: TenantId,
        session_id: SessionId,
        fence: OwnershipFence,
        response: std_mpsc::SyncSender<Result<CreatedPage, OwnerActorError>>,
    },
    DisposeContext {
        session_id: SessionId,
        fence: OwnershipFence,
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
    },
    CreatePage {
        session_id: SessionId,
        response: std_mpsc::SyncSender<Result<CreatedPage, OwnerActorError>>,
    },
    ListPages {
        tenant_id: TenantId,
        session_id: SessionId,
        fence: OwnershipFence,
        response: std_mpsc::SyncSender<Result<Vec<PageId>, OwnerActorError>>,
    },
    ClosePage {
        session_id: SessionId,
        page_id: PageId,
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
    },
    ActivatePage {
        session_id: SessionId,
        page_id: PageId,
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
    },
    ExecutePageCommand {
        session_id: SessionId,
        page_id: PageId,
        command: PageCommand,
        execution_fence: Option<PageExecutionFence>,
        response: std_mpsc::SyncSender<Result<Value, OwnerActorError>>,
    },
    ObservePage {
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
        response: std_mpsc::SyncSender<Result<ObservedPage, OwnerActorError>>,
    },
    ValidateSession {
        session_id: SessionId,
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerActorError {
    Rejected,
    UnknownOwnership,
    StateOverflow,
    Unavailable,
    OutcomeUncertain,
}

#[derive(Clone, Debug)]
struct CreatedPage {
    page_id: PageId,
    target_id: String,
}

#[derive(Clone, Debug)]
pub(crate) enum PageCommand {
    Navigate { url: String },
    Reload,
    Click { x: f64, y: f64 },
    InsertText { text: String },
    ReadUrl,
    ReadTitle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedPage {
    pub(crate) tenant_id: TenantId,
    pub(crate) session_id: SessionId,
    pub(crate) session_incarnation: u64,
    pub(crate) target_incarnation: u64,
    pub(crate) frame_document_epoch: u64,
    pub(crate) url_revision: u64,
    pub(crate) origin: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageExecutionFence {
    pub(crate) target_incarnation: u64,
    pub(crate) frame_document_epoch: u64,
    pub(crate) url_revision: u64,
}

#[derive(Clone)]
struct GuardedPageExecution {
    target_id: String,
    fence: PageExecutionFence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContextOwnership {
    tenant_id: TenantId,
    session_id: SessionId,
    fence: OwnershipFence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextLifecycle {
    Active,
    Disposing,
}

struct ContextEntry {
    ownership: ContextOwnership,
    lifecycle: ContextLifecycle,
    pages: BTreeMap<PageId, String>,
    closing_pages: BTreeSet<PageId>,
}

#[derive(Clone)]
struct PendingPage {
    context_id: String,
    page_id: PageId,
}

#[derive(Clone)]
struct TargetRouteEntry {
    route: ChromiumTargetRoute,
    kind: TargetKind,
    page_id: Option<PageId>,
    target_incarnation: u64,
    frame_document_epoch: u64,
    url_revision: u64,
}

struct ChromiumOwnerActor<D> {
    client: CdpClient,
    events: mpsc::Receiver<CdpIncoming>,
    driver: VerifiedChromiumDriverOwner,
    ingress: Arc<TargetManagerIngress<D>>,
    mailbox: Weak<OwnerMailbox>,
    shard_fence: ShardFence,
    command_timeout: Duration,
    routes: BTreeMap<String, TargetRouteEntry>,
    contexts: BTreeMap<String, ContextEntry>,
    context_by_session: BTreeMap<SessionId, String>,
    pending_pages: BTreeMap<String, PendingPage>,
    closed_page_tombstones: BTreeMap<PageId, SessionId>,
    retired_targets: BTreeSet<String>,
    next_target_incarnation: u64,
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    fn new(
        client: CdpClient,
        events: mpsc::Receiver<CdpIncoming>,
        driver: VerifiedChromiumDriverOwner,
        ingress: Arc<TargetManagerIngress<D>>,
        mailbox: Weak<OwnerMailbox>,
        shard_fence: ShardFence,
        command_timeout: Duration,
    ) -> Self {
        Self {
            client,
            events,
            driver,
            ingress,
            mailbox,
            shard_fence,
            command_timeout,
            routes: BTreeMap::new(),
            contexts: BTreeMap::new(),
            context_by_session: BTreeMap::new(),
            pending_pages: BTreeMap::new(),
            closed_page_tombstones: BTreeMap::new(),
            retired_targets: BTreeSet::new(),
            next_target_incarnation: 1,
        }
    }

    async fn run(
        mut self,
        mut requests: mpsc::Receiver<OwnerRequest>,
        shutdown: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        let mut failed = false;
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                incoming = self.events.recv() => {
                    match incoming {
                        Some(incoming) => {
                            if self.handle_incoming(incoming, None).is_err() {
                                failed = true;
                                break;
                            }
                        }
                        None => {
                            failed = true;
                            break;
                        }
                    }
                }
                request = requests.recv() => {
                    let Some(request) = request else {
                        break;
                    };
                    match request {
                        OwnerRequest::Shutdown => break,
                        request => {
                            if self.handle_request(request).await.is_err() {
                                failed = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if let Some(mailbox) = self.mailbox.upgrade() {
            mailbox.mark_terminal();
            if failed {
                mailbox.fail_closed();
            }
        }
        if failed {
            self.ingress.fail_closed(TargetManagerEvent::TransportLost);
        }
        self.driver.shutdown().await;
        if failed {
            Err(ShardRuntimeError::OutcomeUncertain)
        } else {
            Ok(())
        }
    }

    async fn handle_request(&mut self, request: OwnerRequest) -> Result<(), ()> {
        match request {
            OwnerRequest::Shutdown => return Ok(()),
            OwnerRequest::Health { response } => {
                if response.send(Ok(())).is_err() {
                    return Err(());
                }
            }
            OwnerRequest::EnableAutoAttachAndSnapshot { response } => {
                let result = self.enable_auto_attach_and_snapshot().await;
                let failed = result.is_err();
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::RunStage {
                target,
                stage,
                response,
            } => {
                let result = self.run_stage(&target, stage).await;
                let failed = matches!(
                    result,
                    Err(OwnerActorError::StateOverflow
                        | OwnerActorError::Unavailable
                        | OwnerActorError::OutcomeUncertain)
                );
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::CloseTarget {
                target_id,
                response,
            } => {
                let result = self.close_target(&target_id).await;
                let failed = result.is_err();
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::TargetRoute {
                target_id,
                response,
            } => {
                let result = Ok(self.routes.get(&target_id).map(|entry| entry.route.clone()));
                if response.send(result).is_err() {
                    return Err(());
                }
            }
            OwnerRequest::CreateContext {
                tenant_id,
                session_id,
                fence,
                response,
            } => {
                let result = self.create_context(tenant_id, session_id, fence).await;
                let failed = matches!(
                    result,
                    Err(OwnerActorError::StateOverflow
                        | OwnerActorError::Unavailable
                        | OwnerActorError::OutcomeUncertain)
                );
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::DisposeContext {
                session_id,
                fence,
                response,
            } => {
                let result = self.dispose_context(&session_id, &fence).await;
                let failed = matches!(
                    result,
                    Err(OwnerActorError::StateOverflow
                        | OwnerActorError::Unavailable
                        | OwnerActorError::OutcomeUncertain)
                );
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::CreatePage {
                session_id,
                response,
            } => {
                let result = self.create_page(&session_id).await;
                let failed = matches!(
                    result,
                    Err(OwnerActorError::StateOverflow
                        | OwnerActorError::Unavailable
                        | OwnerActorError::OutcomeUncertain)
                );
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::ListPages {
                tenant_id,
                session_id,
                fence,
                response,
            } => {
                let result = self.list_pages(&tenant_id, &session_id, &fence);
                if response.send(result).is_err() {
                    return Err(());
                }
            }
            OwnerRequest::ClosePage {
                session_id,
                page_id,
                response,
            } => {
                let result = self.close_page(&session_id, &page_id).await;
                let failed = matches!(
                    result,
                    Err(OwnerActorError::StateOverflow
                        | OwnerActorError::Unavailable
                        | OwnerActorError::OutcomeUncertain)
                );
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::ActivatePage {
                session_id,
                page_id,
                response,
            } => {
                let result = self.activate_page(&session_id, &page_id).await;
                let failed = matches!(
                    result,
                    Err(OwnerActorError::StateOverflow
                        | OwnerActorError::Unavailable
                        | OwnerActorError::OutcomeUncertain)
                );
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::ExecutePageCommand {
                session_id,
                page_id,
                command,
                execution_fence,
                response,
            } => {
                let result = self
                    .execute_page_command(&session_id, &page_id, command, execution_fence)
                    .await;
                let failed = matches!(
                    result,
                    Err(OwnerActorError::StateOverflow
                        | OwnerActorError::Unavailable
                        | OwnerActorError::OutcomeUncertain)
                );
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::ObservePage {
                tenant_id,
                session_id,
                session_incarnation,
                page_id,
                response,
            } => {
                let result = self
                    .observe_page(&tenant_id, &session_id, session_incarnation, &page_id)
                    .await;
                let failed = matches!(
                    result,
                    Err(OwnerActorError::StateOverflow
                        | OwnerActorError::Unavailable
                        | OwnerActorError::OutcomeUncertain)
                );
                if response.send(result).is_err() || failed {
                    return Err(());
                }
            }
            OwnerRequest::ValidateSession {
                session_id,
                response,
            } => {
                let result = self.active_context_for_session(&session_id).map(|_| ());
                if response.send(result).is_err() {
                    return Err(());
                }
            }
        }
        Ok(())
    }

    async fn enable_auto_attach_and_snapshot(
        &mut self,
    ) -> Result<TargetBootstrapSnapshot, OwnerActorError> {
        let mut catch_up = Vec::new();
        self.command_event_first(
            "Target.setAutoAttach",
            json!({
                "autoAttach": true,
                "waitForDebuggerOnStart": true,
                "flatten": true,
            }),
            None,
            Some(&mut catch_up),
            None,
        )
        .await?;
        self.command_event_first(
            "Target.setDiscoverTargets",
            json!({"discover": true}),
            None,
            Some(&mut catch_up),
            None,
        )
        .await?;
        let response = self
            .command_event_first(
                "Target.getTargets",
                json!({}),
                None,
                Some(&mut catch_up),
                None,
            )
            .await?;
        let target_infos = response
            .as_object()
            .and_then(|response| response.get("targetInfos"))
            .and_then(Value::as_array)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let mut initial_targets = Vec::with_capacity(target_infos.len());
        let mut initial_ids = BTreeSet::new();
        for target_info in target_infos {
            let (target, context_id) = parse_target_info(target_info)?;
            let context = self
                .contexts
                .get(&context_id)
                .ok_or(OwnerActorError::UnknownOwnership)?;
            if context.lifecycle != ContextLifecycle::Active {
                return Err(OwnerActorError::UnknownOwnership);
            }
            let route = self
                .routes
                .get(target.target_id())
                .ok_or(OwnerActorError::UnknownOwnership)?;
            if route.route.browser_context_id != context_id
                || route.route.owner_session_id != context.ownership.session_id
                || route.kind != *target.kind()
            {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            if initial_ids.insert(target.target_id().to_owned()) {
                initial_targets.push(target);
            }
        }
        let mut catch_up_ids = BTreeSet::new();
        catch_up.retain(|target| {
            !initial_ids.contains(target.target_id())
                && catch_up_ids.insert(target.target_id().to_owned())
        });
        TargetBootstrapSnapshot::new(initial_targets, catch_up)
            .map_err(|_| OwnerActorError::StateOverflow)
    }

    async fn run_stage(
        &mut self,
        target: &PausedTarget,
        stage: BootstrapStage,
    ) -> Result<(), OwnerActorError> {
        let route = self
            .routes
            .get(target.target_id())
            .cloned()
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if route.kind != *target.kind() {
            return Err(OwnerActorError::UnknownOwnership);
        }
        if stage == BootstrapStage::ValidateTargetType && !allowed_target_kind(target.kind()) {
            return Err(OwnerActorError::Rejected);
        }
        let command = stage_command(stage, target.kind());
        let Some((method, params)) = command else {
            return Ok(());
        };
        self.command_event_first(method, params, Some(route.route.session_id), None, None)
            .await
            .map(|_| ())
    }

    async fn close_target(&mut self, target_id: &str) -> Result<(), OwnerActorError> {
        if !valid_identifier(target_id) {
            return Err(OwnerActorError::Rejected);
        }
        let response = self
            .command_event_first(
                "Target.closeTarget",
                json!({"targetId": target_id}),
                None,
                None,
                None,
            )
            .await?;
        if response.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(())
    }

    async fn create_context(
        &mut self,
        tenant_id: TenantId,
        session_id: SessionId,
        fence: OwnershipFence,
    ) -> Result<CreatedPage, OwnerActorError> {
        if self.contexts.len() >= MAX_CONTEXTS_PER_SHARD
            || self.context_by_session.contains_key(&session_id)
            || fence.worker_id() != self.shard_fence.owner().worker_id()
            || fence.worker_epoch() != self.shard_fence.owner().worker_epoch().get()
            || fence.placement_version() == 0
            || fence.session_incarnation() == 0
        {
            return Err(OwnerActorError::Rejected);
        }
        let response = self
            .command_event_first(
                "Target.createBrowserContext",
                json!({"disposeOnDetach": true}),
                None,
                None,
                None,
            )
            .await?;
        let context_id = response
            .as_object()
            .ok_or(OwnerActorError::OutcomeUncertain)
            .and_then(|response| required_string(response, "browserContextId"))?;
        if self.contexts.contains_key(&context_id) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        if self
            .contexts
            .insert(
                context_id.clone(),
                ContextEntry {
                    ownership: ContextOwnership {
                        tenant_id,
                        session_id: session_id.clone(),
                        fence,
                    },
                    lifecycle: ContextLifecycle::Active,
                    pages: BTreeMap::new(),
                    closing_pages: BTreeSet::new(),
                },
            )
            .is_some()
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        if self
            .context_by_session
            .insert(session_id.clone(), context_id)
            .is_some()
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        self.create_page(&session_id).await
    }

    async fn dispose_context(
        &mut self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), OwnerActorError> {
        let context_id = self
            .context_by_session
            .get(session_id)
            .cloned()
            .ok_or(OwnerActorError::UnknownOwnership)?;
        let context = self
            .contexts
            .get(&context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if &context.ownership.fence != fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        if context.lifecycle == ContextLifecycle::Disposing {
            return Ok(());
        }
        self.command_event_first(
            "Target.disposeBrowserContext",
            json!({"browserContextId": context_id}),
            None,
            None,
            None,
        )
        .await?;
        self.contexts
            .get_mut(&context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .lifecycle = ContextLifecycle::Disposing;
        Ok(())
    }

    async fn create_page(
        &mut self,
        session_id: &SessionId,
    ) -> Result<CreatedPage, OwnerActorError> {
        let (context_id, page_count) = {
            let (context_id, context) = self.active_context_for_session(session_id)?;
            (context_id.to_owned(), context.pages.len())
        };
        if page_count >= MAX_PAGES_PER_CONTEXT {
            return Err(OwnerActorError::StateOverflow);
        }
        let response = self
            .command_event_first(
                "Target.createTarget",
                json!({
                    "url": "about:blank",
                    "browserContextId": context_id,
                    "background": false,
                }),
                None,
                None,
                None,
            )
            .await?;
        let target_id = response
            .as_object()
            .ok_or(OwnerActorError::OutcomeUncertain)
            .and_then(|response| required_string(response, "targetId"))?;
        if self.retired_targets.contains(&target_id) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        if let Some(route) = self.routes.get(&target_id) {
            if route.route.browser_context_id != context_id
                || route.route.owner_session_id != *session_id
                || route.kind != TargetKind::Page
            {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            let page_id = route
                .page_id
                .clone()
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            return Ok(CreatedPage { page_id, target_id });
        }
        if self.pending_pages.contains_key(&target_id) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let page_id = PageId::new();
        if self
            .pending_pages
            .insert(
                target_id.clone(),
                PendingPage {
                    context_id,
                    page_id: page_id.clone(),
                },
            )
            .is_some()
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(CreatedPage { page_id, target_id })
    }

    fn list_pages(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<Vec<PageId>, OwnerActorError> {
        let (_, context) = self.active_context_for_session(session_id)?;
        if &context.ownership.tenant_id != tenant_id || &context.ownership.fence != fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        Ok(context.pages.keys().cloned().collect())
    }

    async fn close_page(
        &mut self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), OwnerActorError> {
        if self
            .closed_page_tombstones
            .get(page_id)
            .is_some_and(|owner| owner == session_id)
        {
            return Ok(());
        }
        if self
            .active_context_for_session(session_id)?
            .1
            .closing_pages
            .contains(page_id)
        {
            return Ok(());
        }
        let (context_id, target_id, _) = self.owned_page_route(session_id, page_id)?;
        let context = self
            .contexts
            .get(&context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if context.lifecycle != ContextLifecycle::Active {
            return Err(OwnerActorError::Rejected);
        }
        let response = self
            .command_event_first(
                "Target.closeTarget",
                json!({"targetId": target_id}),
                None,
                None,
                None,
            )
            .await?;
        if response.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        if !self
            .contexts
            .get_mut(&context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .closing_pages
            .insert(page_id.clone())
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(())
    }

    async fn activate_page(
        &mut self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), OwnerActorError> {
        let (_, target_id, _) = self.owned_page_route(session_id, page_id)?;
        self.command_event_first(
            "Target.activateTarget",
            json!({"targetId": target_id}),
            None,
            None,
            None,
        )
        .await
        .map(|_| ())
    }

    async fn execute_page_command(
        &mut self,
        session_id: &SessionId,
        page_id: &PageId,
        command: PageCommand,
        execution_fence: Option<PageExecutionFence>,
    ) -> Result<Value, OwnerActorError> {
        let (_, target_id, route) = self.owned_page_route(session_id, page_id)?;
        let cdp_session_id = route.session_id().to_owned();
        let guarded = execution_fence.map(|fence| GuardedPageExecution { target_id, fence });
        match command {
            PageCommand::Navigate { url } => {
                let result = self
                    .command_event_first(
                        "Page.navigate",
                        json!({"url": url}),
                        Some(cdp_session_id),
                        None,
                        guarded,
                    )
                    .await?;
                if result
                    .get("errorText")
                    .and_then(Value::as_str)
                    .is_some_and(|error| !error.is_empty())
                {
                    return Err(OwnerActorError::Rejected);
                }
                Ok(result)
            }
            PageCommand::Reload => {
                self.command_event_first(
                    "Page.reload",
                    json!({}),
                    Some(cdp_session_id),
                    None,
                    guarded,
                )
                .await
            }
            PageCommand::Click { x, y } => {
                self.command_event_first(
                    "Input.dispatchMouseEvent",
                    json!({"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1}),
                    Some(cdp_session_id.clone()),
                    None,
                    guarded.clone(),
                )
                .await?;
                self.command_event_first(
                    "Input.dispatchMouseEvent",
                    json!({"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1}),
                    Some(cdp_session_id),
                    None,
                    guarded,
                )
                .await
                .map_err(|_| OwnerActorError::OutcomeUncertain)
            }
            PageCommand::InsertText { text } => {
                self.command_event_first(
                    "Input.insertText",
                    json!({"text": text}),
                    Some(cdp_session_id),
                    None,
                    guarded,
                )
                .await
            }
            PageCommand::ReadUrl => {
                self.command_event_first(
                    "Runtime.evaluate",
                    json!({"expression": "globalThis.location.href", "returnByValue": true, "awaitPromise": false}),
                    Some(cdp_session_id),
                    None,
                    guarded,
                )
                .await
            }
            PageCommand::ReadTitle => {
                self.command_event_first(
                    "Runtime.evaluate",
                    json!({"expression": "globalThis.document.title", "returnByValue": true, "awaitPromise": false}),
                    Some(cdp_session_id),
                    None,
                    guarded,
                )
                .await
            }
        }
    }

    async fn observe_page(
        &mut self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        session_incarnation: u64,
        page_id: &PageId,
    ) -> Result<ObservedPage, OwnerActorError> {
        let (_, target_id, route) = self.owned_page_route(session_id, page_id)?;
        if route.tenant_id() != tenant_id
            || route.ownership_fence().session_incarnation() != session_incarnation
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let response = self
            .command_event_first(
                "Runtime.evaluate",
                json!({
                    "expression": "globalThis.location.origin",
                    "returnByValue": true,
                    "awaitPromise": false,
                }),
                Some(route.session_id().to_owned()),
                None,
                None,
            )
            .await?;
        let origin = response
            .get("result")
            .and_then(|result| result.get("value"))
            .and_then(Value::as_str)
            .filter(|origin| origin.len() <= 8_192 && !origin.chars().any(char::is_control))
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .to_owned();
        let route = self
            .routes
            .get(&target_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if route.route.owner_session_id != *session_id {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(ObservedPage {
            tenant_id: route.route.tenant_id.clone(),
            session_id: route.route.owner_session_id.clone(),
            session_incarnation: route.route.ownership_fence.session_incarnation(),
            target_incarnation: route.target_incarnation,
            frame_document_epoch: route.frame_document_epoch,
            url_revision: route.url_revision,
            origin,
        })
    }

    fn active_context_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<(&str, &ContextEntry), OwnerActorError> {
        let context_id = self
            .context_by_session
            .get(session_id)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        let context = self
            .contexts
            .get(context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if context.lifecycle != ContextLifecycle::Active
            || context.ownership.session_id != *session_id
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        Ok((context_id, context))
    }

    fn owned_page_route(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(String, String, ChromiumTargetRoute), OwnerActorError> {
        let (context_id, context) = self.active_context_for_session(session_id)?;
        let target_id = context
            .pages
            .get(page_id)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if context.closing_pages.contains(page_id) {
            return Err(OwnerActorError::Rejected);
        }
        let route = self
            .routes
            .get(target_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if route.page_id.as_ref() != Some(page_id)
            || route.route.browser_context_id != context_id
            || route.route.owner_session_id != *session_id
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok((
            context_id.to_owned(),
            target_id.to_owned(),
            route.route.clone(),
        ))
    }

    async fn command_event_first(
        &mut self,
        method: &'static str,
        params: Value,
        session_id: Option<String>,
        mut catch_up: Option<&mut Vec<PausedTarget>>,
        guarded: Option<GuardedPageExecution>,
    ) -> Result<Value, OwnerActorError> {
        let client = self.client.clone();
        let command_timeout = self.command_timeout;
        let command = async move {
            client
                .command(method, params, session_id, Some(command_timeout))
                .await
        };
        tokio::pin!(command);
        loop {
            if let Some(guarded) = guarded.as_ref() {
                let route = self
                    .routes
                    .get(&guarded.target_id)
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                if route.target_incarnation != guarded.fence.target_incarnation
                    || route.frame_document_epoch != guarded.fence.frame_document_epoch
                    || route.url_revision != guarded.fence.url_revision
                {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
            }
            tokio::select! {
                biased;
                incoming = self.events.recv() => {
                    let incoming = incoming.ok_or(OwnerActorError::OutcomeUncertain)?;
                    self.handle_incoming(incoming, catch_up.as_deref_mut())?;
                }
                response = &mut command => {
                    let response = response.map_err(map_command_error)?;
                    if !response.is_object() {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                    return Ok(response);
                }
            }
        }
    }

    fn handle_incoming(
        &mut self,
        incoming: CdpIncoming,
        catch_up: Option<&mut Vec<PausedTarget>>,
    ) -> Result<(), OwnerActorError> {
        let CdpIncoming::Event {
            method,
            params,
            session_id: event_session_id,
        } = incoming
        else {
            return Err(OwnerActorError::OutcomeUncertain);
        };
        match method.as_str() {
            "Target.attachedToTarget" => {
                let params = params
                    .as_object()
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let session_id = required_string(params, "sessionId")?;
                if params.get("waitingForDebugger").and_then(Value::as_bool) != Some(true) {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                let target_info = params
                    .get("targetInfo")
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let (target, browser_context_id) = parse_target_info(target_info)?;
                if self.retired_targets.contains(target.target_id()) {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                let context = self
                    .contexts
                    .get(&browser_context_id)
                    .ok_or(OwnerActorError::UnknownOwnership)?;
                if context.lifecycle != ContextLifecycle::Active {
                    return Err(OwnerActorError::UnknownOwnership);
                }
                let ownership = context.ownership.clone();
                let page_id = if matches!(target.kind(), TargetKind::Page) {
                    let page_id = match self.pending_pages.remove(target.target_id()) {
                        Some(pending) if pending.context_id == browser_context_id => {
                            pending.page_id
                        }
                        Some(_) => return Err(OwnerActorError::OutcomeUncertain),
                        None => PageId::new(),
                    };
                    let context = self
                        .contexts
                        .get_mut(&browser_context_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if context.pages.len() >= MAX_PAGES_PER_CONTEXT
                        || context
                            .pages
                            .insert(page_id.clone(), target.target_id().to_owned())
                            .is_some()
                    {
                        return Err(OwnerActorError::StateOverflow);
                    }
                    Some(page_id)
                } else {
                    None
                };
                let target_incarnation = self.next_target_incarnation;
                self.next_target_incarnation = self
                    .next_target_incarnation
                    .checked_add(1)
                    .ok_or(OwnerActorError::StateOverflow)?;
                let entry = TargetRouteEntry {
                    route: ChromiumTargetRoute {
                        session_id,
                        browser_context_id,
                        tenant_id: ownership.tenant_id,
                        owner_session_id: ownership.session_id,
                        ownership_fence: ownership.fence,
                    },
                    kind: target.kind().clone(),
                    page_id,
                    target_incarnation,
                    frame_document_epoch: 1,
                    url_revision: 1,
                };
                if let Some(existing) = self.routes.get(target.target_id()) {
                    if existing.route != entry.route
                        || existing.kind != entry.kind
                        || existing.page_id != entry.page_id
                    {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                    return Ok(());
                }
                if self.routes.len() >= 4_096
                    || self
                        .routes
                        .values()
                        .any(|existing| existing.route.session_id == entry.route.session_id)
                {
                    return Err(OwnerActorError::StateOverflow);
                }
                if self
                    .routes
                    .insert(target.target_id().to_owned(), entry)
                    .is_some()
                {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                if let Some(catch_up) = catch_up {
                    catch_up.push(target);
                } else {
                    self.ingress
                        .try_send(TargetManagerEvent::Attached(target))
                        .map_err(|_| OwnerActorError::StateOverflow)?;
                }
            }
            "Target.detachedFromTarget" => {
                let params = params
                    .as_object()
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let session_id = required_string(params, "sessionId")?;
                let target_id = optional_string(params, "targetId")?;
                if let Some(target_id) = target_id {
                    let route = self
                        .routes
                        .get(&target_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if route.route.session_id != session_id {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                    let route = self
                        .routes
                        .remove(&target_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if self.retired_targets.len() >= MAX_RETIRED_TARGETS
                        || !self.retired_targets.insert(target_id.clone())
                    {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                    if let Some(page_id) = route.page_id {
                        let context = self
                            .contexts
                            .get_mut(&route.route.browser_context_id)
                            .ok_or(OwnerActorError::OutcomeUncertain)?;
                        let page_was_exact =
                            context.pages.remove(&page_id).as_deref() == Some(target_id.as_str());
                        let _was_closing = context.closing_pages.remove(&page_id);
                        if !page_was_exact
                            || self.closed_page_tombstones.len() >= MAX_CLOSED_PAGE_TOMBSTONES
                            || self
                                .closed_page_tombstones
                                .insert(page_id, route.route.owner_session_id)
                                .is_some()
                        {
                            return Err(OwnerActorError::OutcomeUncertain);
                        }
                    }
                    self.ingress
                        .try_send(TargetManagerEvent::Detached { target_id })
                        .map_err(|_| OwnerActorError::StateOverflow)?;
                } else {
                    let target_id = self
                        .routes
                        .iter()
                        .find_map(|(target_id, entry)| {
                            (entry.route.session_id == session_id).then(|| target_id.clone())
                        })
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    let route = self
                        .routes
                        .remove(&target_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if self.retired_targets.len() >= MAX_RETIRED_TARGETS
                        || !self.retired_targets.insert(target_id.clone())
                    {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                    if let Some(page_id) = route.page_id {
                        let context = self
                            .contexts
                            .get_mut(&route.route.browser_context_id)
                            .ok_or(OwnerActorError::OutcomeUncertain)?;
                        let page_was_exact =
                            context.pages.remove(&page_id).as_deref() == Some(target_id.as_str());
                        let _was_closing = context.closing_pages.remove(&page_id);
                        if !page_was_exact
                            || self.closed_page_tombstones.len() >= MAX_CLOSED_PAGE_TOMBSTONES
                            || self
                                .closed_page_tombstones
                                .insert(page_id, route.route.owner_session_id)
                                .is_some()
                        {
                            return Err(OwnerActorError::OutcomeUncertain);
                        }
                    }
                    self.ingress
                        .try_send(TargetManagerEvent::Detached { target_id })
                        .map_err(|_| OwnerActorError::StateOverflow)?;
                }
            }
            "Target.targetDestroyed" => {
                let params = params
                    .as_object()
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let target_id = required_string(params, "targetId")?;
                let route = self
                    .routes
                    .remove(&target_id)
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                if self.retired_targets.len() >= MAX_RETIRED_TARGETS
                    || !self.retired_targets.insert(target_id.clone())
                {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                if let Some(page_id) = route.page_id {
                    let context = self
                        .contexts
                        .get_mut(&route.route.browser_context_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    let page_was_exact =
                        context.pages.remove(&page_id).as_deref() == Some(target_id.as_str());
                    let _was_closing = context.closing_pages.remove(&page_id);
                    if !page_was_exact
                        || self.closed_page_tombstones.len() >= MAX_CLOSED_PAGE_TOMBSTONES
                        || self
                            .closed_page_tombstones
                            .insert(page_id, route.route.owner_session_id)
                            .is_some()
                    {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                }
                self.ingress
                    .try_send(TargetManagerEvent::Detached { target_id })
                    .map_err(|_| OwnerActorError::StateOverflow)?;
            }
            "Page.frameNavigated" => {
                let session_id = event_session_id
                    .as_deref()
                    .filter(|session_id| valid_identifier(session_id))
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let frame = params
                    .as_object()
                    .and_then(|params| params.get("frame"))
                    .and_then(Value::as_object)
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                if !frame.contains_key("parentId") {
                    let route = self
                        .routes
                        .values_mut()
                        .find(|route| route.route.session_id == session_id)
                        .ok_or(OwnerActorError::UnknownOwnership)?;
                    route.frame_document_epoch = route
                        .frame_document_epoch
                        .checked_add(1)
                        .ok_or(OwnerActorError::StateOverflow)?;
                    route.url_revision = route
                        .url_revision
                        .checked_add(1)
                        .ok_or(OwnerActorError::StateOverflow)?;
                }
            }
            "Page.navigatedWithinDocument" => {
                let session_id = event_session_id
                    .as_deref()
                    .filter(|session_id| valid_identifier(session_id))
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let route = self
                    .routes
                    .values_mut()
                    .find(|route| route.route.session_id == session_id)
                    .ok_or(OwnerActorError::UnknownOwnership)?;
                route.url_revision = route
                    .url_revision
                    .checked_add(1)
                    .ok_or(OwnerActorError::StateOverflow)?;
            }
            _ => {}
        }
        Ok(())
    }
}

fn parse_target_info(value: &Value) -> Result<(PausedTarget, String), OwnerActorError> {
    let target_info = value.as_object().ok_or(OwnerActorError::OutcomeUncertain)?;
    let target_id = required_string(target_info, "targetId")?;
    let kind = target_kind(&required_string(target_info, "type")?);
    let browser_context_id = required_string(target_info, "browserContextId")?;
    Ok((PausedTarget::new(target_id, kind), browser_context_id))
}

fn required_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, OwnerActorError> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(OwnerActorError::OutcomeUncertain)?;
    if !valid_identifier(value) {
        return Err(OwnerActorError::OutcomeUncertain);
    }
    Ok(value.to_owned())
}

fn optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, OwnerActorError> {
    match object.get(field) {
        None => Ok(None),
        Some(value) => {
            let value = value.as_str().ok_or(OwnerActorError::OutcomeUncertain)?;
            if !valid_identifier(value) {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            Ok(Some(value.to_owned()))
        }
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CDP_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
}

fn allowed_target_kind(kind: &TargetKind) -> bool {
    matches!(
        kind,
        TargetKind::Page
            | TargetKind::Iframe
            | TargetKind::DedicatedWorker
            | TargetKind::SharedWorker
            | TargetKind::ServiceWorker
    )
}

fn stage_command(stage: BootstrapStage, kind: &TargetKind) -> Option<(&'static str, Value)> {
    match stage {
        BootstrapStage::InstallRecursiveAutoAttach => Some((
            "Target.setAutoAttach",
            json!({
                "autoAttach": true,
                "waitForDebuggerOnStart": true,
                "flatten": true,
            }),
        )),
        BootstrapStage::InstallNetworkHooks => Some(("Network.enable", json!({}))),
        BootstrapStage::RunFeatureHooks => Some(("Runtime.enable", json!({}))),
        BootstrapStage::InstallLifecycleHandlers
            if matches!(kind, TargetKind::Page | TargetKind::Iframe) =>
        {
            Some(("Page.enable", json!({})))
        }
        BootstrapStage::InstallFileChooserHandlers
            if matches!(kind, TargetKind::Page | TargetKind::Iframe) =>
        {
            Some((
                "Page.setInterceptFileChooserDialog",
                json!({"enabled": true}),
            ))
        }
        BootstrapStage::Resume => Some(("Runtime.runIfWaitingForDebugger", json!({}))),
        _ => None,
    }
}

fn target_kind(kind: &str) -> TargetKind {
    match kind {
        "page" => TargetKind::Page,
        "iframe" => TargetKind::Iframe,
        "worker" => TargetKind::DedicatedWorker,
        "shared_worker" => TargetKind::SharedWorker,
        "service_worker" => TargetKind::ServiceWorker,
        "prerender" => TargetKind::Prerender,
        "background_page" => TargetKind::Extension,
        "other" => TargetKind::Devtools,
        value => TargetKind::Unknown(value.to_owned()),
    }
}

fn map_command_error(error: CdpCommandError) -> OwnerActorError {
    match error {
        CdpCommandError::Protocol(_) => OwnerActorError::Rejected,
        CdpCommandError::CommandQueueFull | CdpCommandError::PendingLimitExceeded => {
            OwnerActorError::StateOverflow
        }
        CdpCommandError::SequenceExhausted
        | CdpCommandError::TimedOut
        | CdpCommandError::WriteUncertain
        | CdpCommandError::TransportClosed => OwnerActorError::OutcomeUncertain,
    }
}

fn map_actor_stage_error(error: OwnerActorError) -> BootstrapStageFailure {
    match error {
        OwnerActorError::UnknownOwnership => BootstrapStageFailure::UnknownOwnership,
        OwnerActorError::Rejected => BootstrapStageFailure::Rejected,
        OwnerActorError::StateOverflow
        | OwnerActorError::Unavailable
        | OwnerActorError::OutcomeUncertain => BootstrapStageFailure::StateOverflow,
    }
}

fn map_actor_runtime_error(error: OwnerActorError) -> ShardRuntimeError {
    match error {
        OwnerActorError::Rejected | OwnerActorError::UnknownOwnership => {
            ShardRuntimeError::Rejected
        }
        OwnerActorError::StateOverflow | OwnerActorError::Unavailable => {
            ShardRuntimeError::Unavailable
        }
        OwnerActorError::OutcomeUncertain => ShardRuntimeError::OutcomeUncertain,
    }
}

fn map_connection_error(error: ChromiumConnectionError) -> ShardRuntimeError {
    match error {
        ChromiumConnectionError::InvalidTransportConfig
        | ChromiumConnectionError::InvalidExpectedIdentity { .. }
        | ChromiumConnectionError::ProductVersionMismatch { .. }
        | ChromiumConnectionError::RevisionMismatch { .. }
        | ChromiumConnectionError::InvalidVersionField { .. } => ShardRuntimeError::Rejected,
        _ => ShardRuntimeError::OutcomeUncertain,
    }
}
