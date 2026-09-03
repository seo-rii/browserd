use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc as std_mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use browserd_cdp::{CdpClient, CdpCommandError, CdpIncoming};
use browserd_chromium::{
    ChromiumArtifactIdentity, ChromiumConnection, ChromiumConnectionConfig,
    ChromiumConnectionError, VerifiedChromiumDriverOwner,
};
use browserd_core::{IsolationProfile, PageId, SessionId, ShardFence, TenantId};
use browserd_sandbox::{ChromiumCdpPipes, LaunchSpec};
use browserd_session::OwnershipFence;
use browserd_targets::{
    BackendNodeId, BootstrapBackend, BootstrapStage, BootstrapStageFailure, DocumentEpoch,
    NodeBinding, NodeHandle, NodeHandleStore, NodeResolutionContext, PausedTarget,
    SessionIncarnation, ShardTaintReason, SnapshotId, TargetIncarnation, TargetKind, TargetTime,
    UrlRevision,
};
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::cdp_driver::CdpChromiumDriver;
use crate::{
    CdpPipeAcceptor, ProductionTargetManager, SandboxTerminationProof, ShardRuntimeError,
    TargetBootstrapSnapshot, TargetManagerBackend, TargetManagerDrain, TargetManagerEvent,
    TargetManagerIngress, WorkerNavigateWaitUntil, WorkerSessionOptionsV1,
    target_manager::TargetReadiness,
};

const MAX_CDP_IDENTIFIER_BYTES: usize = 1_024;
const MAX_OWNER_COMMAND_CAPACITY: usize = 1_024;
const MAX_CONTEXTS_PER_SHARD: usize = 1_024;
const MAX_PAGES_PER_CONTEXT: usize = 256;
const MAX_CLOSED_PAGE_TOMBSTONES: usize = 4_096;
const MAX_RETIRED_TARGETS: usize = 4_096;
/// Lifecycle waits answer this far ahead of the action deadline so the reply reaches the
/// mailbox before its own deadline expires; a mailbox timeout fails the whole owner closed.
const LIFECYCLE_DEADLINE_RESPONSE_MARGIN: Duration = Duration::from_millis(50);
/// Capacity and lifetime of the per-owner opaque node-handle store.
const NODE_STORE_CAPACITY: usize = 4096;
const NODE_STORE_TTL: Duration = Duration::from_secs(300);
/// Upper bound on the matches a single `query_all` mints, to bound resolution work.
const MAX_QUERY_ALL_MATCHES: usize = 256;
/// Extracts a bounded, rendered-text view of a resolved node for `get_text`.
const NODE_TEXT_FUNCTION: &str = "function () { const value = this.innerText != null ? this.innerText : (this.textContent || ''); return String(value).slice(0, 60000); }";
/// Collects a curated set of scalar element properties for `get_properties`.
const NODE_PROPERTIES_FUNCTION: &str = "function () { const el = this; const out = {}; for (const key of ['tagName','id','className','name','type','value','checked','disabled','selected','readOnly','multiple','href','src','alt','title','placeholder','ariaLabel','role']) { const v = el[key]; if (v !== undefined && v !== null && typeof v !== 'object' && typeof v !== 'function') out[key] = v; } return out; }";
/// Serializes the full computed style of a resolved node for `get_computed_style`.
const NODE_COMPUTED_STYLE_FUNCTION: &str = "function () { const s = getComputedStyle(this); const out = {}; for (let i = 0; i < s.length; i++) { const p = s[i]; out[p] = s.getPropertyValue(p); } return out; }";
/// Extracts a table's cells into rows of trimmed text for `extract_table`.
const NODE_TABLE_FUNCTION: &str = "function () { const rows = this.rows ? Array.from(this.rows) : Array.from(this.querySelectorAll('tr')); return rows.map(r => Array.from(r.cells && r.cells.length ? r.cells : r.querySelectorAll('td,th')).map(c => (c.innerText != null ? c.innerText : (c.textContent || '')).trim())); }";
/// Blurs a resolved node for `blur`.
const NODE_BLUR_FUNCTION: &str = "function () { this.blur(); return true; }";
/// Sets a resolved node's checked state, firing input/change only on a real change, for
/// `check` and `uncheck`.
const NODE_SET_CHECKED_FUNCTION: &str = "function (desired) { if (!!this.checked !== desired) { this.checked = desired; this.dispatchEvent(new Event('input', { bubbles: true })); this.dispatchEvent(new Event('change', { bubbles: true })); } return !!this.checked; }";

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
                options: None,
                response,
            })?;
        self.wait_until_target_ready(&created.target_id)?;
        Ok(created.page_id)
    }

    pub(crate) fn create_context_owned_with_options(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        fence: OwnershipFence,
        options: WorkerSessionOptionsV1,
    ) -> Result<PageId, OwnerActorError> {
        let created = self
            .mailbox
            .request(|response| OwnerRequest::CreateContext {
                tenant_id,
                session_id,
                fence,
                options: Some(Box::new(options)),
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

    pub fn verify_context_disposed(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), ShardRuntimeError> {
        self.verify_context_disposed_with_deadline(tenant_id, session_id, fence, None)
    }

    pub fn verify_context_disposed_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        deadline: Instant,
    ) -> Result<(), ShardRuntimeError> {
        self.verify_context_disposed_with_deadline(tenant_id, session_id, fence, Some(deadline))
    }

    fn verify_context_disposed_with_deadline(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        deadline: Option<Instant>,
    ) -> Result<(), ShardRuntimeError> {
        let request = |response| OwnerRequest::VerifyContextDisposed {
            tenant_id: tenant_id.clone(),
            session_id: session_id.clone(),
            fence: fence.clone(),
            response,
        };
        match deadline {
            Some(deadline) => self.mailbox.request_until(request, deadline),
            None => self.mailbox.request(request),
        }
        .map_err(map_actor_runtime_error)?;
        let wait_timeout = deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(self.target_ready_timeout)
            .min(self.target_ready_timeout);
        self.readiness
            .get()
            .ok_or(ShardRuntimeError::Unavailable)?
            .wait_until_empty(wait_timeout)
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
        self.execute_page_command_with_deadline(session_id, page_id, command, execution_fence, None)
    }

    pub(crate) fn execute_page_command_until(
        &self,
        session_id: SessionId,
        page_id: PageId,
        command: PageCommand,
        execution_fence: Option<PageExecutionFence>,
        deadline: Instant,
    ) -> Result<Value, OwnerActorError> {
        self.execute_page_command_with_deadline(
            session_id,
            page_id,
            command,
            execution_fence,
            Some(deadline),
        )
    }

    fn execute_page_command_with_deadline(
        &self,
        session_id: SessionId,
        page_id: PageId,
        command: PageCommand,
        execution_fence: Option<PageExecutionFence>,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let build = |response| OwnerRequest::ExecutePageCommand {
            session_id,
            page_id,
            command,
            execution_fence,
            deadline,
            response,
        };
        match deadline {
            Some(deadline) => self.mailbox.request_until(build, deadline),
            None => self.mailbox.request(build),
        }
    }

    pub(crate) fn observe_page(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
    ) -> Result<ObservedPage, OwnerActorError> {
        self.observe_page_with_deadline(tenant_id, session_id, session_incarnation, page_id, None)
    }

    pub(crate) fn observe_page_until(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
        deadline: Instant,
    ) -> Result<ObservedPage, OwnerActorError> {
        self.observe_page_with_deadline(
            tenant_id,
            session_id,
            session_incarnation,
            page_id,
            Some(deadline),
        )
    }

    fn observe_page_with_deadline(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
        deadline: Option<Instant>,
    ) -> Result<ObservedPage, OwnerActorError> {
        let build = |response| OwnerRequest::ObservePage {
            tenant_id,
            session_id,
            session_incarnation,
            page_id,
            deadline,
            response,
        };
        match deadline {
            Some(deadline) => self.mailbox.request_until(build, deadline),
            None => self.mailbox.request(build),
        }
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
    forced_termination_spec: Option<LaunchSpec>,
    sandbox_termination_confirmed: AtomicBool,
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
    structurally_terminal: bool,
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
        Self::new_bounded_with_launch_spec(expected, config, fence, event_capacity, drain, None)
    }

    pub fn new_bounded_for_launch(
        expected: ChromiumArtifactIdentity,
        config: ChromiumConnectionConfig,
        fence: ShardFence,
        event_capacity: usize,
        drain: Arc<D>,
        launch_spec: LaunchSpec,
    ) -> Result<(Arc<Self>, Arc<ChromiumTargetManager<D>>), ShardRuntimeError> {
        Self::new_bounded_with_launch_spec(
            expected,
            config,
            fence,
            event_capacity,
            drain,
            Some(launch_spec),
        )
    }

    fn new_bounded_with_launch_spec(
        expected: ChromiumArtifactIdentity,
        config: ChromiumConnectionConfig,
        fence: ShardFence,
        event_capacity: usize,
        drain: Arc<D>,
        forced_termination_spec: Option<LaunchSpec>,
    ) -> Result<(Arc<Self>, Arc<ChromiumTargetManager<D>>), ShardRuntimeError> {
        if !config.is_valid() {
            return Err(ShardRuntimeError::Rejected);
        }
        if forced_termination_spec.as_ref().is_some_and(|launch_spec| {
            launch_spec.dedicated_egress().egress_fence().shard() != &fence
        }) {
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
            forced_termination_spec,
            sandbox_termination_confirmed: AtomicBool::new(false),
            thread: Arc::new(OwnerThreadControl {
                completion,
                join: Mutex::new(OwnerJoinState {
                    handle: None,
                    result: None,
                    structurally_terminal: false,
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
        {
            let mut join = self
                .thread
                .join
                .lock()
                .map_err(|_| ShardRuntimeError::Unavailable)?;
            if let Some(result) = join.result {
                return if self.sandbox_termination_confirmed.load(Ordering::Acquire)
                    && join.structurally_terminal
                {
                    Ok(())
                } else {
                    result
                };
            }
            self.thread.shutdown.cancel();
            if self
                .shutdown_started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let _ = self.mailbox.begin_shutdown();
            }
            if !self.accepted.load(Ordering::Acquire) && join.handle.is_none() {
                join.result = Some(Ok(()));
                join.structurally_terminal = true;
                self.thread.completion.send_replace(Some(Ok(())));
                return Ok(());
            }
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
            return if self.sandbox_termination_confirmed.load(Ordering::Acquire)
                && join.structurally_terminal
            {
                Ok(())
            } else {
                result
            };
        }
        let handle = join
            .handle
            .take()
            .ok_or(ShardRuntimeError::OutcomeUncertain)?;
        let join_result = handle
            .join()
            .map_err(|_| ShardRuntimeError::OutcomeUncertain);
        let structurally_terminal = join_result.is_ok();
        let result = thread_result.and(join_result);
        join.result = Some(result);
        join.structurally_terminal = structurally_terminal;
        if self.sandbox_termination_confirmed.load(Ordering::Acquire) && structurally_terminal {
            Ok(())
        } else {
            result
        }
    }

    pub fn confirm_forced_termination(&self, proof: &SandboxTerminationProof) -> bool {
        if !proof.matches_fence(&self.shard_fence)
            || !self
                .forced_termination_spec
                .as_ref()
                .is_some_and(|spec| proof.matches_launch_spec(spec))
        {
            return false;
        }
        self.sandbox_termination_confirmed
            .store(true, Ordering::Release);
        true
    }

    pub fn is_terminally_joined_after(&self, proof: &SandboxTerminationProof) -> bool {
        if !proof.matches_fence(&self.shard_fence)
            || !self
                .forced_termination_spec
                .as_ref()
                .is_some_and(|spec| proof.matches_launch_spec(spec))
            || !self.sandbox_termination_confirmed.load(Ordering::Acquire)
        {
            return false;
        }
        self.thread
            .join
            .lock()
            .is_ok_and(|join| join.structurally_terminal)
    }
}

#[async_trait]
impl<D: TargetManagerDrain> CdpPipeAcceptor for ChromiumConnectionOwner<D> {
    async fn accept_cdp_pipes(&self, pipes: ChromiumCdpPipes) -> Result<(), ShardRuntimeError> {
        let ready_rx = {
            let mut join = self
                .thread
                .join
                .lock()
                .map_err(|_| ShardRuntimeError::Unavailable)?;
            if self.shutdown_started.load(Ordering::Acquire) {
                return Err(ShardRuntimeError::Rejected);
            }
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
            let failed_completion = completion.clone();
            let failure_mailbox = mailbox.clone();
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
                    publish_owner_thread_result(&failure_mailbox, &completion, result);
                });
            let thread = match thread {
                Ok(thread) => thread,
                Err(_) => {
                    self.mailbox.mark_terminal();
                    self.ingress.fail_closed(TargetManagerEvent::TransportLost);
                    join.result = Some(Err(ShardRuntimeError::Unavailable));
                    join.structurally_terminal = true;
                    failed_completion.send_replace(Some(Err(ShardRuntimeError::Unavailable)));
                    return Err(ShardRuntimeError::Unavailable);
                }
            };
            join.handle = Some(thread);
            ready_rx
        };
        match ready_rx.await {
            Ok(result) => result,
            Err(_) => {
                self.mailbox.mark_terminal();
                self.ingress.fail_closed(TargetManagerEvent::TransportLost);
                Err(ShardRuntimeError::OutcomeUncertain)
            }
        }
    }

    async fn shutdown_cdp(&self) -> Result<(), ShardRuntimeError> {
        let timeout = self
            .config
            .transport
            .default_command_timeout
            .checked_mul(4)
            .unwrap_or(Duration::MAX)
            .saturating_add(Duration::from_millis(100));
        self.shutdown_and_join(timeout).await
    }

    fn confirm_forced_termination(&self, proof: &SandboxTerminationProof) -> bool {
        ChromiumConnectionOwner::confirm_forced_termination(self, proof)
    }

    fn is_terminally_joined_after(&self, proof: &SandboxTerminationProof) -> bool {
        ChromiumConnectionOwner::is_terminally_joined_after(self, proof)
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
            OwnerActorContext {
                ingress,
                mailbox,
                shard_fence,
            },
            config.transport.default_command_timeout,
        )
        .run(receiver, shutdown)
        .await
    })
}

fn publish_owner_thread_result(
    mailbox: &Weak<OwnerMailbox>,
    completion: &watch::Sender<Option<Result<(), ShardRuntimeError>>>,
    result: Result<(), ShardRuntimeError>,
) {
    let result = if result.is_err()
        && catch_unwind(AssertUnwindSafe(|| {
            if let Some(mailbox) = mailbox.upgrade() {
                mailbox.mark_terminal();
                mailbox.fail_closed();
            }
        }))
        .is_err()
    {
        Err(ShardRuntimeError::OutcomeUncertain)
    } else {
        result
    };
    completion.send_replace(Some(result));
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
        self.request_with_deadline(build, None)
    }

    fn request_until<T>(
        &self,
        build: impl FnOnce(std_mpsc::SyncSender<Result<T, OwnerActorError>>) -> OwnerRequest,
        deadline: Instant,
    ) -> Result<T, OwnerActorError> {
        self.request_with_deadline(build, Some(deadline))
    }

    fn request_with_deadline<T>(
        &self,
        build: impl FnOnce(std_mpsc::SyncSender<Result<T, OwnerActorError>>) -> OwnerRequest,
        deadline: Option<Instant>,
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
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(OwnerActorError::DeadlineBeforeDispatch);
        }
        let (response, receiver) = std_mpsc::sync_channel(1);
        let request = build(response);
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(OwnerActorError::DeadlineBeforeDispatch);
        }
        match sender.try_send(request) {
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
        let response_timeout = deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(self.request_timeout)
            .min(self.request_timeout);
        receiver.recv_timeout(response_timeout).map_err(|_| {
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
        options: Option<Box<WorkerSessionOptionsV1>>,
        response: std_mpsc::SyncSender<Result<CreatedPage, OwnerActorError>>,
    },
    DisposeContext {
        session_id: SessionId,
        fence: OwnershipFence,
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
    },
    VerifyContextDisposed {
        tenant_id: TenantId,
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
        deadline: Option<Instant>,
        response: std_mpsc::SyncSender<Result<Value, OwnerActorError>>,
    },
    ObservePage {
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
        deadline: Option<Instant>,
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
    DeadlineBeforeDispatch,
    StateOverflow,
    Unavailable,
    OutcomeUncertain,
    /// The navigated document committed and was then replaced before the requested lifecycle.
    NavigationInterrupted,
    /// The navigate command was acknowledged but the requested lifecycle did not arrive in time.
    NavigationTimeout,
}

#[derive(Clone, Debug)]
struct CreatedPage {
    page_id: PageId,
    target_id: String,
}

#[derive(Clone, Debug)]
pub(crate) enum PageCommand {
    Navigate {
        url: String,
        wait_until: WorkerNavigateWaitUntil,
    },
    Reload,
    GoBack,
    GoForward,
    Click {
        node_ref: String,
    },
    DoubleClick {
        node_ref: String,
    },
    Hover {
        node_ref: String,
    },
    Focus {
        node_ref: String,
    },
    Blur {
        node_ref: String,
    },
    Check {
        node_ref: String,
    },
    Uncheck {
        node_ref: String,
    },
    InsertText {
        text: String,
    },
    PressKey {
        key: String,
    },
    Scroll {
        delta_x: i64,
        delta_y: i64,
    },
    QueryAll {
        selector: String,
    },
    GetText {
        node_ref: String,
    },
    GetHtml {
        node_ref: Option<String>,
    },
    GetAttribute {
        node_ref: String,
        name: String,
    },
    GetProperties {
        node_ref: String,
    },
    GetComputedStyle {
        node_ref: String,
    },
    ExtractTable {
        node_ref: String,
    },
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
    DisposeRequested,
    Disposing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContextEntry {
    ownership: ContextOwnership,
    options: Option<WorkerSessionOptionsV1>,
    emulation_owner_target_id: Option<String>,
    lifecycle: ContextLifecycle,
    pages: BTreeMap<PageId, String>,
    closing_pages: BTreeSet<PageId>,
}

#[derive(Clone)]
struct PendingPage {
    context_id: String,
    page_id: PageId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetRouteEntry {
    route: ChromiumTargetRoute,
    kind: TargetKind,
    page_id: Option<PageId>,
    target_incarnation: u64,
    frame_document_epoch: u64,
    url_revision: u64,
    document: DocumentLoadState,
}

/// Lifecycle of the main-frame document most recently committed on a target.
///
/// `loader_id` correlates `Page.frameNavigated` with the `loaderId` a `Page.navigate`
/// response returned, so a navigate action only completes on its own document.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DocumentLoadState {
    loader_id: Option<String>,
    dom_content_loaded: bool,
    loaded: bool,
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
    retired_targets: BTreeMap<String, String>,
    next_target_incarnation: u64,
    node_store: NodeHandleStore,
}

struct OwnerActorContext<D> {
    ingress: Arc<TargetManagerIngress<D>>,
    mailbox: Weak<OwnerMailbox>,
    shard_fence: ShardFence,
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    fn new(
        client: CdpClient,
        events: mpsc::Receiver<CdpIncoming>,
        driver: VerifiedChromiumDriverOwner,
        context: OwnerActorContext<D>,
        command_timeout: Duration,
    ) -> Self {
        Self {
            client,
            events,
            driver,
            ingress: context.ingress,
            mailbox: context.mailbox,
            shard_fence: context.shard_fence,
            command_timeout,
            routes: BTreeMap::new(),
            contexts: BTreeMap::new(),
            context_by_session: BTreeMap::new(),
            pending_pages: BTreeMap::new(),
            closed_page_tombstones: BTreeMap::new(),
            retired_targets: BTreeMap::new(),
            next_target_incarnation: 1,
            node_store: NodeHandleStore::new(NODE_STORE_CAPACITY, NODE_STORE_TTL),
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
                options,
                response,
            } => {
                let result = self
                    .create_context(
                        tenant_id,
                        session_id,
                        fence,
                        options.map(|options| *options),
                    )
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
            OwnerRequest::VerifyContextDisposed {
                tenant_id,
                session_id,
                fence,
                response,
            } => {
                let result = self
                    .verify_context_disposed(&tenant_id, &session_id, &fence)
                    .await;
                let failed = result.is_err();
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
                deadline,
                response,
            } => {
                let result = self
                    .execute_page_command(&session_id, &page_id, command, execution_fence, deadline)
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
                deadline,
                response,
            } => {
                let result = self
                    .observe_page(
                        &tenant_id,
                        &session_id,
                        session_incarnation,
                        &page_id,
                        deadline,
                    )
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
            None,
        )
        .await?;
        self.command_event_first(
            "Target.setDiscoverTargets",
            json!({"discover": true}),
            None,
            Some(&mut catch_up),
            None,
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
        let validate_route = |actor: &Self| {
            let current = actor
                .routes
                .get(target.target_id())
                .ok_or(OwnerActorError::UnknownOwnership)?;
            if current.route != route.route
                || current.kind != route.kind
                || current.page_id != route.page_id
                || current.kind != *target.kind()
            {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            let context = actor
                .contexts
                .get(current.route.browser_context_id())
                .ok_or(OwnerActorError::UnknownOwnership)?;
            if context.lifecycle != ContextLifecycle::Active
                || &context.ownership.tenant_id != current.route.tenant_id()
                || &context.ownership.session_id != current.route.owner_session_id()
                || &context.ownership.fence != current.route.ownership_fence()
            {
                return Err(OwnerActorError::UnknownOwnership);
            }
            Ok((
                context.options.clone(),
                context.emulation_owner_target_id.clone(),
            ))
        };
        let (options, emulation_owner_target_id) = validate_route(self)?;
        if stage == BootstrapStage::ValidateTargetType
            && (!allowed_target_kind(target.kind())
                || (options.is_some()
                    && match emulation_owner_target_id.as_deref() {
                        Some(owner_target_id) => owner_target_id != target.target_id(),
                        None => !matches!(target.kind(), TargetKind::Page),
                    }))
        {
            return Err(OwnerActorError::Rejected);
        }
        if stage == BootstrapStage::ApplyEmulation {
            let Some(options) = options else {
                return Ok(());
            };
            let mut commands = vec![
                (
                    "Emulation.setDeviceMetricsOverride",
                    json!({
                        "width": options.viewport.width,
                        "height": options.viewport.height,
                        "deviceScaleFactor": options.viewport.device_scale_factor,
                        "mobile": false,
                    }),
                ),
                (
                    "Emulation.setLocaleOverride",
                    json!({"locale": options.locale}),
                ),
                (
                    "Emulation.setTimezoneOverride",
                    json!({"timezoneId": options.timezone}),
                ),
            ];
            if let Some(user_agent) = options.user_agent {
                commands.push((
                    "Network.setUserAgentOverride",
                    json!({"userAgent": user_agent}),
                ));
            }
            for (method, params) in commands {
                validate_route(self)?;
                self.command_event_first(
                    method,
                    params,
                    Some(route.route.session_id.clone()),
                    None,
                    None,
                    None,
                )
                .await?;
            }
            validate_route(self)?;
            let context = self
                .contexts
                .get_mut(route.route.browser_context_id())
                .ok_or(OwnerActorError::UnknownOwnership)?;
            match context.emulation_owner_target_id.as_deref() {
                Some(owner_target_id) if owner_target_id != target.target_id() => {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                Some(_) => {}
                None => {
                    context.emulation_owner_target_id = Some(target.target_id().to_owned());
                }
            }
            return Ok(());
        }
        let command = stage_command(stage, target.kind());
        let Some((method, params)) = command else {
            return Ok(());
        };
        let result = self
            .command_event_first(
                method,
                params,
                Some(route.route.session_id.clone()),
                None,
                None,
                None,
            )
            .await
            .map(|_| ());
        if result.is_ok() {
            validate_route(self)?;
        }
        result
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
        options: Option<WorkerSessionOptionsV1>,
    ) -> Result<CreatedPage, OwnerActorError> {
        let options_context_conflict = if options.is_some() {
            !self.contexts.is_empty()
        } else {
            self.contexts
                .values()
                .any(|context| context.options.is_some())
        };
        if self.contexts.len() >= MAX_CONTEXTS_PER_SHARD
            || self.context_by_session.contains_key(&session_id)
            || fence.worker_id() != self.shard_fence.owner().worker_id()
            || fence.worker_epoch() != self.shard_fence.owner().worker_epoch().get()
            || fence.placement_version() == 0
            || fence.session_incarnation() == 0
            || options.as_ref().is_some_and(|options| !options.is_valid())
            || options_context_conflict
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
                    options,
                    emulation_owner_target_id: None,
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
        match context.lifecycle {
            ContextLifecycle::Disposing => return Ok(()),
            ContextLifecycle::DisposeRequested => {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            ContextLifecycle::Active => {}
        }
        let original_context = context.clone();
        let context_routes = |routes: &BTreeMap<String, TargetRouteEntry>| {
            routes
                .iter()
                .filter(|(_, route)| route.route.browser_context_id() == context_id)
                .map(|(target_id, route)| (target_id.clone(), route.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        let original_routes = context_routes(&self.routes);
        self.contexts
            .get_mut(&context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .lifecycle = ContextLifecycle::DisposeRequested;
        let result = self
            .command_event_first(
                "Target.disposeBrowserContext",
                json!({"browserContextId": context_id.clone()}),
                None,
                None,
                None,
                None,
            )
            .await;
        match result {
            Ok(_) => {
                self.contexts
                    .get_mut(&context_id)
                    .ok_or(OwnerActorError::OutcomeUncertain)?
                    .lifecycle = ContextLifecycle::Disposing;
                Ok(())
            }
            Err(OwnerActorError::Rejected) => {
                let mut requested_context = original_context;
                requested_context.lifecycle = ContextLifecycle::DisposeRequested;
                if self.contexts.get(&context_id) != Some(&requested_context)
                    || context_routes(&self.routes) != original_routes
                {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                self.contexts
                    .get_mut(&context_id)
                    .ok_or(OwnerActorError::OutcomeUncertain)?
                    .lifecycle = ContextLifecycle::Active;
                Err(OwnerActorError::Rejected)
            }
            Err(error) => Err(error),
        }
    }

    async fn verify_context_disposed(
        &mut self,
        tenant_id: &TenantId,
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
        if &context.ownership.tenant_id != tenant_id
            || &context.ownership.session_id != session_id
            || &context.ownership.fence != fence
            || context.lifecycle != ContextLifecycle::Disposing
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let targets = self
            .command_event_first("Target.getTargets", json!({}), None, None, None, None)
            .await?;
        let target_infos = targets
            .as_object()
            .and_then(|targets| targets.get("targetInfos"))
            .and_then(Value::as_array)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if !target_infos.is_empty() {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let contexts = self
            .command_event_first(
                "Target.getBrowserContexts",
                json!({}),
                None,
                None,
                None,
                None,
            )
            .await?;
        let context_ids = contexts
            .as_object()
            .and_then(|contexts| contexts.get("browserContextIds"))
            .and_then(Value::as_array)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let context = self
            .contexts
            .get(&context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if &context.ownership.tenant_id != tenant_id
            || &context.ownership.session_id != session_id
            || &context.ownership.fence != fence
            || context.lifecycle != ContextLifecycle::Disposing
            || !context_ids.is_empty()
            || !self.routes.is_empty()
            || !self.pending_pages.is_empty()
            || !context.pages.is_empty()
            || !context.closing_pages.is_empty()
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        if self.context_by_session.get(session_id) != Some(&context_id) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        self.contexts.remove(&context_id);
        self.context_by_session.remove(session_id);
        Ok(())
    }

    async fn create_page(
        &mut self,
        session_id: &SessionId,
    ) -> Result<CreatedPage, OwnerActorError> {
        let (context_id, page_count, has_options) = {
            let (context_id, context) = self.active_context_for_session(session_id)?;
            (
                context_id.to_owned(),
                context.pages.len(),
                context.options.is_some(),
            )
        };
        if has_options && page_count != 0 {
            return Err(OwnerActorError::Rejected);
        }
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
                None,
            )
            .await?;
        let target_id = response
            .as_object()
            .ok_or(OwnerActorError::OutcomeUncertain)
            .and_then(|response| required_string(response, "targetId"))?;
        if self.retired_targets.contains_key(&target_id) {
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
        if context.options.is_some() {
            let owner_target_id = context
                .emulation_owner_target_id
                .as_deref()
                .ok_or(OwnerActorError::Rejected)?;
            let page_id = context
                .pages
                .iter()
                .find_map(|(page_id, target_id)| {
                    (target_id == owner_target_id).then(|| page_id.clone())
                })
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            return Ok(vec![page_id]);
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
        if context.lifecycle != ContextLifecycle::Active
            || context.emulation_owner_target_id.as_deref() == Some(target_id.as_str())
        {
            return Err(OwnerActorError::Rejected);
        }
        let response = self
            .command_event_first(
                "Target.closeTarget",
                json!({"targetId": target_id}),
                None,
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
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let (_, target_id, route) = self.owned_page_route(session_id, page_id)?;
        let cdp_session_id = route.session_id().to_owned();
        let guarded = execution_fence.map(|fence| GuardedPageExecution {
            target_id: target_id.clone(),
            fence,
        });
        match command {
            PageCommand::Navigate { url, wait_until } => {
                let result = self
                    .command_event_first(
                        "Page.navigate",
                        json!({"url": url}),
                        Some(cdp_session_id),
                        None,
                        guarded,
                        deadline,
                    )
                    .await?;
                if result
                    .get("errorText")
                    .and_then(Value::as_str)
                    .is_some_and(|error| !error.is_empty())
                {
                    return Err(OwnerActorError::Rejected);
                }
                match result.get("loaderId") {
                    // Same-document navigations commit no new loader and fire no lifecycle.
                    None | Some(Value::Null) => {}
                    Some(Value::String(loader_id)) if valid_identifier(loader_id) => {
                        let loader_id = loader_id.clone();
                        self.await_document_lifecycle(&target_id, &loader_id, wait_until, deadline)
                            .await?;
                    }
                    Some(_) => return Err(OwnerActorError::OutcomeUncertain),
                }
                Ok(result)
            }
            PageCommand::Reload => {
                // The document live before the reload; the reload's own document arrives as
                // a later frameNavigated bearing a distinct loader.
                let prior_loader = self
                    .routes
                    .get(&target_id)
                    .and_then(|route| route.document.loader_id.clone());
                let result = self
                    .command_event_first(
                        "Page.reload",
                        json!({}),
                        Some(cdp_session_id),
                        None,
                        guarded,
                        deadline,
                    )
                    .await?;
                self.await_reload_lifecycle(
                    &target_id,
                    prior_loader.as_deref(),
                    WorkerNavigateWaitUntil::Load,
                    deadline,
                )
                .await?;
                Ok(result)
            }
            PageCommand::QueryAll { selector } => {
                self.execute_query_all(&target_id, cdp_session_id, guarded, &selector, deadline)
                    .await
            }
            PageCommand::GetText { node_ref } => {
                self.execute_get_text(&target_id, cdp_session_id, guarded, &node_ref, deadline)
                    .await
            }
            PageCommand::GetHtml { node_ref } => {
                self.execute_get_html(
                    &target_id,
                    cdp_session_id,
                    guarded,
                    node_ref.as_deref(),
                    deadline,
                )
                .await
            }
            PageCommand::GetAttribute { node_ref, name } => {
                self.execute_get_attribute(
                    &target_id,
                    cdp_session_id,
                    guarded,
                    &node_ref,
                    &name,
                    deadline,
                )
                .await
            }
            PageCommand::GetProperties { node_ref } => {
                let value = self
                    .call_function_on_node(
                        &target_id,
                        cdp_session_id,
                        guarded,
                        &node_ref,
                        NodeFunctionCall {
                            declaration: NODE_PROPERTIES_FUNCTION,
                            arguments: json!([]),
                        },
                        deadline,
                    )
                    .await?;
                Ok(json!({ "properties": value }))
            }
            PageCommand::GetComputedStyle { node_ref } => {
                let value = self
                    .call_function_on_node(
                        &target_id,
                        cdp_session_id,
                        guarded,
                        &node_ref,
                        NodeFunctionCall {
                            declaration: NODE_COMPUTED_STYLE_FUNCTION,
                            arguments: json!([]),
                        },
                        deadline,
                    )
                    .await?;
                Ok(json!({ "styles": value }))
            }
            PageCommand::ExtractTable { node_ref } => {
                let value = self
                    .call_function_on_node(
                        &target_id,
                        cdp_session_id,
                        guarded,
                        &node_ref,
                        NodeFunctionCall {
                            declaration: NODE_TABLE_FUNCTION,
                            arguments: json!([]),
                        },
                        deadline,
                    )
                    .await?;
                Ok(json!({ "rows": value }))
            }
            PageCommand::GoBack => {
                self.navigate_history(&target_id, cdp_session_id, guarded, -1, deadline)
                    .await
            }
            PageCommand::GoForward => {
                self.navigate_history(&target_id, cdp_session_id, guarded, 1, deadline)
                    .await
            }
            PageCommand::Click { node_ref } => {
                let point = self
                    .node_pointer_target(
                        &target_id,
                        &cdp_session_id,
                        guarded.clone(),
                        &node_ref,
                        deadline,
                    )
                    .await?;
                self.dispatch_mouse_click(&cdp_session_id, guarded, point, 1, deadline)
                    .await
                    .map_err(|_| OwnerActorError::OutcomeUncertain)
            }
            PageCommand::DoubleClick { node_ref } => {
                let point = self
                    .node_pointer_target(
                        &target_id,
                        &cdp_session_id,
                        guarded.clone(),
                        &node_ref,
                        deadline,
                    )
                    .await?;
                self.dispatch_mouse_click(&cdp_session_id, guarded.clone(), point, 1, deadline)
                    .await?;
                self.dispatch_mouse_click(&cdp_session_id, guarded, point, 2, deadline)
                    .await
                    .map_err(|_| OwnerActorError::OutcomeUncertain)
            }
            PageCommand::Hover { node_ref } => {
                let (x, y) = self
                    .node_pointer_target(
                        &target_id,
                        &cdp_session_id,
                        guarded.clone(),
                        &node_ref,
                        deadline,
                    )
                    .await?;
                self.command_event_first(
                    "Input.dispatchMouseEvent",
                    json!({"type": "mouseMoved", "x": x, "y": y}),
                    Some(cdp_session_id),
                    None,
                    guarded,
                    deadline,
                )
                .await
            }
            PageCommand::Focus { node_ref } => {
                let backend_node_id = self.resolve_node_backend_id(&target_id, &node_ref)?;
                self.command_event_first(
                    "DOM.focus",
                    json!({ "backendNodeId": backend_node_id }),
                    Some(cdp_session_id),
                    None,
                    guarded,
                    deadline,
                )
                .await
            }
            PageCommand::Blur { node_ref } => {
                self.call_function_on_node(
                    &target_id,
                    cdp_session_id,
                    guarded,
                    &node_ref,
                    NodeFunctionCall {
                        declaration: NODE_BLUR_FUNCTION,
                        arguments: json!([]),
                    },
                    deadline,
                )
                .await
            }
            PageCommand::Check { node_ref } => {
                self.call_function_on_node(
                    &target_id,
                    cdp_session_id,
                    guarded,
                    &node_ref,
                    NodeFunctionCall {
                        declaration: NODE_SET_CHECKED_FUNCTION,
                        arguments: json!([{ "value": true }]),
                    },
                    deadline,
                )
                .await
            }
            PageCommand::Uncheck { node_ref } => {
                self.call_function_on_node(
                    &target_id,
                    cdp_session_id,
                    guarded,
                    &node_ref,
                    NodeFunctionCall {
                        declaration: NODE_SET_CHECKED_FUNCTION,
                        arguments: json!([{ "value": false }]),
                    },
                    deadline,
                )
                .await
            }
            PageCommand::InsertText { text } => {
                self.command_event_first(
                    "Input.insertText",
                    json!({"text": text}),
                    Some(cdp_session_id),
                    None,
                    guarded,
                    deadline,
                )
                .await
            }
            PageCommand::PressKey { key } => {
                let stroke = resolve_key_stroke(&key).ok_or(OwnerActorError::Rejected)?;
                let mut down = json!({
                    "type": "keyDown",
                    "key": stroke.key,
                    "code": stroke.code,
                    "windowsVirtualKeyCode": stroke.virtual_key_code,
                    "nativeVirtualKeyCode": stroke.virtual_key_code,
                });
                if let Some(text) = &stroke.text {
                    down["text"] = json!(text);
                }
                self.command_event_first(
                    "Input.dispatchKeyEvent",
                    down,
                    Some(cdp_session_id.clone()),
                    None,
                    guarded.clone(),
                    deadline,
                )
                .await?;
                self.command_event_first(
                    "Input.dispatchKeyEvent",
                    json!({
                        "type": "keyUp",
                        "key": stroke.key,
                        "code": stroke.code,
                        "windowsVirtualKeyCode": stroke.virtual_key_code,
                        "nativeVirtualKeyCode": stroke.virtual_key_code,
                    }),
                    Some(cdp_session_id),
                    None,
                    guarded,
                    deadline,
                )
                .await
                .map_err(|_| OwnerActorError::OutcomeUncertain)
            }
            PageCommand::Scroll { delta_x, delta_y } => {
                self.command_event_first(
                    "Input.dispatchMouseEvent",
                    json!({
                        "type": "mouseWheel",
                        "x": 0,
                        "y": 0,
                        "deltaX": delta_x,
                        "deltaY": delta_y,
                    }),
                    Some(cdp_session_id),
                    None,
                    guarded,
                    deadline,
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
                    deadline,
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
                    deadline,
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
        deadline: Option<Instant>,
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
                deadline,
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
        if context.options.is_some()
            && context.emulation_owner_target_id.as_deref() != Some(target_id.as_str())
        {
            return Err(OwnerActorError::Rejected);
        }
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

    /// Latest instant a lifecycle wait may sleep to.
    ///
    /// Bounded by the actor command timeout and, when the action carries a deadline, by a
    /// margin before that deadline so the mailbox reply is delivered ahead of its own
    /// expiry rather than racing it.
    fn lifecycle_deadline(&self, deadline: Option<Instant>) -> Instant {
        let capped = Instant::now() + self.command_timeout;
        deadline.map_or(capped, |deadline| {
            deadline
                .checked_sub(LIFECYCLE_DEADLINE_RESPONSE_MARGIN)
                .unwrap_or(deadline)
                .min(capped)
        })
    }

    /// Waits until the main-frame document committed for `loader_id` reaches `wait_until`.
    ///
    /// Lifecycle events are recorded by `handle_incoming` regardless of whether they arrive
    /// before or after the `Page.navigate` response, so this only observes route state and
    /// keeps draining the event stream. The wait is bounded by the action deadline (less the
    /// mailbox response margin) and the per-command timeout cap; an expired bound is a known
    /// timeout because the navigate itself was acknowledged and the browser state stays
    /// observable.
    async fn await_document_lifecycle(
        &mut self,
        target_id: &str,
        loader_id: &str,
        wait_until: WorkerNavigateWaitUntil,
        deadline: Option<Instant>,
    ) -> Result<(), OwnerActorError> {
        let expires_at = self.lifecycle_deadline(deadline);
        let expires = tokio::time::sleep_until(expires_at.into());
        tokio::pin!(expires);
        let mut committed = false;
        loop {
            let route = self
                .routes
                .get(target_id)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            match route.document.loader_id.as_deref() {
                Some(current) if current == loader_id => {
                    committed = true;
                    let satisfied = match wait_until {
                        WorkerNavigateWaitUntil::Domcontentloaded => {
                            route.document.dom_content_loaded || route.document.loaded
                        }
                        WorkerNavigateWaitUntil::Load => route.document.loaded,
                    };
                    if satisfied {
                        return Ok(());
                    }
                }
                _ if committed => return Err(OwnerActorError::NavigationInterrupted),
                _ => {}
            }
            tokio::select! {
                biased;
                () = &mut expires => return Err(OwnerActorError::NavigationTimeout),
                incoming = self.events.recv() => {
                    let incoming = incoming.ok_or(OwnerActorError::OutcomeUncertain)?;
                    self.handle_incoming(incoming, None)?;
                }
            }
        }
    }

    /// Awaits the fresh main-frame document a `Page.reload` commits.
    ///
    /// Unlike `Page.navigate`, `Page.reload` returns no `loaderId`, so the reload cannot
    /// name its own document up front. Instead it waits for the next `Page.frameNavigated`
    /// to commit a loader distinct from `prior_loader` — the document that was live when the
    /// reload was issued — then defers to the shared lifecycle wait on that fresh loader.
    async fn await_reload_lifecycle(
        &mut self,
        target_id: &str,
        prior_loader: Option<&str>,
        wait_until: WorkerNavigateWaitUntil,
        deadline: Option<Instant>,
    ) -> Result<(), OwnerActorError> {
        let expires_at = self.lifecycle_deadline(deadline);
        let expires = tokio::time::sleep_until(expires_at.into());
        tokio::pin!(expires);
        loop {
            let route = self
                .routes
                .get(target_id)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            match route.document.loader_id.as_deref() {
                Some(fresh) if Some(fresh) != prior_loader => {
                    let fresh = fresh.to_owned();
                    return self
                        .await_document_lifecycle(target_id, &fresh, wait_until, deadline)
                        .await;
                }
                _ => {}
            }
            tokio::select! {
                biased;
                () = &mut expires => return Err(OwnerActorError::NavigationTimeout),
                incoming = self.events.recv() => {
                    let incoming = incoming.ok_or(OwnerActorError::OutcomeUncertain)?;
                    self.handle_incoming(incoming, None)?;
                }
            }
        }
    }

    /// Resolves the document state a node handle binds to, read from the owned route.
    fn node_document_state(&self, target_id: &str) -> Result<NodeDocumentState, OwnerActorError> {
        let entry = self
            .routes
            .get(target_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        Ok(NodeDocumentState {
            session_incarnation: SessionIncarnation::new(
                entry.route.ownership_fence.session_incarnation(),
            ),
            target_incarnation: TargetIncarnation::new(entry.target_incarnation),
            frame_document_epoch: DocumentEpoch::new(entry.frame_document_epoch),
            url_revision: entry.url_revision,
        })
    }

    /// Resolves a selector against the live document and mints an opaque handle per match.
    ///
    /// Each match's stable `backendNodeId` is bound to the document state observed here, so a
    /// later navigation invalidates the handle. An invalid selector is a caller rejection, not
    /// an ownership fault.
    async fn execute_query_all(
        &mut self,
        target_id: &str,
        cdp_session_id: String,
        guarded: Option<GuardedPageExecution>,
        selector: &str,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let document = self
            .command_event_first(
                "DOM.getDocument",
                json!({ "depth": 0 }),
                Some(cdp_session_id.clone()),
                None,
                guarded.clone(),
                deadline,
            )
            .await?;
        let root_node_id = document
            .get("root")
            .and_then(|root| root.get("nodeId"))
            .and_then(Value::as_i64)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let matches = self
            .command_event_first(
                "DOM.querySelectorAll",
                json!({ "nodeId": root_node_id, "selector": selector }),
                Some(cdp_session_id.clone()),
                None,
                guarded.clone(),
                deadline,
            )
            .await?;
        let node_ids = matches
            .get("nodeIds")
            .and_then(Value::as_array)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let mut backend_ids = Vec::new();
        for node_id in node_ids.iter().take(MAX_QUERY_ALL_MATCHES) {
            let node_id = node_id.as_i64().ok_or(OwnerActorError::OutcomeUncertain)?;
            let described = self
                .command_event_first(
                    "DOM.describeNode",
                    json!({ "nodeId": node_id }),
                    Some(cdp_session_id.clone()),
                    None,
                    guarded.clone(),
                    deadline,
                )
                .await?;
            let backend_node_id = described
                .get("node")
                .and_then(|node| node.get("backendNodeId"))
                .and_then(Value::as_u64)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            backend_ids.push(backend_node_id);
        }
        let document_state = self.node_document_state(target_id)?;
        let now = node_store_now();
        let mut node_refs = Vec::with_capacity(backend_ids.len());
        for backend_node_id in backend_ids {
            let binding = NodeBinding {
                session_incarnation: document_state.session_incarnation,
                target_incarnation: document_state.target_incarnation,
                frame_document_epoch: document_state.frame_document_epoch,
                backend_node_id: BackendNodeId::new(backend_node_id),
                snapshot_id: SnapshotId::new(0),
                url_revision: UrlRevision::new(document_state.url_revision),
            };
            let handle = self.node_store.insert(binding, now);
            node_refs.push(handle.as_token().to_owned());
        }
        Ok(json!({ "node_refs": node_refs }))
    }

    /// Resolves a caller-presented node handle to its stable backend node id.
    ///
    /// Staleness (session/target incarnation, document epoch) is enforced by the store; a
    /// missing or stale handle is a caller rejection. Actionability is read-appropriate here
    /// (a hidden element is still readable), so the visibility gates are left permissive.
    fn resolve_node_backend_id(
        &mut self,
        target_id: &str,
        node_ref: &str,
    ) -> Result<u64, OwnerActorError> {
        let document_state = self.node_document_state(target_id)?;
        let context = NodeResolutionContext {
            session_incarnation: document_state.session_incarnation,
            target_incarnation: document_state.target_incarnation,
            frame_document_epoch: document_state.frame_document_epoch,
            required_snapshot_id: None,
            current_url_revision: UrlRevision::new(document_state.url_revision),
            attached: true,
            visible: true,
            obscured: false,
            disabled: false,
        };
        let handle = NodeHandle::from_token(node_ref);
        let resolved = self
            .node_store
            .resolve(&handle, &context, node_store_now())
            .map_err(|_| OwnerActorError::Rejected)?;
        Ok(resolved.backend_node_id().get())
    }

    /// Resolves a node handle and calls a JS function on the live element by value.
    ///
    /// The shared spine of every node read: resolve the handle to its backend node, obtain a
    /// remote object, then `Runtime.callFunctionOn` returning the value by value. `arguments`
    /// is a CDP call-argument array (empty for a nullary function).
    async fn call_function_on_node(
        &mut self,
        target_id: &str,
        cdp_session_id: String,
        guarded: Option<GuardedPageExecution>,
        node_ref: &str,
        call: NodeFunctionCall<'_>,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let backend_node_id = self.resolve_node_backend_id(target_id, node_ref)?;
        let resolved = self
            .command_event_first(
                "DOM.resolveNode",
                json!({ "backendNodeId": backend_node_id }),
                Some(cdp_session_id.clone()),
                None,
                guarded.clone(),
                deadline,
            )
            .await?;
        let object_id = resolved
            .get("object")
            .and_then(|object| object.get("objectId"))
            .and_then(Value::as_str)
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .to_owned();
        let mut params = json!({
            "objectId": object_id,
            "functionDeclaration": call.declaration,
            "returnByValue": true,
            "awaitPromise": false,
        });
        if call
            .arguments
            .as_array()
            .is_some_and(|arguments| !arguments.is_empty())
        {
            params["arguments"] = call.arguments;
        }
        let evaluated = self
            .command_event_first(
                "Runtime.callFunctionOn",
                params,
                Some(cdp_session_id),
                None,
                guarded,
                deadline,
            )
            .await?;
        evaluated
            .get("result")
            .and_then(|result| result.get("value"))
            .cloned()
            .ok_or(OwnerActorError::OutcomeUncertain)
    }

    /// Resolves a node handle to the pointer coordinates of its first content box.
    ///
    /// An element with no content box (not rendered or hidden) has no actionable point and is
    /// rejected, which gives the click family a basic visibility gate on top of the store's
    /// staleness checks.
    async fn node_pointer_target(
        &mut self,
        target_id: &str,
        cdp_session_id: &str,
        guarded: Option<GuardedPageExecution>,
        node_ref: &str,
        deadline: Option<Instant>,
    ) -> Result<(f64, f64), OwnerActorError> {
        let backend_node_id = self.resolve_node_backend_id(target_id, node_ref)?;
        let response = self
            .command_event_first(
                "DOM.getContentQuads",
                json!({ "backendNodeId": backend_node_id }),
                Some(cdp_session_id.to_owned()),
                None,
                guarded,
                deadline,
            )
            .await?;
        let quad = response
            .get("quads")
            .and_then(Value::as_array)
            .and_then(|quads| quads.first())
            .and_then(Value::as_array)
            .filter(|quad| quad.len() == 8)
            .ok_or(OwnerActorError::Rejected)?;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        for (index, coordinate) in quad.iter().enumerate() {
            let coordinate = coordinate
                .as_f64()
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            if index % 2 == 0 {
                sum_x += coordinate;
            } else {
                sum_y += coordinate;
            }
        }
        Ok((sum_x / 4.0, sum_y / 4.0))
    }

    /// Dispatches a left mouse press/release pair at a point with the given click count.
    async fn dispatch_mouse_click(
        &mut self,
        cdp_session_id: &str,
        guarded: Option<GuardedPageExecution>,
        point: (f64, f64),
        click_count: i64,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let (x, y) = point;
        self.command_event_first(
            "Input.dispatchMouseEvent",
            json!({"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": click_count}),
            Some(cdp_session_id.to_owned()),
            None,
            guarded.clone(),
            deadline,
        )
        .await?;
        self.command_event_first(
            "Input.dispatchMouseEvent",
            json!({"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": click_count}),
            Some(cdp_session_id.to_owned()),
            None,
            guarded,
            deadline,
        )
        .await
    }

    /// Reads the rendered text of a resolved node handle.
    async fn execute_get_text(
        &mut self,
        target_id: &str,
        cdp_session_id: String,
        guarded: Option<GuardedPageExecution>,
        node_ref: &str,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let text = self
            .call_function_on_node(
                target_id,
                cdp_session_id,
                guarded,
                node_ref,
                NodeFunctionCall {
                    declaration: NODE_TEXT_FUNCTION,
                    arguments: json!([]),
                },
                deadline,
            )
            .await?;
        Ok(json!({ "text": text }))
    }

    /// Reads the `outerHTML` of a resolved node, or the whole document when no node is given.
    async fn execute_get_html(
        &mut self,
        target_id: &str,
        cdp_session_id: String,
        guarded: Option<GuardedPageExecution>,
        node_ref: Option<&str>,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let html = match node_ref {
            Some(node_ref) => {
                self.call_function_on_node(
                    target_id,
                    cdp_session_id,
                    guarded,
                    node_ref,
                    NodeFunctionCall {
                        declaration: "function () { return this.outerHTML || ''; }",
                        arguments: json!([]),
                    },
                    deadline,
                )
                .await?
            }
            None => {
                let response = self
                    .command_event_first(
                        "Runtime.evaluate",
                        json!({
                            "expression": "document.documentElement.outerHTML",
                            "returnByValue": true,
                            "awaitPromise": false,
                        }),
                        Some(cdp_session_id),
                        None,
                        guarded,
                        deadline,
                    )
                    .await?;
                response
                    .get("result")
                    .and_then(|result| result.get("value"))
                    .cloned()
                    .ok_or(OwnerActorError::OutcomeUncertain)?
            }
        };
        Ok(json!({ "html": html }))
    }

    /// Reads a single attribute of a resolved node (`null` when the attribute is absent).
    async fn execute_get_attribute(
        &mut self,
        target_id: &str,
        cdp_session_id: String,
        guarded: Option<GuardedPageExecution>,
        node_ref: &str,
        name: &str,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let value = self
            .call_function_on_node(
                target_id,
                cdp_session_id,
                guarded,
                node_ref,
                NodeFunctionCall {
                    declaration: "function (name) { const value = this.getAttribute(name); return value === null ? null : String(value); }",
                    arguments: json!([{ "value": name }]),
                },
                deadline,
            )
            .await?;
        Ok(json!({ "value": value }))
    }

    /// Traverses the target's session history by `delta` (`-1` back, `+1` forward).
    ///
    /// The current history is read first so the destination entry can be named; a `delta`
    /// that falls outside the recorded entries is a rejection because no such entry exists.
    /// The read is unguarded, but the mutating `Page.navigateToHistoryEntry` carries the
    /// execution fence, so a page that navigated between the read and the traversal trips the
    /// fence rather than acting on a stale entry.
    async fn navigate_history(
        &mut self,
        target_id: &str,
        cdp_session_id: String,
        guarded: Option<GuardedPageExecution>,
        delta: i64,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let history = self
            .command_event_first(
                "Page.getNavigationHistory",
                json!({}),
                Some(cdp_session_id.clone()),
                None,
                None,
                deadline,
            )
            .await?;
        let entry_id = select_history_entry(&history, delta)?;
        let (prior_loader, prior_url_revision) = {
            let route = self
                .routes
                .get(target_id)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            (route.document.loader_id.clone(), route.url_revision)
        };
        let result = self
            .command_event_first(
                "Page.navigateToHistoryEntry",
                json!({ "entryId": entry_id }),
                Some(cdp_session_id),
                None,
                guarded,
                deadline,
            )
            .await?;
        self.await_history_lifecycle(
            target_id,
            prior_loader.as_deref(),
            prior_url_revision,
            WorkerNavigateWaitUntil::Load,
            deadline,
        )
        .await?;
        Ok(result)
    }

    /// Awaits the document a `Page.navigateToHistoryEntry` produces.
    ///
    /// Like reload, the traversal returns no `loaderId`. A cross-document entry commits a
    /// fresh loader and is awaited through the shared lifecycle wait; a same-document entry
    /// fires `Page.navigatedWithinDocument`, which advances `url_revision` without a new
    /// document and completes with no lifecycle to observe. The browser itself signals which
    /// occurred, so no URL heuristic is needed.
    async fn await_history_lifecycle(
        &mut self,
        target_id: &str,
        prior_loader: Option<&str>,
        prior_url_revision: u64,
        wait_until: WorkerNavigateWaitUntil,
        deadline: Option<Instant>,
    ) -> Result<(), OwnerActorError> {
        let expires_at = self.lifecycle_deadline(deadline);
        let expires = tokio::time::sleep_until(expires_at.into());
        tokio::pin!(expires);
        loop {
            let route = self
                .routes
                .get(target_id)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            match route.document.loader_id.as_deref() {
                Some(fresh) if Some(fresh) != prior_loader => {
                    let fresh = fresh.to_owned();
                    return self
                        .await_document_lifecycle(target_id, &fresh, wait_until, deadline)
                        .await;
                }
                _ if route.url_revision != prior_url_revision => return Ok(()),
                _ => {}
            }
            tokio::select! {
                biased;
                () = &mut expires => return Err(OwnerActorError::NavigationTimeout),
                incoming = self.events.recv() => {
                    let incoming = incoming.ok_or(OwnerActorError::OutcomeUncertain)?;
                    self.handle_incoming(incoming, None)?;
                }
            }
        }
    }

    async fn command_event_first(
        &mut self,
        method: &'static str,
        params: Value,
        session_id: Option<String>,
        mut catch_up: Option<&mut Vec<PausedTarget>>,
        guarded: Option<GuardedPageExecution>,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let client = self.client.clone();
        let command_timeout_cap = self.command_timeout;
        let command_deadline = deadline;
        let submitted = Arc::new(AtomicBool::new(false));
        let submitted_by_command = Arc::clone(&submitted);
        let command = async move {
            let command_timeout = match command_deadline {
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(OwnerActorError::DeadlineBeforeDispatch);
                    }
                    deadline.duration_since(now).min(command_timeout_cap)
                }
                None => command_timeout_cap,
            };
            submitted_by_command.store(true, Ordering::Release);
            client
                .command(method, params, session_id, Some(command_timeout))
                .await
                .map_err(map_command_error)
        };
        let expires = async move {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(command);
        tokio::pin!(expires);
        loop {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(if submitted.load(Ordering::Acquire) {
                    OwnerActorError::OutcomeUncertain
                } else {
                    OwnerActorError::DeadlineBeforeDispatch
                });
            }
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
                () = &mut expires => {
                    return Err(if submitted.load(Ordering::Acquire) {
                        OwnerActorError::OutcomeUncertain
                    } else {
                        OwnerActorError::DeadlineBeforeDispatch
                    });
                }
                incoming = self.events.recv() => {
                    let incoming = incoming.ok_or(OwnerActorError::OutcomeUncertain)?;
                    self.handle_incoming(incoming, catch_up.as_deref_mut())?;
                }
                response = &mut command => {
                    let response = response?;
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
                if self.retired_targets.contains_key(target.target_id()) {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                let context = self
                    .contexts
                    .get(&browser_context_id)
                    .ok_or(OwnerActorError::UnknownOwnership)?;
                match context.lifecycle {
                    ContextLifecycle::Active => {}
                    ContextLifecycle::DisposeRequested | ContextLifecycle::Disposing => {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
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
                    document: DocumentLoadState::default(),
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
                    if let Some(retired_session_id) = self.retired_targets.get(&target_id) {
                        return if retired_session_id == &session_id {
                            Ok(())
                        } else {
                            Err(OwnerActorError::OutcomeUncertain)
                        };
                    }
                    let route = self
                        .routes
                        .get(&target_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if route.route.session_id != session_id {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                    let context = self
                        .contexts
                        .get(route.route.browser_context_id())
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if context.lifecycle == ContextLifecycle::Active
                        && context.emulation_owner_target_id.as_deref() == Some(target_id.as_str())
                    {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                    let route = self
                        .routes
                        .remove(&target_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if self.retired_targets.len() >= MAX_RETIRED_TARGETS
                        || self
                            .retired_targets
                            .insert(target_id.clone(), route.route.session_id.clone())
                            .is_some()
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
                    let target_id = match self.routes.iter().find_map(|(target_id, entry)| {
                        (entry.route.session_id == session_id).then(|| target_id.clone())
                    }) {
                        Some(target_id) => target_id,
                        None if self
                            .retired_targets
                            .values()
                            .any(|retired_session_id| retired_session_id == &session_id) =>
                        {
                            return Ok(());
                        }
                        None => return Err(OwnerActorError::OutcomeUncertain),
                    };
                    let route = self
                        .routes
                        .get(&target_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    let context = self
                        .contexts
                        .get(route.route.browser_context_id())
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if context.lifecycle == ContextLifecycle::Active
                        && context.emulation_owner_target_id.as_deref() == Some(target_id.as_str())
                    {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                    let route = self
                        .routes
                        .remove(&target_id)
                        .ok_or(OwnerActorError::OutcomeUncertain)?;
                    if self.retired_targets.len() >= MAX_RETIRED_TARGETS
                        || self
                            .retired_targets
                            .insert(target_id.clone(), route.route.session_id.clone())
                            .is_some()
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
                if self.retired_targets.contains_key(&target_id) {
                    return Ok(());
                }
                let route = self
                    .routes
                    .get(&target_id)
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let context = self
                    .contexts
                    .get(route.route.browser_context_id())
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                if context.lifecycle == ContextLifecycle::Active
                    && context.emulation_owner_target_id.as_deref() == Some(target_id.as_str())
                {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                let route = self
                    .routes
                    .remove(&target_id)
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                if self.retired_targets.len() >= MAX_RETIRED_TARGETS
                    || self
                        .retired_targets
                        .insert(target_id.clone(), route.route.session_id.clone())
                        .is_some()
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
                    let loader_id = frame
                        .get("loaderId")
                        .and_then(Value::as_str)
                        .filter(|loader_id| valid_identifier(loader_id))
                        .map(str::to_owned);
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
                    route.document = DocumentLoadState {
                        loader_id,
                        dom_content_loaded: false,
                        loaded: false,
                    };
                }
            }
            "Page.domContentEventFired" | "Page.loadEventFired" => {
                // Both events describe the target's main frame only. Events for retired
                // targets carry no ownership consequence, so they are ignored rather than
                // treated as a protocol fault.
                let Some(session_id) = event_session_id
                    .as_deref()
                    .filter(|session_id| valid_identifier(session_id))
                else {
                    return Ok(());
                };
                if let Some(route) = self
                    .routes
                    .values_mut()
                    .find(|route| route.route.session_id == session_id)
                {
                    route.document.dom_content_loaded = true;
                    if method == "Page.loadEventFired" {
                        route.document.loaded = true;
                    }
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

/// A JS function and its CDP call arguments to run on a resolved node.
struct NodeFunctionCall<'a> {
    declaration: &'a str,
    arguments: Value,
}

/// The document identity a node handle is bound to and resolved against.
struct NodeDocumentState {
    session_incarnation: SessionIncarnation,
    target_incarnation: TargetIncarnation,
    frame_document_epoch: DocumentEpoch,
    url_revision: u64,
}

/// Wall-clock milliseconds for the node-handle store's coarse TTL and LRU accounting.
fn node_store_now() -> TargetTime {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    TargetTime::new(millis)
}

/// A resolved keyboard key ready for `Input.dispatchKeyEvent`.
struct KeyStroke {
    key: String,
    code: String,
    virtual_key_code: i64,
    text: Option<String>,
}

/// Resolves a `press_key` key name into the CDP fields a key event needs.
///
/// Named keys (Enter, Tab, arrows, editing and navigation keys) carry the virtual key code
/// Chromium requires to trigger their default action; a single printable character is sent
/// as inserted text with a best-effort code. Anything else is unresolvable and rejected.
fn resolve_key_stroke(key: &str) -> Option<KeyStroke> {
    let named = |code: &str, virtual_key_code: i64, text: Option<&str>| KeyStroke {
        key: key.to_owned(),
        code: code.to_owned(),
        virtual_key_code,
        text: text.map(str::to_owned),
    };
    let stroke = match key {
        "Enter" => named("Enter", 13, Some("\r")),
        "Tab" => named("Tab", 9, Some("\t")),
        "Backspace" => named("Backspace", 8, None),
        "Delete" => named("Delete", 46, None),
        "Escape" => named("Escape", 27, None),
        "ArrowUp" => named("ArrowUp", 38, None),
        "ArrowDown" => named("ArrowDown", 40, None),
        "ArrowLeft" => named("ArrowLeft", 37, None),
        "ArrowRight" => named("ArrowRight", 39, None),
        "Home" => named("Home", 36, None),
        "End" => named("End", 35, None),
        "PageUp" => named("PageUp", 33, None),
        "PageDown" => named("PageDown", 34, None),
        " " => named("Space", 32, Some(" ")),
        other => {
            let mut chars = other.chars();
            match (chars.next(), chars.next()) {
                (Some(character), None) => {
                    let (code, virtual_key_code) = if character.is_ascii_alphabetic() {
                        let upper = character.to_ascii_uppercase();
                        (format!("Key{upper}"), i64::from(u32::from(upper)))
                    } else if character.is_ascii_digit() {
                        (format!("Digit{character}"), i64::from(u32::from(character)))
                    } else {
                        (String::new(), 0)
                    };
                    KeyStroke {
                        key: other.to_owned(),
                        code,
                        virtual_key_code,
                        text: Some(other.to_owned()),
                    }
                }
                _ => return None,
            }
        }
    };
    Some(stroke)
}

/// Resolves the history entry `delta` positions from the current one into its CDP entry id.
///
/// Returns `Rejected` when no entry exists in that direction (the caller asked to go back
/// from the first entry or forward from the last), and `OutcomeUncertain` when the history
/// payload is malformed.
fn select_history_entry(history: &Value, delta: i64) -> Result<i64, OwnerActorError> {
    let object = history
        .as_object()
        .ok_or(OwnerActorError::OutcomeUncertain)?;
    let current_index = object
        .get("currentIndex")
        .and_then(Value::as_i64)
        .ok_or(OwnerActorError::OutcomeUncertain)?;
    let entries = object
        .get("entries")
        .and_then(Value::as_array)
        .ok_or(OwnerActorError::OutcomeUncertain)?;
    let len = i64::try_from(entries.len()).map_err(|_| OwnerActorError::OutcomeUncertain)?;
    if current_index < 0 || current_index >= len {
        return Err(OwnerActorError::OutcomeUncertain);
    }
    let target_index = current_index
        .checked_add(delta)
        .ok_or(OwnerActorError::OutcomeUncertain)?;
    if target_index < 0 || target_index >= len {
        return Err(OwnerActorError::Rejected);
    }
    let index = usize::try_from(target_index).map_err(|_| OwnerActorError::OutcomeUncertain)?;
    entries
        .get(index)
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_i64)
        .ok_or(OwnerActorError::OutcomeUncertain)
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
        OwnerActorError::Rejected
        | OwnerActorError::NavigationInterrupted
        | OwnerActorError::NavigationTimeout => BootstrapStageFailure::Rejected,
        OwnerActorError::DeadlineBeforeDispatch
        | OwnerActorError::StateOverflow
        | OwnerActorError::Unavailable
        | OwnerActorError::OutcomeUncertain => BootstrapStageFailure::StateOverflow,
    }
}

fn map_actor_runtime_error(error: OwnerActorError) -> ShardRuntimeError {
    match error {
        OwnerActorError::Rejected
        | OwnerActorError::UnknownOwnership
        | OwnerActorError::NavigationInterrupted
        | OwnerActorError::NavigationTimeout => ShardRuntimeError::Rejected,
        OwnerActorError::StateOverflow | OwnerActorError::Unavailable => {
            ShardRuntimeError::Unavailable
        }
        OwnerActorError::DeadlineBeforeDispatch | OwnerActorError::OutcomeUncertain => {
            ShardRuntimeError::OutcomeUncertain
        }
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use browserd_chromium::Sha256Digest;
    use browserd_core::{
        EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionIncarnation, ShardId,
        WorkerEpoch, WorkerId,
    };
    use browserd_sandbox::{ChromiumBinaryDigest, DedicatedEgressSpec, EgressPolicyBinding};

    struct PublicationOrderProbe {
        completion: Mutex<watch::Receiver<Option<Result<(), ShardRuntimeError>>>>,
        failed_before_completion: AtomicBool,
    }

    impl FailureSink for PublicationOrderProbe {
        fn fail_closed(&self) {
            let completion_is_pending = self
                .completion
                .lock()
                .is_ok_and(|completion| completion.borrow().is_none());
            self.failed_before_completion
                .store(completion_is_pending, Ordering::Release);
        }
    }

    struct NoopDrain;

    impl TargetManagerDrain for NoopDrain {
        fn begin_drain(&self) {}
    }

    fn test_identity() -> ChromiumArtifactIdentity {
        let digest = Sha256Digest::from_hex(&"07".repeat(32)).expect("digest should be valid");
        ChromiumArtifactIdentity {
            binary_digest: digest,
            product_version: "149.0.7827.55".to_owned(),
            chromium_revision: "r1234567".to_owned(),
            browser_protocol_schema_digest: digest,
            js_protocol_schema_digest: digest,
            launch_profile_digest: digest,
            extension_bundle_digest: digest,
            font_bundle_digest: digest,
            certificate_runtime_bundle_digest: digest,
        }
    }

    fn test_fence() -> ShardFence {
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new("owner-result-convergence").expect("worker ID should be valid"),
                WorkerEpoch::new(9).expect("worker epoch should be valid"),
            ),
            ShardId::new(),
            LaunchGeneration::new(3).expect("launch generation should be valid"),
        )
    }

    fn test_launch_spec(fence: &ShardFence) -> LaunchSpec {
        let egress = EgressFence::new(
            fence.clone(),
            RouteGeneration::new(1).expect("route generation should be valid"),
            SessionId::new(),
            SessionIncarnation::new(1).expect("session incarnation should be valid"),
        );
        let dedicated = DedicatedEgressSpec::new(
            egress,
            EgressPolicyBinding::new("strict", [7; 32]).expect("policy should be valid"),
            Duration::from_secs(30),
        )
        .expect("dedicated egress should be valid");
        LaunchSpec::production(
            TenantId::new(),
            dedicated,
            ChromiumBinaryDigest::new([7; 32]),
        )
    }

    #[test]
    fn owner_error_fails_closed_before_completion_publication() {
        let mailbox = Arc::new(OwnerMailbox::new(Duration::from_secs(1)));
        let (completion, receiver) = watch::channel(None);
        let probe = Arc::new(PublicationOrderProbe {
            completion: Mutex::new(receiver.clone()),
            failed_before_completion: AtomicBool::new(false),
        });
        let sink: Arc<dyn FailureSink> = probe.clone();
        assert!(mailbox.bind_failure_sink(sink).is_ok());

        publish_owner_thread_result(
            &Arc::downgrade(&mailbox),
            &completion,
            Err(ShardRuntimeError::OutcomeUncertain),
        );

        assert!(probe.failed_before_completion.load(Ordering::Acquire));
        assert_eq!(
            *receiver.borrow(),
            Some(Err(ShardRuntimeError::OutcomeUncertain))
        );
        assert!(
            mailbox
                .endpoint
                .lock()
                .is_ok_and(|endpoint| matches!(*endpoint, OwnerEndpoint::Terminal))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_join_waiters_converge_after_exact_termination_is_confirmed() {
        let fence = test_fence();
        let launch_spec = test_launch_spec(&fence);
        let proof = SandboxTerminationProof::from_test_launch_spec(launch_spec.clone());
        let owner = ChromiumConnectionOwner::new_bounded_for_launch(
            test_identity(),
            ChromiumConnectionConfig::default(),
            fence,
            8,
            Arc::new(NoopDrain),
            launch_spec,
        )
        .expect("owner should be valid")
        .0;
        owner.accepted.store(true, Ordering::Release);
        assert!(owner.confirm_forced_termination(&proof));

        let first = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.shutdown_and_join(Duration::from_secs(1)).await }
        });
        let second = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.shutdown_and_join(Duration::from_secs(1)).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.thread.completion.receiver_count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both cleanup waiters should subscribe");
        {
            let mut join = owner
                .thread
                .join
                .lock()
                .expect("join state should remain available");
            join.result = Some(Err(ShardRuntimeError::OutcomeUncertain));
            join.structurally_terminal = true;
        }
        owner
            .thread
            .completion
            .send_replace(Some(Err(ShardRuntimeError::OutcomeUncertain)));

        assert_eq!(first.await.expect("first waiter should join"), Ok(()));
        assert_eq!(second.await.expect("second waiter should join"), Ok(()));
    }

    #[test]
    fn exact_proof_cannot_confirm_a_different_launch_with_the_same_shard_fence() {
        let fence = test_fence();
        let terminated_spec = test_launch_spec(&fence);
        let different_spec = test_launch_spec(&fence);
        assert_ne!(terminated_spec, different_spec);
        let proof = SandboxTerminationProof::from_test_launch_spec(terminated_spec);
        let owner = ChromiumConnectionOwner::new_bounded_for_launch(
            test_identity(),
            ChromiumConnectionConfig::default(),
            fence,
            8,
            Arc::new(NoopDrain),
            different_spec,
        )
        .expect("owner should be valid")
        .0;

        assert!(!owner.confirm_forced_termination(&proof));
        assert!(!owner.is_terminally_joined_after(&proof));
    }
}
