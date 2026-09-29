#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{
    ActionKind, ActionSequence, ActionSnapshot, KnownFailureReason, OutcomeUnknownReason,
    ResolutionAnnotation, ResolutionKind, ResultDigest, TerminalDetail,
};
use browserd_api::{
    ActionGetRequest, ActionPayload, ActionResolveBody, ActionResolveRequest, ActionSubmitCommand,
    ActionSubmitRequest, ApiRequest, ApiResponse, ApiRouter, ApiService, ResolutionRequestKind,
    decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    CoordinationActorConfig, EventCursor, EventOutboxBlockingClient, GatewayActionCoordination,
    GatewayActionSnapshot, MemoryEventOutbox, MemoryGatewayActionStore, OutboxAggregate,
    OutboxEventKind,
};
use browserd_core::{
    ActionId, ActionState, ErrorCode, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_worker::{
    WorkerActionReceipt, WorkerActionStatus, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerIsolationProfile, WorkerRpcCompletionError,
    WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcRequest, WorkerRpcResponse,
};
use chrono::Utc;
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Result body a `Succeed` completion returns; the receipt's digest is `sha256` of these bytes.
const SUCCEEDED_RESULT_BODY: &[u8] = br#"{"title":"durable result body"}"#;

const CREATE_JSON: &str = r#"{
  "isolation":"shared_context",
  "workload_class_hint":"interactive",
  "viewport":{"width":1280,"height":720,"device_scale_factor":1},
  "locale":"ko-KR",
  "timezone":"Asia/Seoul",
  "user_agent":null,
  "network_policy_id":"public-web-default",
  "network_class":"public",
  "checkpoint_ref":null,
  "dialog_policy":"auto_dismiss",
  "feature_profile":"standard",
  "ttl_seconds":1800,
  "idle_timeout_seconds":600,
  "metadata":{"agent_run_id":"durable-action-runtime"}
}"#;

#[derive(Clone, Copy)]
enum EnqueueMode {
    Queued,
    Succeed,
    Full,
    Timeout,
    ExchangeTimeout,
}

#[derive(Clone, Debug)]
struct EnqueuedAction {
    tenant_id: TenantId,
    session_id: SessionId,
    action_id: ActionId,
    action_sequence: ActionSequence,
    idempotency_key: String,
    canonical_request_hash: [u8; 32],
    kind: ActionKind,
    page_id: Option<PageId>,
}

#[derive(Default)]
struct ReleaseGate {
    released: Mutex<bool>,
    condition: Condvar,
}

impl ReleaseGate {
    fn wait(&self) -> Result<(), WorkerRpcCompletionError> {
        let mut released = self
            .released
            .lock()
            .map_err(|_| WorkerRpcCompletionError::Disconnected)?;
        while !*released {
            released = self
                .condition
                .wait(released)
                .map_err(|_| WorkerRpcCompletionError::Disconnected)?;
        }
        Ok(())
    }

    fn release(&self) -> Result<(), &'static str> {
        let mut released = self.released.lock().map_err(|_| "gate lock poisoned")?;
        *released = true;
        self.condition.notify_all();
        Ok(())
    }
}

struct ControlledPending {
    request: WorkerRpcRequest,
    mode: EnqueueMode,
    entered: mpsc::Sender<()>,
    gate: Arc<ReleaseGate>,
}

impl GatewayWorkerPending for ControlledPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        self.entered
            .send(())
            .map_err(|_| WorkerRpcCompletionError::Disconnected)?;
        self.gate.wait()?;
        if matches!(self.mode, EnqueueMode::Timeout) {
            return Err(WorkerRpcCompletionError::Timeout);
        }
        if matches!(self.mode, EnqueueMode::ExchangeTimeout) {
            return Err(WorkerRpcCompletionError::Exchange(WorkerRpcError::Timeout));
        }
        let WorkerRpcRequest::SubmitAction {
            fence,
            action_id,
            action_sequence,
            idempotency_key,
            canonical_request_hash,
            kind,
            ..
        } = self.request
        else {
            return Err(WorkerRpcCompletionError::Exchange(
                WorkerRpcError::InvalidRequest,
            ));
        };
        if matches!(self.mode, EnqueueMode::Succeed) {
            let digest = ResultDigest::new(Sha256::digest(SUCCEEDED_RESULT_BODY).into());
            return Ok(WorkerRpcResponse::Action(WorkerActionReceipt {
                fence,
                action_id,
                action_sequence,
                idempotency_key,
                canonical_request_hash,
                kind,
                status: WorkerActionStatus::Succeeded,
                dispatch_acknowledged: true,
                approval_decision: None,
                terminal_detail: Some(TerminalDetail::Succeeded(digest)),
                result: Some(SUCCEEDED_RESULT_BODY.to_vec()),
                resolution: None,
            }));
        }
        Ok(WorkerRpcResponse::Action(WorkerActionReceipt {
            fence,
            action_id,
            action_sequence,
            idempotency_key,
            canonical_request_hash,
            kind,
            status: WorkerActionStatus::Queued,
            dispatch_acknowledged: false,
            approval_decision: None,
            terminal_detail: None,
            result: None,
            resolution: None,
        }))
    }
}

struct ActionWorker {
    tenant_id: TenantId,
    session_id: SessionId,
    page_id: PageId,
    mode: EnqueueMode,
    enqueue_count: AtomicUsize,
    request_count: AtomicUsize,
    enqueued: Mutex<Vec<EnqueuedAction>>,
    pending_entered: mpsc::Sender<()>,
    pending_gate: Arc<ReleaseGate>,
}

impl GatewayWorkerClient for ActionWorker {
    type PendingAction = ControlledPending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        if request.tenant_id != self.tenant_id {
            return Err(WorkerRpcError::Protocol);
        }
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: self.session_id.clone(),
            session_incarnation: request.session_incarnation,
            effective_isolation: WorkerIsolationProfile::SharedContext,
            primary_page_id: self.page_id.clone(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            existing: false,
        })
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.request_count.fetch_add(1, Ordering::AcqRel);
        let WorkerRpcRequest::ResolveAction {
            fence,
            action_id,
            resolution,
            resolved_by,
            basis,
            now_unix_millis,
        } = request
        else {
            return Err(WorkerRpcError::InvalidRequest);
        };
        let action = self
            .enqueued
            .lock()
            .map_err(|_| WorkerRpcError::Runtime)?
            .iter()
            .find(|action| action.action_id == action_id)
            .cloned()
            .ok_or(WorkerRpcError::InvalidRequest)?;
        Ok(WorkerRpcResponse::Action(WorkerActionReceipt {
            fence,
            action_id,
            action_sequence: action.action_sequence,
            idempotency_key: action.idempotency_key,
            canonical_request_hash: action.canonical_request_hash,
            kind: action.kind,
            status: WorkerActionStatus::OutcomeUnknown,
            dispatch_acknowledged: true,
            approval_decision: None,
            terminal_detail: Some(TerminalDetail::OutcomeUnknown(
                OutcomeUnknownReason::TimeoutAfterDispatch,
            )),
            result: None,
            resolution: Some(ResolutionAnnotation::new(
                resolution,
                resolved_by,
                now_unix_millis,
                basis,
            )),
        }))
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        let observation = match &request {
            WorkerRpcRequest::SubmitAction {
                fence,
                action_id,
                action_sequence,
                idempotency_key,
                canonical_request_hash,
                kind,
                page_id,
                ..
            } => EnqueuedAction {
                tenant_id: fence.tenant_id.clone(),
                session_id: fence.session_id.clone(),
                action_id: action_id.clone(),
                action_sequence: *action_sequence,
                idempotency_key: idempotency_key.clone(),
                canonical_request_hash: *canonical_request_hash,
                kind: *kind,
                page_id: page_id.clone(),
            },
            _ => return Err(WorkerRpcEnqueueError::Closed(Box::new(request))),
        };
        self.enqueue_count.fetch_add(1, Ordering::AcqRel);
        self.enqueued
            .lock()
            .map_err(|_| WorkerRpcEnqueueError::Closed(Box::new(request.clone())))?
            .push(observation);
        if matches!(self.mode, EnqueueMode::Full) {
            return Err(WorkerRpcEnqueueError::Full(Box::new(request)));
        }
        Ok(ControlledPending {
            request,
            mode: self.mode,
            entered: self.pending_entered.clone(),
            gate: Arc::clone(&self.pending_gate),
        })
    }
}

type ActionRouter = ApiRouter<GatewayWorkerRuntime<ActionWorker>>;

struct Fixture {
    principal: AuthenticatedPrincipal,
    worker: Arc<ActionWorker>,
    router: Arc<ActionRouter>,
    store: Arc<MemoryGatewayActionStore>,
    outbox: Option<EventOutboxBlockingClient>,
    session_id: SessionId,
    pending_entered: mpsc::Receiver<()>,
}

impl Fixture {
    fn new(mode: EnqueueMode) -> Result<Self, Box<dyn Error>> {
        Self::build(mode, None)
    }

    /// A fixture whose runtime records terminal transitions to a durable event outbox (BRD-017);
    /// the returned [`Fixture::outbox`] is a handle for asserting the recorded stream.
    fn new_with_outbox(mode: EnqueueMode) -> Result<Self, Box<dyn Error>> {
        let outbox: Arc<dyn browserd_coordination::EventOutbox> =
            Arc::new(MemoryEventOutbox::default());
        let client = EventOutboxBlockingClient::spawn(outbox, 2)?;
        Self::build(mode, Some(client))
    }

    fn build(
        mode: EnqueueMode,
        outbox: Option<EventOutboxBlockingClient>,
    ) -> Result<Self, Box<dyn Error>> {
        let tenant_id = TenantId::new();
        let principal = authenticated_principal(tenant_id.clone())?;
        let (pending_entered_sender, pending_entered) = mpsc::channel();
        let worker = Arc::new(ActionWorker {
            tenant_id,
            session_id: SessionId::new(),
            page_id: PageId::new(),
            mode,
            enqueue_count: AtomicUsize::new(0),
            request_count: AtomicUsize::new(0),
            enqueued: Mutex::new(Vec::new()),
            pending_entered: pending_entered_sender,
            pending_gate: Arc::new(ReleaseGate::default()),
        });
        let store = Arc::new(MemoryGatewayActionStore::default());
        let actor_config =
            CoordinationActorConfig::new(256, 32, Duration::from_secs(2), Duration::from_secs(5))?;
        let placement =
            GatewayWorkerPlacement::new(WorkerId::new("durable-action-worker")?, 41, 7, 29)?;
        let mut runtime = GatewayWorkerRuntime::with_action_coordination(
            Arc::clone(&worker),
            placement,
            Arc::clone(&store),
            actor_config,
        )?;
        if let Some(client) = outbox.clone() {
            runtime = runtime.with_terminal_event_outbox(client);
        }
        let runtime = Arc::new(runtime);
        let router = Arc::new(ApiRouter::new(runtime));
        let response = router.execute(
            &principal,
            ApiRequest::CreateSession {
                body: decode_session_create(CREATE_JSON)?,
                idempotency_key: Uuid::new_v4().to_string(),
                received_at: Instant::now(),
            },
        )?;
        let ApiResponse::SessionCreate(response) = response else {
            return Err("unexpected create-session response".into());
        };
        let session_id = response
            .data()
            .operation()
            .session()
            .map(|session| session.id.clone())
            .ok_or("created session is missing")?;
        if session_id != worker.session_id {
            return Err("gateway retained a different session ID".into());
        }
        Ok(Self {
            principal,
            worker,
            router,
            store,
            outbox,
            session_id,
            pending_entered,
        })
    }

    fn command(&self, idempotency_key: Uuid) -> ActionSubmitCommand {
        ActionSubmitCommand {
            session_id: self.session_id.clone(),
            idempotency_key,
            body: ActionSubmitRequest {
                page_id: self.worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 1_000,
                action: ActionPayload::GetTitle,
            },
        }
    }

    fn mutating_command(&self, idempotency_key: Uuid) -> ActionSubmitCommand {
        let mut command = self.command(idempotency_key);
        command.body.action = ActionPayload::Reload;
        command
    }

    fn release_pending(&self) -> Result<(), Box<dyn Error>> {
        self.pending_entered
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "action pending did not enter wait")?;
        self.worker.pending_gate.release()?;
        Ok(())
    }
}

fn submit_after_releasing_pending(
    fixture: &Fixture,
    command: ActionSubmitCommand,
) -> Result<ActionSnapshot, Box<dyn Error>> {
    let router = Arc::clone(&fixture.router);
    let principal = fixture.principal.clone();
    let (result_sender, result_receiver) = mpsc::channel();
    let caller = thread::spawn(move || {
        let result = router
            .execute(&principal, ApiRequest::SubmitAction(command))
            .map_err(|error| error.to_string())
            .and_then(action_snapshot);
        let _ = result_sender.send(result);
    });
    fixture.release_pending()?;
    let snapshot = result_receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "action caller did not finish")??;
    caller.join().map_err(|_| "action caller panicked")?;
    Ok(snapshot)
}

fn authenticated_principal(tenant_id: TenantId) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
    let secret = [17_u8; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("durable-action-runtime", Algorithm::HS256, &secret)?;
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let signer = ServiceTokenSigner::new("durable-action-runtime", Algorithm::HS256, &secret);
    let token = signer.sign(&ServiceClaims::new(
        "issuer",
        "audience",
        PrincipalId::new(),
        tenant_id,
        BTreeSet::from([
            "session:create".to_owned(),
            "session:read".to_owned(),
            "browser:act".to_owned(),
        ]),
        "durable-action-runtime",
        1,
        100,
        None,
    ))?;
    Ok(verifier.verify_at(&token, None, 10)?)
}

fn action_snapshot(response: ApiResponse) -> Result<ActionSnapshot, String> {
    let ApiResponse::Action(response) = response else {
        return Err("unexpected non-action response".to_owned());
    };
    Ok(response.data().clone())
}

fn stored_action(
    store: &MemoryGatewayActionStore,
    tenant_id: &TenantId,
    session_id: &SessionId,
    action_id: &ActionId,
) -> Result<GatewayActionSnapshot, Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(store.get_effective_action(tenant_id, session_id, action_id))?
        .ok_or_else(|| "durable action is missing".into())
}

#[test]
fn concurrent_exact_submissions_converge_and_enqueue_once() -> Result<(), Box<dyn Error>> {
    const CALLERS: usize = 32;
    let fixture = Fixture::new(EnqueueMode::Queued)?;
    let idempotency_key = Uuid::new_v4();
    let start = Arc::new(Barrier::new(CALLERS + 1));
    let (result_sender, result_receiver) = mpsc::channel();
    let mut callers = Vec::with_capacity(CALLERS);

    for _ in 0..CALLERS {
        let router = Arc::clone(&fixture.router);
        let principal = fixture.principal.clone();
        let command = fixture.command(idempotency_key);
        let start = Arc::clone(&start);
        let result_sender = result_sender.clone();
        callers.push(thread::spawn(move || {
            start.wait();
            let result = router
                .execute(&principal, ApiRequest::SubmitAction(command))
                .map_err(|error| error.to_string())
                .and_then(action_snapshot);
            let _ = result_sender.send(result);
        }));
    }
    drop(result_sender);
    start.wait();
    fixture.release_pending()?;

    let mut snapshots = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        snapshots.push(
            result_receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| "concurrent action caller did not finish")??,
        );
    }
    for caller in callers {
        caller.join().map_err(|_| "action caller panicked")?;
    }

    let action_ids = snapshots
        .iter()
        .map(|snapshot| snapshot.action_id().clone())
        .collect::<HashSet<_>>();
    let sequences = snapshots
        .iter()
        .map(|snapshot| snapshot.action_sequence().get())
        .collect::<HashSet<_>>();
    assert_eq!(action_ids.len(), 1);
    assert_eq!(sequences.len(), 1);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);

    let action_id = action_ids
        .into_iter()
        .next()
        .ok_or("concurrent action ID is missing")?;
    let stored = stored_action(
        fixture.store.as_ref(),
        fixture.principal.tenant_id(),
        &fixture.session_id,
        &action_id,
    )?;
    let enqueued = fixture
        .worker
        .enqueued
        .lock()
        .map_err(|_| "enqueued action lock poisoned")?;
    assert_eq!(enqueued.len(), 1);
    let wire = &enqueued[0];
    assert_eq!(wire.tenant_id, *fixture.principal.tenant_id());
    assert_eq!(wire.session_id, fixture.session_id);
    assert_eq!(wire.action_id, *stored.action_id());
    assert_eq!(wire.action_sequence, stored.action_sequence());
    assert_eq!(wire.idempotency_key, stored.idempotency_key());
    assert_eq!(
        wire.canonical_request_hash,
        *stored.request_hash().as_bytes()
    );
    assert_eq!(wire.kind, stored.kind());
    assert_eq!(wire.page_id.as_ref(), Some(&fixture.worker.page_id));
    Ok(())
}

#[test]
fn enqueue_full_is_terminal_not_dispatched_and_retry_does_not_enqueue() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new(EnqueueMode::Full)?;
    let idempotency_key = Uuid::new_v4();
    let first = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(idempotency_key)),
    )?)?;
    assert_eq!(first.state(), ActionState::FailedKnown);
    assert_eq!(
        first.terminal_detail(),
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::NotDispatched
        ))
    );

    let retried = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(idempotency_key)),
    )?)?;
    assert_eq!(retried.action_id(), first.action_id());
    assert_eq!(retried.action_sequence(), first.action_sequence());
    assert_eq!(retried.state(), ActionState::FailedKnown);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);

    let stored = stored_action(
        fixture.store.as_ref(),
        fixture.principal.tenant_id(),
        &fixture.session_id,
        first.action_id(),
    )?;
    assert_eq!(stored.action_id(), first.action_id());
    assert_eq!(stored.action_sequence(), first.action_sequence());
    assert_eq!(
        stored.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::NotDispatched
        ))
    );
    Ok(())
}

#[test]
fn completion_timeout_is_terminal_unknown_and_retry_does_not_enqueue() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new(EnqueueMode::Timeout)?;
    let idempotency_key = Uuid::new_v4();
    let router = Arc::clone(&fixture.router);
    let principal = fixture.principal.clone();
    let command = fixture.command(idempotency_key);
    let (result_sender, result_receiver) = mpsc::channel();
    let caller = thread::spawn(move || {
        let result = router
            .execute(&principal, ApiRequest::SubmitAction(command))
            .map_err(|error| error.to_string())
            .and_then(action_snapshot);
        let _ = result_sender.send(result);
    });
    fixture.release_pending()?;
    let first = result_receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "timed-out action caller did not finish")??;
    caller.join().map_err(|_| "timed-out caller panicked")?;

    assert_eq!(first.state(), ActionState::OutcomeUnknown);
    assert_eq!(
        first.terminal_detail(),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::TimeoutAfterDispatch
        ))
    );
    let retried = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(idempotency_key)),
    )?)?;
    assert_eq!(retried.action_id(), first.action_id());
    assert_eq!(retried.action_sequence(), first.action_sequence());
    assert_eq!(retried.state(), ActionState::OutcomeUnknown);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);

    let stored = stored_action(
        fixture.store.as_ref(),
        fixture.principal.tenant_id(),
        &fixture.session_id,
        first.action_id(),
    )?;
    assert_eq!(stored.action_id(), first.action_id());
    assert_eq!(stored.action_sequence(), first.action_sequence());
    assert_eq!(
        stored.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::TimeoutAfterDispatch
        ))
    );
    Ok(())
}

#[test]
fn exchange_timeout_after_handoff_is_timeout_after_dispatch() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::ExchangeTimeout)?;
    let idempotency_key = Uuid::new_v4();
    let router = Arc::clone(&fixture.router);
    let principal = fixture.principal.clone();
    let command = fixture.command(idempotency_key);
    let (result_sender, result_receiver) = mpsc::channel();
    let caller = thread::spawn(move || {
        let result = router
            .execute(&principal, ApiRequest::SubmitAction(command))
            .map_err(|error| error.to_string())
            .and_then(action_snapshot);
        let _ = result_sender.send(result);
    });
    fixture.release_pending()?;
    let snapshot = result_receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "exchange-timeout action caller did not finish")??;
    caller
        .join()
        .map_err(|_| "exchange-timeout caller panicked")?;

    assert_eq!(snapshot.state(), ActionState::OutcomeUnknown);
    assert_eq!(
        snapshot.terminal_detail(),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::TimeoutAfterDispatch
        ))
    );
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn unknown_mutation_blocks_new_mutation_without_another_enqueue() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Timeout)?;
    let unknown =
        submit_after_releasing_pending(&fixture, fixture.mutating_command(Uuid::new_v4()))?;
    assert_eq!(unknown.state(), ActionState::OutcomeUnknown);
    assert_eq!(
        unknown.terminal_detail(),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::TimeoutAfterDispatch,
        ))
    );
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);

    let Err(error) = fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.mutating_command(Uuid::new_v4())),
    ) else {
        return Err("a new mutation unexpectedly bypassed reconciliation".into());
    };
    assert_eq!(error.code(), ErrorCode::ReconciliationRequired);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    assert_eq!(fixture.worker.request_count.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn durable_resolution_reopens_mutating_dispatch() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Timeout)?;
    let unknown =
        submit_after_releasing_pending(&fixture, fixture.mutating_command(Uuid::new_v4()))?;
    assert_eq!(unknown.state(), ActionState::OutcomeUnknown);

    let basis = "post-read verification found no side effect";
    let resolved = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::ResolveAction(ActionResolveRequest {
            session_id: fixture.session_id.clone(),
            action_id: unknown.action_id().clone(),
            body: ActionResolveBody {
                resolution: ResolutionRequestKind::ConfirmedNotExecuted,
                basis: basis.to_owned(),
                note: None,
            },
        }),
    )?)?;
    let annotation = resolved
        .resolution()
        .ok_or("resolved action is missing its annotation")?;
    assert_eq!(annotation.kind(), ResolutionKind::ConfirmedNotExecuted);
    assert_eq!(annotation.resolved_by(), fixture.principal.principal_id());
    assert_eq!(annotation.basis(), basis);
    assert_eq!(resolved.state(), ActionState::OutcomeUnknown);

    let durable = stored_action(
        fixture.store.as_ref(),
        fixture.principal.tenant_id(),
        &fixture.session_id,
        unknown.action_id(),
    )?;
    assert_eq!(durable.resolution(), Some(annotation));
    assert_eq!(fixture.worker.request_count.load(Ordering::Acquire), 1);

    let next = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.mutating_command(Uuid::new_v4())),
    )?)?;
    assert_ne!(next.action_id(), unknown.action_id());
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 2);
    Ok(())
}

#[test]
fn concurrent_second_read_only_times_out_before_worker_enqueue() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Queued)?;
    let first_router = Arc::clone(&fixture.router);
    let first_principal = fixture.principal.clone();
    let first_command = fixture.command(Uuid::new_v4());
    let (first_sender, first_receiver) = mpsc::channel();
    let first_caller = thread::spawn(move || {
        let result = first_router
            .execute(&first_principal, ApiRequest::SubmitAction(first_command))
            .map_err(|error| error.to_string());
        let _ = first_sender.send(result);
    });

    let first_entered = fixture.pending_entered.recv_timeout(Duration::from_secs(5));
    if let Err(error) = first_entered {
        let release_result = fixture.worker.pending_gate.release();
        let first_result = first_receiver.recv_timeout(Duration::from_secs(5));
        let first_join = first_caller.join();
        release_result?;
        first_result.map_err(|_| "first read-only caller did not finish after gate release")??;
        first_join.map_err(|_| "first read-only caller panicked")?;
        return Err(format!("first read-only action did not enter worker wait: {error}").into());
    }

    let second_router = Arc::clone(&fixture.router);
    let second_principal = fixture.principal.clone();
    let second_command = fixture.command(Uuid::new_v4());
    let (second_sender, second_receiver) = mpsc::channel();
    let second_caller = thread::spawn(move || {
        let result =
            second_router.execute(&second_principal, ApiRequest::SubmitAction(second_command));
        let _ = second_sender.send(result);
    });

    let second_before_release = second_receiver.recv_timeout(Duration::from_secs(4));
    let release_result = fixture.worker.pending_gate.release();
    let first_result = first_receiver.recv_timeout(Duration::from_secs(5));
    let second_after_release = if second_before_release.is_err() {
        Some(second_receiver.recv_timeout(Duration::from_secs(5)))
    } else {
        None
    };
    let first_join = first_caller.join();
    let second_join = second_caller.join();

    release_result?;
    first_result.map_err(|_| "first read-only caller did not finish after gate release")??;
    first_join.map_err(|_| "first read-only caller panicked")?;
    second_join.map_err(|_| "second read-only caller panicked")?;

    let second = match second_before_release {
        Ok(result) => result,
        Err(error) => {
            let cleanup_result = second_after_release
                .ok_or("second read-only cleanup result is missing")?
                .map_err(|_| "second read-only caller did not finish after gate release")?;
            drop(cleanup_result);
            return Err(format!(
                "second read-only submission did not finish within its bounded admission window: {error}"
            )
            .into());
        }
    };
    let Err(error) = second else {
        return Err(
            "a contending read-only action unexpectedly returned a success snapshot".into(),
        );
    };
    assert_eq!(error.code(), ErrorCode::ActionAdmissionTimeout);
    assert!(error.retryable());
    assert!(matches!(
        fixture
            .pending_entered
            .recv_timeout(Duration::from_millis(250)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    assert_eq!(fixture.worker.request_count.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn concurrent_second_mutation_returns_retryable_admission_error_without_worker_call()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Queued)?;
    let first_router = Arc::clone(&fixture.router);
    let first_principal = fixture.principal.clone();
    let first_command = fixture.mutating_command(Uuid::new_v4());
    let (first_sender, first_receiver) = mpsc::channel();
    let first_caller = thread::spawn(move || {
        let result = first_router
            .execute(&first_principal, ApiRequest::SubmitAction(first_command))
            .map_err(|error| error.to_string());
        let _ = first_sender.send(result);
    });
    fixture
        .pending_entered
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "first mutation did not enter worker wait")?;

    let second_idempotency_key = Uuid::new_v4();
    let Err(error) = fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.mutating_command(second_idempotency_key)),
    ) else {
        return Err("a contending mutation unexpectedly returned a success snapshot".into());
    };
    assert_eq!(error.code(), ErrorCode::ActionAdmissionTimeout);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    assert_eq!(fixture.worker.request_count.load(Ordering::Acquire), 0);
    fixture.worker.pending_gate.release()?;
    first_receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "first mutation caller did not finish")??;
    first_caller
        .join()
        .map_err(|_| "first mutation caller panicked")?;
    let Err(retry_error) = fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.mutating_command(second_idempotency_key)),
    ) else {
        return Err("the first retry unexpectedly bypassed the active mutation".into());
    };
    assert_eq!(retry_error.code(), ErrorCode::ActionAdmissionTimeout);
    let retry = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.mutating_command(second_idempotency_key)),
    )?)?;
    assert_eq!(retry.state(), ActionState::CancelledBeforeDispatch);
    assert_eq!(
        retry.terminal_detail(),
        Some(TerminalDetail::CancelledBeforeDispatch)
    );
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn exact_resolution_retry_preserves_the_original_server_timestamp() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Timeout)?;
    let unknown =
        submit_after_releasing_pending(&fixture, fixture.mutating_command(Uuid::new_v4()))?;
    let durable = stored_action(
        fixture.store.as_ref(),
        fixture.principal.tenant_id(),
        &fixture.session_id,
        unknown.action_id(),
    )?;
    let basis = "same caller and resolution body";
    let annotation = browserd_actions::ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        fixture.principal.principal_id().clone(),
        1,
        basis,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(fixture.store.resolve_unknown(
        fixture.principal.tenant_id(),
        &fixture.session_id,
        unknown.action_id(),
        durable.revision(),
        durable.placement(),
        annotation.clone(),
        Utc::now(),
    ))?;

    let retried = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::ResolveAction(ActionResolveRequest {
            session_id: fixture.session_id.clone(),
            action_id: unknown.action_id().clone(),
            body: ActionResolveBody {
                resolution: ResolutionRequestKind::ConfirmedNotExecuted,
                basis: basis.to_owned(),
                note: None,
            },
        }),
    )?)?;
    assert_eq!(retried.resolution(), Some(&annotation));
    assert_eq!(fixture.worker.request_count.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn succeeded_result_body_is_durable_across_get_and_same_key_resubmission()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Succeed)?;
    let idempotency_key = Uuid::new_v4();

    // Live completion path: the reconciled snapshot the submit returns carries the result body,
    // not just its digest. This is the direct regression guard for R01 (gateway result loss).
    let completed = submit_after_releasing_pending(&fixture, fixture.command(idempotency_key))?;
    assert_eq!(completed.state(), ActionState::Succeeded);
    assert_eq!(completed.result_content(), Some(SUCCEEDED_RESULT_BODY));
    let action_id = completed.action_id().clone();

    // The durable store persists the body (the GET / same-key / restart source of truth).
    let stored = stored_action(
        &fixture.store,
        fixture.principal.tenant_id(),
        &fixture.session_id,
        &action_id,
    )?;
    assert_eq!(stored.result_content(), Some(SUCCEEDED_RESULT_BODY));

    // The API GET path surfaces the same bytes.
    let fetched = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::GetAction(ActionGetRequest {
            session_id: fixture.session_id.clone(),
            action_id: action_id.clone(),
        }),
    )?)?;
    assert_eq!(fetched.state(), ActionState::Succeeded);
    assert_eq!(fetched.result_content(), Some(SUCCEEDED_RESULT_BODY));

    // Same-key resubmission returns the cached terminal result with the same body and does not
    // re-enqueue the action against the worker.
    let resubmitted = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(idempotency_key)),
    )?)?;
    assert_eq!(resubmitted.action_id(), &action_id);
    assert_eq!(resubmitted.state(), ActionState::Succeeded);
    assert_eq!(resubmitted.result_content(), Some(SUCCEEDED_RESULT_BODY));
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn terminal_action_is_retrievable_after_a_gateway_restart_without_a_live_session()
-> Result<(), Box<dyn Error>> {
    // Complete a succeeded action so the durable action store holds its terminal result body.
    let fixture = Fixture::new(EnqueueMode::Succeed)?;
    let completed = submit_after_releasing_pending(&fixture, fixture.command(Uuid::new_v4()))?;
    assert_eq!(completed.state(), ActionState::Succeeded);
    assert_eq!(completed.result_content(), Some(SUCCEEDED_RESULT_BODY));
    let action_id = completed.action_id().clone();

    // A restarted gateway: a fresh runtime with an empty in-memory session map, sharing only the
    // durable action store. The session placement is not hydrated, so a terminal GET must succeed
    // from durable state alone rather than failing SessionNotFound (BRD-002).
    let actor_config =
        CoordinationActorConfig::new(256, 32, Duration::from_secs(2), Duration::from_secs(5))?;
    let placement =
        GatewayWorkerPlacement::new(WorkerId::new("durable-action-worker")?, 41, 7, 29)?;
    let restarted = Arc::new(GatewayWorkerRuntime::with_action_coordination(
        Arc::clone(&fixture.worker),
        placement,
        Arc::clone(&fixture.store),
        actor_config,
    )?);
    let restarted_router = ApiRouter::new(restarted);

    let fetched = action_snapshot(restarted_router.execute(
        &fixture.principal,
        ApiRequest::GetAction(ActionGetRequest {
            session_id: fixture.session_id.clone(),
            action_id,
        }),
    )?)?;
    assert_eq!(fetched.state(), ActionState::Succeeded);
    assert_eq!(
        fetched.result_content(),
        Some(SUCCEEDED_RESULT_BODY),
        "a restarted gateway returns the terminal action and its body from durable state"
    );
    Ok(())
}

#[test]
fn succeeded_action_records_a_single_terminal_event_in_the_outbox() -> Result<(), Box<dyn Error>> {
    // BRD-017 end-to-end: completing an action drives the runtime's terminal path, which records
    // exactly one durable event for at-least-once notification. A same-key resubmission is served
    // from durable state and must not double-record.
    let fixture = Fixture::new_with_outbox(EnqueueMode::Succeed)?;
    let outbox = fixture
        .outbox
        .clone()
        .ok_or("fixture is missing its event outbox")?;
    let tenant_id = fixture.principal.tenant_id().clone();
    let idempotency_key = Uuid::new_v4();

    let completed = submit_after_releasing_pending(&fixture, fixture.command(idempotency_key))?;
    assert_eq!(completed.state(), ActionState::Succeeded);
    let action_id = completed.action_id().clone();

    // The terminal transition landed in the outbox as one event carrying the action aggregate.
    let page = outbox.read_from(&tenant_id, EventCursor::start(), 16, Utc::now())?;
    assert_eq!(
        page.events().len(),
        1,
        "one terminal event should be recorded"
    );
    let event = &page.events()[0];
    assert_eq!(event.kind(), OutboxEventKind::ActionTerminal);
    match event.aggregate() {
        OutboxAggregate::Action {
            session_id,
            action_id: recorded,
        } => {
            assert_eq!(session_id, &fixture.session_id);
            assert_eq!(recorded, &action_id);
        }
        other => panic!("unexpected outbox aggregate: {other:?}"),
    }
    assert_eq!(event.cursor().position(), 1);
    assert!(!page.cursor_expired());

    // Same-key resubmission is served from durable state (a read path), so the stream is unchanged.
    let resubmitted = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(idempotency_key)),
    )?)?;
    assert_eq!(resubmitted.action_id(), &action_id);
    assert_eq!(resubmitted.state(), ActionState::Succeeded);
    let after = outbox.read_from(&tenant_id, EventCursor::start(), 16, Utc::now())?;
    assert_eq!(
        after.events().len(),
        1,
        "resubmission must not double-record"
    );
    assert_eq!(after.events()[0].event_id(), event.event_id());
    Ok(())
}
