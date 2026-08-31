#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use browserd_core::{
    ActionId, LaunchGeneration, OwnerFence, PageId, SessionId, ShardFence, ShardId, TenantId,
    WorkerEpoch, WorkerId,
};
use browserd_policy::CanonicalActionProposal;
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActionExecutionResult, ActorChromiumDriver, ApprovedActionError, BrowserShardActor,
    BrowserShardActorConfig, BrowserShardRuntime, ChromiumDriver, ChromiumDriverShardRuntime,
    DependencyError, LiveApprovalContext, ShardRuntimeError, WorkerSessionOptionsV1,
    WorkerViewport,
};
use tokio_util::sync::CancellationToken;

struct CreateGate {
    started: SyncSender<()>,
    release: Mutex<Receiver<()>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedCreate {
    tenant_id: TenantId,
    session_id: SessionId,
    fence: OwnershipFence,
    options: Option<WorkerSessionOptionsV1>,
}

#[derive(Default)]
struct RecordingDriver {
    gate: Option<CreateGate>,
    owned_creates: Mutex<Vec<OwnedCreate>>,
    unfenced_creates: AtomicUsize,
    fenced_closes: Mutex<Vec<(SessionId, OwnershipFence)>>,
    unfenced_closes: AtomicUsize,
}

impl RecordingDriver {
    fn gated(started: SyncSender<()>, release: Receiver<()>) -> Self {
        Self {
            gate: Some(CreateGate {
                started,
                release: Mutex::new(release),
            }),
            ..Self::default()
        }
    }
}

impl ChromiumDriver for RecordingDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        self.unfenced_creates.fetch_add(1, Ordering::SeqCst);
        Err(DependencyError::Rejected)
    }

    fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        self.owned_creates
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .push(OwnedCreate {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                fence: fence.clone(),
                options: None,
            });
        if let Some(gate) = &self.gate {
            gate.started
                .send(())
                .map_err(|_| DependencyError::Unavailable)?;
            gate.release
                .lock()
                .map_err(|_| DependencyError::Unavailable)?
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| DependencyError::Unavailable)?;
        }
        Ok(PageId::new())
    }

    fn create_context_owned_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        self.owned_creates
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .push(OwnedCreate {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                fence: fence.clone(),
                options: Some(options.clone()),
            });
        Ok(PageId::new())
    }

    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        self.unfenced_closes.fetch_add(1, Ordering::SeqCst);
        Err(DependencyError::Rejected)
    }

    fn close_context_fenced(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.fenced_closes
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .push((session_id.clone(), fence.clone()));
        Ok(())
    }

    fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn close_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn activate_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        _payload: &[u8],
    ) -> ActionExecutionResult {
        ActionExecutionResult::FailedKnown("not used by this contract test".to_owned())
    }

    fn inspect_approval_context(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn execute_approved_action(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _payload: &[u8],
        _proposal: &CanonicalActionProposal,
        _inspected: &LiveApprovalContext,
        _authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        Err(ApprovedActionError::Unavailable)
    }

    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        Err(DependencyError::Rejected)
    }
}

fn worker_id() -> WorkerId {
    WorkerId::new("shard-driver-fencing").expect("test worker ID must be valid")
}

fn ownership(placement_version: u64) -> OwnershipFence {
    OwnershipFence::new(worker_id(), 7, placement_version, 3)
}

fn shard_fence() -> ShardFence {
    ShardFence::new(
        OwnerFence::new(
            worker_id(),
            WorkerEpoch::new(7).expect("test worker epoch must be nonzero"),
        ),
        ShardId::new(),
        LaunchGeneration::new(1).expect("test launch generation must be nonzero"),
    )
}

fn session_options(locale: &str) -> WorkerSessionOptionsV1 {
    WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1280,
            height: 720,
            device_scale_factor: 1,
        },
        locale: locale.to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: Some("browserd-shard-driver-test/1".to_owned()),
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 1_800,
        idle_timeout_seconds: 600,
        metadata: Default::default(),
    }
}

#[tokio::test]
async fn runtime_forwards_exact_options_and_rejects_an_options_only_retry() {
    let driver = Arc::new(RecordingDriver::default());
    let runtime = ChromiumDriverShardRuntime::new(Arc::clone(&driver));
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let exact = ownership(9);
    let first = session_options("ko-KR");
    let changed = session_options("en-US");

    assert_eq!(
        runtime
            .create_context_owned_with_options(
                &tenant_id,
                &session_id,
                &exact,
                &first,
                CancellationToken::new(),
            )
            .await,
        Ok(())
    );
    assert_eq!(
        runtime
            .create_context_owned_with_options(
                &tenant_id,
                &session_id,
                &exact,
                &changed,
                CancellationToken::new(),
            )
            .await,
        Err(ShardRuntimeError::Rejected)
    );
    assert_eq!(
        driver.owned_creates.lock().ok().map(|calls| calls.clone()),
        Some(vec![OwnedCreate {
            tenant_id,
            session_id,
            fence: exact,
            options: Some(first),
        }])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actor_driver_forwards_exact_options_and_rejects_an_options_only_retry() {
    let driver = Arc::new(RecordingDriver::default());
    let runtime = Arc::new(ChromiumDriverShardRuntime::new(Arc::clone(&driver)));
    let shard_fence = shard_fence();
    let config = BrowserShardActorConfig::new(shard_fence.clone(), 16, 4, 16)
        .expect("actor config should be valid");
    let (actor, task) = BrowserShardActor::spawn(config, Arc::clone(&runtime));
    assert_eq!(actor.activate(&shard_fence).await, Ok(()));
    let actor_driver = ActorChromiumDriver::new(runtime, actor.clone(), shard_fence.clone());
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let exact = ownership(10);
    let first = session_options("ko-KR");
    let changed = session_options("en-US");

    assert!(
        actor_driver
            .create_context_owned_with_options(&tenant_id, &session_id, &exact, &first)
            .is_ok()
    );
    assert_eq!(
        actor_driver.create_context_owned_with_options(&tenant_id, &session_id, &exact, &changed,),
        Err(DependencyError::Rejected)
    );
    assert_eq!(
        driver.owned_creates.lock().ok().map(|calls| calls.clone()),
        Some(vec![OwnedCreate {
            tenant_id,
            session_id: session_id.clone(),
            fence: exact.clone(),
            options: Some(first),
        }])
    );

    assert_eq!(actor.shutdown(&shard_fence).await, Ok(()));
    assert!(task.await.is_ok_and(|result| result.is_ok()));
}

#[tokio::test]
async fn dispose_preserves_exact_owned_context_fence_and_rejects_stale_fence_before_effect() {
    let driver = Arc::new(RecordingDriver::default());
    let runtime = ChromiumDriverShardRuntime::new(Arc::clone(&driver));
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let exact = ownership(11);

    assert_eq!(
        runtime
            .create_context_owned(&tenant_id, &session_id, &exact, CancellationToken::new(),)
            .await,
        Ok(())
    );
    assert_eq!(
        runtime
            .dispose_context(&session_id, &ownership(12), CancellationToken::new(),)
            .await,
        Err(ShardRuntimeError::Rejected)
    );
    assert_eq!(driver.unfenced_closes.load(Ordering::SeqCst), 0);
    assert!(
        driver
            .fenced_closes
            .lock()
            .is_ok_and(|calls| calls.is_empty())
    );

    assert_eq!(
        runtime
            .dispose_context(&session_id, &exact, CancellationToken::new())
            .await,
        Ok(())
    );
    assert_eq!(driver.unfenced_creates.load(Ordering::SeqCst), 0);
    assert_eq!(driver.unfenced_closes.load(Ordering::SeqCst), 0);
    assert_eq!(
        driver.owned_creates.lock().ok().map(|calls| calls.clone()),
        Some(vec![OwnedCreate {
            tenant_id,
            session_id: session_id.clone(),
            fence: exact.clone(),
            options: None,
        }])
    );
    assert_eq!(
        driver.fenced_closes.lock().ok().map(|calls| calls.clone()),
        Some(vec![(session_id, exact)])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_after_driver_create_closes_only_the_exact_owned_context() {
    let (started_tx, started_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let driver = Arc::new(RecordingDriver::gated(started_tx, release_rx));
    let runtime = Arc::new(ChromiumDriverShardRuntime::new(Arc::clone(&driver)));
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let exact = ownership(21);
    let cancellation = CancellationToken::new();
    let create_runtime = Arc::clone(&runtime);
    let create_tenant = tenant_id.clone();
    let create_session = session_id.clone();
    let create_fence = exact.clone();
    let create_cancellation = cancellation.clone();
    let create = tokio::spawn(async move {
        create_runtime
            .create_context_owned(
                &create_tenant,
                &create_session,
                &create_fence,
                create_cancellation,
            )
            .await
    });

    assert_eq!(started_rx.recv_timeout(Duration::from_secs(1)), Ok(()));
    cancellation.cancel();
    assert_eq!(release_tx.send(()), Ok(()));
    let joined = tokio::time::timeout(Duration::from_secs(1), create).await;

    assert!(joined.is_ok());
    assert_eq!(
        joined.ok().and_then(Result::ok),
        Some(Err(ShardRuntimeError::Cancelled))
    );
    assert_eq!(driver.unfenced_closes.load(Ordering::SeqCst), 0);
    assert_eq!(
        driver.fenced_closes.lock().ok().map(|calls| calls.clone()),
        Some(vec![(session_id, exact)])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_and_terminate_linearize_to_one_exact_fenced_close() {
    let (started_tx, started_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let driver = Arc::new(RecordingDriver::gated(started_tx, release_rx));
    let runtime = Arc::new(ChromiumDriverShardRuntime::new(Arc::clone(&driver)));
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let exact = ownership(31);
    let create_runtime = Arc::clone(&runtime);
    let create_tenant = tenant_id.clone();
    let create_session = session_id.clone();
    let create_fence = exact.clone();
    let create = tokio::spawn(async move {
        create_runtime
            .create_context_owned(
                &create_tenant,
                &create_session,
                &create_fence,
                CancellationToken::new(),
            )
            .await
    });
    assert_eq!(started_rx.recv_timeout(Duration::from_secs(1)), Ok(()));

    let (terminate_started_tx, terminate_started_rx) = sync_channel(1);
    let terminate_runtime = Arc::clone(&runtime);
    let terminate = tokio::spawn(async move {
        let _ = terminate_started_tx.send(());
        terminate_runtime.terminate(&shard_fence()).await
    });
    assert_eq!(
        terminate_started_rx.recv_timeout(Duration::from_secs(1)),
        Ok(())
    );
    assert_eq!(release_tx.send(()), Ok(()));

    let created = tokio::time::timeout(Duration::from_secs(1), create).await;
    let terminated = tokio::time::timeout(Duration::from_secs(1), terminate).await;
    assert_eq!(created.ok().and_then(Result::ok), Some(Ok(())));
    assert_eq!(terminated.ok().and_then(Result::ok), Some(Ok(())));
    assert_eq!(driver.unfenced_closes.load(Ordering::SeqCst), 0);
    assert_eq!(
        driver.owned_creates.lock().ok().map(|calls| calls.clone()),
        Some(vec![OwnedCreate {
            tenant_id,
            session_id: session_id.clone(),
            fence: exact.clone(),
            options: None,
        }])
    );
    assert_eq!(
        driver.fenced_closes.lock().ok().map(|calls| calls.clone()),
        Some(vec![(session_id, exact)])
    );
}
