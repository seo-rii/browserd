use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use browserd_actions::ActionJournalLimits;
use browserd_core::{
    ActionId, LaunchGeneration, OwnerFence, PageId, SessionId, ShardFence, ShardId, TenantId,
    WorkerEpoch, WorkerId,
};
use browserd_policy::{CanonicalActionProposal, Origin};
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ActorChromiumDriver, ApprovedActionError,
    ArtifactStoreReceipt, ArtifactStoreRequest, AuthenticatedPeer, BrowserShardActor,
    BrowserShardActorConfig, ChromiumDriver, ChromiumDriverShardRuntime, CreateSessionCommand,
    DependencyError, InternalEndpoint, LiveApprovalContext, SandboxClient, WorkerConfig,
    WorkerControlPlane,
};

#[derive(Default)]
struct ContextDriver {
    pages: Mutex<HashMap<SessionId, PageId>>,
    owners: Mutex<HashMap<SessionId, (TenantId, OwnershipFence)>>,
    action_deadline: Mutex<Option<Instant>>,
}

impl ChromiumDriver for ContextDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        let mut pages = self
            .pages
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let page = pages.entry(session_id.clone()).or_default().clone();
        self.owners
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .insert(session_id.clone(), (tenant_id.clone(), fence.clone()));
        Ok(page)
    }

    fn close_context(&self, session_id: &SessionId) -> Result<(), DependencyError> {
        self.pages
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .remove(session_id);
        self.owners
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .remove(session_id);
        Ok(())
    }

    fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }

    fn close_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn activate_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        _payload: &[u8],
    ) -> ActionExecutionResult {
        ActionExecutionResult::Succeeded(Vec::new())
    }

    fn execute_action_until(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        _payload: &[u8],
        deadline: Instant,
    ) -> ActionExecutionResult {
        if let Ok(mut observed) = self.action_deadline.lock() {
            *observed = Some(deadline);
        }
        ActionExecutionResult::Succeeded(vec![7])
    }

    fn inspect_approval_context(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        let origin =
            Origin::parse("https://example.test/").map_err(|_| DependencyError::Unavailable)?;
        Ok(LiveApprovalContext {
            target_incarnation: 1,
            frame_document_epoch: 1,
            current_origin: origin,
            url_revision: 1,
            node_ref: None,
            node_valid: true,
            resolved_ips: Vec::new(),
            credential_refs: Vec::new(),
            chromium_build: "test".to_owned(),
            effective_isolation: browserd_core::IsolationProfile::SharedContext,
        })
    }

    fn execute_approved_action(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _payload: &[u8],
        _proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        authorize_and_commit(inspected)?;
        Ok(ActionExecutionResult::Succeeded(Vec::new()))
    }

    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        Ok(true)
    }
}

struct ReadySandbox;

impl SandboxClient for ReadySandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn provision(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn cleanup(
        &self,
        _session_id: &SessionId,
        _reason: CleanupReason,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn heartbeat(&self, _worker_id: &WorkerId, _worker_epoch: u64) -> Result<(), DependencyError> {
        Ok(())
    }

    fn store_artifact(
        &self,
        _request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Unavailable)
    }
}

fn shard_fence(worker_id: WorkerId) -> Option<ShardFence> {
    Some(ShardFence::new(
        OwnerFence::new(worker_id, WorkerEpoch::new(31)?),
        ShardId::new(),
        LaunchGeneration::new(1)?,
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_session_create_and_close_are_owned_by_the_shard_actor() {
    let worker_id = WorkerId::new("worker-actor-integration");
    assert!(worker_id.is_ok());
    let Some(worker_id) = worker_id.ok() else {
        return;
    };
    let Some(shard_fence) = shard_fence(worker_id.clone()) else {
        return;
    };
    let context_driver = Arc::new(ContextDriver::default());
    let runtime = Arc::new(ChromiumDriverShardRuntime::new(Arc::clone(&context_driver)));
    let actor_config = BrowserShardActorConfig::new(shard_fence.clone(), 16, 4, 16);
    assert!(actor_config.is_ok());
    let Some(actor_config) = actor_config.ok() else {
        return;
    };
    let (actor, actor_task) = BrowserShardActor::spawn(actor_config, runtime.clone());
    assert_eq!(actor.activate(&shard_fence).await, Ok(()));
    let driver = Arc::new(ActorChromiumDriver::new(
        runtime,
        actor.clone(),
        shard_fence.clone(),
    ));
    let delegated_deadline = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        driver.execute_action_until(&SessionId::new(), None, b"deadline", delegated_deadline),
        ActionExecutionResult::Succeeded(vec![7])
    );
    assert_eq!(
        context_driver
            .action_deadline
            .lock()
            .ok()
            .and_then(|deadline| *deadline),
        Some(delegated_deadline)
    );

    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let peer = AuthenticatedPeer::new("gateway-actor-integration");
    assert!(peer.is_ok());
    let Some(peer) = peer.ok() else {
        return;
    };
    let lease = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3));
    let timeout = SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30));
    let journal = ActionJournalConfig::new(directory.path(), ActionJournalLimits::default());
    assert!(lease.is_ok() && timeout.is_ok() && journal.is_ok());
    let (Some(lease), Some(timeout), Some(journal)) = (lease.ok(), timeout.ok(), journal.ok())
    else {
        return;
    };
    let config = WorkerConfig::new(
        worker_id,
        31,
        InternalEndpoint::Loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19012)),
        peer.clone(),
        4,
        8,
        lease,
        timeout,
        Duration::from_secs(60),
        journal,
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let worker = Arc::new(WorkerControlPlane::new(
        config,
        driver,
        Arc::new(ReadySandbox),
    ));
    let create_worker = worker.clone();
    let create_peer = peer.clone();
    let tenant_id = TenantId::new();
    let create_tenant_id = tenant_id.clone();
    let created = tokio::task::spawn_blocking(move || {
        create_worker.create_session(
            &create_peer,
            CreateSessionCommand {
                tenant_id: create_tenant_id,
                idempotency_key: "actor-create".to_owned(),
                canonical_request_hash: [3; 32],
                placement_version: 5,
                session_incarnation: 1,
            },
            SessionTime::new(1),
        )
    })
    .await;
    assert!(created.is_ok());
    assert!(
        created.as_ref().is_ok_and(|result| result.is_ok()),
        "session creation must not fail before actor ownership is asserted"
    );
    let Some(created) = created.ok().and_then(Result::ok) else {
        return;
    };
    assert_eq!(
        context_driver
            .owners
            .lock()
            .ok()
            .and_then(|owners| owners.get(&created.session_id).cloned()),
        Some((tenant_id, created.fence.clone())),
        "the actor boundary must preserve the exact tenant and session fence"
    );
    let snapshot = actor.snapshot(&shard_fence).await;
    assert!(snapshot.is_ok());
    assert_eq!(
        snapshot.ok().map(|snapshot| snapshot.live_sessions),
        Some(1)
    );

    let close_worker = worker.clone();
    let close_peer = peer;
    let session_id = created.session_id.clone();
    let ownership = created.fence.clone();
    let closed = tokio::task::spawn_blocking(move || {
        close_worker.close_session(&close_peer, &session_id, &ownership, SessionTime::new(2))
    })
    .await;
    assert!(closed.is_ok());
    assert!(closed.ok().is_some_and(|result| result.is_ok()));
    let snapshot = actor.snapshot(&shard_fence).await;
    assert!(snapshot.is_ok());
    assert_eq!(
        snapshot.ok().map(|snapshot| snapshot.live_sessions),
        Some(0)
    );

    actor.lose_ownership(&shard_fence).await.ok();
    drop(actor);
    let _ = actor_task.await;
}
