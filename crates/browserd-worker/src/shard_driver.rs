use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use browserd_core::{ActionId, PageId, SessionId, ShardFence, TenantId};
use browserd_policy::CanonicalActionProposal;
use browserd_session::OwnershipFence;
use tokio_util::sync::CancellationToken;

use crate::{
    ActionExecutionResult, ApprovedActionError, BrowserShardActor, BrowserShardRuntime,
    ChromiumDriver, DependencyError, LiveApprovalContext, ShardActorError, ShardRuntimeError,
};

/// Adapts the synchronous Chromium control-plane contract to a shard runtime while retaining the
/// exact session fence and primary page created by the runtime.
pub struct ChromiumDriverShardRuntime<D> {
    driver: Arc<D>,
    contexts: Mutex<HashMap<SessionId, OwnedContext>>,
}

struct OwnedContext {
    tenant_id: Option<TenantId>,
    fence: OwnershipFence,
    primary_page: PageId,
}

impl<D> ChromiumDriverShardRuntime<D> {
    #[must_use]
    pub fn new(driver: Arc<D>) -> Self {
        Self {
            driver,
            contexts: Mutex::new(HashMap::new()),
        }
    }

    fn primary_page(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        let contexts = self
            .contexts
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        match contexts.get(session_id) {
            Some(context) if &context.fence == fence => Ok(context.primary_page.clone()),
            Some(_) => Err(DependencyError::Rejected),
            None => Err(DependencyError::Unavailable),
        }
    }

    fn create_context_for(
        &self,
        tenant_id: Option<&TenantId>,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError>
    where
        D: ChromiumDriver,
    {
        if cancellation.is_cancelled() {
            return Err(ShardRuntimeError::Cancelled);
        }
        let tenant_id = tenant_id.cloned();
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        if let Some(context) = contexts.get(session_id) {
            return if context.tenant_id == tenant_id && &context.fence == fence {
                Ok(())
            } else {
                Err(ShardRuntimeError::Rejected)
            };
        }
        let page = if let Some(tenant_id) = tenant_id.as_ref() {
            self.driver
                .create_context_owned(tenant_id, session_id, fence)
        } else {
            self.driver.create_context(session_id)
        }
        .map_err(map_dependency_error)?;
        if cancellation.is_cancelled() {
            let _ = self.driver.close_context(session_id);
            return Err(ShardRuntimeError::Cancelled);
        }
        contexts.insert(
            session_id.clone(),
            OwnedContext {
                tenant_id,
                fence: fence.clone(),
                primary_page: page,
            },
        );
        Ok(())
    }
}

#[async_trait]
impl<D: ChromiumDriver> BrowserShardRuntime for ChromiumDriverShardRuntime<D> {
    async fn readiness_check(
        &self,
        _fence: &ShardFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        if cancellation.is_cancelled() {
            return Err(ShardRuntimeError::Cancelled);
        }
        self.driver.qualify().map_err(map_dependency_error)
    }

    async fn create_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        self.create_context_for(None, session_id, fence, cancellation)
    }

    async fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        self.create_context_for(Some(tenant_id), session_id, fence, cancellation)
    }

    async fn dispose_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        if cancellation.is_cancelled() {
            return Err(ShardRuntimeError::Cancelled);
        }
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        match contexts.get(session_id) {
            Some(context) if &context.fence == fence => {}
            Some(_) => return Err(ShardRuntimeError::Rejected),
            None => return Ok(()),
        }
        self.driver
            .close_context(session_id)
            .map_err(map_dependency_error)?;
        contexts.remove(session_id);
        Ok(())
    }

    async fn terminate(&self, _fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        let session_ids = contexts.keys().cloned().collect::<Vec<_>>();
        for session_id in session_ids {
            self.driver
                .close_context(&session_id)
                .map_err(map_dependency_error)?;
            contexts.remove(&session_id);
        }
        Ok(())
    }
}

/// Routes session context ownership through the serial shard actor and delegates all page/action
/// operations to the underlying Chromium driver.
pub struct ActorChromiumDriver<D> {
    runtime: Arc<ChromiumDriverShardRuntime<D>>,
    actor: BrowserShardActor,
    shard_fence: ShardFence,
}

impl<D> ActorChromiumDriver<D> {
    #[must_use]
    pub fn new(
        runtime: Arc<ChromiumDriverShardRuntime<D>>,
        actor: BrowserShardActor,
        shard_fence: ShardFence,
    ) -> Self {
        Self {
            runtime,
            actor,
            shard_fence,
        }
    }
}

impl<D: ChromiumDriver> ChromiumDriver for ActorChromiumDriver<D> {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.runtime.driver.qualify()
    }

    fn shard_managed_contexts(&self) -> bool {
        true
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_context_fenced(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        futures::executor::block_on(self.actor.attach_session(
            &self.shard_fence,
            session_id.clone(),
            fence.clone(),
        ))
        .map_err(map_actor_error)?;
        self.runtime.primary_page(session_id, fence)
    }

    fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        futures::executor::block_on(self.actor.attach_session_owned(
            &self.shard_fence,
            tenant_id.clone(),
            session_id.clone(),
            fence.clone(),
        ))
        .map_err(map_actor_error)?;
        self.runtime.primary_page(session_id, fence)
    }

    fn close_context(&self, session_id: &SessionId) -> Result<(), DependencyError> {
        let fence = {
            let contexts = self
                .runtime
                .contexts
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            contexts
                .get(session_id)
                .map(|context| context.fence.clone())
        };
        match fence {
            Some(fence) => self.close_context_fenced(session_id, &fence),
            None => Ok(()),
        }
    }

    fn close_context_fenced(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        futures::executor::block_on(self.actor.detach_session(
            &self.shard_fence,
            session_id.clone(),
            fence.clone(),
        ))
        .map_err(map_actor_error)?;
        Ok(())
    }

    fn create_page(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        self.runtime.driver.create_page(session_id)
    }

    fn close_page(&self, session_id: &SessionId, page_id: &PageId) -> Result<(), DependencyError> {
        self.runtime.driver.close_page(session_id, page_id)
    }

    fn activate_page(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), DependencyError> {
        self.runtime.driver.activate_page(session_id, page_id)
    }

    fn execute_action(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        self.runtime
            .driver
            .execute_action(session_id, page_id, payload)
    }

    fn inspect_approval_context(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        self.runtime
            .driver
            .inspect_approval_context(session_id, page_id, proposal)
    }

    fn execute_approved_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        self.runtime.driver.execute_approved_action(
            session_id,
            page_id,
            payload,
            proposal,
            inspected,
            authorize_and_commit,
        )
    }

    fn cancel_action(
        &self,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        self.runtime.driver.cancel_action(session_id, action_id)
    }
}

fn map_dependency_error(error: DependencyError) -> ShardRuntimeError {
    match error {
        DependencyError::Unavailable => ShardRuntimeError::Unavailable,
        DependencyError::Rejected => ShardRuntimeError::Rejected,
        DependencyError::OutcomeUncertain => ShardRuntimeError::OutcomeUncertain,
    }
}

fn map_actor_error(error: ShardActorError) -> DependencyError {
    match error {
        ShardActorError::Runtime(ShardRuntimeError::OutcomeUncertain) => {
            DependencyError::OutcomeUncertain
        }
        ShardActorError::Runtime(ShardRuntimeError::Unavailable)
        | ShardActorError::ActorStopped
        | ShardActorError::MailboxFull => DependencyError::Unavailable,
        _ => DependencyError::Rejected,
    }
}
