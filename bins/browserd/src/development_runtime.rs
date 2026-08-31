use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use browser_worker::{
    ProvisionedSessionShard, RoutedArtifactStore, SessionShardFactory, SessionShardLifecycle,
};
use browserd_core::{ActionId, PageId, SessionId, TenantId, WorkerId};
use browserd_policy::CanonicalActionProposal;
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActionExecutionResult, ApprovedActionError, ArtifactStoreReceipt, ArtifactStoreRequest,
    ChromiumDriver, DependencyError, LiveApprovalContext, WorkerSessionOptionsV1,
};

pub(crate) struct DevelopmentShardFactory {
    pub(crate) worker_id: WorkerId,
    pub(crate) worker_epoch: u64,
}

impl SessionShardFactory for DevelopmentShardFactory {
    fn qualify_daemon(&self) -> Result<(), DependencyError> {
        if self.worker_epoch == 0 {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }

    fn heartbeat_daemon(
        &self,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<(), DependencyError> {
        if worker_id != &self.worker_id || worker_epoch != self.worker_epoch {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }

    fn create(
        &self,
        _tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        if fence.worker_id() != &self.worker_id || fence.worker_epoch() != self.worker_epoch {
            return Err(DependencyError::Rejected);
        }
        let driver = Arc::new(DevelopmentChromiumDriver::default());
        let primary_page_id = driver.create_context(session_id)?;
        Ok(ProvisionedSessionShard::new(
            primary_page_id,
            Arc::clone(&driver) as Arc<dyn ChromiumDriver>,
            Arc::new(DevelopmentShardLifecycle {
                session_id: session_id.clone(),
                fence: fence.clone(),
                driver,
            }),
        ))
    }

    fn create_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        if fence.worker_id() != &self.worker_id
            || fence.worker_epoch() != self.worker_epoch
            || !options.is_valid()
        {
            return Err(DependencyError::Rejected);
        }
        let driver = Arc::new(DevelopmentChromiumDriver::default());
        let primary_page_id =
            driver.create_context_owned_with_options(tenant_id, session_id, fence, options)?;
        Ok(ProvisionedSessionShard::new(
            primary_page_id,
            Arc::clone(&driver) as Arc<dyn ChromiumDriver>,
            Arc::new(DevelopmentShardLifecycle {
                session_id: session_id.clone(),
                fence: fence.clone(),
                driver,
            }),
        ))
    }
}

pub(crate) struct RejectDevelopmentArtifacts;

impl RoutedArtifactStore for RejectDevelopmentArtifacts {
    fn store(
        &self,
        _request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
}

struct DevelopmentShardLifecycle {
    session_id: SessionId,
    fence: OwnershipFence,
    driver: Arc<DevelopmentChromiumDriver>,
}

impl SessionShardLifecycle for DevelopmentShardLifecycle {
    fn qualify(&self) -> Result<(), DependencyError> {
        let state = self
            .driver
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if state
            .as_ref()
            .is_some_and(|context| context.session_id == self.session_id)
        {
            Ok(())
        } else {
            Err(DependencyError::Rejected)
        }
    }

    fn heartbeat(&self) -> Result<(), DependencyError> {
        let state = self
            .driver
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if state
            .as_ref()
            .is_some_and(|context| context.session_id == self.session_id)
        {
            Ok(())
        } else {
            Err(DependencyError::Rejected)
        }
    }

    fn terminate(&self, fence: &OwnershipFence) -> Result<(), DependencyError> {
        if fence != &self.fence {
            return Err(DependencyError::Rejected);
        }
        self.driver.close_context(&self.session_id)
    }
}

#[derive(Default)]
struct DevelopmentChromiumDriver {
    state: Mutex<Option<DevelopmentContext>>,
}

struct DevelopmentContext {
    tenant_id: Option<TenantId>,
    session_id: SessionId,
    fence: Option<OwnershipFence>,
    options: Option<WorkerSessionOptionsV1>,
    primary_page_id: PageId,
    pages: HashSet<PageId>,
}

impl ChromiumDriver for DevelopmentChromiumDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.state
            .lock()
            .map(|_| ())
            .map_err(|_| DependencyError::Unavailable)
    }

    fn create_context(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if let Some(context) = state.as_ref() {
            return if &context.session_id == session_id
                && context.tenant_id.is_none()
                && context.fence.is_none()
                && context.options.is_none()
            {
                Ok(context.primary_page_id.clone())
            } else {
                Err(DependencyError::Rejected)
            };
        }
        let primary_page_id = PageId::new();
        let mut pages = HashSet::new();
        pages.insert(primary_page_id.clone());
        *state = Some(DevelopmentContext {
            tenant_id: None,
            session_id: session_id.clone(),
            fence: None,
            options: None,
            primary_page_id: primary_page_id.clone(),
            pages,
        });
        Ok(primary_page_id)
    }

    fn create_context_owned_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        if !options.is_valid() {
            return Err(DependencyError::Rejected);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if let Some(context) = state.as_ref() {
            return if context.tenant_id.as_ref() == Some(tenant_id)
                && &context.session_id == session_id
                && context.fence.as_ref() == Some(fence)
                && context.options.as_ref() == Some(options)
            {
                Ok(context.primary_page_id.clone())
            } else {
                Err(DependencyError::Rejected)
            };
        }
        let primary_page_id = PageId::new();
        let mut pages = HashSet::new();
        pages.insert(primary_page_id.clone());
        *state = Some(DevelopmentContext {
            tenant_id: Some(tenant_id.clone()),
            session_id: session_id.clone(),
            fence: Some(fence.clone()),
            options: Some(options.clone()),
            primary_page_id: primary_page_id.clone(),
            pages,
        });
        Ok(primary_page_id)
    }

    fn close_context(&self, session_id: &SessionId) -> Result<(), DependencyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if state
            .as_ref()
            .is_some_and(|context| &context.session_id == session_id)
        {
            *state = None;
            Ok(())
        } else if state.is_none() {
            Ok(())
        } else {
            Err(DependencyError::Rejected)
        }
    }

    fn create_page(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let context = state.as_mut().ok_or(DependencyError::Rejected)?;
        if &context.session_id != session_id {
            return Err(DependencyError::Rejected);
        }
        let page_id = PageId::new();
        context.pages.insert(page_id.clone());
        Ok(page_id)
    }

    fn close_page(&self, session_id: &SessionId, page_id: &PageId) -> Result<(), DependencyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let context = state.as_mut().ok_or(DependencyError::Rejected)?;
        if &context.session_id != session_id || !context.pages.remove(page_id) {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }

    fn activate_page(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), DependencyError> {
        let state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let context = state.as_ref().ok_or(DependencyError::Rejected)?;
        if &context.session_id != session_id || !context.pages.contains(page_id) {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }

    fn execute_action(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        _payload: &[u8],
    ) -> ActionExecutionResult {
        let Ok(state) = self.state.lock() else {
            return ActionExecutionResult::OutcomeUnknown;
        };
        let Some(context) = state.as_ref() else {
            return ActionExecutionResult::FailedKnown("development context is closed".to_owned());
        };
        if &context.session_id != session_id
            || page_id.is_some_and(|page_id| !context.pages.contains(page_id))
        {
            return ActionExecutionResult::FailedKnown("development target is stale".to_owned());
        }
        ActionExecutionResult::FailedKnown(
            "development runtime does not execute Chromium effects".to_owned(),
        )
    }

    fn inspect_approval_context(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Err(DependencyError::Unavailable)
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
        session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        let state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if state
            .as_ref()
            .is_some_and(|context| &context.session_id == session_id)
        {
            Ok(false)
        } else {
            Err(DependencyError::Rejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use browser_worker::SessionShardFactory;
    use browserd_core::{SessionId, TenantId, WorkerId};
    use browserd_session::OwnershipFence;
    use browserd_worker::{
        ChromiumDriver, DependencyError, WorkerSessionOptionsV1, WorkerViewport,
    };

    use super::{DevelopmentChromiumDriver, DevelopmentShardFactory};

    fn options() -> WorkerSessionOptionsV1 {
        WorkerSessionOptionsV1 {
            workload_class_hint: "interactive".to_owned(),
            viewport: WorkerViewport {
                width: 1280,
                height: 720,
                device_scale_factor: 1,
            },
            locale: "ko-KR".to_owned(),
            timezone: "Asia/Seoul".to_owned(),
            user_agent: None,
            network_policy_id: "public-web-default".to_owned(),
            network_class: "public".to_owned(),
            checkpoint_ref: None,
            dialog_policy: "auto_dismiss".to_owned(),
            feature_profile: "standard".to_owned(),
            ttl_seconds: 1_800,
            idle_timeout_seconds: 600,
            metadata: BTreeMap::from([("agent_run_id".to_owned(), "dev-runtime".to_owned())]),
        }
    }

    fn fixture() -> Option<(DevelopmentShardFactory, TenantId, SessionId, OwnershipFence)> {
        let worker_id = WorkerId::new("development-options-test").ok()?;
        Some((
            DevelopmentShardFactory {
                worker_id: worker_id.clone(),
                worker_epoch: 7,
            },
            TenantId::new(),
            SessionId::new(),
            OwnershipFence::new(worker_id, 7, 1, 1),
        ))
    }

    #[test]
    fn development_driver_binds_exact_options_to_the_context_identity() {
        let Some((_, tenant_id, session_id, fence)) = fixture() else {
            return;
        };
        let driver = DevelopmentChromiumDriver::default();
        let exact = options();
        let first =
            driver.create_context_owned_with_options(&tenant_id, &session_id, &fence, &exact);
        assert!(first.is_ok());
        assert_eq!(
            driver.create_context_owned_with_options(&tenant_id, &session_id, &fence, &exact,),
            first
        );

        let mut changed = exact;
        changed.locale = "en-US".to_owned();
        assert_eq!(
            driver.create_context_owned_with_options(&tenant_id, &session_id, &fence, &changed,),
            Err(DependencyError::Rejected)
        );
        assert_eq!(
            driver.create_context_owned(&tenant_id, &session_id, &fence),
            Err(DependencyError::Rejected)
        );
    }

    #[test]
    fn valid_session_options_create_a_development_context() {
        let Some((factory, tenant_id, session_id, fence)) = fixture() else {
            return;
        };

        let created = factory.create_with_options(&tenant_id, &session_id, &fence, &options());
        assert!(created.is_ok());
    }

    #[test]
    fn invalid_session_options_are_rejected_before_development_create() {
        let Some((factory, tenant_id, session_id, fence)) = fixture() else {
            return;
        };
        let mut invalid = options();
        invalid.idle_timeout_seconds = invalid.ttl_seconds.saturating_add(1);

        assert!(matches!(
            factory.create_with_options(&tenant_id, &session_id, &fence, &invalid),
            Err(DependencyError::Rejected)
        ));
        assert!(
            factory
                .create_with_options(&tenant_id, &session_id, &fence, &options())
                .is_ok()
        );
    }
}
