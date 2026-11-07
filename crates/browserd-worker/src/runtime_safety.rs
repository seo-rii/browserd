use std::sync::Arc;

use crate::{
    ChromiumDriver, SandboxClient, TenantId, WorkerControlPlane, WorkerError,
    WorkerIsolationProfile, WorkerSessionOptionsV1,
};
use browserd_core::{RuntimeSafetyCache, SafetySwitchSnapshot};

pub(crate) struct WorkerRuntimeSafety {
    pub(crate) cache: Arc<RuntimeSafetyCache>,
    chromium_digest: String,
}
impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    pub fn with_runtime_safety_cache(
        mut self,
        cache: Arc<RuntimeSafetyCache>,
        chromium_digest: String,
    ) -> Result<Self, WorkerError> {
        if chromium_digest.len() != 64
            || !chromium_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        if self.runtime_safety.is_some() {
            return Err(WorkerError::InvalidConfiguration);
        }
        self.emergency_policy
            .attach_runtime_safety_cache_with_build(Arc::clone(&cache), chromium_digest.clone())
            .map_err(|_| WorkerError::InvalidConfiguration)?;
        self.runtime_safety = Some(WorkerRuntimeSafety {
            cache,
            chromium_digest,
        });
        Ok(self)
    }

    pub(crate) fn runtime_safety_ready(&self) -> bool {
        self.runtime_safety.as_ref().is_none_or(|runtime| {
            runtime
                .cache
                .with_fresh_snapshot(|snapshot| {
                    !snapshot.chromium_build_disabled(&runtime.chromium_digest)
                })
                .unwrap_or(false)
        })
    }

    pub(crate) fn runtime_create_isolation(
        &self,
        _tenant: &TenantId,
        options: Option<&WorkerSessionOptionsV1>,
        requested: Option<WorkerIsolationProfile>,
    ) -> Result<WorkerIsolationProfile, WorkerError> {
        let requested = requested.unwrap_or_else(|| self.driver.effective_isolation());
        let Some(runtime) = &self.runtime_safety else {
            return Ok(requested);
        };
        runtime
            .cache
            .with_fresh_snapshot(|snapshot| {
                if snapshot.chromium_build_disabled(&runtime.chromium_digest)
                    || snapshot.network_class_stopped(
                        options.map_or("public", |options| options.network_class.as_str()),
                    )
                {
                    return Err(WorkerError::NotReady);
                }
                if options.is_some_and(|options| options.checkpoint_ref.is_some())
                    && snapshot.checkpoint_disabled()
                {
                    return Err(WorkerError::InvalidConfiguration);
                }
                Ok(runtime_isolation(snapshot, requested))
            })
            .map_err(|_| WorkerError::NotReady)?
    }

    pub(crate) fn runtime_verify_create(
        &self,
        tenant: &TenantId,
        options: Option<&WorkerSessionOptionsV1>,
        actual: WorkerIsolationProfile,
    ) -> Result<(), WorkerError> {
        let required = self.runtime_create_isolation(tenant, options, Some(actual))?;
        if required.satisfied_by(actual) {
            Ok(())
        } else {
            Err(WorkerError::NotReady)
        }
    }

    pub(crate) fn admit_runtime_action(
        &self,
        session_id: &crate::SessionId,
        fence: &crate::OwnershipFence,
        executor: &Arc<crate::SessionExecutor>,
    ) -> Result<(), WorkerError> {
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        crate::validate_fence(&session, fence)?;
        self.admit_runtime_operation(&session.tenant_id, session_id, "browser:operation")
    }

    pub(crate) fn admit_runtime_operation(
        &self,
        tenant: &TenantId,
        session_id: &crate::SessionId,
        feature: &str,
    ) -> Result<(), WorkerError> {
        self.emergency_policy
            .authorize_runtime_operation(tenant, session_id, feature, || ())
            .map_err(|_| WorkerError::InvalidActionTransition)
    }
}
fn runtime_isolation(
    snapshot: &SafetySwitchSnapshot,
    requested: WorkerIsolationProfile,
) -> WorkerIsolationProfile {
    if (snapshot.force_dedicated_process() || snapshot.max_contexts_per_shard() == 1)
        && matches!(
            requested,
            WorkerIsolationProfile::SharedContext | WorkerIsolationProfile::TenantDedicatedShard
        )
    {
        WorkerIsolationProfile::DedicatedProcess
    } else {
        requested
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests;
