use browserd_core::{IsolationProfile, RuntimeSafetyCache, SafetySwitchSnapshot};
use std::sync::Arc;

use crate::{
    EmergencyDenyReason, EmergencyPolicy, EmergencyPolicyError, EmergencyPolicyState,
    ExecutionContext, Origin, SecretDispatchAdmissionError, SessionId, TenantId,
};

impl EmergencyPolicy {
    /// Binds the same runtime cache used by the Worker and trusted runtime owners. Rebinding a
    /// live policy to a different authority is forbidden; ordinary snapshots install in the cache.
    pub fn attach_runtime_safety_cache(
        &self,
        cache: Arc<RuntimeSafetyCache>,
    ) -> Result<(), EmergencyPolicyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if let Some(current) = &state.runtime_safety {
            return if Arc::ptr_eq(current, &cache) {
                Ok(())
            } else {
                Err(EmergencyPolicyError::CoordinationUnavailable)
            };
        }
        state.runtime_safety = Some(cache);
        Ok(())
    }

    pub fn attach_runtime_safety_cache_with_build(
        &self,
        cache: Arc<RuntimeSafetyCache>,
        digest: String,
    ) -> Result<(), EmergencyPolicyError> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(EmergencyPolicyError::CoordinationUnavailable);
        }
        self.attach_runtime_safety_cache(Arc::clone(&cache))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state
            .runtime_chromium_digest
            .as_ref()
            .is_some_and(|current| current != &digest)
        {
            return Err(EmergencyPolicyError::CoordinationUnavailable);
        }
        state.runtime_chromium_digest = Some(digest);
        Ok(())
    }

    /// For scoped operations whose existing driver contract supplies no HTTP document observation
    /// (viewer control and checkpoint restore). Ownership, durable intent, and grants stay separate.
    pub fn authorize_runtime_operation<T>(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        feature: &str,
        commit: impl FnOnce() -> T,
    ) -> Result<T, SecretDispatchAdmissionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| SecretDispatchAdmissionError::Unavailable)?;
        let reason = if state.disabled_tenants.contains(tenant_id) {
            Some(EmergencyDenyReason::TenantDisabled)
        } else if state.disabled_sessions.contains(session_id) {
            Some(EmergencyDenyReason::SessionDisabled)
        } else if state.killed_features.contains(feature) {
            Some(EmergencyDenyReason::FeatureKillSwitch)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(SecretDispatchAdmissionError::Denied(reason));
        }
        match &state.runtime_safety {
            None => Ok(commit()),
            Some(cache) => cache
                .with_fresh_snapshot(|snapshot| {
                    if let Some(reason) = build_denial(&state, snapshot) {
                        return Err(SecretDispatchAdmissionError::Denied(reason));
                    }
                    if feature_disabled(snapshot, feature) {
                        return Err(SecretDispatchAdmissionError::Denied(
                            EmergencyDenyReason::FeatureKillSwitch,
                        ));
                    }
                    Ok(commit())
                })
                .map_err(|_| SecretDispatchAdmissionError::Unavailable)?,
        }
    }
}

pub(super) fn feature_disabled(snapshot: &SafetySwitchSnapshot, feature: &str) -> bool {
    match feature {
        "browser:evaluate" => snapshot.evaluate_disabled(),
        "browser:download" => snapshot.downloads_disabled(),
        "browser:checkpoint" | "browser:checkpoint_restore" => snapshot.checkpoint_disabled(),
        "browser:viewer_control" => snapshot.viewer_control_disabled(),
        _ => false,
    }
}
pub(super) fn context_denial(
    snapshot: &SafetySwitchSnapshot,
    context: &ExecutionContext,
) -> Option<EmergencyDenyReason> {
    if feature_disabled(snapshot, &context.feature) {
        Some(EmergencyDenyReason::FeatureKillSwitch)
    } else if snapshot.domain_denied(context.current_origin.host()) {
        Some(EmergencyDenyReason::DomainDenied)
    } else if context
        .resolved_ips
        .iter()
        .any(|ip| snapshot.ip_denied(*ip))
    {
        Some(EmergencyDenyReason::IpDenied)
    } else if snapshot.chromium_build_disabled(&context.chromium_build) {
        Some(EmergencyDenyReason::ChromiumBuildKillSwitch)
    } else if (snapshot.force_dedicated_process() || snapshot.max_contexts_per_shard() == 1)
        && context.effective_isolation < IsolationProfile::DedicatedProcess
    {
        Some(EmergencyDenyReason::ForceDedicatedProcess)
    } else {
        None
    }
}
pub(super) fn admit_context<T>(
    state: &EmergencyPolicyState,
    context: &ExecutionContext,
    commit: impl FnOnce() -> T,
) -> Result<T, SecretDispatchAdmissionError> {
    match &state.runtime_safety {
        None => Ok(commit()),
        Some(cache) => cache
            .with_fresh_snapshot(|snapshot| {
                if let Some(reason) =
                    build_denial(state, snapshot).or_else(|| context_denial(snapshot, context))
                {
                    return Err(SecretDispatchAdmissionError::Denied(reason));
                }
                Ok(commit())
            })
            .map_err(|_| SecretDispatchAdmissionError::Unavailable)?,
    }
}
pub(super) fn admit_secret<T>(
    state: &EmergencyPolicyState,
    origin: &Origin,
    commit: impl FnOnce() -> T,
) -> Result<T, SecretDispatchAdmissionError> {
    match &state.runtime_safety {
        None => Ok(commit()),
        Some(cache) => cache
            .with_fresh_snapshot(|snapshot| {
                if let Some(reason) = build_denial(state, snapshot) {
                    return Err(SecretDispatchAdmissionError::Denied(reason));
                }
                if snapshot.domain_denied(origin.host()) {
                    return Err(SecretDispatchAdmissionError::Denied(
                        EmergencyDenyReason::DomainDenied,
                    ));
                }
                Ok(commit())
            })
            .map_err(|_| SecretDispatchAdmissionError::Unavailable)?,
    }
}

pub(super) fn build_denial(
    state: &EmergencyPolicyState,
    snapshot: &SafetySwitchSnapshot,
) -> Option<EmergencyDenyReason> {
    state
        .runtime_chromium_digest
        .as_ref()
        .filter(|digest| snapshot.chromium_build_disabled(digest))
        .map(|_| EmergencyDenyReason::ChromiumBuildKillSwitch)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
