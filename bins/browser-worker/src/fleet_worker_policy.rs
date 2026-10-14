//! Immutable, private worker admission policy tied to the executed artifact and egress policy.
use browserd_chromium::ChromiumArtifactIdentity;
use browserd_core::WorkerId;
use browserd_sandbox::EgressPolicyBinding;
use browserd_worker::{
    ResourceVector, WorkerAdmissionBudget, WorkerAdmissionPolicy, WorkerTenantAssignment,
};
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePolicy {
    version: u16,
    artifact_identity: ChromiumArtifactIdentity,
    egress_policy_profile: String,
    egress_policy_digest: [u8; 32],
    compatibility_digest: [u8; 32],
    capacity: ResourceVector,
    budgets: Vec<WorkerAdmissionBudget>,
    max_retained_tokens: usize,
    exclusive_assignment: Option<WorkerTenantAssignment>,
}

pub fn load_worker_admission_policy(
    path: &Path,
    worker_id: &WorkerId,
    artifact: &ChromiumArtifactIdentity,
    egress: &EgressPolicyBinding,
) -> Result<WorkerAdmissionPolicy, String> {
    let bytes = crate::shared_context_qualification::read_private_policy(path)
        .map_err(|_| "worker admission policy could not be opened".to_owned())?;
    let policy: FilePolicy =
        serde_json::from_slice(&bytes).map_err(|_| "invalid worker admission policy".to_owned())?;
    if policy.version != 1
        || &policy.artifact_identity != artifact
        || policy.egress_policy_profile != egress.profile()
        || policy.egress_policy_digest != *egress.snapshot_digest()
        || policy
            .exclusive_assignment
            .as_ref()
            .is_some_and(|a| a.worker_id() != worker_id)
    {
        return Err("worker admission policy does not match this worker".to_owned());
    }
    WorkerAdmissionPolicy::new(
        policy.compatibility_digest,
        policy.capacity,
        policy.budgets,
        policy.max_retained_tokens,
        policy.exclusive_assignment,
    )
    .map_err(|_| "invalid worker admission capacity or profiles".to_owned())
}
