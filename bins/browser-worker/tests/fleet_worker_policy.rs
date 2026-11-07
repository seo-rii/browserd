use browser_worker::load_worker_admission_policy;
use browserd_chromium::{ChromiumArtifactIdentity, Sha256Digest};
use browserd_core::{TenantId, WorkerId};
use browserd_sandbox::EgressPolicyBinding;
use browserd_worker::{
    ResourceVector, WorkerAdmissionBudget, WorkerIsolationProfile, WorkerTenantAssignment,
};
use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

fn artifact() -> Result<ChromiumArtifactIdentity, Box<dyn Error>> {
    let digest = Sha256Digest::from_hex(&"ab".repeat(32))?;
    Ok(ChromiumArtifactIdentity {
        binary_digest: digest,
        product_version: "153.0.8010.12".into(),
        chromium_revision: "fleet-fixture".into(),
        browser_protocol_schema_digest: digest,
        js_protocol_schema_digest: digest,
        launch_profile_digest: digest,
        extension_bundle_digest: digest,
        font_bundle_digest: digest,
        certificate_runtime_bundle_digest: digest,
    })
}

#[test]
fn private_policy_pins_artifact_egress_and_whole_worker_assignment() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    let path = root.path().join("fleet.json");
    let worker = WorkerId::new("private-policy-worker")?;
    let identity = artifact()?;
    let egress = EgressPolicyBinding::new("public-web-default", [3; 32])?;
    let assignment = WorkerTenantAssignment::new(worker.clone(), TenantId::new(), [4; 32])
        .map_err(|e| format!("assignment: {e:?}"))?;
    let value = serde_json::json!({
        "version":1, "artifact_identity":identity, "egress_policy_profile":"public-web-default",
        "egress_policy_digest":vec![3u8;32], "compatibility_digest":vec![1u8;32], "capacity":ResourceVector::new(2,2,2,2,2,2),
        "budgets":[WorkerAdmissionBudget { profile_digest:[2;32], isolation:WorkerIsolationProfile::DedicatedWorker,resources:ResourceVector::new(1,1,1,1,1,1) }],
        "max_retained_tokens":64,"exclusive_assignment":assignment,
    });
    let save = |value: &serde_json::Value| -> Result<(), Box<dyn Error>> {
        fs::write(&path, serde_json::to_vec(value)?)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    };
    save(&value)?;
    let policy = load_worker_admission_policy(&path, &worker, &identity, &egress)?;
    assert_eq!(policy.exclusive_assignment(), Some(&assignment));
    for (key, replacement) in [
        ("version", serde_json::json!(2)),
        ("egress_policy_profile", serde_json::json!("foreign-policy")),
        ("egress_policy_digest", serde_json::json!(vec![9u8; 32])),
        ("compatibility_digest", serde_json::json!(vec![0u8; 32])),
        ("max_retained_tokens", serde_json::json!(0)),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut wrong = value.clone();
        wrong[key] = replacement;
        save(&wrong)?;
        assert!(load_worker_admission_policy(&path, &worker, &identity, &egress).is_err());
    }
    save(&value)?;
    assert!(
        load_worker_admission_policy(&path, &WorkerId::new("foreign-worker")?, &identity, &egress)
            .is_err()
    );
    let mut different = identity.clone();
    different.product_version = "different".into();
    assert!(load_worker_admission_policy(&path, &worker, &different, &egress).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(load_worker_admission_policy(&path, &worker, &identity, &egress).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let alias = root.path().join("alias.json");
    symlink(&path, &alias)?;
    assert!(load_worker_admission_policy(&alias, &worker, &identity, &egress).is_err());
    fs::hard_link(&path, root.path().join("hard-link.json"))?;
    assert!(load_worker_admission_policy(&path, &worker, &identity, &egress).is_err());
    Ok(())
}
