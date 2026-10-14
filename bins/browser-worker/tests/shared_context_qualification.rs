use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use browser_worker::{
    SharedContextPlacementConfig, SharedContextPlacementPolicy, TenantShardReusePolicy,
    load_shared_context_policy,
};
use browserd_chromium::{
    ChromiumArtifactIdentity, GateEvidence, QualificationGate, QualificationReceipt, Sha256Digest,
};
use browserd_core::TenantId;
use browserd_worker::WorkerIsolationProfile;
use chrono::Utc;

const KERNEL: &str = "owned-functional-fixture-kernel";

fn artifact() -> Result<ChromiumArtifactIdentity, Box<dyn Error>> {
    let digest = Sha256Digest::from_hex(&"ab".repeat(32))?;
    Ok(ChromiumArtifactIdentity {
        binary_digest: digest,
        product_version: "153.0.8010.12".to_owned(),
        chromium_revision: "functional-fixture".to_owned(),
        browser_protocol_schema_digest: digest,
        js_protocol_schema_digest: digest,
        launch_profile_digest: digest,
        extension_bundle_digest: digest,
        font_bundle_digest: digest,
        certificate_runtime_bundle_digest: digest,
    })
}

// This receipt belongs only to this functional fixture; it is never saved as production evidence.
fn config(identity: &ChromiumArtifactIdentity, tenant: TenantId) -> SharedContextPlacementConfig {
    SharedContextPlacementConfig {
        version: 1,
        force_dedicated_process: false,
        max_contexts_per_shard: 8,
        max_contexts_created_lifetime: 500,
        max_shard_age_secs: 7200,
        qualification: Some(QualificationReceipt {
            artifact_identity: identity.clone(),
            kernel_release: KERNEL.to_owned(),
            qualified_at: Utc::now(),
            evidence: QualificationGate::ALL
                .into_iter()
                .map(|gate| {
                    (
                        gate,
                        GateEvidence {
                            passed: true,
                            evidence_digest: identity.binary_digest,
                            observations: 1,
                        },
                    )
                })
                .collect(),
        }),
        tenant_reuse: BTreeMap::from([(tenant, TenantShardReusePolicy::CrossTenant)]),
    }
}

#[test]
fn effective_placement_requires_each_gate_and_exact_artifact_kernel() -> Result<(), Box<dyn Error>>
{
    let identity = artifact()?;
    let tenant = TenantId::new();
    let original = config(&identity, tenant.clone());
    let qualified = SharedContextPlacementPolicy::from_config(original.clone(), &identity, KERNEL)?;
    assert_eq!(qualified.max_contexts_per_shard(), 8);
    assert_eq!(qualified.max_contexts_created_lifetime(), 500);
    assert_eq!(qualified.max_shard_age().as_secs(), 7200);
    assert_eq!(qualified.artifact_identity(), &identity);
    assert_eq!(
        qualified.effective_isolation(&tenant, WorkerIsolationProfile::SharedContext),
        Ok(WorkerIsolationProfile::SharedContext)
    );
    let mut cases = Vec::new();
    let mut absent = original.clone();
    absent.qualification = None;
    cases.push(absent);
    for gate in QualificationGate::ALL {
        let mut missing = original.clone();
        missing
            .qualification
            .as_mut()
            .ok_or("missing fixture receipt")?
            .evidence
            .remove(&gate);
        cases.push(missing);
        for (passed, observations) in [(false, 1), (true, 0)] {
            let mut failed = original.clone();
            let receipt = failed
                .qualification
                .as_mut()
                .ok_or("missing fixture receipt")?;
            receipt.evidence.insert(
                gate,
                GateEvidence {
                    passed,
                    observations,
                    evidence_digest: identity.binary_digest,
                },
            );
            cases.push(failed);
        }
    }
    let mut other_build = original.clone();
    other_build
        .qualification
        .as_mut()
        .ok_or("missing fixture receipt")?
        .artifact_identity
        .font_bundle_digest = Sha256Digest::from_hex(&"cd".repeat(32))?;
    cases.push(other_build);
    let mut other_kernel = original.clone();
    other_kernel
        .qualification
        .as_mut()
        .ok_or("missing fixture receipt")?
        .kernel_release
        .push_str("-other");
    cases.push(other_kernel);
    let mut forced = original.clone();
    forced.force_dedicated_process = true;
    cases.push(forced);
    let mut one = original;
    one.max_contexts_per_shard = 1;
    cases.push(one);
    for configuration in cases {
        let policy = SharedContextPlacementPolicy::from_config(configuration, &identity, KERNEL)?;
        assert_eq!(policy.max_contexts_per_shard(), 1);
        assert_eq!(policy.max_contexts_created_lifetime(), 1);
        for requested in [
            WorkerIsolationProfile::SharedContext,
            WorkerIsolationProfile::TenantDedicatedShard,
        ] {
            assert_eq!(
                policy.effective_isolation(&tenant, requested),
                Ok(WorkerIsolationProfile::DedicatedProcess)
            );
        }
    }
    Ok(())
}

#[test]
fn tenant_reuse_grants_never_weaken_requested_isolation() -> Result<(), Box<dyn Error>> {
    let identity = artifact()?;
    let cross = TenantId::new();
    let same = TenantId::new();
    let none = TenantId::new();
    let unlisted = TenantId::new();
    let mut configuration = config(&identity, cross.clone());
    configuration
        .tenant_reuse
        .insert(same.clone(), TenantShardReusePolicy::SameTenantOnly);
    configuration
        .tenant_reuse
        .insert(none.clone(), TenantShardReusePolicy::NoReuse);
    let policy = SharedContextPlacementPolicy::from_config(configuration, &identity, KERNEL)?;
    for (tenant, minimum) in [
        (&cross, WorkerIsolationProfile::SharedContext),
        (&same, WorkerIsolationProfile::TenantDedicatedShard),
        (&none, WorkerIsolationProfile::DedicatedProcess),
        (&unlisted, WorkerIsolationProfile::DedicatedProcess),
    ] {
        assert_eq!(
            policy.effective_isolation(tenant, WorkerIsolationProfile::SharedContext),
            Ok(minimum)
        );
        let actual = policy
            .effective_isolation(tenant, WorkerIsolationProfile::TenantDedicatedShard)
            .map_err(|_| "tenant placement rejected")?;
        assert!(WorkerIsolationProfile::TenantDedicatedShard.satisfied_by(actual));
        assert_eq!(
            policy.effective_isolation(tenant, WorkerIsolationProfile::DedicatedProcess),
            Ok(WorkerIsolationProfile::DedicatedProcess)
        );
        assert!(
            policy
                .effective_isolation(tenant, WorkerIsolationProfile::DedicatedWorker)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn invalid_limits_and_excessive_grants_are_rejected() -> Result<(), Box<dyn Error>> {
    let identity = artifact()?;
    let tenant = TenantId::new();
    for (version, live, lifetime, age) in [
        (2, 8, 500, 7200),
        (1, 0, 500, 7200),
        (1, 9, 500, 7200),
        (1, 8, 7, 7200),
        (1, 8, 501, 7200),
        (1, 8, 500, 0),
        (1, 8, 500, 7201),
    ] {
        let mut c = config(&identity, tenant.clone());
        c.version = version;
        c.max_contexts_per_shard = live;
        c.max_contexts_created_lifetime = lifetime;
        c.max_shard_age_secs = age;
        assert!(SharedContextPlacementPolicy::from_config(c, &identity, KERNEL).is_err());
    }
    let mut excessive = config(&identity, tenant.clone());
    excessive.tenant_reuse = (0..4097)
        .map(|_| (TenantId::new(), TenantShardReusePolicy::CrossTenant))
        .collect();
    assert!(SharedContextPlacementPolicy::from_config(excessive, &identity, KERNEL).is_err());
    Ok(())
}

fn private_file(
    path: &Path,
    configuration: &SharedContextPlacementConfig,
) -> Result<(), Box<dyn Error>> {
    fs::write(path, serde_json::to_vec(configuration)?)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[test]
fn production_loader_uses_actual_kernel_and_missing_config_preserves_dedicated()
-> Result<(), Box<dyn Error>> {
    let identity = artifact()?;
    let tenant = TenantId::new();
    assert!(load_shared_context_policy(None, &identity)?.is_none());
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("reuse.json");
    let mut c = config(&identity, tenant.clone());
    private_file(&path, &c)?;
    let mismatched =
        load_shared_context_policy(Some(&path), &identity)?.ok_or("missing loaded policy")?;
    assert_eq!(mismatched.max_contexts_per_shard(), 1);
    c.qualification
        .as_mut()
        .ok_or("missing fixture receipt")?
        .kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim_end()
        .to_owned();
    private_file(&path, &c)?;
    let policy =
        load_shared_context_policy(Some(&path), &identity)?.ok_or("missing loaded policy")?;
    assert_eq!(
        policy.effective_isolation(&tenant, WorkerIsolationProfile::SharedContext),
        Ok(WorkerIsolationProfile::SharedContext)
    );
    // Loading an immutable snapshot does not follow later policy replacement.
    c.force_dedicated_process = true;
    private_file(&path, &c)?;
    assert_eq!(policy.max_contexts_per_shard(), 8);
    assert_eq!(
        load_shared_context_policy(Some(&path), &identity)?
            .ok_or("missing policy")?
            .max_contexts_per_shard(),
        1
    );
    Ok(())
}

#[test]
fn production_loader_rejects_unsafe_path_file_and_parent_ownership_modes()
-> Result<(), Box<dyn Error>> {
    let identity = artifact()?;
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("policy.json");
    let c = config(&identity, TenantId::new());
    private_file(&path, &c)?;
    assert!(load_shared_context_policy(Some(Path::new("relative.json")), &identity).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(load_shared_context_policy(Some(&path), &identity).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let link = directory.path().join("symlink.json");
    symlink(&path, &link)?;
    assert!(load_shared_context_policy(Some(&link), &identity).is_err());
    let hardlink = directory.path().join("hardlink.json");
    fs::hard_link(&path, &hardlink)?;
    assert!(load_shared_context_policy(Some(&path), &identity).is_err());
    fs::remove_file(hardlink)?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))?;
    assert!(load_shared_context_policy(Some(&path), &identity).is_err());
    Ok(())
}

#[test]
fn policy_json_rejects_duplicate_grants_unknown_fields_and_oversize() -> Result<(), Box<dyn Error>>
{
    let identity = artifact()?;
    let tenant = TenantId::new();
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("policy.json");
    let c = config(&identity, tenant.clone());
    private_file(&path, &c)?;
    let encoded = serde_json::to_string(&c)?;
    let duplicate = encoded.replace(
        &format!("\"{tenant}\":\"cross_tenant\""),
        &format!("\"{tenant}\":\"cross_tenant\",\"{tenant}\":\"no_reuse\""),
    );
    assert_ne!(duplicate, encoded);
    fs::write(&path, duplicate)?;
    assert!(load_shared_context_policy(Some(&path), &identity).is_err());
    let mut invalid_tenant = serde_json::to_value(&c)?;
    invalid_tenant["tenant_reuse"] = serde_json::json!({
        "00000000-0000-0000-0000-000000000000": "cross_tenant"
    });
    fs::write(&path, serde_json::to_vec(&invalid_tenant)?)?;
    assert!(load_shared_context_policy(Some(&path), &identity).is_err());
    let mut unknown = serde_json::to_value(c)?;
    unknown["unchecked_proxy"] = serde_json::json!("http://arbitrary.invalid");
    fs::write(&path, serde_json::to_vec(&unknown)?)?;
    assert!(load_shared_context_policy(Some(&path), &identity).is_err());
    fs::write(&path, vec![b' '; 512 * 1024 + 1])?;
    assert!(load_shared_context_policy(Some(&path), &identity).is_err());
    Ok(())
}
