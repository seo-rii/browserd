use browserd_features::{
    BuiltinFeature, FeatureFailurePolicy, FeatureProfile, FeatureRegistry, InternalCapability,
    RegistryError,
};

#[test]
fn builtin_registry_is_complete_unique_and_dependency_ordered() {
    let registry = FeatureRegistry::builtin();
    assert!(registry.validate().is_ok());
    for feature in BuiltinFeature::ALL {
        let manifest = registry.manifest(feature);
        assert!(manifest.is_some(), "missing built-in feature {feature:?}");
    }
    let ordered = registry.hook_order();
    assert!(ordered.is_ok());
    let Some(ordered) = ordered.ok() else {
        return;
    };
    for (index, feature) in ordered.iter().enumerate() {
        let Some(manifest) = registry.manifest(*feature) else {
            return;
        };
        for dependency in manifest.dependencies {
            let dependency_index = ordered.iter().position(|candidate| candidate == dependency);
            assert!(dependency_index.is_some());
            assert!(dependency_index.unwrap_or(index) < index);
        }
    }
}

#[test]
fn limited_feature_context_never_exposes_raw_browser_or_unwrapped_io() {
    assert_eq!(
        InternalCapability::ALL,
        [
            InternalCapability::TargetCommands,
            InternalCapability::ArtifactWriter,
            InternalCapability::PolicyFetchClient,
            InternalCapability::SessionTempFile,
            InternalCapability::AuditEmitter,
            InternalCapability::ActionAdmission,
        ]
    );
    assert!(InternalCapability::ALL.iter().all(|capability| !matches!(
        capability.as_str(),
        "raw_cdp"
            | "browser_handle"
            | "arbitrary_filesystem"
            | "raw_object_store"
            | "arbitrary_http"
    )));
}

#[test]
fn privileged_evaluate_requires_both_profile_and_scope() {
    let registry = FeatureRegistry::builtin();
    assert_eq!(
        registry.authorize(
            BuiltinFeature::PrivilegedEvaluate,
            FeatureProfile::Standard,
            &["browser:evaluate"]
        ),
        Err(RegistryError::ProfileDenied)
    );
    assert_eq!(
        registry.authorize(
            BuiltinFeature::PrivilegedEvaluate,
            FeatureProfile::Privileged,
            &["browser:act"]
        ),
        Err(RegistryError::ScopeDenied)
    );
    assert!(
        registry
            .authorize(
                BuiltinFeature::PrivilegedEvaluate,
                FeatureProfile::Privileged,
                &["browser:evaluate"]
            )
            .is_ok()
    );
    assert_eq!(
        registry
            .manifest(BuiltinFeature::Audit)
            .map(|manifest| manifest.failure_policy),
        Some(FeatureFailurePolicy::BestEffortAudit)
    );
}
