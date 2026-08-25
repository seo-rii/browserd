use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BuiltinFeature {
    CoreNavigation,
    CoreInput,
    Snapshot,
    Screenshot,
    Pdf,
    Scrape,
    Viewer,
    HumanControl,
    Uploads,
    Downloads,
    Checkpoint,
    NetworkPolicy,
    Audit,
    PrivilegedEvaluate,
}

impl BuiltinFeature {
    pub const ALL: [Self; 14] = [
        Self::CoreNavigation,
        Self::CoreInput,
        Self::Snapshot,
        Self::Screenshot,
        Self::Pdf,
        Self::Scrape,
        Self::Viewer,
        Self::HumanControl,
        Self::Uploads,
        Self::Downloads,
        Self::Checkpoint,
        Self::NetworkPolicy,
        Self::Audit,
        Self::PrivilegedEvaluate,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureFailurePolicy {
    RejectAction,
    FailSession,
    TaintShard,
    BestEffortAudit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FeatureResourceRequest {
    pub admission_class: Option<crate::AdmissionClass>,
    pub maximum_output_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureManifest {
    pub feature: BuiltinFeature,
    pub name: &'static str,
    pub version: &'static str,
    pub required_scopes: &'static [&'static str],
    pub dependencies: &'static [BuiltinFeature],
    pub hook_order: i32,
    pub process_compatibility_fingerprint: Option<&'static str>,
    pub resources: FeatureResourceRequest,
    pub failure_policy: FeatureFailurePolicy,
}

const NAVIGATION: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::CoreNavigation,
    name: "core-navigation",
    version: "1",
    required_scopes: &["browser:act"],
    dependencies: &[],
    hook_order: 10,
    process_compatibility_fingerprint: None,
    resources: FeatureResourceRequest {
        admission_class: None,
        maximum_output_bytes: 0,
    },
    failure_policy: FeatureFailurePolicy::RejectAction,
};
const INPUT: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::CoreInput,
    name: "core-input",
    hook_order: 20,
    ..NAVIGATION
};
const SNAPSHOT: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Snapshot,
    name: "snapshot",
    dependencies: &[BuiltinFeature::CoreNavigation],
    hook_order: 30,
    resources: FeatureResourceRequest {
        admission_class: Some(crate::AdmissionClass::LargeSnapshot),
        maximum_output_bytes: 4 * 1024 * 1024,
    },
    ..NAVIGATION
};
const SCREENSHOT: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Screenshot,
    name: "screenshot",
    dependencies: &[BuiltinFeature::Snapshot],
    hook_order: 40,
    resources: FeatureResourceRequest {
        admission_class: Some(crate::AdmissionClass::FullPageScreenshot),
        maximum_output_bytes: 16 * 1024 * 1024,
    },
    ..NAVIGATION
};
const PDF: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Pdf,
    name: "pdf",
    dependencies: &[BuiltinFeature::CoreNavigation],
    hook_order: 50,
    resources: FeatureResourceRequest {
        admission_class: Some(crate::AdmissionClass::Pdf),
        maximum_output_bytes: 64 * 1024 * 1024,
    },
    ..NAVIGATION
};
const SCRAPE: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Scrape,
    name: "scrape",
    dependencies: &[BuiltinFeature::Snapshot],
    hook_order: 60,
    resources: FeatureResourceRequest {
        admission_class: Some(crate::AdmissionClass::Scrape),
        maximum_output_bytes: 4 * 1024 * 1024,
    },
    ..NAVIGATION
};
const VIEWER: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Viewer,
    name: "viewer",
    required_scopes: &["viewer:read"],
    dependencies: &[BuiltinFeature::Screenshot],
    hook_order: 70,
    ..NAVIGATION
};
const HUMAN_CONTROL: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::HumanControl,
    name: "human-control",
    required_scopes: &["viewer:control"],
    dependencies: &[BuiltinFeature::Viewer, BuiltinFeature::CoreInput],
    hook_order: 80,
    ..NAVIGATION
};
const UPLOADS: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Uploads,
    name: "uploads",
    required_scopes: &["artifact:upload"],
    hook_order: 90,
    ..NAVIGATION
};
const DOWNLOADS: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Downloads,
    name: "downloads",
    required_scopes: &["artifact:read"],
    hook_order: 100,
    ..NAVIGATION
};
const CHECKPOINT: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Checkpoint,
    name: "checkpoint",
    required_scopes: &["checkpoint:create"],
    dependencies: &[BuiltinFeature::Uploads],
    hook_order: 110,
    ..NAVIGATION
};
const NETWORK_POLICY: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::NetworkPolicy,
    name: "network-policy",
    required_scopes: &["browser:act"],
    hook_order: 5,
    failure_policy: FeatureFailurePolicy::TaintShard,
    ..NAVIGATION
};
const AUDIT: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::Audit,
    name: "audit",
    required_scopes: &[],
    hook_order: 0,
    failure_policy: FeatureFailurePolicy::BestEffortAudit,
    ..NAVIGATION
};
const EVALUATE: FeatureManifest = FeatureManifest {
    feature: BuiltinFeature::PrivilegedEvaluate,
    name: "privileged-evaluate",
    required_scopes: &["browser:evaluate"],
    dependencies: &[BuiltinFeature::CoreNavigation],
    hook_order: 120,
    process_compatibility_fingerprint: Some("privileged-evaluate-v1"),
    ..NAVIGATION
};

const HOOK_ORDER: [BuiltinFeature; 14] = [
    BuiltinFeature::Audit,
    BuiltinFeature::NetworkPolicy,
    BuiltinFeature::CoreNavigation,
    BuiltinFeature::CoreInput,
    BuiltinFeature::Snapshot,
    BuiltinFeature::Screenshot,
    BuiltinFeature::Pdf,
    BuiltinFeature::Scrape,
    BuiltinFeature::Viewer,
    BuiltinFeature::HumanControl,
    BuiltinFeature::Uploads,
    BuiltinFeature::Downloads,
    BuiltinFeature::Checkpoint,
    BuiltinFeature::PrivilegedEvaluate,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureProfile {
    Standard,
    Privileged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    MissingFeature,
    DuplicateFeature,
    DependencyOrder,
    ProfileDenied,
    ScopeDenied,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FeatureRegistry;

impl FeatureRegistry {
    #[must_use]
    pub const fn builtin() -> Self {
        Self
    }

    #[must_use]
    pub const fn manifest(self, feature: BuiltinFeature) -> Option<&'static FeatureManifest> {
        Some(match feature {
            BuiltinFeature::CoreNavigation => &NAVIGATION,
            BuiltinFeature::CoreInput => &INPUT,
            BuiltinFeature::Snapshot => &SNAPSHOT,
            BuiltinFeature::Screenshot => &SCREENSHOT,
            BuiltinFeature::Pdf => &PDF,
            BuiltinFeature::Scrape => &SCRAPE,
            BuiltinFeature::Viewer => &VIEWER,
            BuiltinFeature::HumanControl => &HUMAN_CONTROL,
            BuiltinFeature::Uploads => &UPLOADS,
            BuiltinFeature::Downloads => &DOWNLOADS,
            BuiltinFeature::Checkpoint => &CHECKPOINT,
            BuiltinFeature::NetworkPolicy => &NETWORK_POLICY,
            BuiltinFeature::Audit => &AUDIT,
            BuiltinFeature::PrivilegedEvaluate => &EVALUATE,
        })
    }

    pub fn validate(self) -> Result<(), RegistryError> {
        let mut names = HashSet::new();
        for feature in BuiltinFeature::ALL {
            let manifest = self
                .manifest(feature)
                .ok_or(RegistryError::MissingFeature)?;
            if !names.insert(manifest.name) {
                return Err(RegistryError::DuplicateFeature);
            }
            let Some(index) = HOOK_ORDER
                .iter()
                .position(|candidate| candidate == &feature)
            else {
                return Err(RegistryError::MissingFeature);
            };
            for dependency in manifest.dependencies {
                let dependency_index = HOOK_ORDER
                    .iter()
                    .position(|candidate| candidate == dependency)
                    .ok_or(RegistryError::MissingFeature)?;
                if dependency_index >= index {
                    return Err(RegistryError::DependencyOrder);
                }
            }
        }
        Ok(())
    }

    pub fn hook_order(self) -> Result<Vec<BuiltinFeature>, RegistryError> {
        self.validate()?;
        Ok(HOOK_ORDER.to_vec())
    }

    pub fn authorize(
        self,
        feature: BuiltinFeature,
        profile: FeatureProfile,
        scopes: &[&str],
    ) -> Result<(), RegistryError> {
        if feature == BuiltinFeature::PrivilegedEvaluate && profile != FeatureProfile::Privileged {
            return Err(RegistryError::ProfileDenied);
        }
        let manifest = self
            .manifest(feature)
            .ok_or(RegistryError::MissingFeature)?;
        if manifest
            .required_scopes
            .iter()
            .all(|required| scopes.contains(required))
        {
            Ok(())
        } else {
            Err(RegistryError::ScopeDenied)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalCapability {
    TargetCommands,
    ArtifactWriter,
    PolicyFetchClient,
    SessionTempFile,
    AuditEmitter,
    ActionAdmission,
}

impl InternalCapability {
    pub const ALL: [Self; 6] = [
        Self::TargetCommands,
        Self::ArtifactWriter,
        Self::PolicyFetchClient,
        Self::SessionTempFile,
        Self::AuditEmitter,
        Self::ActionAdmission,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetCommands => "target_commands",
            Self::ArtifactWriter => "artifact_writer",
            Self::PolicyFetchClient => "policy_fetch_client",
            Self::SessionTempFile => "session_temp_file",
            Self::AuditEmitter => "audit_emitter",
            Self::ActionAdmission => "action_admission",
        }
    }
}
