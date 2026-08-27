//! Immutable Chromium compatibility artifacts and launch qualification gates.

mod connection;

pub use connection::{
    ChromiumConnection, ChromiumConnectionConfig, ChromiumConnectionError, ChromiumVersion,
    VerifiedChromiumDriverOwner,
};

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn from_hex(value: &str) -> Result<Self, CompatibilityError> {
        let bytes = hex::decode(value).map_err(|_| CompatibilityError::InvalidDigest)?;
        let bytes = <[u8; 32]>::try_from(bytes).map_err(|_| CompatibilityError::InvalidDigest)?;
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChromiumArtifactIdentity {
    pub binary_digest: Sha256Digest,
    pub product_version: String,
    pub chromium_revision: String,
    pub browser_protocol_schema_digest: Sha256Digest,
    pub js_protocol_schema_digest: Sha256Digest,
    pub launch_profile_digest: Sha256Digest,
    pub extension_bundle_digest: Sha256Digest,
    pub font_bundle_digest: Sha256Digest,
    pub certificate_runtime_bundle_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactFile {
    pub relative_path: PathBuf,
    pub digest: Sha256Digest,
}

impl ArtifactFile {
    pub fn new(relative_path: impl Into<PathBuf>, digest: Sha256Digest) -> Self {
        Self {
            relative_path: relative_path.into(),
            digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompatibilityArtifact {
    pub identity: ChromiumArtifactIdentity,
    pub files: Vec<ArtifactFile>,
}

impl CompatibilityArtifact {
    pub fn verify(&self, root: &Path) -> Result<(), CompatibilityError> {
        for artifact_file in &self.files {
            let relative_path = artifact_file.relative_path.as_path();
            let display_path = relative_path.to_string_lossy().into_owned();
            if relative_path.as_os_str().is_empty()
                || relative_path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(CompatibilityError::UnsafeRelativePath {
                    relative_path: display_path,
                });
            }

            let mut inspected_path = root.to_path_buf();
            for component in relative_path.components() {
                let Component::Normal(component) = component else {
                    return Err(CompatibilityError::UnsafeRelativePath {
                        relative_path: display_path,
                    });
                };
                inspected_path.push(component);
                let metadata = inspected_path.symlink_metadata().map_err(|_| {
                    CompatibilityError::ArtifactReadFailed {
                        relative_path: display_path.clone(),
                    }
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(CompatibilityError::SymlinkNotAllowed {
                        relative_path: display_path,
                    });
                }
            }

            let metadata =
                inspected_path
                    .metadata()
                    .map_err(|_| CompatibilityError::ArtifactReadFailed {
                        relative_path: display_path.clone(),
                    })?;
            if !metadata.is_file() {
                return Err(CompatibilityError::ArtifactNotAFile {
                    relative_path: display_path,
                });
            }

            let mut file = File::open(&inspected_path).map_err(|_| {
                CompatibilityError::ArtifactReadFailed {
                    relative_path: display_path.clone(),
                }
            })?;
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read =
                    file.read(&mut buffer)
                        .map_err(|_| CompatibilityError::ArtifactReadFailed {
                            relative_path: display_path.clone(),
                        })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            let actual = Sha256Digest(hasher.finalize().into());
            if actual != artifact_file.digest {
                return Err(CompatibilityError::DigestMismatch {
                    relative_path: display_path,
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LaunchPolicy;

impl LaunchPolicy {
    pub const fn production() -> Self {
        Self
    }

    pub fn validate(&self, arguments: &[String]) -> Result<(), CompatibilityError> {
        for argument in arguments {
            if argument == "--no-sandbox"
                || argument == "--disable-setuid-sandbox"
                || argument == "--remote-debugging-port"
                || argument.starts_with("--remote-debugging-port=")
                || argument == "--remote-debugging-address"
                || argument.starts_with("--remote-debugging-address=")
            {
                return Err(CompatibilityError::ForbiddenLaunchArgument {
                    argument: argument.clone(),
                });
            }
        }

        if !arguments
            .iter()
            .any(|argument| argument == "--remote-debugging-pipe")
        {
            return Err(CompatibilityError::RequiredLaunchArgumentMissing {
                argument: "--remote-debugging-pipe".to_owned(),
            });
        }
        if !arguments.iter().any(|argument| {
            argument
                .strip_prefix("--disable-features=")
                .is_some_and(|features| {
                    features
                        .split(',')
                        .any(|feature| feature == "BackForwardCache")
                })
        }) {
            return Err(CompatibilityError::RequiredLaunchArgumentMissing {
                argument: "--disable-features=BackForwardCache".to_owned(),
            });
        }
        if !arguments.iter().any(|argument| {
            argument
                .strip_prefix("--user-data-dir=")
                .is_some_and(|path| {
                    path.starts_with("/run/browserd/shards/") && path.ends_with("/profile")
                })
        }) {
            return Err(CompatibilityError::PrivateProfileRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationGate {
    PerContextProxyAttribution,
    TargetBeforeRunBootstrap,
    ContextCleanup,
    NestedChromiumSandbox,
    MandatoryEgressDenial,
    ServiceWorkerProxyAttribution,
    BfcacheDisabled,
    ViewerCjkIme,
}

impl QualificationGate {
    pub const ALL: [Self; 8] = [
        Self::PerContextProxyAttribution,
        Self::TargetBeforeRunBootstrap,
        Self::ContextCleanup,
        Self::NestedChromiumSandbox,
        Self::MandatoryEgressDenial,
        Self::ServiceWorkerProxyAttribution,
        Self::BfcacheDisabled,
        Self::ViewerCjkIme,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateEvidence {
    pub passed: bool,
    pub evidence_digest: Sha256Digest,
    pub observations: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QualificationReceipt {
    pub artifact_identity: ChromiumArtifactIdentity,
    pub kernel_release: String,
    pub qualified_at: DateTime<Utc>,
    pub evidence: BTreeMap<QualificationGate, GateEvidence>,
}

impl QualificationReceipt {
    pub fn allows_shared_context(
        &self,
        artifact_identity: &ChromiumArtifactIdentity,
        kernel_release: &str,
    ) -> bool {
        self.artifact_identity == *artifact_identity
            && self.kernel_release == kernel_release
            && QualificationGate::ALL.into_iter().all(|gate| {
                self.evidence
                    .get(&gate)
                    .is_some_and(|evidence| evidence.passed && evidence.observations > 0)
            })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessProbe {
    VersionAndRevision,
    ChromiumSandbox,
    OuterSandbox,
    ContextCreateDispose,
    PerContextProxyAndLoopbackRemoval,
    MandatoryEgressDenial,
    TargetPauseBootstrapResume,
    ContextOwnershipAttribution,
    TargetEmulationBeforeRun,
    ContextDownloadBehavior,
    PdfStreaming,
    ScreencastFrameAck,
    CleanupLeavesNoTargets,
}

impl ReadinessProbe {
    const REQUIRED: [Self; 13] = [
        Self::VersionAndRevision,
        Self::ChromiumSandbox,
        Self::OuterSandbox,
        Self::ContextCreateDispose,
        Self::PerContextProxyAndLoopbackRemoval,
        Self::MandatoryEgressDenial,
        Self::TargetPauseBootstrapResume,
        Self::ContextOwnershipAttribution,
        Self::TargetEmulationBeforeRun,
        Self::ContextDownloadBehavior,
        Self::PdfStreaming,
        Self::ScreencastFrameAck,
        Self::CleanupLeavesNoTargets,
    ];

    pub const fn required() -> &'static [Self] {
        &Self::REQUIRED
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CompatibilityError {
    #[error("the SHA-256 digest is not exactly 32 bytes of hexadecimal data")]
    InvalidDigest,
    #[error("artifact path is not a safe relative path: {relative_path}")]
    UnsafeRelativePath { relative_path: String },
    #[error("artifact path contains a symbolic link: {relative_path}")]
    SymlinkNotAllowed { relative_path: String },
    #[error("artifact cannot be read: {relative_path}")]
    ArtifactReadFailed { relative_path: String },
    #[error("artifact is not a regular file: {relative_path}")]
    ArtifactNotAFile { relative_path: String },
    #[error("artifact digest does not match the manifest: {relative_path}")]
    DigestMismatch { relative_path: String },
    #[error("Chromium launch argument is forbidden: {argument}")]
    ForbiddenLaunchArgument { argument: String },
    #[error("required Chromium launch argument is missing: {argument}")]
    RequiredLaunchArgumentMissing { argument: String },
    #[error("Chromium must use a shard-private profile directory")]
    PrivateProfileRequired,
}
