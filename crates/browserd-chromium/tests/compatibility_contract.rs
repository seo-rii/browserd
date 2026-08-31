#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use browserd_chromium::{
    ArtifactFile, ChromiumArtifactIdentity, CompatibilityArtifact, CompatibilityError,
    GateEvidence, LaunchPolicy, QualificationGate, QualificationReceipt, ReadinessProbe,
    Sha256Digest,
};
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn digest(bytes: &[u8]) -> Sha256Digest {
    let value = hex::encode(Sha256::digest(bytes));
    Sha256Digest::from_hex(&value).expect("test digest must be valid")
}

fn identity(binary_digest: Sha256Digest) -> ChromiumArtifactIdentity {
    ChromiumArtifactIdentity {
        binary_digest,
        product_version: "149.0.7827.55".to_owned(),
        chromium_revision: "r1234567".to_owned(),
        browser_protocol_schema_digest: digest(b"browser protocol"),
        js_protocol_schema_digest: digest(b"js protocol"),
        launch_profile_digest: digest(b"launch profile"),
        extension_bundle_digest: digest(b"no extensions"),
        font_bundle_digest: digest(b"fonts"),
        certificate_runtime_bundle_digest: digest(b"certificates"),
    }
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("test directory must be created");
    }
    fs::write(path, bytes).expect("test artifact must be written");
}

#[test]
fn verifies_every_file_against_the_immutable_manifest() {
    let root = tempdir().expect("temporary directory must be created");
    write(root.path(), "chrome", b"pinned chromium");
    write(root.path(), "protocol/browser.json", b"browser protocol");
    write(root.path(), "protocol/js.json", b"js protocol");

    let artifact = CompatibilityArtifact {
        identity: identity(digest(b"pinned chromium")),
        files: vec![
            ArtifactFile::new("chrome", digest(b"pinned chromium")),
            ArtifactFile::new("protocol/browser.json", digest(b"browser protocol")),
            ArtifactFile::new("protocol/js.json", digest(b"js protocol")),
        ],
    };

    assert_eq!(artifact.verify(root.path()), Ok(()));

    write(root.path(), "chrome", b"silently replaced chromium");
    assert!(matches!(
        artifact.verify(root.path()),
        Err(CompatibilityError::DigestMismatch { relative_path }) if relative_path == "chrome"
    ));
}

#[test]
fn rejects_a_manifest_without_any_verified_files() {
    let root = tempdir().expect("temporary directory must be created");
    let artifact = CompatibilityArtifact {
        identity: identity(digest(b"pinned chromium")),
        files: Vec::new(),
    };

    assert_eq!(
        artifact.verify(root.path()),
        Err(CompatibilityError::EmptyArtifactManifest)
    );
}

#[test]
fn requires_the_chromium_binary_digest_to_be_covered_by_the_manifest() {
    let root = tempdir().expect("temporary directory must be created");
    write(root.path(), "protocol/browser.json", b"browser protocol");
    let artifact = CompatibilityArtifact {
        identity: identity(digest(b"pinned chromium")),
        files: vec![ArtifactFile::new(
            "protocol/browser.json",
            digest(b"browser protocol"),
        )],
    };

    assert_eq!(
        artifact.verify(root.path()),
        Err(CompatibilityError::ChromiumBinaryNotInManifest)
    );
}

#[test]
fn rejects_invalid_identity_metadata_before_verifying_files() {
    let root = tempdir().expect("temporary directory must be created");
    write(root.path(), "chrome", b"pinned chromium");
    let mut invalid_identity = identity(digest(b"pinned chromium"));
    invalid_identity.product_version.clear();
    let artifact = CompatibilityArtifact {
        identity: invalid_identity,
        files: vec![ArtifactFile::new(
            "chrome",
            digest(b"pinned chromium"),
        )],
    };

    assert_eq!(
        artifact.verify(root.path()),
        Err(CompatibilityError::InvalidArtifactIdentity {
            field: "product_version"
        })
    );
}

#[test]
fn rejects_manifest_paths_that_escape_or_follow_symlinks() {
    let root = tempdir().expect("temporary directory must be created");
    let outside = tempdir().expect("outside directory must be created");
    write(outside.path(), "chrome", b"outside");

    let traversal = CompatibilityArtifact {
        identity: identity(digest(b"outside")),
        files: vec![ArtifactFile::new("../chrome", digest(b"outside"))],
    };
    assert_eq!(
        traversal.verify(root.path()),
        Err(CompatibilityError::UnsafeRelativePath {
            relative_path: "../chrome".to_owned(),
        })
    );

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path().join("chrome"), root.path().join("chrome"))
            .expect("test symlink must be created");
        let symlink = CompatibilityArtifact {
            identity: identity(digest(b"outside")),
            files: vec![ArtifactFile::new("chrome", digest(b"outside"))],
        };
        assert_eq!(
            symlink.verify(root.path()),
            Err(CompatibilityError::SymlinkNotAllowed {
                relative_path: "chrome".to_owned(),
            })
        );
    }
}

#[test]
fn production_launch_policy_requires_pipe_bfcache_disable_and_both_sandboxes() {
    let args = vec![
        "--remote-debugging-pipe".to_owned(),
        "--disable-features=BackForwardCache".to_owned(),
        "--user-data-dir=/run/browserd/shards/shard-1/profile".to_owned(),
    ];
    assert_eq!(LaunchPolicy::production().validate(&args), Ok(()));

    for forbidden in [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--remote-debugging-port=9222",
        "--remote-debugging-address=0.0.0.0",
    ] {
        let mut invalid = args.clone();
        invalid.push(forbidden.to_owned());
        assert!(matches!(
            LaunchPolicy::production().validate(&invalid),
            Err(CompatibilityError::ForbiddenLaunchArgument { argument }) if argument == forbidden
        ));
    }

    let missing_pipe = args
        .iter()
        .filter(|arg| arg.as_str() != "--remote-debugging-pipe")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        LaunchPolicy::production().validate(&missing_pipe),
        Err(CompatibilityError::RequiredLaunchArgumentMissing {
            argument: "--remote-debugging-pipe".to_owned(),
        })
    );
}

#[test]
fn shared_context_requires_a_complete_receipt_for_the_exact_artifact_and_kernel() {
    let artifact_identity = identity(digest(b"pinned chromium"));
    let mut evidence = QualificationGate::ALL
        .into_iter()
        .map(|gate| {
            (
                gate,
                GateEvidence {
                    passed: true,
                    evidence_digest: digest(format!("{gate:?}").as_bytes()),
                    observations: 1_000,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let receipt = QualificationReceipt {
        artifact_identity: artifact_identity.clone(),
        kernel_release: "6.1.0-52-cloud-amd64".to_owned(),
        qualified_at: Utc
            .with_ymd_and_hms(2026, 8, 24, 14, 0, 0)
            .single()
            .expect("test timestamp must be valid"),
        evidence: evidence.clone(),
    };
    assert!(receipt.allows_shared_context(&artifact_identity, "6.1.0-52-cloud-amd64"));
    assert!(!receipt.allows_shared_context(&artifact_identity, "different-kernel"));

    let other_artifact = identity(digest(b"different chromium"));
    assert!(!receipt.allows_shared_context(&other_artifact, "6.1.0-52-cloud-amd64"));

    evidence.remove(&QualificationGate::PerContextProxyAttribution);
    let missing_gate = QualificationReceipt {
        evidence: evidence.clone(),
        ..receipt.clone()
    };
    assert!(!missing_gate.allows_shared_context(&artifact_identity, "6.1.0-52-cloud-amd64"));

    evidence.insert(
        QualificationGate::PerContextProxyAttribution,
        GateEvidence {
            passed: false,
            evidence_digest: digest(b"failed evidence"),
            observations: 1_000,
        },
    );
    let failed_gate = QualificationReceipt {
        evidence,
        ..receipt
    };
    assert!(!failed_gate.allows_shared_context(&artifact_identity, "6.1.0-52-cloud-amd64"));
}

#[test]
fn readiness_contract_contains_every_behavior_probe_from_the_spec() {
    assert_eq!(
        ReadinessProbe::required(),
        &[
            ReadinessProbe::VersionAndRevision,
            ReadinessProbe::ChromiumSandbox,
            ReadinessProbe::OuterSandbox,
            ReadinessProbe::ContextCreateDispose,
            ReadinessProbe::PerContextProxyAndLoopbackRemoval,
            ReadinessProbe::MandatoryEgressDenial,
            ReadinessProbe::TargetPauseBootstrapResume,
            ReadinessProbe::ContextOwnershipAttribution,
            ReadinessProbe::TargetEmulationBeforeRun,
            ReadinessProbe::ContextDownloadBehavior,
            ReadinessProbe::PdfStreaming,
            ReadinessProbe::ScreencastFrameAck,
            ReadinessProbe::CleanupLeavesNoTargets,
        ]
    );
}
