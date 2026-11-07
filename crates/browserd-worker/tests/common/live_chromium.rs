#![allow(clippy::panic)]
//! Local functional tests of the real owner. No production artifact qualification claim.
#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use browserd_cdp::CdpTransportConfig;
use browserd_chromium::{
    ArtifactFile, ChromiumArtifactIdentity, ChromiumConnectionConfig, CompatibilityArtifact,
    NativeLocaleResource, NativeProfileCatalogV1, Sha256Digest, VerifiedNativeProfileCatalog,
};
use browserd_core::{
    EgressFence, IsolationProfile, LaunchGeneration, OwnerFence, PageId, RouteGeneration,
    SessionId, SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumCdpPipes, ChromiumProcessProfile, ContextEgressBinding, ContextEgressRequest,
    ContextRoutePolicy, DedicatedEgressProxyBinding, DedicatedEgressSpec, EgressPolicyBinding,
    LaunchSpec, PinnedNetworkNamespace, ShardEgressReservation, ShardIngressLease,
    ShardIngressReceipt,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActionExecutionResult, CdpChromiumDriver, CdpPipeAcceptor, ChromiumConnectionOwner,
    ChromiumDriver, ChromiumTargetManager, OwnerContextPolicy, TargetManagerDrain,
    WorkerSessionOptionsV1,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe::{Receiver, Sender};

pub struct Drain(AtomicBool);
impl TargetManagerDrain for Drain {
    fn begin_drain(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_some() {
            return;
        }
        let group = nix::unistd::Pid::from_raw(self.0.id() as i32);
        let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGTERM);
        for _ in 0..50 {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
        let _ = self.0.wait();
    }
}

fn file_digest(path: &Path) -> Sha256Digest {
    use std::io::Read;
    let mut file = std::fs::File::open(path).expect("fixture resource");
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("fixture resource bytes");
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Sha256Digest::from_hex(&format!("{:x}", digest.finalize())).expect("SHA-256")
}

struct ConfiguredFixtureArtifact {
    root: PathBuf,
    artifact: CompatibilityArtifact,
    native_catalog: VerifiedNativeProfileCatalog,
    binary_relative_path: PathBuf,
}

fn configured_artifact(
    root: Option<&Path>,
    binary: &Path,
) -> Result<Option<ConfiguredFixtureArtifact>, String> {
    use std::io::Read;

    let Some(root) = root else {
        return Ok(None);
    };
    let canonical_root =
        std::fs::canonicalize(root).map_err(|_| "configured artifact root missing")?;
    if !root.is_absolute() || canonical_root != root {
        return Err(
            "configured artifact root must be an absolute path without symlinks".to_owned(),
        );
    }
    let manifest_path = root.join("compatibility.json");
    let metadata = manifest_path
        .symlink_metadata()
        .map_err(|_| "configured artifact manifest missing")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err("configured artifact manifest must be a bounded regular file".to_owned());
    }
    let mut raw = Vec::new();
    std::fs::File::open(&manifest_path)
        .map_err(|_| "configured artifact manifest unreadable")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "configured artifact manifest unreadable")?;
    if raw.len() > 1024 * 1024 {
        return Err("configured artifact manifest exceeds its size bound".to_owned());
    }
    let artifact: CompatibilityArtifact =
        serde_json::from_slice(&raw).map_err(|_| "configured artifact manifest malformed")?;
    let zero = Sha256Digest::from_hex(&"00".repeat(32)).expect("zero digest");
    if [
        artifact.identity.binary_digest,
        artifact.identity.browser_protocol_schema_digest,
        artifact.identity.js_protocol_schema_digest,
        artifact.identity.launch_profile_digest,
        artifact.identity.extension_bundle_digest,
        artifact.identity.font_bundle_digest,
        artifact.identity.certificate_runtime_bundle_digest,
    ]
    .contains(&zero)
    {
        return Err("configured artifact identity cannot contain fixture digests".to_owned());
    }
    let mut binaries = artifact
        .files
        .iter()
        .filter(|file| file.digest == artifact.identity.binary_digest);
    let binary_relative_path = binaries
        .next()
        .ok_or("configured artifact has no pinned executable")?
        .relative_path
        .clone();
    if binaries.next().is_some() {
        return Err("configured artifact has ambiguous executable mapping".to_owned());
    }
    let pinned_binary = root.join(&binary_relative_path);
    if std::fs::canonicalize(binary).map_err(|_| "configured executable missing")?
        != std::fs::canonicalize(&pinned_binary).map_err(|_| "pinned executable missing")?
        || pinned_binary
            .metadata()
            .map_err(|_| "pinned executable missing")?
            .permissions()
            .mode()
            & 0o111
            == 0
    {
        return Err(
            "functional executable differs from the configured pinned executable".to_owned(),
        );
    }
    // Catalog loading verifies the complete file manifest as well as every native
    // resource. Do not reconstruct an identity from the browser observation.
    let native_catalog = VerifiedNativeProfileCatalog::load(root, &artifact)
        .map_err(|_| "configured artifact files or native catalog failed verification")?;
    Ok(Some(ConfiguredFixtureArtifact {
        root: root.to_path_buf(),
        artifact,
        native_catalog,
        binary_relative_path,
    }))
}

fn fixture_identity(
    configured: Option<&ConfiguredFixtureArtifact>,
    version: &Value,
    binary: &Path,
    launch_profile_digest: Sha256Digest,
) -> ChromiumArtifactIdentity {
    if let Some(configured) = configured {
        return configured.artifact.identity.clone();
    }
    let digest = Sha256Digest::from_hex(&"00".repeat(32)).expect("fixture digest");
    ChromiumArtifactIdentity {
        binary_digest: file_digest(binary),
        product_version: version["product"]
            .as_str()
            .expect("product")
            .split_once('/')
            .expect("product version")
            .1
            .to_owned(),
        chromium_revision: version["revision"].as_str().expect("revision").to_owned(),
        browser_protocol_schema_digest: digest,
        js_protocol_schema_digest: digest,
        launch_profile_digest,
        extension_bundle_digest: digest,
        font_bundle_digest: digest,
        certificate_runtime_bundle_digest: digest,
    }
}

/// Makes a private resource alias without changing the shared executable or its assets.
/// The catalog describes local fixture bytes; it does not qualify a production artifact.
fn native_fixture(
    source: &Path,
    directory: &Path,
    options: &WorkerSessionOptionsV1,
    configured: Option<&ConfiguredFixtureArtifact>,
) -> (PathBuf, ChromiumProcessProfile, Sha256Digest) {
    if let Some(configured) = configured {
        let expected_profile = configured
            .native_catalog
            .process_profile(&options.locale, &options.timezone)
            .expect("configured native profile");
        let artifact = directory.join("native-artifact");
        std::fs::create_dir(&artifact).expect("private configured artifact");
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o700))
            .expect("private configured artifact permissions");
        // Keep the supplied manifest geometry and exact catalog bytes. Immutable
        // links avoid copying the full runtime/font inventory for each browser.
        for file in &configured.artifact.files {
            let source = configured.root.join(&file.relative_path);
            let destination = artifact.join(&file.relative_path);
            std::fs::create_dir_all(destination.parent().expect("resource directory"))
                .expect("private resource directory");
            std::fs::hard_link(&source, &destination)
                .or_else(|error| {
                    if source.metadata()?.len() > 1024 * 1024 {
                        return Err(error);
                    }
                    std::fs::copy(&source, &destination).map(|_| ())
                })
                .expect("immutable configured resource link (large copies are disabled)");
        }
        let binary = artifact.join(&configured.binary_relative_path);
        let locale_resource = configured
            .native_catalog
            .locale_resources()
            .iter()
            .find(|resource| resource.locale == options.locale)
            .expect("configured locale resource");
        let locales = binary.parent().expect("module directory").join("locales");
        std::fs::create_dir_all(&locales).expect("private module locale directory");
        let exact_locale = locales.join(format!("{}.pak", options.locale));
        if exact_locale.exists() {
            assert_eq!(file_digest(&exact_locale), locale_resource.digest);
        } else {
            let locale_copy = artifact.join(
                locale_resource
                    .source
                    .strip_prefix(&configured.root)
                    .expect("verified locale within configured artifact"),
            );
            std::fs::hard_link(locale_copy, &exact_locale).expect("private exact locale alias");
        }
        let verified = VerifiedNativeProfileCatalog::load(&artifact, &configured.artifact)
            .expect("verified configured fixture snapshot");
        let process_profile = verified
            .process_profile(&options.locale, &options.timezone)
            .expect("verified configured fixture profile");
        assert_eq!(process_profile, expected_profile);
        return (binary, process_profile, verified.catalog_digest());
    }
    assert_eq!(
        options.locale, "ko-KR",
        "the fixture catalog supports ko-KR"
    );
    let source_directory = source.parent().expect("Chromium resource directory");
    let artifact = directory.join("native-artifact");
    std::fs::create_dir(&artifact).expect("private native artifact");
    std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o700))
        .expect("private artifact permissions");
    let binary = artifact.join(source.file_name().expect("Chromium binary name"));
    // /proc/self/exe must resolve into this private directory for DIR_LOCALES.
    // A symlink to the original executable would resolve back to shared assets.
    std::fs::hard_link(source, &binary)
        .or_else(|_| std::fs::copy(source, &binary).map(|_| ()))
        .expect("private executable with unchanged bytes");
    for entry in std::fs::read_dir(source_directory).expect("fixture resources") {
        let entry = entry.expect("fixture resource entry");
        if entry.path() == source
            || entry.file_name() == "locales"
            || entry.file_name() == "icudtl.dat"
            || entry.file_name() == "native-process-profiles.json"
        {
            continue;
        }
        std::os::unix::fs::symlink(entry.path(), artifact.join(entry.file_name()))
            .expect("fixture resource link");
    }
    let locales = artifact.join("locales");
    std::fs::create_dir(&locales).expect("private locale directory");
    let locale_pak = locales.join("ko.pak");
    std::fs::hard_link(source_directory.join("locales/ko.pak"), &locale_pak)
        .or_else(|_| {
            std::fs::copy(source_directory.join("locales/ko.pak"), &locale_pak).map(|_| ())
        })
        .expect("private locale resource with unchanged bytes");
    std::fs::hard_link(&locale_pak, locales.join("ko-KR.pak"))
        .expect("exact locale resource alias");
    let icu_data = artifact.join("icudtl.dat");
    std::fs::hard_link(source_directory.join("icudtl.dat"), &icu_data)
        .or_else(|_| std::fs::copy(source_directory.join("icudtl.dat"), &icu_data).map(|_| ()))
        .expect("private ICU resource with unchanged bytes");
    let binary_digest = file_digest(&binary);
    let locale_pak_digest = file_digest(&locale_pak);
    let icu_data_digest = file_digest(&icu_data);
    let catalog = serde_json::to_vec(&NativeProfileCatalogV1 {
        schema_version: 1,
        icu_data: PathBuf::from("icudtl.dat"),
        locales: vec![NativeLocaleResource {
            locale: "ko-KR".to_owned(),
            pak: PathBuf::from("locales/ko.pak"),
        }],
        time_zones: vec!["Asia/Seoul".to_owned()],
    })
    .expect("fixture catalog");
    std::fs::write(artifact.join("native-process-profiles.json"), &catalog)
        .expect("private fixture catalog");
    let catalog_digest = Sha256Digest::from_hex(&format!("{:x}", Sha256::digest(&catalog)))
        .expect("fixture catalog SHA-256");
    let fixture_digest = Sha256Digest::from_hex(&"00".repeat(32)).expect("fixture digest");
    let manifest = CompatibilityArtifact {
        identity: ChromiumArtifactIdentity {
            binary_digest,
            // Version and revision are probed from the launched process below.
            // This prelaunch identity only verifies local resource bytes.
            product_version: "local-functional-fixture".to_owned(),
            chromium_revision: "local-functional-fixture".to_owned(),
            browser_protocol_schema_digest: fixture_digest,
            js_protocol_schema_digest: fixture_digest,
            launch_profile_digest: catalog_digest,
            extension_bundle_digest: fixture_digest,
            font_bundle_digest: fixture_digest,
            certificate_runtime_bundle_digest: fixture_digest,
        },
        files: vec![
            ArtifactFile::new(
                source.file_name().expect("Chromium binary name"),
                binary_digest,
            ),
            ArtifactFile::new("icudtl.dat", icu_data_digest),
            ArtifactFile::new("locales/ko.pak", locale_pak_digest),
            ArtifactFile::new("native-process-profiles.json", catalog_digest),
        ],
    };
    let verified = VerifiedNativeProfileCatalog::load(&artifact, &manifest)
        .expect("verified functional fixture native catalog");
    let process_profile = verified
        .process_profile(&options.locale, &options.timezone)
        .expect("fixture native profile");
    (binary, process_profile, catalog_digest)
}

#[test]
fn native_fixture_preserves_read_only_source_catalog() {
    let source = tempfile::tempdir().expect("source artifact");
    let binary = source.path().join("chromium");
    std::fs::write(&binary, b"fixture executable").expect("source executable");
    std::fs::write(source.path().join("icudtl.dat"), b"fixture ICU").expect("source ICU");
    std::fs::create_dir(source.path().join("locales")).expect("source locales");
    std::fs::write(source.path().join("locales/ko.pak"), b"fixture locale").expect("source locale");
    let catalog_path = source.path().join("native-process-profiles.json");
    let source_catalog = b"immutable source artifact catalog";
    std::fs::write(&catalog_path, source_catalog).expect("source catalog");
    std::fs::set_permissions(&catalog_path, std::fs::Permissions::from_mode(0o400))
        .expect("read-only source catalog");
    let private = tempfile::tempdir().expect("private fixture");
    let options = WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: browserd_worker::WorkerViewport {
            width: 1440,
            height: 900,
            device_scale_factor: 2,
        },
        locale: "ko-KR".to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: None,
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 1800,
        idle_timeout_seconds: 600,
        metadata: Default::default(),
    };
    let (fixture_binary, _, _) = native_fixture(&binary, private.path(), &options, None);
    let private_catalog = fixture_binary
        .parent()
        .expect("private artifact")
        .join("native-process-profiles.json");
    assert!(!private_catalog.is_symlink());
    assert_eq!(
        std::fs::read(&catalog_path).expect("source unchanged"),
        source_catalog
    );
    assert_ne!(
        std::fs::read(private_catalog).expect("fixture catalog"),
        source_catalog
    );
}

pub struct LiveChromium {
    pub driver: CdpChromiumDriver,
    pub owner: Arc<ChromiumConnectionOwner<Drain>>,
    pub targets: Arc<ChromiumTargetManager<Drain>>,
    pub default_user_agent: String,
    pub session: SessionId,
    pub page: PageId,
    pub tenant: TenantId,
    pub fence: OwnershipFence,
    _process: Process,
    _profile: tempfile::TempDir,
    _network_namespace: Option<PinnedNetworkNamespace>,
    shared_launch: Option<LaunchSpec>,
    shared_options: Option<WorkerSessionOptionsV1>,
    pub initial_context_binding: Option<ContextEgressBinding>,
}

impl LiveChromium {
    pub async fn start() -> Self {
        Self::start_owned(None, None, false, false, false).await
    }

    pub async fn start_with_options(options: WorkerSessionOptionsV1) -> Self {
        Self::start_owned(Some(options), None, false, false, false).await
    }

    /// Exercises the production owner's context routing against a controlled
    /// loopback proxy. This does not create or qualify a production egress route.
    pub async fn start_with_proxy(proxy_address: SocketAddr) -> Self {
        assert!(proxy_address.ip().is_loopback() && proxy_address.port() != 0);
        Self::start_owned(None, Some(proxy_address), false, false, false).await
    }

    /// Explicit local functional pool. These manufactured test capabilities never qualify
    /// or configure a production supervisor or placement policy.
    pub async fn start_shared_with_proxy(proxy_address: SocketAddr) -> Self {
        assert!(proxy_address.ip().is_loopback() && proxy_address.port() != 0);
        let options = WorkerSessionOptionsV1 {
            workload_class_hint: "interactive".to_owned(),
            viewport: browserd_worker::WorkerViewport {
                width: 800,
                height: 600,
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
            ttl_seconds: 1800,
            idle_timeout_seconds: 600,
            metadata: Default::default(),
        };
        Self::start_owned(Some(options), Some(proxy_address), false, false, true).await
    }

    /// Functional-only scratch handoff within the test's isolated user/mount namespace.
    /// The real tmpfs FD is revalidated; this is not a production launch-gate receipt.
    pub async fn start_with_downloads(proxy_address: SocketAddr) -> Self {
        Self::start_owned(None, Some(proxy_address), true, true, false).await
    }

    /// Authenticated physical scratch with browser downloads still denied.
    pub async fn start_with_files(proxy_address: SocketAddr) -> Self {
        Self::start_owned(None, Some(proxy_address), false, true, false).await
    }

    async fn start_owned(
        options: Option<WorkerSessionOptionsV1>,
        proxy_address: Option<SocketAddr>,
        downloads: bool,
        browser_files: bool,
        shared: bool,
    ) -> Self {
        let shared_options = shared.then(|| options.clone().expect("shared Native options"));
        let source_binary = std::env::var_os("BROWSERD_TEST_CHROMIUM")
            .expect("BROWSERD_TEST_CHROMIUM is required for the live owner gate");
        let source_binary =
            std::fs::canonicalize(source_binary).expect("functional Chromium executable");
        let artifact_root = std::env::var_os("BROWSERD_CHROMIUM_ARTIFACT_ROOT").map(PathBuf::from);
        let configured = configured_artifact(artifact_root.as_deref(), &source_binary)
            .expect("configured functional artifact admission");
        let profile = tempfile::tempdir().expect("private Chromium profile");
        std::fs::set_permissions(profile.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private profile permissions");
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/chromium_pipe_fixture.py");
        let (binary, process_profile, launch_profile_digest) = match options.as_ref() {
            Some(options) => {
                native_fixture(&source_binary, profile.path(), options, configured.as_ref())
            }
            None => (
                source_binary,
                ChromiumProcessProfile::BaselineV1,
                configured.as_ref().map_or_else(
                    || Sha256Digest::from_hex(&"00".repeat(32)).expect("baseline fixture digest"),
                    |configured| configured.artifact.identity.launch_profile_digest,
                ),
            ),
        };
        let process_profile = match options.as_ref() {
            Some(options) => process_profile
                .with_user_agent(options.user_agent.clone())
                .expect("functional immutable user agent"),
            None => process_profile,
        };
        let locale = process_profile.locale().unwrap_or("en-US");
        let mut command = Command::new("python3");
        command
            .arg(script)
            .arg(&binary)
            .arg(profile.path())
            .arg(profile.path().join("cdp-target-evidence.jsonl"))
            .arg(process_profile.user_agent().unwrap_or(""))
            .arg(process_profile.locale().unwrap_or(""))
            .env("LANGUAGE", locale)
            // Native paths require an installed UTF-8 C locale. A missing language-specific
            // libc locale falls back to ASCII and Chromium silently drops Korean filenames.
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env_remove("LC_MESSAGES")
            .env("TZ", process_profile.timezone().unwrap_or("UTC"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .process_group(0);
        let mut process = Process(command.spawn().expect("Chromium pipe fixture"));
        let mut sender = Sender::from_owned_fd(process.0.stdin.take().expect("stdin").into())
            .expect("CDP sender");
        let mut receiver = Receiver::from_owned_fd(process.0.stdout.take().expect("stdout").into())
            .expect("CDP receiver");
        sender
            .write_all(b"{\"id\":999999,\"method\":\"Browser.getVersion\",\"params\":{}}\0")
            .await
            .expect("version probe");
        let version = tokio::time::timeout(Duration::from_secs(15), async {
            let mut frame = Vec::new();
            loop {
                let byte = receiver
                    .read_u8()
                    .await
                    .expect("Chromium sandbox launch/version response");
                if byte == 0 {
                    break;
                }
                assert!(frame.len() < 65536, "bounded version probe");
                frame.push(byte);
            }
            serde_json::from_slice::<Value>(&frame).expect("version frame")["result"].clone()
        })
        .await
        .expect("Chromium version probe timed out");
        let pipes = ChromiumCdpPipes::from_owned_fds(
            sender.into_blocking_fd().expect("sender fd"),
            receiver.into_blocking_fd().expect("receiver fd"),
        )
        .expect("owner pipes");
        let expected = fixture_identity(
            configured.as_ref(),
            &version,
            &binary,
            launch_profile_digest,
        );
        let worker = WorkerId::new("live-functional-test").expect("worker");
        let shard = ShardFence::new(
            OwnerFence::new(worker.clone(), WorkerEpoch::new(1).unwrap()),
            ShardId::new(),
            LaunchGeneration::new(1).unwrap(),
        );
        let config = ChromiumConnectionConfig {
            transport: CdpTransportConfig {
                max_frame_bytes: 4 * 1024 * 1024,
                max_pending_commands: 64,
                command_queue_capacity: 64,
                event_queue_capacity: 256,
                write_timeout: Duration::from_secs(3),
                default_command_timeout: Duration::from_secs(5),
            },
            version_probe_timeout: Duration::from_secs(5),
            max_version_field_bytes: 4096,
        };
        let tenant = TenantId::new();
        let session = SessionId::new();
        let launch = LaunchSpec::production(
            tenant.clone(),
            DedicatedEgressSpec::new(
                EgressFence::new(
                    shard.clone(),
                    RouteGeneration::new(1).unwrap(),
                    session.clone(),
                    SessionIncarnation::new(1).unwrap(),
                ),
                EgressPolicyBinding::new("functional-fixture", [7; 32]).unwrap(),
                Duration::from_secs(if shared { 120 } else { 30 }),
            )
            .unwrap(),
            expected.binary_digest.into(),
        )
        .with_process_profile(process_profile)
        .expect("functional fixture launch profile");
        let fence = OwnershipFence::new(worker, 1, 1, 1);
        let launch = if shared {
            launch
                .with_context_route_policy(
                    ContextRoutePolicy::new(fence.as_placement_fence(), false, 8, 500)
                        .expect("functional shared route policy"),
                )
                .expect("functional shared launch")
        } else {
            launch
        };
        let shared_launch = shared.then(|| launch.clone());
        let (pipes, network_namespace, initial_context_binding) = match proxy_address {
            Some(proxy_address) => {
                // Keep the actual namespace descriptor alive with the fixture.
                // The local lease describes this test attachment, not a sandboxd
                // approval or evidence of mandatory production egress enforcement.
                let namespace = PinnedNetworkNamespace::from_owned_fd(
                    std::fs::File::open("/proc/thread-self/ns/net")
                        .expect("current functional fixture network namespace")
                        .into(),
                )
                .expect("pinned functional fixture network namespace");
                let lease = ShardIngressLease::from_attachment(
                    ShardEgressReservation::from_launch_spec(&launch),
                    namespace.identity(),
                    ShardIngressReceipt::with_proxy_address(proxy_address)
                        .expect("functional loopback proxy receipt"),
                );
                let binding = DedicatedEgressProxyBinding::from_lease(&lease)
                    .expect("exact functional fixture route binding");
                let mut pipes = pipes
                    .with_egress_proxy_binding(binding.clone())
                    .expect("route-bound functional CDP pipes");
                if browser_files {
                    use browserd_sandbox::{
                        SANDBOX_SCRATCH_MAX_BYTES, SANDBOX_SCRATCH_PATH, SandboxScratch,
                        ScratchMetadata,
                    };
                    use std::os::unix::fs::MetadataExt;
                    let directory = std::fs::File::open(SANDBOX_SCRATCH_PATH)
                        .expect("isolated mounted scratch");
                    let metadata = directory.metadata().expect("scratch inode");
                    let description: ScratchMetadata = serde_json::from_value(json!({
                        "version":1,"sandbox_path":SANDBOX_SCRATCH_PATH,"max_bytes":SANDBOX_SCRATCH_MAX_BYTES,
                        "owner_uid":metadata.uid(),"device":metadata.dev(),"inode":metadata.ino(),"binding":binding,
                    })).expect("functional exact scratch description");
                    let scratch = SandboxScratch::from_owned_fd(directory.into(), description)
                        .expect("bounded tmpfs validation is mandatory for this fixture");
                    pipes = pipes.with_scratch(scratch).expect("one scratch capability");
                }
                let context_binding = shared.then(|| {
                    ContextEgressBinding::new(
                        ContextEgressRequest::initial(&launch).expect("initial request"),
                        1,
                        1,
                        binding,
                        Duration::from_secs(120),
                    )
                    .expect("functional context capability")
                });
                (pipes, Some(namespace), context_binding)
            }
            None => (pipes, None, None),
        };
        let drain = Arc::new(Drain(AtomicBool::new(false)));
        let (owner, manager) = if shared {
            ChromiumConnectionOwner::new_bounded_for_pooled_launch(
                expected,
                config,
                shard,
                256,
                drain,
                launch.clone(),
                OwnerContextPolicy::shared(8, 500).expect("functional owner policy"),
            )
        } else if proxy_address.is_some() {
            ChromiumConnectionOwner::new_bounded_for_routed_launch(
                expected, config, shard, 256, drain, launch,
            )
        } else {
            ChromiumConnectionOwner::new_bounded_for_launch(
                expected, config, shard, 256, drain, launch,
            )
        }
        .expect("owner");
        if downloads {
            owner
                .enable_downloads()
                .expect("explicit functional download opt-in");
        }
        owner
            .accept_cdp_pipes(pipes)
            .await
            .expect("accept live Chromium");
        manager
            .bootstrap()
            .await
            .expect("bootstrap live target manager");
        let driver = owner
            .chromium_driver(if shared {
                IsolationProfile::SharedContext
            } else {
                IsolationProfile::DedicatedProcess
            })
            .with_privileged_evaluate(
                shared
                    || options
                        .as_ref()
                        .is_some_and(|options| options.feature_profile == "privileged"),
            );
        if shared {
            let backend = owner.target_manager_backend();
            let binding = initial_context_binding.clone().expect("initial capability");
            let tenant = tenant.clone();
            let session = session.clone();
            let fence = fence.clone();
            let valid_until = Instant::now() + binding.granted_ttl();
            tokio::task::spawn_blocking(move || {
                backend.register_context_egress(tenant, session, fence, binding, valid_until)
            })
            .await
            .unwrap()
            .expect("initial context authority");
        }
        let page = tokio::task::spawn_blocking({
            let driver = driver.clone();
            let tenant = tenant.clone();
            let session = session.clone();
            let fence = fence.clone();
            move || match options {
                Some(options) => {
                    driver.create_context_owned_with_options(&tenant, &session, &fence, &options)
                }
                None => driver.create_context_owned(&tenant, &session, &fence),
            }
        })
        .await
        .unwrap()
        .expect("owned browser context");
        Self {
            driver,
            owner,
            targets: manager,
            default_user_agent: version["userAgent"]
                .as_str()
                .expect("version UA")
                .to_owned(),
            tenant,
            session,
            page,
            fence,
            _process: process,
            _profile: profile,
            _network_namespace: network_namespace,
            shared_launch,
            shared_options,
            initial_context_binding,
        }
    }

    pub async fn add_shared_context(
        &self,
        tenant: TenantId,
        proxy_address: SocketAddr,
        route_generation: u64,
    ) -> (SessionId, PageId, OwnershipFence, ContextEgressBinding) {
        let launch = self
            .shared_launch
            .as_ref()
            .expect("explicit shared fixture");
        let session = SessionId::new();
        let fence = self.fence.clone();
        let egress = DedicatedEgressSpec::new(
            EgressFence::new(
                launch.dedicated_egress().egress_fence().shard().clone(),
                RouteGeneration::new(route_generation).unwrap(),
                session.clone(),
                SessionIncarnation::new(fence.session_incarnation()).unwrap(),
            ),
            launch.dedicated_egress().policy_binding().clone(),
            Duration::from_secs(120),
        )
        .unwrap();
        let request =
            ContextEgressRequest::new(tenant.clone(), fence.as_placement_fence(), egress.clone())
                .unwrap();
        let route_launch =
            LaunchSpec::production(tenant.clone(), egress, launch.chromium_binary_digest())
                .with_process_profile(launch.process_profile().clone())
                .unwrap()
                .with_context_route_policy(launch.context_route_policy().unwrap().clone())
                .unwrap();
        let lease = ShardIngressLease::from_attachment(
            ShardEgressReservation::from_launch_spec(&route_launch),
            self._network_namespace.as_ref().unwrap().identity(),
            ShardIngressReceipt::with_proxy_address(proxy_address).unwrap(),
        );
        let binding = ContextEgressBinding::new(
            request,
            1,
            1,
            DedicatedEgressProxyBinding::from_lease(&lease).unwrap(),
            Duration::from_secs(120),
        )
        .unwrap();
        let backend = self.owner.target_manager_backend();
        let driver = self.driver.clone();
        let options = self.shared_options.clone().expect("shared Native options");
        let valid_until = Instant::now() + binding.granted_ttl();
        let page = tokio::task::spawn_blocking({
            let tenant = tenant.clone();
            let session = session.clone();
            let fence = fence.clone();
            let binding = binding.clone();
            move || {
                backend
                    .register_context_egress(
                        tenant.clone(),
                        session.clone(),
                        fence.clone(),
                        binding,
                        valid_until,
                    )
                    .expect("shared route authority");
                driver
                    .create_context_owned_with_options(&tenant, &session, &fence, &options)
                    .expect("additional owned shared context")
            }
        })
        .await
        .unwrap();
        (session, page, fence, binding)
    }

    pub async fn action(&self, command: Value) -> ActionExecutionResult {
        let driver = self.driver.clone();
        let session = self.session.clone();
        let page = self.page.clone();
        tokio::task::spawn_blocking(move || {
            driver.execute_action_until(
                &session,
                Some(&page),
                &serde_json::to_vec(&command).unwrap(),
                Instant::now() + Duration::from_secs(10),
            )
        })
        .await
        .unwrap()
    }

    pub async fn value(&self, command: Value) -> Value {
        let result = self.action(command).await;
        let ActionExecutionResult::Succeeded(bytes) = result else {
            panic!("live action failed: {result:?}");
        };
        serde_json::from_slice(&bytes).expect("action JSON")
    }

    pub async fn evaluate(&self, expression: &str) -> Value {
        self.value(json!({"type":"evaluate","expression":expression}))
            .await["value"]
            .clone()
    }

    pub async fn node(&self, selector: &str) -> String {
        self.value(json!({"type":"query_all","selector":selector}))
            .await["node_refs"][0]
            .as_str()
            .expect("node ref")
            .to_owned()
    }

    pub fn observed_iframe_target(&self) -> bool {
        self.observed_target_count("iframe") != 0
    }

    pub fn observed_target_count(&self, kind: &str) -> usize {
        std::fs::read_to_string(self._profile.path().join("cdp-target-evidence.jsonl"))
            .expect("private target evidence")
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["attached_target_kind"] == kind)
            .count()
    }

    pub fn observed_target_ids(&self, kind: &str) -> Vec<String> {
        std::fs::read_to_string(self._profile.path().join("cdp-target-evidence.jsonl"))
            .expect("private target evidence")
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["attached_target_kind"] == kind)
            .filter_map(|event| event["target_id"].as_str().map(str::to_owned))
            .collect()
    }
}

#[cfg(test)]
mod configured_artifact_tests {
    use super::*;

    fn source_artifact(nested: bool) -> (tempfile::TempDir, PathBuf, CompatibilityArtifact) {
        let root = tempfile::tempdir().expect("configured artifact");
        let binary_relative = if nested { "bin/chromium" } else { "chromium" };
        let icu_relative = if nested {
            "bin/icudtl.dat"
        } else {
            "icudtl.dat"
        };
        let pak_relative = if nested {
            "resources/ko.pak"
        } else {
            "locales/ko.pak"
        };
        let catalog = serde_json::to_vec_pretty(&NativeProfileCatalogV1 {
            schema_version: 1,
            icu_data: PathBuf::from(icu_relative),
            locales: vec![NativeLocaleResource {
                locale: "ko-KR".to_owned(),
                pak: PathBuf::from(pak_relative),
            }],
            time_zones: vec!["Asia/Seoul".to_owned(), "UTC".to_owned()],
        })
        .unwrap();
        let resources: Vec<(&str, &[u8])> = vec![
            (binary_relative, b"configured Chromium executable"),
            (icu_relative, b"configured ICU"),
            (pak_relative, b"configured Korean locale"),
            ("native-process-profiles.json", &catalog),
            ("protocol/browser.json", b"configured browser protocol"),
            ("protocol/js.json", b"configured JavaScript protocol"),
            ("bundles/extensions.json", b"configured extension inventory"),
            ("bundles/fonts.json", b"configured font inventory"),
            (
                "bundles/runtime.json",
                b"configured certificate/runtime inventory",
            ),
        ];
        let mut files = Vec::new();
        for (relative, data) in resources {
            let path = root.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, data).unwrap();
            files.push(ArtifactFile::new(relative, file_digest(&path)));
        }
        let binary = root.path().join(binary_relative);
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o500)).unwrap();
        let identity = ChromiumArtifactIdentity {
            binary_digest: file_digest(&binary),
            product_version: "153.0.8010.12".to_owned(),
            chromium_revision: "pinned-configured-revision".to_owned(),
            browser_protocol_schema_digest: file_digest(&root.path().join("protocol/browser.json")),
            js_protocol_schema_digest: file_digest(&root.path().join("protocol/js.json")),
            launch_profile_digest: file_digest(&root.path().join("native-process-profiles.json")),
            extension_bundle_digest: file_digest(&root.path().join("bundles/extensions.json")),
            font_bundle_digest: file_digest(&root.path().join("bundles/fonts.json")),
            certificate_runtime_bundle_digest: file_digest(
                &root.path().join("bundles/runtime.json"),
            ),
        };
        let artifact = CompatibilityArtifact { identity, files };
        std::fs::write(
            root.path().join("compatibility.json"),
            serde_json::to_vec(&artifact).unwrap(),
        )
        .unwrap();
        (root, binary, artifact)
    }

    fn configured(
        root: &Path,
        binary: &Path,
        artifact: CompatibilityArtifact,
    ) -> ConfiguredFixtureArtifact {
        let native_catalog = VerifiedNativeProfileCatalog::load(root, &artifact).unwrap();
        let binary_relative_path = binary.strip_prefix(root).unwrap().to_path_buf();
        ConfiguredFixtureArtifact {
            root: root.to_path_buf(),
            artifact,
            native_catalog,
            binary_relative_path,
        }
    }

    fn options() -> WorkerSessionOptionsV1 {
        WorkerSessionOptionsV1 {
            workload_class_hint: "interactive".to_owned(),
            viewport: browserd_worker::WorkerViewport {
                width: 1440,
                height: 900,
                device_scale_factor: 2,
            },
            locale: "ko-KR".to_owned(),
            timezone: "Asia/Seoul".to_owned(),
            user_agent: None,
            network_policy_id: "public-web-default".to_owned(),
            network_class: "public".to_owned(),
            checkpoint_ref: None,
            dialog_policy: "auto_dismiss".to_owned(),
            feature_profile: "standard".to_owned(),
            ttl_seconds: 1800,
            idle_timeout_seconds: 600,
            metadata: Default::default(),
        }
    }

    #[test]
    fn configured_artifact_keeps_all_supplied_identity_fields_despite_live_observation() {
        let (root, binary, artifact) = source_artifact(false);
        let expected = artifact.identity.clone();
        let pinned = configured(root.path(), &binary, artifact);
        let observed =
            json!({"product":"HeadlessChrome/unrelated-version", "revision":"unrelated-revision"});
        assert_eq!(
            fixture_identity(
                Some(&pinned),
                &observed,
                &binary,
                Sha256Digest::from_hex(&"00".repeat(32)).unwrap()
            ),
            expected
        );
    }

    #[test]
    fn configured_artifact_verifies_complete_manifest_and_native_catalog() {
        let (root, binary, artifact) = source_artifact(false);
        let pinned = configured_artifact(Some(root.path()), &binary)
            .unwrap()
            .expect("configured identity required");
        assert_eq!(pinned.artifact, artifact);
        assert_eq!(
            pinned.native_catalog.catalog_digest(),
            artifact.identity.launch_profile_digest
        );
        assert_eq!(pinned.binary_relative_path, Path::new("chromium"));
    }

    #[test]
    fn configured_artifact_rejects_another_executable_even_with_identical_bytes() {
        let (root, binary, _) = source_artifact(false);
        let other = tempfile::tempdir().unwrap();
        let other_binary = other.path().join("chromium");
        std::fs::copy(binary, &other_binary).unwrap();
        assert!(configured_artifact(Some(root.path()), &other_binary).is_err());
    }

    #[test]
    fn configured_artifact_rejects_malformed_manifest_before_launch() {
        let (root, binary, _) = source_artifact(false);
        std::fs::write(root.path().join("compatibility.json"), b"{not JSON").unwrap();
        assert!(configured_artifact(Some(root.path()), &binary).is_err());
    }

    #[test]
    fn configured_artifact_rejects_every_changed_resource_before_launch() {
        for relative in [
            "chromium",
            "icudtl.dat",
            "locales/ko.pak",
            "protocol/browser.json",
            "bundles/fonts.json",
        ] {
            let (root, binary, _) = source_artifact(false);
            if relative == "chromium" {
                std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            std::fs::write(root.path().join(relative), b"changed artifact bytes").unwrap();
            assert!(
                configured_artifact(Some(root.path()), &binary).is_err(),
                "resource {relative}"
            );
        }
    }

    #[test]
    fn configured_artifact_rejects_manifest_symlink_and_nonregular_file_before_read() {
        for nonregular in [false, true] {
            let (root, binary, _) = source_artifact(false);
            let manifest = root.path().join("compatibility.json");
            std::fs::rename(&manifest, root.path().join("original.json")).unwrap();
            if nonregular {
                nix::unistd::mkfifo(
                    &manifest,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )
                .unwrap();
            } else {
                std::os::unix::fs::symlink(root.path().join("original.json"), &manifest).unwrap();
            }
            assert!(configured_artifact(Some(root.path()), &binary).is_err());
        }
    }

    #[test]
    fn configured_artifact_native_snapshot_preserves_catalog_identity_geometry_and_source() {
        let (root, binary, artifact) = source_artifact(true);
        let catalog_path = root.path().join("native-process-profiles.json");
        let original = std::fs::read(&catalog_path).unwrap();
        std::fs::set_permissions(&catalog_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let pinned = configured(root.path(), &binary, artifact.clone());
        let private = tempfile::tempdir().unwrap();
        let (fixture_binary, profile, catalog_digest) =
            native_fixture(&binary, private.path(), &options(), Some(&pinned));
        let private_root = private.path().join("native-artifact");
        assert_eq!(fixture_binary, private_root.join("bin/chromium"));
        assert_eq!(catalog_digest, artifact.identity.launch_profile_digest);
        assert_eq!(
            profile,
            pinned
                .native_catalog
                .process_profile("ko-KR", "Asia/Seoul")
                .unwrap()
        );
        assert_eq!(std::fs::read(&catalog_path).unwrap(), original);
        assert_eq!(
            std::fs::read(private_root.join("native-process-profiles.json")).unwrap(),
            original
        );
        assert!(
            !private_root
                .join("native-process-profiles.json")
                .is_symlink()
        );
        artifact.verify(&private_root).unwrap();
        assert_eq!(
            std::fs::read(private_root.join("bin/locales/ko-KR.pak")).unwrap(),
            std::fs::read(root.path().join("resources/ko.pak")).unwrap()
        );
    }

    #[test]
    fn configured_artifact_absence_retains_unpinned_functional_fixture() {
        assert!(
            configured_artifact(None, Path::new("/missing/unconfigured-browser"))
                .unwrap()
                .is_none()
        );
    }
}
