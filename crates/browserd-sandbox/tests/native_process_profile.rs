#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, ChromiumProcessProfile, CleanupReason, CreateShardOutcome,
    DedicatedEgressSpec, EgressPolicyBinding, InspectResources, LaunchSpec, SandboxBackend,
    SandboxCapabilities, SandboxError, SandboxHandle, SandboxRpcClient, SandboxRpcConfig,
    SandboxRpcServer, SandboxSupervisor, SupervisorConfig, WorkerOwnership,
};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

fn launch_spec() -> LaunchSpec {
    let owner = OwnerFence::new(
        WorkerId::new("native-profile-contract").expect("worker ID is valid"),
        WorkerEpoch::new(7).expect("worker epoch is positive"),
    );
    let fence = EgressFence::new(
        ShardFence::new(
            owner,
            ShardId::new(),
            LaunchGeneration::new(3).expect("launch generation is positive"),
        ),
        RouteGeneration::new(5).expect("route generation is positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation is positive"),
    );
    LaunchSpec::production(
        TenantId::new(),
        DedicatedEgressSpec::new(
            fence,
            EgressPolicyBinding::new("public", [9; 32]).expect("egress policy is valid"),
            Duration::from_millis(50),
        )
        .expect("egress binding is valid"),
        ChromiumBinaryDigest::new([1; 32]),
    )
}

fn native_profile() -> Value {
    json!({
        "schema": "native_locale_v1",
        "locale": "ko-KR",
        "time_zone": "Asia/Seoul",
        "catalog_digest": "02".repeat(32),
        "locale_pak_digest": "03".repeat(32),
        "icu_data_digest": "04".repeat(32),
    })
}

fn native_spec(spec: &LaunchSpec, profile: Value) -> LaunchSpec {
    let mut wire = serde_json::to_value(spec).expect("launch spec serializes");
    wire["process_profile"] = profile;
    serde_json::from_value(wire).expect("typed process profile deserializes")
}

#[test]
fn every_launch_serializes_an_explicit_baseline_profile() {
    let wire = serde_json::to_value(launch_spec()).expect("launch spec serializes");
    assert_eq!(wire["process_profile"], json!({"schema": "baseline_v1"}));
}

#[test]
fn launch_wire_requires_a_known_profile_schema_and_exact_fields() {
    let mut wire = serde_json::to_value(launch_spec()).expect("launch spec serializes");
    wire.as_object_mut()
        .expect("launch spec is an object")
        .remove("process_profile");
    assert!(serde_json::from_value::<LaunchSpec>(wire.clone()).is_err());
    for profile in [
        json!({}),
        json!({"schema": "native_locale_v2"}),
        json!({"schema": "baseline_v1", "locale": "ko-KR"}),
        json!({"schema": "native_locale_v1", "locale": "ko-KR"}),
    ] {
        wire["process_profile"] = profile;
        assert!(serde_json::from_value::<LaunchSpec>(wire.clone()).is_err());
    }
    wire["process_profile"] = native_profile();
    assert!(serde_json::from_value::<LaunchSpec>(wire.clone()).is_ok());
    for field in ["catalog_digest", "locale_pak_digest", "icu_data_digest"] {
        let mut missing = wire.clone();
        missing["process_profile"]
            .as_object_mut()
            .expect("profile is an object")
            .remove(field);
        assert!(serde_json::from_value::<LaunchSpec>(missing).is_err());
        let mut malformed = wire.clone();
        malformed["process_profile"][field] = json!("not-a-digest");
        assert!(serde_json::from_value::<LaunchSpec>(malformed).is_err());
    }
    wire["process_profile"]["environment"] = json!({"LD_PRELOAD": "/tmp/unsafe"});
    assert!(serde_json::from_value::<LaunchSpec>(wire).is_err());
}

#[test]
fn native_user_agent_roundtrips_and_preserves_legacy_absence() {
    let baseline_native: ChromiumProcessProfile =
        serde_json::from_value(native_profile()).expect("native wire");
    assert_eq!(
        serde_json::to_value(&baseline_native).expect("native serialization"),
        native_profile()
    );
    assert_eq!(baseline_native.user_agent(), None);
    let custom = baseline_native
        .with_user_agent(Some("browserd-workers/1.0".to_owned()))
        .expect("immutable custom UA");
    assert_eq!(custom.user_agent(), Some("browserd-workers/1.0"));
    let wire = serde_json::to_value(&custom).expect("serialize custom UA");
    assert_eq!(wire["user_agent"], "browserd-workers/1.0");
    assert_eq!(
        serde_json::from_value::<ChromiumProcessProfile>(wire).expect("native UA roundtrip"),
        custom
    );
    assert!(
        ChromiumProcessProfile::BaselineV1
            .with_user_agent(Some("UA".to_owned()))
            .is_err()
    );
}

#[derive(Clone, Default)]
struct CountingBackend(Arc<AtomicUsize>, Arc<Mutex<Vec<LaunchSpec>>>);

#[async_trait]
impl SandboxBackend for CountingBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.0.fetch_add(1, Ordering::AcqRel);
        self.1
            .lock()
            .expect("recording lock is available")
            .push(spec.clone());
        Ok(SandboxHandle::new(
            spec.shard_id().clone(),
            "native-profile",
        ))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Ok(InspectResources {
            memory_current_bytes: 0,
            memory_peak_bytes: 0,
            process_count: 0,
            egress_route_active: false,
        })
    }
}

fn supervisor(backend: CountingBackend) -> SandboxSupervisor<CountingBackend> {
    SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(1), Duration::from_secs(2))
            .expect("supervisor bounds are valid"),
        backend,
    )
}

fn ownership(spec: &LaunchSpec) -> WorkerOwnership {
    WorkerOwnership::new(
        spec.worker_id().clone(),
        spec.worker_epoch(),
        tokio::time::Instant::now() + Duration::from_millis(900),
    )
}

#[tokio::test]
async fn deserialized_unsafe_profiles_are_rejected_before_provision() {
    let backend = CountingBackend::default();
    let provisions = Arc::clone(&backend.0);
    let supervisor = supervisor(backend);
    let base = launch_spec();
    let mut profiles = Vec::new();
    for locale in [
        "",
        "ko_KR",
        "../ko-KR",
        "ko--KR",
        "ko-KR-",
        "0ko-KR",
        "ko.KR",
        "ko:KR",
        " ko-KR",
        "ko-KR\n",
        "한국어",
        "abcdefghijklmnopq",
    ] {
        let mut profile = native_profile();
        profile["locale"] = json!(locale);
        profiles.push(profile);
    }
    for time_zone in [
        "",
        "/Asia/Seoul",
        "Asia//Seoul",
        "Asia/../Seoul",
        "Asia:Seoul",
        "Asia/Seoul/",
        "Asia/Seoul\n",
        " Asia/Seoul",
        "한국/서울",
    ] {
        let mut profile = native_profile();
        profile["time_zone"] = json!(time_zone);
        profiles.push(profile);
    }
    for user_agent in ["", " ", "unsafe\nUA", "unsafe\0UA"] {
        let mut profile = native_profile();
        profile["user_agent"] = json!(user_agent);
        profiles.push(profile);
    }
    let mut oversized_ua = native_profile();
    oversized_ua["user_agent"] = json!("a".repeat(4097));
    profiles.push(oversized_ua);
    for field in ["catalog_digest", "locale_pak_digest", "icu_data_digest"] {
        let mut profile = native_profile();
        profile[field] = json!("00".repeat(32));
        profiles.push(profile);
    }
    let mut too_long_locale = native_profile();
    too_long_locale["locale"] = json!(["abcdefghijklmno"; 5].join("-"));
    profiles.push(too_long_locale);
    let mut too_long_time_zone = native_profile();
    too_long_time_zone["time_zone"] = json!("A".repeat(129));
    profiles.push(too_long_time_zone);
    for profile in profiles {
        let spec = native_spec(&base, profile.clone());
        let result = supervisor
            .create_shard(spec.clone(), ownership(&spec))
            .await;
        assert_eq!(
            result,
            Err(SandboxError::InvalidChromiumProcessProfile),
            "unsafe profile must be rejected: {profile}"
        );
        assert_eq!(provisions.load(Ordering::Acquire), 0);
    }
}

#[tokio::test]
async fn native_profile_is_an_immutable_part_of_exact_launch_retry_binding() {
    let backend = CountingBackend::default();
    let provisions = Arc::clone(&backend.0);
    let supervisor = supervisor(backend);
    let base = launch_spec();
    let spec = native_spec(&base, native_profile());
    assert_eq!(
        supervisor
            .create_shard(spec.clone(), ownership(&spec))
            .await,
        Ok(CreateShardOutcome::Created),
    );
    assert_eq!(
        supervisor
            .create_shard(spec.clone(), ownership(&spec))
            .await,
        Ok(CreateShardOutcome::AlreadyExists),
    );
    for (field, value) in [
        ("locale", json!("en-US")),
        ("time_zone", json!("UTC")),
        ("catalog_digest", json!("05".repeat(32))),
        ("locale_pak_digest", json!("06".repeat(32))),
        ("icu_data_digest", json!("07".repeat(32))),
        ("user_agent", json!("browserd-immutable-workers/1.0")),
    ] {
        let mut profile = native_profile();
        profile[field] = value;
        let conflict = native_spec(&base, profile);
        assert_eq!(
            supervisor
                .create_shard(conflict.clone(), ownership(&conflict))
                .await,
            Err(SandboxError::LaunchBindingMismatch),
        );
    }
    assert_eq!(
        supervisor
            .create_shard(base.clone(), ownership(&base))
            .await,
        Err(SandboxError::LaunchBindingMismatch),
    );
    assert_eq!(provisions.load(Ordering::Acquire), 1);
}

#[test]
fn native_profile_constructor_and_builder_validate_untrusted_fields() {
    for (locale, time_zone) in [
        ("ko-KR", "Asia/Seoul"),
        ("es-419", "Etc/GMT+9"),
        ("en", "UTC"),
    ] {
        let profile = ChromiumProcessProfile::native_locale(
            locale,
            time_zone,
            ChromiumBinaryDigest::new([2; 32]),
            ChromiumBinaryDigest::new([3; 32]),
            ChromiumBinaryDigest::new([4; 32]),
        )
        .expect("safe syntactic profile is accepted");
        assert_eq!(profile.locale(), Some(locale));
        assert_eq!(profile.timezone(), Some(time_zone));
        let spec = launch_spec()
            .with_process_profile(profile.clone())
            .expect("validated profile binds into launch spec");
        assert_eq!(spec.process_profile(), &profile);
    }
    assert!(
        ChromiumProcessProfile::native_locale(
            "ko_KR",
            "Asia/Seoul",
            ChromiumBinaryDigest::new([2; 32]),
            ChromiumBinaryDigest::new([3; 32]),
            ChromiumBinaryDigest::new([4; 32]),
        )
        .is_err()
    );
    assert!(
        ChromiumProcessProfile::native_locale(
            "ko-KR",
            ":/etc/localtime",
            ChromiumBinaryDigest::new([2; 32]),
            ChromiumBinaryDigest::new([3; 32]),
            ChromiumBinaryDigest::new([4; 32]),
        )
        .is_err()
    );
    let profile: ChromiumProcessProfile = serde_json::from_value({
        let mut wire = native_profile();
        wire["catalog_digest"] = json!("00".repeat(32));
        wire
    })
    .expect("untrusted serialized profile reaches validation");
    assert!(launch_spec().with_process_profile(profile).is_err());
    assert_eq!(ChromiumProcessProfile::BaselineV1.locale(), None);
    assert_eq!(ChromiumProcessProfile::BaselineV1.timezone(), None);
}

#[tokio::test]
async fn sandbox_rpc_preserves_native_profile_and_rejects_missing_or_unknown_schema() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let backend = CountingBackend::default();
    let provisions = Arc::clone(&backend.0);
    let observed_specs = Arc::clone(&backend.1);
    let server = SandboxRpcServer::new(
        Arc::new(supervisor(backend)),
        SandboxRpcConfig::new(
            8 * 1024,
            2,
            Duration::from_millis(500),
            Duration::from_millis(10),
            Some(nix::unistd::Uid::effective().as_raw()),
        )
        .expect("RPC bounds are valid")
        .with_daemon_epoch(1)
        .expect("daemon epoch is positive"),
    );
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    let base = launch_spec();
    let mut request = json!({
        "operation": "create_shard", "sandboxd_epoch": 1,
        "tenant_id": base.tenant_id(), "shard_id": base.shard_id(),
        "worker_id": base.worker_id(), "worker_epoch": base.worker_epoch(),
        "chromium_binary_digest": base.chromium_binary_digest(),
        "dedicated_egress": base.dedicated_egress(), "lease_ttl_ms": 900,
    });
    for profile in [None, Some(json!({"schema": "unknown_v1"}))] {
        if let Some(profile) = profile {
            request["process_profile"] = profile;
        }
        let mut stream = UnixStream::connect(&socket)
            .await
            .expect("raw client connects");
        let bytes = serde_json::to_vec(&request).expect("request serializes");
        stream
            .write_all(
                &u32::try_from(bytes.len())
                    .expect("request length fits")
                    .to_be_bytes(),
            )
            .await
            .expect("frame length writes");
        stream.write_all(&bytes).await.expect("frame writes");
        let mut response = [0; 4];
        let result = tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut response))
            .await
            .expect("invalid request terminates within deadline");
        assert!(
            result.is_err(),
            "unsupported profile wire must close before admission"
        );
        assert_eq!(provisions.load(Ordering::Acquire), 0);
    }
    let mut profile = native_profile();
    profile["user_agent"] = json!("browserd-rpc-workers/1.0");
    let spec = native_spec(&base, profile);
    let client = SandboxRpcClient::new(
        socket,
        8 * 1024,
        Duration::from_secs(1),
        nix::unistd::Uid::effective().as_raw(),
        1,
    )
    .expect("client bounds are valid");
    assert_eq!(
        client
            .create_shard(spec.clone(), Duration::from_millis(900))
            .await,
        Ok(CreateShardOutcome::Created)
    );
    assert_eq!(
        *observed_specs.lock().expect("recording lock is available"),
        vec![spec]
    );
    assert_eq!(provisions.load(Ordering::Acquire), 1);
    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}
