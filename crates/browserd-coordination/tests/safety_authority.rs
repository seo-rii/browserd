#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_coordination::{
    CoordinationActorConfig, MemorySafetyAuthority, RedisSafetyAuthority,
    RedisSafetyAuthorityConfig, SafetyActorIdentity, SafetyAuditAck, SafetyAuditIntent,
    SafetyAuthority, SafetyAuthorityBlockingClient, SafetyAuthorityClock, SafetyAuthorityConfig,
    SafetyAuthorityError as Error, SafetyAuthoritySnapshot, SafetyInitializeRequest,
    SafetyMutationReceipt, SafetyMutationRequest, SafetyObserver,
};
use browserd_core::{
    RuntimeSafetyCache, SafetySwitchMutation as Mutation, SafetySwitchSnapshot, TenantId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn identity(name: &str) -> SafetyActorIdentity {
    SafetyActorIdentity::new(
        "018f9ac0-0000-7000-8000-000000000001".parse().unwrap(),
        name,
    )
    .unwrap()
}
fn initialize() -> SafetyInitializeRequest {
    SafetyInitializeRequest::new(
        identity("operator"),
        Uuid::new_v4(),
        "conservative initialization",
    )
    .unwrap()
}
fn mutation(version: u64, value: Mutation) -> SafetyMutationRequest {
    SafetyMutationRequest::new(
        identity("operator"),
        Uuid::new_v4(),
        version,
        value,
        "operator safety change",
    )
    .unwrap()
}
fn limits(receipts: usize, actor: usize, audits: usize, bytes: usize) -> SafetyAuthorityConfig {
    SafetyAuthorityConfig::new(
        receipts,
        actor,
        audits,
        bytes,
        Duration::from_secs(24 * 60 * 60),
    )
    .unwrap()
}
#[derive(Default)]
struct Clock(AtomicU64);
impl Clock {
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}
impl SafetyAuthorityClock for Clock {
    fn now_unix_ms(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

async fn contract(store: Arc<dyn SafetyAuthority>) {
    assert_eq!(store.read().await, Err(Error::MissingAuthority));
    let init = initialize();
    let receipt = store.initialize(init.clone()).await.unwrap();
    assert_eq!(receipt.version(), 0);
    assert_eq!(receipt.previous_version(), None);
    assert_eq!(receipt.audit_sequence(), 1);
    assert_eq!(store.initialize(init.clone()).await.unwrap(), receipt);
    assert_eq!(
        store.initialize(initialize()).await,
        Err(Error::AlreadyInitialized)
    );
    let initial = store.read().await.unwrap();
    assert_eq!(*initial.snapshot(), SafetySwitchSnapshot::default());
    assert_eq!(initial.namespace_id(), receipt.namespace_id());
    let first = mutation(0, Mutation::DisableViewerControl(true));
    let applied = store.mutate(first.clone()).await.unwrap();
    assert_eq!(applied.version(), 1);
    assert_eq!(applied.previous_version(), Some(0));
    assert_eq!(applied.audit_sequence(), 2);
    assert_eq!(store.mutate(first.clone()).await.unwrap(), applied);
    let mismatch = SafetyMutationRequest::new(
        first.identity().clone(),
        first.idempotency_key(),
        0,
        Mutation::DisableViewerControl(true),
        "different reason",
    )
    .unwrap();
    assert_eq!(
        store.mutate(mismatch).await,
        Err(Error::IdempotencyConflict)
    );
    assert_eq!(
        store
            .mutate(mutation(0, Mutation::DisableDownloads(true)))
            .await,
        Err(Error::VersionConflict {
            expected: 0,
            current: 1
        })
    );
    let domain_id = Uuid::new_v4();
    let domain = SafetyMutationRequest::new(
        identity("operator"),
        domain_id,
        1,
        Mutation::SetDeniedDomain {
            domain: " Example.COM. ".into(),
            denied: true,
        },
        "deny domain",
    )
    .unwrap();
    let canonical = SafetyMutationRequest::new(
        identity("operator"),
        domain_id,
        1,
        Mutation::SetDeniedDomain {
            domain: "example.com".into(),
            denied: true,
        },
        "deny domain",
    )
    .unwrap();
    let denied = store.mutate(domain).await.unwrap();
    assert_eq!(store.mutate(canonical).await.unwrap(), denied);
    let current = store.read().await.unwrap();
    assert!(current.snapshot().viewer_control_disabled());
    assert!(current.snapshot().domain_denied("child.example.com"));
    let audits = store.pending_audits(32).await.unwrap();
    assert_eq!(audits.len(), 3);
    assert_eq!(audits[0].receipt(), &receipt);
    assert_eq!(audits[1].receipt(), &applied);
    assert_eq!(audits[2].receipt(), &denied);
    assert_eq!(audits[1].identity(), first.identity());
    assert_eq!(audits[1].mutation(), Some(first.mutation()));
    assert_eq!(
        store.ack_audit(audits[1].ack()).await,
        Err(Error::InvalidAck)
    );
    let bad = SafetyAuditAck::new(
        audits[0].ack().namespace_id(),
        1,
        audits[0].ack().event_id(),
        [3; 32],
    )
    .unwrap();
    assert_eq!(store.ack_audit(bad).await, Err(Error::InvalidAck));
    store.ack_audit(audits[0].ack()).await.unwrap();
    store.ack_audit(audits[0].ack()).await.unwrap();
    assert_eq!(
        store.pending_audits(1).await.unwrap(),
        vec![audits[1].clone()]
    );
    store.ack_audit(audits[1].ack()).await.unwrap();
    assert_eq!(
        store.ack_audit(audits[0].ack()).await,
        Err(Error::InvalidAck)
    );
    store.ack_audit(audits[2].ack()).await.unwrap();
    assert!(store.pending_audits(32).await.unwrap().is_empty());
    assert_eq!(store.read().await.unwrap(), current);
    assert_eq!(store.mutate(first).await.unwrap(), applied);
    assert_eq!(store.pending_audits(0).await, Err(Error::InvalidInput));
    assert_eq!(store.pending_audits(33).await, Err(Error::InvalidInput));
}

#[tokio::test]
async fn memory_audited_cas_canonical_retry_and_exact_ack_contract() {
    contract(Arc::new(MemorySafetyAuthority::default())).await;
}

#[test]
fn typed_requests_reject_qualification_mint_invalid_binding_and_unbounded_configuration() {
    assert!(SafetyActorIdentity::new(TenantId::new(), "\nspoof").is_err());
    assert!(SafetyInitializeRequest::new(identity("operator"), Uuid::nil(), "why").is_err());
    assert!(SafetyInitializeRequest::new(identity("operator"), Uuid::new_v4(), " ").is_err());
    assert!(
        SafetyInitializeRequest::new(identity("operator"), Uuid::new_v4(), "x".repeat(2_049))
            .is_err()
    );
    assert!(
        SafetyMutationRequest::new(
            identity("operator"),
            Uuid::new_v4(),
            0,
            Mutation::SetSharedAdmission {
                qualified: true,
                force_dedicated_process: false,
                max_contexts_per_shard: 8
            },
            "mint"
        )
        .is_err()
    );
    assert!(SafetyAuthorityConfig::new(0, 1, 1, 4_096, Duration::from_secs(86_400)).is_err());
    assert!(SafetyAuthorityConfig::new(4, 5, 1, 4_096, Duration::from_secs(86_400)).is_err());
    assert!(SafetyAuthorityConfig::new(4, 1, 5, 4_096, Duration::from_secs(86_400)).is_err());
    assert!(SafetyAuthorityConfig::new(4, 1, 1, usize::MAX, Duration::from_secs(86_400)).is_err());
    assert!(SafetyAuthorityConfig::new(4, 1, 1, 4_096, Duration::from_secs(86_399)).is_err());
    assert!(
        RedisSafetyAuthorityConfig::new(
            "redis://user:secret@example.test/",
            "prefix",
            SafetyAuthorityConfig::default(),
            0,
            Duration::from_secs(1)
        )
        .is_err()
    );
    let config = RedisSafetyAuthorityConfig::new(
        "redis://user:secret@example.test/",
        "prefix",
        SafetyAuthorityConfig::default(),
        1,
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(!format!("{config:?}").contains("secret"));
}

#[tokio::test]
async fn memory_full_audit_lane_preserves_authority_and_returns_exact_retries() {
    let clock = Arc::new(Clock::default());
    clock.set(100);
    let store = MemorySafetyAuthority::new(limits(4, 4, 2, 64 * 1024)).with_clock(clock.clone());
    let init = initialize();
    let initial = store.initialize(init.clone()).await.unwrap();
    let request = mutation(0, Mutation::DisableDownloads(true));
    let receipt = store.mutate(request.clone()).await.unwrap();
    let snapshot = store.read().await.unwrap();
    assert_eq!(
        store
            .mutate(mutation(1, Mutation::DisableCheckpoint(true)))
            .await,
        Err(Error::Capacity)
    );
    assert_eq!(store.read().await.unwrap(), snapshot);
    assert_eq!(store.initialize(init).await.unwrap(), initial);
    assert_eq!(store.mutate(request).await.unwrap(), receipt);
    let audits = store.pending_audits(32).await.unwrap();
    store.ack_audit(audits[0].ack()).await.unwrap();
    clock.set(0);
    let next = store
        .mutate(mutation(1, Mutation::DisableCheckpoint(true)))
        .await
        .unwrap();
    assert_eq!(next.occurred_at_unix_ms(), 100);
    assert_eq!(store.pending_audits(32).await.unwrap().len(), 2);
}

#[tokio::test]
async fn memory_receipt_retention_starts_after_ack_and_gc_preserves_permanent_version() {
    let clock = Arc::new(Clock::default());
    clock.set(1_000);
    let store = MemorySafetyAuthority::new(limits(2, 2, 2, 64 * 1024)).with_clock(clock.clone());
    let init = initialize();
    let init_receipt = store.initialize(init.clone()).await.unwrap();
    let request = mutation(0, Mutation::DisableDownloads(true));
    let receipt = store.mutate(request.clone()).await.unwrap();
    let audits = store.pending_audits(32).await.unwrap();
    clock.set(10 * 86_400_000);
    assert_eq!(store.prune_receipts().await.unwrap(), 0); // unexported audits are permanent
    store.ack_audit(audits[0].ack()).await.unwrap();
    store.ack_audit(audits[1].ack()).await.unwrap();
    let ack_at = 10 * 86_400_000;
    clock.set(ack_at + 86_400_000 - 1);
    assert_eq!(store.prune_receipts().await.unwrap(), 0);
    assert_eq!(store.initialize(init.clone()).await.unwrap(), init_receipt);
    assert_eq!(store.mutate(request.clone()).await.unwrap(), receipt);
    assert_eq!(
        store
            .mutate(mutation(1, Mutation::DisableCheckpoint(true)))
            .await,
        Err(Error::Capacity)
    );
    clock.set(ack_at + 86_400_000);
    assert_eq!(store.prune_receipts().await.unwrap(), 2);
    assert_eq!(store.read().await.unwrap().snapshot().version(), 1);
    assert_eq!(store.initialize(init).await, Err(Error::AlreadyInitialized));
    assert_eq!(
        store.mutate(request).await,
        Err(Error::VersionConflict {
            expected: 0,
            current: 1
        })
    );
    store.ack_audit(audits[1].ack()).await.unwrap(); // latest exact ACK survives receipt GC
    let next = store
        .mutate(mutation(1, Mutation::DisableCheckpoint(true)))
        .await
        .unwrap();
    assert_eq!(next.version(), 2);
    assert_eq!(next.audit_sequence(), 3);
}

#[tokio::test]
async fn memory_actor_quota_and_encoded_byte_limit_fail_without_partial_mutation() {
    let store = MemorySafetyAuthority::new(limits(3, 1, 3, 64 * 1024));
    let initial = store.initialize(initialize()).await.unwrap();
    assert_eq!(
        store
            .mutate(mutation(0, Mutation::DisableDownloads(true)))
            .await,
        Err(Error::Capacity)
    );
    let other = SafetyMutationRequest::new(
        identity("other-operator"),
        Uuid::new_v4(),
        0,
        Mutation::DisableDownloads(true),
        "other actor",
    )
    .unwrap();
    store.mutate(other.clone()).await.unwrap();
    assert_eq!(
        store.mutate(other.clone()).await.unwrap().idempotency_key(),
        other.idempotency_key()
    );
    assert_eq!(store.pending_audits(32).await.unwrap().len(), 2);
    assert_eq!(
        store.read().await.unwrap().namespace_id(),
        initial.namespace_id()
    );
    let bytes = MemorySafetyAuthority::new(limits(10, 10, 10, 4_096));
    let init = initialize();
    let original = bytes.initialize(init.clone()).await.unwrap();
    let snapshot = bytes.read().await.unwrap();
    let large = SafetyMutationRequest::new(
        identity("operator"),
        Uuid::new_v4(),
        0,
        Mutation::DisableDownloads(true),
        "x".repeat(2_048),
    )
    .unwrap();
    assert_eq!(bytes.mutate(large).await, Err(Error::Capacity));
    assert_eq!(bytes.read().await.unwrap(), snapshot);
    assert_eq!(bytes.pending_audits(32).await.unwrap().len(), 1);
    assert_eq!(bytes.initialize(init).await.unwrap(), original);
}

async fn concurrent_contract(store: Arc<dyn SafetyAuthority>) {
    let init = initialize();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let store = Arc::clone(&store);
        let init = init.clone();
        tasks.spawn(async move { store.initialize(init).await });
    }
    let first = tasks.join_next().await.unwrap().unwrap().unwrap();
    while let Some(receipt) = tasks.join_next().await {
        assert_eq!(receipt.unwrap().unwrap(), first);
    }
    for _ in 0..16 {
        let store = Arc::clone(&store);
        tasks.spawn(async move {
            store
                .mutate(mutation(0, Mutation::DisableDownloads(true)))
                .await
        });
    }
    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(_) => winners += 1,
            Err(Error::VersionConflict {
                expected: 0,
                current: 1,
            }) => {}
            other => panic!("unexpected CAS outcome: {other:?}"),
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(store.pending_audits(32).await.unwrap().len(), 2);
}

#[tokio::test]
async fn memory_concurrent_duplicate_initialization_and_global_version_cas() {
    concurrent_contract(Arc::new(MemorySafetyAuthority::default())).await;
}

struct SlowAuthority {
    inner: MemorySafetyAuthority,
    release: tokio::sync::Semaphore,
    completed: std::sync::mpsc::SyncSender<()>,
}
#[async_trait]
impl SafetyAuthority for SlowAuthority {
    async fn initialize(&self, r: SafetyInitializeRequest) -> Result<SafetyMutationReceipt, Error> {
        self.inner.initialize(r).await
    }
    async fn read(&self) -> Result<SafetyAuthoritySnapshot, Error> {
        self.inner.read().await
    }
    async fn mutate(&self, r: SafetyMutationRequest) -> Result<SafetyMutationReceipt, Error> {
        self.release.acquire().await.unwrap().forget();
        let result = self.inner.mutate(r).await;
        self.completed.send(()).unwrap();
        result
    }
    async fn pending_audits(&self, n: usize) -> Result<Vec<SafetyAuditIntent>, Error> {
        self.inner.pending_audits(n).await
    }
    async fn ack_audit(&self, a: SafetyAuditAck) -> Result<(), Error> {
        self.inner.ack_audit(a).await
    }
    async fn prune_receipts(&self) -> Result<usize, Error> {
        self.inner.prune_receipts().await
    }
}

#[test]
fn blocking_actor_keeps_admitted_mutation_owned_after_caller_timeout() {
    let (completed, receiver) = std::sync::mpsc::sync_channel(1);
    let store = Arc::new(SlowAuthority {
        inner: MemorySafetyAuthority::default(),
        release: tokio::sync::Semaphore::new(0),
        completed,
    });
    let config =
        CoordinationActorConfig::new(4, 1, Duration::from_millis(50), Duration::from_millis(50))
            .unwrap();
    let client = SafetyAuthorityBlockingClient::spawn(Arc::clone(&store), config).unwrap();
    client.initialize(initialize()).unwrap();
    let request = mutation(0, Mutation::DisableDownloads(true));
    assert_eq!(client.mutate(request.clone()), Err(Error::TimedOut));
    store.release.add_permits(1);
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    client.drain().unwrap();
    assert_eq!(client.read().unwrap().snapshot().version(), 1);
    assert_eq!(client.pending_audits(32).unwrap().len(), 2);
    store.release.add_permits(1);
    let retry = client.mutate(request).unwrap();
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(retry.version(), 1);
    assert_eq!(client.pending_audits(32).unwrap().len(), 2);
}

struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("browserd-safety-{}", Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("safety.pin")
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ReadAuthority(Mutex<Result<SafetyAuthoritySnapshot, Error>>);
#[async_trait]
impl SafetyAuthority for ReadAuthority {
    async fn initialize(&self, _: SafetyInitializeRequest) -> Result<SafetyMutationReceipt, Error> {
        Err(Error::Unavailable)
    }
    async fn read(&self) -> Result<SafetyAuthoritySnapshot, Error> {
        self.0.lock().unwrap().clone()
    }
    async fn mutate(&self, _: SafetyMutationRequest) -> Result<SafetyMutationReceipt, Error> {
        Err(Error::Unavailable)
    }
    async fn pending_audits(&self, _: usize) -> Result<Vec<SafetyAuditIntent>, Error> {
        Err(Error::Unavailable)
    }
    async fn ack_audit(&self, _: SafetyAuditAck) -> Result<(), Error> {
        Err(Error::Unavailable)
    }
    async fn prune_receipts(&self) -> Result<usize, Error> {
        Err(Error::Unavailable)
    }
}

#[tokio::test]
async fn observer_fsync_pin_restart_rollback_equivocation_and_namespace_loss_fail_closed() {
    let dir = PrivateDirectory::new();
    let store = MemorySafetyAuthority::default();
    store.initialize(initialize()).await.unwrap();
    let v0 = store.read().await.unwrap();
    let authority = Arc::new(ReadAuthority(Mutex::new(Ok(v0.clone()))));
    let cache = Arc::new(RuntimeSafetyCache::new());
    let observer = SafetyObserver::open(
        dir.path(),
        authority.clone(),
        cache.clone(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(cache.generation().is_err());
    observer.refresh().await.unwrap();
    let bytes = std::fs::read(dir.path()).unwrap();
    let pin: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(pin["pin"]["namespace_id"], v0.namespace_id().to_string());
    assert_eq!(pin["pin"]["version"], 0);
    assert_eq!(cache.generation().unwrap().version(), 0);
    store
        .mutate(mutation(0, Mutation::DisableDownloads(true)))
        .await
        .unwrap();
    let v1 = store.read().await.unwrap();
    *authority.0.lock().unwrap() = Ok(v1.clone());
    observer.refresh().await.unwrap();
    assert_eq!(observer.last_accepted().unwrap().unwrap().version(), 1);
    drop(observer);
    let cache = Arc::new(RuntimeSafetyCache::new());
    let observer = SafetyObserver::open(
        dir.path(),
        authority.clone(),
        cache.clone(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(cache.generation().is_err());
    observer.refresh().await.unwrap();
    let generation = cache.generation().unwrap();
    *authority.0.lock().unwrap() = Ok(v0);
    assert_eq!(observer.refresh().await, Err(Error::Rollback));
    assert!(generation.cancellation_token().is_cancelled());
    assert!(cache.generation().is_err());
    *authority.0.lock().unwrap() = Ok(v1.clone());
    observer.refresh().await.unwrap();
    let alternate = SafetySwitchSnapshot::default()
        .apply(&Mutation::DisableCheckpoint(true))
        .unwrap();
    *authority.0.lock().unwrap() =
        Ok(SafetyAuthoritySnapshot::new(v1.namespace_id(), alternate).unwrap());
    assert_eq!(observer.refresh().await, Err(Error::Equivocation));
    assert!(cache.generation().is_err());
    *authority.0.lock().unwrap() = Ok(v1.clone());
    observer.refresh().await.unwrap();
    *authority.0.lock().unwrap() = Err(Error::MissingAuthority);
    assert_eq!(observer.refresh().await, Err(Error::MissingAuthority));
    assert!(cache.generation().is_err());
    *authority.0.lock().unwrap() =
        Ok(SafetyAuthoritySnapshot::new(Uuid::now_v7(), v1.snapshot().clone()).unwrap());
    assert_eq!(observer.refresh().await, Err(Error::NamespaceMismatch));
    assert_eq!(
        observer.last_accepted().unwrap().unwrap().namespace_id(),
        v1.namespace_id()
    );
}

#[tokio::test]
async fn observer_transient_read_failure_does_not_refresh_or_preempt_unexpired_cache() {
    let dir = PrivateDirectory::new();
    let snapshot =
        SafetyAuthoritySnapshot::new(Uuid::now_v7(), SafetySwitchSnapshot::default()).unwrap();
    let authority = Arc::new(ReadAuthority(Mutex::new(Ok(snapshot))));
    let cache = Arc::new(RuntimeSafetyCache::new());
    let observer = SafetyObserver::open(
        dir.path(),
        authority.clone(),
        cache.clone(),
        Duration::from_millis(50),
    )
    .unwrap();
    observer.refresh().await.unwrap();
    let generation = cache.generation().unwrap();
    *authority.0.lock().unwrap() = Err(Error::Unavailable);
    assert_eq!(observer.refresh().await, Err(Error::Unavailable));
    assert!(cache.generation().is_ok());
    tokio::time::sleep_until(
        tokio::time::Instant::from_std(generation.expires_at()) + Duration::from_millis(1),
    )
    .await;
    assert!(cache.generation().is_err());
    assert!(generation.cancellation_token().is_cancelled());
}

#[tokio::test]
async fn observer_detects_replaced_pin_before_publication_and_missing_qualified_pin_on_reopen() {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = PrivateDirectory::new();
    let store = Arc::new(MemorySafetyAuthority::default());
    store.initialize(initialize()).await.unwrap();
    let cache = Arc::new(RuntimeSafetyCache::new());
    let observer = SafetyObserver::open(
        dir.path(),
        store.clone(),
        cache.clone(),
        Duration::from_secs(30),
    )
    .unwrap();
    observer.refresh().await.unwrap();
    let before = cache.generation().unwrap();
    store
        .mutate(mutation(0, Mutation::DisableDownloads(true)))
        .await
        .unwrap();
    std::fs::remove_file(dir.path()).unwrap();
    let replacement = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.path())
        .unwrap();
    assert_eq!(observer.refresh().await, Err(Error::DurabilityUnavailable));
    assert!(before.cancellation_token().is_cancelled());
    assert!(cache.generation().is_err());
    assert_eq!(replacement.metadata().unwrap().len(), 0);
    drop(observer);
    drop(replacement);
    std::fs::remove_file(dir.path()).unwrap();
    assert!(matches!(
        SafetyObserver::open(
            dir.path(),
            store,
            Arc::new(RuntimeSafetyCache::new()),
            Duration::from_secs(30)
        ),
        Err(Error::DurabilityUnavailable)
    ));
}

#[tokio::test]
async fn observer_rejects_identical_pin_recreation_hardlinks_and_symlink_replacement() {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, symlink};

    for replacement in ["identical", "hardlink", "symlink"] {
        let dir = PrivateDirectory::new();
        let store = Arc::new(MemorySafetyAuthority::default());
        store.initialize(initialize()).await.unwrap();
        let cache = Arc::new(RuntimeSafetyCache::new());
        let observer =
            SafetyObserver::open(dir.path(), store, cache.clone(), Duration::from_secs(30))
                .unwrap();
        observer.refresh().await.unwrap();
        // Exercise descriptor replacement after both initial write and an exact durable refresh.
        observer.refresh().await.unwrap();
        let accepted = observer.last_accepted().unwrap();
        let generation = cache.generation().unwrap();
        let bytes = std::fs::read(dir.path()).unwrap();
        let alternative = dir.path().with_extension("alternative");
        if replacement == "hardlink" {
            std::fs::hard_link(dir.path(), &alternative).unwrap();
        } else {
            std::fs::remove_file(dir.path()).unwrap();
            let target = if replacement == "identical" {
                dir.path()
            } else {
                alternative.clone()
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(target)
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
            if replacement == "symlink" {
                symlink(&alternative, dir.path()).unwrap();
            }
        }
        assert_eq!(
            observer.refresh().await,
            Err(Error::DurabilityUnavailable),
            "{replacement} must not acquire fresh authority publication"
        );
        assert!(generation.cancellation_token().is_cancelled());
        assert!(cache.generation().is_err());
        assert_eq!(std::fs::read(dir.path()).unwrap(), bytes);
        assert!(matches!(
            observer.last_accepted(),
            Err(Error::DurabilityUnavailable)
        ));
        // Rejected replacement does not advance the durable watermark.
        let durable: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(durable["pin"]["version"], accepted.unwrap().version());
    }
}

struct RedisFixture {
    endpoint: String,
    prefix: String,
    config: RedisSafetyAuthorityConfig,
    store: Arc<RedisSafetyAuthority>,
}
impl RedisFixture {
    async fn new(label: &str, limits: SafetyAuthorityConfig) -> Option<Self> {
        let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
            eprintln!("skipping safety authority Redis test: BROWSERD_REDIS_TEST_URL is unset");
            return None;
        };
        let prefix = format!("browserd-safety-{label}-{}", Uuid::new_v4());
        let config = RedisSafetyAuthorityConfig::new(
            endpoint.clone(),
            prefix.clone(),
            limits,
            32,
            Duration::from_secs(5),
        )
        .unwrap();
        let store = Arc::new(RedisSafetyAuthority::connect(config.clone()).await.unwrap());
        Some(Self {
            endpoint,
            prefix,
            config,
            store,
        })
    }
    fn key(&self) -> String {
        format!("{}:safety:{{browserd-safety}}:authority", self.prefix)
    }
    async fn connection(&self) -> redis::aio::MultiplexedConnection {
        redis::Client::open(self.endpoint.as_str())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap()
    }
    async fn cleanup(&self) {
        redis::cmd("UNLINK")
            .arg(self.key())
            .query_async::<usize>(&mut self.connection().await)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn redis_actual_audited_cas_contract_and_reconnect_lost_reply() {
    let Some(fixture) = RedisFixture::new("contract", SafetyAuthorityConfig::default()).await
    else {
        return;
    };
    contract(fixture.store.clone()).await;
    let restart = RedisSafetyAuthority::connect(fixture.config.clone())
        .await
        .unwrap();
    assert_eq!(
        restart.read().await.unwrap(),
        fixture.store.read().await.unwrap()
    );
    let request = mutation(2, Mutation::DisableDownloads(true));
    let original = fixture.store.mutate(request.clone()).await.unwrap();
    let restart = RedisSafetyAuthority::connect(fixture.config.clone())
        .await
        .unwrap();
    assert_eq!(restart.mutate(request).await.unwrap(), original);
    assert_eq!(restart.pending_audits(32).await.unwrap().len(), 1);
    fixture.cleanup().await;
}

#[tokio::test]
async fn redis_actual_concurrent_duplicate_initialization_and_cas() {
    let Some(fixture) = RedisFixture::new("concurrent", SafetyAuthorityConfig::default()).await
    else {
        return;
    };
    concurrent_contract(fixture.store.clone()).await;
    fixture.cleanup().await;
}

#[tokio::test]
async fn redis_actual_audit_full_exact_retry_and_namespace_loss_reject_old_observer() {
    let Some(fixture) = RedisFixture::new("full-loss", limits(2, 2, 2, 64 * 1024)).await else {
        return;
    };
    let init = initialize();
    let initialized = fixture.store.initialize(init.clone()).await.unwrap();
    let request = mutation(0, Mutation::DisableDownloads(true));
    let receipt = fixture.store.mutate(request.clone()).await.unwrap();
    let current = fixture.store.read().await.unwrap();
    let mut connection = fixture.connection().await;
    let before: Vec<u8> = redis::cmd("GET")
        .arg(fixture.key())
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .mutate(mutation(1, Mutation::DisableCheckpoint(true)))
            .await,
        Err(Error::Capacity)
    );
    let after: Vec<u8> = redis::cmd("GET")
        .arg(fixture.key())
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(fixture.store.initialize(init).await.unwrap(), initialized);
    assert_eq!(fixture.store.mutate(request).await.unwrap(), receipt);
    let dir = PrivateDirectory::new();
    let cache = Arc::new(RuntimeSafetyCache::new());
    let observer = SafetyObserver::open(
        dir.path(),
        fixture.store.clone(),
        cache.clone(),
        Duration::from_secs(30),
    )
    .unwrap();
    observer.refresh().await.unwrap();
    let generation = cache.generation().unwrap();
    fixture.cleanup().await;
    assert_eq!(fixture.store.read().await, Err(Error::MissingAuthority));
    assert_eq!(
        fixture
            .store
            .mutate(mutation(1, Mutation::DisableCheckpoint(true)))
            .await,
        Err(Error::MissingAuthority)
    );
    assert_eq!(observer.refresh().await, Err(Error::MissingAuthority));
    assert!(generation.cancellation_token().is_cancelled());
    let restarted = RedisSafetyAuthority::connect(fixture.config.clone())
        .await
        .unwrap();
    assert_eq!(restarted.read().await, Err(Error::MissingAuthority));
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(fixture.key())
            .query_async::<usize>(&mut connection)
            .await
            .unwrap(),
        0
    );
    let new = restarted.initialize(initialize()).await.unwrap();
    assert_ne!(new.namespace_id(), current.namespace_id());
    assert_eq!(observer.refresh().await, Err(Error::NamespaceMismatch));
    fixture.cleanup().await;
}

#[tokio::test]
async fn redis_actual_bad_key_type_expiry_and_immutable_config_fail_without_writes() {
    let Some(fixture) = RedisFixture::new("corrupt", SafetyAuthorityConfig::default()).await else {
        return;
    };
    fixture.store.initialize(initialize()).await.unwrap();
    let mut connection = fixture.connection().await;
    let original: Vec<u8> = redis::cmd("GET")
        .arg(fixture.key())
        .query_async(&mut connection)
        .await
        .unwrap();
    let incompatible = RedisSafetyAuthorityConfig::new(
        fixture.endpoint.clone(),
        fixture.prefix.clone(),
        limits(2_048, 128, 1_024, 8 * 1024 * 1024),
        1,
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(matches!(
        RedisSafetyAuthority::connect(incompatible).await,
        Err(Error::ConfigMismatch)
    ));
    redis::cmd("PEXPIRE")
        .arg(fixture.key())
        .arg(60_000)
        .query_async::<usize>(&mut connection)
        .await
        .unwrap();
    assert_eq!(fixture.store.read().await, Err(Error::CorruptState));
    assert_eq!(
        fixture
            .store
            .mutate(mutation(0, Mutation::DisableDownloads(true)))
            .await,
        Err(Error::CorruptState)
    );
    redis::cmd("PERSIST")
        .arg(fixture.key())
        .query_async::<usize>(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        redis::cmd("GET")
            .arg(fixture.key())
            .query_async::<Vec<u8>>(&mut connection)
            .await
            .unwrap(),
        original
    );
    fixture.cleanup().await;
    redis::cmd("LPUSH")
        .arg(fixture.key())
        .arg("owned invalid-type fixture")
        .query_async::<usize>(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        fixture.store.initialize(initialize()).await,
        Err(Error::CorruptState)
    );
    assert_eq!(
        redis::cmd("LLEN")
            .arg(fixture.key())
            .query_async::<usize>(&mut connection)
            .await
            .unwrap(),
        1
    );
    fixture.cleanup().await;
}

// Mirror only the finite envelope to create a realistic retained/GC history in an owned key.
// Field order matches the production typed state for its checksum; no operator key is touched.
#[derive(Serialize, Deserialize)]
struct FixtureState {
    format_version: u8,
    config_digest: [u8; 32],
    authority: SafetyAuthoritySnapshot,
    floor: u64,
    audit_tail: u64,
    audit_delivered: u64,
    last_ack: Option<SafetyAuditAck>,
    receipts: BTreeMap<String, FixtureReceipt>,
    pending: BTreeMap<u64, String>,
}
#[derive(Serialize, Deserialize)]
struct FixtureReceipt {
    audit: SafetyAuditIntent,
    acknowledged_at: Option<u64>,
}
#[derive(Serialize, Deserialize)]
struct FixtureEnvelope {
    state: FixtureState,
    checksum: [u8; 32],
}
impl FixtureEnvelope {
    fn encode(&mut self) -> Vec<u8> {
        self.checksum = Sha256::digest(serde_json::to_vec(&self.state).unwrap()).into();
        serde_json::to_vec(self).unwrap()
    }
}

#[tokio::test]
async fn redis_actual_acked_receipt_gc_time_floor_and_exact_versions_above_lua_precision() {
    let Some(fixture) = RedisFixture::new("gc-floor", SafetyAuthorityConfig::default()).await
    else {
        return;
    };
    fixture.store.initialize(initialize()).await.unwrap();
    let request = mutation(0, Mutation::DisableDownloads(true));
    let receipt = fixture.store.mutate(request.clone()).await.unwrap();
    let audits = fixture.store.pending_audits(32).await.unwrap();
    for audit in &audits {
        fixture.store.ack_audit(audit.ack()).await.unwrap();
    }
    let mut connection = fixture.connection().await;
    let bytes: Vec<u8> = redis::cmd("GET")
        .arg(fixture.key())
        .query_async(&mut connection)
        .await
        .unwrap();
    let mut state: FixtureEnvelope = serde_json::from_slice(&bytes).unwrap();
    // Advance only the trusted persisted floor, proving wall-clock rollback cannot undo it.
    let first_ack = state
        .state
        .receipts
        .values()
        .map(|record| record.acknowledged_at.unwrap())
        .min()
        .unwrap();
    let last_ack = state
        .state
        .receipts
        .values()
        .map(|record| record.acknowledged_at.unwrap())
        .max()
        .unwrap();
    state.state.floor = first_ack + 86_400_000 - 1;
    redis::cmd("SET")
        .arg(fixture.key())
        .arg(state.encode())
        .query_async::<()>(&mut connection)
        .await
        .unwrap();
    let restart = RedisSafetyAuthority::connect(fixture.config.clone())
        .await
        .unwrap();
    assert_eq!(restart.prune_receipts().await.unwrap(), 0);
    assert_eq!(restart.mutate(request.clone()).await.unwrap(), receipt);
    let bytes: Vec<u8> = redis::cmd("GET")
        .arg(fixture.key())
        .query_async(&mut connection)
        .await
        .unwrap();
    let mut state: FixtureEnvelope = serde_json::from_slice(&bytes).unwrap();
    state.state.floor = last_ack + 86_400_000;
    let floor = state.state.floor;
    redis::cmd("SET")
        .arg(fixture.key())
        .arg(state.encode())
        .query_async::<()>(&mut connection)
        .await
        .unwrap();
    assert_eq!(restart.prune_receipts().await.unwrap(), 2);
    assert_eq!(
        restart.read().await.unwrap().snapshot().version(),
        receipt.version()
    );
    assert_eq!(
        restart.mutate(request).await,
        Err(Error::VersionConflict {
            expected: 0,
            current: 1
        })
    );
    restart.ack_audit(audits[1].ack()).await.unwrap();
    let applied = restart
        .mutate(mutation(1, Mutation::DisableCheckpoint(true)))
        .await
        .unwrap();
    assert_eq!(applied.occurred_at_unix_ms(), floor);
    let audit = restart.pending_audits(1).await.unwrap().remove(0);
    restart.ack_audit(audit.ack()).await.unwrap();
    let bytes: Vec<u8> = redis::cmd("GET")
        .arg(fixture.key())
        .query_async(&mut connection)
        .await
        .unwrap();
    let mut state: FixtureEnvelope = serde_json::from_slice(&bytes).unwrap();
    state.state.receipts.clear();
    let high = 9_007_199_254_740_993_u64;
    let mut snapshot = serde_json::to_value(state.state.authority.snapshot()).unwrap();
    snapshot["version"] = high.into();
    let snapshot: SafetySwitchSnapshot = serde_json::from_value(snapshot).unwrap();
    let namespace = state.state.authority.namespace_id();
    state.state.authority = SafetyAuthoritySnapshot::new(namespace, snapshot).unwrap();
    state.state.audit_tail = high + 1;
    state.state.audit_delivered = high + 1;
    state.state.last_ack =
        Some(SafetyAuditAck::new(namespace, high + 1, Uuid::now_v7(), [0; 32]).unwrap());
    redis::cmd("SET")
        .arg(fixture.key())
        .arg(state.encode())
        .query_async::<()>(&mut connection)
        .await
        .unwrap();
    let receipt = restart
        .mutate(mutation(high, Mutation::DisableViewerControl(true)))
        .await
        .unwrap();
    assert_eq!(receipt.previous_version(), Some(high));
    assert_eq!(receipt.version(), high + 1);
    assert_eq!(receipt.audit_sequence(), high + 2);
    assert_eq!(restart.read().await.unwrap().snapshot().version(), high + 1);
    fixture.cleanup().await;
}
