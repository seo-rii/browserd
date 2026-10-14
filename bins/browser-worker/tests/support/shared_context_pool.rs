#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::*;
use browser_worker::{
    SharedContextPlacementConfig, SharedContextPlacementPolicy, TenantShardReusePolicy,
};
use browserd_chromium::{GateEvidence, QualificationGate, QualificationReceipt};
use browserd_sandbox::{ContextEgressBinding, ContextEgressReleaseReceipt, ContextEgressRequest};
use browserd_worker::WorkerIsolationProfile;
use std::collections::BTreeMap;

struct PoolSandbox {
    inner: ScriptedSandbox,
    initial: Mutex<Vec<DedicatedEgressProxyBinding>>,
    attached: Mutex<Vec<ContextEgressRequest>>,
    released: Mutex<Vec<ContextEgressRequest>>,
    reject_release: AtomicBool,
}
#[async_trait]
impl SandboxShardRpc for PoolSandbox {
    async fn create_shard(
        &self,
        spec: LaunchSpec,
        ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        self.inner.create_shard(spec, ttl).await
    }
    async fn cancel_or_kill_shard(
        &self,
        spec: &LaunchSpec,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.inner.cancel_or_kill_shard(spec, reason).await
    }
    async fn claim_cdp_pipes(
        &self,
        id: &ShardId,
        worker: &WorkerId,
        epoch: u64,
        generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        let pipes = self
            .inner
            .claim_cdp_pipes(id, worker, epoch, generation)
            .await?;
        self.initial
            .lock()
            .unwrap()
            .push(pipes.egress_proxy_binding().expect("bound pipes").clone());
        Ok(pipes)
    }
    async fn renew_owner_lease(
        &self,
        id: &ShardId,
        epoch: u64,
        generation: LaunchGeneration,
        ttl: Duration,
    ) -> Result<(), ShardRuntimeError> {
        self.inner
            .renew_owner_lease(id, epoch, generation, ttl)
            .await
    }
    async fn kill_shard(
        &self,
        id: &ShardId,
        epoch: u64,
        generation: LaunchGeneration,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.inner.kill_shard(id, epoch, generation, reason).await
    }
    async fn attach_context_egress(
        &self,
        request: &ContextEgressRequest,
    ) -> Result<ContextEgressBinding, ShardRuntimeError> {
        let spec = self
            .inner
            .created_specs
            .lock()
            .unwrap()
            .iter()
            .find(|spec| {
                spec.dedicated_egress().egress_fence().shard()
                    == request.egress().egress_fence().shard()
            })
            .expect("owned launch")
            .clone();
        request.validate_for(&spec).expect("exact route request");
        let initial = self
            .initial
            .lock()
            .unwrap()
            .iter()
            .find(|binding| {
                binding.egress_fence().shard() == request.egress().egress_fence().shard()
            })
            .expect("initial pinned namespace")
            .clone();
        let proxy = if initial.egress_fence() == request.egress().egress_fence() {
            initial
        } else {
            let route = LaunchSpec::production(
                request.tenant_id().clone(),
                request.egress().clone(),
                spec.chromium_binary_digest(),
            );
            let port =
                u16::try_from(32_099 + request.egress().egress_fence().route_generation().get())
                    .expect("bounded fixture route generation");
            let lease = ShardIngressLease::from_attachment(
                ShardEgressReservation::from_launch_spec(&route),
                initial.namespace_identity(),
                ShardIngressReceipt::with_proxy_address(([127, 0, 0, 1], port).into()).unwrap(),
            );
            DedicatedEgressProxyBinding::from_lease(&lease).unwrap()
        };
        self.attached.lock().unwrap().push(request.clone());
        ContextEgressBinding::new(request.clone(), 17, 9, proxy, Duration::from_secs(30))
            .map_err(|_| ShardRuntimeError::Rejected)
    }
    async fn release_context_egress(
        &self,
        request: &ContextEgressRequest,
    ) -> Result<ContextEgressReleaseReceipt, ShardRuntimeError> {
        assert!(self.attached.lock().unwrap().contains(request));
        self.released.lock().unwrap().push(request.clone());
        if self.reject_release.load(Ordering::SeqCst) {
            return Err(ShardRuntimeError::Unavailable);
        }
        ContextEgressReleaseReceipt::new(request.clone(), 17, 9)
            .map_err(|_| ShardRuntimeError::Rejected)
    }
}
#[async_trait]
impl ProductionSandboxControl for PoolSandbox {
    async fn probe_daemon_epoch(
        &self,
        worker: &WorkerId,
        epoch: u64,
    ) -> Result<u64, ShardRuntimeError> {
        self.inner.probe_daemon_epoch(worker, epoch).await
    }
}

async fn send_event(writer: &mut Sender, value: Value) {
    writer
        .write_all(&serde_json::to_vec(&value).unwrap())
        .await
        .unwrap();
    writer.write_all(&[0]).await.unwrap();
}
struct RuntimeUpdate {
    cache: Arc<browserd_core::RuntimeSafetyCache>,
    snapshot: browserd_core::SafetySwitchSnapshot,
}
impl RuntimeUpdate {
    fn commit(self) {
        let namespace = self.cache.generation().unwrap().namespace_id();
        self.cache
            .install(namespace, self.snapshot, Duration::from_secs(30))
            .unwrap();
    }
}
type HealthGate = Arc<Mutex<Option<(mpsc::SyncSender<()>, CancellationToken)>>>;

async fn pooled_peer(
    peer: oneshot::Receiver<(Receiver, Sender)>,
    runtime_resume_hook: Arc<Mutex<Option<RuntimeUpdate>>>,
    health_gate: HealthGate,
) {
    let (mut reader, mut writer) = peer.await.expect("pooled CDP pipes");
    let mut contexts = BTreeMap::<String, String>::new();
    let mut targets = BTreeMap::<String, String>::new();
    let mut created = 0u64;
    loop {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0u8];
            let count = tokio::time::timeout(Duration::from_secs(15), reader.read(&mut byte))
                .await
                .expect("bounded fake peer")
                .expect("read");
            if count == 0 {
                assert!(bytes.is_empty());
                return;
            }
            if byte[0] == 0 {
                break;
            }
            assert!(bytes.len() < 128 * 1024);
            bytes.push(byte[0]);
        }
        let command: Value = serde_json::from_slice(&bytes).unwrap();
        let flat = command["sessionId"].as_str().unwrap_or("");
        let index = flat.strip_prefix("flat-").unwrap_or("");
        let result = match command["method"].as_str().unwrap() {
            "Browser.getVersion" => {
                let gate = health_gate.lock().unwrap().take();
                if let Some((entered, release)) = gate {
                    entered.send(()).unwrap();
                    release.cancelled().await;
                }
                json!({"protocolVersion":"1.3", "product":"HeadlessChrome/149.0.7827.55", "revision":"r1234567", "userAgent":"browserd-production-factory-test", "jsVersion":"14.9"})
            }
            "Target.setAutoAttach" | "Target.setDiscoverTargets" => json!({}),
            "Target.getTargets" => {
                json!({"targetInfos":targets.iter().map(|(target, context)| json!({"targetId":target,"browserContextId":context,"type":"page"})).collect::<Vec<_>>()})
            }
            "Target.getBrowserContexts" => {
                json!({"browserContextIds":contexts.keys().collect::<Vec<_>>()})
            }
            "Target.createBrowserContext" => {
                assert_eq!(command["params"]["disposeOnDetach"], true);
                assert_eq!(command["params"]["proxyBypassList"], "<-loopback>");
                created += 1;
                assert_eq!(
                    command["params"]["proxyServer"],
                    format!("http://127.0.0.1:{}", 32_099 + created),
                    "each context must use its own exact route endpoint"
                );
                let id = format!("context-{created}");
                contexts.insert(id.clone(), String::new());
                json!({"browserContextId":id})
            }
            "Browser.setDownloadBehavior" => {
                assert_eq!(command["params"]["behavior"], "deny");
                json!({})
            }
            "Target.createTarget" => {
                let context = command["params"]["browserContextId"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let number = context.strip_prefix("context-").unwrap();
                let target = format!("target-{number}");
                let flat = format!("flat-{number}");
                *contexts.get_mut(&context).expect("created context") = target.clone();
                targets.insert(target.clone(), context.clone());
                send_event(&mut writer, json!({"method":"Target.attachedToTarget","params":{"sessionId":flat,"waitingForDebugger":true,"targetInfo":{"targetId":target,"browserContextId":context,"type":"page"}}})).await;
                json!({"targetId":target})
            }
            "Runtime.enable" => {
                send_event(&mut writer,json!({"method":"Runtime.executionContextCreated","sessionId":flat,"params":{"context":{"id":1,"uniqueId":format!("realm-{index}"),"origin":"about:blank","name":"","auxData":{"isDefault":true,"type":"default","frameId":format!("frame-{index}")}}}})).await;
                json!({})
            }
            "Page.getFrameTree" => {
                json!({"frameTree":{"frame":{"id":format!("frame-{index}"),"url":"about:blank","securityOrigin":"://"}}})
            }
            "Network.enable"
            | "Page.enable"
            | "Page.setInterceptFileChooserDialog"
            | "Emulation.setDeviceMetricsOverride"
            | "Network.setUserAgentOverride" => json!({}),
            "Runtime.runIfWaitingForDebugger" => {
                if let Some(update) = runtime_resume_hook.lock().unwrap().take() {
                    update.commit();
                }
                json!({})
            }
            "Target.disposeBrowserContext" => {
                let context = command["params"]["browserContextId"].as_str().unwrap();
                let target = contexts.remove(context).expect("exact context disposal");
                targets.remove(&target);
                send_event(
                    &mut writer,
                    json!({"method":"Target.targetDestroyed","params":{"targetId":target}}),
                )
                .await;
                json!({})
            }
            other => panic!("unexpected pooled fixture command: {other}"),
        };
        respond(&mut writer, &command, result).await;
    }
}

struct Fixture {
    runtime: tokio::runtime::Runtime,
    _native: NativeCatalogFixture,
    sandbox: Arc<PoolSandbox>,
    router: SessionShardRouter<ProductionSessionShardFactory<PoolSandbox>, RejectArtifacts>,
    peers: Vec<tokio::task::JoinHandle<()>>,
    worker: WorkerId,
    runtime_resume_hook: Arc<Mutex<Option<RuntimeUpdate>>>,
    health_gate: HealthGate,
}
impl Fixture {
    fn new(tenants: &[TenantId], lifetime: u64) -> Self {
        Self::new_assigned(tenants, lifetime, None)
    }
    fn new_assigned(tenants: &[TenantId], lifetime: u64, assigned: Option<TenantId>) -> Self {
        Self::new_configured(tenants, lifetime, assigned, None, true)
    }
    fn new_configured(
        tenants: &[TenantId],
        lifetime: u64,
        assigned: Option<TenantId>,
        runtime_safety: Option<Arc<browserd_core::RuntimeSafetyCache>>,
        qualified: bool,
    ) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let native = NativeCatalogFixture::new();
        // Functional fixture evidence only; never written to a deployment qualification file.
        let policy = SharedContextPlacementPolicy::from_config(
            SharedContextPlacementConfig {
                version: 1,
                force_dedicated_process: !qualified,
                max_contexts_per_shard: 2,
                max_contexts_created_lifetime: lifetime,
                max_shard_age_secs: 7200,
                qualification: Some(QualificationReceipt {
                    artifact_identity: native.artifact.identity.clone(),
                    kernel_release: "fixture-kernel".to_owned(),
                    qualified_at: chrono::Utc::now(),
                    evidence: QualificationGate::ALL
                        .into_iter()
                        .map(|gate| {
                            (
                                gate,
                                GateEvidence {
                                    passed: true,
                                    evidence_digest: native.artifact.identity.binary_digest,
                                    observations: 1,
                                },
                            )
                        })
                        .collect(),
                }),
                tenant_reuse: tenants
                    .iter()
                    .cloned()
                    .map(|tenant| (tenant, TenantShardReusePolicy::CrossTenant))
                    .collect(),
            },
            &native.artifact.identity,
            "fixture-kernel",
        )
        .unwrap();
        let worker = WorkerId::new("native-profile-factory").unwrap();
        let config = ProductionSessionShardConfig::new(
            worker.clone(),
            31,
            17,
            native.artifact.identity.clone(),
            ChromiumConnectionConfig::default(),
            EgressPolicyBinding::new("public-web-default", [25; 32]).unwrap(),
            Duration::from_secs(30),
        )
        .unwrap()
        .with_native_profiles(native.catalog())
        .unwrap()
        .with_shared_context_policy(Arc::new(policy))
        .unwrap();
        let config = if let Some(tenant) = assigned {
            config
                .with_worker_tenant_assignment(
                    browserd_worker::WorkerTenantAssignment::new(worker.clone(), tenant, [91; 32])
                        .unwrap(),
                )
                .unwrap()
        } else {
            config
        };
        let (ready_tx, ready_rx) = oneshot::channel();
        let mut senders = VecDeque::from([ready_tx]);
        let mut peers = Vec::new();
        let runtime_resume_hook = Arc::new(Mutex::new(None));
        let health_gate = Arc::new(Mutex::new(None));
        for _ in 0..4 {
            let (tx, rx) = oneshot::channel();
            senders.push_back(tx);
            peers.push(runtime.spawn(pooled_peer(
                rx,
                runtime_resume_hook.clone(),
                health_gate.clone(),
            )));
        }
        let sandbox = Arc::new(PoolSandbox {
            inner: ScriptedSandbox {
                daemon_epoch: 17,
                cancel_delay: Mutex::new(Duration::ZERO),
                peer_termination: None,
                panic_next_cancel: AtomicBool::new(false),
                missing_binding: false,
                created_specs: Mutex::new(Vec::new()),
                pinned_namespaces: Mutex::new(Vec::new()),
                peers: Mutex::new(senders),
                launches: AtomicUsize::new(0),
                claims: AtomicUsize::new(0),
                renewals: AtomicUsize::new(0),
                kills: AtomicUsize::new(0),
                cancelled_specs: Mutex::new(Vec::new()),
            },
            initial: Mutex::new(Vec::new()),
            attached: Mutex::new(Vec::new()),
            released: Mutex::new(Vec::new()),
            reject_release: AtomicBool::new(false),
        });
        let mut factory =
            ProductionSessionShardFactory::new(config, sandbox.clone(), runtime.handle().clone())
                .unwrap();
        if let Some(cache) = runtime_safety {
            factory = factory.with_runtime_safety(cache);
        }
        let factory = Arc::new(factory);
        let ready = runtime.spawn(run_scripted_protocol(ready_rx, CleanupProbe::Clean));
        assert_eq!(factory.qualify_daemon(), Ok(()));
        wait_protocol(&runtime, ready).unwrap();
        let router =
            SessionShardRouter::new(worker.clone(), 31, factory, Arc::new(RejectArtifacts), 16)
                .unwrap();
        Self {
            runtime,
            _native: native,
            sandbox,
            router,
            peers,
            worker,
            runtime_resume_hook,
            health_gate,
        }
    }
    fn create(
        &self,
        tenant: &TenantId,
        placement: u64,
        isolation: WorkerIsolationProfile,
    ) -> (SessionId, OwnershipFence) {
        self.create_effective(tenant, placement, isolation, isolation)
    }
    fn create_effective(
        &self,
        tenant: &TenantId,
        placement: u64,
        requested: WorkerIsolationProfile,
        effective: WorkerIsolationProfile,
    ) -> (SessionId, OwnershipFence) {
        let session = SessionId::new();
        let fence = OwnershipFence::new(self.worker.clone(), 31, placement, 1);
        let mut options = native_session_options();
        options.network_policy_id = "public-web-default".to_owned();
        let receipt = self
            .router
            .create_context_owned_with_placement(
                tenant,
                &session,
                &fence,
                Some(&options),
                requested,
            )
            .expect("pooled context");
        assert_eq!(receipt.effective_isolation, effective);
        (session, fence)
    }
    fn close(&self, session: &(SessionId, OwnershipFence)) {
        assert_eq!(
            self.router.close_context_fenced(&session.0, &session.1),
            Ok(())
        );
    }
    fn finish(mut self) {
        let started = self.sandbox.inner.claims.load(Ordering::SeqCst) - 1;
        for (index, peer) in self.peers.drain(..).enumerate() {
            if index < started {
                wait_protocol(&self.runtime, peer).unwrap();
            } else {
                peer.abort();
            }
        }
    }
}

fn runtime_pool_cache() -> Arc<browserd_core::RuntimeSafetyCache> {
    let cache = Arc::new(browserd_core::RuntimeSafetyCache::new());
    let snapshot = browserd_core::SafetySwitchSnapshot::default()
        .apply(&browserd_core::SafetySwitchMutation::SetForceDedicatedProcess(false))
        .unwrap()
        .apply(&browserd_core::SafetySwitchMutation::SetMaxContextsPerShard(2))
        .unwrap();
    cache
        .install(
            *TenantId::new().as_uuid(),
            snapshot,
            Duration::from_secs(30),
        )
        .unwrap();
    cache
}
fn pool_safety_update(
    cache: &browserd_core::RuntimeSafetyCache,
    mutation: browserd_core::SafetySwitchMutation,
) {
    let namespace = cache.generation().unwrap().namespace_id();
    let snapshot = cache
        .with_fresh_snapshot(|snapshot| snapshot.apply(&mutation))
        .unwrap()
        .unwrap();
    cache
        .install(namespace, snapshot, Duration::from_secs(30))
        .unwrap();
}

#[test]
fn runtime_density_decrease_permanently_drains_old_pool_and_raise_preserves_qualified_ceiling() {
    let tenant = TenantId::new();
    let cache = runtime_pool_cache();
    let fixture = Fixture::new_configured(
        std::slice::from_ref(&tenant),
        8,
        None,
        Some(cache.clone()),
        true,
    );
    let first = fixture.create(&tenant, 1, WorkerIsolationProfile::SharedContext);
    assert_eq!(fixture.sandbox.inner.launches.load(Ordering::SeqCst), 2);
    pool_safety_update(
        &cache,
        browserd_core::SafetySwitchMutation::SetMaxContextsPerShard(1),
    );
    pool_safety_update(
        &cache,
        browserd_core::SafetySwitchMutation::SetMaxContextsPerShard(8),
    );
    // Neither update was observed by a heartbeat; the old generation remains cancelled.
    fixture.router.heartbeat(&fixture.worker, 31).unwrap();
    let second = fixture.create(&tenant, 2, WorkerIsolationProfile::SharedContext);
    assert_eq!(
        fixture.sandbox.inner.launches.load(Ordering::SeqCst),
        3,
        "old pool never resumes admission"
    );
    let third = fixture.create(&tenant, 3, WorkerIsolationProfile::SharedContext);
    assert_eq!(fixture.sandbox.inner.launches.load(Ordering::SeqCst), 3);
    let fourth = fixture.create(&tenant, 4, WorkerIsolationProfile::SharedContext);
    assert_eq!(
        fixture.sandbox.inner.launches.load(Ordering::SeqCst),
        4,
        "runtime 8 never exceeds qualified 2"
    );
    for session in [&first, &second, &third, &fourth] {
        fixture.close(session);
    }
    fixture.finish();
}

#[test]
fn runtime_shared_intent_never_mints_local_qualification_and_force_dedicated_strengthens_placement()
{
    for qualified in [false, true] {
        let tenant = TenantId::new();
        let cache = runtime_pool_cache();
        if qualified {
            pool_safety_update(
                &cache,
                browserd_core::SafetySwitchMutation::SetForceDedicatedProcess(true),
            );
        }
        let fixture = Fixture::new_configured(
            std::slice::from_ref(&tenant),
            8,
            None,
            Some(cache),
            qualified,
        );
        let session = fixture.create_effective(
            &tenant,
            1,
            WorkerIsolationProfile::SharedContext,
            WorkerIsolationProfile::DedicatedProcess,
        );
        assert!(
            fixture
                .sandbox
                .inner
                .created_specs
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .context_route_policy()
                .is_none()
        );
        fixture.close(&session);
        fixture.finish();
    }
}

#[test]
fn runtime_unavailable_network_stop_and_actual_build_digest_deny_before_any_user_launch() {
    for deny in 0..3 {
        let tenant = TenantId::new();
        let cache = runtime_pool_cache();
        let fixture = Fixture::new_configured(
            std::slice::from_ref(&tenant),
            8,
            None,
            Some(cache.clone()),
            true,
        );
        match deny {
            0 => {
                cache.invalidate().expect("cache invalidation");
            }
            1 => pool_safety_update(
                &cache,
                browserd_core::SafetySwitchMutation::SetStoppedNetworkClass {
                    network_class: "public".into(),
                    stopped: true,
                },
            ),
            _ => pool_safety_update(
                &cache,
                browserd_core::SafetySwitchMutation::SetChromiumBuildDisabled {
                    digest: fixture._native.artifact.identity.binary_digest.to_string(),
                    disabled: true,
                },
            ),
        }
        let session = SessionId::new();
        let fence = OwnershipFence::new(fixture.worker.clone(), 31, 1, 1);
        let mut options = native_session_options();
        options.network_policy_id = "public-web-default".into();
        assert!(
            fixture
                .router
                .create_context_owned_with_placement(
                    &tenant,
                    &session,
                    &fence,
                    Some(&options),
                    WorkerIsolationProfile::SharedContext
                )
                .is_err()
        );
        assert_eq!(
            fixture.sandbox.inner.launches.load(Ordering::SeqCst),
            1,
            "only structural qualification launched"
        );
        fixture.finish();
    }
}

#[test]
fn runtime_update_after_bootstrap_before_exposure_requires_positive_exact_cleanup() {
    let tenant = TenantId::new();
    let cache = runtime_pool_cache();
    let fixture = Fixture::new_configured(
        std::slice::from_ref(&tenant),
        8,
        None,
        Some(cache.clone()),
        true,
    );
    let snapshot = cache
        .with_fresh_snapshot(|snapshot| {
            snapshot.apply(
                &browserd_core::SafetySwitchMutation::SetStoppedNetworkClass {
                    network_class: "public".into(),
                    stopped: true,
                },
            )
        })
        .unwrap()
        .unwrap();
    *fixture.runtime_resume_hook.lock().unwrap() = Some(RuntimeUpdate { cache, snapshot });
    let session = SessionId::new();
    let fence = OwnershipFence::new(fixture.worker.clone(), 31, 1, 1);
    let mut options = native_session_options();
    options.network_policy_id = "public-web-default".into();
    assert!(
        fixture
            .router
            .create_context_owned_with_placement(
                &tenant,
                &session,
                &fence,
                Some(&options),
                WorkerIsolationProfile::SharedContext
            )
            .is_err()
    );
    assert_eq!(
        fixture.sandbox.inner.launches.load(Ordering::SeqCst),
        2,
        "update raced a real user startup"
    );
    assert!(
        fixture.runtime_resume_hook.lock().unwrap().is_none(),
        "update occurred at actual bootstrap resume"
    );
    assert_eq!(
        fixture.sandbox.inner.cancelled_specs.lock().unwrap().len(),
        2,
        "qualification and rejected user launch both cleaned by exact spec"
    );
    fixture.finish();
}

#[test]
fn pooled_qualifier_releases_membership_lock_during_renderer_rpc() {
    let tenant = TenantId::new();
    let fixture = Fixture::new(std::slice::from_ref(&tenant), 3);
    let first = fixture.create(&tenant, 1, WorkerIsolationProfile::SharedContext);
    let second = fixture.create(&tenant, 2, WorkerIsolationProfile::SharedContext);
    let (entered, observed) = mpsc::sync_channel(1);
    let release = CancellationToken::new();
    *fixture.health_gate.lock().unwrap() = Some((entered, release.clone()));
    std::thread::scope(|scope| {
        let qualification = scope.spawn(|| ChromiumDriver::qualify(&fixture.router));
        let entered = observed.recv_timeout(Duration::from_secs(2));
        let (completed, result) = mpsc::channel();
        let router = &fixture.router;
        let worker = &fixture.worker;
        let heartbeat = scope.spawn(move || {
            let renewal = SandboxClient::heartbeat(router, worker, 31);
            let _ = completed.send(renewal);
            renewal
        });
        let while_renderer_waits = result.recv_timeout(Duration::from_millis(200));
        release.cancel();
        let qualified = qualification.join();
        let renewed = heartbeat.join();
        assert!(entered.is_ok());
        assert_eq!(
            while_renderer_waits,
            Ok(Ok(())),
            "physical renewal does not wait for the pooled renderer probe"
        );
        assert!(matches!(qualified, Ok(Ok(()))));
        assert!(matches!(renewed, Ok(Ok(()))));
    });
    assert_eq!(
        fixture.sandbox.inner.renewals.load(Ordering::SeqCst),
        1,
        "one exact physical owner for both contexts"
    );
    fixture.close(&first);
    fixture.close(&second);
    fixture.finish();
}

#[test]
fn shared_pool_reuses_exact_shard_and_closes_only_the_owned_context() {
    let a = TenantId::new();
    let b = TenantId::new();
    let f = Fixture::new(&[a.clone(), b.clone()], 3);
    let first = f.create(&a, 1, WorkerIsolationProfile::SharedContext);
    let second = f.create(&b, 2, WorkerIsolationProfile::SharedContext);
    assert_eq!(f.sandbox.inner.launches.load(Ordering::SeqCst), 2); // readiness + shared process
    assert_eq!(SandboxClient::heartbeat(&f.router, &f.worker, 31), Ok(()));
    assert_eq!(f.sandbox.inner.renewals.load(Ordering::SeqCst), 1);
    f.close(&first);
    assert_eq!(f.sandbox.inner.kills.load(Ordering::SeqCst), 1);
    assert_eq!(SandboxClient::heartbeat(&f.router, &f.worker, 31), Ok(())); // first session's route is already released
    let third = f.create(&a, 3, WorkerIsolationProfile::SharedContext);
    assert_eq!(f.sandbox.inner.launches.load(Ordering::SeqCst), 2);
    f.close(&second); // free live capacity, lifetime must still prevent a fourth context
    let fourth = f.create(&b, 4, WorkerIsolationProfile::SharedContext);
    assert_eq!(f.sandbox.inner.launches.load(Ordering::SeqCst), 3);
    f.close(&third);
    assert_eq!(f.sandbox.inner.kills.load(Ordering::SeqCst), 2);
    f.close(&fourth);
    assert_eq!(f.sandbox.inner.kills.load(Ordering::SeqCst), 3);
    assert_eq!(f.sandbox.released.lock().unwrap().len(), 4);
    f.finish();
}

#[test]
fn tenant_dedicated_pool_never_reuses_a_foreign_tenants_shard() {
    let a = TenantId::new();
    let b = TenantId::new();
    let f = Fixture::new(&[a.clone(), b.clone()], 8);
    let first = f.create(&a, 1, WorkerIsolationProfile::TenantDedicatedShard);
    let second = f.create(&a, 2, WorkerIsolationProfile::TenantDedicatedShard);
    let third = f.create(&b, 3, WorkerIsolationProfile::TenantDedicatedShard);
    assert_eq!(f.sandbox.inner.launches.load(Ordering::SeqCst), 3);
    f.close(&first);
    f.close(&second);
    f.close(&third);
    f.finish();
}

#[test]
fn uncertain_context_route_release_requires_positive_whole_shard_cleanup() {
    let tenant = TenantId::new();
    let f = Fixture::new(std::slice::from_ref(&tenant), 8);
    let first = f.create(&tenant, 1, WorkerIsolationProfile::SharedContext);
    let second = f.create(&tenant, 2, WorkerIsolationProfile::SharedContext);
    f.sandbox.reject_release.store(true, Ordering::SeqCst);
    f.close(&first);
    assert_eq!(f.sandbox.inner.kills.load(Ordering::SeqCst), 2);
    assert!(ChromiumDriver::qualify(&f.router).is_err());
    f.close(&second);
    assert_eq!(f.sandbox.inner.kills.load(Ordering::SeqCst), 2);
    f.finish();
}

#[test]
fn concurrent_pool_creates_reserve_capacity_before_launch_or_context_effect() {
    let tenant = TenantId::new();
    let f = Fixture::new(std::slice::from_ref(&tenant), 8);
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| f.create(&tenant, 1, WorkerIsolationProfile::SharedContext));
        let second = scope.spawn(|| f.create(&tenant, 2, WorkerIsolationProfile::SharedContext));
        (
            first.join().expect("first create"),
            second.join().expect("second create"),
        )
    });
    assert_eq!(f.sandbox.inner.launches.load(Ordering::SeqCst), 2);
    let third = f.create(&tenant, 3, WorkerIsolationProfile::SharedContext);
    assert_eq!(f.sandbox.inner.launches.load(Ordering::SeqCst), 3);
    f.close(&first);
    f.close(&second);
    f.close(&third);
    f.finish();
}

#[test]
fn exclusive_worker_strengthens_weaker_requests_and_rejects_foreign_tenant_before_launch() {
    let tenant = TenantId::new();
    let f = Fixture::new_assigned(std::slice::from_ref(&tenant), 3, Some(tenant.clone()));
    let mut sessions = Vec::new();
    for (index, requested) in [
        WorkerIsolationProfile::SharedContext,
        WorkerIsolationProfile::DedicatedWorker,
    ]
    .into_iter()
    .enumerate()
    {
        let session = SessionId::new();
        let fence = OwnershipFence::new(f.worker.clone(), 31, index as u64 + 1, 1);
        let mut options = native_session_options();
        options.network_policy_id = "public-web-default".to_owned();
        let receipt = f
            .router
            .create_context_owned_with_placement(
                &tenant,
                &session,
                &fence,
                Some(&options),
                requested,
            )
            .unwrap();
        assert_eq!(
            receipt.effective_isolation,
            WorkerIsolationProfile::DedicatedWorker
        );
        sessions.push((session, fence));
    }
    assert_eq!(f.sandbox.inner.launches.load(Ordering::SeqCst), 3);
    let foreign = TenantId::new();
    let session = SessionId::new();
    let fence = OwnershipFence::new(f.worker.clone(), 31, 3, 1);
    assert!(
        f.router
            .create_context_owned_with_placement(
                &foreign,
                &session,
                &fence,
                Some(&native_session_options()),
                WorkerIsolationProfile::DedicatedWorker
            )
            .is_err()
    );
    assert_eq!(f.sandbox.inner.launches.load(Ordering::SeqCst), 3);
    for session in sessions {
        f.close(&session);
    }
    f.finish();
}
