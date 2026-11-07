use super::*;
use browserd_core::PlacementFence;
use browserd_sandbox::{ContextEgressRequest, ContextRoutePhase, ContextRoutePolicy};

type SharedBackend = LinuxSandboxBackend<FakeFilesystem, FakeProcess, FakeEgress>;
async fn shared_fixture(
    live: u16,
    lifetime: u16,
) -> (
    tempfile::TempDir,
    Arc<FilePreparedShardJournal>,
    SharedBackend,
    FakeEgress,
    LaunchSpec,
    browserd_sandbox::SandboxHandle,
) {
    let directory = tempfile::tempdir().expect("journal dir");
    let journal = Arc::new(
        FilePreparedShardJournal::open_with_limits_and_roots(
            directory.path(),
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(
                PathBuf::from("/sys/fs/cgroup/browserd"),
                PathBuf::from("/var/lib/browserd/shards"),
            )
            .expect("roots"),
        )
        .expect("journal"),
    );
    let egress = FakeEgress::default();
    let filesystem = FakeFilesystem::production_tree();
    let backend = backend(
        filesystem.clone(),
        FakeProcess {
            identity_matches: true,
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
        },
        egress.clone(),
    )
    .with_prepared_journal(journal.clone(), 41)
    .expect("journal binding");
    let spec = launch_spec(ShardId::new())
        .with_context_route_policy(
            ContextRoutePolicy::new(PlacementFence::new(7, 1, 1), false, live, lifetime)
                .expect("policy"),
        )
        .expect("shared launch");
    let handle = backend.provision_gated(&spec).await.expect("provision");
    drop(backend.claim_cdp_pipes(&handle).await.expect("pipes"));
    backend
        .commit_cdp_claim(&handle)
        .await
        .expect("claim receipt");
    backend.activate(&handle).await.expect("activate");
    let cgroup =
        PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{}-launch-1", spec.shard_id()));
    {
        let mut files = filesystem.files.lock().expect("files");
        files.insert(cgroup.join("memory.current"), "1\n".into());
        files.insert(cgroup.join("memory.peak"), "1\n".into());
    }
    (directory, journal, backend, egress, spec, handle)
}
fn next_request(spec: &LaunchSpec, index: u64) -> ContextEgressRequest {
    ContextEgressRequest::new(
        TenantId::new(),
        PlacementFence::new(7, index, 1),
        DedicatedEgressSpec::new(
            EgressFence::new(
                spec.dedicated_egress().egress_fence().shard().clone(),
                RouteGeneration::new(index).expect("route"),
                SessionId::new(),
                SessionIncarnation::new(1).expect("incarnation"),
            ),
            spec.dedicated_egress().policy_binding().clone(),
            Duration::from_secs(5),
        )
        .expect("egress"),
    )
    .expect("request")
}
#[tokio::test]
async fn shared_primary_close_preserves_sibling_and_owner_renewal_skips_released_primary() {
    let (_directory, journal, backend, egress, spec, handle) = shared_fixture(8, 500).await;
    let first_request = ContextEgressRequest::initial(&spec).expect("initial");
    let first = backend
        .attach_context_egress(&handle, &first_request, 11, Duration::from_secs(5))
        .await
        .expect("primary adoption");
    let second_request = next_request(&spec, 2);
    let second = backend
        .attach_context_egress(&handle, &second_request, 11, Duration::from_secs(5))
        .await
        .expect("second binding");
    assert!(first.granted_ttl() <= Duration::from_secs(5));
    assert_eq!(
        first.proxy_binding().namespace_identity(),
        second.proxy_binding().namespace_identity()
    );
    assert_ne!(
        first.proxy_binding().attachment_generation(),
        second.proxy_binding().attachment_generation()
    );
    let release = backend
        .release_context_egress(&handle, &first_request, 11)
        .await
        .expect("primary close");
    assert!(release.listener_closed() && release.drained() && release.released());
    assert!(
        backend
            .inspect(&handle)
            .await
            .expect("sibling health")
            .egress_route_active
    );
    let before = egress.calls.lock().expect("calls").len();
    backend
        .renew_egress(&handle, Duration::from_secs(5))
        .await
        .expect("renew sibling only");
    {
        let calls = egress.calls.lock().expect("calls");
        let renewed: Vec<_> = calls[before..]
            .iter()
            .filter_map(|call| {
                if let EgressCall::Renew(lease, _) = call {
                    lease.reservation().egress_fence()
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(renewed, vec![second_request.egress().egress_fence()]);
    }
    assert!(
        backend
            .attach_context_egress(&handle, &first_request, 11, Duration::from_secs(5))
            .await
            .is_err()
    );
    assert!(
        backend
            .attach_context_egress(&handle, &second_request, 11, Duration::from_secs(5))
            .await
            .is_ok()
    );
    assert_eq!(
        journal.records().expect("records")[0].context_routes()[0].phase(),
        ContextRoutePhase::Released
    );
    backend
        .release_context_egress(&handle, &second_request, 11)
        .await
        .expect("last route close");
    assert!(
        !backend
            .inspect(&handle)
            .await
            .expect("empty shared health")
            .egress_route_active
    );
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("whole shard retirement after all routes release");
    assert!(egress.calls.lock().expect("calls").iter().any(|call| matches!(call,EgressCall::RetireShard(fence) if fence == spec.dedicated_egress().egress_fence().shard())));
}
#[tokio::test]
async fn shared_cancel_before_attach_and_route_capacity_fail_before_prepare() {
    let (_directory, journal, backend, egress, spec, handle) = shared_fixture(1, 3).await;
    let second = next_request(&spec, 2);
    let before = egress.calls.lock().expect("calls").len();
    assert!(
        backend
            .attach_context_egress(&handle, &second, 11, Duration::from_secs(5))
            .await
            .is_err()
    );
    assert_eq!(egress.calls.lock().expect("calls").len(), before);
    backend
        .release_context_egress(&handle, &second, 11)
        .await
        .expect("cancel unknown exact request");
    assert!(
        backend
            .attach_context_egress(&handle, &second, 11, Duration::from_secs(5))
            .await
            .is_err()
    );
    assert_eq!(
        journal.records().expect("records")[0].context_routes()[1].phase(),
        ContextRoutePhase::Released
    );
}
#[tokio::test]
async fn shared_release_failure_retains_ownership_and_retry_releases_same_generation() {
    let (_directory, journal, backend, egress, spec, handle) = shared_fixture(2, 3).await;
    let second = next_request(&spec, 2);
    backend
        .attach_context_egress(&handle, &second, 11, Duration::from_secs(5))
        .await
        .expect("attach");
    egress.fail_release_once.store(1, Ordering::SeqCst);
    assert!(
        backend
            .release_context_egress(&handle, &second, 11)
            .await
            .is_err()
    );
    assert_eq!(
        journal.records().expect("records")[0].context_routes()[1].phase(),
        ContextRoutePhase::Releasing
    );
    assert!(
        backend.inspect(&handle).await.is_err(),
        "uncertain route release cannot report shared health"
    );
    assert!(
        backend
            .attach_context_egress(&handle, &next_request(&spec, 3), 11, Duration::from_secs(5))
            .await
            .is_err()
    );
    backend
        .release_context_egress(&handle, &second, 11)
        .await
        .expect("exact retry");
    backend
        .release_context_egress(&handle, &second, 11)
        .await
        .expect("lost reply retry");
    assert_eq!(
        journal.records().expect("records")[0].context_routes()[1].phase(),
        ContextRoutePhase::Released
    );
}

#[tokio::test]
async fn renewed_context_binding_from_another_sandbox_epoch_is_rejected_before_connect() {
    let (_directory, _journal, backend, _egress, spec, handle) = shared_fixture(2, 3).await;
    let binding = backend
        .attach_context_egress(
            &handle,
            &ContextEgressRequest::initial(&spec).expect("primary"),
            11,
            Duration::from_secs(5),
        )
        .await
        .expect("binding");
    let client = browserd_sandbox::SandboxRpcClient::new(
        "/nonexistent/browserd-context-epoch.sock",
        64 * 1024,
        Duration::from_millis(20),
        nix::unistd::Uid::effective().as_raw(),
        12,
    )
    .expect("client");
    assert!(matches!(
        client
            .renew_context_egress(&binding, Duration::from_secs(1))
            .await,
        Err(browserd_sandbox::SandboxRpcError::Protocol)
    ));
}
