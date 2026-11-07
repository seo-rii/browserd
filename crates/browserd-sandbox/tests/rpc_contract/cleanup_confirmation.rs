use super::*;

fn client(socket: &std::path::Path, budget: Duration) -> SandboxRpcClient {
    SandboxRpcClient::new(
        socket,
        4 * 1024,
        budget,
        nix::unistd::Uid::effective().as_raw(),
        SANDBOXD_EPOCH,
    )
    .expect("bounded client")
    .with_expected_server_identity(ChildIdentity::new(
        std::process::id(),
        current_process_start_time(),
    ))
}

fn assert_exact_request(request: &serde_json::Value, spec: &LaunchSpec) {
    assert_eq!(
        request,
        &json!({
            "operation": "cancel_or_kill_shard",
            "sandboxd_epoch": SANDBOXD_EPOCH,
            "spec": spec,
            "reason": "administrative",
        })
    );
}

async fn send_response(stream: &mut UnixStream, response: serde_json::Value) {
    let bytes = serde_json::to_vec(&response).expect("bounded response JSON");
    let length = u32::try_from(bytes.len()).expect("test frame fits");
    // A deadline test intentionally sends after the original caller has disconnected.
    if stream.write_all(&length.to_be_bytes()).await.is_ok() {
        let _ = stream.write_all(&bytes).await;
    }
}

fn confirmation(outcome: KillShardOutcome) -> serde_json::Value {
    json!({"status": "success", "value": {
        "result": "cancel_or_kill_shard", "value": outcome,
    }})
}

#[tokio::test]
async fn lost_cleanup_ack_recovers_only_the_exact_supervisor_termination_confirmation() {
    for committed_before_disconnect in [true, false] {
        let temporary = tempdir().expect("private socket directory");
        let socket = temporary.path().join("cleanup.sock");
        let listener = UnixListener::bind(&socket).expect("bounded Unix fixture");
        let backend = RecordingBackend::default();
        let observed = backend.clone();
        let supervisor = supervisor(backend);
        let spec = launch_spec(ShardId::new(), worker(), 9);
        assert_eq!(
            supervisor
                .create_shard(
                    spec.clone(),
                    WorkerOwnership::new(
                        spec.worker_id().clone(),
                        spec.worker_epoch(),
                        tokio::time::Instant::now() + Duration::from_millis(80),
                    )
                )
                .await,
            Ok(CreateShardOutcome::Created),
        );
        let expected_spec = spec.clone();
        let server = tokio::spawn(async move {
            let (first, request) = accept_probe_request(&listener).await;
            assert_exact_request(&request, &expected_spec);
            if committed_before_disconnect {
                let result = supervisor
                    .cancel_or_kill_shard(&expected_spec, CleanupReason::Administrative)
                    .await
                    .expect("actual first cleanup commits");
                assert!(matches!(result, KillShardOutcome::Terminated(cleanup)
                    if cleanup.route_revoked && cleanup.cgroup_killed && cleanup.namespaces_cleaned));
            }
            // Drop the first ACK, whether the exact cleanup committed or was not started.
            drop(first);
            let (mut second, repeated) = accept_probe_request(&listener).await;
            assert_eq!(
                request, repeated,
                "retry preserves every immutable launch field"
            );
            assert_exact_request(&repeated, &expected_spec);
            let outcome = supervisor
                .cancel_or_kill_shard(&expected_spec, CleanupReason::Administrative)
                .await
                .expect("actual fenced supervisor confirmation");
            if committed_before_disconnect {
                assert_eq!(outcome, KillShardOutcome::AlreadyTerminated);
            } else {
                assert!(matches!(outcome, KillShardOutcome::Terminated(cleanup)
                    if cleanup.route_revoked && cleanup.cgroup_killed && cleanup.namespaces_cleaned));
            }
            send_response(&mut second, confirmation(outcome)).await;
            outcome
        });
        let result = client(&socket, Duration::from_secs(1))
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await;
        if result.is_err() {
            server.abort();
        }
        assert!(
            matches!(
                result,
                Ok(KillShardOutcome::AlreadyTerminated | KillShardOutcome::Terminated(_))
            ),
            "lost ACK needs a real termination confirmation: {result:?}"
        );
        assert_eq!(
            result.expect("confirmed result"),
            server.await.expect("bounded server")
        );
        assert_eq!(
            observed.events(),
            ["provision", "revoke", "kill", "cleanup"],
            "the confirmation must not repeat completed cleanup effects"
        );
    }
}

#[tokio::test]
async fn two_cleanup_disconnects_remain_an_error_and_never_start_a_third_attempt() {
    let temporary = tempdir().expect("private socket directory");
    let socket = temporary.path().join("cleanup.sock");
    let listener = UnixListener::bind(&socket).expect("Unix fixture");
    let spec = launch_spec(ShardId::new(), worker(), 9);
    let expected_spec = spec.clone();
    let server = tokio::spawn(async move {
        let (first, request) = accept_probe_request(&listener).await;
        assert_exact_request(&request, &expected_spec);
        drop(first);
        let second =
            tokio::time::timeout(Duration::from_millis(500), accept_probe_request(&listener)).await;
        let count = if let Ok((second, repeated)) = second {
            assert_eq!(request, repeated);
            drop(second);
            2
        } else {
            1
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err(),
            "two failures exhaust the confirmation budget"
        );
        count
    });
    assert_eq!(
        client(&socket, Duration::from_secs(1))
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Err(SandboxRpcError::ConnectionClosed)
    );
    assert_eq!(server.await.expect("bounded observer"), 2);
}

#[tokio::test]
async fn cleanup_confirmation_retry_shares_the_original_overall_deadline() {
    let temporary = tempdir().expect("private socket directory");
    let socket = temporary.path().join("cleanup.sock");
    let listener = UnixListener::bind(&socket).expect("Unix fixture");
    let backend = RecordingBackend::default();
    let supervisor = supervisor(backend);
    let spec = launch_spec(ShardId::new(), worker(), 9);
    supervisor
        .create_shard(
            spec.clone(),
            WorkerOwnership::new(
                spec.worker_id().clone(),
                spec.worker_epoch(),
                tokio::time::Instant::now() + Duration::from_millis(80),
            ),
        )
        .await
        .expect("active shard");
    let expected_spec = spec.clone();
    let server = tokio::spawn(async move {
        let (first, request) = accept_probe_request(&listener).await;
        assert_exact_request(&request, &expected_spec);
        supervisor
            .cancel_or_kill_shard(&expected_spec, CleanupReason::Administrative)
            .await
            .expect("first cleanup committed");
        tokio::time::sleep(Duration::from_millis(250)).await;
        drop(first);
        let second =
            tokio::time::timeout(Duration::from_millis(500), accept_probe_request(&listener)).await;
        if let Ok((mut second, repeated)) = second {
            assert_eq!(request, repeated);
            let outcome = supervisor
                .cancel_or_kill_shard(&expected_spec, CleanupReason::Administrative)
                .await
                .expect("completed exact shard");
            assert_eq!(outcome, KillShardOutcome::AlreadyTerminated);
            tokio::time::sleep(Duration::from_millis(250)).await;
            send_response(&mut second, confirmation(outcome)).await;
        }
    });
    let result = client(&socket, Duration::from_millis(400))
        .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
        .await;
    server.await.expect("bounded delayed confirmation");
    assert_eq!(
        result,
        Err(SandboxRpcError::TimedOut),
        "a confirmation at 500ms must not extend the original 400ms request budget"
    );
}

#[tokio::test]
async fn first_cleanup_timeout_does_not_retry() {
    let temporary = tempdir().expect("private socket directory");
    let socket = temporary.path().join("cleanup.sock");
    let listener = UnixListener::bind(&socket).expect("Unix fixture");
    let spec = launch_spec(ShardId::new(), worker(), 9);
    let expected_spec = spec.clone();
    let server = tokio::spawn(async move {
        let (first, request) = accept_probe_request(&listener).await;
        assert_exact_request(&request, &expected_spec);
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(first);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    });
    assert_eq!(
        client(&socket, Duration::from_millis(50))
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Err(SandboxRpcError::TimedOut)
    );
    server.await.expect("timeout observer");
}

#[tokio::test]
async fn explicit_remote_and_protocol_failures_do_not_retry_cleanup() {
    for (response, error) in [
        (
            json!({"status":"failure","value":{"code":"worker_epoch_mismatch","message":"stale owner"}}),
            SandboxRpcError::Remote {
                code: RpcFailureCode::WorkerEpochMismatch,
                message: "stale owner".into(),
            },
        ),
        (
            json!({"status":"failure","value":{"code":"ownership_mismatch","message":"wrong owner"}}),
            SandboxRpcError::Remote {
                code: RpcFailureCode::OwnershipMismatch,
                message: "wrong owner".into(),
            },
        ),
        (
            json!({"status":"failure","value":{"code":"incomplete_cleanup","message":"cleanup incomplete"}}),
            SandboxRpcError::Remote {
                code: RpcFailureCode::IncompleteCleanup,
                message: "cleanup incomplete".into(),
            },
        ),
        (
            json!({"status":"success","value":{"result":"renewed"}}),
            SandboxRpcError::Protocol,
        ),
    ] {
        let temporary = tempdir().expect("private socket directory");
        let socket = temporary.path().join("cleanup.sock");
        let listener = UnixListener::bind(&socket).expect("Unix fixture");
        let spec = launch_spec(ShardId::new(), worker(), 9);
        let expected_spec = spec.clone();
        let server = tokio::spawn(async move {
            let (mut stream, request) = accept_probe_request(&listener).await;
            assert_exact_request(&request, &expected_spec);
            send_response(&mut stream, response).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err(),
                "an explicit failure is final"
            );
        });
        assert_eq!(
            client(&socket, Duration::from_secs(1))
                .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
                .await,
            Err(error)
        );
        server.await.expect("explicit failure observer");
    }
}

#[tokio::test]
async fn stale_daemon_epoch_cannot_turn_disconnect_recovery_into_cleanup_success() {
    let temporary = tempdir().expect("private socket directory");
    let socket = temporary.path().join("cleanup.sock");
    let listener = UnixListener::bind(&socket).expect("actual sandbox server");
    let backend = RecordingBackend::default();
    let observed = backend.clone();
    let server = SandboxRpcServer::new(supervisor(backend), bound_rpc_config());
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve(listener, shutdown.clone()));
    let stale = SandboxRpcClient::new(
        socket,
        4 * 1024,
        Duration::from_secs(1),
        nix::unistd::Uid::effective().as_raw(),
        SANDBOXD_EPOCH + 1,
    )
    .expect("stale client config")
    .with_expected_server_identity(ChildIdentity::new(
        std::process::id(),
        current_process_start_time(),
    ));
    let result = stale
        .cancel_or_kill_shard(
            &launch_spec(ShardId::new(), worker(), 9),
            CleanupReason::Administrative,
        )
        .await;
    shutdown.cancel();
    task.await
        .expect("actual server join")
        .expect("bounded server shutdown");
    assert_eq!(result, Err(SandboxRpcError::ConnectionClosed));
    assert!(
        observed.events().is_empty(),
        "every stale-epoch attempt is fenced before effects"
    );
}

#[tokio::test]
async fn cleanup_peer_rejection_sends_no_request_and_does_not_retry() {
    for wrong_uid in [true, false] {
        let temporary = tempdir().expect("private socket directory");
        let socket = temporary.path().join("cleanup.sock");
        let listener = UnixListener::bind(&socket).expect("Unix fixture");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("first peer check");
            let mut byte = [0];
            assert_eq!(
                stream.read(&mut byte).await.expect("rejected peer closes"),
                0
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
        });
        let uid = nix::unistd::Uid::effective().as_raw();
        let expected_uid = if wrong_uid { uid.wrapping_add(1) } else { uid };
        let expected_start = current_process_start_time() + u64::from(!wrong_uid);
        let client = SandboxRpcClient::new(
            socket,
            4 * 1024,
            Duration::from_secs(1),
            expected_uid,
            SANDBOXD_EPOCH,
        )
        .expect("pinned client")
        .with_expected_server_identity(ChildIdentity::new(std::process::id(), expected_start));
        let result = client
            .cancel_or_kill_shard(
                &launch_spec(ShardId::new(), worker(), 9),
                CleanupReason::Administrative,
            )
            .await;
        if wrong_uid {
            assert_eq!(
                result,
                Err(SandboxRpcError::PeerUidMismatch {
                    expected: expected_uid,
                    received: uid
                })
            );
        } else {
            assert_eq!(result, Err(SandboxRpcError::PeerProcessMismatch));
        }
        server.await.expect("peer check observer");
    }
}
