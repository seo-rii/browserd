use super::*;

async fn snapshot_page() -> OwnedPage {
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let mut config = connection_config();
    // This fixture exercises the SPEC result limit rather than the unrelated small-command
    // frame bound used by the shared fixture. Every test still uses a bounded real CDP pipe.
    config.transport.max_frame_bytes = 8 * 1024 * 1024;
    config.transport.default_command_timeout = Duration::from_secs(5);
    config.transport.write_timeout = Duration::from_secs(5);
    let (owner, manager) = ChromiumConnectionOwner::new_bounded(
        identity(),
        config,
        shard_fence(),
        16,
        Arc::clone(&drain),
    )
    .unwrap();
    let driver = owner.chromium_driver(IsolationProfile::SharedContext);
    let (pipes, mut reader, mut writer) = pipe_pair();
    let accept = tokio::spawn({
        let owner = Arc::clone(&owner);
        async move { owner.accept_cdp_pipes(pipes).await }
    });
    qualify(&mut reader, &mut writer).await;
    assert_eq!(accept.await.unwrap(), Ok(()));
    bootstrap_empty(Arc::clone(&manager), &mut reader, &mut writer).await;
    let session_id = SessionId::new();
    let tenant_id = TenantId::new();
    let page_id = create_owned_context(
        driver.clone(),
        tenant_id.clone(),
        session_id.clone(),
        ownership_fence(),
        &mut reader,
        &mut writer,
    )
    .await;
    OwnedPage {
        _owner: owner,
        manager,
        drain,
        driver,
        reader,
        writer,
        session_id,
        page_id,
        tenant_id,
    }
}

async fn finish_snapshot(page: &mut OwnedPage, names: Vec<String>) -> ActionExecutionResult {
    let action = spawn_action(page, br#"{"type":"snapshot"}"#, None);
    let backends: Vec<u64> = (100..100 + names.len() as u64).collect();
    let ax = read_command(&mut page.reader).await;
    assert_eq!(ax["method"], "Accessibility.getFullAXTree");
    let nodes: Vec<Value> = names
        .into_iter()
        .zip(&backends)
        .map(|(name, backend)| {
            json!({
                "ignored": false, "backendDOMNodeId": backend,
                "role": {"value":"button"}, "name": {"value":name},
            })
        })
        .collect();
    respond(&mut page.writer, &ax, json!({"nodes":nodes})).await;
    let dom = read_command(&mut page.reader).await;
    assert_eq!(dom["method"], "DOMSnapshot.captureSnapshot");
    respond(&mut page.writer, &dom, json!({
        "documents":[{"frameId":0,"nodes":{"backendNodeId":backends},"layout":{"nodeIndex":[],"bounds":[]}}],
        "strings":["frame-flat-primary"],
    })).await;
    let metrics = read_command(&mut page.reader).await;
    assert_eq!(metrics["method"], "Page.getLayoutMetrics");
    respond(
        &mut page.writer,
        &metrics,
        json!({"cssLayoutViewport":{"clientWidth":1280,"clientHeight":720}}),
    )
    .await;
    action.await.unwrap()
}

#[tokio::test]
async fn review_six_hundred_node_snapshot_above_64k_remains_a_known_success() {
    let mut page = snapshot_page().await;
    let result = finish_snapshot(&mut page, vec!["가".repeat(16); 600]).await;
    assert!(
        matches!(&result, ActionExecutionResult::Succeeded(_)),
        "a SPEC-sized snapshot must succeed rather than lose outcome certainty: {result:?}"
    );
    let bytes = succeeded_bytes(result);
    assert!(bytes.len() > 64 * 1024);
    assert!(bytes.len() <= 4 * 1024 * 1024);
    let tree: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(tree["returned_nodes"], 600);
    assert_eq!(tree["total_nodes"], 600);
    assert_eq!(tree["truncated"], false);
    assert_eq!(tree["nodes"][0]["name"], "가".repeat(16));
    assert!(!page.manager.is_tainted());
    assert!(!page.drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn review_snapshot_above_four_megabytes_is_known_too_large_without_taint() {
    let mut page = snapshot_page().await;
    let result = finish_snapshot(&mut page, vec!["가".repeat(1365); 1500]).await;
    assert_eq!(
        result,
        ActionExecutionResult::FailedKnown("snapshot_too_large".into())
    );
    assert!(!page.manager.is_tainted());
    assert!(!page.drain.0.load(Ordering::SeqCst));
    let followup = spawn_action(&page, br#"{"type":"get_title"}"#, None);
    let command = read_command(&mut page.reader).await;
    respond(
        &mut page.writer,
        &command,
        json!({"result":{"value":"still owned"}}),
    )
    .await;
    assert!(matches!(
        followup.await.unwrap(),
        ActionExecutionResult::Succeeded(_)
    ));
}

#[tokio::test]
async fn review_snapshot_node_strings_truncate_at_utf8_boundaries_with_explicit_node_counts() {
    let mut page = snapshot_page().await;
    let oversized_name = "x".repeat(4095) + "€";
    let result = finish_snapshot(&mut page, vec![oversized_name]).await;
    let tree: Value = serde_json::from_slice(&succeeded_bytes(result)).unwrap();
    let retained = tree["nodes"][0]["name"].as_str().unwrap();
    assert_eq!(retained.len(), 4095);
    assert!(!retained.contains('€'));
    assert_eq!(tree["returned_nodes"], 1);
    assert_eq!(tree["total_nodes"], 1);
    assert_eq!(tree["truncated"], false);
}
