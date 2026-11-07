use super::*;

#[tokio::test]
async fn review_network_quiet_preserves_the_new_loader_request_across_commit() {
    let mut page = owned_page().await;
    let wait = spawn_action(
        &page,
        br#"{"type":"wait_for","condition":{"type":"network_quiet","quiet_ms":40}}"#,
        Some(Instant::now() + Duration::from_secs(3)),
    );
    for (request, loader) in [
        ("old-document", "old-loader"),
        ("new-document", "new-loader"),
    ] {
        write_message(&mut page.writer, json!({
            "method":"Network.requestWillBeSent","sessionId":"flat-primary",
            "params":{"requestId":request,"loaderId":loader,"frameId":"frame-flat-primary","type":"Document"}
        })).await;
    }
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame-flat-primary",
            "new-loader",
            "https://example.test/new",
        ),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !wait.is_finished(),
        "commit must preserve the still-running new document request"
    );
    write_message(
        &mut page.writer,
        network_event("flat-primary", "Network.loadingFinished", "new-document"),
    )
    .await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .unwrap()
            .unwrap(),
        succeeded()
    );
    assert!(!page.manager.is_tainted());
}
