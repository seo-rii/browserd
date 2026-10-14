use super::*;

#[tokio::test]
async fn review_health_progresses_while_a_page_command_is_pending() {
    let mut page = owned_page().await;
    let action = spawn_action(
        &page,
        br#"{"type":"wait_for","condition":{"type":"load_state","state":"load"}}"#,
        Some(Instant::now() + Duration::from_secs(3)),
    );
    let pending = read_command(&mut page.reader).await;
    assert_eq!(pending["method"], "Runtime.evaluate");
    let health = tokio::task::spawn_blocking({
        let driver = page.driver.clone();
        move || driver.qualify()
    });
    tokio::time::timeout(
        Duration::from_millis(250),
        qualify(&mut page.reader, &mut page.writer),
    )
    .await
    .expect("a pending page command must not delay the independent health command");
    assert_eq!(health.await.unwrap(), Ok(()));
    assert!(!action.is_finished());
    respond(
        &mut page.writer,
        &pending,
        json!({"result":{"type":"boolean","value":true}}),
    )
    .await;
    assert_eq!(action.await.unwrap(), succeeded());
    assert!(!page.drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn review_auto_dismiss_handles_each_dialog_during_a_pending_page_command() {
    for (kind, accept) in [
        ("alert", true),
        ("confirm", false),
        ("prompt", false),
        ("beforeunload", false),
    ] {
        let mut page = owned_page_with_options(true).await;
        let action = spawn_action(
            &page,
            br#"{"type":"wait_for","condition":{"type":"load_state","state":"load"}}"#,
            Some(Instant::now() + Duration::from_secs(3)),
        );
        let pending = read_command(&mut page.reader).await;
        assert_eq!(pending["method"], "Runtime.evaluate");
        write_message(&mut page.writer, json!({
            "method":"Page.javascriptDialogOpening", "sessionId":"flat-options-primary",
            "params":{"type":kind,"message":"boundary test","url":"https://example.test/","hasBrowserHandler":false}
        })).await;
        let handled =
            tokio::time::timeout(Duration::from_millis(250), read_command(&mut page.reader))
                .await
                .expect("dialog policy must run while the renderer command is blocked");
        assert_eq!(handled["method"], "Page.handleJavaScriptDialog");
        assert_eq!(handled["sessionId"], "flat-options-primary");
        assert_eq!(handled["params"]["accept"], accept);
        respond(&mut page.writer, &handled, json!({})).await;
        respond(
            &mut page.writer,
            &pending,
            json!({"result":{"type":"boolean","value":true}}),
        )
        .await;
        assert_eq!(action.await.unwrap(), succeeded());
        assert!(!page.manager.is_tainted());
    }
}

#[tokio::test]
async fn review_shutdown_cancels_pending_page_and_health_without_waiting_for_renderer() {
    let mut page = owned_page().await;
    let action = spawn_action(
        &page,
        br#"{"type":"wait_for","condition":{"type":"load_state","state":"load"}}"#,
        Some(Instant::now() + Duration::from_secs(3)),
    );
    let pending = read_command(&mut page.reader).await;
    assert_eq!(pending["method"], "Runtime.evaluate");
    let health = tokio::task::spawn_blocking({
        let driver = page.driver.clone();
        move || driver.qualify()
    });
    let health_command =
        tokio::time::timeout(Duration::from_millis(250), read_command(&mut page.reader))
            .await
            .unwrap();
    assert_eq!(health_command["method"], "Browser.getVersion");
    let _closed = page
        ._owner
        .shutdown_and_join(Duration::from_millis(250))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), health)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(250), action)
            .await
            .unwrap()
            .unwrap(),
        ActionExecutionResult::OutcomeUnknown
    );
}
