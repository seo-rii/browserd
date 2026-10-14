use super::*;

#[tokio::test]
async fn query_navigation_before_last_dom_reply_is_known_and_next_document_read_works() {
    let mut page = owned_page().await;
    let query = spawn_action(&page, br#"{"type":"query_all","selector":"a.link"}"#, None);
    let document = read_command(&mut page.reader).await;
    assert_eq!(document["method"], "DOM.getDocument");
    respond(&mut page.writer, &document, json!({"root":{"nodeId":1}})).await;
    let search = read_command(&mut page.reader).await;
    assert_eq!(search["method"], "DOM.querySelectorAll");
    respond(&mut page.writer, &search, json!({"nodeIds":[2,3]})).await;
    let first = read_command(&mut page.reader).await;
    assert_eq!(first["method"], "DOM.describeNode");
    respond(
        &mut page.writer,
        &first,
        json!({"node":{"backendNodeId":100}}),
    )
    .await;
    let last = read_command(&mut page.reader).await;
    assert_eq!(last["method"], "DOM.describeNode");
    assert_eq!(last["params"]["nodeId"], 3);
    write_message(
        &mut page.writer,
        frame_navigated(
            "flat-primary",
            "frame-flat-primary",
            "replacement-document",
            "https://example.test/replacement",
        ),
    )
    .await;
    respond(
        &mut page.writer,
        &last,
        json!({"node":{"backendNodeId":101}}),
    )
    .await;

    // Neither an earlier match nor the late reply may escape as an opaque ref.
    assert_eq!(
        query.await.unwrap(),
        ActionExecutionResult::FailedKnown("document_changed".to_owned())
    );
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());

    let fresh = mint_node(&mut page, 900).await;
    let read = spawn_action_owned(
        &page,
        serde_json::to_vec(&json!({"type":"get_text","node_ref":fresh})).unwrap(),
        None,
    );
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    assert_eq!(resolve["params"]["backendNodeId"], 900);
    respond(
        &mut page.writer,
        &resolve,
        json!({"object":{"objectId":"fresh-document-node"}}),
    )
    .await;
    let value = read_command(&mut page.reader).await;
    assert_eq!(value["method"], "Runtime.callFunctionOn");
    respond(
        &mut page.writer,
        &value,
        json!({"result":{"value":"fresh document"}}),
    )
    .await;
    let release = read_command(&mut page.reader).await;
    assert_eq!(release["method"], "Runtime.releaseObject");
    respond(&mut page.writer, &release, json!({})).await;
    let result: Value = serde_json::from_slice(&succeeded_bytes(read.await.unwrap())).unwrap();
    assert_eq!(result["text"], "fresh document");
    assert!(!page.drain.0.load(Ordering::SeqCst));
    assert!(!page.manager.is_tainted());
}
