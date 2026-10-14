use super::*;
use browserd_policy::ApprovalContextScope;
use browserd_worker::{TypedApprovalObservation, WorkerActionCommand};

fn inspect(
    page: &OwnedPage,
    action: WorkerActionCommand,
    context: bool,
) -> tokio::task::JoinHandle<Result<TypedApprovalObservation, ApprovedActionError>> {
    let (driver, tenant, session, page_id) = (
        page.driver.clone(),
        page.tenant_id.clone(),
        page.session_id.clone(),
        page.page_id.clone(),
    );
    tokio::task::spawn_blocking(move || {
        driver.inspect_typed_approval_until(
            &tenant,
            &session,
            (!context).then_some(&page_id),
            &ownership_fence(),
            &action,
            Instant::now() + Duration::from_secs(3),
        )
    })
}

async fn origin(page: &mut OwnedPage, flat: &str, security_origin: &str) {
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Page.getFrameTree");
    assert_eq!(command["sessionId"], flat);
    respond(&mut page.writer,&command,json!({"frameTree":{"frame":{"id":format!("frame-{flat}"),"url":format!("{security_origin}/form"),"securityOrigin":security_origin}}})).await;
}

async fn node_observation(page: &mut OwnedPage, flat: &str, security_origin: &str, backend: u64) {
    origin(page, flat, security_origin).await;
    let describe = read_command(&mut page.reader).await;
    assert_eq!(describe["method"], "DOM.describeNode");
    assert_eq!(describe["params"]["backendNodeId"], backend);
    respond(&mut page.writer,&describe,json!({"node":{"backendNodeId":backend,"attributes":["role","textbox","aria-label","계정 입력","value","never-an-approval-hint"]}})).await;
    for (method, result) in [
        (
            "DOM.resolveNode",
            json!({"object":{"objectId":"observed-node"}}),
        ),
        ("Runtime.callFunctionOn", json!({"result":{"value":true}})),
        ("Runtime.releaseObject", json!({})),
    ] {
        let command = read_command(&mut page.reader).await;
        assert_eq!(command["method"], method);
        assert_eq!(command["sessionId"], flat);
        if method == "Runtime.callFunctionOn" {
            assert_eq!(
                command["params"]["uniqueContextId"],
                format!("realm-{flat}")
            );
        }
        respond(&mut page.writer, &command, result).await;
    }
}

/// A real event-first health round trip acknowledges that the injected events
/// reached the actor before the test starts a subsequent guarded observation.
async fn frame_event_barrier(page: &mut OwnedPage, events: &[Value]) {
    let health = tokio::task::spawn_blocking({
        let driver = page.driver.clone();
        move || driver.qualify()
    });
    let command = read_command(&mut page.reader).await;
    assert_eq!(command["method"], "Browser.getVersion");
    let response = json!({"id":command["id"],"result":{"protocolVersion":"1.3","product":"HeadlessChrome/149.0.7827.55","revision":"r1234567","userAgent":"browserd-test","jsVersion":"14.9"}});
    let mut messages = Vec::new();
    for message in events.iter().chain(std::iter::once(&response)) {
        messages.extend(serde_json::to_vec(message).unwrap());
        messages.push(0);
    }
    page.writer.write_all(&messages).await.unwrap();
    assert_eq!(health.await.unwrap(), Ok(()));
}

fn execute(
    page: &OwnedPage,
    expected: TypedApprovalObservation,
    payload: Vec<u8>,
    mut callback: impl FnMut(&TypedApprovalObservation) -> Result<(), ApprovedActionError>
    + Send
    + 'static,
) -> tokio::task::JoinHandle<Result<ActionExecutionResult, ApprovedActionError>> {
    let driver = page.driver.clone();
    tokio::task::spawn_blocking(move || {
        driver.execute_typed_browser_until(
            &expected,
            &payload,
            Instant::now() + Duration::from_secs(3),
            &mut callback,
        )
    })
}

#[tokio::test]
async fn typed_context_checkpoint_needs_no_fake_origin_and_denial_reads_no_cookies() {
    let mut page = owned_page().await;
    let expected = inspect(
        &page,
        WorkerActionCommand::Checkpoint { origins: vec![] },
        true,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(expected.context_scope, ApprovalContextScope::BrowserContext);
    assert_eq!(expected.live.current_origin.as_str(), "browserd:context");
    assert!(expected.page_id.is_none());
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    let driver = page.driver.clone();
    let denied = tokio::task::spawn_blocking(move || {
        driver.capture_typed_checkpoint_until(
            &expected,
            &[],
            Instant::now() + Duration::from_secs(2),
            &mut |_| Err(ApprovedActionError::DispatchRevoked),
        )
    })
    .await
    .unwrap();
    assert!(matches!(denied, Err(ApprovedActionError::DispatchRevoked)));
    assert!(has_no_command_bytes(&mut page.reader, false).await);
    assert!(!page.manager.is_tainted());
}

#[tokio::test]
async fn typed_browser_callback_denial_and_wrong_full_fence_dispatch_nothing() {
    let mut page = owned_page().await;
    let pending = inspect(&page, WorkerActionCommand::GetTitle, false);
    origin(&mut page, "flat-primary", "https://owned.test:8443").await;
    let expected = pending.await.unwrap().unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let denied = execute(
        &page,
        expected.clone(),
        br#"{"type":"get_title"}"#.to_vec(),
        {
            let called = called.clone();
            move |live| {
                assert_eq!(live.live.current_origin.as_str(), "https://owned.test:8443");
                called.store(true, Ordering::SeqCst);
                Err(ApprovedActionError::DispatchRevoked)
            }
        },
    );
    origin(&mut page, "flat-primary", "https://owned.test:8443").await;
    assert_eq!(
        denied.await.unwrap(),
        Err(ApprovedActionError::DispatchRevoked)
    );
    assert!(called.load(Ordering::SeqCst));
    let mut foreign = expected;
    foreign.fence = OwnershipFence::new(ownership_fence().worker_id().clone(), 17, 24, 29);
    called.store(false, Ordering::SeqCst);
    let rejected = execute(&page, foreign, br#"{"type":"get_title"}"#.to_vec(), {
        let called = called.clone();
        move |_| {
            called.store(true, Ordering::SeqCst);
            Ok(())
        }
    })
    .await
    .unwrap();
    assert_eq!(rejected, Err(ApprovedActionError::DispatchRevoked));
    assert!(!called.load(Ordering::SeqCst));
    assert!(has_no_command_bytes(&mut page.reader, false).await);
}

#[tokio::test]
async fn typed_child_observation_binds_leaf_origin_hints_and_ancestor_epoch() {
    let mut page = owned_page().await;
    attach_owned_oopif(&mut page).await;
    let node = mint_oopif_node(&mut page).await;
    let pending = inspect(
        &page,
        WorkerActionCommand::Fill {
            node_ref: node.clone(),
            value: "prepared".to_owned(),
        },
        false,
    );
    node_observation(&mut page, "flat-child", "https://child.test:8444", 500).await;
    let expected = pending.await.unwrap().unwrap();
    let binding = expected.node_binding.as_ref().unwrap();
    assert_eq!(binding.node_ref, node);
    assert_eq!(binding.role.as_deref(), Some("textbox"));
    assert_eq!(binding.name.as_deref(), Some("계정 입력"));
    assert_eq!(
        expected.live.current_origin.as_str(),
        "https://child.test:8444"
    );
    assert_ne!(binding.binding_sha256, [0; 32]);
    let called = Arc::new(AtomicBool::new(false));
    let denied = execute(
        &page,
        expected.clone(),
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"prepared"})).unwrap(),
        {
            let called = called.clone();
            move |_| {
                called.store(true, Ordering::SeqCst);
                Err(ApprovedActionError::DispatchRevoked)
            }
        },
    );
    node_observation(&mut page, "flat-child", "https://child.test:8444", 500).await;
    assert_eq!(
        denied.await.unwrap(),
        Err(ApprovedActionError::DispatchRevoked)
    );
    assert!(called.load(Ordering::SeqCst));
    frame_event_barrier(&mut page, &[
        frame_navigated("flat-primary", "frame-flat-primary", "new-parent", "https://parent.test/replaced"),
        json!({"method":"Runtime.executionContextCreated","sessionId":"flat-primary","params":{"context":{"id":1,"uniqueId":"new-parent-realm","auxData":{"isDefault":true,"frameId":"frame-flat-primary"}}}}),
    ]).await;
    called.store(false, Ordering::SeqCst);
    let stale = execute(
        &page,
        expected,
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"prepared"})).unwrap(),
        {
            let called = called.clone();
            move |_| {
                called.store(true, Ordering::SeqCst);
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(stale, Err(ApprovedActionError::DispatchRevoked));
    assert!(!called.load(Ordering::SeqCst));
    assert!(has_no_command_bytes(&mut page.reader, false).await);
}

#[tokio::test]
async fn typed_approval_consumed_before_realm_aba_never_dispatches_into_replacement() {
    let mut page = owned_page().await;
    let pending = inspect(&page, WorkerActionCommand::GetTitle, false);
    origin(&mut page, "flat-primary", "https://owned.test").await;
    let expected = pending.await.unwrap().unwrap();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(1);
    let action = execute(
        &page,
        expected,
        br#"{"type":"get_title"}"#.to_vec(),
        move |_| {
            entered_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            Ok(())
        },
    );
    origin(&mut page, "flat-primary", "https://owned.test").await;
    entered_rx.recv().await.unwrap();
    // Keep admission paused until both halves of the numeric-ID ABA are observed.
    frame_event_barrier(&mut page, &[
        json!({"method":"Runtime.executionContextsCleared","sessionId":"flat-primary","params":{}}),
        json!({"method":"Runtime.executionContextCreated","sessionId":"flat-primary","params":{"context":{"id":1,"uniqueId":"replacement-realm","auxData":{"isDefault":true,"frameId":"frame-flat-primary"}}}}),
    ]).await;
    resume_tx.send(()).unwrap();
    // Re-observation may read trusted frame metadata, but no Runtime effect is allowed.
    origin(&mut page, "flat-primary", "https://owned.test").await;
    assert_eq!(
        action.await.unwrap(),
        Ok(ActionExecutionResult::OutcomeUnknown)
    );
    assert!(has_no_command_bytes(&mut page.reader, false).await);
}

#[tokio::test]
async fn typed_child_same_document_ancestor_drift_after_commit_is_unknown_before_mutation() {
    let mut page = owned_page().await;
    attach_owned_oopif(&mut page).await;
    let node = mint_oopif_node(&mut page).await;
    let pending = inspect(
        &page,
        WorkerActionCommand::Fill {
            node_ref: node.clone(),
            value: "owned".into(),
        },
        false,
    );
    node_observation(&mut page, "flat-child", "https://child.test", 500).await;
    let expected = pending.await.unwrap().unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let action = execute(
        &page,
        expected,
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"owned"})).unwrap(),
        {
            let called = called.clone();
            move |_| {
                called.store(true, Ordering::SeqCst);
                Ok(())
            }
        },
    );
    node_observation(&mut page, "flat-child", "https://child.test", 500).await;
    node_observation(&mut page, "flat-child", "https://child.test", 500).await;
    assert!(called.load(Ordering::SeqCst));
    let resolve = read_command(&mut page.reader).await;
    assert_eq!(resolve["method"], "DOM.resolveNode");
    let mut messages=serde_json::to_vec(&json!({"method":"Page.navigatedWithinDocument","sessionId":"flat-primary","params":{"frameId":"frame-flat-primary","url":"https://parent.test/#changed"}})).unwrap();
    messages.push(0);
    messages.extend(
        serde_json::to_vec(
            &json!({"id":resolve["id"],"result":{"object":{"objectId":"effect-node"}}}),
        )
        .unwrap(),
    );
    messages.push(0);
    page.writer.write_all(&messages).await.unwrap();
    assert_eq!(
        action.await.unwrap(),
        Ok(ActionExecutionResult::OutcomeUnknown)
    );
    assert!(has_no_command_bytes(&mut page.reader, true).await);
}

#[tokio::test]
async fn legacy_manual_child_proposal_observes_trusted_leaf_and_denies_before_effect() {
    let mut page = owned_page().await;
    attach_owned_oopif(&mut page).await;
    let node = mint_oopif_node(&mut page).await;
    let payload =
        serde_json::to_vec(&json!({"type":"fill","node_ref":node,"value":"owned"})).unwrap();
    let proposal = browserd_policy::CanonicalActionProposal::new(
        page.tenant_id.clone(),
        browserd_core::PrincipalId::new(),
        page.session_id.clone(),
        ownership_fence().session_incarnation(),
        page.page_id.clone(),
        1,
        1,
        browserd_policy::Origin::parse("https://child.test").unwrap(),
        1,
        browserd_policy::ActionType::Fill,
        browserd_policy::ActionArgumentsHash::digest(&payload),
        Some(browserd_policy::NodeReference::new(node).unwrap()),
        browserd_policy::CredentialRefsHash::digest(std::iter::empty::<&str>()),
        u64::MAX,
    );
    let pending = tokio::task::spawn_blocking({
        let driver = page.driver.clone();
        let session = page.session_id.clone();
        let id = page.page_id.clone();
        let proposal = proposal.clone();
        move || driver.inspect_approval_context(&session, &id, &proposal)
    });
    node_observation(&mut page, "flat-child", "https://child.test", 500).await;
    let observed = pending.await.unwrap().unwrap();
    assert_eq!(observed.current_origin.as_str(), "https://child.test");
    let action = tokio::task::spawn_blocking({
        let driver = page.driver.clone();
        let session = page.session_id.clone();
        let id = page.page_id.clone();
        move || {
            driver.execute_approved_action_until(
                &session,
                &id,
                &payload,
                &proposal,
                &observed,
                Instant::now() + Duration::from_secs(3),
                &mut |_| Err(ApprovedActionError::DispatchRevoked),
            )
        }
    });
    node_observation(&mut page, "flat-child", "https://child.test", 500).await;
    assert_eq!(
        action.await.unwrap(),
        Err(ApprovedActionError::DispatchRevoked)
    );
    assert!(has_no_command_bytes(&mut page.reader, false).await);
}
