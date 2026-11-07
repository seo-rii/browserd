#![allow(clippy::expect_used)]
use browserd_actions::{
    ActionKind, BrowserResult, CanonicalRequestHash, DispatchId, JournalSessionScope,
    KnownFailureReason, OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind, ResultDigest,
    TerminalCustodyReceipt, TerminalDetail,
};
use browserd_coordination::{
    ClaimGatewayAction, DirectoryFence, GatewayActionCoordination,
    GatewayActionCoordinationError as Error, GatewayActionPlacement, GatewayActionRecoveryCursor,
    GatewayActionSnapshot, GatewayCustodyCursor, GatewayPendingCustody,
};
use browserd_core::{
    ActionId, NotificationSourceFamily, NotificationSourceScope, PlacementFence, PrincipalId,
    SessionId, TenantId, WorkerId,
};
use chrono::Utc;

pub struct Action {
    pub tenant: TenantId,
    pub session: SessionId,
    pub action: ActionId,
    pub placement: GatewayActionPlacement,
    pub dispatch: DispatchId,
    pub armed: GatewayActionSnapshot,
}
impl Action {
    pub async fn new(store: &dyn GatewayActionCoordination) -> Self {
        let tenant = TenantId::new();
        let session = SessionId::new();
        let action = ActionId::new();
        let placement = GatewayActionPlacement::new(
            DirectoryFence::new(WorkerId::new("custody-worker").expect("worker"), 7, 11, 13)
                .expect("fence"),
            17,
        )
        .expect("placement");
        let claim = ClaimGatewayAction::new(
            tenant.clone(),
            session.clone(),
            action.clone(),
            "original-key",
            CanonicalRequestHash::new([1; 32]),
            ActionKind::Mutating,
            placement.clone(),
        )
        .expect("claim");
        let accepted = store
            .claim_action(claim, Utc::now())
            .await
            .expect("claim accepted")
            .into_snapshot();
        let dispatch = DispatchId::new();
        let armed = store
            .arm_dispatch(
                &tenant,
                &session,
                &action,
                accepted.revision(),
                &placement,
                dispatch.clone(),
                Utc::now(),
            )
            .await
            .expect("armed");
        Self {
            tenant,
            session,
            action,
            placement,
            dispatch,
            armed,
        }
    }
    pub fn receipt(
        &self,
        detail: TerminalDetail,
        resolution: Option<ResolutionAnnotation>,
    ) -> TerminalCustodyReceipt {
        TerminalCustodyReceipt::new(
            JournalSessionScope::new(
                self.tenant.clone(),
                self.session.clone(),
                self.placement.directory_fence().worker_id().clone(),
                PlacementFence::new(7, 11, 13),
            )
            .expect("scope"),
            self.action.clone(),
            self.armed.action_sequence(),
            ActionKind::Mutating,
            CanonicalRequestHash::new([99; 32]),
            Some(DispatchId::new()),
            detail,
            resolution,
        )
        .expect("receipt")
    }
    pub async fn terminal(
        &self,
        store: &dyn GatewayActionCoordination,
        receipt: TerminalCustodyReceipt,
        expected: u64,
    ) -> Result<GatewayActionSnapshot, Error> {
        store
            .record_worker_terminal_with_custody(
                &self.tenant,
                &self.session,
                &self.action,
                expected,
                &self.placement,
                &self.dispatch,
                self.armed.action_sequence(),
                receipt.terminal(),
                Some(receipt),
                None,
                Utc::now(),
            )
            .await
    }
    pub async fn events(&self, store: &dyn GatewayActionCoordination) -> Vec<u64> {
        let mut events = Vec::new();
        while let Some(event) = store
            .peek_event_projection(&self.tenant, &self.session)
            .await
            .expect("peek")
        {
            assert!(events.len() < 8, "bounded event history");
            events.push(event.append().aggregate_revision());
            store.ack_event_projection(&event).await.expect("event ack");
        }
        events
    }
}
fn resolution() -> ResolutionAnnotation {
    ResolutionAnnotation::new(
        ResolutionKind::ConfirmedExecuted,
        PrincipalId::new(),
        42,
        "operator inspected target",
    )
}
fn unknown() -> TerminalDetail {
    TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch)
}
fn resolved_copy(
    receipt: &TerminalCustodyReceipt,
    annotation: ResolutionAnnotation,
) -> TerminalCustodyReceipt {
    TerminalCustodyReceipt::new(
        receipt.scope().clone(),
        receipt.action_id().clone(),
        receipt.action_sequence(),
        receipt.kind(),
        receipt.request_hash(),
        receipt.dispatch_id().cloned(),
        receipt.terminal(),
        Some(annotation),
    )
    .expect("resolved receipt")
}

pub async fn release_entry(
    store: &dyn GatewayActionCoordination,
    copy: &GatewayPendingCustody,
) -> GatewayPendingCustody {
    assert!(!copy.is_release());
    let page = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 256)
        .await
        .expect("release discovery");
    let release = page
        .entries()
        .iter()
        .find(|entry| entry.receipt() == copy.receipt())
        .expect("release remains indexed")
        .clone();
    assert!(release.is_release());
    assert_eq!(release.action_revision(), copy.action_revision());
    assert_eq!(
        store.complete_custody_release(copy, Utc::now()).await,
        Err(Error::CustodyAckConflict)
    );
    store
        .complete_custody_release(&release, Utc::now())
        .await
        .expect("release completed");
    store
        .complete_custody_release(&release, Utc::now())
        .await
        .expect("lost release response retry");
    release
}

pub async fn terminal_commit_and_ack_are_independent_and_idempotent(
    store: &dyn GatewayActionCoordination,
) {
    let action = Action::new(store).await;
    let bytes = b"durable-result".to_vec();
    let digest = ResultDigest::new([19; 32]);
    let receipt = action.receipt(TerminalDetail::Succeeded(digest), None);
    let terminal = store
        .record_worker_result_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            action.armed.revision(),
            &action.placement,
            &action.dispatch,
            action.armed.action_sequence(),
            BrowserResult::Succeeded(digest),
            Some(bytes.clone()),
            Some(receipt.clone()),
            None,
            Utc::now(),
        )
        .await
        .expect("atomic result");
    assert_eq!(terminal.result_content(), Some(bytes.as_slice()));
    let page = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("custody");
    let entry = &page.entries()[0];
    assert_eq!(entry.receipt(), &receipt);
    assert_eq!(entry.action_revision(), terminal.revision());
    assert_eq!(
        action
            .terminal(store, receipt.clone(), action.armed.revision())
            .await
            .expect("lost response retry"),
        terminal
    );
    store
        .ack_pending_custody(entry, Utc::now())
        .await
        .expect("ack while source event still pending");
    store
        .ack_pending_custody(entry, Utc::now())
        .await
        .expect("lost ack response retry");
    release_entry(store, entry).await;
    let retried = action
        .terminal(store, receipt, action.armed.revision())
        .await
        .expect("late terminal retry");
    assert_eq!(retried.revision(), terminal.revision());
    assert_eq!(retried.terminal(), terminal.terminal());
    assert_eq!(retried.result_content(), terminal.result_content());
    assert!(
        store
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("scan")
            .entries()
            .is_empty()
    );
    assert_eq!(action.events(store).await, vec![terminal.revision()]);
}

pub async fn invalid_receipt_preserves_pending_action_and_source_journal(
    store: &dyn GatewayActionCoordination,
) {
    let action = Action::new(store).await;
    let receipt = action.receipt(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        None,
    );
    let foreign = TerminalCustodyReceipt::new(
        JournalSessionScope::new(
            TenantId::new(),
            action.session.clone(),
            receipt.original_worker_id().clone(),
            receipt.fence(),
        )
        .expect("scope"),
        action.action.clone(),
        receipt.action_sequence(),
        receipt.kind(),
        receipt.request_hash(),
        receipt.dispatch_id().cloned(),
        receipt.terminal(),
        None,
    )
    .expect("foreign");
    assert_eq!(
        action
            .terminal(store, foreign, action.armed.revision())
            .await,
        Err(Error::InvalidCustodyReceipt)
    );
    let wrong_fence = TerminalCustodyReceipt::new(
        JournalSessionScope::new(
            action.tenant.clone(),
            action.session.clone(),
            receipt.original_worker_id().clone(),
            PlacementFence::new(8, 11, 13),
        )
        .expect("scope"),
        action.action.clone(),
        receipt.action_sequence(),
        receipt.kind(),
        receipt.request_hash(),
        receipt.dispatch_id().cloned(),
        receipt.terminal(),
        None,
    )
    .expect("wrong fence");
    assert_eq!(
        action
            .terminal(store, wrong_fence, action.armed.revision())
            .await,
        Err(Error::InvalidCustodyReceipt)
    );
    assert!(action.events(store).await.is_empty());
    assert!(
        store
            .get_effective_action(&action.tenant, &action.session, &action.action)
            .await
            .expect("get")
            .expect("action")
            .terminal()
            .is_none()
    );
    assert_eq!(
        store
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
            .await
            .expect("pending")
            .actions()
            .len(),
        1
    );
    assert!(
        store
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("custody")
            .entries()
            .is_empty()
    );
    action
        .terminal(store, receipt, action.armed.revision())
        .await
        .expect("valid receipt succeeds");
}

pub async fn resolution_supersedes_exact_pending_receipt_and_rejects_old_ack(
    store: &dyn GatewayActionCoordination,
) {
    let action = Action::new(store).await;
    let receipt = action.receipt(unknown(), None);
    let terminal = action
        .terminal(store, receipt.clone(), action.armed.revision())
        .await
        .expect("unknown");
    let old = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("scan")
        .entries()[0]
        .clone();
    store
        .ack_pending_custody(&old, Utc::now())
        .await
        .expect("copy acknowledged before competing resolution");
    let old_release = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("release")
        .entries()[0]
        .clone();
    assert!(old_release.is_release());
    let annotation = resolution();
    let resolved = resolved_copy(&receipt, annotation.clone());
    let snapshot = store
        .resolve_unknown_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            terminal.revision(),
            &action.placement,
            annotation.clone(),
            Some(resolved.clone()),
            None,
            Utc::now(),
        )
        .await
        .expect("atomic resolution");
    assert_eq!(snapshot.resolution(), Some(&annotation));
    assert_eq!(
        store.ack_pending_custody(&old, Utc::now()).await,
        Err(Error::CustodyAckConflict)
    );
    assert_eq!(
        store
            .complete_custody_release(&old_release, Utc::now())
            .await,
        Err(Error::CustodyAckConflict)
    );
    let current = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("scan")
        .entries()[0]
        .clone();
    assert_eq!(current.receipt(), &resolved);
    assert_eq!(current.action_revision(), snapshot.revision());
    store
        .ack_pending_custody(&current, Utc::now())
        .await
        .expect("new receipt ack");
    release_entry(store, &current).await;
    assert_eq!(
        store.ack_pending_custody(&old, Utc::now()).await,
        Err(Error::CustodyAckConflict)
    );
    assert_eq!(
        action.events(store).await,
        vec![terminal.revision(), snapshot.revision()]
    );
}

pub async fn already_resolved_worker_receipt_commits_two_events_atomically(
    store: &dyn GatewayActionCoordination,
) {
    let action = Action::new(store).await;
    let annotation = resolution();
    let receipt = action.receipt(unknown(), Some(annotation.clone()));
    let snapshot = action
        .terminal(store, receipt.clone(), action.armed.revision())
        .await
        .expect("already resolved worker");
    assert_eq!(snapshot.revision(), action.armed.revision() + 2);
    assert_eq!(snapshot.resolution(), Some(&annotation));
    assert_eq!(
        action
            .terminal(store, receipt.clone(), action.armed.revision())
            .await
            .expect("lost response"),
        snapshot
    );
    assert!(
        store
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
            .await
            .expect("scan")
            .actions()
            .is_empty()
    );
    assert_eq!(
        action.events(store).await,
        vec![snapshot.revision() - 1, snapshot.revision()]
    );
    let page = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("custody");
    assert_eq!(page.entries()[0].receipt(), &receipt);
    // The reconciliation lane is released by the same commit.
    let next = ClaimGatewayAction::new(
        action.tenant,
        action.session,
        ActionId::new(),
        "next",
        CanonicalRequestHash::new([2; 32]),
        ActionKind::Mutating,
        action.placement,
    )
    .expect("claim");
    store
        .claim_action(next, Utc::now())
        .await
        .expect("resolved lane admits next action");
}

pub async fn existing_unknown_adopts_worker_resolution_without_overwriting_winner(
    store: &dyn GatewayActionCoordination,
) {
    let action = Action::new(store).await;
    let receipt = action.receipt(unknown(), None);
    let terminal = action
        .terminal(store, receipt.clone(), action.armed.revision())
        .await
        .expect("unknown");
    let annotation = resolution();
    let resolved = resolved_copy(&receipt, annotation.clone());
    let snapshot = action
        .terminal(store, resolved.clone(), terminal.revision())
        .await
        .expect("adopt annotation");
    assert_eq!(snapshot.revision(), terminal.revision() + 1);
    let different = resolved_copy(
        &receipt,
        ResolutionAnnotation::new(
            ResolutionKind::Abandoned,
            PrincipalId::new(),
            43,
            "different operator decision",
        ),
    );
    assert_eq!(
        action.terminal(store, different, snapshot.revision()).await,
        Err(Error::ResolutionConflict)
    );
    assert_eq!(
        store
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("scan")
            .entries()[0]
            .receipt(),
        &resolved
    );
    assert_eq!(
        action.events(store).await,
        vec![terminal.revision(), snapshot.revision()]
    );
}

pub async fn bounded_cursor_and_late_receipt_attachment(store: &dyn GatewayActionCoordination) {
    let first = Action::new(store).await;
    let second = Action::new(store).await;
    for action in [&first, &second] {
        let receipt = action.receipt(
            TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
            None,
        );
        let terminal = store
            .record_worker_terminal(
                &action.tenant,
                &action.session,
                &action.action,
                action.armed.revision(),
                &action.placement,
                &action.dispatch,
                action.armed.action_sequence(),
                receipt.terminal(),
                Utc::now(),
            )
            .await
            .expect("legacy terminal");
        let copied = action
            .terminal(store, receipt, terminal.revision())
            .await
            .expect("late custody attachment");
        assert_eq!(copied.revision(), terminal.revision());
        assert_eq!(action.events(store).await, vec![terminal.revision()]);
    }
    for limit in [0, 257] {
        assert!(matches!(
            store
                .scan_pending_custody(GatewayCustodyCursor::default(), limit)
                .await,
            Err(Error::InvalidCustodyScanLimit)
        ));
    }
    let first_page = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("first");
    assert_eq!(first_page.entries().len(), 1);
    assert!(!first_page.is_complete());
    store
        .ack_pending_custody(&first_page.entries()[0], Utc::now())
        .await
        .expect("ack");
    let second_page = store
        .scan_pending_custody(first_page.next_cursor().clone(), 1)
        .await
        .expect("next");
    assert_eq!(second_page.entries().len(), 1);
    assert_ne!(
        first_page.entries()[0].receipt().action_id(),
        second_page.entries()[0].receipt().action_id()
    );
    let last = store
        .scan_pending_custody(second_page.next_cursor().clone(), 1)
        .await
        .expect("end");
    assert!(last.entries().is_empty());
    assert!(last.is_complete());
}

pub async fn gateway_only_resolution_preserves_historical_ack_without_new_obligation(
    store: &dyn GatewayActionCoordination,
) {
    let action = Action::new(store).await;
    let receipt = action.receipt(unknown(), None);
    let terminal = action
        .terminal(store, receipt, action.armed.revision())
        .await
        .expect("terminal");
    let old = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("scan")
        .entries()[0]
        .clone();
    store
        .ack_pending_custody(&old, Utc::now())
        .await
        .expect("old transferred");
    release_entry(store, &old).await;
    let annotation = resolution();
    let snapshot = store
        .resolve_unknown_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            terminal.revision(),
            &action.placement,
            annotation.clone(),
            None,
            None,
            Utc::now(),
        )
        .await
        .expect("worker NotFound fallback");
    assert_eq!(
        store
            .get_effective_action(&action.tenant, &action.session, &action.action)
            .await
            .expect("persisted historical proof remains valid"),
        Some(snapshot)
    );
    store
        .ack_pending_custody(&old, Utc::now())
        .await
        .expect("old exact ack retry");
    assert!(
        store
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("scan")
            .entries()
            .is_empty()
    );
}

pub async fn conflicting_winner_never_transfers_custody(store: &dyn GatewayActionCoordination) {
    let action = Action::new(store).await;
    store
        .record_transport_loss(
            &action.tenant,
            &action.session,
            &action.action,
            action.armed.revision(),
            &action.placement,
            &action.dispatch,
            browserd_actions::TransportLoss::Ambiguous(
                OutcomeUnknownReason::AmbiguousTransportLoss,
            ),
            Utc::now(),
        )
        .await
        .expect("durable transport winner");
    let current = store
        .get_effective_action(&action.tenant, &action.session, &action.action)
        .await
        .expect("get")
        .expect("winner");
    let receipt = action.receipt(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        None,
    );
    assert!(
        action
            .terminal(store, receipt, current.revision())
            .await
            .is_err()
    );
    assert!(
        store
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("scan")
            .entries()
            .is_empty()
    );
    assert_eq!(
        store
            .get_effective_action(&action.tenant, &action.session, &action.action)
            .await
            .expect("get"),
        Some(current.clone())
    );
    assert_eq!(action.events(store).await, vec![current.revision()]);
}

pub async fn custody_reserves_bounded_session_capacity_until_ack(
    store: &dyn GatewayActionCoordination,
) {
    let scope = Action::new(store).await;
    let receipt = scope.receipt(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        None,
    );
    scope
        .terminal(store, receipt, scope.armed.revision())
        .await
        .expect("first custody");
    for index in 1..256 {
        let action = ActionId::new();
        let claim = ClaimGatewayAction::new(
            scope.tenant.clone(),
            scope.session.clone(),
            action.clone(),
            format!("bounded-{index}"),
            CanonicalRequestHash::new([8; 32]),
            ActionKind::ReadOnly,
            scope.placement.clone(),
        )
        .expect("claim");
        let accepted = store
            .claim_action(claim, Utc::now())
            .await
            .expect("reserved")
            .into_snapshot();
        let dispatch = DispatchId::new();
        let armed = store
            .arm_dispatch(
                &scope.tenant,
                &scope.session,
                &action,
                accepted.revision(),
                &scope.placement,
                dispatch.clone(),
                Utc::now(),
            )
            .await
            .expect("arm");
        let receipt = TerminalCustodyReceipt::new(
            JournalSessionScope::new(
                scope.tenant.clone(),
                scope.session.clone(),
                scope.placement.directory_fence().worker_id().clone(),
                PlacementFence::new(7, 11, 13),
            )
            .expect("scope"),
            action.clone(),
            armed.action_sequence(),
            ActionKind::ReadOnly,
            CanonicalRequestHash::new([9; 32]),
            Some(DispatchId::new()),
            TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
            None,
        )
        .expect("receipt");
        store
            .record_worker_terminal_with_custody(
                &scope.tenant,
                &scope.session,
                &action,
                armed.revision(),
                &scope.placement,
                &dispatch,
                armed.action_sequence(),
                receipt.terminal(),
                Some(receipt),
                None,
                Utc::now(),
            )
            .await
            .expect("reserved terminal cannot overflow custody");
    }
    let claim = ClaimGatewayAction::new(
        scope.tenant.clone(),
        scope.session.clone(),
        ActionId::new(),
        "after-capacity",
        CanonicalRequestHash::new([10; 32]),
        ActionKind::ReadOnly,
        scope.placement.clone(),
    )
    .expect("claim");
    assert_eq!(
        store.claim_action(claim.clone(), Utc::now()).await,
        Err(Error::PendingActionCapacity)
    );
    let page = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 256)
        .await
        .expect("bounded page");
    assert_eq!(page.entries().len(), 256);
    store
        .ack_pending_custody(&page.entries()[0], Utc::now())
        .await
        .expect("release capacity");
    assert_eq!(
        store.claim_action(claim.clone(), Utc::now()).await,
        Err(Error::PendingActionCapacity)
    );
    release_entry(store, &page.entries()[0]).await;
    store
        .claim_action(claim, Utc::now())
        .await
        .expect("one custody slot released");
}

pub struct NotifyingCustody {
    pub action: Action,
    pub snapshot: GatewayActionSnapshot,
    pub copy: GatewayPendingCustody,
    pub legacy_revision: Option<u64>,
}
fn notifying(receipt: TerminalCustodyReceipt) -> TerminalCustodyReceipt {
    let source = NotificationSourceScope::new(
        receipt.tenant_id().clone(),
        receipt.original_worker_id().clone(),
        *receipt.session_id().as_uuid(),
        NotificationSourceFamily::ActionJournal,
    )
    .expect("same original worker journal source");
    receipt
        .with_notification_source(source)
        .expect("durable notification capability")
}
pub async fn notifying_terminal_has_no_legacy_events(
    store: &dyn GatewayActionCoordination,
    already_resolved: bool,
) -> NotifyingCustody {
    let action = Action::new(store).await;
    let annotation = already_resolved.then(resolution);
    let detail = if already_resolved {
        unknown()
    } else {
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected)
    };
    let receipt = notifying(action.receipt(detail, annotation.clone()));
    let snapshot = action
        .terminal(store, receipt.clone(), action.armed.revision())
        .await
        .expect("notification-capable terminal");
    assert_eq!(
        snapshot.revision(),
        action.armed.revision() + if already_resolved { 2 } else { 1 }
    );
    assert_eq!(snapshot.resolution(), annotation.as_ref());
    assert_eq!(snapshot.last_source_event_sequence(), None);
    assert_eq!(snapshot.terminal_outbox_append(), None);
    assert!(
        store
            .peek_event_projection(&action.tenant, &action.session)
            .await
            .expect("no legacy projection")
            .is_none()
    );
    assert_eq!(
        action
            .terminal(store, receipt.clone(), action.armed.revision())
            .await
            .expect("lost commit response exact retry"),
        snapshot
    );
    let page = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 32)
        .await
        .expect("custody");
    assert_eq!(page.entries().len(), 1);
    let copy = page.entries()[0].clone();
    assert_eq!(copy.receipt(), &receipt);
    NotifyingCustody {
        action,
        snapshot,
        copy,
        legacy_revision: None,
    }
}
pub async fn notifying_resolution_preserves_old_legacy_event(
    store: &dyn GatewayActionCoordination,
) -> NotifyingCustody {
    let action = Action::new(store).await;
    let legacy_receipt = action.receipt(unknown(), None);
    let legacy = action
        .terminal(store, legacy_receipt.clone(), action.armed.revision())
        .await
        .expect("pre-capability terminal");
    assert_eq!(legacy.last_source_event_sequence(), Some(1));
    let annotation = resolution();
    let receipt = notifying(resolved_copy(&legacy_receipt, annotation.clone()));
    let snapshot = store
        .resolve_unknown_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            legacy.revision(),
            &action.placement,
            annotation,
            Some(receipt.clone()),
            None,
            Utc::now(),
        )
        .await
        .expect("new notifying resolution");
    assert_eq!(snapshot.revision(), legacy.revision() + 1);
    assert_eq!(snapshot.last_source_event_sequence(), Some(1));
    assert_eq!(snapshot.terminal_outbox_append(), None);
    let pending = store
        .peek_event_projection(&action.tenant, &action.session)
        .await
        .expect("old source still pending")
        .expect("original legacy event");
    assert_eq!(pending.sequence(), 1);
    assert_eq!(pending.append().aggregate_revision(), legacy.revision());
    let page = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 32)
        .await
        .expect("superseding custody");
    assert_eq!(page.entries().len(), 1);
    let copy = page.entries()[0].clone();
    assert_eq!(copy.receipt(), &receipt);
    NotifyingCustody {
        action,
        snapshot,
        copy,
        legacy_revision: Some(legacy.revision()),
    }
}

pub async fn gateway_only_resolution_of_notifying_terminal_emits_its_own_typed_event(
    store: &dyn GatewayActionCoordination,
) -> NotifyingCustody {
    let action = Action::new(store).await;
    let receipt = notifying(action.receipt(unknown(), None));
    let terminal = action
        .terminal(store, receipt.clone(), action.armed.revision())
        .await
        .expect("notifying unknown terminal");
    assert!(action.events(store).await.is_empty());
    let page = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 32)
        .await
        .expect("copy");
    let copy = page.entries()[0].clone();
    store
        .ack_pending_custody(&copy, Utc::now())
        .await
        .expect("original terminal copied");
    release_entry(store, &copy).await;
    let annotation = resolution();
    let snapshot = store
        .resolve_unknown_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            terminal.revision(),
            &action.placement,
            annotation.clone(),
            None,
            None,
            Utc::now(),
        )
        .await
        .expect("worker NotFound resolution owned by gateway");
    let event = store
        .peek_event_projection(&action.tenant, &action.session)
        .await
        .expect("gateway notification")
        .expect("typed resolution event");
    assert_eq!(event.sequence(), 1);
    assert_eq!(event.append().aggregate_revision(), snapshot.revision());
    assert_eq!(
        event.append().kind(),
        browserd_coordination::OutboxEventKind::ActionStateChanged
    );
    assert_eq!(
        event.append().summary(),
        Some(&browserd_coordination::EventStateSummary::Action {
            state: browserd_coordination::EventActionState::OutcomeUnknown,
            resolution: Some(browserd_coordination::EventActionResolution::ConfirmedExecuted)
        })
    );
    assert_eq!(snapshot.resolution(), Some(&annotation));
    assert_eq!(snapshot.last_source_event_sequence(), Some(1));
    assert!(
        store
            .scan_pending_custody(GatewayCustodyCursor::default(), 32)
            .await
            .expect("no invented worker receipt")
            .entries()
            .is_empty()
    );
    store
        .ack_pending_custody(&copy, Utc::now())
        .await
        .expect("historical receipt ACK remains valid");
    NotifyingCustody {
        action,
        snapshot,
        copy,
        legacy_revision: Some(event.append().aggregate_revision()),
    }
}
pub async fn replacement_notifying_resolution_never_duplicates_the_worker_event(
    store: &dyn GatewayActionCoordination,
) {
    let action = Action::new(store).await;
    let receipt = notifying(action.receipt(unknown(), None));
    let terminal = action
        .terminal(store, receipt.clone(), action.armed.revision())
        .await
        .expect("terminal");
    let old = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 32)
        .await
        .expect("old copy")
        .entries()[0]
        .clone();
    let annotation = resolution();
    let resolved = notifying(resolved_copy(&receipt, annotation.clone()));
    let snapshot = store
        .resolve_unknown_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            terminal.revision(),
            &action.placement,
            annotation,
            Some(resolved.clone()),
            None,
            Utc::now(),
        )
        .await
        .expect("worker journal owns actual replacement resolution");
    assert!(snapshot.terminal_outbox_append().is_none());
    assert_eq!(snapshot.last_source_event_sequence(), None);
    assert!(action.events(store).await.is_empty());
    assert_eq!(
        store.ack_pending_custody(&old, Utc::now()).await,
        Err(Error::CustodyAckConflict)
    );
    let current = store
        .scan_pending_custody(GatewayCustodyCursor::default(), 32)
        .await
        .expect("replacement")
        .entries()[0]
        .clone();
    assert_eq!(current.receipt(), &resolved);
    store
        .ack_pending_custody(&current, Utc::now())
        .await
        .expect("new copy ACK");
    release_entry(store, &current).await;
}
