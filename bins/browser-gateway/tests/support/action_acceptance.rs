use super::*;

struct ReleasePendingOnDrop(Arc<ReleaseGate>);

impl Drop for ReleasePendingOnDrop {
    fn drop(&mut self) {
        let _ = self.0.release();
    }
}

#[test]
fn durable_acceptance_arrives_before_enqueue_and_before_pending_completion()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Succeed)?;
    let _release_on_exit = ReleasePendingOnDrop(fixture.worker.pending_gate.clone());
    let router = fixture.router.clone();
    let worker = fixture.worker.clone();
    let principal = fixture.principal.clone();
    let key = Uuid::new_v4();
    let command = fixture.command(key);
    let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let observed = Arc::new(AtomicUsize::new(0));
    let observer_count = observed.clone();
    let caller = thread::spawn(move || {
        let result = router
            .execute_with_action_acceptance(
                &principal,
                ApiRequest::SubmitAction(command),
                &mut |receipt| {
                    assert_eq!(
                        worker.enqueue_count.load(Ordering::Acquire),
                        0,
                        "acceptance must precede the first worker enqueue"
                    );
                    observer_count.fetch_add(1, Ordering::AcqRel);
                    accepted_tx
                        .try_send(receipt)
                        .expect("one non-blocking receipt");
                },
            )
            .map_err(|error| error.to_string())
            .and_then(action_snapshot);
        let _ = result_tx.send(result);
    });
    let receipt = accepted_rx.recv_timeout(Duration::from_secs(5))?;
    fixture
        .pending_entered
        .recv_timeout(Duration::from_secs(5))?;
    assert!(
        matches!(result_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "worker completion is still held"
    );
    assert_eq!(receipt.data().state(), ActionState::MayHaveExecuted);
    assert!(!receipt.data().dispatch_acknowledged());
    assert!(receipt.data().terminal_detail().is_none());
    let durable = stored_action(
        fixture.store.as_ref(),
        fixture.principal.tenant_id(),
        &fixture.session_id,
        receipt.data().action_id(),
    )?;
    assert_eq!(durable.action_id(), receipt.data().action_id());
    assert_eq!(durable.action_sequence(), receipt.data().action_sequence());
    assert_eq!(
        durable.request_hash().as_bytes(),
        receipt.data().request().canonical_request_hash().as_bytes()
    );
    fixture.worker.pending_gate.release()?;
    let completed = result_rx.recv_timeout(Duration::from_secs(5))??;
    caller
        .join()
        .map_err(|_| "observed submit caller panicked")?;
    assert_eq!(completed.state(), ActionState::Succeeded);
    assert_eq!(completed.action_id(), receipt.data().action_id());
    assert_eq!(
        completed.action_sequence(),
        receipt.data().action_sequence()
    );
    assert_eq!(observed.load(Ordering::Acquire), 1);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);

    let mut repeated_observations = 0;
    let replay = action_snapshot(fixture.router.execute_with_action_acceptance(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(key)),
        &mut |_| repeated_observations += 1,
    )?)?;
    assert_eq!(replay, completed);
    assert_eq!(
        repeated_observations, 0,
        "immediate replay does not emit a new dispatch acceptance"
    );
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn accepted_action_can_finish_not_dispatched_without_changing_identity()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Full)?;
    let key = Uuid::new_v4();
    let mut receipts = Vec::new();
    let final_snapshot = action_snapshot(fixture.router.execute_with_action_acceptance(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(key)),
        &mut |receipt| {
            assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 0);
            receipts.push(receipt);
        },
    )?)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].data().state(), ActionState::MayHaveExecuted);
    assert!(!receipts[0].data().dispatch_acknowledged());
    assert_eq!(final_snapshot.action_id(), receipts[0].data().action_id());
    assert_eq!(
        final_snapshot.action_sequence(),
        receipts[0].data().action_sequence()
    );
    assert_eq!(
        final_snapshot.terminal_detail(),
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::NotDispatched
        ))
    );
    let mut repeat_observations = 0;
    let replay = action_snapshot(fixture.router.execute_with_action_acceptance(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(key)),
        &mut |_| repeat_observations += 1,
    )?)?;
    assert_eq!(replay, final_snapshot);
    assert_eq!(repeat_observations, 0);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn dropping_the_acceptance_receiver_does_not_cancel_durable_dispatch() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new(EnqueueMode::Succeed)?;
    let _release_on_exit = ReleasePendingOnDrop(fixture.worker.pending_gate.clone());
    let router = fixture.router.clone();
    let principal = fixture.principal.clone();
    let command = fixture.command(Uuid::new_v4());
    let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
    drop(accepted_rx);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let caller = thread::spawn(move || {
        let result = router
            .execute_with_action_acceptance(
                &principal,
                ApiRequest::SubmitAction(command),
                &mut |receipt| {
                    assert!(matches!(
                        accepted_tx.try_send(receipt),
                        Err(mpsc::TrySendError::Disconnected(_))
                    ));
                },
            )
            .map_err(|error| error.to_string())
            .and_then(action_snapshot);
        let _ = result_tx.send(result);
    });
    fixture.release_pending()?;
    let completed = result_rx.recv_timeout(Duration::from_secs(5))??;
    caller
        .join()
        .map_err(|_| "observed submit caller panicked")?;
    assert_eq!(completed.state(), ActionState::Succeeded);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn rejected_or_conflicting_submissions_never_emit_new_acceptance() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(EnqueueMode::Full)?;
    let mut invalid = fixture.command(Uuid::nil());
    let mut observations = 0;
    let result = fixture.router.execute_with_action_acceptance(
        &fixture.principal,
        ApiRequest::SubmitAction(invalid.clone()),
        &mut |_| observations += 1,
    );
    assert_eq!(
        result.expect_err("nil key must be rejected").code(),
        ErrorCode::InvalidRequest
    );
    assert_eq!(observations, 0);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 0);

    invalid.idempotency_key = Uuid::new_v4();
    let _ = fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(invalid.clone()),
    )?;
    invalid.body.action = ActionPayload::GetUrl;
    assert!(
        fixture
            .router
            .execute_with_action_acceptance(
                &fixture.principal,
                ApiRequest::SubmitAction(invalid),
                &mut |_| observations += 1
            )
            .is_err()
    );
    assert_eq!(observations, 0);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    Ok(())
}
