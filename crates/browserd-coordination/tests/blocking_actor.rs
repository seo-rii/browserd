#![allow(clippy::expect_used)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_coordination::{
    CanonicalRequestHash, ClaimCreateOperation, ClaimOutcome, CoordinationActorConfig,
    CoordinationBlockingClient, CoordinationError, CreateOperationSnapshot,
    CreateSessionCoordination, OperationMutation, RecoverableCreateIntent,
};
use browserd_core::{CreateOperationState, OperationId, PrincipalId, TenantId};
use chrono::{DateTime, Utc};

#[derive(Default)]
struct BlockingStore {
    gate: Arc<(Mutex<bool>, Condvar)>,
    entered: Arc<(Mutex<bool>, Condvar)>,
    completed: Arc<(Mutex<bool>, Condvar)>,
}

impl BlockingStore {
    fn release(&self) {
        let (lock, condition) = &*self.gate;
        if let Ok(mut released) = lock.lock() {
            *released = true;
            condition.notify_all();
        }
    }

    fn wait_until_completed(&self) -> bool {
        let (lock, condition) = &*self.completed;
        let Ok(completed) = lock.lock() else {
            return false;
        };
        condition
            .wait_timeout_while(completed, Duration::from_secs(1), |completed| !*completed)
            .map(|(completed, _)| *completed)
            .unwrap_or(false)
    }

    fn wait_until_entered(&self) -> bool {
        let (lock, condition) = &*self.entered;
        let Ok(entered) = lock.lock() else {
            return false;
        };
        condition
            .wait_timeout_while(entered, Duration::from_secs(1), |entered| !*entered)
            .map(|(entered, _)| *entered)
            .unwrap_or(false)
    }

    fn block_until_released(&self) -> Result<(), CoordinationError> {
        let (entered_lock, entered_condition) = &*self.entered;
        let mut entered = entered_lock
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        *entered = true;
        entered_condition.notify_all();
        drop(entered);

        let (lock, condition) = &*self.gate;
        let mut released = lock
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        while !*released {
            released = condition
                .wait(released)
                .map_err(|_| CoordinationError::LockUnavailable)?;
        }
        let (completed_lock, completed_condition) = &*self.completed;
        let mut completed = completed_lock
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        *completed = true;
        completed_condition.notify_all();
        Ok(())
    }
}

#[async_trait]
impl CreateSessionCoordination for BlockingStore {
    async fn claim_create(
        &self,
        _claim: ClaimCreateOperation,
        _now: DateTime<Utc>,
    ) -> Result<ClaimOutcome, CoordinationError> {
        self.block_until_released()?;
        Err(CoordinationError::LockUnavailable)
    }

    async fn get(
        &self,
        _tenant_id: &TenantId,
        _operation_id: &OperationId,
    ) -> Result<Option<CreateOperationSnapshot>, CoordinationError> {
        Err(CoordinationError::LockUnavailable)
    }

    async fn compare_and_set(
        &self,
        _tenant_id: &TenantId,
        _operation_id: &OperationId,
        _expected_revision: u64,
        _expected_state: CreateOperationState,
        _mutation: OperationMutation,
        _now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        self.block_until_released()?;
        Err(CoordinationError::LockUnavailable)
    }

    async fn purge_expired(&self, _now: DateTime<Utc>) -> Result<u64, CoordinationError> {
        Err(CoordinationError::LockUnavailable)
    }
}

fn claim(key: &str) -> ClaimCreateOperation {
    let operation_id = OperationId::new();
    let accepted_at = Utc::now();
    ClaimCreateOperation::new(
        TenantId::new(),
        PrincipalId::new(),
        operation_id.clone(),
        key,
        CanonicalRequestHash::new([1; 32]),
        RecoverableCreateIntent::new(
            &operation_id,
            serde_json::json!({}),
            accepted_at,
            accepted_at + chrono::Duration::seconds(30),
            serde_json::json!({}),
        )
        .expect("intent"),
    )
    .expect("claim should be valid")
}

#[test]
fn bounded_actor_fails_closed_when_its_queue_is_full() {
    let store = Arc::new(BlockingStore::default());
    let client = CoordinationBlockingClient::spawn(
        store.clone(),
        CoordinationActorConfig::new(1, 1, Duration::from_secs(5), Duration::from_secs(5))
            .expect("actor config should be valid"),
    )
    .expect("actor should start");
    let first_client = client.clone();
    let first = std::thread::spawn(move || first_client.claim_create(claim("first"), Utc::now()));
    assert!(store.wait_until_entered());
    let second_client = client.clone();
    let second =
        std::thread::spawn(move || second_client.claim_create(claim("second"), Utc::now()));
    std::thread::sleep(Duration::from_millis(50));

    let overflow = client.claim_create(claim("overflow"), Utc::now());
    assert!(matches!(overflow, Err(CoordinationError::ActorQueueFull)));

    store.release();
    assert!(first.join().expect("first caller should finish").is_err());
    assert!(second.join().expect("second caller should finish").is_err());
}

#[test]
fn mutation_timeout_cannot_be_shorter_than_query_timeout() {
    assert!(matches!(
        CoordinationActorConfig::new(1, 1, Duration::from_secs(2), Duration::from_secs(1)),
        Err(CoordinationError::InvalidActorConfig)
    ));
}

#[test]
fn claim_timeout_is_bounded_but_does_not_cancel_the_admitted_command() {
    let store = Arc::new(BlockingStore::default());
    let client = CoordinationBlockingClient::spawn(
        store.clone(),
        CoordinationActorConfig::new(1, 1, Duration::from_millis(25), Duration::from_millis(25))
            .expect("actor config should be valid"),
    )
    .expect("actor should start");
    let result = client.claim_create(claim("admitted"), Utc::now());
    assert!(matches!(
        result,
        Err(CoordinationError::ActorMutationTimeout)
    ));
    store.release();
    client
        .drain()
        .expect("drain should wait for admitted claim");
    assert!(store.wait_until_completed());
}

#[test]
fn mutating_cas_timeout_is_bounded_and_admitted_mutation_drains() {
    let store = Arc::new(BlockingStore::default());
    let client = CoordinationBlockingClient::spawn(
        store.clone(),
        CoordinationActorConfig::new(1, 1, Duration::from_millis(25), Duration::from_millis(25))
            .expect("actor config should be valid"),
    )
    .expect("actor should start");
    let (finished_sender, finished_receiver) = std::sync::mpsc::channel();
    let caller = std::thread::spawn(move || {
        let result = client.compare_and_set(
            &TenantId::new(),
            &OperationId::new(),
            0,
            CreateOperationState::Reserving,
            OperationMutation::transition(CreateOperationState::Creating),
            Utc::now(),
        );
        let _ = finished_sender.send(result);
    });
    assert!(store.wait_until_entered());
    assert!(matches!(
        finished_receiver.recv_timeout(Duration::from_millis(75)),
        Ok(Err(CoordinationError::ActorMutationTimeout))
    ));
    store.release();
    assert!(store.wait_until_completed());
    caller.join().expect("CAS caller should finish");
}

#[test]
fn a_slow_claim_does_not_head_of_line_block_an_unrelated_read() {
    let store = Arc::new(BlockingStore::default());
    let client = CoordinationBlockingClient::spawn(
        store.clone(),
        CoordinationActorConfig::new(4, 2, Duration::from_secs(1), Duration::from_secs(1))
            .expect("actor config should be valid"),
    )
    .expect("actor should start");
    let claim_client = client.clone();
    let claim_caller =
        std::thread::spawn(move || claim_client.claim_create(claim("slow"), Utc::now()));
    assert!(store.wait_until_entered());

    let started = std::time::Instant::now();
    let read = client.get(&TenantId::new(), &OperationId::new());
    assert!(matches!(read, Err(CoordinationError::LockUnavailable)));
    assert!(started.elapsed() < Duration::from_millis(250));

    store.release();
    assert!(
        claim_caller
            .join()
            .expect("claim caller should finish")
            .is_err()
    );
}
