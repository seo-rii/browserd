#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use browserd_coordination::{
    EphemeralCoordinationError, RedisEphemeralConfig, RedisEphemeralCoordinationStore,
    WorkerCapacity, WorkerHeartbeat, WorkerLeaseStore, WorkerReadiness, WorkerRegistration,
    WorkerRegistrationQuery, WorkerReservationMutation, WorkerReservationOutcome,
    WorkerReservationRequest, WorkerReservationSnapshot, WorkerReservationStore,
};
use browserd_core::{OperationId, TenantId, WorkerId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn vector(memory: u64) -> WorkerCapacity {
    WorkerCapacity::new(memory, 0, 0, 0, 0, 0)
}

fn worker_key(prefix: &str, worker_id: &str) -> String {
    format!("{prefix}:{{browserd-worker}}:worker:{worker_id}:lease")
}

fn worker_active_key(prefix: &str, worker_id: &str) -> String {
    format!("{prefix}:{{browserd-worker}}:worker:{worker_id}:active")
}

fn operation_key(prefix: &str, operation_id: &OperationId) -> String {
    format!("{prefix}:{{browserd-worker}}:operation:{operation_id}")
}

fn ready_index_key(prefix: &str, region: &str, compatibility: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"browserd-worker-ready-index-v1\0");
    digest.update(region.as_bytes());
    digest.update(b"\0");
    digest.update(compatibility.as_bytes());
    format!(
        "{prefix}:{{browserd-worker}}:ready:{}",
        hex::encode(digest.finalize())
    )
}

async fn sorted_hash(
    connection: &mut redis::aio::MultiplexedConnection,
    key: &str,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = redis::cmd("HGETALL")
        .arg(key)
        .query_async(connection)
        .await
        .expect("fixture hash should be readable");
    fields.sort();
    fields
}

async fn absolute_expiry(connection: &mut redis::aio::MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("PEXPIRETIME")
        .arg(key)
        .query_async(connection)
        .await
        .expect("absolute expiry should be readable")
}

async fn reservation_raw_state(
    connection: &mut redis::aio::MultiplexedConnection,
    worker_key: &str,
    operation_key: &str,
    active_key: &str,
) -> (
    (Vec<(Vec<u8>, Vec<u8>)>, i64),
    (Vec<(Vec<u8>, Vec<u8>)>, i64),
    Vec<(Vec<u8>, f64)>,
) {
    let worker = (
        sorted_hash(connection, worker_key).await,
        absolute_expiry(connection, worker_key).await,
    );
    let operation = (
        sorted_hash(connection, operation_key).await,
        absolute_expiry(connection, operation_key).await,
    );
    let active = redis::cmd("ZRANGE")
        .arg(active_key)
        .arg(0_i8)
        .arg(-1_i8)
        .arg("WITHSCORES")
        .query_async(connection)
        .await
        .expect("active index should be readable");
    (worker, operation, active)
}

async fn register(
    store: &RedisEphemeralCoordinationStore,
    worker: &str,
    epoch: u64,
    capacity: u64,
) -> browserd_coordination::WorkerRegistrationSnapshot {
    store
        .register_worker(
            WorkerRegistration::new(
                WorkerId::new(worker).expect("worker id should validate"),
                epoch,
                "redis-test-region",
                "redis-test-release",
                vec!["redis-test-compat".to_owned()],
                vector(capacity),
                format!("worker-rpc://{worker}"),
            )
            .expect("registration should validate"),
            WorkerHeartbeat::new(vector(capacity), 0, 0, WorkerReadiness::Ready)
                .expect("heartbeat should validate"),
            Duration::from_secs(30),
        )
        .await
        .expect("worker should register")
        .into_snapshot()
        .expect("registration should return a snapshot")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_worker_reservation_end_to_end() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let prefix = format!("browserd-test-{}", Uuid::new_v4());
    let store = Arc::new(
        RedisEphemeralCoordinationStore::connect(
            RedisEphemeralConfig::new(endpoint, prefix, 32, Duration::from_secs(2))
                .expect("Redis config should validate"),
        )
        .await
        .expect("Redis should connect"),
    );
    let huge = 9_007_199_254_740_993_u64;
    let worker = register(&store, "redis-worker-a", 7, huge).await;
    let duplicate = WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(1))
        .expect("request should validate");
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = Arc::clone(&store);
        let worker = worker.clone();
        let duplicate = duplicate.clone();
        tasks.push(tokio::spawn(async move {
            store
                .reserve_worker(&worker, duplicate, Duration::from_secs(5))
                .await
        }));
    }
    let mut acquired = 0;
    let mut existing = 0;
    for task in tasks {
        match task
            .await
            .expect("task should join")
            .expect("reserve should run")
        {
            WorkerReservationOutcome::Acquired(_) => acquired += 1,
            WorkerReservationOutcome::Existing(_) => existing += 1,
            _ => {}
        }
    }
    assert_eq!((acquired, existing), (1, 15));
    let worker = store
        .query_ready_workers(
            &WorkerRegistrationQuery::new("redis-test-region", "redis-test-compat", 1)
                .expect("query should validate"),
        )
        .await
        .expect("worker should remain queryable")
        .pop()
        .expect("worker should remain registered");
    let first = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("first reserve should run")
        .into_grant()
        .expect("first reserve should acquire");
    let second = store
        .reserve_worker(
            first.worker(),
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("second reserve should run")
        .into_grant()
        .expect("second reserve should acquire");
    let after_older_release = store
        .release_worker_reservation(first.reservation())
        .await
        .expect("older release should run")
        .into_worker()
        .expect("older exact reservation should release from current state");
    assert!(after_older_release.revision() > second.worker().revision());

    let operation_id = OperationId::new();
    let tenant_id = TenantId::new();
    let exact =
        WorkerReservationRequest::new(operation_id.clone(), tenant_id.clone(), vector(huge - 60))
            .expect("request should validate");
    let expiring = store
        .reserve_worker(
            &after_older_release,
            exact.clone(),
            Duration::from_millis(200),
        )
        .await
        .expect("large exact reservation should run")
        .into_grant()
        .expect("large exact reservation should acquire without rounding");
    assert!(matches!(
        store
            .reserve_worker(&worker, exact, Duration::from_millis(200))
            .await
            .expect("stale exact retry should run"),
        WorkerReservationOutcome::Existing(_)
    ));
    let other_worker = register(&store, "redis-worker-b", 7, huge).await;
    let cross_worker_retry = store
        .reserve_worker(
            &other_worker,
            expiring.reservation().request().clone(),
            Duration::from_secs(5),
        )
        .await
        .expect("cross-worker exact retry should run")
        .into_grant()
        .expect("cross-worker exact retry should return the original grant");
    assert_eq!(
        cross_worker_retry.worker().registration().worker_id(),
        expiring.worker().registration().worker_id()
    );
    let forged_release = WorkerReservationSnapshot::from_persisted(
        expiring.reservation().request().clone(),
        other_worker.clone(),
        expiring.reservation().expires_at_millis(),
    )
    .expect("forged receipt fixture should validate structurally");
    assert_eq!(
        store
            .release_worker_reservation(&forged_release)
            .await
            .expect("forged release should be rejected as an outcome"),
        WorkerReservationMutation::FenceMismatch
    );
    assert!(
        store
            .reserve_worker(
                &other_worker,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(huge),)
                    .expect("request should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("worker B capacity check should run")
            .into_grant()
            .is_ok(),
        "forged release must not mutate worker B capacity"
    );
    let conflict = WorkerReservationRequest::new(operation_id, tenant_id, vector(huge - 61))
        .expect("conflict should validate");
    assert_eq!(
        store
            .reserve_worker(&other_worker, conflict, Duration::from_secs(5))
            .await
            .expect("cross-worker conflict should run"),
        WorkerReservationOutcome::Conflict
    );

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        store
            .release_worker_reservation(expiring.reservation())
            .await
            .expect("expired release should run"),
        WorkerReservationMutation::Expired
    );
    let current = store
        .query_ready_workers(
            &WorkerRegistrationQuery::new("redis-test-region", "redis-test-compat", 2)
                .expect("query should validate"),
        )
        .await
        .expect("worker should remain queryable")
        .into_iter()
        .find(|worker| worker.registration().worker_id() == expiring.reservation().worker_id())
        .expect("reservation worker should remain registered");
    assert!(
        store
            .reserve_worker(
                &current,
                WorkerReservationRequest::new(
                    OperationId::new(),
                    TenantId::new(),
                    vector(huge - 31),
                )
                .expect("request should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("reclaimed capacity check should run")
            .into_grant()
            .is_ok(),
        "expiry must restore the exact huge reservation while preserving active 1+30"
    );
}

#[tokio::test]
async fn redis_heartbeat_preserves_debits_and_same_epoch_cannot_cross_lease_expiry() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(
            endpoint,
            format!("browserd-test-{}", Uuid::new_v4()),
            16,
            Duration::from_secs(2),
        )
        .expect("Redis config should validate"),
    )
    .await
    .expect("Redis should connect");
    let worker = register(&store, "redis-heartbeat-worker", 31, 100).await;
    let active = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should acquire");
    let heartbeated = store
        .heartbeat_worker(
            active.worker(),
            WorkerHeartbeat::new(vector(100), 9, 4, WorkerReadiness::Ready)
                .expect("advertised heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("heartbeat should work")
        .into_snapshot()
        .expect("heartbeat should update mutable facts without dropping debit");
    assert_eq!(heartbeated.heartbeat().free(), vector(70));
    assert_eq!(heartbeated.heartbeat().queue_depth(), 9);
    store
        .release_worker_reservation(active.reservation())
        .await
        .expect("release should work")
        .into_worker()
        .expect("release should apply");
    let current = store
        .query_ready_workers(
            &WorkerRegistrationQuery::new("redis-test-region", "redis-test-compat", 1)
                .expect("query should validate"),
        )
        .await
        .expect("query should work")
        .pop()
        .expect("worker should remain ready");
    assert_eq!(current.heartbeat().free(), vector(100));

    let short_registration = WorkerRegistration::new(
        WorkerId::new("redis-expiring-worker").expect("worker id should validate"),
        41,
        "redis-test-region",
        "redis-test-release",
        vec!["redis-test-compat".to_owned()],
        vector(100),
        "worker-rpc://redis-expiring-worker",
    )
    .expect("registration should validate");
    store
        .register_worker(
            short_registration.clone(),
            WorkerHeartbeat::new(vector(100), 0, 0, WorkerReadiness::Ready)
                .expect("heartbeat should validate"),
            Duration::from_millis(5),
        )
        .await
        .expect("short registration should work");
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        store
            .register_worker(
                short_registration,
                WorkerHeartbeat::new(vector(100), 0, 0, WorkerReadiness::Ready)
                    .expect("heartbeat should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("same epoch retry should be fenced"),
        browserd_coordination::WorkerLeaseMutation::FenceMismatch
    );
}

#[tokio::test]
async fn redis_heartbeat_reclaims_expired_reservations_in_bounded_batches() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(
            endpoint,
            format!("browserd-test-{}", Uuid::new_v4()),
            16,
            Duration::from_secs(2),
        )
        .expect("Redis config should validate"),
    )
    .await
    .expect("Redis should connect");
    let mut worker = register(&store, "redis-heartbeat-sweep-worker", 51, 100).await;
    let first_request =
        WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(1))
            .expect("request should validate");
    for index in 0..65 {
        let request = if index == 0 {
            first_request.clone()
        } else {
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(1))
                .expect("request should validate")
        };
        worker = store
            .reserve_worker(&worker, request, Duration::from_millis(200))
            .await
            .expect("reserve should work")
            .into_grant()
            .expect("reserve should acquire")
            .worker()
            .clone();
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    let first = store
        .heartbeat_worker(
            &worker,
            WorkerHeartbeat::new(vector(100), 3, 2, WorkerReadiness::Ready)
                .expect("advertised heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("first bounded heartbeat sweep should work")
        .into_snapshot()
        .expect("heartbeat should apply");
    assert_eq!(first.heartbeat().free(), vector(99));
    let second = store
        .heartbeat_worker(
            &first,
            WorkerHeartbeat::new(vector(100), 4, 2, WorkerReadiness::Ready)
                .expect("advertised heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("second bounded heartbeat sweep should work")
        .into_snapshot()
        .expect("heartbeat should apply");
    assert_eq!(second.heartbeat().free(), vector(100));
    assert_eq!(
        store
            .reserve_worker(&second, first_request, Duration::from_secs(5))
            .await
            .expect("expired exact retry should be stable"),
        WorkerReservationOutcome::Expired
    );
    assert!(
        store
            .reserve_worker(
                &second,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(100),)
                    .expect("request should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("fully reclaimed capacity should be usable")
            .into_grant()
            .is_ok()
    );
}

#[tokio::test]
async fn redis_ready_query_limit_is_independent_of_a_noisy_shared_keyspace() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let noise_namespace = Uuid::new_v4();
    let client = redis::Client::open(endpoint.clone()).expect("Redis endpoint should validate");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis fixture connection should open");
    let mut noise = redis::pipe();
    for index in 0..32_768 {
        noise
            .cmd("SET")
            .arg(format!("browserd-query-noise-{noise_namespace}:{index}"))
            .arg("noise")
            .arg("PX")
            .arg(300_000_u64)
            .ignore();
    }
    tokio::time::timeout(
        Duration::from_secs(10),
        noise.query_async::<()>(&mut connection),
    )
    .await
    .expect("noise fixture should be time bounded")
    .expect("noise fixture should be written");

    for index in 0..8 {
        let prefix = format!("browserd-query-target-{}-{index}", Uuid::new_v4());
        let store = RedisEphemeralCoordinationStore::connect(
            RedisEphemeralConfig::new(endpoint.clone(), prefix, 4, Duration::from_secs(2))
                .expect("Redis config should validate"),
        )
        .await
        .expect("Redis should connect");
        let worker_id = format!("redis-query-worker-{index}");
        register(&store, &worker_id, 61, 100).await;
        let ready = store
            .query_ready_workers(
                &WorkerRegistrationQuery::new("redis-test-region", "redis-test-compat", 1)
                    .expect("query should validate"),
            )
            .await
            .expect("bounded query should work");
        assert_eq!(ready.len(), 1, "query missed ready worker {index}");
        assert_eq!(ready[0].registration().worker_id().as_str(), worker_id);
    }
}

#[tokio::test]
async fn redis_reserve_reclaims_its_own_expired_debit_before_snapshot_cas() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(
            endpoint,
            format!("browserd-self-reclaim-{}", Uuid::new_v4()),
            8,
            Duration::from_secs(2),
        )
        .expect("Redis config should validate"),
    )
    .await
    .expect("Redis should connect");
    let worker = register(&store, "redis-self-reclaim-worker", 71, 100).await;
    let expired = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(100))
                .expect("request should validate"),
            Duration::from_millis(50),
        )
        .await
        .expect("initial reserve should work")
        .into_grant()
        .expect("initial reserve should acquire");
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert!(
        store
            .reserve_worker(
                expired.worker(),
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(100))
                    .expect("replacement request should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("self-reclaiming reserve should work")
            .into_grant()
            .is_ok()
    );
}

#[tokio::test]
async fn redis_foreign_active_index_member_fails_closed_without_touching_its_owner() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let prefix = format!("browserd-foreign-index-{}", Uuid::new_v4());
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("Redis config should validate"),
    )
    .await
    .expect("Redis should connect");
    let worker_a = register(&store, "redis-index-worker-a", 81, 100).await;
    let worker_b = register(&store, "redis-index-worker-b", 81, 100).await;
    let grant_a = store
        .reserve_worker(
            &worker_a,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("worker A reserve should work")
        .into_grant()
        .expect("worker A reserve should acquire");
    let client = redis::Client::open(endpoint).expect("Redis endpoint should validate");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection should open");
    redis::cmd("ZADD")
        .arg(worker_active_key(&prefix, "redis-index-worker-b"))
        .arg(0_u8)
        .arg(operation_key(&prefix, grant_a.reservation().operation_id()))
        .query_async::<()>(&mut connection)
        .await
        .expect("foreign active fixture should be inserted");
    assert_eq!(
        store
            .reserve_worker(
                &worker_b,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(1))
                    .expect("request should validate"),
                Duration::from_secs(5),
            )
            .await,
        Err(EphemeralCoordinationError::InvalidResponse)
    );
    assert!(matches!(
        store
            .release_worker_reservation(grant_a.reservation())
            .await
            .expect("worker A release should remain possible"),
        WorkerReservationMutation::Released(_)
    ));
}

#[tokio::test]
async fn redis_release_validation_failure_leaves_all_coordination_bytes_unchanged() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let prefix = format!("browserd-release-atomic-{}", Uuid::new_v4());
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("Redis config should validate"),
    )
    .await
    .expect("Redis should connect");
    let worker = register(&store, "redis-release-atomic-worker", 91, 100).await;
    let grant = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should acquire");
    let worker_key = worker_key(&prefix, "redis-release-atomic-worker");
    let operation_key = operation_key(&prefix, grant.reservation().operation_id());
    let active_key = worker_active_key(&prefix, "redis-release-atomic-worker");
    let client = redis::Client::open(endpoint).expect("Redis endpoint should validate");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection should open");
    redis::cmd("HDEL")
        .arg(&worker_key)
        .arg("queue_depth")
        .query_async::<()>(&mut connection)
        .await
        .expect("corrupt fixture should be applied");
    let before =
        reservation_raw_state(&mut connection, &worker_key, &operation_key, &active_key).await;
    assert_eq!(
        store.release_worker_reservation(grant.reservation()).await,
        Err(EphemeralCoordinationError::InvalidResponse)
    );
    let after =
        reservation_raw_state(&mut connection, &worker_key, &operation_key, &active_key).await;
    assert!(
        after == before,
        "release validation failure mutated raw coordination fields"
    );
}

#[tokio::test]
async fn redis_release_wrongtype_active_index_is_fully_atomic() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let prefix = format!("browserd-release-wrongtype-{}", Uuid::new_v4());
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("Redis config should validate"),
    )
    .await
    .expect("Redis should connect");
    let worker = register(&store, "redis-release-wrongtype-worker", 96, 100).await;
    let grant = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should acquire");
    let worker_key = worker_key(&prefix, "redis-release-wrongtype-worker");
    let operation_key = operation_key(&prefix, grant.reservation().operation_id());
    let active_key = worker_active_key(&prefix, "redis-release-wrongtype-worker");
    let client = redis::Client::open(endpoint).expect("Redis endpoint should validate");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection should open");
    redis::cmd("DEL")
        .arg(&active_key)
        .query_async::<()>(&mut connection)
        .await
        .expect("active index should be removed for the WRONGTYPE fixture");
    redis::cmd("SET")
        .arg(&active_key)
        .arg("wrong-type-active-index")
        .arg("PX")
        .arg(300_000_u64)
        .query_async::<()>(&mut connection)
        .await
        .expect("WRONGTYPE fixture should be installed");
    let before = (
        sorted_hash(&mut connection, &worker_key).await,
        absolute_expiry(&mut connection, &worker_key).await,
        sorted_hash(&mut connection, &operation_key).await,
        absolute_expiry(&mut connection, &operation_key).await,
        redis::cmd("GET")
            .arg(&active_key)
            .query_async::<Vec<u8>>(&mut connection)
            .await
            .expect("active fixture should remain a string"),
        absolute_expiry(&mut connection, &active_key).await,
    );
    assert!(
        store
            .release_worker_reservation(grant.reservation())
            .await
            .is_err(),
        "release must fail closed on a WRONGTYPE active index"
    );
    let after = (
        sorted_hash(&mut connection, &worker_key).await,
        absolute_expiry(&mut connection, &worker_key).await,
        sorted_hash(&mut connection, &operation_key).await,
        absolute_expiry(&mut connection, &operation_key).await,
        redis::cmd("GET")
            .arg(&active_key)
            .query_async::<Vec<u8>>(&mut connection)
            .await
            .expect("active fixture should remain a string"),
        absolute_expiry(&mut connection, &active_key).await,
    );
    assert_eq!(
        after, before,
        "failed release changed worker, operation, or active-index bytes"
    );
}

#[tokio::test]
async fn redis_higher_epoch_ignores_dangling_old_active_index_members() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis integration test: BROWSERD_REDIS_TEST_URL is unset");
        return;
    };
    let prefix = format!("browserd-dangling-active-{}", Uuid::new_v4());
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("Redis config should validate"),
    )
    .await
    .expect("Redis should connect");
    let old = register(&store, "redis-dangling-worker", 101, 100).await;
    let old_grant = store
        .reserve_worker(
            &old,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(20))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("old reserve should work")
        .into_grant()
        .expect("old reserve should acquire");
    let client = redis::Client::open(endpoint).expect("Redis endpoint should validate");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection should open");
    let old_operation_key = operation_key(&prefix, old_grant.reservation().operation_id());
    redis::cmd("DEL")
        .arg(worker_key(&prefix, "redis-dangling-worker"))
        .arg(&old_operation_key)
        .query_async::<()>(&mut connection)
        .await
        .expect("old records should be removed while leaving the active index dangling");
    redis::cmd("ZADD")
        .arg(worker_active_key(&prefix, "redis-dangling-worker"))
        .arg(0_u8)
        .arg(old_operation_key)
        .query_async::<()>(&mut connection)
        .await
        .expect("dangling due member should remain visible to heartbeat sweep");
    let registration = WorkerRegistration::new(
        WorkerId::new("redis-dangling-worker").expect("worker id should validate"),
        102,
        "redis-test-region",
        "redis-test-release",
        vec!["redis-test-compat".to_owned()],
        vector(100),
        "worker-rpc://redis-dangling-worker",
    )
    .expect("higher epoch registration should validate");
    let current = store
        .register_worker(
            registration,
            WorkerHeartbeat::new(vector(100), 0, 0, WorkerReadiness::Ready)
                .expect("heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("higher epoch registration should work")
        .into_snapshot()
        .expect("higher epoch should apply");
    assert!(
        store
            .heartbeat_worker(
                &current,
                WorkerHeartbeat::new(vector(100), 1, 0, WorkerReadiness::Ready)
                    .expect("heartbeat should validate"),
                Duration::from_secs(20),
            )
            .await
            .expect("dangling old index must not poison the new epoch")
            .into_snapshot()
            .is_ok()
    );
}

#[tokio::test]
async fn redis_live_epoch_takeover_moves_worker_between_ready_selectors() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        return;
    };
    let prefix = format!("browserd-selector-takeover-{}", Uuid::new_v4());
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("config"),
    )
    .await
    .expect("connect");
    let make_registration = |worker: &str, epoch, region: &str, compatibility: &str| {
        WorkerRegistration::new(
            WorkerId::new(worker).expect("worker id"),
            epoch,
            region,
            "release",
            vec![compatibility.to_owned()],
            vector(100),
            format!("worker-rpc://{worker}"),
        )
        .expect("registration")
    };
    let heartbeat =
        || WorkerHeartbeat::new(vector(100), 0, 0, WorkerReadiness::Ready).expect("heartbeat");
    store
        .register_worker(
            make_registration("selector-b", 1, "old-region", "old-compat"),
            heartbeat(),
            Duration::from_secs(20),
        )
        .await
        .expect("B register");
    store
        .register_worker(
            make_registration("selector-a", 1, "old-region", "old-compat"),
            heartbeat(),
            Duration::from_secs(10),
        )
        .await
        .expect("A old register");
    store
        .register_worker(
            make_registration("selector-a", 2, "new-region", "new-compat"),
            heartbeat(),
            Duration::from_secs(20),
        )
        .await
        .expect("A takeover");
    let old = store
        .query_ready_workers(
            &WorkerRegistrationQuery::new("old-region", "old-compat", 1).expect("query"),
        )
        .await
        .expect("old selector query");
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].registration().worker_id().as_str(), "selector-b");
    let new = store
        .query_ready_workers(
            &WorkerRegistrationQuery::new("new-region", "new-compat", 1).expect("query"),
        )
        .await
        .expect("new selector query");
    assert_eq!(new.len(), 1);
    assert_eq!(new[0].worker_epoch(), 2);
    let client = redis::Client::open(endpoint).expect("endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection");
    let members: Vec<Vec<u8>> = redis::cmd("ZRANGE")
        .arg(ready_index_key(&prefix, "old-region", "old-compat"))
        .arg(0_i8)
        .arg(-1_i8)
        .query_async(&mut connection)
        .await
        .expect("old index");
    assert!(
        !members
            .iter()
            .any(|member| member == worker_key(&prefix, "selector-a").as_bytes())
    );
}

#[tokio::test]
async fn redis_register_wrongtype_ready_index_is_fully_atomic() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        return;
    };
    let prefix = format!("browserd-register-wrongtype-{}", Uuid::new_v4());
    let worker_id = "register-wrongtype-worker";
    let worker_key = worker_key(&prefix, worker_id);
    let high_water = format!("{prefix}:{{browserd-worker}}:worker:{worker_id}:epoch");
    let active = worker_active_key(&prefix, worker_id);
    let ready = ready_index_key(&prefix, "redis-test-region", "redis-test-compat");
    let client = redis::Client::open(endpoint.clone()).expect("endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection");
    redis::cmd("SET")
        .arg(&ready)
        .arg("wrong-type")
        .arg("PX")
        .arg(300_000_u64)
        .query_async::<()>(&mut connection)
        .await
        .expect("wrongtype fixture");
    redis::cmd("ZADD")
        .arg(&active)
        .arg(1_u8)
        .arg("sentinel")
        .query_async::<()>(&mut connection)
        .await
        .expect("active sentinel");
    redis::cmd("PEXPIRE")
        .arg(&active)
        .arg(300_000_u64)
        .query_async::<()>(&mut connection)
        .await
        .expect("active ttl");
    let before = (
        sorted_hash(&mut connection, &worker_key).await,
        redis::cmd("GET")
            .arg(&high_water)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("highwater"),
        redis::cmd("ZRANGE")
            .arg(&active)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, f64)>>(&mut connection)
            .await
            .expect("active"),
        redis::cmd("GET")
            .arg(&ready)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &active).await,
        absolute_expiry(&mut connection, &ready).await,
    );
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint, prefix, 8, Duration::from_secs(2)).expect("config"),
    )
    .await
    .expect("connect");
    let result = store
        .register_worker(
            WorkerRegistration::new(
                WorkerId::new(worker_id).expect("id"),
                1,
                "redis-test-region",
                "release",
                vec!["redis-test-compat".to_owned()],
                vector(100),
                "worker-rpc://wrongtype",
            )
            .expect("registration"),
            WorkerHeartbeat::new(vector(100), 0, 0, WorkerReadiness::Ready).expect("heartbeat"),
            Duration::from_secs(20),
        )
        .await;
    assert!(result.is_err());
    let after = (
        sorted_hash(&mut connection, &worker_key).await,
        redis::cmd("GET")
            .arg(&high_water)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("highwater"),
        redis::cmd("ZRANGE")
            .arg(&active)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, f64)>>(&mut connection)
            .await
            .expect("active"),
        redis::cmd("GET")
            .arg(&ready)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &active).await,
        absolute_expiry(&mut connection, &ready).await,
    );
    assert!(
        after == before,
        "failed register mutated coordination state"
    );
}

#[tokio::test]
async fn redis_heartbeat_wrongtype_ready_index_is_fully_atomic() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        return;
    };
    let prefix = format!("browserd-heartbeat-wrongtype-{}", Uuid::new_v4());
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("config"),
    )
    .await
    .expect("connect");
    let worker = register(&store, "heartbeat-wrongtype-worker", 111, 100).await;
    let worker_key = worker_key(&prefix, "heartbeat-wrongtype-worker");
    let active = worker_active_key(&prefix, "heartbeat-wrongtype-worker");
    let ready = ready_index_key(&prefix, "redis-test-region", "redis-test-compat");
    let client = redis::Client::open(endpoint).expect("endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection");
    redis::cmd("DEL")
        .arg(&ready)
        .query_async::<()>(&mut connection)
        .await
        .expect("delete index");
    redis::cmd("SET")
        .arg(&ready)
        .arg("wrong-type")
        .arg("PX")
        .arg(300_000_u64)
        .query_async::<()>(&mut connection)
        .await
        .expect("wrongtype fixture");
    let before = (
        sorted_hash(&mut connection, &worker_key).await,
        absolute_expiry(&mut connection, &worker_key).await,
        redis::cmd("ZRANGE")
            .arg(&active)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, f64)>>(&mut connection)
            .await
            .expect("active"),
        redis::cmd("GET")
            .arg(&ready)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &ready).await,
    );
    let result = store
        .heartbeat_worker(
            &worker,
            WorkerHeartbeat::new(vector(100), 7, 3, WorkerReadiness::Ready).expect("heartbeat"),
            Duration::from_secs(20),
        )
        .await;
    assert!(result.is_err());
    let after = (
        sorted_hash(&mut connection, &worker_key).await,
        absolute_expiry(&mut connection, &worker_key).await,
        redis::cmd("ZRANGE")
            .arg(&active)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, f64)>>(&mut connection)
            .await
            .expect("active"),
        redis::cmd("GET")
            .arg(&ready)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &ready).await,
    );
    assert!(
        after == before,
        "failed heartbeat mutated coordination state"
    );
}

#[tokio::test]
async fn redis_query_rejects_forged_secondary_selector_fields() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        return;
    };
    let prefix = format!("browserd-forged-selector-{}", Uuid::new_v4());
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("config"),
    )
    .await
    .expect("connect");
    let worker = register(&store, "forged-selector-worker", 121, 100).await;
    let lease = worker_key(&prefix, "forged-selector-worker");
    let forged_index = ready_index_key(&prefix, "forged-region", "forged-compat");
    let client = redis::Client::open(endpoint).expect("endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection");
    redis::cmd("HSET")
        .arg(&lease)
        .arg("region")
        .arg("forged-region")
        .arg("compatibility")
        .arg("[\"forged-compat\"]")
        .arg("readiness")
        .arg("ready")
        .query_async::<()>(&mut connection)
        .await
        .expect("forge secondary fields");
    redis::cmd("ZADD")
        .arg(&forged_index)
        .arg(worker.expires_at_millis())
        .arg(&lease)
        .query_async::<()>(&mut connection)
        .await
        .expect("forge selector index");
    redis::cmd("PEXPIREAT")
        .arg(&forged_index)
        .arg(worker.expires_at_millis())
        .query_async::<()>(&mut connection)
        .await
        .expect("index ttl");
    assert_eq!(
        store
            .query_ready_workers(
                &WorkerRegistrationQuery::new("forged-region", "forged-compat", 1).expect("query")
            )
            .await,
        Err(EphemeralCoordinationError::InvalidResponse)
    );
}

#[tokio::test]
async fn redis_register_rejects_infinite_ready_index_score_without_partial_effects() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        return;
    };
    let prefix = format!("browserd-register-infinite-score-{}", Uuid::new_v4());
    let worker_id = "register-infinite-score-worker";
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("config"),
    )
    .await
    .expect("connect");
    register(&store, worker_id, 131, 100).await;
    let lease = worker_key(&prefix, worker_id);
    let high_water = format!("{prefix}:{{browserd-worker}}:worker:{worker_id}:epoch");
    let active = worker_active_key(&prefix, worker_id);
    let ready = ready_index_key(&prefix, "redis-test-region", "redis-test-compat");
    let client = redis::Client::open(endpoint).expect("endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection");
    redis::cmd("ZADD")
        .arg(&ready)
        .arg("+inf")
        .arg("malformed-score-sentinel")
        .query_async::<()>(&mut connection)
        .await
        .expect("infinite score fixture");
    redis::cmd("ZADD")
        .arg(&active)
        .arg(1_u8)
        .arg("active-sentinel")
        .query_async::<()>(&mut connection)
        .await
        .expect("active sentinel");
    redis::cmd("PEXPIRE")
        .arg(&active)
        .arg(300_000_u64)
        .query_async::<()>(&mut connection)
        .await
        .expect("active ttl");
    let before = (
        sorted_hash(&mut connection, &lease).await,
        absolute_expiry(&mut connection, &lease).await,
        redis::cmd("GET")
            .arg(&high_water)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("highwater"),
        redis::cmd("ZRANGE")
            .arg(&active)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, String)>>(&mut connection)
            .await
            .expect("active"),
        absolute_expiry(&mut connection, &active).await,
        redis::cmd("ZRANGE")
            .arg(&ready)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, String)>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &ready).await,
    );
    let registration = WorkerRegistration::new(
        WorkerId::new(worker_id).expect("worker id"),
        132,
        "redis-test-region",
        "redis-test-release",
        vec!["redis-test-compat".to_owned()],
        vector(100),
        "worker-rpc://register-infinite-score-worker",
    )
    .expect("registration");
    assert!(
        store
            .register_worker(
                registration,
                WorkerHeartbeat::new(vector(100), 0, 0, WorkerReadiness::Ready).expect("heartbeat"),
                Duration::from_secs(20)
            )
            .await
            .is_err()
    );
    let after = (
        sorted_hash(&mut connection, &lease).await,
        absolute_expiry(&mut connection, &lease).await,
        redis::cmd("GET")
            .arg(&high_water)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("highwater"),
        redis::cmd("ZRANGE")
            .arg(&active)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, String)>>(&mut connection)
            .await
            .expect("active"),
        absolute_expiry(&mut connection, &active).await,
        redis::cmd("ZRANGE")
            .arg(&ready)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, String)>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &ready).await,
    );
    assert!(
        after == before,
        "failed higher-epoch register changed logical state"
    );
}

#[tokio::test]
async fn redis_heartbeat_rejects_infinite_ready_index_score_without_partial_effects() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        return;
    };
    let prefix = format!("browserd-heartbeat-infinite-score-{}", Uuid::new_v4());
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("config"),
    )
    .await
    .expect("connect");
    let worker = register(&store, "heartbeat-infinite-score-worker", 141, 100).await;
    let grant = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(30))
                .expect("request"),
            Duration::from_secs(5),
        )
        .await
        .expect("reserve")
        .into_grant()
        .expect("grant");
    let lease = worker_key(&prefix, "heartbeat-infinite-score-worker");
    let active = worker_active_key(&prefix, "heartbeat-infinite-score-worker");
    let operation = operation_key(&prefix, grant.reservation().operation_id());
    let ready = ready_index_key(&prefix, "redis-test-region", "redis-test-compat");
    let client = redis::Client::open(endpoint).expect("endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection");
    redis::cmd("ZADD")
        .arg(&ready)
        .arg("+inf")
        .arg("malformed-score-sentinel")
        .query_async::<()>(&mut connection)
        .await
        .expect("infinite score fixture");
    let before = (
        reservation_raw_state(&mut connection, &lease, &operation, &active).await,
        redis::cmd("ZRANGE")
            .arg(&ready)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, String)>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &ready).await,
    );
    assert!(
        store
            .heartbeat_worker(
                grant.worker(),
                WorkerHeartbeat::new(vector(100), 9, 4, WorkerReadiness::Ready).expect("heartbeat"),
                Duration::from_secs(20),
            )
            .await
            .is_err()
    );
    let after = (
        reservation_raw_state(&mut connection, &lease, &operation, &active).await,
        redis::cmd("ZRANGE")
            .arg(&ready)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, String)>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &ready).await,
    );
    assert!(
        after == before,
        "failed heartbeat changed worker, reservation, or index state"
    );
}

#[tokio::test]
async fn redis_same_epoch_register_rejects_corrupt_stored_heartbeat_without_partial_effects() {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        return;
    };
    let prefix = format!("browserd-register-corrupt-heartbeat-{}", Uuid::new_v4());
    let worker_id = "register-corrupt-heartbeat-worker";
    let store = RedisEphemeralCoordinationStore::connect(
        RedisEphemeralConfig::new(endpoint.clone(), prefix.clone(), 8, Duration::from_secs(2))
            .expect("config"),
    )
    .await
    .expect("connect");
    let worker = register(&store, worker_id, 151, 100).await;
    let grant = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), vector(30))
                .expect("request"),
            Duration::from_secs(5),
        )
        .await
        .expect("reserve")
        .into_grant()
        .expect("grant");
    let lease = worker_key(&prefix, worker_id);
    let high_water = format!("{prefix}:{{browserd-worker}}:worker:{worker_id}:epoch");
    let active = worker_active_key(&prefix, worker_id);
    let operation = operation_key(&prefix, grant.reservation().operation_id());
    let ready = ready_index_key(&prefix, "redis-test-region", "redis-test-compat");
    let client = redis::Client::open(endpoint).expect("endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection");
    redis::cmd("HSET")
        .arg(&lease)
        .arg("heartbeat")
        .arg("{malformed-json")
        .arg("readiness")
        .arg("not-a-readiness")
        .query_async::<()>(&mut connection)
        .await
        .expect("corrupt stored heartbeat fixture");
    let before = (
        reservation_raw_state(&mut connection, &lease, &operation, &active).await,
        redis::cmd("GET")
            .arg(&high_water)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("highwater"),
        redis::cmd("ZRANGE")
            .arg(&ready)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, String)>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &ready).await,
    );
    assert_eq!(
        store
            .register_worker(
                worker.registration().clone(),
                WorkerHeartbeat::new(vector(100), 0, 0, WorkerReadiness::Ready).expect("heartbeat"),
                Duration::from_secs(20),
            )
            .await,
        Err(EphemeralCoordinationError::InvalidResponse)
    );
    let after = (
        reservation_raw_state(&mut connection, &lease, &operation, &active).await,
        redis::cmd("GET")
            .arg(&high_water)
            .query_async::<Option<Vec<u8>>>(&mut connection)
            .await
            .expect("highwater"),
        redis::cmd("ZRANGE")
            .arg(&ready)
            .arg(0_i8)
            .arg(-1_i8)
            .arg("WITHSCORES")
            .query_async::<Vec<(Vec<u8>, String)>>(&mut connection)
            .await
            .expect("ready"),
        absolute_expiry(&mut connection, &ready).await,
    );
    assert!(
        after == before,
        "corrupt same-epoch retry changed logical state"
    );
}
