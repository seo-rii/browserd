#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

use browserd_artifacts::{DownloadTokenError, OneTimeDownloadTokenRegistry};
use chrono::{DateTime, TimeDelta, Utc};

use common::artifact_fixture;

fn fixed_now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000, 0).expect("fixed timestamp must be valid")
}

#[tokio::test]
async fn download_token_can_be_consumed_exactly_once() {
    let fixture = artifact_fixture();
    let registry = OneTimeDownloadTokenRegistry::new();
    let now = fixed_now();
    let token = registry
        .issue(&fixture.key, now + TimeDelta::minutes(5))
        .await;

    assert_eq!(
        registry
            .consume(&token, &fixture.namespace, now)
            .await
            .expect("fresh owner-scoped token should be consumable"),
        fixture.key
    );
    assert_eq!(
        registry.consume(&token, &fixture.namespace, now).await,
        Err(DownloadTokenError::Unavailable)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_token_consumers_have_one_winner() {
    const CONSUMERS: usize = 32;

    let fixture = artifact_fixture();
    let registry = Arc::new(OneTimeDownloadTokenRegistry::new());
    let now = fixed_now();
    let token = registry
        .issue(&fixture.key, now + TimeDelta::minutes(5))
        .await;
    let mut tasks = Vec::with_capacity(CONSUMERS);

    for _ in 0..CONSUMERS {
        let registry = registry.clone();
        let token = token.clone();
        let namespace = fixture.namespace.clone();
        tasks.push(tokio::spawn(async move {
            registry.consume(&token, &namespace, now).await
        }));
    }

    let mut successes = 0;
    let mut unavailable = 0;
    for task in tasks {
        match task.await.expect("consumer task should not panic") {
            Ok(key) => {
                assert_eq!(key, fixture.key);
                successes += 1;
            }
            Err(DownloadTokenError::Unavailable) => unavailable += 1,
        }
    }

    assert_eq!(successes, 1);
    assert_eq!(unavailable, CONSUMERS - 1);
}

#[tokio::test]
async fn wrong_namespace_cannot_consume_or_burn_the_owners_token() {
    let owner = artifact_fixture();
    let attacker = artifact_fixture();
    let registry = OneTimeDownloadTokenRegistry::new();
    let now = fixed_now();
    let token = registry
        .issue(&owner.key, now + TimeDelta::minutes(5))
        .await;

    assert_eq!(
        registry.consume(&token, &attacker.namespace, now).await,
        Err(DownloadTokenError::Unavailable)
    );
    assert_eq!(
        registry
            .consume(&token, &owner.namespace, now)
            .await
            .expect("wrong-scope attempt must not burn the owner's token"),
        owner.key
    );
}

#[tokio::test]
async fn expired_token_is_never_consumable() {
    let fixture = artifact_fixture();
    let registry = OneTimeDownloadTokenRegistry::new();
    let now = fixed_now();
    let token = registry
        .issue(&fixture.key, now - TimeDelta::seconds(1))
        .await;

    assert_eq!(
        registry.consume(&token, &fixture.namespace, now).await,
        Err(DownloadTokenError::Unavailable)
    );
}
