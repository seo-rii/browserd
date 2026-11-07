#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

struct ScriptedResolver {
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
    calls: AtomicUsize,
    delay: Duration,
}

#[async_trait]
impl WebhookResolver for ScriptedResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(TransportError::Unavailable)
    }
}

struct RecordingPoster {
    requests: Mutex<Vec<(PreparedWebhook, ConnectPlan)>>,
    status: u16,
    delay: Duration,
}

#[async_trait]
impl PinnedWebhookPoster for RecordingPoster {
    async fn post(
        &self,
        request: PreparedWebhook,
        plan: ConnectPlan,
    ) -> Result<u16, TransportError> {
        self.requests.lock().unwrap().push((request, plan));
        tokio::time::sleep(self.delay).await;
        Ok(self.status)
    }
}

fn request(url: &str, timestamp: i64) -> PreparedWebhook {
    let body = br#"{"event_id":"019c0000-0000-7000-8000-000000000001","kind":"action.state_changed","resource":{"type":"action","id":"019c0000-0000-7000-8000-000000000002"}}"#.to_vec();
    PreparedWebhook {
        url: url.into(),
        signature: webhook_signature(&WebhookSigningSecret::new([37; 32]), timestamp, &body)
            .unwrap(),
        body,
        event_id: Uuid::parse_str("019c0000-0000-7000-8000-000000000001").unwrap(),
        key_id: Uuid::new_v4(),
        timestamp: timestamp.to_string(),
    }
}

fn fixture(
    answers: Vec<Vec<&str>>,
    status: u16,
) -> (
    ReqwestWebhookTransport,
    Arc<ScriptedResolver>,
    Arc<RecordingPoster>,
) {
    let resolver = Arc::new(ScriptedResolver {
        answers: Mutex::new(
            answers
                .into_iter()
                .map(|batch| batch.into_iter().map(|ip| ip.parse().unwrap()).collect())
                .collect(),
        ),
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
    });
    let poster = Arc::new(RecordingPoster {
        requests: Mutex::new(Vec::new()),
        status,
        delay: Duration::ZERO,
    });
    let transport = ReqwestWebhookTransport {
        resolver: resolver.clone(),
        poster: poster.clone(),
        budget: SEND_BUDGET,
    };
    (transport, resolver, poster)
}

#[test]
fn signatures_bind_exact_bytes_and_canonical_timestamp_with_a_bounded_replay_window() {
    let secret = WebhookSigningSecret::new([37; 32]);
    let body = br#"{"event_id":"example","kind":"action.state_changed"}"#;
    let signature = webhook_signature(&secret, 1000, body).unwrap();
    assert!(verify_webhook_signature(
        &secret, "1000", &signature, body, 1000
    ));
    assert!(verify_webhook_signature(
        &secret, "1000", &signature, body, 700
    ));
    assert!(verify_webhook_signature(
        &secret, "1000", &signature, body, 1300
    ));
    assert!(!verify_webhook_signature(
        &secret, "1000", &signature, body, 699
    ));
    assert!(!verify_webhook_signature(
        &secret, "1000", &signature, body, 1301
    ));
    assert!(!verify_webhook_signature(
        &secret, "1001", &signature, body, 1001
    ));
    assert!(!verify_webhook_signature(
        &secret, "01000", &signature, body, 1000
    ));
    assert!(!verify_webhook_signature(
        &secret, "-1000", &signature, body, 1000
    ));
    assert!(!verify_webhook_signature(
        &secret, "1000", &signature, b"{}", 1000
    ));
    assert!(!verify_webhook_signature(
        &WebhookSigningSecret::new([38; 32]),
        "1000",
        &signature,
        body,
        1000
    ));
    assert!(!verify_webhook_signature(
        &secret,
        "1000",
        "v2=invalid",
        body,
        1000
    ));
    assert!(!verify_webhook_signature(
        &secret, "1000", "v1=", body, 1000
    ));
}

#[tokio::test]
async fn each_attempt_rechecks_dns_and_keeps_original_host_sni_and_exact_signed_body() {
    let (transport, resolver, poster) =
        fixture(vec![vec!["1.1.1.1", "9.9.9.9"], vec!["10.0.0.1"]], 204);
    let original = request("https://hooks.example:8443/notify?private=value", 1000);
    let original_body = original.body.clone();
    assert_eq!(
        transport.send_prepared(original).await,
        WebhookAttemptOutcome::Delivered { status_code: 204 }
    );
    assert_eq!(
        transport
            .send_prepared(request(
                "https://hooks.example:8443/notify?private=value",
                1001
            ))
            .await,
        WebhookAttemptOutcome::PermanentFailure { status_code: None }
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    let seen = poster.requests.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (sent, plan) = &seen[0];
    assert_eq!(
        plan.inspected_socket_addr().as_socket_addr(),
        "1.1.1.1:8443".parse().unwrap()
    );
    assert_eq!(plan.declared_host(), "hooks.example");
    assert_eq!(plan.http_host_header(), "hooks.example:8443");
    assert_eq!(plan.tls_server_name(), Some("hooks.example"));
    assert_eq!(sent.body, original_body);
    assert!(verify_webhook_signature(
        &WebhookSigningSecret::new([37; 32]),
        &sent.timestamp,
        &sent.signature,
        &sent.body,
        1000
    ));
    let debug = format!("{sent:?}");
    assert!(!debug.contains("private=value"));
    assert!(!debug.contains(&sent.signature));
}

#[tokio::test]
async fn any_forbidden_dns_candidate_denies_the_entire_attempt_before_http() {
    for blocked in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "100.100.100.200",
        "::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::7f00:1",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "fec0::1",
        "100::1",
        "2001::1",
        "2001:2::1",
        "2002:0808:0808::1",
        "3fff::1",
    ] {
        let (transport, _, poster) = fixture(vec![vec!["1.1.1.1", blocked]], 200);
        assert_eq!(
            transport
                .send_prepared(request("https://hooks.example/notify", 1000))
                .await,
            WebhookAttemptOutcome::PermanentFailure { status_code: None },
            "blocked candidate {blocked}"
        );
        assert!(poster.requests.lock().unwrap().is_empty());
    }
    let answers = vec!["1.1.1.1"; MAX_DNS_CANDIDATES + 1];
    let (transport, _, poster) = fixture(vec![answers], 200);
    assert_eq!(
        transport
            .send_prepared(request("https://hooks.example/notify", 1000))
            .await,
        WebhookAttemptOutcome::PermanentFailure { status_code: None }
    );
    assert!(poster.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ordinary_global_ipv6_and_public_mapped_ipv4_remain_reachable() {
    for allowed in [
        "2607:f8b0:4004:800::200e",
        "2606:4700:4700::1111",
        "::ffff:1.1.1.1",
    ] {
        let (transport, _, poster) = fixture(vec![vec![allowed]], 204);
        assert_eq!(
            transport
                .send_prepared(request("https://hooks.example/notify", 1000))
                .await,
            WebhookAttemptOutcome::Delivered { status_code: 204 },
            "allowed candidate {allowed}"
        );
        assert_eq!(poster.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn non_https_credentials_fragments_and_control_bytes_never_reach_dns_or_http() {
    for url in [
        "http://hooks.example/",
        "https://user:password@hooks.example/",
        "https://@hooks.example/",
        "https://hooks.example/#fragment",
        "https://hooks.example/\nsecret",
        "file:///tmp/private",
    ] {
        let (transport, resolver, poster) = fixture(vec![vec!["1.1.1.1"]], 200);
        assert_eq!(
            transport.send_prepared(request(url, 1000)).await,
            WebhookAttemptOutcome::PermanentFailure { status_code: None }
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert!(poster.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn redirects_are_not_followed_and_only_transient_http_outcomes_retry() {
    for status in [204, 302, 307, 400, 403, 410, 408, 425, 429, 500, 503] {
        let (transport, resolver, poster) = fixture(vec![vec!["1.1.1.1"]], status);
        let result = transport
            .send_prepared(request("https://hooks.example/notify", 1000))
            .await;
        let expected = match status {
            200..=299 => WebhookAttemptOutcome::Delivered {
                status_code: status,
            },
            408 | 425 | 429 | 500..=599 => WebhookAttemptOutcome::TransientFailure {
                status_code: Some(status),
            },
            _ => WebhookAttemptOutcome::PermanentFailure {
                status_code: Some(status),
            },
        };
        assert_eq!(result, expected);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(poster.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn one_total_deadline_bounds_dns_and_an_already_started_http_effect() {
    let resolver = Arc::new(ScriptedResolver {
        answers: Mutex::new(VecDeque::from([vec!["1.1.1.1".parse().unwrap()]])),
        calls: AtomicUsize::new(0),
        delay: Duration::from_secs(60),
    });
    let poster = Arc::new(RecordingPoster {
        requests: Mutex::new(Vec::new()),
        status: 200,
        delay: Duration::ZERO,
    });
    let transport = ReqwestWebhookTransport {
        resolver,
        poster: poster.clone(),
        budget: Duration::from_millis(20),
    };
    assert_eq!(
        transport
            .send_prepared(request("https://hooks.example/", 1000))
            .await,
        WebhookAttemptOutcome::TransportUnknown
    );
    assert!(poster.requests.lock().unwrap().is_empty());
    let resolver = Arc::new(ScriptedResolver {
        answers: Mutex::new(VecDeque::from([vec!["1.1.1.1".parse().unwrap()]])),
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
    });
    let poster = Arc::new(RecordingPoster {
        requests: Mutex::new(Vec::new()),
        status: 200,
        delay: Duration::from_secs(60),
    });
    let transport = ReqwestWebhookTransport {
        resolver,
        poster: poster.clone(),
        budget: Duration::from_millis(20),
    };
    assert_eq!(
        transport
            .send_prepared(request("https://hooks.example/", 1000))
            .await,
        WebhookAttemptOutcome::TransportUnknown
    );
    assert_eq!(poster.requests.lock().unwrap().len(), 1);
}
