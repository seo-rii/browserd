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

/// Sends through the production request path to a plain-HTTP loopback receiver. Such a
/// receiver can pass neither the public-address policy nor certificate verification, so
/// only the pinned HTTPS client is swapped out.
struct LocalReceiverPoster {
    url: String,
}

#[async_trait]
impl PinnedWebhookPoster for LocalReceiverPoster {
    async fn post(
        &self,
        mut request: PreparedWebhook,
        _plan: ConnectPlan,
    ) -> Result<u16, TransportError> {
        request.url = self.url.clone();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        post_signed(&client, request).await
    }
}

#[derive(Clone, Copy, Debug)]
enum ReplyBody {
    Sized(usize),
    Chunked(usize),
    /// Declares the length but closes the connection after the first KiB.
    Truncated(usize),
}

/// Answers one webhook request and yields the raw request bytes it received.
async fn local_receiver(status: u16, body: ReplyBody) -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/notify", listener.local_addr().unwrap());
    let served = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "request ended early");
            received.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&received).to_ascii_lowercase();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .map_or(0, |value| value.parse::<usize>().unwrap());
                if received.len() >= end + 4 + length {
                    break;
                }
            }
        }
        let mut reply = format!("HTTP/1.1 {status} Reply\r\nconnection: close\r\n").into_bytes();
        match body {
            ReplyBody::Sized(len) => {
                reply.extend(format!("content-length: {len}\r\n\r\n").bytes());
                reply.extend(std::iter::repeat_n(b'x', len));
            }
            ReplyBody::Chunked(len) => {
                reply.extend(b"transfer-encoding: chunked\r\n\r\n");
                for _ in 0..len / 1024 {
                    reply.extend(b"400\r\n");
                    reply.extend([b'x'; 1024]);
                    reply.extend(b"\r\n");
                }
                reply.extend(b"0\r\n\r\n");
            }
            ReplyBody::Truncated(len) => {
                reply.extend(format!("content-length: {len}\r\n\r\n").bytes());
                reply.extend([b'x'; 1024]);
            }
        }
        // The sender may stop reading once its cap is reached, so the tail is best effort.
        let _ = stream.write_all(&reply).await;
        let _ = stream.shutdown().await;
        String::from_utf8(received).unwrap()
    });
    (url, served)
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

#[tokio::test]
async fn the_status_line_alone_classifies_a_reply_whatever_its_body() {
    const LARGE: usize = 64 * 1024;
    for (status, body, expected) in [
        (
            200,
            ReplyBody::Sized(LARGE),
            WebhookAttemptOutcome::Delivered { status_code: 200 },
        ),
        (
            200,
            ReplyBody::Chunked(LARGE),
            WebhookAttemptOutcome::Delivered { status_code: 200 },
        ),
        (
            202,
            ReplyBody::Truncated(LARGE),
            WebhookAttemptOutcome::Delivered { status_code: 202 },
        ),
        (
            204,
            ReplyBody::Sized(0),
            WebhookAttemptOutcome::Delivered { status_code: 204 },
        ),
        (
            503,
            ReplyBody::Sized(LARGE),
            WebhookAttemptOutcome::TransientFailure {
                status_code: Some(503),
            },
        ),
        (
            400,
            ReplyBody::Chunked(LARGE),
            WebhookAttemptOutcome::PermanentFailure {
                status_code: Some(400),
            },
        ),
    ] {
        let (url, served) = local_receiver(status, body).await;
        let (mut transport, _, _) = fixture(vec![vec!["1.1.1.1"]], 0);
        transport.poster = Arc::new(LocalReceiverPoster { url });
        assert_eq!(
            transport
                .send_prepared(request("https://hooks.example/notify", 1000))
                .await,
            expected,
            "{status} with {body:?}"
        );
        let received = served.await.unwrap();
        assert!(
            received.contains("browserd-webhook-event-id: 019c0000-0000-7000-8000-000000000001")
        );
    }
}
