#![allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "common/live_chromium.rs"]
mod live_chromium;

use browserd_artifacts::{ArtifactChecksum, ArtifactKey, ArtifactObjectGeneration};
use browserd_core::{ArtifactId, SessionId, WorkerId};
use browserd_features::{CaptureCommand, CaptureDelivery, ScreenshotOptions};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ArtifactStoreReceipt, ArtifactStoreRequest, ChromiumDriver, DependencyError,
    GeneratedArtifactRequest, GeneratedArtifactSink, GeneratedCaptureResult, SandboxClient,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Store {
    bytes: Arc<Mutex<Vec<u8>>>,
    chunks: Arc<Mutex<Vec<usize>>>,
}
struct Sink {
    request: GeneratedArtifactRequest,
    bytes: Arc<Mutex<Vec<u8>>>,
    chunks: Arc<Mutex<Vec<usize>>>,
}
#[async_trait::async_trait]
impl GeneratedArtifactSink for Sink {
    async fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), DependencyError> {
        assert!(bytes.len() <= 64 * 1024);
        self.chunks.lock().unwrap().push(bytes.len());
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(())
    }
    async fn finish(&mut self) -> Result<ArtifactStoreReceipt, DependencyError> {
        let bytes = self.bytes.lock().unwrap();
        ArtifactStoreReceipt::new_generated(
            self.request.key().clone(),
            bytes.len() as u64,
            ArtifactChecksum::new(Sha256::digest(&*bytes).into()),
            self.request.content_type(),
            ArtifactObjectGeneration::new([3; 32]),
        )
        .map_err(|_| DependencyError::Rejected)
    }
    async fn abort(&mut self) -> Result<(), DependencyError> {
        self.bytes.lock().unwrap().clear();
        Ok(())
    }
}
impl SandboxClient for Store {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn cleanup(
        &self,
        _: &SessionId,
        _: browserd_sandbox::CleanupReason,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn heartbeat(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn store_artifact(
        &self,
        _: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn begin_generated_artifact(
        &self,
        request: &GeneratedArtifactRequest,
    ) -> Result<Box<dyn GeneratedArtifactSink>, DependencyError> {
        Ok(Box::new(Sink {
            request: request.clone(),
            bytes: self.bytes.clone(),
            chunks: self.chunks.clone(),
        }))
    }
}
async fn capture(
    live: &live_chromium::LiveChromium,
    command: CaptureCommand,
    store: Arc<Store>,
) -> GeneratedCaptureResult {
    let driver = live.driver.clone();
    let session = live.session.clone();
    let page = live.page.clone();
    let request = GeneratedArtifactRequest::new(
        ArtifactKey::new(live.tenant.clone(), session.clone(), ArtifactId::new()),
        live.fence.clone(),
        command.content_type(),
        "live-functional-capture",
        command.maximum_bytes(),
    )
    .unwrap();
    tokio::task::spawn_blocking(move || {
        driver.execute_capture_until(
            &session,
            &page,
            command,
            request,
            store,
            Instant::now() + Duration::from_secs(15),
        )
    })
    .await
    .unwrap()
    .expect("real owner capture")
}

#[tokio::test]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM"]
async fn real_owner_screenshot_pdf_and_scrape_produce_valid_bounded_content() {
    let live = live_chromium::LiveChromium::start().await;
    live.evaluate("document.documentElement.lang='ko'; document.title='owner capture'; document.body.innerHTML='<h1>한글 owner capture</h1><a href=\"https://example.invalid/item\">link</a>'; true").await;
    let store = Arc::new(Store::default());
    let shot = capture(
        &live,
        CaptureCommand::Screenshot {
            options: ScreenshotOptions {
                delivery: CaptureDelivery::Artifact,
                ..Default::default()
            },
        },
        store.clone(),
    )
    .await;
    assert_eq!(&store.bytes.lock().unwrap()[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(
        shot.receipt.as_ref().unwrap().detected_content_type(),
        "image/png"
    );
    assert!(shot.cleanup.is_some());
    let store = Arc::new(Store::default());
    let pdf = capture(
        &live,
        CaptureCommand::Pdf {
            options: Default::default(),
        },
        store.clone(),
    )
    .await;
    assert!(store.bytes.lock().unwrap().starts_with(b"%PDF-"));
    assert_eq!(
        pdf.receipt.as_ref().unwrap().detected_content_type(),
        "application/pdf"
    );
    assert!(
        store
            .chunks
            .lock()
            .unwrap()
            .iter()
            .all(|size| *size <= 64 * 1024)
    );
    let store = Arc::new(Store::default());
    let scrape = capture(
        &live,
        CaptureCommand::Scrape {
            options: Default::default(),
        },
        store.clone(),
    )
    .await;
    let data: Value = serde_json::from_slice(&store.bytes.lock().unwrap()).unwrap();
    assert!(
        data["text"]
            .as_str()
            .unwrap()
            .contains("한글 owner capture")
    );
    assert_eq!(data["metadata"]["title"], "owner capture");
    assert_eq!(data["resources"], "not_fetched");
    assert_eq!(data["scripts"], "unchanged");
    assert_eq!(data["links"][0]["url"], "https://example.invalid/item");
    assert_eq!(
        scrape.receipt.as_ref().unwrap().detected_content_type(),
        "application/json"
    );
    assert!(
        serde_json::from_slice::<Value>(&scrape.result)
            .unwrap()
            .get("artifact_id")
            .is_some()
    );
    assert_eq!(
        live.evaluate("document.title").await,
        json!("owner capture")
    );
}

// Controlled loopback fixtures exercise Chromium's proxy behavior. They are not
// an approved production proxy, an outer sandbox, or a security qualification.
mod routed_proxy_functional {
    use super::*;
    use browserd_worker::ActionExecutionResult;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct HttpFixture {
        address: SocketAddr,
        connections: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl HttpFixture {
        fn new(marker: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("private loopback fixture");
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let connections = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let accepted = connections.clone();
            let observed = requests.clone();
            let stopping = stop.clone();
            let thread = std::thread::spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            accepted.fetch_add(1, Ordering::AcqRel);
                            stream
                                .set_read_timeout(Some(Duration::from_millis(200)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_millis(200)))
                                .unwrap();
                            let mut request = Vec::new();
                            while request.len() < 4096 && !request.ends_with(b"\r\n\r\n") {
                                let mut byte = [0];
                                if !matches!(stream.read(&mut byte), Ok(1)) {
                                    break;
                                }
                                request.push(byte[0]);
                            }
                            if let Some(line) = String::from_utf8_lossy(&request).lines().next() {
                                let mut requests = observed.lock().unwrap();
                                if requests.len() < 32 {
                                    requests.push(line.to_owned());
                                }
                            }
                            let body = format!("<!doctype html><html><body>{marker}</body></html>");
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(response.as_bytes());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                address,
                connections,
                requests,
                stop,
                thread: Some(thread),
            }
        }

        fn prove_reachable_and_reset(&self, marker: &str) {
            let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(1))
                .expect("origin is reachable without the proxy");
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .write_all(
                    format!(
                        "GET /control-readiness HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        self.address
                    )
                    .as_bytes(),
                )
                .unwrap();
            let mut response = String::new();
            stream.take(4096).read_to_string(&mut response).unwrap();
            assert!(response.contains(marker));
            assert_eq!(self.connections.load(Ordering::Acquire), 1);
            self.connections.store(0, Ordering::Release);
            self.requests.lock().unwrap().clear();
        }

        fn shutdown(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.join().expect("HTTP fixture stopped");
            }
        }
    }

    impl Drop for HttpFixture {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not production egress qualification"]
    async fn real_routed_owner_has_no_loopback_proxy_bypass_or_direct_fallback() {
        let origin = HttpFixture::new("direct-origin-must-not-be-reached");
        origin.prove_reachable_and_reset("direct-origin-must-not-be-reached");
        let mut proxy = HttpFixture::new("fixed-proxy-marker");
        let live = live_chromium::LiveChromium::start_with_proxy(proxy.address).await;
        let first_url = format!("http://{}/through-proxy", origin.address);
        live.value(json!({"type":"navigate", "url":first_url, "wait_until":"domcontentloaded"}))
            .await;
        assert_eq!(
            live.evaluate("document.body.textContent").await,
            "fixed-proxy-marker"
        );
        assert!(
            proxy
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| { request == &format!("GET {first_url} HTTP/1.1") }),
            "Chromium must send the absolute origin URL to the configured proxy"
        );
        assert_eq!(
            origin.connections.load(Ordering::Acquire),
            0,
            "<-loopback> must prevent implicit localhost proxy bypass"
        );

        // The origin stays reachable and the new URL cannot reuse the no-store
        // proxy response. Only the fixed proxy's listener is stopped.
        proxy.shutdown();
        let result = live
            .action(json!({
                "type":"navigate",
                "url":format!("http://{}/after-proxy-stop", origin.address),
                "wait_until":"domcontentloaded",
            }))
            .await;
        assert!(
            matches!(
                result,
                ActionExecutionResult::FailedKnown(ref reason) if reason == "browser_operation_rejected"
            ),
            "unavailable fixed proxy must cause a known network rejection: {result:?}"
        );
        assert!(
            live.targets.is_ready(),
            "a transport failure cannot stand in for proxy denial"
        );
        assert_eq!(
            origin.connections.load(Ordering::Acquire),
            0,
            "Chromium must never fall back to DIRECT when the fixed proxy is unavailable"
        );
    }
}
