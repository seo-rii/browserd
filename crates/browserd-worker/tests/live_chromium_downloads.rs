//! Real sandbox-enabled Chromium + actual bounded tmpfs, explicitly unqualified functional proof.
#![allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "common/bounded_scratch.rs"]
mod bounded_scratch;
#[path = "common/live_chromium.rs"]
mod live_chromium;

use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use browserd_sandbox::SANDBOX_SCRATCH_PATH;
use browserd_worker::{ActionExecutionResult, BrowserDownloadCompletion, ChromiumDriver};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn pending(browser: &live_chromium::LiveChromium) -> Vec<BrowserDownloadCompletion> {
    let driver = browser.driver.clone();
    let session = browser.session.clone();
    let fence = browser.fence.clone();
    tokio::task::spawn_blocking(move || driver.pending_browser_downloads(&session, &fence, 4))
        .await
        .unwrap()
        .unwrap()
}

async fn download(
    browser: &live_chromium::LiveChromium,
    selector: &str,
) -> BrowserDownloadCompletion {
    let node = browser.node(selector).await;
    assert!(matches!(
        browser
            .action(json!({"type":"click","node_ref":node}))
            .await,
        ActionExecutionResult::Succeeded(_)
    ));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let items = pending(browser).await;
        if let Some(item) = items.into_iter().next() {
            return item;
        }
        assert!(
            Instant::now() < deadline,
            "actual browser download did not complete"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
#[ignore = "requires explicit Chromium executable, user/mount/pid namespaces, and tmpfs; no production qualification"]
fn actual_owner_download_uses_bounded_scratch_and_exact_artifact_identity() {
    if !bounded_scratch::enter_or_spawn(
        "actual_owner_download_uses_bounded_scratch_and_exact_artifact_identity",
    ) {
        return;
    }
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        if request.len() >= 16 * 1024 { return; }
                        match tokio::time::timeout(Duration::from_secs(3), stream.read_u8()).await {
                            Ok(Ok(byte)) => request.push(byte),
                            _ => return,
                        }
                    }
                    let first = String::from_utf8_lossy(&request).lines().next().unwrap_or("").to_owned();
                    let (content_type, disposition, body): (&str, &str, &[u8]) = if first.starts_with("GET http://download.test/file ") {
                        ("application/octet-stream", "Content-Disposition: attachment; filename=\"../../untrusted-display.bin\"\r\n", "browserd-download-한국어".as_bytes())
                    } else if first.starts_with("GET http://download.test/empty ") {
                        ("application/octet-stream", "Content-Disposition: attachment; filename=empty.bin\r\n", b"")
                    } else if first.starts_with("GET http://download.test/ ") {
                        ("text/html", "", b"<!doctype html><a id='file' href='/file' download>file</a><a id='empty' href='/empty' download>empty</a>")
                    } else { return; };
                    let header = format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n{disposition}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    if stream.write_all(header.as_bytes()).await.is_ok() { let _ = stream.write_all(body).await; }
                });
            }
        });
        let browser = live_chromium::LiveChromium::start_with_downloads(proxy_address).await;
        browser.value(json!({"type":"navigate","url":"http://download.test/","wait_until":"load"})).await;
        for (selector, expected) in [("#file", "browserd-download-한국어".as_bytes()), ("#empty", b"".as_slice())] {
            let completion = download(&browser, selector).await;
            assert_eq!(completion.tenant_id, browser.tenant);
            assert_eq!(completion.session_id, browser.session);
            assert_eq!(completion.page_id, browser.page);
            assert_eq!(completion.fence, browser.fence);
            assert_eq!(pending(&browser).await, vec![completion.clone()], "polling does not mint another ArtifactId");
            let driver = browser.driver.clone();
            let read = completion.clone();
            let bytes = tokio::task::spawn_blocking(move || {
                let mut wrong = read.clone();
                wrong.artifact_id = browserd_core::ArtifactId::new();
                assert!(driver.open_browser_download(&wrong).is_err());
                let pinned = driver.open_browser_download(&read).unwrap();
                pinned.validate_unchanged().unwrap();
                let mut bytes = Vec::new();
                pinned.file().take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes).unwrap();
                pinned.validate_unchanged().unwrap();
                drop(pinned);
                driver.ack_browser_download(&read).unwrap();
                driver.ack_browser_download(&read).unwrap();
                bytes
            }).await.unwrap();
            assert_eq!(bytes, expected);
            assert!(pending(&browser).await.is_empty());
            assert!(!Path::new(SANDBOX_SCRATCH_PATH).join("downloads").join(&completion.guid).exists());
        }
        proxy.abort();
        browser.owner.shutdown_and_join(Duration::from_secs(5)).await.unwrap();
    });
}
