#![allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "common/live_chromium.rs"]
mod live_chromium;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use browserd_worker::{
    ActionExecutionResult, ApprovedActionError, ChromiumDriver, WorkerSessionOptionsV1,
    WorkerViewport,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Explicitly unqualified functional evidence: a real sandbox-enabled Chromium process
// and a controlled HTTP origin, without any production launch or approval receipt.
#[tokio::test]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM"]
async fn real_owner_privileged_evaluate_uses_trusted_origin_and_never_replays_unknown_effects() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Chromium may open an idle preconnection; it must not block other requests.
            tokio::spawn(async move {
                let mut request = [0; 8192];
                if !matches!(tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request)).await, Ok(Ok(count)) if count > 0)
                {
                    return;
                }
                let body = "<!doctype html><meta charset=utf-8><title>evaluate fixture</title><script>window.counter=0;</script>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    let live = live_chromium::LiveChromium::start_with_options(WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1280,
            height: 720,
            device_scale_factor: 1,
        },
        locale: "ko-KR".to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: None,
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "privileged".to_owned(),
        ttl_seconds: 1800,
        idle_timeout_seconds: 600,
        metadata: Default::default(),
    })
    .await;
    live.value(json!({"type":"navigate","url":format!("{origin}/owned"),"wait_until":"load"}))
        .await;
    live.evaluate("Object.defineProperty(window, 'globalThis', {value:{location:{origin:'https://forged.invalid'}}, configurable:true}); true").await;
    let admissions = Arc::new(AtomicUsize::new(0));
    for (expression, permit, expected_count, expected_unknown) in [
        ("window.counter += 100", false, 0, false),
        (
            "throw new Error('untrusted exception content')",
            true,
            0,
            true,
        ),
        (
            "window.counter++; throw new Error('untrusted exception content')",
            true,
            1,
            true,
        ),
        ("({counter:window.counter, label:'한글'})", true, 1, false),
    ] {
        let driver = live.driver.clone();
        let tenant = live.tenant.clone();
        let session = live.session.clone();
        let page = live.page.clone();
        let fence = live.fence.clone();
        let expected_origin = origin.clone();
        let admissions = admissions.clone();
        let payload =
            serde_json::to_vec(&json!({"type":"evaluate","expression":expression})).unwrap();
        let result = tokio::task::spawn_blocking(move || {
            driver.execute_privileged_evaluate_until(
                &tenant,
                &session,
                &page,
                &fence,
                &payload,
                Instant::now() + Duration::from_secs(5),
                &mut |observed| {
                    assert_eq!(observed.current_origin.as_str(), expected_origin);
                    assert_eq!(
                        observed.resolved_ips,
                        vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
                    );
                    admissions.fetch_add(1, Ordering::SeqCst);
                    if permit {
                        Ok(())
                    } else {
                        Err(ApprovedActionError::DispatchRevoked)
                    }
                },
            )
        })
        .await
        .unwrap();
        if !permit {
            assert_eq!(result, Err(ApprovedActionError::DispatchRevoked));
        } else if expected_unknown {
            assert_eq!(result, Ok(ActionExecutionResult::OutcomeUnknown));
        } else {
            let bytes = match result.unwrap() {
                ActionExecutionResult::Succeeded(bytes) => Some(bytes),
                _ => None,
            }
            .expect("pure evaluate should succeed");
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value, json!({"value":{"counter":1,"label":"한글"}}));
        }
        assert_eq!(live.evaluate("window.counter").await, expected_count);
        assert!(
            !live.targets.is_tainted(),
            "script exceptions must retain the observation path"
        );
    }
    assert_eq!(
        admissions.load(Ordering::SeqCst),
        4,
        "each request must be admitted at most once"
    );
    server.abort();
}
