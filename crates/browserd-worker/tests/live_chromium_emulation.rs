#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Real options-aware owner coverage; this does not qualify a production artifact.
//! Native defaults cover OOPIF Intl inheritance and renderer replacement.
//! Worker startup and lifetime proofs are in live_chromium_workers.
#[path = "common/live_chromium.rs"]
mod live_chromium;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use browserd_worker::{WorkerSessionOptionsV1, WorkerViewport};
use live_chromium::LiveChromium;
use serde_json::{Value, json};

const USER_AGENT: &str = "browserd-emulation-live/1.0 (explicit-session-profile)";
const SAMPLE: &str = r#"
const requestHeaders = __REQUEST_HEADERS__;
const sampleProfile = () => ({
    label: new URL(location.href).searchParams.get('id') || 'top',
    locale: new Intl.DateTimeFormat().resolvedOptions().locale,
    timezone: new Intl.DateTimeFormat().resolvedOptions().timeZone,
    userAgent: navigator.userAgent,
    userAgentBrands: navigator.userAgentData?.brands || null,
    language: navigator.language,
    languages: [...navigator.languages],
    requestUserAgent: requestHeaders['user-agent'] || null,
    requestAcceptLanguage: requestHeaders['accept-language'] || null,
    requestSecChUa: requestHeaders['sec-ch-ua'] || null
});
const report = sampleProfile();
"#;

struct FixtureServer {
    url: String,
    routes: Arc<Mutex<BTreeMap<String, (String, String)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FixtureServer {
    fn new(address: &str) -> Self {
        let listener = std::net::TcpListener::bind((address, 0)).expect("loopback fixture");
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let routes = Arc::new(Mutex::new(BTreeMap::<String, (String, String)>::new()));
        let serving = routes.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut chunk = [0; 1024];
                        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(length) => request.extend_from_slice(&chunk[..length]),
                            }
                            if request.len() > 16384 {
                                break;
                            }
                        }
                        let request = String::from_utf8_lossy(&request);
                        let mut lines = request.split("\r\n");
                        let path = lines
                            .next()
                            .unwrap_or("")
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("/");
                        let headers: BTreeMap<String, String> = lines
                            .filter_map(|line| line.split_once(':'))
                            .map(|(name, value)| {
                                (name.to_ascii_lowercase(), value.trim().to_owned())
                            })
                            .collect();
                        let (mime, body) = serving
                            .lock()
                            .unwrap()
                            .get(path.split('?').next().unwrap())
                            .cloned()
                            .unwrap_or_else(|| ("text/plain".to_owned(), "fixture".to_owned()));
                        let body = body.replace(
                            "__REQUEST_HEADERS__",
                            &serde_json::to_string(&headers).unwrap(),
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {mime}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                            body.len()
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
            url,
            routes,
            stop,
            thread: Some(thread),
        }
    }

    fn route(&self, path: &str, mime: &str, body: String) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_owned(), (mime.to_owned(), body));
    }

    fn pages(&self, other: &Self) {
        self.route(
            "/frame",
            "text/html",
            format!("<script>{SAMPLE}parent.postMessage({{kind:'profile',report}},'*');addEventListener('message',event=>{{if(event.data?.kind==='read-profile')parent.postMessage({{kind:'fresh-profile',report:sampleProfile()}},'*')}});</script>"),
        );
        self.route("/top", "text/html", format!(
            "<script>{SAMPLE}window.profileReports=[report];addEventListener('message',event=>{{if(event.data?.kind==='profile')profileReports.push(event.data.report)}});</script><iframe src='/frame?id=same-origin'></iframe><iframe src='{}/frame?id=remote-a'></iframe><iframe src='{}/frame?id=remote-b'></iframe>",
            other.url, other.url
        ));
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn options(user_agent: Option<&str>) -> WorkerSessionOptionsV1 {
    WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1440,
            height: 900,
            device_scale_factor: 2,
        },
        locale: "ko-KR".to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: user_agent.map(str::to_owned),
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 1800,
        idle_timeout_seconds: 600,
        metadata: Default::default(),
    }
}

async fn reports(live: &LiveChromium) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let value = live.evaluate("window.profileReports").await;
        let reports = value.as_array().expect("fixture reports");
        if reports.len() == 4 {
            return reports.clone();
        }
        assert!(
            Instant::now() < deadline,
            "all frame reports must arrive: {value}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn assert_profile(reports: &[Value], user_agent: &str) {
    let mut labels: Vec<_> = reports
        .iter()
        .map(|report| report["label"].as_str().unwrap())
        .collect();
    labels.sort_unstable();
    assert_eq!(labels, ["remote-a", "remote-b", "same-origin", "top"]);
    for report in reports {
        assert_profile_fields(report, user_agent);
    }
}

fn assert_profile_fields(report: &Value, user_agent: &str) {
    assert_eq!(report["locale"], "ko-KR", "Intl locale: {report}");
    assert_eq!(report["timezone"], "Asia/Seoul", "timezone: {report}");
    assert_target_profile_fields(report, user_agent);
}

fn assert_target_profile_fields(report: &Value, user_agent: &str) {
    assert_eq!(report["language"], "ko-KR", "navigator language: {report}");
    assert_eq!(
        report["languages"][0], "ko-KR",
        "navigator languages: {report}"
    );
    assert!(
        report["requestAcceptLanguage"]
            .as_str()
            .unwrap_or("")
            .starts_with("ko-KR"),
        "request locale: {report}"
    );
    assert_eq!(
        report["userAgent"], report["requestUserAgent"],
        "JS and HTTP UA must agree: {report}"
    );
    assert_eq!(report["userAgent"], user_agent, "session UA: {report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires sandbox-enabled BROWSERD_TEST_CHROMIUM and native locale fixture resources"]
async fn live_owner_options_apply_to_oopif_reload_and_renderer_replacement() {
    let first = FixtureServer::new("127.0.0.1");
    let second = FixtureServer::new("127.0.0.2");
    first.pages(&second);
    second.pages(&first);
    let live = LiveChromium::start_with_options(options(Some(USER_AGENT))).await;
    live.value(json!({"type":"navigate","url":format!("{}/top",first.url),"wait_until":"load"}))
        .await;
    assert!(
        live.observed_target_count("iframe") >= 2,
        "two real OOPIF targets must bootstrap"
    );
    assert_profile(&reports(&live).await, USER_AGENT);
    live.value(json!({"type":"reload"})).await;
    assert_profile(&reports(&live).await, USER_AGENT);
    let previous_iframes = live.observed_target_count("iframe");
    live.value(json!({"type":"navigate","url":format!("{}/top",second.url),"wait_until":"load"}))
        .await;
    assert!(
        live.observed_target_count("iframe") > previous_iframes,
        "cross-site top navigation must attach replacement OOPIFs"
    );
    assert_profile(&reports(&live).await, USER_AGENT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires sandbox-enabled BROWSERD_TEST_CHROMIUM and native locale fixture resources"]
async fn live_owner_locale_without_custom_user_agent_is_consistent_across_frames() {
    let first = FixtureServer::new("127.0.0.1");
    let second = FixtureServer::new("127.0.0.2");
    first.pages(&second);
    second.pages(&first);
    let live = LiveChromium::start_with_options(options(None)).await;
    live.value(json!({"type":"navigate","url":format!("{}/top",first.url),"wait_until":"load"}))
        .await;
    assert!(
        live.observed_target_count("iframe") >= 2,
        "default-UA case must exercise OOPIFs"
    );
    assert_profile(&reports(&live).await, &live.default_user_agent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires sandbox-enabled BROWSERD_TEST_CHROMIUM and native locale fixture resources"]
async fn live_owner_oopif_profile_survives_first_same_renderer_frame_removal() {
    let first = FixtureServer::new("127.0.0.1");
    let second = FixtureServer::new("127.0.0.2");
    second.pages(&first);
    first.route(
        "/lifetime",
        "text/html",
        format!(
            r#"
        <script>{SAMPLE}
        window.profileReports=[report]; window.peerAfterRemoval=null;
        function frame(id) {{
            const element=document.createElement('iframe');element.id=id;
            element.src={remote}+'/frame?id='+id;document.body.append(element);return element;
        }}
        addEventListener('message',event=>{{
            if(event.data?.kind==='profile'){{
                profileReports.push(event.data.report);
                if(event.data.report.label==='owner')window.peerFrame=frame('peer');
            }}
            if(event.data?.kind==='fresh-profile')peerAfterRemoval=event.data.report;
        }});
        </script><body><script>window.ownerFrame=frame('owner');</script>
        "#,
            remote = serde_json::to_string(&second.url).unwrap()
        ),
    );
    let live = LiveChromium::start_with_options(options(Some(USER_AGENT))).await;
    live.value(
        json!({"type":"navigate","url":format!("{}/lifetime",first.url),"wait_until":"load"}),
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let before = loop {
        let reports = live.evaluate("profileReports").await;
        if let Some(peer) = reports
            .as_array()
            .unwrap()
            .iter()
            .find(|report| report["label"] == "peer")
            .filter(|_| live.targets.ready_target_count() == 3)
        {
            break peer.clone();
        }
        assert!(
            Instant::now() < deadline,
            "bounded sequential OOPIF setup: {reports}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(
        live.observed_target_count("iframe"),
        2,
        "owner then peer must use actual OOPIF targets"
    );
    live.evaluate("ownerFrame.remove();true").await;
    while live.targets.ready_target_count() != 2 {
        assert!(
            Instant::now() < deadline,
            "removed OOPIF must detach before fresh peer readback"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    live.evaluate("peerFrame.contentWindow.postMessage({kind:'read-profile'},'*');true")
        .await;
    let after = loop {
        let after = live.evaluate("peerAfterRemoval").await;
        if !after.is_null() {
            break after;
        }
        assert!(
            Instant::now() < deadline,
            "surviving peer must return a fresh profile"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(
        after["locale"], "ko-KR",
        "peer locale after override-owner removal; before={before}, after={after}"
    );
    assert_eq!(
        after["timezone"], "Asia/Seoul",
        "peer timezone after override-owner removal; before={before}, after={after}"
    );
    assert_profile_fields(&after, USER_AGENT);
}

async fn target_profile_navigation(user_agent: Option<&str>) {
    let first = FixtureServer::new("127.0.0.1");
    let second = FixtureServer::new("127.0.0.2");
    first.pages(&second);
    second.pages(&first);
    let live = LiveChromium::start_with_options(options(user_agent)).await;
    let expected_user_agent = user_agent.unwrap_or(&live.default_user_agent);
    let mut previous_iframes = 0;
    for (index, command) in [
        json!({"type":"navigate","url":format!("{}/top",first.url),"wait_until":"load"}),
        json!({"type":"reload"}),
        json!({"type":"navigate","url":format!("{}/top",second.url),"wait_until":"load"}),
    ]
    .into_iter()
    .enumerate()
    {
        live.value(command).await;
        let reports = reports(&live).await;
        let mut labels: Vec<_> = reports
            .iter()
            .map(|report| report["label"].as_str().unwrap())
            .collect();
        labels.sort_unstable();
        assert_eq!(labels, ["remote-a", "remote-b", "same-origin", "top"]);
        for report in &reports {
            assert_target_profile_fields(report, expected_user_agent);
            if user_agent.is_none() {
                assert!(
                    report["userAgentBrands"]
                        .as_array()
                        .is_some_and(|brands| !brands.is_empty()),
                    "preserving default UA must retain native client-hint brands: {report}"
                );
                assert!(
                    report["requestSecChUa"]
                        .as_str()
                        .is_some_and(|header| !header.is_empty()),
                    "preserving default UA must retain the native Sec-CH-UA request header: {report}"
                );
            }
            if report["label"] == "top" {
                assert_eq!(
                    report["locale"], "ko-KR",
                    "primary page retains its Intl locale: {report}"
                );
                assert_eq!(
                    report["timezone"], "Asia/Seoul",
                    "primary page retains its timezone: {report}"
                );
            }
        }
        assert_eq!(
            live.evaluate("[innerWidth,innerHeight,devicePixelRatio]")
                .await,
            json!([1440, 900, 2]),
            "child target configuration must preserve the primary viewport"
        );
        let iframes = live.observed_target_count("iframe");
        assert!(iframes >= 2, "actual OOPIF targets must participate");
        if index == 2 {
            assert!(
                iframes > previous_iframes,
                "cross-site navigation must attach replacement OOPIF targets"
            );
        }
        previous_iframes = iframes;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not security qualification"]
async fn live_owner_explicit_target_profile_survives_oopif_reload_and_renderer_replacement() {
    target_profile_navigation(Some(USER_AGENT)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not security qualification"]
async fn live_owner_default_ua_target_profile_survives_oopif_reload_and_renderer_replacement() {
    target_profile_navigation(None).await;
}
