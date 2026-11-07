#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Actual Native owner worker coverage; local functional evidence, not qualification.
#[path = "common/live_chromium.rs"]
mod live_chromium;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use browserd_worker::{ChromiumDriver, WorkerSessionOptionsV1, WorkerViewport};
use live_chromium::LiveChromium;
use serde_json::{Value, json};

const CUSTOM_UA: &str = "browserd-native-owner-worker/1.0";
const FIRST_PROFILE: &str = r#"const first={
    locale:new Intl.DateTimeFormat().resolvedOptions().locale,
    timezone:new Intl.DateTimeFormat().resolvedOptions().timeZone,
    language:navigator.language,languages:[...navigator.languages],
    userAgent:navigator.userAgent,scriptUrl:location.href
};
const evidence=fetch('/first?sample='+encodeURIComponent(JSON.stringify(first)));
"#;

#[derive(Clone, Debug)]
struct Request {
    path: String,
    headers: BTreeMap<String, String>,
}

#[derive(Default)]
struct Observations {
    requests: Vec<Request>,
    first: Vec<Value>,
    error: Option<String>,
}

struct WorkerFixture {
    url: String,
    observed: Arc<Mutex<Observations>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WorkerFixture {
    fn new(kind: &'static str, nested: bool) -> Self {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let observed = Arc::new(Mutex::new(Observations::default()));
        let recorded = observed.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => {
                        recorded.lock().unwrap().error = Some(error.to_string());
                        break;
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut raw = Vec::with_capacity(16 * 1024);
                let mut chunk = [0; 1024];
                while !raw.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(length) if raw.len() + length <= 16 * 1024 => {
                            raw.extend_from_slice(&chunk[..length]);
                        }
                        Ok(_) => {
                            recorded.lock().unwrap().error =
                                Some("HTTP request bound exceeded".into());
                            break;
                        }
                    }
                }
                let request = String::from_utf8_lossy(&raw);
                let mut lines = request.split("\r\n");
                let path = lines
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/");
                let headers: BTreeMap<String, String> = lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
                    .collect();
                {
                    let mut observed = recorded.lock().unwrap();
                    if observed.requests.len() >= 256 {
                        observed.error = Some("request count bound exceeded".into());
                        break;
                    }
                    observed.requests.push(Request {
                        path: path.to_owned(),
                        headers,
                    });
                    if path.starts_with("/first?") {
                        let parsed = url::Url::parse(&format!("http://fixture{path}")).unwrap();
                        let sample = parsed
                            .query_pairs()
                            .find(|(key, _)| key == "sample")
                            .unwrap()
                            .1;
                        match serde_json::from_str(&sample) {
                            Ok(value) => observed.first.push(value),
                            Err(error) => observed.error = Some(error.to_string()),
                        }
                    }
                }
                let (mime, body) = match path.split('?').next().unwrap() {
                    "/top" => {
                        let create = match kind {
                            "worker" => "window.child=new Worker('/worker.js');",
                            "shared_worker" => {
                                "window.child=new SharedWorker('/worker.js');child.port.start();"
                            }
                            "service_worker" => {
                                "navigator.serviceWorker.register('/worker.js').then(r=>window.registration=r).catch(()=>{});"
                            }
                            _ => panic!("invalid fixture worker kind"),
                        };
                        (
                            "text/html",
                            format!("<!doctype html><script>{create}</script>"),
                        )
                    }
                    "/worker.js" => {
                        let continuation = match kind {
                            "worker" if nested => {
                                "if(!location.search)self.child=new Worker('/worker.js?nested=1');onmessage=()=>postMessage(first);"
                            }
                            "worker" => "onmessage=()=>postMessage(first);",
                            "shared_worker" => {
                                "onconnect=e=>{e.ports[0].start();e.ports[0].postMessage(first)};"
                            }
                            "service_worker" => {
                                "addEventListener('install',e=>e.waitUntil(evidence.then(()=>skipWaiting())));addEventListener('activate',e=>e.waitUntil(clients.claim()));"
                            }
                            _ => panic!("invalid fixture worker kind"),
                        };
                        ("text/javascript", format!("{FIRST_PROFILE}{continuation}"))
                    }
                    _ => ("text/plain", "fixture".to_owned()),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {mime}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            url,
            observed,
            stop,
            thread: Some(thread),
        }
    }

    async fn wait_first(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            {
                let observed = self.observed.lock().unwrap();
                assert!(
                    observed.error.is_none(),
                    "fixture error: {:?}",
                    observed.error
                );
                if observed.first.len() == count {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "first worker script never reported; observed {} scripts and {} requests",
                    observed.first.len(),
                    observed.requests.len()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn assert_profiles_and_requests(&self, count: usize, expected_ua: &str) {
        let observed = self.observed.lock().unwrap();
        assert_eq!(observed.first.len(), count);
        for profile in &observed.first {
            assert_eq!(profile["locale"], "ko-KR", "first script: {profile}");
            assert_eq!(profile["timezone"], "Asia/Seoul");
            assert_eq!(profile["language"], "ko-KR");
            assert_eq!(profile["languages"], json!(["ko-KR"]));
            assert_eq!(profile["userAgent"], expected_ua);
        }
        let scripts: Vec<_> = observed
            .requests
            .iter()
            .filter(|r| r.path.starts_with("/worker.js"))
            .collect();
        let fetches: Vec<_> = observed
            .requests
            .iter()
            .filter(|r| r.path.starts_with("/first?"))
            .collect();
        assert_eq!(
            scripts.len(),
            count,
            "all initial worker script requests must be observed"
        );
        assert_eq!(
            fetches.len(),
            count,
            "all first-script network effects must be observed"
        );
        for request in scripts.iter().chain(&fetches) {
            assert_eq!(
                request.headers.get("user-agent").map(String::as_str),
                Some(expected_ua),
                "first network effect: {request:?}"
            );
            assert_eq!(
                request
                    .headers
                    .get("accept-language")
                    .and_then(|header| header.split(',').next())
                    .map(str::trim),
                Some("ko-KR"),
                "first network effect: {request:?}"
            );
        }
    }
}

impl Drop for WorkerFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn options(custom_ua: bool) -> WorkerSessionOptionsV1 {
    WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1280,
            height: 720,
            device_scale_factor: 1,
        },
        locale: "ko-KR".to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: custom_ua.then(|| CUSTOM_UA.to_owned()),
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

async fn first_script(kind: &'static str, custom_ua: bool, nested: bool) {
    let fixture = WorkerFixture::new(kind, nested);
    let live = LiveChromium::start_with_options(options(custom_ua)).await;
    let expected_ua = if custom_ua {
        CUSTOM_UA
    } else {
        &live.default_user_agent
    };
    live.value(json!({"type":"navigate","url":format!("{}/top",fixture.url),"wait_until":"load"}))
        .await;
    let count = if nested { 2 } else { 1 };
    fixture.wait_first(count).await;
    fixture.assert_profiles_and_requests(count, expected_ua);
    assert_eq!(
        live.observed_target_count(kind),
        count,
        "worker must attach exactly once"
    );
    assert!(live.targets.is_ready());
    assert!(!live.targets.is_tainted());
    dispose_and_verify(&live).await;
}

async fn dispose_and_verify(live: &LiveChromium) {
    let backend = live.owner.target_manager_backend();
    let driver = live.driver.clone();
    let session = live.session.clone();
    let tenant = live.tenant.clone();
    let fence = live.fence.clone();
    tokio::task::spawn_blocking(move || {
        driver
            .close_context_fenced(&session, &fence)
            .expect("dispose exact owned worker context");
        backend
            .verify_context_disposed(&tenant, &session, &fence)
            .expect("all worker targets and context must be absent before cleanup succeeds");
    })
    .await
    .unwrap();
    assert_eq!(live.targets.ready_target_count(), 0);
    assert!(!live.targets.is_tainted());
}

async fn wait_target_count(live: &LiveChromium, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(live.targets.is_ready(), "owner admission must remain open");
        assert!(!live.targets.is_tainted());
        let current = live.targets.ready_target_count();
        if current == count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected {count} live targets, observed {current}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_dedicated_worker_first_script_default_ua() {
    first_script("worker", false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_dedicated_worker_first_script_custom_ua() {
    first_script("worker", true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_shared_worker_first_script_default_ua() {
    first_script("shared_worker", false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_shared_worker_first_script_custom_ua() {
    first_script("shared_worker", true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_service_worker_first_script_default_ua() {
    first_script("service_worker", false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_service_worker_first_script_custom_ua() {
    first_script("service_worker", true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_nested_dedicated_workers_first_script_custom_ua() {
    first_script("worker", true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_shared_worker_last_client_navigation_and_reconnect_gets_new_target() {
    let fixture = WorkerFixture::new("shared_worker", false);
    let live = LiveChromium::start_with_options(options(true)).await;
    live.value(json!({"type":"navigate","url":format!("{}/top",fixture.url),"wait_until":"load"}))
        .await;
    fixture.wait_first(1).await;
    wait_target_count(&live, 2).await;
    let first_ids = live.observed_target_ids("shared_worker");
    assert_eq!(first_ids.len(), 1);
    assert!(live.targets.has_ready_target(&first_ids[0]));

    live.value(json!({"type":"navigate","url":format!("{}/idle",fixture.url),"wait_until":"load"}))
        .await;
    wait_target_count(&live, 1).await;
    assert!(
        !live.targets.has_ready_target(&first_ids[0]),
        "last client removal must retire its worker route"
    );
    live.value(json!({"type":"navigate","url":format!("{}/top?restart=1",fixture.url),"wait_until":"load"})).await;
    fixture.wait_first(2).await;
    wait_target_count(&live, 2).await;
    let ids = live.observed_target_ids("shared_worker");
    assert_eq!(ids.len(), 2, "each replacement attaches exactly once");
    assert_eq!(ids[0], first_ids[0]);
    assert_ne!(
        ids[0], ids[1],
        "the reconnected worker must have a new target identity"
    );
    assert!(live.targets.has_ready_target(&ids[1]));
    fixture.assert_profiles_and_requests(2, CUSTOM_UA);
    dispose_and_verify(&live).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn native_service_worker_outlives_navigation_and_reregistration_retains_both_targets_until_dispose()
 {
    let fixture = WorkerFixture::new("service_worker", false);
    let live = LiveChromium::start_with_options(options(true)).await;
    live.value(json!({"type":"navigate","url":format!("{}/top",fixture.url),"wait_until":"load"}))
        .await;
    fixture.wait_first(1).await;
    assert_eq!(
        live.evaluate("navigator.serviceWorker.ready.then(()=>true)")
            .await,
        json!(true)
    );
    wait_target_count(&live, 2).await;
    let first_ids = live.observed_target_ids("service_worker");
    assert_eq!(first_ids.len(), 1);

    live.value(json!({"type":"navigate","url":format!("{}/idle",fixture.url),"wait_until":"load"}))
        .await;
    assert_eq!(
        live.evaluate("location.href").await,
        json!(format!("{}/idle", fixture.url))
    );
    assert!(
        live.targets.has_ready_target(&first_ids[0]),
        "service lifetime must not be tied to its creating document"
    );
    live.value(json!({"type":"navigate","url":format!("{}/idle",fixture.url),"wait_until":"load"}))
        .await;
    assert_eq!(
        live.evaluate("navigator.serviceWorker.getRegistration().then(r=>r?r.unregister():false)")
            .await,
        json!(true)
    );
    live.value(json!({"type":"navigate","url":format!("{}/idle",fixture.url),"wait_until":"load"}))
        .await;
    live.value(json!({"type":"navigate","url":format!("{}/top?restart=1",fixture.url),"wait_until":"load"})).await;
    fixture.wait_first(2).await;
    wait_target_count(&live, 3).await;
    let ids = live.observed_target_ids("service_worker");
    assert_eq!(
        ids.len(),
        2,
        "registration generations attach exactly once each"
    );
    assert_eq!(ids[0], first_ids[0]);
    assert_ne!(ids[0], ids[1]);
    for id in &ids {
        assert!(
            live.targets.has_ready_target(id),
            "a surviving worker remains charged to its exact context until confirmed gone"
        );
    }
    fixture.assert_profiles_and_requests(2, CUSTOM_UA);
    dispose_and_verify(&live).await;
}
