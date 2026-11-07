#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[path = "common/live_chromium.rs"]
mod live_chromium;

use browserd_worker::{ActionExecutionResult, WorkerSessionOptionsV1, WorkerViewport};
use live_chromium::LiveChromium;
use serde_json::json;

struct FixtureServer {
    url: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FixtureServer {
    fn new(address: &str, html: String) -> Self {
        use std::io::{Read, Write};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let listener = std::net::TcpListener::bind((address, 0)).expect("loopback fixture");
        let url = format!("http://{}/", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                            .unwrap();
                        let mut request = [0; 4096];
                        let _ = stream.read(&mut request);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            html.len(),
                            html
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not security qualification"]
async fn live_owner_click_scroll_occlusion_and_korean_insert_text() {
    let live = LiveChromium::start().await;
    live.evaluate("document.body.innerHTML='<input id=entry><button id=target style=\"position:absolute;top:1800px\">target</button>'; window.clicks=0; target.onclick=()=>clicks++;window.insertions=[];entry.addEventListener('input',event=>insertions.push({data:event.data,inputType:event.inputType}))").await;
    let button = live.node("#target").await;
    assert!(matches!(
        live.action(json!({"type":"click","node_ref":button})).await,
        ActionExecutionResult::Succeeded(_)
    ));
    assert_eq!(live.evaluate("clicks").await, 1);
    let entry = live.node("#entry").await;
    live.value(json!({"type":"focus","node_ref":entry})).await;
    live.value(json!({"type":"type_text","text":"한글 입력 테스트"}))
        .await;
    assert_eq!(live.evaluate("entry.value").await, "한글 입력 테스트");
    assert_eq!(
        live.evaluate("insertions").await,
        json!([{"data":"한글 입력 테스트","inputType":"insertText"}])
    );
    live.evaluate("target.scrollIntoView(); const overlay=document.createElement('div'); overlay.style='position:fixed;inset:0;z-index:999;background:red';document.body.append(overlay)").await;
    assert!(matches!(
        live.action(json!({"type":"click","node_ref":button})).await,
        ActionExecutionResult::FailedKnown(_)
    ));
    assert_eq!(live.evaluate("clicks").await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not security qualification"]
async fn live_owner_rejects_moving_geometry_before_pointer_dispatch() {
    let live = LiveChromium::start().await;
    live.evaluate("document.body.innerHTML='<button id=target style=\"position:absolute;left:100px;top:100px;width:80px;height:40px\">moving</button>';window.clicks=0;target.onclick=()=>clicks++;target.animate([{transform:'translateX(0)'},{transform:'translateX(400px)'}],{duration:500,iterations:Infinity,direction:'alternate'})").await;
    let button = live.node("#target").await;
    assert!(
        matches!(
            live.action(json!({"type":"click","node_ref":button})).await,
            ActionExecutionResult::FailedKnown(_)
        ),
        "moving geometry must fail before input"
    );
    assert_eq!(live.evaluate("clicks").await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not security qualification"]
async fn live_owner_rejects_handle_adopted_into_another_frame_document() {
    let live = LiveChromium::start().await;
    live.evaluate("document.body.innerHTML='<button id=target>adopted</button><iframe id=child style=\"position:absolute;left:300px;top:200px\"></iframe>';window.clicks=0;target.onclick=()=>clicks++").await;
    let button = live.node("#target").await;
    live.evaluate("child.contentDocument.body.append(target)")
        .await;
    assert!(
        matches!(
            live.action(json!({"type":"click","node_ref":button})).await,
            ActionExecutionResult::FailedKnown(_)
        ),
        "foreign document coordinates cannot be used on page input"
    );
    assert_eq!(live.evaluate("clicks").await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not security qualification"]
async fn live_owner_rejects_mutation_and_focus_after_node_adoption() {
    let live = LiveChromium::start().await;
    live.evaluate(
        "document.body.innerHTML='<input id=target value=original><iframe id=child></iframe>'",
    )
    .await;
    let entry = live.node("#target").await;
    live.evaluate("child.contentDocument.body.append(target)")
        .await;
    for command in [
        json!({"type":"fill","node_ref":entry,"value":"다른 문서"}),
        json!({"type":"focus","node_ref":entry}),
    ] {
        assert!(
            matches!(
                live.action(command).await,
                ActionExecutionResult::FailedKnown(_)
            ),
            "document adoption invalidates the top-document handle for mutations"
        );
    }
    assert_eq!(
        live.evaluate("child.contentDocument.querySelector('#target').value")
            .await,
        "original"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not security qualification"]
async fn live_owner_mutations_respect_editability_and_native_controlled_setters() {
    let live = LiveChromium::start().await;
    live.evaluate("document.body.innerHTML='<fieldset disabled><input id=disabled></fieldset><input id=readonly readonly><input id=controlled><div id=editable contenteditable></div><select id=select><option value=ko>한국어</option><option value=en>English</option></select>';window.observed='';let tracked='';Object.defineProperty(controlled,'value',{get(){return tracked},set(v){tracked=v}});controlled.addEventListener('input',()=>{observed=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').get.call(controlled)})").await;
    for selector in ["#disabled", "#readonly"] {
        let node = live.node(selector).await;
        assert!(matches!(
            live.action(json!({"type":"fill","node_ref":node,"value":"변경 금지"}))
                .await,
            ActionExecutionResult::FailedKnown(_)
        ));
    }
    let controlled = live.node("#controlled").await;
    live.value(json!({"type":"fill","node_ref":controlled,"value":"한국어 제어 입력"}))
        .await;
    assert_eq!(live.evaluate("observed").await, "한국어 제어 입력");
    let editable = live.node("#editable").await;
    live.value(json!({"type":"fill","node_ref":editable,"value":"편집 가능한 한글"}))
        .await;
    assert_eq!(
        live.evaluate("editable.textContent").await,
        "편집 가능한 한글"
    );
    let select = live.node("#select").await;
    live.value(json!({"type":"select_option","node_ref":select,"values":["en"]}))
        .await;
    assert_eq!(live.evaluate("select.value").await, "en");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; functional, not security qualification"]
async fn live_owner_oopif_children_are_not_exposed_as_top_document_handles() {
    let child = FixtureServer::new(
        "127.0.0.2",
        "<button id=child_target>child-only-marker</button>".to_owned(),
    );
    let parent = FixtureServer::new(
        "127.0.0.1",
        format!(
            "<button id=target onclick='window.clicks=(window.clicks||0)+1'>parent</button><iframe src='{}' style='position:absolute;left:300px;top:200px'></iframe>",
            child.url
        ),
    );
    let live = LiveChromium::start_with_options(WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1440,
            height: 900,
            device_scale_factor: 2,
        },
        locale: "ko-KR".to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: None,
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 1800,
        idle_timeout_seconds: 600,
        metadata: Default::default(),
    })
    .await;
    // The parent's load event depends on resuming the paused child after its complete
    // bootstrap barrier, while the original navigation still owns the action slot.
    live.value(json!({"type":"navigate","url":parent.url,"wait_until":"load"}))
        .await;
    assert_eq!(live.evaluate("document.readyState").await, "complete");
    live.value(json!({"type":"reload"})).await;
    assert_eq!(live.evaluate("document.readyState").await, "complete");
    assert_eq!(
        live.evaluate("[innerWidth,innerHeight,devicePixelRatio]")
            .await,
        json!([1440, 900, 2]),
        "bootstrapping the iframe must preserve its parent's emulation settings"
    );
    let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if live.observed_iframe_target() && live.evaluate("document.readyState").await == "complete"
        {
            break;
        }
        assert!(
            std::time::Instant::now() < ready_deadline,
            "bounded OOPIF bootstrap did not complete"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(
        live.observed_iframe_target(),
        "fixture must produce an actual OOPIF target"
    );
    let child_query = live
        .value(json!({"type":"query_all","selector":"#child_target"}))
        .await;
    assert_eq!(
        child_query["returned_count"], 0,
        "cross-frame lookup is explicitly unsupported"
    );
    let snapshot = live.value(json!({"type":"snapshot"})).await;
    assert!(
        !snapshot["nodes"]
            .as_array()
            .expect("snapshot nodes")
            .iter()
            .any(|node| node["name"] == "child-only-marker"),
        "child nodes must not receive top-document refs"
    );
    let target = live.node("#target").await;
    live.value(json!({"type":"click","node_ref":target})).await;
    assert_eq!(live.evaluate("clicks").await, 1);
}
