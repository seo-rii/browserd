#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use super::super::live_chromium::LiveChromium;
use crate::{ActionExecutionResult, ChromiumDriver, SecretFillError};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct FrameFixture {
    url: String,
    servers: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for FrameFixture {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
    }
}

const LEAF: &str = r#"<!doctype html><meta charset=utf-8>
<style>body{margin:12px}button{width:130px;height:40px}#state{white-space:pre}</style>
<button id=button data-marker=owned>프레임 버튼</button>
<input id=entry><textarea id=notes></textarea><input id=checked type=checkbox>
<select id=select><option value=a>A</option><option value=b>B</option></select>
<input id=readonly readonly><input id=file type=file><a id=hash href='#changed'>hash</a>
<table id=table><tr><td>한글</td><td>42</td></tr></table><pre id=state></pre>
<script>
window.counts={clicks:0,double:0,hovers:0,input:0,change:0,focus:0,blur:0,hash:0};
const report=()=>{state.textContent=JSON.stringify(counts)};
button.addEventListener('click',()=>{counts.clicks++;report()});
button.addEventListener('dblclick',()=>{counts.double++;report()});
button.addEventListener('mouseenter',()=>{counts.hovers++;report()});
for(const name of ['input','change','focus','blur'])document.addEventListener(name,()=>{counts[name]++;report()},true);
addEventListener('hashchange',()=>{counts.hash++;report()});report();
</script>"#;

async fn fixture() -> FrameFixture {
    let same = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
    let same_origin = format!("http://{}", same.local_addr().unwrap());
    let remote_origin = format!("http://{}", remote.local_addr().unwrap());
    let top = format!(
        "<!doctype html><meta charset=utf-8><style>body{{margin:0;height:2600px}}iframe{{width:600px;height:500px;border:11px solid green}}</style><button id=top>top</button><iframe id=same src='{same_origin}/same' style='position:absolute;left:130px;top:1100px;transform:scale(.85);transform-origin:0 0'></iframe><iframe id=peer src='{same_origin}/same' style='position:absolute;left:750px;top:1100px'></iframe>"
    );
    let middle = format!(
        "<!doctype html><meta charset=utf-8><style>body{{margin:19px;height:1800px}}iframe{{width:440px;height:360px;border:7px solid blue}}</style><iframe id=nested src='{same_origin}/leaf' style='position:absolute;left:37px;top:530px'></iframe><iframe id=remote src='{remote_origin}/leaf' style='position:absolute;left:37px;top:1020px'></iframe>"
    );
    let same_server = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = same.accept().await else {
                break;
            };
            let mut request = [0_u8; 4096];
            let Ok(Ok(length @ 1..)) =
                tokio::time::timeout(Duration::from_secs(2), socket.read(&mut request)).await
            else {
                continue;
            };
            let first_line = String::from_utf8_lossy(&request[..length]);
            let route = first_line.split_whitespace().nth(1).unwrap_or("/");
            let body = match route.split('?').next().unwrap_or(route) {
                "/" => top.as_str(),
                "/same" => middle.as_str(),
                _ => LEAF,
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    let remote_server = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = remote.accept().await else {
                break;
            };
            let mut request = [0_u8; 4096];
            if !matches!(
                tokio::time::timeout(Duration::from_secs(2), socket.read(&mut request)).await,
                Ok(Ok(1..))
            ) {
                continue;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{LEAF}",
                LEAF.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    FrameFixture {
        url: format!("{same_origin}/"),
        servers: vec![same_server, remote_server],
    }
}

async fn node(browser: &LiveChromium, path: &[&str], selector: &str) -> String {
    let result = browser
        .value(json!({"type":"query_all","selector":selector,"frame_path":path}))
        .await;
    assert_eq!(result["returned_count"], 1, "unique fixture node");
    result["node_refs"][0].as_str().unwrap().to_owned()
}

async fn properties(browser: &LiveChromium, node: &str) -> Value {
    browser
        .value(json!({"type":"get_properties","node_ref":node}))
        .await["properties"]
        .clone()
}

async fn counts(browser: &LiveChromium, path: &[&str]) -> Value {
    let state = node(browser, path, "#state").await;
    let text = browser
        .value(json!({"type":"get_text","node_ref":state}))
        .await;
    serde_json::from_str(text["text"].as_str().unwrap()).unwrap()
}

async fn reject(browser: &LiveChromium, command: Value) {
    let action_type = command["type"].as_str().unwrap().to_owned();
    let result = browser.action(command).await;
    assert!(
        matches!(result, ActionExecutionResult::FailedKnown(_)),
        "{action_type}: rejection must precede browser effects, received {result:?}"
    );
}

async fn secret_target_is_rejected(browser: &LiveChromium, node_ref: String) {
    let (driver, tenant, session, page, fence) = (
        browser.driver.clone(),
        browser.tenant.clone(),
        browser.session.clone(),
        browser.page.clone(),
        browser.fence.clone(),
    );
    let result = tokio::task::spawn_blocking(move || {
        driver.inspect_secret_fill_target_until(
            &tenant,
            &session,
            &page,
            &fence,
            &node_ref,
            Instant::now() + Duration::from_secs(5),
        )
    })
    .await
    .unwrap();
    assert!(matches!(result, Err(SecretFillError::Rejected)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicitly configured sandbox-enabled Chromium; functional proof, not production qualification"]
async fn actual_owner_nested_frames_and_oopif_input_are_fenced() {
    tokio::time::timeout(Duration::from_secs(150), async {
        let fixture = fixture().await;
        let browser = LiveChromium::start().await;
        browser.value(json!({"type":"navigate","url":fixture.url,"wait_until":"load"})).await;
        assert!(browser.observed_iframe_target(), "fixture must attach a real OOPIF");
        assert_eq!(browser.value(json!({"type":"query_all","selector":"#entry"})).await["returned_count"], 0);
        reject(&browser,json!({"type":"query_all","selector":"#entry","frame_path":["iframe"]})).await;
        reject(&browser,json!({"type":"query_all","selector":"#entry","frame_path":["#top"]})).await;
        reject(&browser,json!({"type":"query_all","selector":"#entry","frame_path":["#missing"]})).await;

        eprintln!("frame proof: nested same-process and OOPIF reads and native mutations");
        for path in [["#same", "#nested"], ["#same", "#remote"]] {
            let entry = node(&browser, &path, "#entry").await;
            let notes = node(&browser, &path, "#notes").await;
            let checkbox = node(&browser, &path, "#checked").await;
            let select = node(&browser, &path, "#select").await;
            let readonly = node(&browser, &path, "#readonly").await;
            browser.value(json!({"type":"focus","node_ref":entry})).await;
            browser.value(json!({"type":"blur","node_ref":entry})).await;
            browser.value(json!({"type":"fill","node_ref":entry,"value":"한글 프레임"})).await;
            browser.value(json!({"type":"fill","node_ref":notes,"value":"중첩 textarea"})).await;
            browser.value(json!({"type":"check","node_ref":checkbox})).await;
            assert_eq!(properties(&browser,&checkbox).await["checked"],true);
            browser.value(json!({"type":"uncheck","node_ref":checkbox})).await;
            assert_eq!(properties(&browser,&checkbox).await["checked"],false);
            browser.value(json!({"type":"select_option","node_ref":select,"values":["b"]})).await;
            assert_eq!(properties(&browser,&entry).await["value"],"한글 프레임");
            assert_eq!(properties(&browser,&notes).await["value"],"중첩 textarea");
            assert_eq!(properties(&browser,&select).await["value"],"b");
            reject(&browser,json!({"type":"fill","node_ref":readonly,"value":"invalid"})).await;
            assert_eq!(properties(&browser,&readonly).await["value"],"");
            let table = node(&browser,&path,"#table").await;
            assert_eq!(browser.value(json!({"type":"extract_table","node_ref":table})).await["rows"],json!([["한글","42"]]));
            let button = node(&browser,&path,"#button").await;
            assert_eq!(browser.value(json!({"type":"get_attribute","node_ref":button,"name":"data-marker"})).await["value"],"owned");
            assert!(browser.value(json!({"type":"get_html","node_ref":button})).await["html"].as_str().unwrap().contains("프레임 버튼"));
            assert_eq!(browser.value(json!({"type":"get_computed_style","node_ref":button})).await["styles"]["width"],"130px");
            secret_target_is_rejected(&browser,entry).await;
            let before = counts(&browser,&path).await;
            browser.value(json!({"type":"hover","node_ref":button})).await;
            browser.value(json!({"type":"click","node_ref":button})).await;
            browser.value(json!({"type":"double_click","node_ref":button})).await;
            let after = counts(&browser,&path).await;
            assert_eq!(after["clicks"].as_u64().unwrap(),before["clicks"].as_u64().unwrap()+3);
            assert_eq!(after["double"].as_u64().unwrap(),before["double"].as_u64().unwrap()+1);
            assert!(after["hovers"].as_u64().unwrap()>before["hovers"].as_u64().unwrap());
            assert!(after["input"].as_u64().unwrap()>=5 && after["change"].as_u64().unwrap()>=5);
        }

        eprintln!("frame proof: ancestor overlay, scroll, border and affine transform");
        let path = ["#same", "#remote"];
        let button = node(&browser,&path,"#button").await;
        let before = counts(&browser,&path).await;
        browser.evaluate("const overlay=document.createElement('div');overlay.id='overlay';overlay.style='position:fixed;inset:0;z-index:9999;background:red';document.body.append(overlay);true").await;
        reject(&browser,json!({"type":"click","node_ref":button})).await;
        assert_eq!(counts(&browser,&path).await["clicks"],before["clicks"]);
        browser.evaluate("overlay.remove();const m=same.contentDocument;const o=m.createElement('div');o.id='middle_overlay';o.style='position:fixed;inset:0;z-index:9999;background:red';m.body.append(o);true").await;
        reject(&browser,json!({"type":"click","node_ref":button})).await;
        assert_eq!(counts(&browser,&path).await["clicks"],before["clicks"]);
        browser.evaluate("same.contentDocument.querySelector('#middle_overlay').remove();same.style.transform='rotate(5deg) scale(.85)';true").await;
        browser.value(json!({"type":"click","node_ref":button})).await;
        assert_eq!(counts(&browser,&path).await["clicks"].as_u64().unwrap(),before["clicks"].as_u64().unwrap()+1);
        browser.evaluate("same.style.transform='perspective(300px) rotateY(30deg)';true").await;
        reject(&browser,json!({"type":"click","node_ref":button})).await;
        assert_eq!(counts(&browser,&path).await["clicks"].as_u64().unwrap(),before["clicks"].as_u64().unwrap()+1);
        browser.evaluate("same.style.transform='scale(.85)';true").await;
        browser.evaluate("window.frameMotion=same.animate([{transform:'scale(.8)'},{transform:'scale(.9)'}],{duration:2000,iterations:Infinity,direction:'alternate'});true").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        reject(&browser,json!({"type":"click","node_ref":button})).await;
        assert_eq!(counts(&browser,&path).await["clicks"].as_u64().unwrap(),before["clicks"].as_u64().unwrap()+1,"moving ancestor must receive no pointer effect");
        browser.evaluate("frameMotion.cancel();true").await;

        eprintln!("frame proof: sibling isolation, same-document navigation and adoption");
        let entry = node(&browser,&path,"#entry").await;
        let peer = node(&browser,&["#peer","#remote"],"#entry").await;
        assert_ne!(entry,peer);
        browser.value(json!({"type":"fill","node_ref":entry,"value":"sole owner"})).await;
        assert_eq!(properties(&browser,&peer).await["value"],"");
        let hash = node(&browser,&path,"#hash").await;
        let hash_before = counts(&browser,&path).await["hash"].as_u64().unwrap();
        browser.value(json!({"type":"click","node_ref":hash})).await;
        let hash_deadline = Instant::now()+Duration::from_secs(3);
        loop {
            let changed = counts(&browser,&path).await["hash"].as_u64().unwrap();
            if changed == hash_before+1 { break; }
            assert!(changed == hash_before && Instant::now()<hash_deadline,"actual same-document hash navigation");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(properties(&browser,&entry).await["value"],"sole owner","hash navigation must retain the document binding");
        let adopted = node(&browser,&["#same","#nested"],"#entry").await;
        browser.evaluate("const a=same.contentDocument.querySelector('#nested').contentDocument.querySelector('#entry');a.id='adopted';peer.contentDocument.querySelector('#nested').contentDocument.body.append(a);true").await;
        reject(&browser,json!({"type":"fill","node_ref":adopted,"value":"foreign document"})).await;
        let newly_adopted = node(&browser,&["#peer","#nested"],"#adopted").await;
        assert_eq!(properties(&browser,&newly_adopted).await["value"],"한글 프레임");
        browser.value(json!({"type":"fill","node_ref":newly_adopted,"value":"new owner document"})).await;
        assert_eq!(properties(&browser,&newly_adopted).await["value"],"new owner document");

        eprintln!("frame proof: target swap, detach and fresh documents reject old nodes");
        browser.evaluate("new Promise(resolve=>{const f=same.contentDocument.querySelector('#remote');f.onload=()=>resolve(true);f.src='/leaf?swapped';})").await;
        reject(&browser,json!({"type":"fill","node_ref":entry,"value":"stale target"})).await;
        let swapped = node(&browser,&path,"#entry").await;
        assert_eq!(properties(&browser,&swapped).await["value"],"");
        browser.value(json!({"type":"fill","node_ref":swapped,"value":"new document"})).await;
        assert_eq!(properties(&browser,&peer).await["value"],"","a sibling route survives another renderer swap");
        browser.evaluate("same.contentDocument.querySelector('#remote').remove();true").await;
        reject(&browser,json!({"type":"fill","node_ref":swapped,"value":"detached"})).await;
        assert_eq!(properties(&browser,&peer).await["value"],"","a sibling route survives frame removal");
        let stale = node(&browser,&["#peer","#remote"],"#entry").await;
        browser.value(json!({"type":"reload"})).await;
        reject(&browser,json!({"type":"fill","node_ref":stale,"value":"stale ancestor"})).await;
        let fresh = node(&browser,&path,"#entry").await;
        assert_eq!(properties(&browser,&fresh).await["value"],"");
        browser.value(json!({"type":"fill","node_ref":fresh,"value":"fresh"})).await;
    }).await.expect("bounded real frame proof");
}
