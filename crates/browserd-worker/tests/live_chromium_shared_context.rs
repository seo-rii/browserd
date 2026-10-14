#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Actual eight-context functional evidence; never a production qualification receipt.
#[path = "common/live_chromium.rs"]
mod live_chromium;

use browserd_core::{PageId, SessionId, TenantId};
use browserd_sandbox::ContextEgressReleaseReceipt;
use browserd_worker::{ActionExecutionResult, ChromiumDriver};
use live_chromium::LiveChromium;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

struct Proxy {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Proxy {
    fn new(index: usize) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let recorded = requests.clone();
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(length) if request.len() + length <= 16 * 1024 => {
                            request.extend_from_slice(&chunk[..length])
                        }
                        Ok(_) => panic!("fixture request exceeds bound"),
                    }
                }
                let raw = String::from_utf8_lossy(&request);
                let Some(uri) = raw
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                else {
                    continue;
                };
                let url =
                    url::Url::parse(uri).expect("Chromium must use this context's HTTP proxy");
                assert_eq!(url.host_str(), Some("localhost"));
                assert_eq!(url.port(), Some(17777));
                let count = recorded.fetch_add(1, Ordering::AcqRel);
                assert!(count < 128, "bounded fixture requests");
                let (mime, body) = match url.path() {
                    "/context" => (
                        "text/html",
                        format!(
                            r#"<!doctype html><script>
window.proof={{pending:true}};
(async()=>{{
 const before={{cookie:document.cookie,local:localStorage.getItem('shared-key'),
 cache:(await caches.keys()).length,sw:(await navigator.serviceWorker.getRegistrations()).length}};
 const db=await new Promise((resolve,reject)=>{{let r=indexedDB.open('shared-db',1);r.onupgradeneeded=()=>r.result.createObjectStore('values');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)}});
 const read=()=>new Promise((resolve,reject)=>{{const r=db.transaction('values').objectStore('values').get('key');r.onsuccess=()=>resolve(r.result??null);r.onerror=()=>reject(r.error)}});
 before.idb=await read();
 await new Promise((resolve,reject)=>{{const t=db.transaction('values','readwrite');t.objectStore('values').put({index},'key');t.oncomplete=resolve;t.onerror=()=>reject(t.error)}});
 document.cookie='shared-key={index}; path=/';localStorage.setItem('shared-key','{index}');
 const cache=await caches.open('shared-cache');await cache.put('/value',new Response('{index}'));
 const worker=new SharedWorker('/shared.js','same-name');window.sharedWorker=worker;
 const shared=await new Promise(resolve=>{{worker.port.onmessage=e=>resolve(e.data);worker.port.start();worker.port.postMessage('read')}});
 const registration=await navigator.serviceWorker.register('/sw.js',{{scope:'/sw-scope/'}});
 await new Promise(resolve=>{{if(registration.active)resolve();else{{const w=registration.installing||registration.waiting;w.addEventListener('statechange',()=>{{if(w.state==='activated')resolve()}})}}}});
 const channel=new MessageChannel();const sw=await new Promise(resolve=>{{channel.port1.onmessage=e=>resolve(e.data);registration.active.postMessage('read',[channel.port2])}});
 window.proof={{index:{index},before,cookie:document.cookie,local:localStorage.getItem('shared-key'),idb:await read(),cache:await(await cache.match('/value')).text(),shared,sw}};
 window.readAgain=async()=>{{
  const shared=await new Promise(resolve=>{{worker.port.onmessage=e=>resolve(e.data);worker.port.postMessage('read')}});
  const channel=new MessageChannel();const sw=await new Promise(resolve=>{{channel.port1.onmessage=e=>resolve(e.data);registration.active.postMessage('read',[channel.port2])}});
  window.after={{local:localStorage.getItem('shared-key'),idb:await read(),cache:await(await cache.match('/value')).text(),network:await(await fetch('/network?after')).text(),shared,sw}};
 }};
}})().catch(e=>window.proof={{error:String(e)}});
</script>"#
                        ),
                    ),
                    "/shared.js" => (
                        "text/javascript",
                        format!(
                            "let connections=0;onconnect=e=>{{const number=++connections;const p=e.ports[0];p.onmessage=()=>p.postMessage({{index:{index},connections:number}});p.start()}}"
                        ),
                    ),
                    "/sw.js" => (
                        "text/javascript",
                        format!(
                            "let messages=0;oninstall=e=>e.waitUntil(skipWaiting());onmessage=e=>e.ports[0].postMessage({{index:{index},messages:++messages}})"
                        ),
                    ),
                    "/network" => ("text/plain", index.to_string()),
                    _ => ("text/plain", "fixture".to_owned()),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            address,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

async fn action(live: &LiveChromium, session: &SessionId, page: &PageId, command: Value) -> Value {
    let driver = live.driver.clone();
    let session = session.clone();
    let page = page.clone();
    let result = tokio::task::spawn_blocking(move || {
        driver.execute_action_until(
            &session,
            Some(&page),
            &serde_json::to_vec(&command).unwrap(),
            Instant::now() + Duration::from_secs(10),
        )
    })
    .await
    .unwrap();
    let ActionExecutionResult::Succeeded(bytes) = result else {
        panic!("shared live action failed: {result:?}");
    };
    serde_json::from_slice(&bytes).unwrap()
}

async fn wait_value(
    live: &LiveChromium,
    session: &SessionId,
    page: &PageId,
    expression: &str,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let value = action(
            live,
            session,
            page,
            json!({"type":"evaluate","expression":expression}),
        )
        .await["value"]
            .clone();
        assert!(
            value.get("error").is_none(),
            "browser proof failed: {value}"
        );
        if !value.is_null() && value.get("pending").is_none() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "shared context evidence timed out"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM; local functional evidence"]
async fn eight_contexts_keep_storage_workers_and_proxy_routes_separate_after_sibling_close() {
    let proxies: Vec<_> = (0..8).map(Proxy::new).collect();
    let live = LiveChromium::start_shared_with_proxy(proxies[0].address).await;
    let mut contexts = vec![(
        live.session.clone(),
        live.page.clone(),
        live.fence.clone(),
        live.initial_context_binding.clone().unwrap(),
    )];
    for (index, proxy) in proxies.iter().enumerate().skip(1) {
        contexts.push(
            live.add_shared_context(TenantId::new(), proxy.address, index as u64 + 1)
                .await,
        );
    }
    for (session, page, _, _) in &contexts {
        action(
            &live,
            session,
            page,
            json!({"type":"navigate","url":"http://localhost:17777/context","wait_until":"load"}),
        )
        .await;
    }
    for (index, (session, page, _, _)) in contexts.iter().enumerate() {
        let proof = wait_value(&live, session, page, "window.proof").await;
        assert_eq!(
            proof["before"],
            json!({"cookie":"","local":null,"cache":0,"sw":0,"idb":null})
        );
        assert_eq!(proof["index"], index);
        assert_eq!(proof["cookie"], format!("shared-key={index}"));
        assert_eq!(proof["local"], index.to_string());
        assert_eq!(proof["idb"], index);
        assert_eq!(proof["cache"], index.to_string());
        assert_eq!(proof["shared"], json!({"index":index,"connections":1}));
        assert_eq!(proof["sw"], json!({"index":index,"messages":1}));
    }
    let (session, _, fence, binding) = &contexts[0];
    let driver = live.driver.clone();
    let session = session.clone();
    let fence = fence.clone();
    tokio::task::spawn_blocking(move || driver.close_context_fenced(&session, &fence))
        .await
        .unwrap()
        .unwrap();
    // The controlled listener is physically stopped before minting this fixture-only receipt.
    let mut proxies = proxies;
    proxies[0].stop.store(true, Ordering::Release);
    proxies[0].thread.take().unwrap().join().unwrap();
    let receipt = ContextEgressReleaseReceipt::new(binding.request().clone(), 1, 1).unwrap();
    let backend = live.owner.target_manager_backend();
    tokio::task::spawn_blocking(move || backend.confirm_context_egress_released(receipt))
        .await
        .unwrap()
        .unwrap();
    for (index, (session, page, _, _)) in contexts.iter().enumerate().skip(1) {
        action(
            &live,
            session,
            page,
            json!({"type":"evaluate","expression":"window.readAgain(); true"}),
        )
        .await;
        let after = wait_value(&live, session, page, "window.after").await;
        assert_eq!(
            after,
            json!({"local":index.to_string(),"idb":index,"cache":index.to_string(),"network":index.to_string(),"shared":{"index":index,"connections":1},"sw":{"index":index,"messages":2}})
        );
        assert!(proxies[index].requests.load(Ordering::Acquire) >= 4);
    }
}
