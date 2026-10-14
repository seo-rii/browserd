#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use super::super::{live_chromium::LiveChromium, uploads::bounded_scratch};
use super::*;
use crate::{
    ActionExecutionResult, ApprovedActionError, ChromiumDriver, FileSecretResolver, SecretResolver,
};
use browserd_artifacts::{ArtifactChecksum, ArtifactKey, ArtifactObjectGeneration};
use browserd_core::{ArtifactId, PrincipalId};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOP: &str = "http://127.0.0.1:31901";
const CHILD: &str = "http://127.0.0.2:31902";
const LEAF: &str = r#"<!doctype html><meta charset=utf-8><input id=password type=password role=textbox aria-label='승인 계정'><textarea id=notes></textarea><input id=file type=file multiple><script>
const digest=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),x=>x.toString(16).padStart(2,'0')).join('');
const counts={};for(const name of ['input','change'])document.addEventListener(name,async e=>{counts[e.target.id+':'+name]=(counts[e.target.id+':'+name]||0)+1;if(name!=='change')return;const el=e.target;const result=el.type==='file'?await Promise.all(Array.from(el.files,async f=>({name:f.name,size:f.size,hash:await digest(await f.arrayBuffer())}))):{hash:await digest(new TextEncoder().encode(el.value)),input:counts[el.id+':input'],change:counts[el.id+':change']};top.postMessage({id:el.id,result},'*')});
</script>"#;

async fn proxy() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let top = format!(
                "<!doctype html><meta charset=utf-8><script>window.reports={{}};addEventListener('message',e=>{{if(e.origin==='{CHILD}')reports[e.data.id]=e.data.result}})</script><iframe id=same src='{TOP}/same' style='width:900px;height:700px'></iframe>"
            );
            let middle = format!(
                "<!doctype html><iframe id=remote src='{CHILD}/leaf' style='width:700px;height:500px'></iframe>"
            );
            tokio::spawn(async move {
                let mut bytes = [0_u8; 4096];
                let Ok(Ok(length @ 1..)) =
                    tokio::time::timeout(Duration::from_secs(2), socket.read(&mut bytes)).await
                else {
                    return;
                };
                let text = String::from_utf8_lossy(&bytes[..length]);
                let url = text.split_whitespace().nth(1).unwrap_or("");
                let body = if url.starts_with(CHILD) {
                    LEAF
                } else if url.ends_with("/same") {
                    &middle
                } else {
                    &top
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (address, task)
}
async fn inspect(
    browser: &LiveChromium,
    action: WorkerActionCommand,
    context: bool,
) -> TypedApprovalObservation {
    let (driver, tenant, session, page, fence) = (
        browser.driver.clone(),
        browser.tenant.clone(),
        browser.session.clone(),
        browser.page.clone(),
        browser.fence.clone(),
    );
    tokio::task::spawn_blocking(move || {
        driver.inspect_typed_approval_until(
            &tenant,
            &session,
            (!context).then_some(&page),
            &fence,
            &action,
            Instant::now() + Duration::from_secs(8),
        )
    })
    .await
    .unwrap()
    .expect("typed owned observation")
}
async fn node(browser: &LiveChromium, selector: &str) -> String {
    let result = browser
        .value(json!({"type":"query_all","selector":selector,"frame_path":["#same","#remote"]}))
        .await;
    assert_eq!(result["returned_count"], 1);
    result["node_refs"][0].as_str().unwrap().to_owned()
}
async fn report(browser: &LiveChromium, id: &str) -> Value {
    browser.evaluate(&format!("new Promise((resolve,reject)=>{{const end=Date.now()+3000;const check=()=>{{if(reports[{id:?}])resolve(reports[{id:?}]);else if(Date.now()>end)reject(new Error('fixture report timeout'));else setTimeout(check,10)}};check()}})")).await
}
fn private_file(path: &std::path::Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn file(browser: &LiveChromium, name: &str, bytes: &[u8]) -> BrowserFileAttachment {
    BrowserFileAttachment::verified(
        ArtifactKey::new(
            browser.tenant.clone(),
            browser.session.clone(),
            ArtifactId::new(),
        ),
        browser.fence.clone(),
        ArtifactObjectGeneration::new([7; 32]),
        ArtifactChecksum::new(Sha256::digest(bytes).into()),
        name.to_owned(),
        Arc::from(bytes),
    )
}

#[test]
#[ignore = "requires explicit sandbox-enabled Chromium and private bounded scratch namespaces; functional proof only"]
fn actual_owner_typed_approvals_bind_child_secret_files_and_blank_context() {
    const NAME: &str = "chromium_owner::approvals::live_tests::actual_owner_typed_approvals_bind_child_secret_files_and_blank_context";
    if !bounded_scratch::enter_or_spawn(NAME) {
        return;
    }
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(100),async {
            let (address,server)=proxy().await;let browser=LiveChromium::start_with_files(address).await;
            eprintln!("typed approval proof: blank context checkpoint and initial navigation");
            let expected=inspect(&browser,WorkerActionCommand::Checkpoint{origins:vec![]},true).await;
            assert_eq!(expected.context_scope,ApprovalContextScope::BrowserContext);assert!(expected.page_id.is_none());
            let driver=browser.driver.clone();
            let snapshot=tokio::task::spawn_blocking(move || {let mut count=0;let result=driver.capture_typed_checkpoint_until(&expected,&[],Instant::now()+Duration::from_secs(8),&mut |_|{count+=1;Ok(())});assert_eq!(count,1);result}).await.unwrap().unwrap();
            assert!(snapshot.cookies.is_empty()&&snapshot.origins.is_empty());
            let action=WorkerActionCommand::Navigate{url:format!("{TOP}/"),wait_until:WorkerNavigateWaitUntil::Load};
            let expected=inspect(&browser,action.clone(),false).await;assert_eq!(expected.context_scope,ApprovalContextScope::OpaqueDocument);
            let payload=serde_json::to_vec(&action).unwrap();let driver=browser.driver.clone();
            let navigation=tokio::task::spawn_blocking(move || {let mut count=0;let result=driver.execute_typed_browser_until(&expected,&payload,Instant::now()+Duration::from_secs(10),&mut |_|{count+=1;Ok(())});assert_eq!(count,1);result}).await.unwrap().unwrap();
            assert!(matches!(navigation,ActionExecutionResult::Succeeded(_)));
            assert!(browser.observed_iframe_target());
            let temporary=tempfile::tempdir().unwrap();let principal=PrincipalId::new();let dummy="fixture-only-승인-비밀번호";
            private_file(&temporary.path().join("value"),dummy.as_bytes());private_file(&temporary.path().join("catalog.json"),&serde_json::to_vec(&json!({"schema_version":1,"grants":[{"tenant_id":browser.tenant,"principal_ids":[principal],"secret_ref":"login","allowed_origins":[CHILD],"value_file":"value"}]})).unwrap());
            let provider=FileSecretResolver::open(&temporary.path().join("catalog.json")).unwrap();let grant=provider.authorize(&browser.tenant,&principal,"login",&Origin::parse(CHILD).unwrap(),Instant::now()+Duration::from_secs(3)).unwrap();
            eprintln!("typed approval proof: child native secret denied then admitted");
            for selector in ["#password","#notes"] {
                let reference=node(&browser,selector).await;let expected=inspect(&browser,WorkerActionCommand::FillSecret{node_ref:reference,secret_ref:"login".to_owned()},false).await;
                assert_eq!(expected.live.current_origin.as_str(),CHILD);
                if selector=="#password" {assert_eq!(expected.node_binding.as_ref().unwrap().name.as_deref(),Some("승인 계정"));}
                let secret=provider.resolve(&grant,Instant::now()+Duration::from_secs(3)).unwrap();let driver=browser.driver.clone();let rejected=expected.clone();
                let denied=tokio::task::spawn_blocking(move || driver.execute_typed_secret_until(&rejected,secret,Instant::now()+Duration::from_secs(8),&mut |_|Err(ApprovedActionError::DispatchRevoked))).await.unwrap();assert!(matches!(denied,Err(ApprovedActionError::DispatchRevoked)));
                let secret=provider.resolve(&grant,Instant::now()+Duration::from_secs(3)).unwrap();let driver=browser.driver.clone();
                let result=tokio::task::spawn_blocking(move || {let mut count=0;let result=driver.execute_typed_secret_until(&expected,secret,Instant::now()+Duration::from_secs(8),&mut |_|{count+=1;Ok(())});assert_eq!(count,1);result}).await.unwrap().unwrap();
                assert!(matches!(result,ActionExecutionResult::Succeeded(ref value) if value==br#"{"ok":true}"#));
                let reported=report(&browser,&selector[1..]).await;assert!(reported["hash"].as_str()==Some(format!("{:x}",Sha256::digest(dummy.as_bytes())).as_str()));assert_eq!(reported["input"],1);assert_eq!(reported["change"],1);
            }
            eprintln!("typed approval proof: child file selection and retained bytes");
            let reference=node(&browser,"#file").await;let files=vec![file(&browser,"한글.txt","승인 파일".as_bytes()),file(&browser,"empty.bin",b"")];
            let expected=inspect(&browser,WorkerActionCommand::SetFiles{node_ref:reference,artifact_ids:files.iter().map(|f|f.key().artifact_id().clone()).collect()},false).await;
            let driver=browser.driver.clone();let rejected=expected.clone();let rejected_files=files.clone();
            let denied=tokio::task::spawn_blocking(move || driver.execute_typed_files_until(&rejected,rejected_files,Instant::now()+Duration::from_secs(8),&mut |_|Err(ApprovedActionError::DispatchRevoked))).await.unwrap();assert!(matches!(denied,Err(ApprovedActionError::DispatchRevoked)));
            assert_eq!(browser.evaluate("Object.hasOwn(reports,'file')").await,false);
            let driver=browser.driver.clone();let old=expected.clone();
            let result=tokio::task::spawn_blocking(move || {let mut count=0;let result=driver.execute_typed_files_until(&expected,files,Instant::now()+Duration::from_secs(8),&mut |_|{count+=1;Ok(())});assert_eq!(count,1);result}).await.unwrap().unwrap();assert!(matches!(result,ActionExecutionResult::Succeeded(_)));
            let reported=report(&browser,"file").await;assert_eq!(reported[0]["name"],"한글.txt");assert_eq!(reported[0]["hash"],format!("{:x}",Sha256::digest("승인 파일".as_bytes())));assert_eq!(reported[1]["size"],0);
            browser.value(json!({"type":"reload"})).await;
            let driver=browser.driver.clone();let file=file(&browser,"later.txt",b"later");
            let stale=tokio::task::spawn_blocking(move || {let mut count=0;let result=driver.execute_typed_files_until(&old,vec![file],Instant::now()+Duration::from_secs(8),&mut |_|{count+=1;Ok(())});assert_eq!(count,0);result}).await.unwrap();assert!(matches!(stale,Err(ApprovedActionError::DispatchRevoked)));
            server.abort();
        }).await.expect("bounded typed approval functional proof");
    });
}
