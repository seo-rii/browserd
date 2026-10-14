#![allow(clippy::panic)]

use super::*;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use browserd_core::PrincipalId;
use browserd_policy::Origin;
use browserd_worker::{
    FileSecretResolver, ResolvedSecret, SecretFillError, SecretFillTarget, SecretResolver,
};

const SECRET: &str = "fixture-only-secret-value";
/// What a hostile page makes every script read of its origin report, e.g. by replacing
/// `globalThis` with `{top: itself, location: {origin: ...}}` and `Document.prototype.defaultView`.
const SPOOFED_ORIGIN: &str = "https://bank.example";
const BROWSER_ORIGIN: &str = "https://evil.example";

/// A private catalog that grants `login` to `origin` only.
struct Catalog {
    _directory: tempfile::TempDir,
    resolver: FileSecretResolver,
    principal: PrincipalId,
}

impl Catalog {
    fn new(tenant: &TenantId, origin: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let principal = PrincipalId::new();
        let write = |name: &str, bytes: &[u8]| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.path().join(name))
                .unwrap()
                .write_all(bytes)
                .unwrap();
        };
        write("value", SECRET.as_bytes());
        write(
            "catalog.json",
            &serde_json::to_vec(&json!({"schema_version":1,"grants":[{"tenant_id":tenant,
                "principal_ids":[principal],"secret_ref":"login","allowed_origins":[origin],
                "value_file":"value"}]}))
            .unwrap(),
        );
        let resolver = FileSecretResolver::open(&directory.path().join("catalog.json")).unwrap();
        Self {
            _directory: directory,
            resolver,
            principal,
        }
    }

    fn authorize(
        &self,
        tenant: &TenantId,
        origin: &Origin,
    ) -> Result<browserd_worker::SecretGrant, SecretFillError> {
        self.resolver.authorize(
            tenant,
            &self.principal,
            "login",
            origin,
            Instant::now() + Duration::from_secs(5),
        )
    }

    fn secret(&self, tenant: &TenantId, origin: &str) -> ResolvedSecret {
        let grant = self
            .authorize(tenant, &Origin::parse(origin).unwrap())
            .unwrap();
        self.resolver
            .resolve(&grant, Instant::now() + Duration::from_secs(5))
            .unwrap()
    }
}

fn main_frame_tree(security_origin: &str) -> Value {
    json!({"frameTree":{"frame":{"id":"frame-flat-primary","loaderId":"loader-a",
        "url":"https://evil.example/login","domainAndRegistry":"evil.example",
        "securityOrigin":security_origin,"mimeType":"text/html","secureContextType":"Secure",
        "crossOriginIsolatedContextType":"NotIsolated","gatedAPIFeatures":[]},"childFrames":[]}})
}

fn spawn_secret_inspection(
    page: &OwnedPage,
    node: &str,
) -> tokio::task::JoinHandle<Result<SecretFillTarget, SecretFillError>> {
    let (driver, tenant, session, page_id, node) = (
        page.driver.clone(),
        page.tenant_id.clone(),
        page.session_id.clone(),
        page.page_id.clone(),
        node.to_owned(),
    );
    tokio::task::spawn_blocking(move || {
        driver.inspect_secret_fill_target_until(
            &tenant,
            &session,
            &page_id,
            &ownership_fence(),
            &node,
            Instant::now() + Duration::from_secs(5),
        )
    })
}

/// Runs the legacy fill and counts how often the dispatch was durably committed.
fn spawn_secret_fill(
    page: &OwnedPage,
    target: SecretFillTarget,
    secret: ResolvedSecret,
) -> tokio::task::JoinHandle<(Result<ActionExecutionResult, SecretFillError>, usize)> {
    let driver = page.driver.clone();
    tokio::task::spawn_blocking(move || {
        let mut commits = 0;
        let result = driver.execute_secret_fill_until(
            &target,
            secret,
            Instant::now() + Duration::from_secs(5),
            &mut |_| {
                commits += 1;
                Ok(())
            },
        );
        (result, commits)
    })
}

fn push_state() -> Value {
    json!({"method":"Page.navigatedWithinDocument","sessionId":"flat-primary",
        "params":{"frameId":"frame-flat-primary","url":"https://evil.example/pushed"}})
}

fn new_document() -> Value {
    frame_navigated(
        "flat-primary",
        "frame-flat-primary",
        "loader-b",
        "https://evil.example/next",
    )
}

/// Reads one command, or `None` once the owner closed the pipe by failing the shard closed.
async fn next_command(reader: &mut Receiver) -> Option<Value> {
    let mut bytes = Vec::new();
    loop {
        match reader.read_u8().await {
            Ok(0) => return Some(serde_json::from_slice(&bytes).expect("valid CDP command")),
            Ok(byte) => bytes.push(byte),
            Err(_) if bytes.is_empty() => return None,
            Err(error) => panic!("truncated CDP command: {error}"),
        }
    }
}

/// Writes like `write_message`, but reports a pipe the owner already closed instead of panicking.
async fn send(writer: &mut Sender, message: Value) -> bool {
    let mut bytes = serde_json::to_vec(&message).unwrap();
    bytes.push(0);
    if message["method"] == "Page.frameNavigated" {
        let realm = json!({"method":"Runtime.executionContextCreated","sessionId":message["sessionId"],
            "params":{"context":{"id":1,"uniqueId":uuid::Uuid::new_v4().to_string(),
                "auxData":{"isDefault":true,"frameId":message["params"]["frame"]["id"]}}}});
        bytes.extend(serde_json::to_vec(&realm).unwrap());
        bytes.push(0);
    }
    writer.write_all(&bytes).await.is_ok()
}

/// Plays a page until `task` finishes: page script reports `script_origin` for any
/// `location.origin` it is asked to return, while the browser answers the frame tree with `tree`.
/// `interrupt` writes an event before the response to the n-th (1-based) command of a method.
/// Returns every command the owner sent.
async fn serve_page<T>(
    page: &mut OwnedPage,
    tree: Value,
    script_origin: &str,
    interrupt: Option<(&str, usize, Value)>,
    mut task: tokio::task::JoinHandle<T>,
) -> (T, Vec<Value>) {
    let mut commands: Vec<Value> = Vec::new();
    loop {
        let command = tokio::select! {
            biased;
            result = &mut task => return (result.unwrap(), commands),
            command = next_command(&mut page.reader) => command,
        };
        let Some(command) = command else {
            return (task.await.unwrap(), commands);
        };
        let method = command["method"].as_str().unwrap().to_owned();
        let declaration = command["params"]["functionDeclaration"]
            .as_str()
            .unwrap_or_default();
        let answer = match method.as_str() {
            "Page.getFrameTree" => tree.clone(),
            "DOM.resolveNode" => json!({"object":{"objectId":"secret-input"}}),
            "Runtime.callFunctionOn"
                if declaration.contains("return globalThis.location.origin") =>
            {
                json!({"result":{"type":"string","value":script_origin}})
            }
            "Runtime.callFunctionOn" => json!({"result":{"type":"boolean","value":true}}),
            "Runtime.releaseObject" => json!({}),
            "Runtime.evaluate" => json!({"result":{"type":"string","value":"title"}}),
            other => panic!("unexpected command {other}"),
        };
        commands.push(command.clone());
        let seen = commands
            .iter()
            .filter(|sent| sent["method"] == method)
            .count();
        if let Some((at, nth, event)) = &interrupt
            && *at == method
            && *nth == seen
            && !send(&mut page.writer, event.clone()).await
        {
            return (task.await.unwrap(), commands);
        }
        if !send(
            &mut page.writer,
            json!({"id":command["id"].as_u64().unwrap(),"result":answer}),
        )
        .await
        {
            return (task.await.unwrap(), commands);
        }
    }
}

/// The owner still serves the session and nothing marked the shard for drain.
async fn shard_intact(page: &mut OwnedPage) -> bool {
    let title = spawn_action(page, br#"{"type":"get_title"}"#, None);
    let (title, _) = serve_page(page, Value::Null, BROWSER_ORIGIN, None, title).await;
    matches!(title, ActionExecutionResult::Succeeded(_))
        && !page.drain.0.load(Ordering::SeqCst)
        && !page.manager.is_tainted()
}

#[tokio::test]
async fn legacy_secret_origin_is_the_browser_security_origin_not_page_script() {
    let mut page = owned_page().await;
    let node = mint_node(&mut page, 42).await;
    let inspection = spawn_secret_inspection(&page, &node);
    let (target, commands) = serve_page(
        &mut page,
        main_frame_tree(BROWSER_ORIGIN),
        SPOOFED_ORIGIN,
        None,
        inspection,
    )
    .await;
    let target = target.expect("a main-frame text input is inspectable");
    assert_eq!(target.origin, Origin::parse(BROWSER_ORIGIN).unwrap());
    assert!(
        commands.iter().any(
            |sent| sent["method"] == "Page.getFrameTree" && sent["sessionId"] == "flat-primary"
        )
    );

    // The bank's grant must not be authorized for, or filled into, the hostile page.
    let catalog = Catalog::new(&page.tenant_id, SPOOFED_ORIGIN);
    assert!(catalog.authorize(&page.tenant_id, &target.origin).is_err());
    let forged = SecretFillTarget {
        origin: Origin::parse(SPOOFED_ORIGIN).unwrap(),
        ..target
    };
    let fill = spawn_secret_fill(
        &page,
        forged,
        catalog.secret(&page.tenant_id, SPOOFED_ORIGIN),
    );
    let ((result, commits), commands) = serve_page(
        &mut page,
        main_frame_tree(BROWSER_ORIGIN),
        SPOOFED_ORIGIN,
        None,
        fill,
    )
    .await;
    assert_eq!(result, Err(SecretFillError::DispatchRevoked));
    assert_eq!(commits, 0);
    assert!(!serde_json::to_string(&commands).unwrap().contains(SECRET));
    assert!(shard_intact(&mut page).await);
}

#[tokio::test]
async fn legacy_secret_target_refuses_child_frames_and_non_canonical_origins() {
    let mut page = owned_page().await;
    // An OOPIF is a cross-origin frame; only main-frame inputs may receive a secret.
    attach_owned_oopif(&mut page).await;
    let child = mint_oopif_node(&mut page).await;
    let inspection = spawn_secret_inspection(&page, &child);
    let (result, commands) = serve_page(
        &mut page,
        main_frame_tree(BROWSER_ORIGIN),
        SPOOFED_ORIGIN,
        None,
        inspection,
    )
    .await;
    assert_eq!(result, Err(SecretFillError::Rejected));
    assert!(
        commands.is_empty(),
        "a child-frame node is refused before CDP"
    );

    let node = mint_node(&mut page, 42).await;
    let mut trees: Vec<_> = [
        "null",
        "://",
        "file://",
        "https://EVIL.example",
        "https://evil.example/",
        "https://evil.example:443",
    ]
    .into_iter()
    .map(main_frame_tree)
    .collect();
    let mut not_main = main_frame_tree(BROWSER_ORIGIN);
    not_main["frameTree"]["frame"]["parentId"] = json!("outer-frame");
    trees.push(not_main);
    let mut other_root = main_frame_tree(BROWSER_ORIGIN);
    other_root["frameTree"]["frame"]["id"] = json!("frame-other");
    trees.push(other_root);
    for tree in trees {
        let inspection = spawn_secret_inspection(&page, &node);
        let (result, _) =
            serve_page(&mut page, tree.clone(), SPOOFED_ORIGIN, None, inspection).await;
        assert_eq!(result, Err(SecretFillError::Rejected), "{tree}");
    }
    assert!(shard_intact(&mut page).await);
}

#[tokio::test]
async fn legacy_secret_inspection_across_a_navigation_is_refused_without_failing_the_shard() {
    // An honest page: only the race is under test here.
    let mut page = owned_page().await;
    let mut last_revision = 1;
    // A page can always `pushState`; a cross-document commit needs a navigation.
    for event in [push_state(), new_document()] {
        let node = mint_node(&mut page, 42).await;
        let inspection = spawn_secret_inspection(&page, &node);
        let (result, _) = serve_page(
            &mut page,
            main_frame_tree(BROWSER_ORIGIN),
            BROWSER_ORIGIN,
            Some(("Runtime.callFunctionOn", 1, event.clone())),
            inspection,
        )
        .await;
        assert_eq!(result, Err(SecretFillError::Rejected), "{event}");
        assert!(shard_intact(&mut page).await, "{event}");

        // The settled document is inspected under its own revision.
        let node = mint_node(&mut page, 43).await;
        let inspection = spawn_secret_inspection(&page, &node);
        let (target, _) = serve_page(
            &mut page,
            main_frame_tree(BROWSER_ORIGIN),
            BROWSER_ORIGIN,
            None,
            inspection,
        )
        .await;
        let target = target.expect("the settled document is inspectable");
        assert!(target.url_revision > last_revision, "{event}");
        last_revision = target.url_revision;
    }
}

#[tokio::test]
async fn legacy_secret_fill_refuses_a_navigation_after_inspection_without_failing_the_shard() {
    // An honest page: only the race is under test here.
    let mut page = owned_page().await;
    let catalog = Catalog::new(&page.tenant_id, BROWSER_ORIGIN);
    for event in [push_state(), new_document()] {
        let node = mint_node(&mut page, 42).await;
        let inspection = spawn_secret_inspection(&page, &node);
        let (target, _) = serve_page(
            &mut page,
            main_frame_tree(BROWSER_ORIGIN),
            BROWSER_ORIGIN,
            None,
            inspection,
        )
        .await;
        let fill = spawn_secret_fill(
            &page,
            target.unwrap(),
            catalog.secret(&page.tenant_id, BROWSER_ORIGIN),
        );
        // Resolves: the driver's re-inspection, the owner's re-inspection, then the fill's own
        // node. The page navigates while that last one is outstanding.
        let ((result, commits), commands) = serve_page(
            &mut page,
            main_frame_tree(BROWSER_ORIGIN),
            BROWSER_ORIGIN,
            Some(("DOM.resolveNode", 3, event.clone())),
            fill,
        )
        .await;
        // Authorization was committed, so the action stays unknown and is never replayed. The
        // credential never left the owner, though, and the shard keeps serving its sessions.
        assert_eq!(commits, 1, "{event}");
        assert_eq!(result, Ok(ActionExecutionResult::OutcomeUnknown), "{event}");
        assert!(
            !serde_json::to_string(&commands).unwrap().contains(SECRET),
            "{event}"
        );
        assert!(shard_intact(&mut page).await, "{event}");
    }
}
