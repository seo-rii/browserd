//! Secret values stay in a typed, zeroizing lane separate from public action payloads.
use futures::StreamExt;
use std::time::Instant;

use browserd_core::{PageId, SessionId, TenantId};
use browserd_policy::Origin;
use browserd_session::OwnershipFence;
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    ChromiumOwnerActor, ChromiumTargetManagerBackend, GuardedPageExecution, NodeFunctionCall,
    OwnerActorError, OwnerRequest, PageExecutionFence, downloads, valid_identifier,
};
use crate::{ResolvedSecret, SecretFillTarget, TargetManagerDrain};

// The secret is never passed to the inspection call, and page script never reports the origin.
// Cross-frame lookup is unsupported.
const INSPECT_SECRET_INPUT: &str = "function () { const el=this, doc=el.ownerDocument; if (!el.isConnected || doc!==document || !doc || doc.defaultView!==globalThis || globalThis!==globalThis.top || el.disabled || el.readOnly || el.matches(':disabled')) return false; return el.tagName==='TEXTAREA' || (el.tagName==='INPUT' && ['text','search','tel','url','email','password'].includes(el.type)); }";
// The in-page origin comparison can only refuse. The origin authority is the browser frame tree.
const FILL_SECRET_INPUT: &str = "function (expectedOrigin, value) { const el=this, doc=el.ownerDocument; if (!el.isConnected || doc!==document || !doc || doc.defaultView!==globalThis || globalThis!==globalThis.top || globalThis.location.origin!==expectedOrigin || el.disabled || el.readOnly || el.matches(':disabled')) return false; const tag=el.tagName; if (!(tag==='TEXTAREA' || (tag==='INPUT' && ['text','search','tel','url','email','password'].includes(el.type)))) return false; const proto=tag==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype; const setter=Object.getOwnPropertyDescriptor(proto,'value'); if (!setter || typeof setter.set!=='function') return false; setter.set.call(el,value); if (el.value!==value) return false; el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); return true; }";

#[cfg(test)]
use super::live_chromium;

pub(super) struct SecretTargetQuery {
    tenant: TenantId,
    session: SessionId,
    page: PageId,
    fence: OwnershipFence,
    node: String,
}

impl ChromiumTargetManagerBackend {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn inspect_secret_target_until(
        &self,
        tenant: TenantId,
        session: SessionId,
        page: PageId,
        fence: OwnershipFence,
        node: String,
        deadline: Instant,
    ) -> Result<SecretFillTarget, OwnerActorError> {
        self.mailbox.request_until(
            |response| OwnerRequest::InspectSecretTarget {
                query: SecretTargetQuery {
                    tenant,
                    session,
                    page,
                    fence,
                    node,
                },
                deadline,
                response,
            },
            deadline,
        )
    }

    pub(crate) fn fill_secret_until(
        &self,
        target: SecretFillTarget,
        secret: ResolvedSecret,
        deadline: Instant,
    ) -> Result<Value, OwnerActorError> {
        self.mailbox.request_until(
            |response| OwnerRequest::FillSecret {
                target,
                secret,
                deadline,
                response,
            },
            deadline,
        )
    }
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    pub(super) async fn inspect_typed_secret_input(
        &mut self,
        top: &str,
        node: &str,
        deadline: Instant,
    ) -> Result<(), OwnerActorError> {
        let (frame, _) = self.node_frame_guard(top, node, false)?;
        let valid = self.call_function_on_node(top, frame.scope.cdp_session_id.as_str().to_owned(), None, node,
            NodeFunctionCall { declaration: "function () { const el=this, doc=el.ownerDocument; return !!(el.isConnected && doc===document && doc && doc.defaultView===globalThis && !el.disabled && !el.readOnly && !el.matches(':disabled') && (el.tagName==='TEXTAREA' || (el.tagName==='INPUT' && ['text','search','tel','url','email','password'].includes(el.type)))); }", arguments:json!([]) }, Some(deadline)).await?;
        if valid != Value::Bool(true) {
            return Err(OwnerActorError::Rejected);
        }
        self.validate_frame_guard(&frame)
    }

    pub(super) async fn fill_typed_secret(
        &mut self,
        session: &SessionId,
        page: &PageId,
        node: &str,
        origin: &Origin,
        secret: ResolvedSecret,
        deadline: Instant,
    ) -> Result<Value, OwnerActorError> {
        let (_, top, _) = self.owned_page_route(session, page)?;
        self.inspect_typed_secret_input(&top, node, deadline)
            .await?;
        let (frame, backend) = self.node_frame_guard(&top, node, false)?;
        self.active_frame_guard = Some(frame.clone());
        let flat = frame.scope.cdp_session_id.as_str().to_owned();
        let resolved = self
            .command_event_first(
                "DOM.resolveNode",
                json!({"backendNodeId":backend,"executionContextId":frame.realm.id}),
                Some(flat.clone()),
                None,
                None,
                Some(deadline),
            )
            .await?;
        let object = resolved
            .pointer("/object/objectId")
            .and_then(Value::as_str)
            .filter(|value| valid_identifier(value))
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        #[derive(Serialize)]
        #[serde(untagged)]
        enum Argument<'a> {
            Object {
                #[serde(rename = "objectId")]
                object_id: &'a str,
            },
            Value {
                value: &'a str,
            },
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Invocation<'a> {
            unique_context_id: &'a str,
            function_declaration: &'a str,
            arguments: [Argument<'a>; 3],
            return_by_value: bool,
            await_promise: bool,
        }
        let invocation = Invocation {
            unique_context_id: &frame.realm.unique_id,
            function_declaration: "function (el, expectedOrigin, value) { const doc=el.ownerDocument; if (!el.isConnected || doc!==document || !doc || doc.defaultView!==globalThis || globalThis.location.origin!==expectedOrigin || el.disabled || el.readOnly || el.matches(':disabled')) return false; const tag=el.tagName; if (!(tag==='TEXTAREA' || (tag==='INPUT' && ['text','search','tel','url','email','password'].includes(el.type)))) return false; const proto=tag==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype; const setter=Object.getOwnPropertyDescriptor(proto,'value'); if (!setter || typeof setter.set!=='function') return false; setter.set.call(el,value); if (el.value!==value) return false; el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); return true; }",
            arguments: [
                Argument::Object { object_id: object },
                Argument::Value {
                    value: origin.as_str(),
                },
                Argument::Value {
                    value: secret.value(),
                },
            ],
            return_by_value: true,
            await_promise: false,
        };
        let client = self.client.clone();
        let deadline = self.context_command_deadline(deadline);
        let expires_at = deadline.min(Instant::now() + self.command_timeout);
        let command = client.command_sensitive(
            "Runtime.callFunctionOn",
            &invocation,
            Some(flat.clone()),
            expires_at,
        );
        tokio::pin!(command);
        let response = loop {
            self.service_downloads()
                .await
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            self.validate_active_approval()
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            self.validate_frame_guard(&frame)
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            if self.event_failed_closed || Instant::now() >= expires_at {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            tokio::select! {
                biased;
                ()=self.shutdown.cancelled()=>return Err(OwnerActorError::OutcomeUncertain),
                control = self.control_requests.recv() => {
                    self.start_control(control.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                completed = self.control_tasks.next(), if !self.control_tasks.is_empty() => {
                    self.finish_control(completed.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                ()=tokio::time::sleep_until(expires_at.into())=>return Err(OwnerActorError::OutcomeUncertain),
                ()=tokio::time::sleep(downloads::DOWNLOAD_TICK),if self.downloads.enabled()=>{},
                incoming=self.events.recv()=>{self.handle_incoming(incoming.ok_or(OwnerActorError::OutcomeUncertain)?,None).map_err(|_|OwnerActorError::OutcomeUncertain)?;},
                bootstrap=self.bootstrap_requests.recv(),if !self.bootstrap_in_progress=>{self.handle_bootstrap_request(bootstrap.ok_or(OwnerActorError::OutcomeUncertain)?,Some(deadline)).await.map_err(|_|OwnerActorError::OutcomeUncertain)?;},
                result=&mut command=>break result.map_err(|_|OwnerActorError::OutcomeUncertain)?,
            }
        };
        self.validate_active_approval()
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        self.validate_frame_guard(&frame)
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        if response.get("exceptionDetails").is_some()
            || response.pointer("/result/value") != Some(&Value::Bool(true))
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        self.command_event_first(
            "Runtime.releaseObject",
            json!({"objectId":object}),
            Some(flat),
            None,
            None,
            Some(deadline),
        )
        .await
        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        Ok(json!({"ok":true}))
    }

    pub(super) async fn inspect_secret_target(
        &mut self,
        query: &SecretTargetQuery,
        deadline: Instant,
    ) -> Result<SecretFillTarget, OwnerActorError> {
        if Instant::now() >= deadline {
            return Err(OwnerActorError::DeadlineBeforeDispatch);
        }
        if query.node.is_empty()
            || query.node.len() > 1024
            || query.node.trim() != query.node
            || query.node.chars().any(char::is_control)
        {
            return Err(OwnerActorError::Rejected);
        }
        let (_, target_id, route) = self.owned_page_route(&query.session, &query.page)?;
        if route.tenant_id() != &query.tenant || route.ownership_fence() != &query.fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let entry = self
            .routes
            .get(&target_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let fence = PageExecutionFence {
            target_incarnation: entry.target_incarnation,
            frame_document_epoch: entry.frame_document_epoch,
            url_revision: entry.url_revision,
        };
        // Only a node of the page's main frame resolves here; a child-frame node is refused
        // before any CDP command.
        let (frame, _) = self.node_frame_guard(&target_id, &query.node, true)?;
        // The origin comes from the browser's frame tree, never from page script: `globalThis`,
        // `location` and `defaultView` are page-writable, so a script-read origin could name
        // another origin's grant.
        let tree = self
            .command_event_first(
                "Page.getFrameTree",
                json!({}),
                Some(route.session_id().to_owned()),
                None,
                None,
                Some(deadline),
            )
            .await?;
        let eligible = self
            .call_function_on_node(
                &target_id,
                route.session_id().to_owned(),
                None,
                &query.node,
                NodeFunctionCall {
                    declaration: INSPECT_SECRET_INPUT,
                    arguments: json!([]),
                },
                Some(deadline),
            )
            .await?;
        if eligible != Value::Bool(true) {
            return Err(OwnerActorError::Rejected);
        }
        // Both reads are unguarded, so events that precede each response have been applied and a
        // document change shows up here. It is a known refusal of a read-only inspection;
        // OutcomeUncertain would fail the whole shard closed and let any page tear down every
        // session on it by navigating.
        self.validate_frame_guard(&frame)?;
        let entry = self
            .routes
            .get(&target_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if entry.route.ownership_fence() != &query.fence {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        if entry.target_incarnation != fence.target_incarnation
            || entry.frame_document_epoch != fence.frame_document_epoch
            || entry.url_revision != fence.url_revision
        {
            return Err(OwnerActorError::Rejected);
        }
        let root = tree
            .pointer("/frameTree/frame")
            .ok_or(OwnerActorError::Rejected)?;
        if root.get("id").and_then(Value::as_str) != Some(frame.scope.frame_id.as_str())
            || root.get("parentId").is_some()
        {
            return Err(OwnerActorError::Rejected);
        }
        // A secret binds only to a canonical tuple HTTP(S) origin. An opaque document (a fresh
        // `about:blank`, `data:`, a sandboxed page) reports none and is refused.
        let raw_origin = root
            .get("securityOrigin")
            .and_then(Value::as_str)
            .filter(|origin| origin.len() <= 8_192)
            .ok_or(OwnerActorError::Rejected)?;
        let origin = Origin::parse(raw_origin).map_err(|_| OwnerActorError::Rejected)?;
        if origin.as_str() != raw_origin {
            return Err(OwnerActorError::Rejected);
        }
        Ok(SecretFillTarget {
            tenant_id: query.tenant.clone(),
            session_id: query.session.clone(),
            page_id: query.page.clone(),
            fence: query.fence.clone(),
            node_ref: query.node.clone(),
            origin,
            target_incarnation: fence.target_incarnation,
            frame_document_epoch: fence.frame_document_epoch,
            url_revision: fence.url_revision,
        })
    }

    /// Fills an authorized secret into the inspected target. `Rejected` is returned only before
    /// the credential is submitted; every failure after that is `OutcomeUncertain`.
    pub(super) async fn fill_secret(
        &mut self,
        target: &SecretFillTarget,
        secret: ResolvedSecret,
        deadline: Instant,
    ) -> Result<Value, OwnerActorError> {
        if secret.grant().tenant_id() != &target.tenant_id
            || secret.grant().origin() != &target.origin
        {
            return Err(OwnerActorError::Rejected);
        }
        let current = self
            .inspect_secret_target(
                &SecretTargetQuery {
                    tenant: target.tenant_id.clone(),
                    session: target.session_id.clone(),
                    page: target.page_id.clone(),
                    fence: target.fence.clone(),
                    node: target.node_ref.clone(),
                },
                deadline,
            )
            .await?;
        if &current != target {
            return Err(OwnerActorError::Rejected);
        }
        let (_, target_id, route) = self.owned_page_route(&target.session_id, &target.page_id)?;
        let guarded = Some(GuardedPageExecution {
            viewer_transform: None,
            target_id: target_id.clone(),
            fence: PageExecutionFence {
                target_incarnation: target.target_incarnation,
                frame_document_epoch: target.frame_document_epoch,
                url_revision: target.url_revision,
            },
        });
        let backend = self.resolve_node_backend_id(&target_id, &target.node_ref)?;
        let resolved = self
            .command_event_first(
                "DOM.resolveNode",
                json!({"backendNodeId":backend}),
                Some(route.session_id().to_owned()),
                None,
                None,
                Some(deadline),
            )
            .await?;
        let object = resolved
            .get("object")
            .and_then(|object| object.get("objectId"))
            .and_then(Value::as_str)
            .filter(|value| valid_identifier(value))
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        // The credential has not left the actor yet, so a document that changed since the
        // inspection is a known refusal rather than an uncertain effect.
        let entry = self
            .routes
            .get(&target_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if entry.target_incarnation != target.target_incarnation
            || entry.frame_document_epoch != target.frame_document_epoch
            || entry.url_revision != target.url_revision
        {
            return Err(OwnerActorError::Rejected);
        }

        #[derive(Serialize)]
        struct Argument<'a> {
            value: &'a str,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Invocation<'a> {
            object_id: &'a str,
            function_declaration: &'a str,
            arguments: [Argument<'a>; 2],
            return_by_value: bool,
            await_promise: bool,
        }
        let invocation = Invocation {
            object_id: object,
            function_declaration: FILL_SECRET_INPUT,
            arguments: [
                Argument {
                    value: target.origin.as_str(),
                },
                Argument {
                    value: secret.value(),
                },
            ],
            return_by_value: true,
            await_promise: false,
        };
        let client = self.client.clone();
        let deadline = self.context_command_deadline(deadline);
        let expires_at = deadline.min(Instant::now() + self.command_timeout);
        let command = client.command_sensitive(
            "Runtime.callFunctionOn",
            &invocation,
            Some(route.session_id().to_owned()),
            expires_at,
        );
        tokio::pin!(command);
        let response = loop {
            self.service_downloads()
                .await
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            let entry = self
                .routes
                .get(&target_id)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            if self.event_failed_closed
                || Instant::now() >= deadline
                || entry.target_incarnation != target.target_incarnation
                || entry.frame_document_epoch != target.frame_document_epoch
                || entry.url_revision != target.url_revision
                || entry.route.ownership_fence() != &target.fence
            {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => return Err(OwnerActorError::OutcomeUncertain),
                control = self.control_requests.recv() => {
                    self.start_control(control.ok_or(OwnerActorError::OutcomeUncertain)?)
                        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                }
                completed = self.control_tasks.next(), if !self.control_tasks.is_empty() => {
                    self.finish_control(completed.ok_or(OwnerActorError::OutcomeUncertain)?)
                        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                }
                () = tokio::time::sleep_until(deadline.into()) => return Err(OwnerActorError::OutcomeUncertain),
                () = tokio::time::sleep(downloads::DOWNLOAD_TICK), if self.downloads.enabled() => {}
                incoming = self.events.recv() => {
                    self.handle_incoming(incoming.ok_or(OwnerActorError::OutcomeUncertain)?, None)
                        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                }
                bootstrap = self.bootstrap_requests.recv(), if !self.bootstrap_in_progress => {
                    self.handle_bootstrap_request(bootstrap.ok_or(OwnerActorError::OutcomeUncertain)?, Some(deadline))
                        .await.map_err(|_| OwnerActorError::OutcomeUncertain)?;
                }
                result = &mut command => break result.map_err(|_| OwnerActorError::OutcomeUncertain)?,
            }
        };
        if response.get("exceptionDetails").is_some()
            || response.get("result").and_then(|value| value.get("value"))
                != Some(&Value::Bool(true))
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        self.command_event_first(
            "Runtime.releaseObject",
            json!({"objectId":object}),
            Some(route.session_id().to_owned()),
            None,
            guarded,
            Some(deadline),
        )
        .await
        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        Ok(json!({"ok":true}))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod live_tests {
    use super::*;
    use crate::{
        ActionExecutionResult, ChromiumDriver, FileSecretResolver, SecretFillError, SecretResolver,
    };
    use browserd_core::PrincipalId;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::net::SocketAddr;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..32 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 2048];
                if !matches!(
                    tokio::time::timeout(Duration::from_secs(2), socket.read(&mut request)).await,
                    Ok(Ok(1..))
                ) {
                    continue;
                }
                let body = "<!doctype html><meta charset=utf-8><input id=password type=password><textarea id=notes></textarea><input id=disabled disabled><input id=readonly readonly><input id=file type=file><fieldset disabled><input id=fieldset></fieldset><script>window.events=[];for(const name of ['input','change'])document.addEventListener(name,e=>events.push(name+':'+e.target.id));</script>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        (address, server)
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    }

    async fn inspect(
        browser: &live_chromium::LiveChromium,
        node: &str,
    ) -> Result<SecretFillTarget, SecretFillError> {
        let driver = browser.driver.clone();
        let (tenant, session, page, fence, node) = (
            browser.tenant.clone(),
            browser.session.clone(),
            browser.page.clone(),
            browser.fence.clone(),
            node.to_owned(),
        );
        tokio::task::spawn_blocking(move || {
            driver.inspect_secret_fill_target_until(
                &tenant,
                &session,
                &page,
                &fence,
                &node,
                Instant::now() + Duration::from_secs(5),
            )
        })
        .await
        .unwrap()
    }

    async fn execute(
        browser: &live_chromium::LiveChromium,
        target: SecretFillTarget,
        secret: ResolvedSecret,
        authorize: bool,
    ) -> (Result<ActionExecutionResult, SecretFillError>, usize) {
        let driver = browser.driver.clone();
        tokio::task::spawn_blocking(move || {
            let mut commits = 0;
            let result = driver.execute_secret_fill_until(
                &target,
                secret,
                Instant::now() + Duration::from_secs(5),
                &mut |_| {
                    if !authorize {
                        return Err(SecretFillError::DispatchRevoked);
                    }
                    commits += 1;
                    Ok(())
                },
            );
            (result, commits)
        })
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires explicitly configured sandbox-enabled Chromium; functional proof, not production qualification"]
    async fn actual_owner_secret_fill_preserves_origin_and_redacts_results() {
        tokio::time::timeout(Duration::from_secs(80), async {
            let (address, server_a) = server().await;
            let (other_address, server_b) = server().await;
            let browser = live_chromium::LiveChromium::start().await;
            let origin_text = format!("http://{address}");
            let origin = Origin::parse(&origin_text).unwrap();
            let principal = PrincipalId::new();
            let temporary = tempfile::tempdir().unwrap();
            let dummy = "fixture-only-한글-비밀번호";
            private_file(&temporary.path().join("value"), dummy.as_bytes());
            private_file(&temporary.path().join("catalog.json"), &serde_json::to_vec(&json!({
                "schema_version":1,"grants":[{"tenant_id":browser.tenant,"principal_ids":[principal],
                    "secret_ref":"fixture-login","allowed_origins":[origin_text],"value_file":"value"}]
            })).unwrap());
            let provider = FileSecretResolver::open(&temporary.path().join("catalog.json")).unwrap();
            let grant = provider.authorize(&browser.tenant, &principal, "fixture-login", &origin,
                Instant::now()+Duration::from_secs(5)).unwrap();
            let resolve = || provider.resolve(&grant, Instant::now()+Duration::from_secs(5)).unwrap();
            let navigate = |url: String| json!({"type":"navigate","url":url,"wait_until":"load"});
            assert!(matches!(browser.action(navigate(format!("{origin_text}/"))).await, ActionExecutionResult::Succeeded(_)));

            for selector in ["#disabled", "#readonly", "#file", "#fieldset"] {
                let node = browser.node(selector).await;
                assert!(matches!(inspect(&browser, &node).await, Err(SecretFillError::Rejected)));
            }
            let node = browser.node("#password").await;
            let initial = inspect(&browser, &node).await.unwrap();
            assert_eq!(initial.origin, origin);
            let mut foreign = initial.clone();
            foreign.tenant_id = TenantId::new();
            let (foreign_tenant, commits) = execute(&browser, foreign, resolve(), true).await;
            assert!(matches!(foreign_tenant, Err(SecretFillError::DispatchRevoked)));
            assert_eq!(commits, 0);
            let (revoked, commits) = execute(&browser, initial.clone(), resolve(), false).await;
            assert!(matches!(revoked, Err(SecretFillError::DispatchRevoked)));
            assert_eq!(commits, 0);
            assert_eq!(browser.evaluate("document.querySelector('#password').value.length").await, json!(0));
            assert!(matches!(browser.action(json!({"type":"reload"})).await, ActionExecutionResult::Succeeded(_)));
            let (stale, commits) = execute(&browser, initial, resolve(), true).await;
            assert!(stale.is_err());
            assert_eq!(commits, 0);

            assert!(matches!(browser.action(navigate(format!("http://{other_address}/"))).await, ActionExecutionResult::Succeeded(_)));
            let node = browser.node("#password").await;
            let other = inspect(&browser, &node).await.unwrap();
            assert_ne!(other.origin, origin);
            let (wrong_port, commits) = execute(&browser, other.clone(), resolve(), true).await;
            assert!(matches!(wrong_port, Err(SecretFillError::DispatchRevoked)));
            assert_eq!(commits, 0);
            let mut forged = other;
            forged.origin = origin.clone();
            let (wrong_observation, commits) = execute(&browser, forged, resolve(), true).await;
            assert!(matches!(wrong_observation, Err(SecretFillError::DispatchRevoked)));
            assert_eq!(commits, 0);

            assert!(matches!(browser.action(navigate(format!("{origin_text}/"))).await, ActionExecutionResult::Succeeded(_)));
            for selector in ["#password", "#notes"] {
                let node = browser.node(selector).await;
                let target = inspect(&browser, &node).await.unwrap();
                let (result, commits) = execute(&browser, target, resolve(), true).await;
                assert!(matches!(result, Ok(ActionExecutionResult::Succeeded(ref bytes)) if bytes == br#"{"ok":true}"#));
                assert_eq!(commits, 1);
            }
            // Read only hashes and event metadata back through ordinary page evaluation.
            let hashes = browser.evaluate("Promise.all(['password','notes'].map(async id=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(document.getElementById(id).value))),b=>b.toString(16).padStart(2,'0')).join('')))").await;
            let expected = format!("{:x}", Sha256::digest(dummy.as_bytes()));
            assert_eq!(hashes, json!([expected, expected]));
            assert_eq!(browser.evaluate("window.events").await, json!(["input:password","change:password","input:notes","change:notes"]));

            // A native setter effect followed by an exception must never permit replay.
            browser.evaluate("(()=>{const d=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');Object.defineProperty(HTMLInputElement.prototype,'value',{...d,set(v){d.set.call(this,v);throw new Error('fixture setter interruption')}});return true})()").await;
            let node = browser.node("#password").await;
            let target = inspect(&browser, &node).await.unwrap();
            let (uncertain, commits) = execute(&browser, target, resolve(), true).await;
            assert!(matches!(uncertain, Ok(ActionExecutionResult::OutcomeUnknown)));
            assert_eq!(commits, 1);
            let _ = browser.owner.shutdown_and_join(Duration::from_secs(2)).await;
            assert!(browser.targets.is_tainted());
            server_a.abort(); server_b.abort();
        }).await.expect("bounded actual secret fill proof");
    }
}
