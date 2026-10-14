//! Bounded, context-owned state capture and one-shot offline restoration.
//! No persistent initialization script or upstream request is used to seed storage.
use futures::StreamExt;
use std::collections::BTreeSet;
use std::time::Instant;

use browserd_core::{PageId, SessionId, TenantId};
use browserd_policy::Origin;
use browserd_session::OwnershipFence;
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    ChromiumOwnerActor, ChromiumTargetManagerBackend, ChromiumTargetRoute, GuardedPageExecution,
    OwnerActorError, OwnerRequest, PageExecutionFence, TargetKind, valid_identifier,
};
use crate::{
    CheckpointCookie, CheckpointOriginStorage, CheckpointSnapshot, CheckpointStorageEntry,
    TargetManagerDrain,
};

const MAX_ORIGINS: usize = 16;
const MAX_ENTRIES: usize = 256;
const MAX_COOKIES: usize = 128;
const MAX_PAUSED_REQUESTS: usize = 128;

pub(super) struct CheckpointQuery {
    pub(super) tenant: TenantId,
    pub(super) session: SessionId,
    pub(super) fence: OwnershipFence,
}

/// Exists only while the unpublished primary page is used to seed storage.
/// Unknown requests are failed, never continued, even when the expected request completed.
pub(super) struct RestoreInterception {
    session_id: String,
    frame_id: String,
    expected_url: Option<String>,
    fulfilled: bool,
    seen: BTreeSet<String>,
}

impl RestoreInterception {
    fn response(
        &mut self,
        session: Option<&str>,
        params: &Value,
    ) -> Result<(&'static str, Value), OwnerActorError> {
        if session != Some(self.session_id.as_str()) || self.seen.len() >= MAX_PAUSED_REQUESTS {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let id = params
            .get("requestId")
            .and_then(Value::as_str)
            .filter(|id| valid_identifier(id))
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if !self.seen.insert(id.to_owned()) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let expected = !self.fulfilled
            && self.expected_url.as_deref()
                == params.pointer("/request/url").and_then(Value::as_str)
            && self.expected_url.is_some()
            && params.pointer("/request/method").and_then(Value::as_str) == Some("GET")
            && params.get("frameId").and_then(Value::as_str) == Some(self.frame_id.as_str())
            && params.get("resourceType").and_then(Value::as_str) == Some("Document")
            && params.get("responseStatusCode").is_none()
            && params.get("responseErrorReason").is_none();
        if expected {
            self.fulfilled = true;
            Ok((
                "Fetch.fulfillRequest",
                json!({
                    "requestId":id,"responseCode":200,
                    "responseHeaders":[
                        {"name":"Content-Type","value":"text/html; charset=utf-8"},
                        {"name":"Cache-Control","value":"no-store"},
                        {"name":"Content-Security-Policy","value":"default-src 'none'; frame-src 'none'; connect-src 'none'; script-src 'none'"}
                    ],
                    "body":"PCFkb2N0eXBlIGh0bWw+PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjwvYm9keT48L2h0bWw+"
                }),
            ))
        } else {
            Ok((
                "Fetch.failRequest",
                json!({"requestId":id,"errorReason":"BlockedByClient"}),
            ))
        }
    }
}

impl ChromiumTargetManagerBackend {
    pub(crate) fn capture_checkpoint_until(
        &self,
        tenant: TenantId,
        session: SessionId,
        fence: OwnershipFence,
        origins: Vec<String>,
        deadline: Instant,
    ) -> Result<CheckpointSnapshot, OwnerActorError> {
        self.mailbox.request_until(
            |response| OwnerRequest::CaptureCheckpoint {
                query: CheckpointQuery {
                    tenant,
                    session,
                    fence,
                },
                origins,
                deadline,
                response,
            },
            deadline,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore_checkpoint_until(
        &self,
        tenant: TenantId,
        session: SessionId,
        primary_page: PageId,
        fence: OwnershipFence,
        snapshot: CheckpointSnapshot,
        deadline: Instant,
    ) -> Result<(), OwnerActorError> {
        self.mailbox.request_until(
            |response| OwnerRequest::RestoreCheckpoint {
                query: CheckpointQuery {
                    tenant,
                    session,
                    fence,
                },
                primary_page,
                snapshot,
                deadline,
                response,
            },
            deadline,
        )
    }
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    fn checkpoint_context(&self, query: &CheckpointQuery) -> Result<String, OwnerActorError> {
        let (id, context) = self.active_context_for_session(&query.session)?;
        if context.ownership.tenant_id != query.tenant || context.ownership.fence != query.fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        Ok(id.to_owned())
    }

    /// Sensitive serialization also redacts protocol errors; incoming payloads never enter
    /// public action results. This loop services Fetch before waiting for navigate ACKs.
    async fn checkpoint_command<T: Serialize + ?Sized>(
        &mut self,
        method: &'static str,
        params: &T,
        session: Option<String>,
        guarded: Option<GuardedPageExecution>,
        deadline: Instant,
    ) -> Result<Value, OwnerActorError> {
        let deadline = self.context_command_deadline(deadline);
        if Instant::now() >= deadline {
            return Err(OwnerActorError::DeadlineBeforeDispatch);
        }
        let client = self.client.clone();
        let expires = deadline.min(Instant::now() + self.command_timeout);
        let command = client.command_sensitive(method, params, session, expires);
        tokio::pin!(command);
        loop {
            self.service_downloads()
                .await
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            self.validate_active_approval()?;
            if self.event_failed_closed {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            if let Some(guard) = &guarded {
                self.validate_checkpoint_guard(guard)?;
            }
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => return Err(OwnerActorError::OutcomeUncertain),
                control = self.control_requests.recv() => {
                    self.start_control(control.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                completed = self.control_tasks.next(), if !self.control_tasks.is_empty() => {
                    self.finish_control(completed.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                () = tokio::time::sleep(super::downloads::DOWNLOAD_TICK), if self.downloads.enabled() => {},
                () = tokio::time::sleep_until(expires.into()) => return Err(OwnerActorError::OutcomeUncertain),
                incoming = super::control::checkpoint_event(&mut self.events, &mut self.deferred_checkpoint_events) => {
                    let incoming = incoming.ok_or(OwnerActorError::OutcomeUncertain)?;
                    if let browserd_cdp::CdpIncoming::Event { method, params, session_id } = &incoming
                        && method == "Fetch.requestPaused"
                    {
                        let state = self.checkpoint_interception.as_mut().ok_or(OwnerActorError::OutcomeUncertain)?;
                        let response_session = state.session_id.clone();
                        let (method, params) = state.response(session_id.as_deref(), params)?;
                        let client = self.client.clone();
                        let command = client.command_sensitive(method, &params, Some(response_session), expires);
                        let response = self.control_ack(command, expires).await?;
                        if !response.is_object() { return Err(OwnerActorError::OutcomeUncertain); }
                    } else {
                        self.handle_incoming(incoming, None).map_err(|_| OwnerActorError::OutcomeUncertain)?;
                    }
                }
                bootstrap = self.bootstrap_requests.recv(), if !self.bootstrap_in_progress => {
                    self.handle_bootstrap_request(bootstrap.ok_or(OwnerActorError::OutcomeUncertain)?, Some(deadline))
                        .await.map_err(|_| OwnerActorError::OutcomeUncertain)?;
                }
                result = &mut command => {
                    let result = result.map_err(|_| OwnerActorError::OutcomeUncertain)?;
                    if !result.is_object() { return Err(OwnerActorError::OutcomeUncertain); }
                    if let Some(guard) = &guarded { self.validate_checkpoint_guard(guard)?; }
                    self.validate_active_approval()?;
                    return Ok(result);
                }
            }
        }
    }

    fn validate_checkpoint_guard(
        &self,
        guard: &GuardedPageExecution,
    ) -> Result<(), OwnerActorError> {
        let entry = self
            .routes
            .get(&guard.target_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if entry.target_incarnation != guard.fence.target_incarnation
            || entry.frame_document_epoch != guard.fence.frame_document_epoch
            || entry.url_revision != guard.fence.url_revision
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(())
    }

    fn checkpoint_guard(&self, target: &str) -> Result<GuardedPageExecution, OwnerActorError> {
        let entry = self
            .routes
            .get(target)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        Ok(GuardedPageExecution {
            viewer_transform: None,
            target_id: target.to_owned(),
            fence: PageExecutionFence {
                target_incarnation: entry.target_incarnation,
                frame_document_epoch: entry.frame_document_epoch,
                url_revision: entry.url_revision,
            },
        })
    }

    pub(super) async fn capture_checkpoint(
        &mut self,
        query: &CheckpointQuery,
        origins: &[String],
        deadline: Instant,
    ) -> Result<CheckpointSnapshot, OwnerActorError> {
        validate_origins(origins)?;
        let context_id = self.checkpoint_context(query)?;
        let response = self
            .checkpoint_command(
                "Storage.getCookies",
                &json!({"browserContextId":context_id}),
                None,
                None,
                deadline,
            )
            .await?;
        let cookies = parse_cookies(response)?;
        let mut snapshot = CheckpointSnapshot {
            artifact_identity: self.artifact_identity.clone(),
            cookies,
            origins: Vec::new(),
        };
        let mut outstanding: BTreeSet<&str> = origins.iter().map(String::as_str).collect();
        let pages: Vec<_> = self
            .contexts
            .get(&context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .pages
            .keys()
            .cloned()
            .collect();
        let mut guards = Vec::new();
        for page in pages {
            if outstanding.is_empty() {
                break;
            }
            let (_, target, route) = self.owned_page_route(&query.session, &page)?;
            let guard = self.checkpoint_guard(&target)?;
            let tree = self
                .checkpoint_command(
                    "Page.getFrameTree",
                    &json!({}),
                    Some(route.session_id().to_owned()),
                    Some(guard.clone()),
                    deadline,
                )
                .await?;
            let frame = tree
                .pointer("/frameTree/frame")
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            let Some(origin) = frame_origin(frame) else {
                continue;
            };
            if !outstanding.contains(origin.as_str()) {
                continue;
            }
            let response = self
                .checkpoint_command(
                    "DOMStorage.getDOMStorageItems",
                    &json!({"storageId":{"securityOrigin":origin,"isLocalStorage":true}}),
                    Some(route.session_id().to_owned()),
                    Some(guard.clone()),
                    deadline,
                )
                .await?;
            let entries = parse_entries(response)?;
            outstanding.remove(origin.as_str());
            snapshot.origins.push(CheckpointOriginStorage {
                origin,
                local_storage: entries,
            });
            snapshot.validate().map_err(|_| OwnerActorError::Rejected)?;
            guards.push(guard);
        }
        if !outstanding.is_empty() {
            return Err(OwnerActorError::Rejected);
        }
        if self.checkpoint_context(query)? != context_id {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        for guard in &guards {
            self.validate_checkpoint_guard(guard)?;
        }
        snapshot.origins.sort_by(|a, b| a.origin.cmp(&b.origin));
        snapshot.validate().map_err(|_| OwnerActorError::Rejected)?;
        Ok(snapshot)
    }

    pub(super) async fn restore_checkpoint(
        &mut self,
        query: &CheckpointQuery,
        primary_page: &PageId,
        snapshot: CheckpointSnapshot,
        deadline: Instant,
    ) -> Result<(), OwnerActorError> {
        snapshot.validate().map_err(|_| OwnerActorError::Rejected)?;
        if snapshot.artifact_identity != self.artifact_identity
            || self.checkpoint_interception.is_some()
        {
            return Err(OwnerActorError::Rejected);
        }
        let context_id = self.checkpoint_context(query)?;
        let context = self
            .contexts
            .get(&context_id)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if !context.checkpoint_restore_available
            || context.pages.len() != 1
            || !context.closing_pages.is_empty()
        {
            return Err(OwnerActorError::Rejected);
        }
        let (_, target, route) = self.owned_page_route(&query.session, primary_page)?;
        if self
            .routes
            .get(&target)
            .is_none_or(|entry| entry.kind != TargetKind::Page)
        {
            return Err(OwnerActorError::Rejected);
        }
        let tree = self
            .checkpoint_command(
                "Page.getFrameTree",
                &json!({}),
                Some(route.session_id().to_owned()),
                None,
                deadline,
            )
            .await?;
        let frame = tree
            .pointer("/frameTree/frame")
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if frame.get("url").and_then(Value::as_str) != Some("about:blank")
            || tree
                .pointer("/frameTree/childFrames")
                .and_then(Value::as_array)
                .is_some_and(|frames| !frames.is_empty())
        {
            return Err(OwnerActorError::Rejected);
        }
        let frame_id = frame
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| valid_identifier(id))
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .to_owned();
        let guard = self.checkpoint_guard(&target)?;
        let current = self
            .checkpoint_command(
                "Storage.getCookies",
                &json!({"browserContextId":context_id}),
                None,
                Some(guard),
                deadline,
            )
            .await?;
        if !parse_cookies(current)?.is_empty()
            || self
                .contexts
                .get(&context_id)
                .is_none_or(|context| !context.checkpoint_restore_available)
        {
            return Err(OwnerActorError::Rejected);
        }
        self.contexts
            .get_mut(&context_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .checkpoint_restore_available = false;
        // From this point any failure means this new context must be discarded, not retried.
        let result = self
            .restore_checkpoint_effect(&route, &target, &frame_id, &snapshot, deadline)
            .await;
        if result.is_err() {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        if self.checkpoint_context(query)? != context_id {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let (_, observed_target, observed_route) = self
            .owned_page_route(&query.session, primary_page)
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        if observed_target != target || observed_route != route {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(())
    }

    async fn restore_checkpoint_effect(
        &mut self,
        route: &ChromiumTargetRoute,
        target: &str,
        frame_id: &str,
        snapshot: &CheckpointSnapshot,
        deadline: Instant,
    ) -> Result<(), OwnerActorError> {
        let session = route.session_id().to_owned();
        if !snapshot.origins.is_empty() {
            self.checkpoint_interception = Some(RestoreInterception {
                session_id: session.clone(),
                frame_id: frame_id.to_owned(),
                expected_url: None,
                fulfilled: false,
                seen: BTreeSet::new(),
            });
            self.checkpoint_command(
                "Fetch.enable",
                &json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}),
                Some(session.clone()),
                None,
                deadline,
            )
            .await?;
            for origin in &snapshot.origins {
                let url = format!(
                    "{}/.browserd-checkpoint/{}",
                    origin.origin,
                    uuid::Uuid::new_v4()
                );
                let state = self
                    .checkpoint_interception
                    .as_mut()
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                state.expected_url = Some(url.clone());
                state.fulfilled = false;
                let nav = self
                    .checkpoint_command(
                        "Page.navigate",
                        &json!({"url":url}),
                        Some(session.clone()),
                        None,
                        deadline,
                    )
                    .await?;
                if nav.get("errorText").is_some()
                    || nav.get("isDownload").and_then(Value::as_bool) == Some(true)
                {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                self.wait_checkpoint_document(target, &session, &url, deadline)
                    .await?;
                if !self
                    .checkpoint_interception
                    .as_ref()
                    .is_some_and(|state| state.fulfilled)
                {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                let guard = self.checkpoint_guard(target)?;
                let existing = self.checkpoint_command("DOMStorage.getDOMStorageItems", &json!({"storageId":{"securityOrigin":origin.origin,"isLocalStorage":true}}), Some(session.clone()), Some(guard.clone()), deadline).await?;
                if !parse_entries(existing)?.is_empty() {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct StorageId<'a> {
                    security_origin: &'a str,
                    is_local_storage: bool,
                }
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct Item<'a> {
                    storage_id: StorageId<'a>,
                    key: &'a str,
                    value: &'a str,
                }
                for entry in &origin.local_storage {
                    let item = Item {
                        storage_id: StorageId {
                            security_origin: &origin.origin,
                            is_local_storage: true,
                        },
                        key: &entry.name,
                        value: &entry.value,
                    };
                    self.checkpoint_command(
                        "DOMStorage.setDOMStorageItem",
                        &item,
                        Some(session.clone()),
                        Some(guard.clone()),
                        deadline,
                    )
                    .await?;
                }
                let observed = self.checkpoint_command("DOMStorage.getDOMStorageItems", &json!({"storageId":{"securityOrigin":origin.origin,"isLocalStorage":true}}), Some(session.clone()), Some(guard), deadline).await?;
                let actual = parse_entries(observed)?;
                if actual.len() != origin.local_storage.len()
                    || actual.iter().any(|a| {
                        !origin
                            .local_storage
                            .iter()
                            .any(|b| a.name == b.name && a.value == b.value)
                    })
                {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
            }
            self.checkpoint_interception
                .as_mut()
                .ok_or(OwnerActorError::OutcomeUncertain)?
                .expected_url = None;
            let nav = self
                .checkpoint_command(
                    "Page.navigate",
                    &json!({"url":"about:blank"}),
                    Some(session.clone()),
                    None,
                    deadline,
                )
                .await?;
            if nav.get("errorText").is_some() {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            self.wait_checkpoint_document(target, &session, "about:blank", deadline)
                .await?;
            self.checkpoint_command(
                "Page.resetNavigationHistory",
                &json!({}),
                Some(session.clone()),
                None,
                deadline,
            )
            .await?;
            self.checkpoint_command("Fetch.disable", &json!({}), Some(session), None, deadline)
                .await?;
            if !self.deferred_checkpoint_events.is_empty() {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            self.checkpoint_interception = None;
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Cookies<'a> {
            browser_context_id: &'a str,
            cookies: &'a [CheckpointCookie],
        }
        self.checkpoint_command(
            "Storage.setCookies",
            &Cookies {
                browser_context_id: route.browser_context_id(),
                cookies: &snapshot.cookies,
            },
            None,
            None,
            deadline,
        )
        .await?;
        let observed = self
            .checkpoint_command(
                "Storage.getCookies",
                &json!({"browserContextId":route.browser_context_id()}),
                None,
                None,
                deadline,
            )
            .await?;
        let cookies = parse_cookies(observed)?;
        // Chromium may normalize expiry precision; every security/ownership attribute is exact.
        if cookies.len() != snapshot.cookies.len()
            || cookies
                .iter()
                .any(|a| !snapshot.cookies.iter().any(|b| cookie_matches(a, b)))
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(())
    }

    async fn wait_checkpoint_document(
        &mut self,
        target: &str,
        session: &str,
        url: &str,
        deadline: Instant,
    ) -> Result<(), OwnerActorError> {
        loop {
            let tree = self
                .checkpoint_command(
                    "Page.getFrameTree",
                    &json!({}),
                    Some(session.to_owned()),
                    None,
                    deadline,
                )
                .await?;
            let entry = self
                .routes
                .get(target)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            if tree.pointer("/frameTree/frame/url").and_then(Value::as_str) == Some(url)
                && entry.document.dom_content_loaded
            {
                return Ok(());
            }
            // Each bounded command pumps lifecycle and interception events; no detached navigation.
            if Instant::now() >= deadline {
                return Err(OwnerActorError::OutcomeUncertain);
            }
        }
    }
}

pub(super) fn validate_origins(origins: &[String]) -> Result<(), OwnerActorError> {
    if origins.len() > MAX_ORIGINS {
        return Err(OwnerActorError::Rejected);
    }
    let mut seen = BTreeSet::new();
    for text in origins {
        let origin = Origin::parse(text).map_err(|_| OwnerActorError::Rejected)?;
        if text.len() > 2048 || origin.as_str() != text || !seen.insert(text) {
            return Err(OwnerActorError::Rejected);
        }
    }
    Ok(())
}

fn frame_origin(frame: &Value) -> Option<String> {
    let url = url::Url::parse(frame.get("url")?.as_str()?).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let text = url.origin().ascii_serialization();
    let origin = Origin::parse(&text).ok()?;
    // An HTTP URL can still have an opaque sandboxed security origin. Such a page
    // must not authorize DOMStorage access through a different matching child frame.
    (origin.as_str() == text
        && frame.get("securityOrigin").and_then(Value::as_str) == Some(text.as_str()))
    .then_some(text)
}

fn parse_entries(mut response: Value) -> Result<Vec<CheckpointStorageEntry>, OwnerActorError> {
    let entries = response
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .ok_or(OwnerActorError::OutcomeUncertain)?;
    if entries.len() > MAX_ENTRIES {
        return Err(OwnerActorError::Rejected);
    }
    let mut output: Vec<CheckpointStorageEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = entry
            .as_array_mut()
            .filter(|fields| fields.len() == 2)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let Value::String(name) = fields[0].take() else {
            return Err(OwnerActorError::OutcomeUncertain);
        };
        let Value::String(value) = fields[1].take() else {
            return Err(OwnerActorError::OutcomeUncertain);
        };
        if output.iter().any(|entry| entry.name == name) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        output.push(CheckpointStorageEntry { name, value });
    }
    Ok(output)
}

fn parse_cookies(mut response: Value) -> Result<Vec<CheckpointCookie>, OwnerActorError> {
    let cookies = response
        .get_mut("cookies")
        .and_then(Value::as_array_mut)
        .ok_or(OwnerActorError::OutcomeUncertain)?;
    if cookies.len() > MAX_COOKIES {
        return Err(OwnerActorError::Rejected);
    }
    let mut output = Vec::with_capacity(cookies.len());
    for cookie in cookies {
        let object = cookie
            .as_object_mut()
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if object.contains_key("partitionKey")
            || object
                .get("partitionKeyOpaque")
                .is_some_and(|value| value != &Value::Bool(false))
            || object
                .get("sameParty")
                .is_some_and(|value| value != &Value::Bool(false))
        {
            return Err(OwnerActorError::Rejected);
        }
        object.remove("partitionKeyOpaque");
        object.remove("sameParty");
        object.remove("size");
        let session = object
            .remove("session")
            .and_then(|value| value.as_bool())
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if session {
            object.remove("expires");
        }
        output.push(serde_json::from_value(cookie.take()).map_err(|_| OwnerActorError::Rejected)?);
    }
    Ok(output)
}

fn cookie_matches(a: &CheckpointCookie, b: &CheckpointCookie) -> bool {
    a.name == b.name
        && a.value == b.value
        && a.domain == b.domain
        && a.path == b.path
        && a.http_only == b.http_only
        && a.secure == b.secure
        && a.same_site == b.same_site
        && a.priority == b.priority
        && a.source_scheme == b.source_scheme
        && a.source_port == b.source_port
        && match (a.expires, b.expires) {
            (None, None) => true,
            (Some(a), Some(b)) => (a - b).abs() < 0.001,
            _ => false,
        }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn interception() -> RestoreInterception {
        RestoreInterception {
            session_id: "owned".into(),
            frame_id: "main".into(),
            expected_url: Some("https://example.test/.browserd-checkpoint/fixed".into()),
            fulfilled: false,
            seen: BTreeSet::new(),
        }
    }
    fn request(id: &str) -> Value {
        json!({"requestId":id,"frameId":"main","resourceType":"Document","request":{"url":"https://example.test/.browserd-checkpoint/fixed","method":"GET"}})
    }

    #[test]
    fn checkpoint_interception_fulfills_only_one_exact_main_document() {
        let mut state = interception();
        assert_eq!(
            state.response(Some("owned"), &request("one")).unwrap().0,
            "Fetch.fulfillRequest"
        );
        assert_eq!(
            state.response(Some("owned"), &request("two")).unwrap().0,
            "Fetch.failRequest"
        );
        assert!(state.response(Some("owned"), &request("one")).is_err());
    }

    #[test]
    fn checkpoint_interception_blocks_favicons_subframes_and_unexpected_urls() {
        for (field, value) in [
            ("resourceType", json!("Image")),
            ("frameId", json!("child")),
            (
                "request",
                json!({"url":"https://example.test/favicon.ico","method":"GET"}),
            ),
            (
                "request",
                json!({"url":"https://example.test/.browserd-checkpoint/fixed","method":"POST"}),
            ),
        ] {
            let mut event = request("one");
            event[field] = value;
            let mut state = interception();
            assert_eq!(
                state.response(Some("owned"), &event).unwrap().0,
                "Fetch.failRequest"
            );
            assert!(!state.fulfilled);
        }
        assert!(
            interception()
                .response(Some("foreign"), &request("one"))
                .is_err()
        );
    }

    #[test]
    fn checkpoint_interception_has_a_lifetime_request_bound() {
        let mut state = interception();
        for i in 0..MAX_PAUSED_REQUESTS {
            assert!(
                state
                    .response(Some("owned"), &request(&i.to_string()))
                    .is_ok()
            );
        }
        assert!(state.response(Some("owned"), &request("overflow")).is_err());
    }

    #[test]
    fn checkpoint_origins_reject_aliases_duplicates_and_non_web_schemes() {
        for origins in [
            vec!["https://example.test/".into()],
            vec!["https://example.test".into(); 2],
            vec!["file:///tmp/owned".into()],
            vec!["https://example.test:443".into()],
        ] {
            assert!(validate_origins(&origins).is_err());
        }
        assert!(validate_origins(&["http://example.test:1234".into()]).is_ok());
    }

    #[test]
    fn checkpoint_cookies_reject_partitioned_state_without_silently_dropping_it() {
        assert!(
            parse_cookies(
                json!({"cookies":[{"partitionKey":{"topLevelSite":"https://example.test"}}]})
            )
            .is_err()
        );
        assert!(parse_cookies(json!({"cookies":[{"partitionKeyOpaque":true}]})).is_err());
        assert!(parse_cookies(json!({"cookies":vec![json!({});MAX_COOKIES+1]})).is_err());
    }

    #[test]
    fn checkpoint_entry_bounds_and_unique_keys_are_enforced() {
        assert!(parse_entries(json!({"entries":[["x","a"],["x","b"]]})).is_err());
        assert!(parse_entries(json!({"entries":vec![json!(["x","a"]);MAX_ENTRIES+1]})).is_err());
        let entries =
            parse_entries(json!({"entries":[["한글","저장된 값"],["empty",""]]})).unwrap();
        assert!(entries[0].value == "저장된 값" && entries[1].value.is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod live_tests {
    use super::super::live_chromium::LiveChromium;
    use super::*;
    use crate::{ActionExecutionResult, CheckpointError, ChromiumDriver};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0_u8; 4096];
                if !matches!(
                    tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer)).await,
                    Ok(Ok(1..))
                ) {
                    continue;
                }
                observed.fetch_add(1, Ordering::SeqCst);
                let body = "<!doctype html><meta charset=utf-8><title>checkpoint fixture</title>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: checkpoint_session=fixture-session; Path=/; HttpOnly; SameSite=Lax\r\nSet-Cookie: checkpoint_persistent=fixture-persistent; Path=/; Max-Age=3600; SameSite=Strict\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        (origin, count, task)
    }

    async fn capture(
        browser: &LiveChromium,
        origins: Vec<String>,
    ) -> Result<CheckpointSnapshot, CheckpointError> {
        let (driver, tenant, session, fence) = (
            browser.driver.clone(),
            browser.tenant.clone(),
            browser.session.clone(),
            browser.fence.clone(),
        );
        tokio::task::spawn_blocking(move || {
            driver.capture_checkpoint_until(
                &tenant,
                &session,
                &fence,
                &origins,
                Instant::now() + Duration::from_secs(10),
            )
        })
        .await
        .unwrap()
    }

    async fn restore(
        browser: &LiveChromium,
        tenant: TenantId,
        fence: OwnershipFence,
        snapshot: CheckpointSnapshot,
    ) -> Result<(), CheckpointError> {
        let (driver, session, page) = (
            browser.driver.clone(),
            browser.session.clone(),
            browser.page.clone(),
        );
        tokio::task::spawn_blocking(move || {
            driver.restore_checkpoint_until(
                &tenant,
                &session,
                &page,
                &fence,
                snapshot,
                Instant::now() + Duration::from_secs(20),
            )
        })
        .await
        .unwrap()
    }

    async fn other_page_action(browser: &LiveChromium, page: PageId, command: Value) {
        let (driver, session) = (browser.driver.clone(), browser.session.clone());
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
        assert!(
            matches!(result, ActionExecutionResult::Succeeded(_)),
            "secondary page fixture action"
        );
    }

    fn empty_snapshot(
        identity: &browserd_chromium::ChromiumArtifactIdentity,
    ) -> CheckpointSnapshot {
        CheckpointSnapshot {
            artifact_identity: identity.clone(),
            cookies: Vec::new(),
            origins: Vec::new(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires explicitly configured sandbox-enabled Chromium; functional proof, not production qualification"]
    async fn actual_owner_checkpoint_roundtrip_without_network_or_reapplication() {
        tokio::time::timeout(Duration::from_secs(120),async {
            let (origin_a,count_a,server_a) = server().await;
            let (origin_b,count_b,server_b) = server().await;
            let source = LiveChromium::start().await;
            source.value(json!({"type":"navigate","url":format!("{origin_a}/source"),"wait_until":"load"})).await;
            assert!(source.evaluate("localStorage.setItem('한글','체크포인트 값'); true").await == json!(true));
            let page_b = tokio::task::spawn_blocking({let driver=source.driver.clone();let session=source.session.clone();move || driver.create_page(&session)}).await.unwrap().unwrap();
            other_page_action(&source,page_b.clone(),json!({"type":"navigate","url":format!("{origin_b}/source"),"wait_until":"load"})).await;
            other_page_action(&source,page_b,json!({"type":"evaluate","expression":"localStorage.setItem('second','다른 origin'); true"})).await;
            let snapshot = capture(&source,vec![origin_a.clone(),origin_b.clone()]).await.expect("owned multi-origin capture");
            assert!(snapshot.origins.len()==2);
            assert!(snapshot.cookies.iter().any(|cookie| cookie.http_only && cookie.expires.is_none()));
            assert!(snapshot.cookies.iter().any(|cookie| cookie.expires.is_some()));
            assert!(capture(&source,vec!["https://unvisited.invalid".into()]).await.is_err());
            let identity = snapshot.artifact_identity.clone();
            let original_session = source.session.clone();
            drop(source);
            let restored = LiveChromium::start().await;
            assert!(restored.session != original_session);
            assert!(matches!(restore(&restored,TenantId::new(),restored.fence.clone(),empty_snapshot(&identity)).await,Err(CheckpointError::Rejected)));
            let foreign_fence = OwnershipFence::new(restored.fence.worker_id().clone(),restored.fence.worker_epoch(),restored.fence.placement_version()+1,restored.fence.session_incarnation());
            assert!(matches!(restore(&restored,restored.tenant.clone(),foreign_fence,empty_snapshot(&identity)).await,Err(CheckpointError::Rejected)));
            let mut changed = empty_snapshot(&identity); changed.artifact_identity.chromium_revision.push_str("-foreign");
            assert!(matches!(restore(&restored,restored.tenant.clone(),restored.fence.clone(),changed).await,Err(CheckpointError::Rejected)));
            let before = (count_a.load(Ordering::SeqCst),count_b.load(Ordering::SeqCst));
            restore(&restored,restored.tenant.clone(),restored.fence.clone(),snapshot).await.expect("offline restore");
            assert!((count_a.load(Ordering::SeqCst),count_b.load(Ordering::SeqCst))==before,"restore must send no upstream HTTP requests");
            assert!(restored.evaluate("location.href").await == json!("about:blank"));
            assert!(matches!(restore(&restored,restored.tenant.clone(),restored.fence.clone(),empty_snapshot(&identity)).await,Err(CheckpointError::Rejected)));
            let cookies_only = capture(&restored,Vec::new()).await.expect("cookies-only restored capture");
            assert!(cookies_only.cookies.iter().any(|cookie| cookie.http_only && cookie.expires.is_none()));
            restored.value(json!({"type":"navigate","url":format!("{origin_a}/after"),"wait_until":"load"})).await;
            assert!(restored.evaluate("localStorage.getItem('한글')==='체크포인트 값' && !document.cookie.includes('checkpoint_session')").await == json!(true));
            assert!(restored.evaluate("localStorage.setItem('한글','사용자가 변경');true").await == json!(true));
            restored.value(json!({"type":"reload"})).await;
            assert!(restored.evaluate("localStorage.getItem('한글')==='사용자가 변경'").await == json!(true));
            restored.value(json!({"type":"navigate","url":format!("{origin_b}/after"),"wait_until":"load"})).await;
            assert!(restored.evaluate("localStorage.getItem('second')==='다른 origin' && localStorage.getItem('한글')===null").await == json!(true));
            server_a.abort(); server_b.abort();
        }).await.expect("bounded actual checkpoint proof");
    }
}
