//! One bounded screencast slot per owned page; Chromium ACKs never wait for observers.
use super::{
    ChromiumOwnerActor, GuardedPageExecution, OwnerActorError, PageExecutionFence,
    resolve_key_stroke,
};
use crate::{
    MAX_VIEWER_JPEG_BYTES, MAX_VIEWER_METADATA_BYTES, MAX_VIEWER_SAFE_INTEGER, TargetManagerDrain,
    ViewerClientMessage, ViewerKeyPhase, ViewerMouseButton, ViewerMousePhase, WorkerViewerFrame,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use browserd_core::{PageId, SessionId};
use browserd_session::OwnershipFence;
use browserd_viewer::InputCleanup;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub(crate) enum ViewerOperation {
    Start,
    Stop,
    Frame,
    Input {
        transform_epoch: u64,
        message: ViewerClientMessage,
    },
    Cleanup(InputCleanup),
}
#[derive(Clone, PartialEq)]
struct Geometry {
    width: f64,
    height: f64,
    scale: f64,
    top: f64,
    scroll_x: f64,
    scroll_y: f64,
}
pub(super) struct Stream {
    target: String,
    cdp_session: String,
    fence: OwnershipFence,
    identity: (u64, u64, u64),
    epoch: u64,
    geometry: Option<Geometry>,
    pub(super) latest: Option<WorkerViewerFrame>,
}
pub(super) struct ViewerState {
    pub(super) streams: BTreeMap<PageId, Stream>,
    next_frame: u64,
    next_transform: u64,
    acknowledgements: Arc<Semaphore>,
}
impl Default for ViewerState {
    fn default() -> Self {
        Self {
            streams: BTreeMap::new(),
            next_frame: 1,
            next_transform: 1,
            acknowledgements: Arc::new(Semaphore::new(16)),
        }
    }
}
fn increment(counter: &mut u64) -> Result<u64, OwnerActorError> {
    if *counter > MAX_VIEWER_SAFE_INTEGER {
        return Err(OwnerActorError::StateOverflow);
    }
    let value = *counter;
    *counter += 1;
    Ok(value)
}
fn finite(value: &Value, key: &str) -> Result<f64, OwnerActorError> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .filter(|number| number.is_finite())
        .ok_or(OwnerActorError::Rejected)
}
impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    pub(super) fn viewer_rebind(
        &mut self,
        session: &SessionId,
        page: &PageId,
        fence: &OwnershipFence,
    ) -> Result<u64, OwnerActorError> {
        let (_, _, route) = self.owned_page_route(session, page)?;
        if route.ownership_fence() != fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let stream = self
            .viewer
            .streams
            .get_mut(page)
            .ok_or(OwnerActorError::Rejected)?;
        if &stream.fence != fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let epoch = increment(&mut self.viewer.next_transform)?;
        stream.epoch = epoch;
        stream.latest = None;
        Ok(epoch)
    }
    pub(super) fn viewer_frame_event(
        &mut self,
        session: Option<&str>,
        params: &Value,
    ) -> Result<(), OwnerActorError> {
        let Some(session) = session else {
            return Err(OwnerActorError::UnknownOwnership);
        };
        // ACK is bounded and independent of both the actor's active command and all observers.
        let acknowledgement = params
            .get("sessionId")
            .and_then(Value::as_u64)
            .ok_or(OwnerActorError::Rejected)?;
        if !self
            .routes
            .values()
            .any(|entry| entry.route.session_id() == session)
        {
            return Ok(());
        }
        let permit = self
            .viewer
            .acknowledgements
            .clone()
            .try_acquire_owned()
            .map_err(|_| OwnerActorError::StateOverflow)?;
        let client = self.client.clone();
        let mailbox = self.mailbox.clone();
        let timeout = self.command_timeout;
        let ack_session = session.to_owned();
        tokio::spawn(async move {
            let _permit = permit;
            if client
                .command(
                    "Page.screencastFrameAck",
                    json!({"sessionId":acknowledgement}),
                    Some(ack_session),
                    Some(timeout),
                )
                .await
                .is_err()
                && let Some(mailbox) = mailbox.upgrade()
            {
                mailbox.fail_closed();
            }
        });
        let Some((page, stream)) = self
            .viewer
            .streams
            .iter()
            .find(|(_, stream)| stream.cdp_session == session)
        else {
            return Ok(());
        };
        let page = page.clone();
        let Some(route) = self.routes.get(&stream.target) else {
            return Ok(());
        };
        if route.route.ownership_fence() != &stream.fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let identity = (
            route.target_incarnation,
            route.frame_document_epoch,
            route.url_revision,
        );
        let previous_identity = stream.identity;
        let previous_geometry = stream.geometry.clone();
        let previous_epoch = stream.epoch;
        // A rejected image/metadata may describe a newer geometry. Never let old pixels
        // authorize input while that new frame is unvalidated.
        if let Some(stream) = self.viewer.streams.get_mut(&page) {
            stream.latest = None;
        }
        let Some(data) = params
            .get("data")
            .and_then(Value::as_str)
            .filter(|data| data.len() <= MAX_VIEWER_JPEG_BYTES.div_ceil(3) * 4)
        else {
            return Ok(());
        };
        let Ok(decoded) = BASE64.decode(data) else {
            return Ok(());
        };
        if decoded.len() > MAX_VIEWER_JPEG_BYTES
            || !decoded.starts_with(&[0xff, 0xd8])
            || !decoded.ends_with(&[0xff, 0xd9])
        {
            return Ok(());
        }
        let Some(metadata) = params.get("metadata") else {
            return Ok(());
        };
        let geometry = (|| {
            Ok::<_, OwnerActorError>(Geometry {
                width: finite(metadata, "deviceWidth")?,
                height: finite(metadata, "deviceHeight")?,
                scale: finite(metadata, "pageScaleFactor")?,
                top: finite(metadata, "offsetTop")?,
                scroll_x: finite(metadata, "scrollOffsetX")?,
                scroll_y: finite(metadata, "scrollOffsetY")?,
            })
        })();
        let Ok(geometry) = geometry else {
            return Ok(());
        };
        if geometry.width <= 0.0
            || geometry.width > 16384.0
            || geometry.height <= 0.0
            || geometry.height > 16384.0
            || geometry.scale <= 0.0
            || geometry.scale > 8.0
            || geometry.top != 0.0
        {
            return Ok(());
        }
        let changed =
            previous_identity != identity || previous_geometry.as_ref() != Some(&geometry);
        let epoch = if changed {
            increment(&mut self.viewer.next_transform)?
        } else {
            previous_epoch
        };
        let dpr = self
            .context_by_session
            .get(route.route.owner_session_id())
            .and_then(|id| self.contexts.get(id))
            .and_then(|context| context.options.as_ref())
            .map_or(1, |options| options.viewport.device_scale_factor);
        let css_width = (geometry.width / geometry.scale).ceil();
        let css_height = (geometry.height / geometry.scale).ceil();
        if css_width > 16384.0 || css_height > 16384.0 {
            return Ok(());
        }
        let public_metadata=serde_json::to_vec(&json!({"width":css_width as u32,"height":css_height as u32,"device_scale_factor":dpr,"page_id":page,"frame_transform_id":epoch})).map_err(|_|OwnerActorError::Rejected)?;
        if public_metadata.len() > MAX_VIEWER_METADATA_BYTES {
            return Ok(());
        }
        let frame_id = increment(&mut self.viewer.next_frame)?;
        let stream = self
            .viewer
            .streams
            .get_mut(&page)
            .ok_or(OwnerActorError::Rejected)?;
        stream.identity = identity;
        stream.epoch = epoch;
        stream.geometry = Some(geometry);
        stream.latest = Some(WorkerViewerFrame {
            frame_id,
            page_id: page,
            frame_transform_id: epoch,
            metadata: public_metadata,
            jpeg_base64: data.to_owned(),
        });
        Ok(())
    }

    pub(super) async fn viewer_command(
        &mut self,
        session: &SessionId,
        page: &PageId,
        fence: &OwnershipFence,
        operation: ViewerOperation,
    ) -> Result<Option<WorkerViewerFrame>, OwnerActorError> {
        // Remove retired routes on every request, bounding state even after page/context closure.
        self.viewer.streams.retain(|_, stream| {
            self.routes
                .get(&stream.target)
                .is_some_and(|route| route.route.ownership_fence() == &stream.fence)
        });
        // Drain already queued lifecycle/frame updates before the final effect fence check.
        while let Ok(incoming) = self.events.try_recv() {
            self.handle_incoming(incoming, None)?;
        }
        let (_, target, route) = self.owned_page_route(session, page)?;
        if route.ownership_fence() != fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let entry = self
            .routes
            .get(&target)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        let identity = (
            entry.target_incarnation,
            entry.frame_document_epoch,
            entry.url_revision,
        );
        let cdp_session = route.session_id().to_owned();
        match operation {
            ViewerOperation::Start => {
                if self.viewer.streams.contains_key(page) {
                    return Ok(None);
                }
                if self.viewer.streams.len() >= 32 {
                    return Err(OwnerActorError::Rejected);
                }
                let epoch = increment(&mut self.viewer.next_transform)?;
                self.viewer.streams.insert(
                    page.clone(),
                    Stream {
                        target,
                        cdp_session: cdp_session.clone(),
                        fence: fence.clone(),
                        identity,
                        epoch,
                        geometry: None,
                        latest: None,
                    },
                );
                if let Err(error)=self.command_event_first("Page.startScreencast",json!({"format":"jpeg","quality":70,"maxWidth":1280,"maxHeight":720,"everyNthFrame":1}),Some(cdp_session),None,None,None).await {
                    self.viewer.streams.remove(page); return Err(error);
                }
            }
            ViewerOperation::Stop => {
                if self.viewer.streams.remove(page).is_some() {
                    self.command_event_first(
                        "Page.stopScreencast",
                        json!({}),
                        Some(cdp_session),
                        None,
                        None,
                        None,
                    )
                    .await?;
                }
            }
            ViewerOperation::Frame => {
                return Ok(self
                    .viewer
                    .streams
                    .get(page)
                    .filter(|stream| stream.identity == identity)
                    .and_then(|stream| stream.latest.clone()));
            }
            ViewerOperation::Input {
                transform_epoch,
                message,
            } => {
                let stream = self
                    .viewer
                    .streams
                    .get(page)
                    .ok_or(OwnerActorError::Rejected)?;
                let frame = stream.latest.as_ref().ok_or(OwnerActorError::Rejected)?;
                if !message.is_valid()
                    || message
                        .input_meta()
                        .is_none_or(|(_, _, message_page, epoch)| {
                            message_page != page || epoch != transform_epoch
                        })
                    || frame.frame_transform_id != transform_epoch
                    || stream.identity != identity
                {
                    return Err(OwnerActorError::Rejected);
                }
                let geometry = stream.geometry.as_ref().ok_or(OwnerActorError::Rejected)?;
                let width = geometry.width / geometry.scale;
                let height = geometry.height / geometry.scale;
                let guarded = Some(GuardedPageExecution {
                    target_id: target,
                    fence: PageExecutionFence {
                        target_incarnation: identity.0,
                        frame_document_epoch: identity.1,
                        url_revision: identity.2,
                    },
                    viewer_transform: Some((page.clone(), transform_epoch)),
                });
                let (method, params) = match message {
                    ViewerClientMessage::Mouse {
                        phase,
                        button,
                        buttons,
                        x,
                        y,
                        ..
                    } => {
                        let x = x.as_f64().ok_or(OwnerActorError::Rejected)?;
                        let y = y.as_f64().ok_or(OwnerActorError::Rejected)?;
                        if x < 0.0 || y < 0.0 || x >= width || y >= height {
                            return Err(OwnerActorError::Rejected);
                        }
                        let kind = match phase {
                            ViewerMousePhase::Down => "mousePressed",
                            ViewerMousePhase::Up => "mouseReleased",
                            ViewerMousePhase::Move => "mouseMoved",
                        };
                        let button = match button {
                            ViewerMouseButton::Left => "left",
                            ViewerMouseButton::Middle => "middle",
                            ViewerMouseButton::Right => "right",
                            ViewerMouseButton::None => "none",
                        };
                        (
                            "Input.dispatchMouseEvent",
                            json!({"type":kind,"x":x,"y":y,"button":button,"buttons":buttons,"clickCount":if matches!(phase,ViewerMousePhase::Move){0}else{1}}),
                        )
                    }
                    ViewerClientMessage::Wheel {
                        x,
                        y,
                        delta_x,
                        delta_y,
                        ..
                    } => {
                        let x = x.and_then(|n| n.as_f64()).unwrap_or(width / 2.0);
                        let y = y.and_then(|n| n.as_f64()).unwrap_or(height / 2.0);
                        if x < 0.0 || y < 0.0 || x >= width || y >= height {
                            return Err(OwnerActorError::Rejected);
                        }
                        (
                            "Input.dispatchMouseEvent",
                            json!({"type":"mouseWheel","x":x,"y":y,"deltaX":delta_x,"deltaY":delta_y}),
                        )
                    }
                    ViewerClientMessage::Key {
                        phase,
                        key,
                        code,
                        alt,
                        ctrl,
                        meta,
                        shift,
                        ..
                    } => {
                        let virtual_key = resolve_key_stroke(&key).map_or(
                            match key.as_str() {
                                "Shift" => 16,
                                "Control" => 17,
                                "Alt" => 18,
                                "Meta" => 91,
                                _ => 0,
                            },
                            |stroke| stroke.virtual_key_code,
                        );
                        let modifiers = u8::from(alt)
                            + 2 * u8::from(ctrl)
                            + 4 * u8::from(meta)
                            + 8 * u8::from(shift);
                        // Printable text arrives through insert_text/composition. Enter needs its
                        // CDP character payload for textarea/default submit behavior.
                        let enter = phase == ViewerKeyPhase::Down
                            && key == "Enter"
                            && !alt
                            && !ctrl
                            && !meta;
                        let mut params = json!({"type":if phase==ViewerKeyPhase::Down {if enter {"keyDown"} else {"rawKeyDown"}}else{"keyUp"},"key":key,"code":code,"windowsVirtualKeyCode":virtual_key,"modifiers":modifiers});
                        if enter {
                            params["text"] = json!("\r");
                        }
                        ("Input.dispatchKeyEvent", params)
                    }
                    ViewerClientMessage::InsertText { text, .. }
                    | ViewerClientMessage::CompositionCommit { text, .. } => {
                        ("Input.insertText", json!({"text":text}))
                    }
                    ViewerClientMessage::CompositionUpdate { text, .. } => {
                        let length = text.encode_utf16().count();
                        (
                            "Input.imeSetComposition",
                            json!({"text":text,"selectionStart":length,"selectionEnd":length}),
                        )
                    }
                    ViewerClientMessage::CompositionStart { .. }
                    | ViewerClientMessage::CompositionCancel { .. } => (
                        "Input.imeSetComposition",
                        json!({"text":"","selectionStart":0,"selectionEnd":0}),
                    ),
                    _ => return Err(OwnerActorError::Rejected),
                };
                self.command_event_first(method, params, Some(cdp_session), None, guarded, None)
                    .await?;
            }
            ViewerOperation::Cleanup(cleanup) => {
                for button in cleanup.released_mouse_buttons() {
                    let name = match button {
                        0 => "left",
                        1 => "middle",
                        2 => "right",
                        _ => return Err(OwnerActorError::Rejected),
                    };
                    self.command_event_first("Input.dispatchMouseEvent",json!({"type":"mouseReleased","x":0,"y":0,"button":name,"buttons":0,"clickCount":1}),Some(cdp_session.clone()),None,None,None).await?;
                }
                for key in cleanup.released_keys() {
                    let code = resolve_key_stroke(key).map_or(0, |stroke| stroke.virtual_key_code);
                    self.command_event_first("Input.dispatchKeyEvent",json!({"type":"keyUp","key":key,"windowsVirtualKeyCode":code,"modifiers":0}),Some(cdp_session.clone()),None,None,None).await?;
                }
                if cleanup.drag_cancelled() {
                    self.command_event_first(
                        "Input.cancelDragging",
                        json!({}),
                        Some(cdp_session.clone()),
                        None,
                        None,
                        None,
                    )
                    .await?;
                }
                if cleanup.cancelled_composition().is_some() {
                    self.command_event_first(
                        "Input.imeSetComposition",
                        json!({"text":"","selectionStart":0,"selectionEnd":0}),
                        Some(cdp_session),
                        None,
                        None,
                        None,
                    )
                    .await?;
                }
            }
        }
        Ok(None)
    }
}
