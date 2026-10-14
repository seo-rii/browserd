//! Bounded viewer messages carried only over the authenticated worker RPC socket.

use browserd_core::PageId;
use browserd_viewer::{ConnectionId, InputKind, ViewerConnection};
use serde::{Deserialize, Serialize};
use serde_json::Number;

use super::{
    WorkerControlPlaneRpcHandler, WorkerRpcFailure, WorkerRpcFailureCode, WorkerRpcResponse,
    WorkerSessionFence, worker_failure,
};
use crate::{ChromiumDriver, SandboxClient};

pub const MAX_VIEWER_METADATA_BYTES: usize = 64 * 1024;
pub const MAX_VIEWER_JPEG_BYTES: usize = 1024 * 1024;
pub const MAX_VIEWER_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_CONTROL_EVENT_PAGE: usize = 128;

/// An immutable notification from the worker's durable control-transition journal.
/// `sequence` is a persistent journal counter, independent of the human lease epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerControlEvent {
    pub fence: WorkerSessionFence,
    pub sequence: u64,
    pub control_epoch: u64,
    pub human: bool,
    pub page_id: Option<PageId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerViewerOpenRequest {
    pub fence: WorkerSessionFence,
    pub connection: ViewerConnection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerViewerPollRequest {
    pub fence: WorkerSessionFence,
    pub connection_id: ConnectionId,
    pub after_frame_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerViewerMessageRequest {
    pub fence: WorkerSessionFence,
    pub connection_id: ConnectionId,
    pub message: ViewerClientMessage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerViewerCloseRequest {
    pub fence: WorkerSessionFence,
    pub connection_id: ConnectionId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerViewerController {
    Agent,
    ThisConnection,
    OtherConnection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerViewerControl {
    pub controller: WorkerViewerController,
    pub lease_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerViewerFrame {
    pub frame_id: u64,
    pub page_id: PageId,
    pub frame_transform_id: u64,
    pub metadata: Vec<u8>,
    pub jpeg_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerViewerSnapshot {
    pub fence: WorkerSessionFence,
    pub connection_id: ConnectionId,
    pub page_id: PageId,
    pub frame_transform_id: u64,
    pub frame: Option<WorkerViewerFrame>,
    pub control: WorkerViewerControl,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewerMousePhase {
    Down,
    Up,
    Move,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewerKeyPhase {
    Down,
    Up,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewerMouseButton {
    Left,
    Middle,
    Right,
    None,
}

impl ViewerMouseButton {
    #[must_use]
    pub const fn index(self) -> Option<u8> {
        match self {
            Self::Left => Some(0),
            Self::Middle => Some(1),
            Self::Right => Some(2),
            Self::None => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ViewerClientMessage {
    Ack {
        frame_id: String,
    },
    Ping {},
    SelectPage {
        page_id: PageId,
    },
    RequestControl {
        #[serde(default)]
        force: bool,
    },
    ReleaseControl {},
    ResizeViewOnly {
        width: u32,
        height: u32,
    },
    Mouse {
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        frame_transform_id: u64,
        phase: ViewerMousePhase,
        button: ViewerMouseButton,
        buttons: u8,
        x: Number,
        y: Number,
    },
    Wheel {
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        frame_transform_id: u64,
        delta_x: Number,
        delta_y: Number,
        #[serde(default)]
        x: Option<Number>,
        #[serde(default)]
        y: Option<Number>,
    },
    Key {
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        frame_transform_id: u64,
        phase: ViewerKeyPhase,
        key: String,
        code: String,
        #[serde(default)]
        alt: bool,
        #[serde(default)]
        ctrl: bool,
        #[serde(default)]
        meta: bool,
        #[serde(default)]
        shift: bool,
    },
    InsertText {
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        frame_transform_id: u64,
        text: String,
    },
    CompositionStart {
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        frame_transform_id: u64,
    },
    CompositionUpdate {
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        frame_transform_id: u64,
        text: String,
    },
    CompositionCommit {
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        frame_transform_id: u64,
        text: String,
    },
    CompositionCancel {
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        frame_transform_id: u64,
    },
}

impl ViewerClientMessage {
    #[must_use]
    pub fn input_meta(&self) -> Option<(u64, u64, &PageId, u64)> {
        match self {
            Self::Mouse {
                lease_epoch,
                input_sequence,
                page_id,
                frame_transform_id,
                ..
            }
            | Self::Wheel {
                lease_epoch,
                input_sequence,
                page_id,
                frame_transform_id,
                ..
            }
            | Self::Key {
                lease_epoch,
                input_sequence,
                page_id,
                frame_transform_id,
                ..
            }
            | Self::InsertText {
                lease_epoch,
                input_sequence,
                page_id,
                frame_transform_id,
                ..
            }
            | Self::CompositionStart {
                lease_epoch,
                input_sequence,
                page_id,
                frame_transform_id,
            }
            | Self::CompositionUpdate {
                lease_epoch,
                input_sequence,
                page_id,
                frame_transform_id,
                ..
            }
            | Self::CompositionCommit {
                lease_epoch,
                input_sequence,
                page_id,
                frame_transform_id,
                ..
            }
            | Self::CompositionCancel {
                lease_epoch,
                input_sequence,
                page_id,
                frame_transform_id,
            } => Some((*lease_epoch, *input_sequence, page_id, *frame_transform_id)),
            _ => None,
        }
    }

    #[must_use]
    pub fn input_kind(&self) -> Option<InputKind> {
        match self {
            Self::Mouse {
                phase: ViewerMousePhase::Down,
                button,
                ..
            } => button.index().map(InputKind::MouseDown),
            Self::Mouse {
                phase: ViewerMousePhase::Up,
                button,
                ..
            } => button.index().map(InputKind::MouseUp),
            Self::Mouse {
                phase: ViewerMousePhase::Move,
                ..
            } => Some(InputKind::MouseMove),
            Self::Wheel { .. } => Some(InputKind::Wheel),
            Self::Key {
                phase: ViewerKeyPhase::Down,
                key,
                ..
            } => Some(InputKind::KeyDown(key.clone())),
            Self::Key {
                phase: ViewerKeyPhase::Up,
                key,
                ..
            } => Some(InputKind::KeyUp(key.clone())),
            Self::InsertText { text, .. } => Some(InputKind::InsertText(text.clone())),
            Self::CompositionStart { .. } => Some(InputKind::CompositionStart),
            Self::CompositionUpdate { text, .. } => {
                Some(InputKind::CompositionUpdate(text.clone()))
            }
            Self::CompositionCommit { text, .. } => {
                Some(InputKind::CompositionCommit(text.clone()))
            }
            Self::CompositionCancel { .. } => Some(InputKind::CompositionCancel),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        if let Some((lease, sequence, _, transform)) = self.input_meta()
            && [lease, sequence, transform]
                .into_iter()
                .any(|value| value == 0 || value > MAX_VIEWER_SAFE_INTEGER)
        {
            return false;
        }
        let coordinate = |value: &Number| {
            value
                .as_f64()
                .is_some_and(|value| value.is_finite() && (0.0..=16_384.0).contains(&value))
        };
        let delta = |value: &Number| {
            value
                .as_f64()
                .is_some_and(|value| value.is_finite() && value.abs() <= 1_000_000.0)
        };
        match self {
            Self::Ack { frame_id } => {
                !frame_id.is_empty()
                    && frame_id.len() <= 20
                    && frame_id.bytes().all(|byte| byte.is_ascii_digit())
                    && frame_id.parse::<u64>().is_ok()
            }
            Self::ResizeViewOnly { width, height } => {
                (1..=16_384).contains(width) && (1..=16_384).contains(height)
            }
            Self::Mouse {
                phase,
                button,
                buttons,
                x,
                y,
                ..
            } => {
                *buttons <= 7
                    && coordinate(x)
                    && coordinate(y)
                    && (*phase == ViewerMousePhase::Move || button.index().is_some())
            }
            Self::Wheel {
                delta_x,
                delta_y,
                x,
                y,
                ..
            } => {
                delta(delta_x)
                    && delta(delta_y)
                    && x.as_ref().is_none_or(coordinate)
                    && y.as_ref().is_none_or(coordinate)
                    && x.is_some() == y.is_some()
            }
            Self::Key { key, code, .. } => {
                !key.is_empty()
                    && key.len() <= 64
                    && code.len() <= 64
                    && !key.chars().any(char::is_control)
                    && !code.chars().any(char::is_control)
            }
            Self::InsertText { text, .. }
            | Self::CompositionUpdate { text, .. }
            | Self::CompositionCommit { text, .. } => {
                text.len() <= 16 * 1024 && !text.contains('\0')
            }
            _ => true,
        }
    }
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlaneRpcHandler<D, S> {
    pub(super) fn handle_viewer_open(
        &self,
        request: WorkerViewerOpenRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcFailure> {
        self.ownership_fence(&request.fence)?;
        if request.connection.tenant_id() != &request.fence.tenant_id
            || request.connection.session_id() != &request.fence.session_id
            || request.connection.session_incarnation() != request.fence.session_incarnation
            || !request.connection.scopes().can_read()
        {
            return Err(WorkerRpcFailure::new(
                WorkerRpcFailureCode::FenceMismatch,
                "viewer grant does not match session ownership",
            ));
        }
        self.worker
            .viewer_open(
                &self.peer,
                &request,
                self.worker.clock.now().map_err(worker_failure)?,
            )
            .map(WorkerRpcResponse::Viewer)
            .map_err(worker_failure)
    }

    pub(super) fn handle_viewer_poll(
        &self,
        request: WorkerViewerPollRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcFailure> {
        self.ownership_fence(&request.fence)?;
        self.worker
            .viewer_poll(
                &self.peer,
                &request,
                self.worker.clock.now().map_err(worker_failure)?,
            )
            .map(WorkerRpcResponse::Viewer)
            .map_err(worker_failure)
    }

    pub(super) fn handle_viewer_message(
        &self,
        request: WorkerViewerMessageRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcFailure> {
        self.ownership_fence(&request.fence)?;
        if !request.message.is_valid() {
            return Err(WorkerRpcFailure::new(
                WorkerRpcFailureCode::InvalidRequest,
                "viewer message exceeds protocol limits",
            ));
        }
        self.worker
            .viewer_message(
                &self.peer,
                &request,
                self.worker.clock.now().map_err(worker_failure)?,
            )
            .map(WorkerRpcResponse::Viewer)
            .map_err(worker_failure)
    }

    pub(super) fn handle_viewer_close(
        &self,
        request: WorkerViewerCloseRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcFailure> {
        self.ownership_fence(&request.fence)?;
        self.worker
            .viewer_close(
                &self.peer,
                &request,
                self.worker.clock.now().map_err(worker_failure)?,
            )
            .map(|()| WorkerRpcResponse::Empty)
            .map_err(worker_failure)
    }
}
