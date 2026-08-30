use browserd_core::ActionState;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BrowserResult, DispatchId, KnownFailureReason, OutcomeUnknownReason, TerminalDetail,
    TransportLoss,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionDeliveryEvidence {
    NotAttempted,
    DispatchArmed(DispatchId),
    ExposurePossible(DispatchId),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionTerminalSource {
    Worker,
    ProvenNonDelivery,
    TransportLoss,
    CancelBeforeDispatch,
    WorkerLoss,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionTerminalEvidence {
    detail: TerminalDetail,
    source: ActionTerminalSource,
}

impl ActionTerminalEvidence {
    #[must_use]
    pub const fn new(detail: TerminalDetail, source: ActionTerminalSource) -> Self {
        Self { detail, source }
    }

    #[must_use]
    pub const fn detail(self) -> TerminalDetail {
        self.detail
    }

    #[must_use]
    pub const fn source(self) -> ActionTerminalSource {
        self.source
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionEvidenceMutation {
    Recorded,
    AlreadyRecorded,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ActionEvidenceError {
    #[error("dispatch has not been armed")]
    DispatchNotArmed,
    #[error("dispatch attempt does not match the durable attempt")]
    DispatchAttemptConflict {
        current: DispatchId,
        attempted: DispatchId,
    },
    #[error("proven non-delivery contradicts possible request exposure")]
    DeliveryEvidenceConflict,
    #[error("action terminal evidence conflicts with the existing terminal")]
    TerminalConflict {
        current: ActionTerminalEvidence,
        attempted: ActionTerminalEvidence,
    },
    #[error("action already has terminal evidence")]
    Terminal(ActionTerminalEvidence),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionEvidence {
    delivery: ActionDeliveryEvidence,
    terminal: Option<ActionTerminalEvidence>,
}

impl ActionEvidence {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            delivery: ActionDeliveryEvidence::NotAttempted,
            terminal: None,
        }
    }

    #[must_use]
    pub const fn delivery(&self) -> &ActionDeliveryEvidence {
        &self.delivery
    }

    #[must_use]
    pub const fn terminal(&self) -> Option<&ActionTerminalEvidence> {
        self.terminal.as_ref()
    }

    #[must_use]
    pub fn state(&self) -> ActionState {
        if let Some(terminal) = self.terminal {
            return terminal.detail().state();
        }
        match &self.delivery {
            ActionDeliveryEvidence::NotAttempted => ActionState::Accepted,
            ActionDeliveryEvidence::DispatchArmed(_)
            | ActionDeliveryEvidence::ExposurePossible(_) => ActionState::MayHaveExecuted,
        }
    }

    pub fn arm_dispatch(
        &mut self,
        attempted: DispatchId,
    ) -> Result<ActionEvidenceMutation, ActionEvidenceError> {
        if let Some(terminal) = self.terminal {
            return Err(ActionEvidenceError::Terminal(terminal));
        }
        match &self.delivery {
            ActionDeliveryEvidence::NotAttempted => {
                self.delivery = ActionDeliveryEvidence::DispatchArmed(attempted);
                Ok(ActionEvidenceMutation::Recorded)
            }
            ActionDeliveryEvidence::DispatchArmed(current)
            | ActionDeliveryEvidence::ExposurePossible(current)
                if current == &attempted =>
            {
                Ok(ActionEvidenceMutation::AlreadyRecorded)
            }
            ActionDeliveryEvidence::DispatchArmed(current)
            | ActionDeliveryEvidence::ExposurePossible(current) => {
                Err(ActionEvidenceError::DispatchAttemptConflict {
                    current: current.clone(),
                    attempted,
                })
            }
        }
    }

    pub fn mark_exposure_possible(
        &mut self,
        attempted: &DispatchId,
    ) -> Result<ActionEvidenceMutation, ActionEvidenceError> {
        if let Some(terminal) = self.terminal {
            return Err(ActionEvidenceError::Terminal(terminal));
        }
        match &self.delivery {
            ActionDeliveryEvidence::NotAttempted => Err(ActionEvidenceError::DispatchNotArmed),
            ActionDeliveryEvidence::DispatchArmed(current) if current == attempted => {
                self.delivery = ActionDeliveryEvidence::ExposurePossible(current.clone());
                Ok(ActionEvidenceMutation::Recorded)
            }
            ActionDeliveryEvidence::ExposurePossible(current) if current == attempted => {
                Ok(ActionEvidenceMutation::AlreadyRecorded)
            }
            ActionDeliveryEvidence::DispatchArmed(current)
            | ActionDeliveryEvidence::ExposurePossible(current) => {
                Err(ActionEvidenceError::DispatchAttemptConflict {
                    current: current.clone(),
                    attempted: attempted.clone(),
                })
            }
        }
    }

    pub fn record_worker_result(
        &mut self,
        dispatch_id: &DispatchId,
        result: BrowserResult,
    ) -> Result<ActionEvidenceMutation, ActionEvidenceError> {
        self.require_dispatch(dispatch_id)?;
        let detail = match result {
            BrowserResult::Succeeded(digest) => TerminalDetail::Succeeded(digest),
            BrowserResult::FailedKnown(reason) => TerminalDetail::FailedKnown(reason),
            BrowserResult::CancellationConfirmed => TerminalDetail::CancelledConfirmed,
        };
        self.record_terminal(ActionTerminalEvidence::new(
            detail,
            ActionTerminalSource::Worker,
        ))
    }

    pub fn record_transport_loss(
        &mut self,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
    ) -> Result<ActionEvidenceMutation, ActionEvidenceError> {
        self.require_dispatch(dispatch_id)?;
        let terminal = match loss {
            TransportLoss::ConfirmedNotWritten => {
                if matches!(self.delivery, ActionDeliveryEvidence::ExposurePossible(_)) {
                    return Err(ActionEvidenceError::DeliveryEvidenceConflict);
                }
                ActionTerminalEvidence::new(
                    TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched),
                    ActionTerminalSource::ProvenNonDelivery,
                )
            }
            TransportLoss::Ambiguous(reason) => ActionTerminalEvidence::new(
                TerminalDetail::OutcomeUnknown(reason),
                ActionTerminalSource::TransportLoss,
            ),
        };
        self.record_terminal(terminal)
    }

    pub fn cancel_before_dispatch(
        &mut self,
    ) -> Result<ActionEvidenceMutation, ActionEvidenceError> {
        if !matches!(self.delivery, ActionDeliveryEvidence::NotAttempted) {
            return Err(ActionEvidenceError::DeliveryEvidenceConflict);
        }
        self.record_terminal(ActionTerminalEvidence::new(
            TerminalDetail::CancelledBeforeDispatch,
            ActionTerminalSource::CancelBeforeDispatch,
        ))
    }

    #[must_use]
    pub fn effective_terminal(&self, session_lost: bool) -> Option<ActionTerminalEvidence> {
        self.terminal.or_else(|| {
            session_lost.then(|| match &self.delivery {
                ActionDeliveryEvidence::NotAttempted => ActionTerminalEvidence::new(
                    TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched),
                    ActionTerminalSource::WorkerLoss,
                ),
                ActionDeliveryEvidence::DispatchArmed(_)
                | ActionDeliveryEvidence::ExposurePossible(_) => ActionTerminalEvidence::new(
                    TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
                    ActionTerminalSource::WorkerLoss,
                ),
            })
        })
    }

    pub fn materialize_worker_loss(
        &mut self,
    ) -> Result<ActionEvidenceMutation, ActionEvidenceError> {
        let Some(terminal) = self.effective_terminal(true) else {
            return Err(ActionEvidenceError::DispatchNotArmed);
        };
        self.record_terminal(terminal)
    }

    fn require_dispatch(&self, attempted: &DispatchId) -> Result<(), ActionEvidenceError> {
        match &self.delivery {
            ActionDeliveryEvidence::NotAttempted => Err(ActionEvidenceError::DispatchNotArmed),
            ActionDeliveryEvidence::DispatchArmed(current)
            | ActionDeliveryEvidence::ExposurePossible(current)
                if current == attempted =>
            {
                Ok(())
            }
            ActionDeliveryEvidence::DispatchArmed(current)
            | ActionDeliveryEvidence::ExposurePossible(current) => {
                Err(ActionEvidenceError::DispatchAttemptConflict {
                    current: current.clone(),
                    attempted: attempted.clone(),
                })
            }
        }
    }

    fn record_terminal(
        &mut self,
        attempted: ActionTerminalEvidence,
    ) -> Result<ActionEvidenceMutation, ActionEvidenceError> {
        if let Some(current) = self.terminal {
            return if current == attempted {
                Ok(ActionEvidenceMutation::AlreadyRecorded)
            } else {
                Err(ActionEvidenceError::TerminalConflict { current, attempted })
            };
        }
        self.terminal = Some(attempted);
        Ok(ActionEvidenceMutation::Recorded)
    }
}

impl Default for ActionEvidence {
    fn default() -> Self {
        Self::new()
    }
}
