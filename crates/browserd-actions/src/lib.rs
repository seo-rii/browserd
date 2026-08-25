//! Durable action ledger and browser side-effect uncertainty boundary.

mod ledger;
mod types;

pub use ledger::ActionLedger;
pub use types::{
    AcceptDecision, ActionKind, ActionLedgerError, ActionRequest, ActionSequence, ActionSnapshot,
    BrowserResult, CanonicalRequestHash, DispatchDecision, DispatchId, DispatchPermit,
    DurableActionJournal, IdempotencyKey, JournalEntry, JournalEntryKind, JournalEntryType,
    JournalError, KnownFailureReason, LedgerSession, OutcomeUnknownReason, RecordOutcome,
    ResolutionAnnotation, ResolutionKind, ResolutionOutcome, ResolutionPolicy, ResultDigest,
    TerminalDetail, TransportLoss,
};
