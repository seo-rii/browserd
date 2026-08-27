//! Durable action ledger and browser side-effect uncertainty boundary.

mod file_journal;
mod ledger;
mod types;

pub use file_journal::{ActionJournalLimits, FileActionJournal};
pub use ledger::ActionLedger;
pub use types::{
    AcceptDecision, ActionKind, ActionLedgerError, ActionRequest, ActionSequence, ActionSnapshot,
    ActionSnapshotFacts, ActionSnapshotReconstructionError, ApprovalDecision, BrowserResult,
    CanonicalRequestHash, DispatchDecision, DispatchId, DispatchPermit, DurableActionJournal,
    IdempotencyKey, JournalEntry, JournalEntryKind, JournalEntryType, JournalError,
    KnownFailureReason, LedgerSession, OutcomeUnknownReason, RecordOutcome,
    ReplayableActionJournal, ResolutionAnnotation, ResolutionKind, ResolutionOutcome,
    ResolutionPolicy, ResultDigest, TerminalDetail, TransportLoss,
};
