//! Durable action ledger and browser side-effect uncertainty boundary.

mod evidence;
mod file_journal;
mod journal_pool;
mod ledger;
mod notifications;
mod terminal_custody;
mod types;

pub use evidence::{
    ActionDeliveryEvidence, ActionEvidence, ActionEvidenceError, ActionEvidenceMutation,
    ActionTerminalEvidence, ActionTerminalSource,
};
pub use file_journal::{ActionJournalLimits, FileActionJournal};
pub use journal_pool::{
    ActionJournalPool, ActionJournalPoolConfig, ActionJournalPoolLimits, ManagedActionJournal,
};
pub use ledger::ActionLedger;
pub use notifications::ActionNotificationPage;
pub use terminal_custody::{
    JournalSessionScope, TerminalCustodyReceipt, TerminalCustodyRequirement,
};
pub use types::{
    AcceptDecision, ActionKind, ActionLedgerError, ActionRequest, ActionResultBudget,
    ActionSequence, ActionSnapshot, ActionSnapshotFacts, ActionSnapshotReconstructionError,
    ApprovalDecision, BrowserResult, CanonicalRequestHash, DispatchDecision, DispatchId,
    DispatchPermit, DurableActionJournal, IdempotencyKey, JournalEntry, JournalEntryKind,
    JournalEntryType, JournalError, KnownFailureReason, LedgerSession,
    MAX_ACTION_RESULT_CONTENT_BYTES, MAX_SNAPSHOT_RESULT_CONTENT_BYTES, OutcomeUnknownReason,
    RecordOutcome, ReplayableActionJournal, ResolutionAnnotation, ResolutionKind,
    ResolutionOutcome, ResolutionPolicy, ResultDigest, TerminalDetail, TransportLoss,
};
