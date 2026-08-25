#![allow(dead_code)]
#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use browserd_actions::{
    AcceptDecision, ActionKind, ActionLedger, ActionRequest, ActionSnapshot, CanonicalRequestHash,
    DurableActionJournal, IdempotencyKey, JournalEntry, JournalEntryType, JournalError,
    LedgerSession,
};
use browserd_core::{PlacementFence, SessionId, TenantId};

#[derive(Default)]
pub struct RecordingJournal {
    entries: Mutex<Vec<JournalEntry>>,
    fail_next: Mutex<Option<JournalEntryType>>,
}

impl RecordingJournal {
    pub fn entries(&self) -> Vec<JournalEntry> {
        self.entries
            .lock()
            .expect("journal entries lock should not be poisoned")
            .clone()
    }

    pub fn count(&self, entry_type: JournalEntryType) -> usize {
        self.entries()
            .iter()
            .filter(|entry| entry.kind().entry_type() == entry_type)
            .count()
    }

    pub fn fail_next(&self, entry_type: JournalEntryType) {
        *self
            .fail_next
            .lock()
            .expect("journal failpoint lock should not be poisoned") = Some(entry_type);
    }
}

impl DurableActionJournal for RecordingJournal {
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        let mut fail_next = self
            .fail_next
            .lock()
            .expect("journal failpoint lock should not be poisoned");
        if fail_next.as_ref() == Some(&entry.kind().entry_type()) {
            *fail_next = None;
            return Err(JournalError::new("injected durable journal failure"));
        }
        drop(fail_next);

        self.entries
            .lock()
            .expect("journal entries lock should not be poisoned")
            .push(entry.clone());
        Ok(())
    }
}

pub struct LedgerFixture {
    pub ledger: Arc<ActionLedger<RecordingJournal>>,
    pub journal: Arc<RecordingJournal>,
    pub fence: PlacementFence,
}

pub fn ledger_fixture() -> LedgerFixture {
    let fence = PlacementFence::new(7, 11, 1);
    let journal = Arc::new(RecordingJournal::default());
    let session = LedgerSession::new(TenantId::new(), SessionId::new(), fence);
    let ledger = Arc::new(ActionLedger::new(session, journal.clone()));
    LedgerFixture {
        ledger,
        journal,
        fence,
    }
}

pub fn request(key: impl Into<String>, hash_byte: u8) -> ActionRequest {
    ActionRequest::new(
        IdempotencyKey::new(key),
        CanonicalRequestHash::new([hash_byte; 32]),
        ActionKind::Mutating,
    )
}

pub fn ready_action(
    ledger: &ActionLedger<RecordingJournal>,
    fence: PlacementFence,
    request: ActionRequest,
) -> ActionSnapshot {
    let accepted = ledger
        .accept(fence, request)
        .expect("action acceptance should succeed");
    assert!(matches!(accepted, AcceptDecision::Created(_)));
    let action_id = accepted.snapshot().action_id().clone();
    ledger
        .enqueue(fence, &action_id)
        .expect("action enqueue should succeed");
    ledger
        .mark_ready(fence, &action_id)
        .expect("action should become dispatch-ready")
}
