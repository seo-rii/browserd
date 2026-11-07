//! Authenticated, bounded transfer of committed metadata without browser execution.
use browserd_core::{NotificationAck, NotificationCommit, NotificationSourceFamily, WorkerId};
use serde::{Deserialize, Serialize};

use crate::{ChromiumDriver, SandboxClient, WorkerControlPlane, WorkerError};

pub const MAX_NOTIFICATION_SCOPES_PER_PAGE: usize = 32;
pub const MAX_NOTIFICATION_PAGE_DESCRIPTORS: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerNotificationPage {
    pub commits: Vec<NotificationCommit>,
    pub cursor: Option<String>,
    pub examined: usize,
    pub is_complete: bool,
}

impl WorkerNotificationPage {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            commits: Vec::new(),
            cursor: None,
            examined: 0,
            is_complete: true,
        }
    }

    pub fn validate(
        &self,
        worker: &WorkerId,
        serving_epoch: u64,
        family: NotificationSourceFamily,
        limit: usize,
    ) -> Result<(), WorkerError> {
        if !(1..=MAX_NOTIFICATION_SCOPES_PER_PAGE).contains(&limit)
            || serving_epoch == 0
            || self.examined > limit
            || self.commits.len() > self.examined
            || self
                .commits
                .iter()
                .map(|c| c.descriptors().len())
                .sum::<usize>()
                > MAX_NOTIFICATION_PAGE_DESCRIPTORS
            || self
                .cursor
                .as_ref()
                .is_some_and(|c| c.is_empty() || c.len() > 1024 || c.chars().any(char::is_control))
            || (!self.is_complete && (self.examined == 0 || self.cursor.is_none()))
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let mut sources = std::collections::HashSet::new();
        for commit in &self.commits {
            commit
                .validate()
                .map_err(|_| WorkerError::DurabilityUnavailable)?;
            if commit.scope().original_worker_id() != worker
                || commit.scope().family() != family
                || !sources.insert(commit.scope())
                || commit
                    .descriptors()
                    .iter()
                    .any(|d| d.session_scope().fence().worker_epoch > serving_epoch)
            {
                return Err(WorkerError::InvalidConfiguration);
            }
        }
        Ok(())
    }
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    pub fn pending_notifications(
        &self,
        peer: &crate::AuthenticatedPeer,
        expected_worker: &WorkerId,
        serving_epoch: u64,
        family: NotificationSourceFamily,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<WorkerNotificationPage, WorkerError> {
        self.authorize(peer)?;
        if expected_worker != &self.config.worker_id
            || serving_epoch != self.config.worker_epoch
            || !(1..=MAX_NOTIFICATION_SCOPES_PER_PAGE).contains(&limit)
            || cursor
                .is_some_and(|c| c.is_empty() || c.len() > 1024 || c.chars().any(char::is_control))
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let page = match family {
            NotificationSourceFamily::ActionJournal => {
                let Some(pool) = &self.action_journal_pool else {
                    return Ok(WorkerNotificationPage::empty());
                };
                let parsed = cursor
                    .map(str::parse::<browserd_core::SessionId>)
                    .transpose()
                    .map_err(|_| WorkerError::InvalidConfiguration)?;
                let page = pool
                    .pending_notifications_all(
                        parsed.as_ref(),
                        limit,
                        std::time::Instant::now() + std::time::Duration::from_secs(5),
                    )
                    .map_err(|_| WorkerError::DurabilityUnavailable)?;
                WorkerNotificationPage {
                    commits: page.commits,
                    cursor: page.cursor.map(|id| id.to_string()),
                    examined: page.examined,
                    is_complete: page.is_complete,
                }
            }
            NotificationSourceFamily::ArtifactRegistry => self
                .sandbox
                .pending_artifact_notifications(cursor, limit, MAX_NOTIFICATION_PAGE_DESCRIPTORS)
                .map_err(|_| WorkerError::DurabilityUnavailable)?,
            NotificationSourceFamily::SessionLifecycle => match &self.session_event_journal {
                Some(journal) => journal.pending(cursor, limit)?,
                None => WorkerNotificationPage::empty(),
            },
            NotificationSourceFamily::ControlJournal => self
                .control_event_journal
                .pending_notifications(cursor, limit)?,
        };
        page.validate(expected_worker, serving_epoch, family, limit)?;
        Ok(page)
    }

    pub fn ack_notification(
        &self,
        peer: &crate::AuthenticatedPeer,
        expected_worker: &WorkerId,
        serving_epoch: u64,
        ack: &NotificationAck,
    ) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        ack.validate()
            .map_err(|_| WorkerError::InvalidConfiguration)?;
        if expected_worker != &self.config.worker_id
            || serving_epoch != self.config.worker_epoch
            || ack.scope().original_worker_id() != expected_worker
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        match ack.scope().family() {
            NotificationSourceFamily::ActionJournal => self
                .action_journal_pool
                .as_ref()
                .ok_or(WorkerError::DurabilityUnavailable)?
                .ack_notification(ack, self.clock.now()?.get())
                .map_err(|_| WorkerError::DurabilityUnavailable),
            NotificationSourceFamily::ArtifactRegistry => self
                .sandbox
                .ack_artifact_notification(ack)
                .map_err(|_| WorkerError::DurabilityUnavailable),
            NotificationSourceFamily::SessionLifecycle => self
                .session_event_journal
                .as_ref()
                .ok_or(WorkerError::DurabilityUnavailable)?
                .ack(ack),
            NotificationSourceFamily::ControlJournal => {
                self.control_event_journal.ack_notification(ack)
            }
        }
    }
}
