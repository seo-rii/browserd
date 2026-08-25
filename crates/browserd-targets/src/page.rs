use std::collections::BTreeMap;

use crate::{DocumentEpoch, FrameId, PageId, TargetIncarnation, UrlRevision};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameState {
    target_incarnation: TargetIncarnation,
    document_epoch: DocumentEpoch,
}

impl FrameState {
    #[must_use]
    pub const fn target_incarnation(self) -> TargetIncarnation {
        self.target_incarnation
    }

    #[must_use]
    pub const fn document_epoch(self) -> DocumentEpoch {
        self.document_epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageEpochError {
    FrameAlreadyAttached,
    UnknownFrame,
    DocumentEpochOverflow,
}

/// The single-writer source of truth for page, frame, and document revisions.
#[derive(Debug)]
pub struct PageEpochTracker {
    page_id: PageId,
    target_incarnation: TargetIncarnation,
    url_revision: UrlRevision,
    frames: BTreeMap<FrameId, FrameState>,
}

impl PageEpochTracker {
    #[must_use]
    pub fn new(page_id: PageId, target_incarnation: TargetIncarnation, top_frame: FrameId) -> Self {
        let mut frames = BTreeMap::new();
        frames.insert(
            top_frame,
            FrameState {
                target_incarnation,
                document_epoch: DocumentEpoch::new(1),
            },
        );
        Self {
            page_id,
            target_incarnation,
            url_revision: UrlRevision::new(1),
            frames,
        }
    }

    #[must_use]
    pub const fn page_id(&self) -> &PageId {
        &self.page_id
    }

    #[must_use]
    pub const fn target_incarnation(&self) -> TargetIncarnation {
        self.target_incarnation
    }

    #[must_use]
    pub fn url_revision(&self) -> UrlRevision {
        self.url_revision.clone()
    }

    pub fn record_same_document_navigation(&mut self) -> UrlRevision {
        for word in &mut self.url_revision.0 {
            if let Some(next) = word.checked_add(1) {
                *word = next;
                return self.url_revision.clone();
            }
            *word = 0;
        }
        self.url_revision.0.push(1);
        self.url_revision.clone()
    }

    pub fn attach_frame(
        &mut self,
        frame_id: FrameId,
        target_incarnation: TargetIncarnation,
    ) -> Result<DocumentEpoch, PageEpochError> {
        if self.frames.contains_key(&frame_id) {
            return Err(PageEpochError::FrameAlreadyAttached);
        }
        let epoch = DocumentEpoch::new(1);
        self.frames.insert(
            frame_id,
            FrameState {
                target_incarnation,
                document_epoch: epoch,
            },
        );
        Ok(epoch)
    }

    pub fn document_committed(
        &mut self,
        frame_id: &FrameId,
    ) -> Result<DocumentEpoch, PageEpochError> {
        let Some(frame) = self.frames.get_mut(frame_id) else {
            return Err(PageEpochError::UnknownFrame);
        };
        let next = frame
            .document_epoch
            .checked_next()
            .ok_or(PageEpochError::DocumentEpochOverflow)?;
        frame.document_epoch = next;
        Ok(next)
    }

    pub fn replace_oopif_target(
        &mut self,
        frame_id: &FrameId,
        target_incarnation: TargetIncarnation,
    ) -> Result<DocumentEpoch, PageEpochError> {
        let Some(frame) = self.frames.get_mut(frame_id) else {
            return Err(PageEpochError::UnknownFrame);
        };
        let next = frame
            .document_epoch
            .checked_next()
            .ok_or(PageEpochError::DocumentEpochOverflow)?;
        frame.document_epoch = next;
        frame.target_incarnation = target_incarnation;
        Ok(next)
    }

    #[must_use]
    pub fn frame_state(&self, frame_id: &FrameId) -> Option<FrameState> {
        self.frames.get(frame_id).copied()
    }
}
