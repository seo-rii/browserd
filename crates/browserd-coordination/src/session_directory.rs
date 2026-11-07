//! Durable single-host routing projections. These never grant worker ownership.

use std::collections::BTreeMap;

use browserd_core::{SessionId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    GatewayActionCoordinationError as Error, GatewayActionPlacement, GatewaySessionIsolation,
};

pub const MAX_SESSION_DIRECTORY_RECORDS: usize = 16_384;
pub const MAX_SESSION_DIRECTORY_BYTES: usize = 16_384;
pub const MAX_SESSION_DIRECTORY_PAGE: usize = 256;

#[derive(Clone, Debug)]
pub struct GatewaySessionDirectoryPage {
    records: Vec<GatewaySessionDirectoryRecord>,
    ceiling: Option<SessionId>,
    has_more: bool,
}
impl GatewaySessionDirectoryPage {
    pub(crate) fn new(
        tenant: &TenantId,
        records: Vec<GatewaySessionDirectoryRecord>,
        ceiling: Option<SessionId>,
        has_more: bool,
    ) -> Result<Self, Error> {
        if records.len() > MAX_SESSION_DIRECTORY_PAGE
            || records
                .windows(2)
                .any(|pair| pair[0].session_id() >= pair[1].session_id())
            || records.iter().any(|record| {
                record.validate().is_err()
                    || record.tenant_id() != tenant
                    || ceiling.as_ref().is_none_or(|end| record.session_id() > end)
            })
            || (has_more && records.is_empty())
        {
            return Err(Error::InvalidSessionDirectory);
        }
        Ok(Self {
            records,
            ceiling,
            has_more,
        })
    }
    pub fn records(&self) -> &[GatewaySessionDirectoryRecord] {
        &self.records
    }
    pub const fn ceiling(&self) -> Option<&SessionId> {
        self.ceiling.as_ref()
    }
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayDirectoryLifecycle {
    Creating,
    Ready,
    Closing,
    Closed,
    Failed,
}
impl GatewayDirectoryLifecycle {
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }
    fn advances(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (
                    Self::Creating,
                    Self::Ready | Self::Closing | Self::Closed | Self::Failed
                ) | (Self::Ready, Self::Closing | Self::Closed | Self::Failed)
                    | (Self::Closing, Self::Closed | Self::Failed)
            )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GatewaySessionDirectoryRecord {
    tenant_id: TenantId,
    session_id: SessionId,
    placement: GatewayActionPlacement,
    lifecycle: GatewayDirectoryLifecycle,
    requested_isolation: GatewaySessionIsolation,
    effective_isolation: GatewaySessionIsolation,
    metadata: BTreeMap<String, String>,
    revision: u64,
    updated_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryWire {
    tenant_id: TenantId,
    session_id: SessionId,
    placement: GatewayActionPlacement,
    lifecycle: GatewayDirectoryLifecycle,
    requested_isolation: GatewaySessionIsolation,
    effective_isolation: GatewaySessionIsolation,
    metadata: BTreeMap<String, String>,
    revision: u64,
    updated_at: DateTime<Utc>,
}
impl TryFrom<DirectoryWire> for GatewaySessionDirectoryRecord {
    type Error = Error;
    fn try_from(wire: DirectoryWire) -> Result<Self, Error> {
        let value = Self {
            tenant_id: wire.tenant_id,
            session_id: wire.session_id,
            placement: wire.placement,
            lifecycle: wire.lifecycle,
            requested_isolation: wire.requested_isolation,
            effective_isolation: wire.effective_isolation,
            metadata: wire.metadata,
            revision: wire.revision,
            updated_at: wire.updated_at,
        };
        value.validate()?;
        Ok(value)
    }
}
impl<'de> Deserialize<'de> for GatewaySessionDirectoryRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(DirectoryWire::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl GatewaySessionDirectoryRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        placement: GatewayActionPlacement,
        lifecycle: GatewayDirectoryLifecycle,
        requested_isolation: GatewaySessionIsolation,
        effective_isolation: GatewaySessionIsolation,
        metadata: BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        let value = Self {
            tenant_id,
            session_id,
            placement,
            lifecycle,
            requested_isolation,
            effective_isolation,
            metadata,
            revision: 1,
            updated_at: Utc::now(),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.revision == 0
            || self.placement.directory_revision() == 0
            || self.placement.directory_fence().worker_epoch() == 0
            || self.placement.directory_fence().placement_version() == 0
            || self.placement.directory_fence().session_incarnation() == 0
            || !self
                .requested_isolation
                .satisfied_by(self.effective_isolation)
            || self.metadata.len() > 34
            || self.metadata.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 64
                    || key.trim() != key
                    || key.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
                    || value.len()
                        > if key == "restored_from_checkpoint" {
                            1024
                        } else {
                            256
                        }
            })
            || self
                .metadata
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>()
                > 5376
            || self.updated_at.timestamp_millis() < 0
        {
            return Err(Error::InvalidSessionDirectory);
        }
        Ok(())
    }
    pub fn with_lifecycle(&self, lifecycle: GatewayDirectoryLifecycle) -> Result<Self, Error> {
        if !self.lifecycle.advances(lifecycle) {
            return Err(Error::PlacementMismatch);
        }
        if self.lifecycle == lifecycle {
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.lifecycle = lifecycle;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionOverflow)?;
        next.updated_at = Utc::now();
        Ok(next)
    }
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    pub const fn placement(&self) -> &GatewayActionPlacement {
        &self.placement
    }
    pub const fn lifecycle(&self) -> GatewayDirectoryLifecycle {
        self.lifecycle
    }
    pub const fn requested_isolation(&self) -> GatewaySessionIsolation {
        self.requested_isolation
    }
    pub const fn effective_isolation(&self) -> GatewaySessionIsolation {
        self.effective_isolation
    }
    pub const fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.session_id == other.session_id
            && self.placement == other.placement
            && self.requested_isolation == other.requested_isolation
            && self.effective_isolation == other.effective_isolation
            && self.metadata == other.metadata
    }
    pub(crate) fn checked_commit(
        &self,
        incoming: &Self,
        expected: Option<u64>,
    ) -> Result<Self, Error> {
        if !self.same_owner(incoming) {
            return Err(Error::PlacementMismatch);
        }
        if expected.is_none() || self == incoming {
            return Ok(self.clone());
        }
        if expected != Some(self.revision)
            || !self.lifecycle.advances(incoming.lifecycle)
            || incoming.revision
                != self
                    .revision
                    .checked_add(1)
                    .ok_or(Error::RevisionOverflow)?
        {
            return Err(Error::SessionDirectoryConflict);
        }
        Ok(incoming.clone())
    }
}
