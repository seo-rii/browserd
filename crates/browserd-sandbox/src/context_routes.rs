//! Exact, supervisor-authenticated context routing contracts. An address alone is not authority.
use std::time::Duration;

use browserd_core::{PlacementFence, TenantId};
use serde::{Deserialize, Serialize};

use crate::{
    DedicatedEgressProxyBinding, DedicatedEgressSpec, LaunchSpec, NetworkNamespaceIdentity,
    SandboxError,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRoutePolicy {
    #[serde(with = "placement_wire")]
    initial_placement: PlacementFence,
    tenant_dedicated: bool,
    max_live_routes: u16,
    max_lifetime_routes: u16,
}
impl ContextRoutePolicy {
    pub fn new(
        initial_placement: PlacementFence,
        tenant_dedicated: bool,
        max_live_routes: u16,
        max_lifetime_routes: u16,
    ) -> Result<Self, SandboxError> {
        let value = Self {
            initial_placement,
            tenant_dedicated,
            max_live_routes,
            max_lifetime_routes,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.initial_placement.worker_epoch == 0
            || self.initial_placement.placement_version == 0
            || self.initial_placement.session_incarnation == 0
            || self.max_live_routes == 0
            || self.max_live_routes > 8
            || self.max_lifetime_routes < self.max_live_routes
            || self.max_lifetime_routes > 500
        {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(())
    }
    pub const fn initial_placement(&self) -> PlacementFence {
        self.initial_placement
    }
    pub const fn tenant_dedicated(&self) -> bool {
        self.tenant_dedicated
    }
    pub const fn max_live_routes(&self) -> u16 {
        self.max_live_routes
    }
    pub const fn max_lifetime_routes(&self) -> u16 {
        self.max_lifetime_routes
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextEgressRequest {
    tenant_id: TenantId,
    #[serde(with = "placement_wire")]
    placement: PlacementFence,
    egress: DedicatedEgressSpec,
}

mod placement_wire {
    use browserd_core::PlacementFence;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        worker_epoch: u64,
        placement_version: u64,
        session_incarnation: u64,
    }

    pub fn serialize<S: Serializer>(
        value: &PlacementFence,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if value.worker_epoch == 0 || value.placement_version == 0 || value.session_incarnation == 0
        {
            return Err(serde::ser::Error::custom("placement fence must be nonzero"));
        }
        Wire {
            worker_epoch: value.worker_epoch,
            placement_version: value.placement_version,
            session_incarnation: value.session_incarnation,
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PlacementFence, D::Error> {
        let value = Wire::deserialize(deserializer)?;
        if value.worker_epoch == 0 || value.placement_version == 0 || value.session_incarnation == 0
        {
            return Err(serde::de::Error::custom("placement fence must be nonzero"));
        }
        Ok(PlacementFence::new(
            value.worker_epoch,
            value.placement_version,
            value.session_incarnation,
        ))
    }
}
impl ContextEgressRequest {
    pub fn new(
        tenant_id: TenantId,
        placement: PlacementFence,
        egress: DedicatedEgressSpec,
    ) -> Result<Self, SandboxError> {
        let value = Self {
            tenant_id,
            placement,
            egress,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), SandboxError> {
        self.egress.validate()?;
        if self.placement.worker_epoch
            != self
                .egress
                .egress_fence()
                .shard()
                .owner()
                .worker_epoch()
                .get()
            || self.placement.placement_version == 0
            || self.placement.session_incarnation
                != self.egress.egress_fence().session_incarnation().get()
        {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(())
    }
    pub fn validate_for(&self, spec: &LaunchSpec) -> Result<(), SandboxError> {
        self.validate()?;
        let policy = spec
            .context_route_policy()
            .ok_or(SandboxError::LaunchFenceMismatch)?;
        policy.validate()?;
        if self.egress.egress_fence().shard() != spec.dedicated_egress().egress_fence().shard()
            || self.egress.policy_binding() != spec.dedicated_egress().policy_binding()
            || (policy.tenant_dedicated && self.tenant_id != *spec.tenant_id())
        {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(())
    }
    pub fn initial(spec: &LaunchSpec) -> Result<Self, SandboxError> {
        Self::new(
            spec.tenant_id().clone(),
            spec.context_route_policy()
                .ok_or(SandboxError::LaunchFenceMismatch)?
                .initial_placement,
            spec.dedicated_egress().clone(),
        )
    }
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub const fn placement(&self) -> PlacementFence {
        self.placement
    }
    pub const fn egress(&self) -> &DedicatedEgressSpec {
        &self.egress
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextEgressBinding {
    request: ContextEgressRequest,
    sandboxd_epoch: u64,
    egress_daemon_epoch: u64,
    proxy_binding: DedicatedEgressProxyBinding,
    granted_ttl_ms: u64,
}
impl ContextEgressBinding {
    pub fn new(
        request: ContextEgressRequest,
        sandboxd_epoch: u64,
        egress_daemon_epoch: u64,
        proxy_binding: DedicatedEgressProxyBinding,
        granted_ttl: Duration,
    ) -> Result<Self, SandboxError> {
        let granted_ttl_ms =
            u64::try_from(granted_ttl.as_millis()).map_err(|_| SandboxError::InvalidEgressLease)?;
        let value = Self {
            request,
            sandboxd_epoch,
            egress_daemon_epoch,
            proxy_binding,
            granted_ttl_ms,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), SandboxError> {
        self.request.validate()?;
        if self.sandboxd_epoch == 0
            || self.egress_daemon_epoch == 0
            || self.granted_ttl_ms == 0
            || self.granted_ttl() > self.request.egress.initial_lease_ttl()
            || self.proxy_binding.tenant_id() != self.request.tenant_id()
            || self.proxy_binding.egress_fence() != self.request.egress.egress_fence()
            || self.proxy_binding.policy_binding() != self.request.egress.policy_binding()
        {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(())
    }
    pub fn validate_for(
        &self,
        spec: &LaunchSpec,
        request: &ContextEgressRequest,
        sandboxd_epoch: u64,
        namespace: NetworkNamespaceIdentity,
    ) -> Result<(), SandboxError> {
        self.validate()?;
        self.request.validate_for(spec)?;
        if &self.request != request
            || self.sandboxd_epoch != sandboxd_epoch
            || self.proxy_binding.namespace_identity() != namespace
        {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(())
    }
    pub const fn request(&self) -> &ContextEgressRequest {
        &self.request
    }
    pub const fn sandboxd_epoch(&self) -> u64 {
        self.sandboxd_epoch
    }
    pub const fn egress_daemon_epoch(&self) -> u64 {
        self.egress_daemon_epoch
    }
    pub const fn proxy_binding(&self) -> &DedicatedEgressProxyBinding {
        &self.proxy_binding
    }
    pub const fn granted_ttl(&self) -> Duration {
        Duration::from_millis(self.granted_ttl_ms)
    }
}

/// Minted only after exact listener closure and accepted-connection drain have completed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextEgressReleaseReceipt {
    request: ContextEgressRequest,
    sandboxd_epoch: u64,
    egress_daemon_epoch: u64,
    listener_closed: bool,
    drained: bool,
    released: bool,
}
impl ContextEgressReleaseReceipt {
    pub fn new(
        request: ContextEgressRequest,
        sandboxd_epoch: u64,
        egress_daemon_epoch: u64,
    ) -> Result<Self, SandboxError> {
        let receipt = Self {
            request,
            sandboxd_epoch,
            egress_daemon_epoch,
            listener_closed: true,
            drained: true,
            released: true,
        };
        receipt.validate()?;
        Ok(receipt)
    }
    pub fn validate(&self) -> Result<(), SandboxError> {
        self.request.validate()?;
        if self.sandboxd_epoch == 0
            || self.egress_daemon_epoch == 0
            || !self.listener_closed
            || !self.drained
            || !self.released
        {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(())
    }
    pub fn validate_for(
        &self,
        request: &ContextEgressRequest,
        sandboxd_epoch: u64,
    ) -> Result<(), SandboxError> {
        self.validate()?;
        if &self.request != request || self.sandboxd_epoch != sandboxd_epoch {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(())
    }
    pub const fn request(&self) -> &ContextEgressRequest {
        &self.request
    }
    pub const fn sandboxd_epoch(&self) -> u64 {
        self.sandboxd_epoch
    }
    pub const fn egress_daemon_epoch(&self) -> u64 {
        self.egress_daemon_epoch
    }
    pub const fn listener_closed(&self) -> bool {
        self.listener_closed
    }
    pub const fn drained(&self) -> bool {
        self.drained
    }
    pub const fn released(&self) -> bool {
        self.released
    }
}
