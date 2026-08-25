//! Mandatory browser egress policy, connection planning, and quota accounting.

#![forbid(unsafe_code)]

mod ip_policy;
mod planner;
mod quota;
mod scheme;
mod upstream_proxy;
mod url;

pub use ip_policy::{IpDenyReason, IpPolicy};
pub use planner::{
    ConnectPlan, ConnectionPlanner, DnsResolution, EgressPolicy, EgressPolicyError,
    InspectedSocketAddr, PlanError,
};
pub use quota::{ConnectionId, MonotonicMillis, QuotaError, QuotaLedger, QuotaLimits, QuotaUsage};
pub use scheme::{NavigationScope, SchemeDecision, SchemePolicy};
pub use upstream_proxy::{NetworkClass, UpstreamProxy, UpstreamProxyError, UpstreamProxyPolicy};
pub use url::{CanonicalUrl, CanonicalUrlError};
