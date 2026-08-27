//! Mandatory browser egress policy, connection planning, and quota accounting.

#![forbid(unsafe_code)]

mod attachment;
#[cfg(test)]
mod attachment_tests;
mod data_plane;
#[cfg(test)]
mod data_plane_tests;
mod ingress;
#[cfg(test)]
mod ingress_tests;
mod ip_policy;
mod manager;
#[cfg(test)]
mod manager_tests;
mod planner;
mod proxy_protocol;
mod quota;
mod route;
#[cfg(test)]
mod route_tests;
mod scheme;
mod upstream_proxy;
mod url;

pub use attachment::{
    ActiveAttachmentReceipt, AttachmentError, AttachmentExpiry, AttachmentId, AttachmentRegistry,
    AttachmentState, AttachmentStatus, BindingDigest, CancelledAttachmentReceipt, DaemonEpoch,
    InstallReceipt, InstallingAttachmentReceipt, PreparedAttachmentReceipt,
    ReleasedAttachmentReceipt,
};
#[cfg(test)]
pub(crate) use data_plane::VerifiedRouteSource;
pub use data_plane::{
    BoxedEgressIo, Connector, DataPlane, DataPlaneError, DataPlaneLimits, EgressIo, Resolver,
    TcpConnector, TokioResolver,
};
pub use ingress::{AcceptedRouteIngress, RouteIngressError, RouteIngressListener};
pub use ip_policy::{IpDenyReason, IpPolicy};
pub use manager::{
    AcceptedIngressHandler, AttachmentManager, AttachmentManagerError, IngressHandlerError,
};
pub use planner::{
    ConnectPlan, ConnectionPlanner, DnsResolution, EgressPolicy, EgressPolicyError,
    InspectedSocketAddr, PlanError,
};
pub use proxy_protocol::{ProxyProtocolError, ProxyProtocolLimits, ProxyRequest, ProxyRequestKind};
pub use quota::{ConnectionId, MonotonicMillis, QuotaError, QuotaLedger, QuotaLimits, QuotaUsage};
pub use route::{
    RouteBinding, RouteClaim, RouteEndpoint, RouteError, RouteIdentity, RouteRegistry,
    RouteRegistryLimits,
};
pub use scheme::{NavigationScope, SchemeDecision, SchemePolicy};
pub use upstream_proxy::{NetworkClass, UpstreamProxy, UpstreamProxyError, UpstreamProxyPolicy};
pub use url::{CanonicalUrl, CanonicalUrlError};
