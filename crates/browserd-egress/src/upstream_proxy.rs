/// The egress topology assigned to a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkClass {
    SharedPublic,
    DedicatedPrivate,
}

/// A configured upstream route. Values remain identifiers here; secret
/// resolution belongs to the trusted network control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpstreamProxy {
    BrowserdManagedRegional { route_id: String },
    ApprovedCorporate { policy_id: String },
    TenantProvided { endpoint: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamProxyError {
    TenantProxyForbiddenInSharedTier,
    EmptyRouteIdentity,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UpstreamProxyPolicy;

impl UpstreamProxyPolicy {
    pub fn validate(
        network_class: NetworkClass,
        proxy: &UpstreamProxy,
    ) -> Result<(), UpstreamProxyError> {
        match proxy {
            UpstreamProxy::TenantProvided { endpoint } => {
                if endpoint.trim().is_empty() {
                    return Err(UpstreamProxyError::EmptyRouteIdentity);
                }
                if network_class == NetworkClass::SharedPublic {
                    return Err(UpstreamProxyError::TenantProxyForbiddenInSharedTier);
                }
            }
            UpstreamProxy::BrowserdManagedRegional { route_id } => {
                if route_id.trim().is_empty() {
                    return Err(UpstreamProxyError::EmptyRouteIdentity);
                }
            }
            UpstreamProxy::ApprovedCorporate { policy_id } => {
                if policy_id.trim().is_empty() {
                    return Err(UpstreamProxyError::EmptyRouteIdentity);
                }
            }
        }
        Ok(())
    }
}
