use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::ip_policy::{IpDenyReason, IpPolicy};
use crate::scheme::{NavigationScope, SchemeDecision, SchemePolicy};
use crate::url::{CanonicalUrl, CanonicalUrlError, canonicalize_host};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgressPolicyError {
    InvalidAllowlistAuthority,
    InvalidAllowlistHost(CanonicalUrlError),
}

impl fmt::Display for EgressPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid egress policy: {self:?}")
    }
}

impl std::error::Error for EgressPolicyError {}

#[derive(Clone, Debug)]
enum HostPolicy {
    AnyPublic,
    ExactAuthorities(BTreeSet<(String, u16)>),
}

/// Network policy used to plan an outbound connection.
#[derive(Clone, Debug)]
pub struct EgressPolicy {
    host_policy: HostPolicy,
    ip_policy: IpPolicy,
    scheme_policy: SchemePolicy,
}

impl EgressPolicy {
    #[must_use]
    pub const fn public_web_default() -> Self {
        Self {
            host_policy: HostPolicy::AnyPublic,
            ip_policy: IpPolicy::public_web_default(),
            scheme_policy: SchemePolicy::browserd_default(),
        }
    }

    pub fn allowlist_only<I, S>(authorities: I) -> Result<Self, EgressPolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut entries = BTreeSet::new();
        for authority in authorities {
            let authority = authority.as_ref();
            let (host, raw_port) = if let Some(bracketed) = authority.strip_prefix('[') {
                bracketed
                    .split_once("]:")
                    .ok_or(EgressPolicyError::InvalidAllowlistAuthority)?
            } else {
                let (host, raw_port) = authority
                    .rsplit_once(':')
                    .ok_or(EgressPolicyError::InvalidAllowlistAuthority)?;
                if host.contains(':') {
                    return Err(EgressPolicyError::InvalidAllowlistAuthority);
                }
                (host, raw_port)
            };
            if host.is_empty()
                || raw_port.is_empty()
                || !raw_port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(EgressPolicyError::InvalidAllowlistAuthority);
            }
            let port = raw_port
                .parse::<u16>()
                .map_err(|_| EgressPolicyError::InvalidAllowlistAuthority)?;
            if port == 0 {
                return Err(EgressPolicyError::InvalidAllowlistAuthority);
            }
            let host = canonicalize_resolution_host(host).ok_or(
                EgressPolicyError::InvalidAllowlistHost(CanonicalUrlError::InvalidHost),
            )?;
            entries.insert((host, port));
        }
        if entries.is_empty() {
            return Err(EgressPolicyError::InvalidAllowlistAuthority);
        }
        Ok(Self {
            host_policy: HostPolicy::ExactAuthorities(entries),
            ip_policy: IpPolicy::public_web_default(),
            scheme_policy: SchemePolicy::browserd_default(),
        })
    }
}

/// A DNS result tied to the declared hostname that was resolved.
#[derive(Clone, Debug)]
pub struct DnsResolution {
    canonical_host: Option<String>,
    addresses: Vec<IpAddr>,
}

impl DnsResolution {
    #[must_use]
    pub fn new<H, I>(host: H, addresses: I) -> Self
    where
        H: AsRef<str>,
        I: IntoIterator<Item = IpAddr>,
    {
        Self {
            canonical_host: canonicalize_resolution_host(host.as_ref()),
            addresses: addresses.into_iter().collect(),
        }
    }

    #[must_use]
    pub const fn empty_for_local_scheme() -> Self {
        Self {
            canonical_host: None,
            addresses: Vec::new(),
        }
    }
}

/// An address that can only be produced after host, DNS, and IP inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectedSocketAddr(SocketAddr);

impl InspectedSocketAddr {
    #[must_use]
    pub const fn as_socket_addr(self) -> SocketAddr {
        self.0
    }
}

/// A fully inspected outbound connection plan. Connectors should accept this
/// type instead of a hostname so they cannot accidentally resolve twice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectPlan {
    inspected_socket_addr: InspectedSocketAddr,
    declared_host: String,
    http_host_header: String,
    tls_server_name: Option<String>,
}

impl ConnectPlan {
    #[must_use]
    pub const fn inspected_socket_addr(&self) -> InspectedSocketAddr {
        self.inspected_socket_addr
    }

    #[must_use]
    pub fn declared_host(&self) -> &str {
        &self.declared_host
    }

    #[must_use]
    pub fn http_host_header(&self) -> &str {
        &self.http_host_header
    }

    #[must_use]
    pub fn tls_server_name(&self) -> Option<&str> {
        self.tls_server_name.as_deref()
    }
}

/// A fail-closed connection-planning failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    SchemeDenied {
        scheme: String,
    },
    HostNotAllowed {
        host: String,
        port: u16,
    },
    DnsHostMismatch {
        declared: String,
        resolved: Option<String>,
    },
    EmptyDnsAnswer,
    ForbiddenDnsCandidate {
        address: IpAddr,
        reason: IpDenyReason,
    },
    LiteralAddressMismatch {
        declared: Option<IpAddr>,
        resolved: IpAddr,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "egress connection denied: {self:?}")
    }
}

impl std::error::Error for PlanError {}

#[derive(Clone, Debug)]
pub struct ConnectionPlanner {
    policy: EgressPolicy,
}

impl ConnectionPlanner {
    #[must_use]
    pub const fn new(policy: EgressPolicy) -> Self {
        Self { policy }
    }

    pub fn plan(
        &self,
        url: &CanonicalUrl,
        resolution: DnsResolution,
    ) -> Result<ConnectPlan, PlanError> {
        self.authorize(url)?;
        if resolution.canonical_host.as_deref() != Some(url.host()) {
            return Err(PlanError::DnsHostMismatch {
                declared: url.host().to_owned(),
                resolved: resolution.canonical_host,
            });
        }
        if resolution.addresses.is_empty() {
            return Err(PlanError::EmptyDnsAnswer);
        }

        let checked_literal = url
            .host()
            .parse::<IpAddr>()
            .ok()
            .map(|address| {
                self.policy
                    .ip_policy
                    .check(address)
                    .map_err(|reason| PlanError::ForbiddenDnsCandidate { address, reason })
            })
            .transpose()?;

        let mut inspected = Vec::with_capacity(resolution.addresses.len());
        for candidate in resolution.addresses {
            let canonical = self.policy.ip_policy.check(candidate).map_err(|reason| {
                PlanError::ForbiddenDnsCandidate {
                    address: candidate,
                    reason,
                }
            })?;
            if checked_literal.is_some_and(|literal| literal != canonical) {
                return Err(PlanError::LiteralAddressMismatch {
                    declared: checked_literal,
                    resolved: canonical,
                });
            }
            inspected.push(canonical);
        }
        let Some(selected) = inspected.first().copied() else {
            return Err(PlanError::EmptyDnsAnswer);
        };
        let host = if url.host().contains(':') {
            format!("[{}]", url.host())
        } else {
            url.host().to_owned()
        };
        let host_header = if url.is_default_port() {
            host
        } else {
            format!("{host}:{}", url.port())
        };
        let tls_server_name =
            matches!(url.scheme(), "https" | "wss").then(|| url.host().to_owned());

        Ok(ConnectPlan {
            inspected_socket_addr: InspectedSocketAddr(SocketAddr::new(selected, url.port())),
            declared_host: url.host().to_owned(),
            http_host_header: host_header,
            tls_server_name,
        })
    }

    pub fn authorize(&self, url: &CanonicalUrl) -> Result<(), PlanError> {
        if self
            .policy
            .scheme_policy
            .classify(NavigationScope::PageRequest, url.scheme())
            != SchemeDecision::AllowEgress
        {
            return Err(PlanError::SchemeDenied {
                scheme: url.scheme().to_owned(),
            });
        }
        let host_is_allowed = match &self.policy.host_policy {
            HostPolicy::AnyPublic => true,
            HostPolicy::ExactAuthorities(entries) => {
                entries.contains(&(url.host().to_owned(), url.port()))
            }
        };
        if !host_is_allowed {
            return Err(PlanError::HostNotAllowed {
                host: url.host().to_owned(),
                port: url.port(),
            });
        }
        Ok(())
    }

    pub fn revalidate_redirect(
        &self,
        _previous: &ConnectPlan,
        redirect: &CanonicalUrl,
        resolution: DnsResolution,
    ) -> Result<ConnectPlan, PlanError> {
        // Deliberately start from the URL and fresh DNS result rather than
        // inheriting any authorization from the previous hop.
        self.plan(redirect, resolution)
    }
}

fn canonicalize_resolution_host(host: &str) -> Option<String> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = unbracketed.parse::<IpAddr>() {
        Some(address.to_string())
    } else {
        canonicalize_host(unbracketed).ok()
    }
}
