use std::fmt;
use std::net::Ipv6Addr;

use url::Host;

/// A URL parsing or canonicalization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalUrlError {
    MissingScheme,
    InvalidScheme,
    MissingAuthority,
    CredentialsForbidden,
    EncodedAuthorityForbidden,
    ZoneIdentifierForbidden,
    InvalidHost,
    InvalidPort,
    NumericHostOutOfRange,
    IdnaEncodingFailed,
}

impl fmt::Display for CanonicalUrlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "URL canonicalization failed: {self:?}")
    }
}

impl std::error::Error for CanonicalUrlError {}

/// A URL whose scheme and authority are canonicalized before policy checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalUrl {
    scheme: String,
    host: String,
    port: u16,
    path_and_query: String,
}

impl CanonicalUrl {
    /// Parses a URL without performing DNS resolution.
    pub fn parse(input: &str) -> Result<Self, CanonicalUrlError> {
        if input.chars().any(char::is_control) || input.contains(char::is_whitespace) {
            return Err(CanonicalUrlError::InvalidHost);
        }

        let Some(scheme_end) = input.find(':') else {
            return Err(CanonicalUrlError::MissingScheme);
        };
        let raw_scheme = &input[..scheme_end];
        let mut scheme_characters = raw_scheme.chars();
        let valid_scheme = scheme_characters
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
            && scheme_characters.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            });
        if !valid_scheme {
            return Err(CanonicalUrlError::InvalidScheme);
        }
        let scheme = raw_scheme.to_ascii_lowercase();
        let remainder = &input[scheme_end + 1..];

        if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
            return Ok(Self {
                scheme,
                host: String::new(),
                port: 0,
                path_and_query: remainder
                    .split_once('#')
                    .map_or(remainder, |(before, _)| before)
                    .to_owned(),
            });
        }

        let Some(after_slashes) = remainder.strip_prefix("//") else {
            return Err(CanonicalUrlError::MissingAuthority);
        };
        if after_slashes.contains('\\') {
            return Err(CanonicalUrlError::InvalidHost);
        }
        let authority_end = after_slashes
            .find(['/', '?', '#'])
            .unwrap_or(after_slashes.len());
        let authority = &after_slashes[..authority_end];
        if authority.is_empty() {
            return Err(CanonicalUrlError::MissingAuthority);
        }
        if authority.contains('@') {
            return Err(CanonicalUrlError::CredentialsForbidden);
        }
        if authority.contains('%') {
            if authority.starts_with('[') {
                return Err(CanonicalUrlError::ZoneIdentifierForbidden);
            }
            return Err(CanonicalUrlError::EncodedAuthorityForbidden);
        }

        let default_port = default_port(&scheme).ok_or(CanonicalUrlError::InvalidPort)?;
        let parse_explicit_port = |raw_port: &str| {
            if raw_port.is_empty() || !raw_port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(CanonicalUrlError::InvalidPort);
            }
            let port = raw_port
                .parse::<u16>()
                .map_err(|_| CanonicalUrlError::InvalidPort)?;
            if port == 0 {
                return Err(CanonicalUrlError::InvalidPort);
            }
            Ok(port)
        };
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let Some(close_index) = bracketed.find(']') else {
                return Err(CanonicalUrlError::InvalidHost);
            };
            let address_text = &bracketed[..close_index];
            if address_text.contains('%') {
                return Err(CanonicalUrlError::ZoneIdentifierForbidden);
            }
            let address = address_text
                .parse::<Ipv6Addr>()
                .map_err(|_| CanonicalUrlError::InvalidHost)?;
            let suffix = &bracketed[close_index + 1..];
            let port = if suffix.is_empty() {
                default_port
            } else if let Some(raw_port) = suffix.strip_prefix(':') {
                parse_explicit_port(raw_port)?
            } else {
                return Err(CanonicalUrlError::InvalidHost);
            };
            (address.to_string(), port)
        } else {
            if authority.contains(['[', ']']) {
                return Err(CanonicalUrlError::InvalidHost);
            }
            if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
                return Err(CanonicalUrlError::InvalidHost);
            }
            let (raw_host, port) = match authority.rsplit_once(':') {
                Some((host, raw_port)) => (host, parse_explicit_port(raw_port)?),
                None => (authority, default_port),
            };
            (canonicalize_host(raw_host)?, port)
        };
        let path = &after_slashes[authority_end..];
        let without_fragment = path.split_once('#').map_or(path, |(before, _)| before);
        let (path, query) = without_fragment
            .split_once('?')
            .map_or((without_fragment, None), |(path, query)| {
                (path, Some(query))
            });
        let path = if path.is_empty() { "/" } else { path };
        let mut segments = Vec::new();
        for segment in path.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                _ => segments.push(segment),
            }
        }
        let mut path_and_query = String::from("/");
        path_and_query.push_str(&segments.join("/"));
        if path.ends_with('/') && path_and_query.len() > 1 {
            path_and_query.push('/');
        }
        if let Some(query) = query {
            path_and_query.push('?');
            path_and_query.push_str(query);
        }

        Ok(Self {
            scheme,
            host,
            port,
            path_and_query,
        })
    }

    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    pub(crate) fn is_default_port(&self) -> bool {
        default_port(&self.scheme) == Some(self.port)
    }
}

pub(crate) fn canonicalize_host(host: &str) -> Result<String, CanonicalUrlError> {
    if host.is_empty() || host.chars().any(char::is_control) || host.contains(char::is_whitespace) {
        return Err(CanonicalUrlError::InvalidHost);
    }
    if host.contains(['%', '\\', '/', '@', '[', ']']) {
        return Err(CanonicalUrlError::InvalidHost);
    }

    if host.is_empty() || host.ends_with("..") {
        return Err(CanonicalUrlError::InvalidHost);
    }
    let parsed = Host::parse(host).map_err(|_| CanonicalUrlError::InvalidHost)?;
    let canonical = match parsed {
        Host::Domain(domain) => domain.strip_suffix('.').unwrap_or(&domain).to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    if canonical.is_empty() || canonical.len() > 253 {
        Err(CanonicalUrlError::InvalidHost)
    } else {
        Ok(canonical)
    }
}

pub(crate) fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}
