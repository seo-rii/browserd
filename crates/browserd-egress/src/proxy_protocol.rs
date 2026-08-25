use std::collections::BTreeSet;
use std::fmt;

use crate::CanonicalUrl;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyProtocolLimits {
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    pub max_request_target_bytes: usize,
}

impl Default for ProxyProtocolLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_header_count: 64,
            max_request_target_bytes: 8 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyRequestKind {
    ConnectTunnel,
    ForwardHttp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyRequest {
    kind: ProxyRequestKind,
    method: String,
    url: CanonicalUrl,
    content_length: Option<u64>,
    upstream_head: Vec<u8>,
    buffered_after_head: Vec<u8>,
}

impl ProxyRequest {
    pub fn parse(input: &[u8], limits: ProxyProtocolLimits) -> Result<Self, ProxyProtocolError> {
        if limits.max_header_bytes == 0
            || limits.max_header_count == 0
            || limits.max_request_target_bytes == 0
        {
            return Err(ProxyProtocolError::InvalidLimits);
        }
        let Some(head_end) = input.windows(4).position(|window| window == b"\r\n\r\n") else {
            return if input.len() > limits.max_header_bytes {
                Err(ProxyProtocolError::HeaderTooLarge)
            } else {
                Err(ProxyProtocolError::IncompleteHeader)
            };
        };
        let consumed_head = head_end
            .checked_add(4)
            .ok_or(ProxyProtocolError::HeaderTooLarge)?;
        if consumed_head > limits.max_header_bytes {
            return Err(ProxyProtocolError::HeaderTooLarge);
        }
        let head_bytes = &input[..head_end];
        if head_bytes.iter().any(|byte| {
            !byte.is_ascii()
                || *byte == 0
                || (*byte < 0x20 && !matches!(*byte, b'\r' | b'\n' | b'\t'))
                || *byte == 0x7f
        }) {
            return Err(ProxyProtocolError::InvalidHeader);
        }
        let head =
            std::str::from_utf8(head_bytes).map_err(|_| ProxyProtocolError::InvalidHeader)?;
        let mut lines = head.split("\r\n");
        let request_line = lines.next().ok_or(ProxyProtocolError::InvalidRequestLine)?;
        if request_line.contains(['\r', '\n', '\t']) {
            return Err(ProxyProtocolError::InvalidRequestLine);
        }
        let parts = request_line.split(' ').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
            return Err(ProxyProtocolError::InvalidRequestLine);
        }
        let method = parts[0];
        if !method.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        }) || !method
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
        {
            return Err(ProxyProtocolError::InvalidMethod);
        }
        let target = parts[1];
        if target.len() > limits.max_request_target_bytes {
            return Err(ProxyProtocolError::RequestTargetTooLarge);
        }
        if parts[2] != "HTTP/1.1" {
            return Err(ProxyProtocolError::UnsupportedHttpVersion);
        }

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty()
                || line.starts_with([' ', '\t'])
                || line.contains(['\r', '\n'])
                || headers.len() >= limits.max_header_count
            {
                return if headers.len() >= limits.max_header_count {
                    Err(ProxyProtocolError::TooManyHeaders)
                } else {
                    Err(ProxyProtocolError::InvalidHeader)
                };
            }
            let (name, raw_value) = line
                .split_once(':')
                .ok_or(ProxyProtocolError::InvalidHeader)?;
            if name.is_empty()
                || !name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            byte,
                            b'!' | b'#'
                                | b'$'
                                | b'%'
                                | b'&'
                                | b'\''
                                | b'*'
                                | b'+'
                                | b'-'
                                | b'.'
                                | b'^'
                                | b'_'
                                | b'`'
                                | b'|'
                                | b'~'
                        )
                })
            {
                return Err(ProxyProtocolError::InvalidHeader);
            }
            let value = raw_value.trim_matches([' ', '\t']);
            if value
                .bytes()
                .any(|byte| byte < 0x20 || byte == 0x7f || !byte.is_ascii())
            {
                return Err(ProxyProtocolError::InvalidHeader);
            }
            headers.push((name.to_owned(), value.to_owned()));
        }

        let mut connection_named = BTreeSet::new();
        let mut websocket_upgrade = false;
        for (name, value) in &headers {
            if name.eq_ignore_ascii_case("connection") {
                for token in value.split(',') {
                    let token = token.trim().to_ascii_lowercase();
                    websocket_upgrade |= token == "upgrade";
                    connection_named.insert(token);
                }
            }
        }
        if connection_named.iter().any(|name| {
            matches!(
                name.as_str(),
                "content-length" | "host" | "transfer-encoding"
            )
        }) {
            return Err(ProxyProtocolError::InvalidHeader);
        }
        websocket_upgrade &= headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("upgrade") && !value.is_empty());

        let host_values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        if host_values.len() != 1 {
            return Err(ProxyProtocolError::HostHeaderRequired);
        }
        if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        {
            return Err(ProxyProtocolError::AmbiguousBodyFraming);
        }
        let content_lengths = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        if content_lengths.len() > 1
            || content_lengths.first().is_some_and(|value| {
                value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(ProxyProtocolError::AmbiguousBodyFraming);
        }
        let content_length = content_lengths
            .first()
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| ProxyProtocolError::AmbiguousBodyFraming)
            })
            .transpose()?;

        let kind = if method == "CONNECT" {
            ProxyRequestKind::ConnectTunnel
        } else {
            ProxyRequestKind::ForwardHttp
        };
        let url = match kind {
            ProxyRequestKind::ConnectTunnel => {
                if target.contains(['/', '?', '#', '@', '\\']) {
                    return Err(ProxyProtocolError::InvalidConnectAuthority);
                }
                let has_explicit_port = if let Some(bracketed) = target.strip_prefix('[') {
                    bracketed
                        .find(']')
                        .is_some_and(|close| bracketed[close + 1..].starts_with(':'))
                } else {
                    target.rsplit_once(':').is_some_and(|(host, port)| {
                        !host.is_empty()
                            && !port.is_empty()
                            && !host.contains(':')
                            && port.bytes().all(|byte| byte.is_ascii_digit())
                    })
                };
                if !has_explicit_port {
                    return Err(ProxyProtocolError::InvalidConnectAuthority);
                }
                CanonicalUrl::parse(&format!("https://{target}/"))
                    .map_err(|_| ProxyProtocolError::InvalidConnectAuthority)?
            }
            ProxyRequestKind::ForwardHttp => {
                let parsed = CanonicalUrl::parse(target)
                    .map_err(|_| ProxyProtocolError::AbsoluteFormRequired)?;
                if !matches!(parsed.scheme(), "http" | "ws") {
                    return Err(ProxyProtocolError::AbsoluteFormRequired);
                }
                parsed
            }
        };
        let host_url = CanonicalUrl::parse(&format!("{}://{}/", url.scheme(), host_values[0]))
            .map_err(|_| ProxyProtocolError::HostMismatch)?;
        if host_url.host() != url.host() || host_url.port() != url.port() {
            return Err(ProxyProtocolError::HostMismatch);
        }
        let buffered_length = u64::try_from(input.len() - consumed_head)
            .map_err(|_| ProxyProtocolError::UnexpectedBufferedData)?;
        if kind == ProxyRequestKind::ForwardHttp
            && content_length.map_or(buffered_length != 0, |length| buffered_length > length)
        {
            return Err(ProxyProtocolError::UnexpectedBufferedData);
        }

        let upstream_head = if kind == ProxyRequestKind::ConnectTunnel {
            Vec::new()
        } else {
            let mut head = format!("{method} {} HTTP/1.1\r\n", url.path_and_query()).into_bytes();
            let host = if url.host().contains(':') {
                format!("[{}]", url.host())
            } else {
                url.host().to_owned()
            };
            let default_port = matches!(
                (url.scheme(), url.port()),
                ("http" | "ws", 80) | ("https" | "wss", 443)
            );
            let authority = if default_port {
                host
            } else {
                format!("{host}:{}", url.port())
            };
            head.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
            if websocket_upgrade {
                head.extend_from_slice(b"Connection: Upgrade\r\n");
            } else {
                head.extend_from_slice(b"Connection: close\r\n");
            }
            for (name, value) in headers {
                let lowered = name.to_ascii_lowercase();
                if lowered == "host"
                    || lowered == "connection"
                    || lowered == "proxy-connection"
                    || lowered == "proxy-authorization"
                    || lowered == "proxy-authenticate"
                    || lowered == "te"
                    || lowered == "trailer"
                    || (connection_named.contains(&lowered) && lowered != "upgrade")
                    || (lowered == "upgrade" && !websocket_upgrade)
                {
                    continue;
                }
                head.extend_from_slice(name.as_bytes());
                head.extend_from_slice(b": ");
                head.extend_from_slice(value.as_bytes());
                head.extend_from_slice(b"\r\n");
            }
            head.extend_from_slice(b"\r\n");
            head
        };

        Ok(Self {
            kind,
            method: method.to_owned(),
            url,
            content_length,
            upstream_head,
            buffered_after_head: input[consumed_head..].to_vec(),
        })
    }

    #[must_use]
    pub const fn kind(&self) -> ProxyRequestKind {
        self.kind
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub const fn url(&self) -> &CanonicalUrl {
        &self.url
    }

    #[must_use]
    pub const fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    #[must_use]
    pub fn upstream_head(&self) -> &[u8] {
        &self.upstream_head
    }

    #[must_use]
    pub fn buffered_after_head(&self) -> &[u8] {
        &self.buffered_after_head
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyProtocolError {
    InvalidLimits,
    IncompleteHeader,
    HeaderTooLarge,
    TooManyHeaders,
    RequestTargetTooLarge,
    InvalidRequestLine,
    InvalidMethod,
    UnsupportedHttpVersion,
    InvalidHeader,
    HostHeaderRequired,
    HostMismatch,
    AmbiguousBodyFraming,
    UnexpectedBufferedData,
    InvalidConnectAuthority,
    AbsoluteFormRequired,
}

impl fmt::Display for ProxyProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid proxy request: {self:?}")
    }
}

impl std::error::Error for ProxyProtocolError {}
