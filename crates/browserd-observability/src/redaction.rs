use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRedaction {
    Plain,
    Hash,
}

pub struct UrlRedactor {
    host_redaction: HostRedaction,
}

impl UrlRedactor {
    #[must_use]
    pub const fn new(host_redaction: HostRedaction) -> Self {
        Self { host_redaction }
    }

    pub fn redact(&self, raw_url: &str) -> Result<RedactedUrl, RedactionError> {
        let parsed = url::Url::parse(raw_url).map_err(|_| RedactionError::InvalidUrl)?;
        let host = parsed.host_str().ok_or(RedactionError::MissingHost)?;
        let (host, host_hash) = match self.host_redaction {
            HostRedaction::Plain => (Some(host.to_owned()), None),
            HostRedaction::Hash => {
                let mut hasher = Sha256::new();
                hasher.update(host.as_bytes());
                (None, Some(hex::encode(hasher.finalize())))
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(parsed.path().as_bytes());
        Ok(RedactedUrl {
            scheme: parsed.scheme().to_owned(),
            host,
            host_hash,
            port: parsed.port(),
            path_hash: Some(hex::encode(hasher.finalize())),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedUrl {
    scheme: String,
    host: Option<String>,
    host_hash: Option<String>,
    port: Option<u16>,
    path_hash: Option<String>,
}

impl RedactedUrl {
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    #[must_use]
    pub fn host_hash(&self) -> Option<&str> {
        self.host_hash.as_deref()
    }

    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    #[must_use]
    pub fn path_hash(&self) -> Option<&str> {
        self.path_hash.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldSensitivity {
    Public,
    Secret,
}

pub struct LogField {
    key: String,
    value: String,
    sensitivity: FieldSensitivity,
}

impl LogField {
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        value: impl Into<String>,
        sensitivity: FieldSensitivity,
    ) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            sensitivity,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedLogFields(BTreeMap<String, String>);

impl RedactedLogFields {
    #[must_use]
    pub fn value(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

#[must_use]
pub fn redact_log_fields<I>(fields: I) -> RedactedLogFields
where
    I: IntoIterator<Item = LogField>,
{
    let mut redacted = BTreeMap::new();
    for field in fields {
        let normalized = field.key.to_ascii_lowercase().replace('-', "_");
        let reserved_secret = matches!(
            normalized.as_str(),
            "authorization"
                | "cookie"
                | "set_cookie"
                | "password"
                | "token"
                | "secret"
                | "form_value"
                | "credential"
                | "resolved_secret"
                | "api_key"
        ) || normalized.ends_with("_token")
            || normalized.ends_with("_secret")
            || normalized.ends_with("_password");
        let value = if field.sensitivity == FieldSensitivity::Secret || reserved_secret {
            "[REDACTED]".to_owned()
        } else {
            field.value
        };
        redacted.insert(field.key, value);
    }
    RedactedLogFields(redacted)
}

pub struct MetricLabelPolicy;

impl MetricLabelPolicy {
    pub fn validate<I, S>(labels: I) -> Result<(), MetricLabelError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for label in labels {
            let label = label.as_ref();
            if !matches!(
                label,
                "profile"
                    | "reason"
                    | "type"
                    | "state"
                    | "isolation"
                    | "plan"
                    | "workload_class"
                    | "class"
                    | "status"
                    | "resolution"
                    | "mode"
                    | "result"
                    | "network_class"
            ) {
                return Err(MetricLabelError::HighCardinalityLabel(label.to_owned()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedactionError {
    InvalidUrl,
    MissingHost,
}

impl fmt::Display for RedactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "redaction error: {self:?}")
    }
}

impl std::error::Error for RedactionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricLabelError {
    HighCardinalityLabel(String),
}

impl fmt::Display for MetricLabelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "metric label error: {self:?}")
    }
}

impl std::error::Error for MetricLabelError {}
