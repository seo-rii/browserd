use std::time::Duration;

use browserd_cdp::{
    CdpClient, CdpCommandError, CdpDriver, CdpIncoming, CdpTransport, CdpTransportConfig,
};
use browserd_sandbox::ChromiumCdpPipes;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::net::unix::pipe::{Receiver, Sender};
use tokio::sync::mpsc;

use crate::ChromiumArtifactIdentity;

const MAX_VERSION_FIELD_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChromiumConnectionConfig {
    pub transport: CdpTransportConfig,
    pub version_probe_timeout: Duration,
    pub max_version_field_bytes: usize,
}

impl Default for ChromiumConnectionConfig {
    fn default() -> Self {
        Self {
            transport: CdpTransportConfig::default(),
            version_probe_timeout: Duration::from_secs(5),
            max_version_field_bytes: MAX_VERSION_FIELD_BYTES,
        }
    }
}

impl ChromiumConnectionConfig {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.transport.is_valid()
            && !self.version_probe_timeout.is_zero()
            && self.max_version_field_bytes > 0
    }
}

/// Runtime identity returned by the exact Chromium process over its private CDP pipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChromiumVersion {
    pub protocol_version: String,
    pub product: String,
    pub revision: String,
    pub user_agent: String,
    pub js_version: String,
}

/// A capability-bound CDP transport whose runtime version matches its immutable artifact.
#[derive(Debug)]
pub struct ChromiumConnection {
    driver: CdpDriver,
    client: CdpClient,
    events: mpsc::Receiver<CdpIncoming>,
    version: ChromiumVersion,
}

impl ChromiumConnection {
    pub async fn connect(
        pipes: ChromiumCdpPipes,
        expected: &ChromiumArtifactIdentity,
        config: ChromiumConnectionConfig,
    ) -> Result<Self, ChromiumConnectionError> {
        if !config.is_valid() {
            return Err(ChromiumConnectionError::InvalidTransportConfig);
        }
        for (field, value) in [
            ("product_version", expected.product_version.as_str()),
            ("chromium_revision", expected.chromium_revision.as_str()),
        ] {
            if value.is_empty()
                || value.len() > config.max_version_field_bytes
                || value.chars().any(char::is_control)
            {
                return Err(ChromiumConnectionError::InvalidExpectedIdentity { field });
            }
        }

        let (command_writer, event_reader) = pipes.into_owned_fds();
        let command_writer = Sender::from_owned_fd(command_writer).map_err(|error| {
            ChromiumConnectionError::PipeConversion {
                capability: "command_writer",
                message: error.to_string(),
            }
        })?;
        let event_reader = Receiver::from_owned_fd(event_reader).map_err(|error| {
            ChromiumConnectionError::PipeConversion {
                capability: "event_reader",
                message: error.to_string(),
            }
        })?;
        let (client, events, driver) =
            CdpTransport::spawn_split(event_reader, command_writer, config.transport);
        let response = match tokio::time::timeout(
            config.version_probe_timeout,
            client.command(
                "Browser.getVersion",
                json!({}),
                None,
                Some(config.version_probe_timeout),
            ),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(CdpCommandError::TimedOut)) | Err(_) => {
                return Err(ChromiumConnectionError::VersionProbeTimedOut);
            }
            Ok(Err(error)) => return Err(ChromiumConnectionError::Command(error)),
        };

        let field = |name: &'static str| -> Result<String, ChromiumConnectionError> {
            let value = response
                .get(name)
                .and_then(Value::as_str)
                .ok_or(ChromiumConnectionError::InvalidVersionField { field: name })?;
            if value.is_empty()
                || value.len() > config.max_version_field_bytes
                || value.chars().any(char::is_control)
            {
                return Err(ChromiumConnectionError::InvalidVersionField { field: name });
            }
            Ok(value.to_owned())
        };
        let protocol_version = field("protocolVersion")?;
        let product = field("product")?;
        let revision = field("revision")?;
        let user_agent = field("userAgent")?;
        let js_version = field("jsVersion")?;

        let Some((brand, actual_product_version)) = product.split_once('/') else {
            return Err(ChromiumConnectionError::InvalidVersionField { field: "product" });
        };
        if !matches!(brand, "Chrome" | "Chromium" | "HeadlessChrome")
            || actual_product_version.is_empty()
            || actual_product_version.contains('/')
        {
            return Err(ChromiumConnectionError::InvalidVersionField { field: "product" });
        }
        if actual_product_version != expected.product_version {
            return Err(ChromiumConnectionError::ProductVersionMismatch {
                expected: expected.product_version.clone(),
                actual: actual_product_version.to_owned(),
            });
        }
        if revision != expected.chromium_revision {
            return Err(ChromiumConnectionError::RevisionMismatch {
                expected: expected.chromium_revision.clone(),
                actual: revision,
            });
        }

        Ok(Self {
            driver,
            client,
            events,
            version: ChromiumVersion {
                protocol_version,
                product,
                revision,
                user_agent,
                js_version,
            },
        })
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.client.is_closed()
    }

    pub async fn next_event(&mut self) -> Option<CdpIncoming> {
        self.events.recv().await
    }

    pub async fn command(
        &self,
        method: impl Into<String>,
        params: Value,
        session_id: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Value, CdpCommandError> {
        self.client
            .command(method, params, session_id, timeout)
            .await
    }

    #[must_use]
    pub const fn version(&self) -> &ChromiumVersion {
        &self.version
    }

    pub async fn shutdown(self) {
        self.driver.shutdown().await;
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ChromiumConnectionError {
    #[error("the CDP transport configuration is invalid")]
    InvalidTransportConfig,
    #[error("the expected Chromium identity field is invalid: {field}")]
    InvalidExpectedIdentity { field: &'static str },
    #[error("failed to convert the Chromium {capability} capability: {message}")]
    PipeConversion {
        capability: &'static str,
        message: String,
    },
    #[error("Chromium readiness command failed: {0}")]
    Command(CdpCommandError),
    #[error("Chromium Browser.getVersion readiness probe timed out")]
    VersionProbeTimedOut,
    #[error("Chromium returned an invalid Browser.getVersion field: {field}")]
    InvalidVersionField { field: &'static str },
    #[error("Chromium product version mismatch: expected {expected}, received {actual}")]
    ProductVersionMismatch { expected: String, actual: String },
    #[error("Chromium revision mismatch: expected {expected}, received {actual}")]
    RevisionMismatch { expected: String, actual: String },
}
