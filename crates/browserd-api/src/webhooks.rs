//! Tenant webhook management. Signing material is returned only after durable registration.

use std::fmt;
use std::sync::Arc;

use browserd_coordination::WebhookSigningKeyRef;
use browserd_core::TenantId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{ApiError, ErrorCode};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookPutBody {
    pub url: String,
    pub expected_revision: Option<u64>,
}

impl fmt::Debug for WebhookPutBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookPutBody")
            .field("url", &"[REDACTED]")
            .field("expected_revision", &self.expected_revision)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookDeleteBody {
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebhookResumeMode {
    Continue,
    AcceptGapToTail {
        expected_pruned_through: u64,
        expected_tail: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookResumeBody {
    pub expected_revision: u64,
    pub mode: WebhookResumeMode,
}

#[derive(Debug)]
pub enum WebhookRequest {
    Get,
    Put {
        body: WebhookPutBody,
        idempotency_key: Uuid,
    },
    Delete {
        body: WebhookDeleteBody,
        idempotency_key: Uuid,
    },
    Resume {
        body: WebhookResumeBody,
        idempotency_key: Uuid,
    },
}

impl WebhookRequest {
    pub(crate) fn scope(&self) -> &'static str {
        if matches!(self, Self::Get) {
            "webhooks:read"
        } else {
            "webhooks:write"
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        let (key, revision) = match self {
            Self::Get => return Ok(()),
            Self::Put {
                body,
                idempotency_key,
            } => {
                let parsed = url::Url::parse(&body.url)
                    .map_err(|_| ApiError::invalid_request("invalid webhook endpoint URL"))?;
                if body.url.len() > 2048
                    || parsed.scheme() != "https"
                    || parsed.host_str().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.fragment().is_some()
                    || parsed.as_str() != body.url
                    || body.url.chars().any(char::is_control)
                {
                    return Err(ApiError::invalid_request("invalid webhook endpoint URL"));
                }
                (idempotency_key, body.expected_revision)
            }
            Self::Delete {
                body,
                idempotency_key,
            } => (idempotency_key, Some(body.expected_revision)),
            Self::Resume {
                body,
                idempotency_key,
            } => (idempotency_key, Some(body.expected_revision)),
        };
        if key.is_nil() || revision == Some(0) {
            return Err(ApiError::invalid_request(
                "invalid webhook mutation identity",
            ));
        }
        Ok(())
    }
}

/// Registry-backed API adapter; no browser or worker readiness is consulted.
#[derive(Clone)]
pub struct WebhookApi {
    store: browserd_coordination::WebhookBlockingClient,
    keys: Arc<dyn WebhookSigningKeyProvider>,
}

impl WebhookApi {
    #[must_use]
    pub fn new(
        store: browserd_coordination::WebhookBlockingClient,
        keys: Arc<dyn WebhookSigningKeyProvider>,
    ) -> Self {
        Self { store, keys }
    }

    pub(crate) fn execute(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        request: WebhookRequest,
    ) -> Result<crate::ApiResponse, ApiError> {
        use browserd_coordination::{
            WebhookEndpointRef, WebhookEndpointSpec, WebhookMutationBinding, WebhookPutRequest,
        };
        let binding = |key: Uuid, method: &str, body: serde_json::Value| {
            let hash = browserd_operations::CanonicalRequestHash::from_json(
                &serde_json::json!({"method":method,"body":body}),
            );
            WebhookMutationBinding::new(
                principal.tenant_id().clone(),
                principal.principal_id().clone(),
                key.to_string(),
                *hash.as_bytes(),
            )
            .map_err(store_error)
        };
        let expected = |revision| {
            let endpoint = self
                .store
                .get_endpoint(principal.tenant_id())
                .map_err(store_error)?
                .ok_or_else(|| store_error(browserd_coordination::WebhookStoreError::NotFound))?;
            WebhookEndpointRef::new(
                principal.tenant_id().clone(),
                endpoint.endpoint_ref().endpoint_id(),
                revision,
            )
            .map_err(store_error)
        };
        let (endpoint, signing_secret) = match request {
            WebhookRequest::Get => (
                self.store
                    .get_endpoint(principal.tenant_id())
                    .map_err(store_error)?
                    .ok_or_else(|| {
                        store_error(browserd_coordination::WebhookStoreError::NotFound)
                    })?,
                None,
            ),
            WebhookRequest::Put {
                body,
                idempotency_key,
            } => {
                let mutation = binding(
                    idempotency_key,
                    "put",
                    serde_json::to_value(&body).map_err(|_| unavailable())?,
                )?;
                let key_ref =
                    WebhookSigningKeyRef::new(self.keys.active_master_version_id(), Uuid::new_v4())
                        .map_err(store_error)?;
                let spec = WebhookEndpointSpec::new(body.url, key_ref).map_err(store_error)?;
                let request = WebhookPutRequest::new(mutation, body.expected_revision, spec)
                    .map_err(store_error)?;
                // Derive only from the canonical committed reference, including a lost-reply retry.
                let endpoint = self.store.put_endpoint(request).map_err(store_error)?;
                let secret = self
                    .keys
                    .derive(principal.tenant_id(), endpoint.spec().signing_key_ref())
                    .map_err(|_| unavailable())?;
                (endpoint, Some(secret))
            }
            WebhookRequest::Delete {
                body,
                idempotency_key,
            } => {
                let mutation = binding(
                    idempotency_key,
                    "delete",
                    serde_json::to_value(&body).map_err(|_| unavailable())?,
                )?;
                (
                    self.store
                        .delete_endpoint(&expected(body.expected_revision)?, mutation)
                        .map_err(store_error)?,
                    None,
                )
            }
            WebhookRequest::Resume {
                body,
                idempotency_key,
            } => {
                let mutation = binding(
                    idempotency_key,
                    "resume",
                    serde_json::to_value(&body).map_err(|_| unavailable())?,
                )?;
                let mode = match body.mode {
                    WebhookResumeMode::Continue => {
                        browserd_coordination::WebhookResumeMode::Continue
                    }
                    WebhookResumeMode::AcceptGapToTail {
                        expected_pruned_through,
                        expected_tail,
                    } => browserd_coordination::WebhookResumeMode::AcceptGapToTail {
                        expected_pruned_through,
                        expected_tail,
                    },
                };
                (
                    self.store
                        .resume_endpoint(&expected(body.expected_revision)?, mutation, mode)
                        .map_err(store_error)?,
                    None,
                )
            }
        };
        Ok(crate::ApiResponse::WebhookEndpoint(
            crate::ApiEnvelope::new(WebhookEndpointResponse {
                endpoint,
                signing_secret,
            }),
        ))
    }
}

/// The secret has no serialization implementation and is never included in GET responses.
#[derive(Debug)]
pub struct WebhookEndpointResponse {
    pub endpoint: browserd_coordination::WebhookEndpointSnapshot,
    pub signing_secret: Option<WebhookSigningSecret>,
}

pub(crate) fn unavailable() -> ApiError {
    ApiError::new(ErrorCode::WorkerUnavailable, "webhook registry unavailable")
}

fn store_error(error: browserd_coordination::WebhookStoreError) -> ApiError {
    use browserd_coordination::WebhookStoreError as E;
    match error {
        E::InvalidEndpoint | E::InvalidMutation | E::InvalidConfiguration | E::InvalidPayload => {
            ApiError::invalid_request("invalid webhook request")
        }
        E::Conflict | E::IdempotencyConflict | E::Gap | E::LeaseMismatch => ApiError::new(
            ErrorCode::IdempotencyConflict,
            "webhook revision or idempotency conflict",
        ),
        E::NotFound => ApiError::new(ErrorCode::OperationNotFound, "webhook endpoint not found"),
        E::Capacity => ApiError::new(ErrorCode::TenantQuotaExceeded, "webhook capacity exhausted"),
        E::AuditCapacity => ApiError::new(
            ErrorCode::AuditUnavailable,
            "webhook audit capacity exhausted",
        ),
        E::Unavailable | E::Busy | E::QueryTimeout | E::MutationTimeout => unavailable(),
    }
}

/// Operator key derivation; references contain no signing material.
pub trait WebhookSigningKeyProvider: Send + Sync {
    fn active_master_version_id(&self) -> &str;
    fn derive(
        &self,
        tenant: &TenantId,
        key_ref: &WebhookSigningKeyRef,
    ) -> Result<WebhookSigningSecret, WebhookKeyError>;
}

pub struct WebhookSigningSecret(Zeroizing<[u8; 32]>);

impl WebhookSigningSecret {
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for WebhookSigningSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookSigningSecret([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookKeyError {
    InvalidReference,
    Unavailable,
}

impl fmt::Display for WebhookKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidReference => "invalid webhook signing key reference",
            Self::Unavailable => "webhook signing key unavailable",
        })
    }
}

impl std::error::Error for WebhookKeyError {}
