//! Authenticated global operator control independent of browser and PostgreSQL readiness.
use browserd_auth::AuthenticatedPrincipal;
use browserd_coordination::{
    SafetyActorIdentity, SafetyAuditAck, SafetyAuthorityBlockingClient, SafetyAuthorityError,
    SafetyInitializeRequest, SafetyMutationRequest,
};
use browserd_core::{ErrorCode, SafetySwitchMutation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{ApiEnvelope, ApiError, ApiResponse};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyInitializeBody {
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyMutationBody {
    pub expected_version: u64,
    pub mutation: SafetySwitchMutation,
    pub reason: String,
}

#[derive(Debug)]
pub enum SafetyRequest {
    Get,
    Initialize {
        body: SafetyInitializeBody,
        idempotency_key: Uuid,
    },
    Mutate {
        body: SafetyMutationBody,
        idempotency_key: Uuid,
    },
    Audits,
    AckAudit(SafetyAuditAck),
}

impl SafetyRequest {
    pub(crate) fn scope(&self) -> &'static str {
        if matches!(self, Self::Get | Self::Audits) {
            "admin:safety:read"
        } else {
            "admin:safety:write"
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        let (key, reason) = match self {
            Self::Get | Self::Audits => return Ok(()),
            Self::AckAudit(ack) => {
                SafetyAuditAck::new(
                    ack.namespace_id(),
                    ack.audit_sequence(),
                    ack.event_id(),
                    ack.digest(),
                )
                .map_err(store_error)?;
                return Ok(());
            }
            Self::Initialize {
                body,
                idempotency_key,
            } => (idempotency_key, &body.reason),
            Self::Mutate {
                body,
                idempotency_key,
            } => {
                // Qualification evidence is immutable local configuration, never operator input.
                if matches!(
                    body.mutation,
                    SafetySwitchMutation::SetSharedAdmission { .. }
                ) {
                    return Err(ApiError::invalid_request(
                        "runtime updates cannot grant shared-context qualification",
                    ));
                }
                body.mutation
                    .normalized()
                    .map_err(|_| ApiError::invalid_request("invalid safety mutation"))?;
                (idempotency_key, &body.reason)
            }
        };
        if key.is_nil()
            || reason.trim().is_empty()
            || reason.len() > 2048
            || reason.chars().any(char::is_control)
        {
            return Err(ApiError::invalid_request(
                "invalid safety mutation identity or reason",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SafetyApi {
    store: SafetyAuthorityBlockingClient,
}

impl SafetyApi {
    #[must_use]
    pub fn new(store: SafetyAuthorityBlockingClient) -> Self {
        Self { store }
    }

    pub(crate) fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: SafetyRequest,
    ) -> Result<ApiResponse, ApiError> {
        // Retain authorization here too so alternate routers cannot bypass the global scope.
        principal.require_scope(request.scope()).map_err(|_| {
            ApiError::new(
                ErrorCode::PermissionDenied,
                "operator safety scope is required",
            )
        })?;
        request.validate()?;
        let identity = || {
            SafetyActorIdentity::new(
                principal.tenant_id().clone(),
                principal.principal_id().to_string(),
            )
            .map_err(store_error)
        };
        let data = match request {
            SafetyRequest::Get => encode(self.store.read().map_err(store_error)?)?,
            SafetyRequest::Initialize {
                body,
                idempotency_key,
            } => {
                let request =
                    SafetyInitializeRequest::new(identity()?, idempotency_key, body.reason)
                        .map_err(store_error)?;
                let receipt = self.store.initialize(request).map_err(store_error)?;
                json!({"receipt":encode(receipt)?, "status":"persisted", "application":"pending_observation"})
            }
            SafetyRequest::Mutate {
                body,
                idempotency_key,
            } => {
                let request = SafetyMutationRequest::new(
                    identity()?,
                    idempotency_key,
                    body.expected_version,
                    body.mutation,
                    body.reason,
                )
                .map_err(store_error)?;
                let receipt = self.store.mutate(request).map_err(store_error)?;
                json!({"receipt":encode(receipt)?, "status":"persisted", "application":"pending_observation"})
            }
            SafetyRequest::Audits => {
                let intents = self.store.pending_audits(32).map_err(store_error)?;
                let items: Vec<Value> = intents
                    .iter()
                    .map(|intent| json!({"event":intent,"ack":intent.ack()}))
                    .collect();
                json!({"items":items})
            }
            SafetyRequest::AckAudit(ack) => {
                self.store.ack_audit(ack.clone()).map_err(store_error)?;
                json!({"acknowledged":ack})
            }
        };
        Ok(ApiResponse::Safety(ApiEnvelope::new(data)))
    }
}

fn encode(value: impl Serialize) -> Result<Value, ApiError> {
    serde_json::to_value(value)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "safety response serialization failed"))
}

pub(crate) fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::WorkerUnavailable,
        "runtime safety authority unavailable",
    )
}

fn store_error(error: SafetyAuthorityError) -> ApiError {
    use SafetyAuthorityError as E;
    match error {
        E::InvalidInput | E::InvalidAck | E::InvalidSnapshot => {
            ApiError::invalid_request("invalid runtime safety request")
        }
        E::AlreadyInitialized | E::IdempotencyConflict | E::VersionConflict { .. } => {
            ApiError::new(
                ErrorCode::IdempotencyConflict,
                "runtime safety version or idempotency conflict",
            )
        }
        E::Capacity => ApiError::new(
            ErrorCode::AuditUnavailable,
            "runtime safety audit or receipt capacity exhausted",
        ),
        E::MissingAuthority
        | E::InvalidConfig
        | E::ConfigMismatch
        | E::CorruptState
        | E::Unavailable
        | E::TimedOut
        | E::QueueFull
        | E::ActorDisconnected
        | E::ActorSpawn
        | E::NamespaceMismatch
        | E::Rollback
        | E::Equivocation
        | E::DurabilityUnavailable => unavailable(),
    }
}
