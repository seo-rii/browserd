//! Historical artifact reads authenticate the serving worker without restoring a browser session.

use super::*;
use browserd_auth::AuthenticatedPrincipal;
use browserd_core::ArtifactId;
use browserd_worker::{WorkerRetainedArtifactReceipt, WorkerRetainedArtifactScope};

fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::WorkerUnavailable,
        "retained artifact unavailable",
    )
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    pub(super) fn live_artifact_record(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<Option<GatewaySessionRecord>, ApiError> {
        if self.fleet.is_some() {
            return Ok(None);
        }
        let sessions = self.sessions.lock().map_err(|_| unavailable())?;
        Ok(sessions
            .get(&(tenant.clone(), session.clone()))
            .filter(|record| record.resource.lifecycle == SessionLifecycle::Ready)
            .cloned())
    }

    pub(super) fn retained_artifact_scope(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<WorkerRetainedArtifactScope, ApiError> {
        let original = self
            .placement_authority(tenant, session)?
            .map(|authority| authority.entry().fence().worker_id().clone())
            .unwrap_or_else(|| self.placement.worker_id.clone());
        let serving = self.historical_worker(&original)?;
        Ok(WorkerRetainedArtifactScope {
            worker_id: serving.worker_id,
            worker_epoch: serving.epoch,
            tenant_id: tenant.clone(),
            session_id: session.clone(),
        })
    }

    pub(super) fn validate_retained_artifact(
        &self,
        scope: &WorkerRetainedArtifactScope,
        id: &ArtifactId,
        receipt: &WorkerRetainedArtifactReceipt,
    ) -> Result<ArtifactMetadata, ApiError> {
        let artifact = &receipt.publication.artifact;
        let now = u64::try_from(Utc::now().timestamp_millis()).map_err(|_| unavailable())?;
        if (self.fleet.is_none()
            && (scope.worker_id != self.placement.worker_id
                || scope.worker_epoch != self.placement.worker_epoch))
            || receipt.serving_worker_id != scope.worker_id
            || receipt.serving_worker_epoch != scope.worker_epoch
            || receipt.publication.original_worker_id != scope.worker_id
            || artifact.fence.tenant_id != scope.tenant_id
            || artifact.fence.session_id != scope.session_id
            || artifact.artifact_id != *id
            || artifact.state != WorkerArtifactState::Available
            || now >= receipt.publication.expires_at_unix_millis
            || receipt.publication.published_at_unix_millis > now
        {
            return Err(unavailable());
        }
        receipt
            .publication
            .to_publication()
            .map_err(|_| unavailable())?;
        Self::artifact_content_metadata(&scope.tenant_id, &scope.session_id, artifact.clone())
    }

    pub(super) fn retained_artifact_receipt(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        id: &ArtifactId,
    ) -> Result<WorkerRetainedArtifactReceipt, ApiError> {
        let scope = self.retained_artifact_scope(tenant, session)?;
        let response = self
            .client_for_worker_id(&scope.worker_id)?
            .request(WorkerRpcRequest::GetRetainedArtifact {
                scope: scope.clone(),
                artifact_id: id.clone(),
            })
            .map_err(|_| unavailable())?;
        let WorkerRpcResponse::RetainedArtifact(receipt) = response else {
            return Err(unavailable());
        };
        self.validate_retained_artifact(&scope, id, &receipt)?;
        Ok(receipt)
    }

    pub(super) fn get_retained_artifact(
        &self,
        principal: &AuthenticatedPrincipal,
        command: ArtifactRequest,
    ) -> Result<ApiResponse, ApiError> {
        let scope = self.retained_artifact_scope(principal.tenant_id(), &command.session_id)?;
        let receipt = self.retained_artifact_receipt(
            principal.tenant_id(),
            &command.session_id,
            &command.artifact_id,
        )?;
        self.validate_retained_artifact(&scope, &command.artifact_id, &receipt)
            .map(ApiEnvelope::new)
            .map(ApiResponse::Artifact)
    }

    pub(super) fn list_retained_artifacts(
        &self,
        principal: &AuthenticatedPrincipal,
        command: ArtifactListRequest,
    ) -> Result<ApiResponse, ApiError> {
        command.validate()?;
        let scope = self.retained_artifact_scope(principal.tenant_id(), &command.session_id)?;
        let response = self
            .client_for_worker_id(&scope.worker_id)?
            .request(WorkerRpcRequest::ListRetainedArtifacts {
                scope: scope.clone(),
                after: command.after.clone(),
                limit: command.limit + 1,
            })
            .map_err(|_| unavailable())?;
        let WorkerRpcResponse::RetainedArtifacts(receipts) = response else {
            return Err(unavailable());
        };
        if receipts.len() > command.limit + 1 {
            return Err(unavailable());
        }
        let mut previous = command.after;
        let mut items = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            let id = receipt.publication.artifact.artifact_id.clone();
            if previous.as_ref().is_some_and(|previous| id <= *previous) {
                return Err(unavailable());
            }
            // Validate the lookahead row too: pagination is never a scope-validation shortcut.
            items.push(self.validate_retained_artifact(&scope, &id, &receipt)?);
            previous = Some(id);
        }
        let next_cursor = if items.len() > command.limit {
            items.truncate(command.limit);
            items.last().map(|item| item.key.artifact_id().clone())
        } else {
            None
        };
        Ok(ApiResponse::Artifacts(ApiEnvelope::new(ArtifactListPage {
            items,
            next_cursor,
        })))
    }
}
