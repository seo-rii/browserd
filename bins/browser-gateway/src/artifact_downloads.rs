use super::*;
use async_trait::async_trait;
use browserd_api::ArtifactUploadRequest;
use browserd_artifacts::DownloadToken;
use browserd_auth::AuthenticatedPrincipal;
use browserd_core::{ArtifactId, LeaseId};
use browserd_http::{ArtifactBody, ArtifactDownloadBody, ArtifactTransport};
use browserd_worker::{WorkerRetainedArtifactReceipt, WorkerRetainedArtifactScope};
use sha2::{Digest, Sha256};

const MAX_TOKENS: usize = 256;
const TOKEN_TTL: Duration = Duration::from_secs(60);

struct TokenRecord {
    token: DownloadToken,
    receipt: WorkerArtifactReceipt,
    retained: Option<WorkerRetainedArtifactReceipt>,
    expires: Instant,
}

#[derive(Default)]
pub(super) struct DownloadTokens {
    records: HashMap<String, TokenRecord>,
}

fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::WorkerUnavailable,
        "artifact transfer unavailable",
    )
}

impl DownloadTokens {
    fn issue(&mut self, receipt: WorkerArtifactReceipt) -> Result<DownloadToken, ApiError> {
        self.issue_bound(receipt, None, TOKEN_TTL)
    }

    fn issue_retained(
        &mut self,
        receipt: WorkerRetainedArtifactReceipt,
    ) -> Result<DownloadToken, ApiError> {
        let now = u64::try_from(Utc::now().timestamp_millis()).map_err(|_| unavailable())?;
        let remaining = receipt
            .publication
            .expires_at_unix_millis
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(unavailable)?;
        self.issue_bound(
            receipt.publication.artifact.clone(),
            Some(receipt),
            TOKEN_TTL.min(Duration::from_millis(remaining)),
        )
    }

    fn issue_bound(
        &mut self,
        receipt: WorkerArtifactReceipt,
        retained: Option<WorkerRetainedArtifactReceipt>,
        ttl: Duration,
    ) -> Result<DownloadToken, ApiError> {
        self.records
            .retain(|_, record| record.expires > Instant::now());
        if self.records.len() >= MAX_TOKENS {
            return Err(unavailable());
        }
        let token = DownloadToken::new();
        let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        self.records.insert(
            secret,
            TokenRecord {
                token: token.clone(),
                receipt,
                retained,
                expires: Instant::now() + ttl,
            },
        );
        Ok(token)
    }

    fn consume(
        &mut self,
        tenant: &TenantId,
        session: &SessionId,
        artifact: &ArtifactId,
        secret: &str,
    ) -> Result<TokenRecord, ApiError> {
        self.records
            .retain(|_, record| record.expires > Instant::now());
        let record = self.records.get(secret).ok_or_else(unavailable)?;
        if &record.receipt.fence.tenant_id != tenant
            || &record.receipt.fence.session_id != session
            || &record.receipt.artifact_id != artifact
        {
            return Err(unavailable());
        }
        self.records.remove(secret).ok_or_else(unavailable)
    }
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    async fn open_retained_download(
        &self,
        expected: WorkerRetainedArtifactReceipt,
    ) -> Result<ArtifactDownloadBody, ApiError> {
        let artifact = &expected.publication.artifact;
        let scope = WorkerRetainedArtifactScope {
            worker_id: expected.serving_worker_id.clone(),
            worker_epoch: expected.serving_worker_epoch,
            tenant_id: artifact.fence.tenant_id.clone(),
            session_id: artifact.fence.session_id.clone(),
        };
        self.validate_retained_artifact(&scope, &artifact.artifact_id, &expected)?;
        let request = WorkerRpcRequest::OpenRetainedArtifact {
            scope: scope.clone(),
            publication: expected.publication.clone(),
            max_chunk_bytes: 64 * 1024,
        };
        let pinned_client = self.client_for_worker_id(&scope.worker_id)?;
        let client = Arc::clone(&pinned_client);
        let response = tokio::task::spawn_blocking(move || client.request(request))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        let WorkerRpcResponse::RetainedArtifactOpened { receipt, stream_id } = response else {
            return Err(unavailable());
        };
        let mut stream = DownloadStream {
            client: pinned_client,
            fence: artifact.fence.clone(),
            retained_scope: Some(scope),
            expires_at_unix_millis: Some(expected.publication.expires_at_unix_millis),
            stream_id,
            next_sequence: 0,
            closed: false,
            pending: None,
            bytes_read: 0,
            expected_size: artifact.size_bytes,
            expected_checksum: artifact.checksum_sha256,
            hash: Sha256::new(),
        };
        if receipt != expected {
            stream.abort();
            return Err(unavailable());
        }
        Ok(ArtifactDownloadBody {
            size_bytes: artifact.size_bytes,
            stream: Box::new(stream),
        })
    }

    pub(super) fn upload_artifact(
        &self,
        principal: &AuthenticatedPrincipal,
        command: ArtifactUploadRequest,
    ) -> Result<ApiResponse, ApiError> {
        command.body.validate()?;
        let bytes = command.body.decode_bytes()?;
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let response = self
            .request_worker(WorkerRpcRequest::UploadNamedArtifact {
                fence: record.fence.clone(),
                bytes,
                display_filename: command.body.display_filename,
                content_type: command
                    .body
                    .declared_content_type
                    .unwrap_or_else(|| "application/octet-stream".to_owned()),
                now_unix_millis: u64::try_from(Utc::now().timestamp_millis())
                    .map_err(|_| unavailable())?,
            })
            .map_err(|_| unavailable())?;
        let WorkerRpcResponse::ArtifactStored(receipt) = response else {
            return Err(unavailable());
        };
        let artifact_id = receipt.artifact_id.clone();
        if receipt.source != WorkerArtifactSource::ClientUpload {
            return Err(unavailable());
        }
        self.artifact_metadata(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            &artifact_id,
            receipt,
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::ArtifactUpload)
    }

    pub(super) fn issue_artifact_download(
        &self,
        principal: &AuthenticatedPrincipal,
        command: ArtifactRequest,
    ) -> Result<ApiResponse, ApiError> {
        let Some(record) = self.live_artifact_record(principal.tenant_id(), &command.session_id)?
        else {
            let receipt = self.retained_artifact_receipt(
                principal.tenant_id(),
                &command.session_id,
                &command.artifact_id,
            )?;
            let token = self
                .downloads
                .lock()
                .map_err(|_| unavailable())?
                .issue_retained(receipt)?;
            return Ok(ApiResponse::ArtifactDownload(ApiEnvelope::new(token)));
        };
        let response = self
            .request_worker(WorkerRpcRequest::GetArtifact {
                fence: record.fence.clone(),
                artifact_id: command.artifact_id.clone(),
            })
            .map_err(|_| unavailable())?;
        let WorkerRpcResponse::Artifact(receipt) = response else {
            return Err(unavailable());
        };
        self.artifact_metadata(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            &command.artifact_id,
            receipt.clone(),
        )?;
        if receipt.state != WorkerArtifactState::Available {
            return Err(unavailable());
        }
        let token = self
            .downloads
            .lock()
            .map_err(|_| unavailable())?
            .issue(receipt)?;
        Ok(ApiResponse::ArtifactDownload(ApiEnvelope::new(token)))
    }
}

#[async_trait]
impl<C: GatewayWorkerClient> ArtifactTransport for GatewayWorkerRuntime<C> {
    fn present_token(&self, token: &DownloadToken) -> Option<String> {
        self.downloads
            .lock()
            .ok()?
            .records
            .iter()
            .find(|(_, record)| &record.token == token && record.expires > Instant::now())
            .map(|(secret, _)| secret.clone())
    }

    async fn consume(
        &self,
        principal: &AuthenticatedPrincipal,
        session_id: &SessionId,
        artifact_id: &ArtifactId,
        secret: &str,
    ) -> Result<ArtifactDownloadBody, ApiError> {
        principal
            .require_scope("artifact:read")
            .map_err(|_| unavailable())?;
        let token_record = self.downloads.lock().map_err(|_| unavailable())?.consume(
            principal.tenant_id(),
            session_id,
            artifact_id,
            secret,
        )?;
        if let Some(retained) = token_record.retained {
            return self.open_retained_download(retained).await;
        }
        let expected = token_record.receipt;
        self.validate_current_fence(principal.tenant_id(), session_id, &expected.fence)?;
        let request = WorkerRpcRequest::OpenArtifact {
            fence: expected.fence.clone(),
            artifact_id: artifact_id.clone(),
        };
        let pinned_client = self.client_for_fence(&expected.fence)?;
        let client = Arc::clone(&pinned_client);
        let response = tokio::task::spawn_blocking(move || client.request(request))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        let WorkerRpcResponse::ArtifactOpened {
            fence,
            stream_id,
            artifact,
        } = response
        else {
            return Err(unavailable());
        };
        let mut stream = DownloadStream {
            client: pinned_client,
            fence: fence.clone(),
            retained_scope: None,
            expires_at_unix_millis: None,
            stream_id,
            next_sequence: 0,
            closed: false,
            pending: None,
            bytes_read: 0,
            expected_size: expected.size_bytes,
            expected_checksum: expected.checksum_sha256,
            hash: Sha256::new(),
        };
        if fence != expected.fence || artifact != expected {
            stream.abort();
            return Err(unavailable());
        }
        Ok(ArtifactDownloadBody {
            size_bytes: expected.size_bytes,
            stream: Box::new(stream),
        })
    }
}

struct DownloadStream<C: GatewayWorkerClient> {
    client: Arc<C>,
    fence: WorkerSessionFence,
    retained_scope: Option<WorkerRetainedArtifactScope>,
    expires_at_unix_millis: Option<u64>,
    stream_id: LeaseId,
    next_sequence: u64,
    closed: bool,
    pending: Option<Vec<u8>>,
    bytes_read: u64,
    expected_size: u64,
    expected_checksum: [u8; 32],
    hash: Sha256,
}

impl<C: GatewayWorkerClient> DownloadStream<C> {
    async fn read(&mut self) -> Result<Option<Vec<u8>>, ApiError> {
        if let Some(expiry) = self.expires_at_unix_millis {
            let now = u64::try_from(Utc::now().timestamp_millis()).map_err(|_| unavailable())?;
            if now >= expiry {
                return Err(unavailable());
            }
        }
        let request = if let Some(scope) = &self.retained_scope {
            WorkerRpcRequest::ReadRetainedArtifact {
                scope: scope.clone(),
                stream_id: self.stream_id.clone(),
                sequence: self.next_sequence,
            }
        } else {
            WorkerRpcRequest::ReadArtifact {
                fence: self.fence.clone(),
                stream_id: self.stream_id.clone(),
                sequence: self.next_sequence,
            }
        };
        let client = Arc::clone(&self.client);
        let response = tokio::task::spawn_blocking(move || client.request(request))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        let bytes = match (response, &self.retained_scope) {
            (
                WorkerRpcResponse::ArtifactChunk {
                    fence,
                    stream_id,
                    sequence,
                    bytes,
                },
                None,
            ) if fence == self.fence
                && stream_id == self.stream_id
                && sequence == self.next_sequence =>
            {
                bytes
            }
            (
                WorkerRpcResponse::RetainedArtifactChunk {
                    scope,
                    stream_id,
                    sequence,
                    bytes,
                    end,
                },
                Some(expected),
            ) if scope == *expected
                && stream_id == self.stream_id
                && sequence == self.next_sequence =>
            {
                if end {
                    if !bytes.is_empty() {
                        return Err(unavailable());
                    }
                    None
                } else {
                    Some(bytes)
                }
            }
            _ => return Err(unavailable()),
        };
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(unavailable)?;
        if let Some(bytes) = &bytes {
            if bytes.is_empty() || bytes.len() > 64 * 1024 {
                return Err(unavailable());
            }
            self.bytes_read = self
                .bytes_read
                .checked_add(bytes.len() as u64)
                .ok_or_else(unavailable)?;
            if self.bytes_read > self.expected_size {
                return Err(unavailable());
            }
            self.hash.update(bytes);
        } else if self.bytes_read != self.expected_size
            || <[u8; 32]>::from(self.hash.clone().finalize()) != self.expected_checksum
        {
            return Err(unavailable());
        }
        Ok(bytes)
    }
}

#[async_trait]
impl<C: GatewayWorkerClient> ArtifactBody for DownloadStream<C> {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ApiError> {
        if self.closed {
            return Ok(None);
        }
        let current = match self.pending.take() {
            Some(bytes) => bytes,
            None => match self.read().await? {
                Some(bytes) => bytes,
                None => {
                    self.closed = true;
                    return Ok(None);
                }
            },
        };
        // Withhold the final chunk until the worker EOF and full checksum are verified.
        self.pending = self.read().await?;
        if self.pending.is_none() {
            self.closed = true;
        }
        Ok(Some(current))
    }

    fn abort(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let request = if let Some(scope) = &self.retained_scope {
            WorkerRpcRequest::CloseRetainedArtifact {
                scope: scope.clone(),
                stream_id: self.stream_id.clone(),
            }
        } else {
            WorkerRpcRequest::CloseArtifact {
                fence: self.fence.clone(),
                stream_id: self.stream_id.clone(),
            }
        };
        let client = Arc::clone(&self.client);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(move || {
                let _ = client.request(request);
            });
        }
        // Worker idle expiry also covers gateway crashes and runtimes that have shut down.
    }
}

impl<C: GatewayWorkerClient> Drop for DownloadStream<C> {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestClient {
        chunks: Mutex<std::collections::VecDeque<Vec<u8>>>,
        wrong_fence: bool,
    }
    struct NoPending;
    impl GatewayWorkerPending for NoPending {
        fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
            Err(WorkerRpcCompletionError::Disconnected)
        }
    }
    impl GatewayWorkerClient for TestClient {
        type PendingAction = NoPending;
        fn create_session(
            &self,
            _request: WorkerCreateSessionRequest,
        ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
            Err(WorkerRpcError::InvalidConfig)
        }
        fn enqueue_action(
            &self,
            request: WorkerRpcRequest,
        ) -> Result<NoPending, WorkerRpcEnqueueError> {
            Err(WorkerRpcEnqueueError::Closed(Box::new(request)))
        }
        fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
            match request {
                WorkerRpcRequest::ReadArtifact {
                    mut fence,
                    stream_id,
                    sequence,
                } => {
                    if self.wrong_fence {
                        fence.tenant_id = TenantId::new();
                    }
                    let bytes = self
                        .chunks
                        .lock()
                        .map_err(|_| WorkerRpcError::InvalidConfig)?
                        .pop_front();
                    Ok(WorkerRpcResponse::ArtifactChunk {
                        fence,
                        stream_id,
                        sequence,
                        bytes,
                    })
                }
                WorkerRpcRequest::CloseArtifact { .. } => Ok(WorkerRpcResponse::Empty),
                _ => Err(WorkerRpcError::InvalidConfig),
            }
        }
    }
    fn stream(data: &[u8], chunks: Vec<Vec<u8>>, wrong_fence: bool) -> DownloadStream<TestClient> {
        DownloadStream {
            client: Arc::new(TestClient {
                chunks: Mutex::new(chunks.into()),
                wrong_fence,
            }),
            fence: receipt().fence,
            retained_scope: None,
            expires_at_unix_millis: None,
            stream_id: LeaseId::new(),
            next_sequence: 0,
            closed: false,
            pending: None,
            bytes_read: 0,
            expected_size: data.len() as u64,
            expected_checksum: Sha256::digest(data).into(),
            hash: Sha256::new(),
        }
    }

    #[tokio::test]
    async fn stream_verifies_size_checksum_and_fence_before_releasing_final_bytes()
    -> Result<(), ApiError> {
        let mut valid = stream(b"hello", vec![b"he".to_vec(), b"llo".to_vec()], false);
        assert_eq!(valid.next_chunk().await?, Some(b"he".to_vec()));
        assert_eq!(valid.next_chunk().await?, Some(b"llo".to_vec()));
        assert_eq!(valid.next_chunk().await?, None);
        let mut corrupt = stream(b"hello", vec![b"world".to_vec()], false);
        assert!(corrupt.next_chunk().await.is_err());
        let mut truncated = stream(b"hello", vec![b"hell".to_vec()], false);
        assert!(truncated.next_chunk().await.is_err());
        let mut foreign = stream(b"hello", vec![b"hello".to_vec()], true);
        assert!(foreign.next_chunk().await.is_err());
        let mut oversized = stream(&vec![0; 65_537], vec![vec![0; 65_537]], false);
        assert!(oversized.next_chunk().await.is_err());
        Ok(())
    }

    fn receipt() -> WorkerArtifactReceipt {
        WorkerArtifactReceipt {
            fence: WorkerSessionFence {
                tenant_id: TenantId::new(),
                session_id: SessionId::new(),
                worker_epoch: 1,
                placement_version: 1,
                session_incarnation: 1,
            },
            artifact_id: ArtifactId::new(),
            state: WorkerArtifactState::Available,
            size_bytes: 1,
            checksum_sha256: [1; 32],
            content_type: "application/octet-stream".to_owned(),
            source: WorkerArtifactSource::Generated,
            display_filename: None,
            origin: "browserd-test".to_owned(),
            object_generation: [2; 32],
        }
    }
    #[test]
    fn tokens_are_scoped_one_use_expiring_and_bounded() -> Result<(), ApiError> {
        let mut tokens = DownloadTokens::default();
        let expected = receipt();
        tokens.issue(expected.clone())?;
        let secret = tokens
            .records
            .keys()
            .next()
            .cloned()
            .ok_or_else(unavailable)?;
        assert!(
            tokens
                .consume(
                    &TenantId::new(),
                    &expected.fence.session_id,
                    &expected.artifact_id,
                    &secret
                )
                .is_err()
        );
        assert!(
            tokens
                .consume(
                    &expected.fence.tenant_id,
                    &SessionId::new(),
                    &expected.artifact_id,
                    &secret
                )
                .is_err()
        );
        assert_eq!(
            tokens
                .consume(
                    &expected.fence.tenant_id,
                    &expected.fence.session_id,
                    &expected.artifact_id,
                    &secret
                )?
                .receipt,
            expected
        );
        assert!(
            tokens
                .consume(
                    &expected.fence.tenant_id,
                    &expected.fence.session_id,
                    &expected.artifact_id,
                    &secret
                )
                .is_err()
        );
        for _ in 0..MAX_TOKENS {
            tokens.issue(expected.clone())?;
        }
        assert!(tokens.issue(expected.clone()).is_err());
        for record in tokens.records.values_mut() {
            record.expires = Instant::now();
        }
        assert!(tokens.issue(expected).is_ok());
        Ok(())
    }
}
