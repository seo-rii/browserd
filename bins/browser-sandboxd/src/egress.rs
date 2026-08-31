use std::collections::HashMap;
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::panic::AssertUnwindSafe;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{EgressFence, LeaseId, TenantId};
use browserd_egress_control::{
    ActiveInstallResponse, EpochProbeRequest, InstallRequest, send_epoch_probe, send_listener,
};
use browserd_sandbox::{
    EgressRouteBackend, NetworkNamespaceIdentity, PinnedNetworkNamespace, SandboxError,
    ShardEgressReservation, ShardIngressLease, ShardIngressReceipt,
    create_dedicated_egress_listener,
};
use futures::{FutureExt, StreamExt};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Semaphore, oneshot};
use tokio::time::{Instant, timeout, timeout_at};
use url::Url;

const MAX_TOKEN_BYTES: usize = 4 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_IN_FLIGHT_INSTALLS: usize = 32;
const MAX_IN_FLIGHT_REVOKES: usize = 32;

#[derive(Clone)]
pub struct EgressClientConfig {
    control_endpoint: Url,
    install_socket: PathBuf,
    daemon_epoch: u64,
    expected_server_uid: u32,
    worker_token: Arc<str>,
    supervisor_token: Arc<str>,
    request_timeout: Duration,
    max_response_bytes: usize,
}

impl std::fmt::Debug for EgressClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EgressClientConfig")
            .field("control_endpoint", &self.control_endpoint)
            .field("install_socket", &self.install_socket)
            .field("daemon_epoch", &self.daemon_epoch)
            .field("expected_server_uid", &self.expected_server_uid)
            .field("worker_token", &"[REDACTED]")
            .field("supervisor_token", &"[REDACTED]")
            .field("request_timeout", &self.request_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl EgressClientConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        control_endpoint: Url,
        install_socket: PathBuf,
        daemon_epoch: u64,
        expected_server_uid: u32,
        worker_token: impl Into<String>,
        supervisor_token: impl Into<String>,
        request_timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, EgressControlError> {
        let worker_token = worker_token.into();
        let supervisor_token = supervisor_token.into();
        let loopback = control_endpoint
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if control_endpoint.scheme() != "http"
            || !loopback
            || !control_endpoint.username().is_empty()
            || control_endpoint.password().is_some()
            || control_endpoint.query().is_some()
            || control_endpoint.fragment().is_some()
            || control_endpoint.path() != "/"
            || !safe_socket_path(&install_socket)
            || daemon_epoch == 0
            || request_timeout.is_zero()
            || request_timeout > Duration::from_secs(30)
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || !valid_token(&worker_token)
            || !valid_token(&supervisor_token)
            || worker_token == supervisor_token
        {
            return Err(EgressControlError::InvalidConfig);
        }
        Ok(Self {
            control_endpoint,
            install_socket,
            daemon_epoch,
            expected_server_uid,
            worker_token: Arc::from(worker_token),
            supervisor_token: Arc::from(supervisor_token),
            request_timeout,
            max_response_bytes,
        })
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub fn install_socket(&self) -> &Path {
        &self.install_socket
    }

    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }
}

fn valid_token(token: &str) -> bool {
    (32..=MAX_TOKEN_BYTES).contains(&token.len())
        && token.as_bytes().iter().all(u8::is_ascii_graphic)
}

fn safe_socket_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path.file_name().is_some()
        && !path.starts_with("/tmp")
        && !path.starts_with("/var/tmp")
        && !path.starts_with("/run/user")
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRouteReceipt {
    daemon_epoch: u64,
    egress_fence: EgressFence,
    binding_digest: [u8; 32],
    prepare_revision: u64,
}

impl PreparedRouteReceipt {
    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    #[must_use]
    pub const fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    #[must_use]
    pub const fn prepare_revision(&self) -> u64 {
        self.prepare_revision
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatusState {
    Absent,
    Prepared,
    Installing,
    Active,
    Revoking,
    Revoked,
    Drained,
    Cancelled,
    Released,
}

impl RouteStatusState {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Absent | Self::Revoked | Self::Drained | Self::Cancelled | Self::Released
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteStatusReceipt {
    daemon_epoch: u64,
    egress_fence: EgressFence,
    state: RouteStatusState,
    active: Option<ActiveInstallResponse>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewRouteLeaseRequest {
    renewal_sequence: u64,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    attachment_id: u64,
    activation_revision: u64,
    lease_ttl: Duration,
}

impl RenewRouteLeaseRequest {
    pub fn new(
        renewal_sequence: u64,
        daemon_epoch: u64,
        egress_fence: EgressFence,
        attachment_id: u64,
        activation_revision: u64,
        lease_ttl: Duration,
    ) -> Result<Self, EgressControlError> {
        if renewal_sequence == 0
            || daemon_epoch == 0
            || attachment_id == 0
            || activation_revision == 0
            || lease_ttl.is_zero()
        {
            return Err(EgressControlError::Protocol(
                "invalid route renewal request".into(),
            ));
        }
        Ok(Self {
            renewal_sequence,
            daemon_epoch,
            egress_fence,
            attachment_id,
            activation_revision,
            lease_ttl,
        })
    }

    #[must_use]
    pub const fn renewal_sequence(&self) -> u64 {
        self.renewal_sequence
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewedRouteLeaseReceipt {
    renewal_sequence: u64,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    attachment_id: u64,
    activation_revision: u64,
    expires_at_millis: u64,
}

impl RenewedRouteLeaseReceipt {
    #[must_use]
    pub const fn renewal_sequence(&self) -> u64 {
        self.renewal_sequence
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    #[must_use]
    pub const fn attachment_id(&self) -> u64 {
        self.attachment_id
    }

    #[must_use]
    pub const fn activation_revision(&self) -> u64 {
        self.activation_revision
    }

    #[must_use]
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }
}

impl RouteStatusReceipt {
    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    #[must_use]
    pub const fn state(&self) -> RouteStatusState {
        self.state
    }

    #[must_use]
    pub const fn active(&self) -> Option<&ActiveInstallResponse> {
        self.active.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum EgressControlError {
    #[error("egress control configuration is invalid")]
    InvalidConfig,
    #[error("egress control request timed out")]
    TimedOut,
    #[error("egress listener install outcome requires status reconciliation")]
    InstallUncertain,
    #[error("egress control peer UID mismatch: expected {expected}, received {received}")]
    PeerUidMismatch { expected: u32, received: u32 },
    #[error("egress control protocol failed: {0}")]
    Protocol(String),
    #[error("egress control request failed: {0}")]
    Transport(String),
}

#[derive(Clone, Debug)]
pub struct PrepareRouteRequest {
    pub daemon_epoch: u64,
    pub tenant_id: TenantId,
    pub egress_fence: EgressFence,
    pub binding_digest: [u8; 32],
    pub profile: String,
    pub lease_ttl: Duration,
}

#[async_trait]
pub trait EgressControlPlane: Send + Sync + 'static {
    async fn current_daemon_epoch(&self) -> Result<u64, EgressControlError>;

    async fn prepare(
        &self,
        request: PrepareRouteRequest,
    ) -> Result<PreparedRouteReceipt, EgressControlError>;

    async fn install(
        &self,
        request: InstallRequest,
        listener: OwnedFd,
    ) -> Result<ActiveInstallResponse, EgressControlError>;

    async fn renew(
        &self,
        _request: RenewRouteLeaseRequest,
    ) -> Result<RenewedRouteLeaseReceipt, EgressControlError> {
        Err(EgressControlError::Protocol(
            "route renewal is unsupported by this control plane".into(),
        ))
    }

    async fn status(
        &self,
        daemon_epoch: u64,
        fence: &EgressFence,
    ) -> Result<Option<RouteStatusReceipt>, EgressControlError>;

    async fn revoke(
        &self,
        daemon_epoch: u64,
        fence: &EgressFence,
    ) -> Result<Option<RouteStatusReceipt>, EgressControlError>;
}

#[derive(Clone)]
pub struct HttpEgressControl {
    config: EgressClientConfig,
    client: Client,
}

impl HttpEgressControl {
    pub fn new(config: EgressClientConfig) -> Result<Self, EgressControlError> {
        let client = Client::builder()
            .connect_timeout(config.request_timeout)
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| EgressControlError::Transport(error.to_string()))?;
        Ok(Self { config, client })
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.config.daemon_epoch
    }

    async fn connect_install_socket(&self) -> Result<UnixStream, EgressControlError> {
        let stream = timeout(
            self.config.request_timeout,
            UnixStream::connect(&self.config.install_socket),
        )
        .await
        .map_err(|_| EgressControlError::TimedOut)?
        .map_err(|error| EgressControlError::Transport(error.to_string()))?;
        let peer = stream
            .peer_cred()
            .map_err(|error| EgressControlError::Transport(error.to_string()))?;
        if peer.uid() != self.config.expected_server_uid {
            return Err(EgressControlError::PeerUidMismatch {
                expected: self.config.expected_server_uid,
                received: peer.uid(),
            });
        }
        Ok(stream)
    }

    pub async fn authenticated_current_daemon_epoch(&self) -> Result<u64, EgressControlError> {
        let stream = self.connect_install_socket().await?;
        timeout(
            self.config.request_timeout,
            send_epoch_probe(stream, EpochProbeRequest::new(LeaseId::new())),
        )
        .await
        .map_err(|_| EgressControlError::TimedOut)?
        .map(|response| response.current_daemon_epoch())
        .map_err(|error| EgressControlError::Protocol(error.to_string()))
    }

    async fn post<Request, Response>(
        &self,
        path: &str,
        token: &str,
        request: &Request,
    ) -> Result<Option<Response>, EgressControlError>
    where
        Request: Serialize + Sync,
        Response: for<'de> Deserialize<'de>,
    {
        let endpoint = self
            .config
            .control_endpoint
            .join(path)
            .map_err(|error| EgressControlError::Protocol(error.to_string()))?;
        let request_deadline = Instant::now() + self.config.request_timeout;
        let response = timeout_at(
            request_deadline,
            self.client
                .post(endpoint)
                .bearer_auth(token)
                .json(request)
                .send(),
        )
        .await
        .map_err(|_| EgressControlError::TimedOut)?
        .map_err(|error| EgressControlError::Transport(error.to_string()))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(EgressControlError::Protocol(format!(
                "egress control returned HTTP {}",
                response.status()
            )));
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = timeout_at(request_deadline, stream.next())
            .await
            .map_err(|_| EgressControlError::TimedOut)?
        {
            let chunk = chunk.map_err(|error| EgressControlError::Transport(error.to_string()))?;
            if body.len().saturating_add(chunk.len()) > self.config.max_response_bytes {
                return Err(EgressControlError::Protocol(
                    "egress control response exceeded its configured limit".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|error| EgressControlError::Protocol(error.to_string()))
    }
}

#[derive(Serialize)]
struct PrepareApiRequest<'a> {
    daemon_epoch: u64,
    tenant_id: &'a TenantId,
    egress_fence: &'a EgressFence,
    binding_digest_hex: String,
    profile: &'a str,
    lease_ttl_millis: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareApiResponse {
    daemon_epoch: u64,
    egress_fence: EgressFence,
    binding_digest_hex: String,
    prepare_revision: u64,
}

#[derive(Serialize)]
struct FenceApiRequest<'a> {
    daemon_epoch: u64,
    egress_fence: &'a EgressFence,
}

#[derive(Serialize)]
struct RenewApiRequest<'a> {
    renewal_sequence: u64,
    daemon_epoch: u64,
    egress_fence: &'a EgressFence,
    attachment_id: u64,
    activation_revision: u64,
    lease_ttl_millis: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewApiResponse {
    renewal_sequence: u64,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    attachment_id: u64,
    activation_revision: u64,
    expires_at_millis: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusApiResponse {
    daemon_epoch: u64,
    egress_fence: EgressFence,
    state: RouteStatusState,
    active: Option<ActiveInstallResponse>,
}

#[async_trait]
impl EgressControlPlane for HttpEgressControl {
    async fn current_daemon_epoch(&self) -> Result<u64, EgressControlError> {
        self.authenticated_current_daemon_epoch().await
    }

    async fn prepare(
        &self,
        request: PrepareRouteRequest,
    ) -> Result<PreparedRouteReceipt, EgressControlError> {
        let lease_ttl_millis = u64::try_from(request.lease_ttl.as_millis())
            .map_err(|_| EgressControlError::Protocol("lease TTL overflow".into()))?;
        let response: PrepareApiResponse = self
            .post(
                "/v1/routes/prepare",
                &self.config.worker_token,
                &PrepareApiRequest {
                    daemon_epoch: request.daemon_epoch,
                    tenant_id: &request.tenant_id,
                    egress_fence: &request.egress_fence,
                    binding_digest_hex: hex::encode(request.binding_digest),
                    profile: &request.profile,
                    lease_ttl_millis,
                },
            )
            .await?
            .ok_or_else(|| EgressControlError::Protocol("prepare route was not found".into()))?;
        let decoded = hex::decode(response.binding_digest_hex)
            .map_err(|error| EgressControlError::Protocol(error.to_string()))?;
        let binding_digest: [u8; 32] = decoded
            .try_into()
            .map_err(|_| EgressControlError::Protocol("invalid binding digest".into()))?;
        if response.daemon_epoch == 0 || response.prepare_revision == 0 || binding_digest == [0; 32]
        {
            return Err(EgressControlError::Protocol(
                "invalid prepared route receipt".into(),
            ));
        }
        Ok(PreparedRouteReceipt {
            daemon_epoch: response.daemon_epoch,
            egress_fence: response.egress_fence,
            binding_digest,
            prepare_revision: response.prepare_revision,
        })
    }

    async fn install(
        &self,
        request: InstallRequest,
        listener: OwnedFd,
    ) -> Result<ActiveInstallResponse, EgressControlError> {
        let stream = self.connect_install_socket().await?;
        timeout(
            self.config.request_timeout,
            send_listener(stream, request, listener),
        )
        .await
        .map_err(|_| EgressControlError::InstallUncertain)?
        .map_err(|error| EgressControlError::Protocol(error.to_string()))
    }

    async fn renew(
        &self,
        request: RenewRouteLeaseRequest,
    ) -> Result<RenewedRouteLeaseReceipt, EgressControlError> {
        let lease_ttl_millis = u64::try_from(request.lease_ttl.as_millis())
            .map_err(|_| EgressControlError::Protocol("lease TTL overflow".into()))?;
        let response: RenewApiResponse = self
            .post(
                "/v1/routes/renew",
                &self.config.worker_token,
                &RenewApiRequest {
                    renewal_sequence: request.renewal_sequence,
                    daemon_epoch: request.daemon_epoch,
                    egress_fence: &request.egress_fence,
                    attachment_id: request.attachment_id,
                    activation_revision: request.activation_revision,
                    lease_ttl_millis,
                },
            )
            .await?
            .ok_or_else(|| EgressControlError::Protocol("renew route was not found".into()))?;
        if response.renewal_sequence != request.renewal_sequence
            || response.daemon_epoch != request.daemon_epoch
            || response.egress_fence != request.egress_fence
            || response.attachment_id != request.attachment_id
            || response.activation_revision != request.activation_revision
            || response.expires_at_millis == 0
        {
            return Err(EgressControlError::Protocol(
                "renewed route receipt did not match its request".into(),
            ));
        }
        Ok(RenewedRouteLeaseReceipt {
            renewal_sequence: response.renewal_sequence,
            daemon_epoch: response.daemon_epoch,
            egress_fence: response.egress_fence,
            attachment_id: response.attachment_id,
            activation_revision: response.activation_revision,
            expires_at_millis: response.expires_at_millis,
        })
    }

    async fn status(
        &self,
        daemon_epoch: u64,
        fence: &EgressFence,
    ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
        let response: Option<StatusApiResponse> = self
            .post(
                "/v1/routes/status",
                &self.config.supervisor_token,
                &FenceApiRequest {
                    daemon_epoch,
                    egress_fence: fence,
                },
            )
            .await?;
        Ok(response.map(|response| RouteStatusReceipt {
            daemon_epoch: response.daemon_epoch,
            egress_fence: response.egress_fence,
            state: response.state,
            active: response.active,
        }))
    }

    async fn revoke(
        &self,
        daemon_epoch: u64,
        fence: &EgressFence,
    ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
        let response: Option<StatusApiResponse> = self
            .post(
                "/v1/routes/revoke",
                &self.config.supervisor_token,
                &FenceApiRequest {
                    daemon_epoch,
                    egress_fence: fence,
                },
            )
            .await?;
        Ok(response.map(|response| RouteStatusReceipt {
            daemon_epoch: response.daemon_epoch,
            egress_fence: response.egress_fence,
            state: response.state,
            active: response.active,
        }))
    }
}

struct ListenerCapability {
    descriptor: OwnedFd,
    address: std::net::SocketAddr,
    namespace: NetworkNamespaceIdentity,
}

trait EgressListenerFactory: Send + Sync + 'static {
    fn create(
        &self,
        namespace: &PinnedNetworkNamespace,
    ) -> Result<ListenerCapability, SandboxError>;
}

struct ExactListenerFactory;

impl EgressListenerFactory for ExactListenerFactory {
    fn create(
        &self,
        namespace: &PinnedNetworkNamespace,
    ) -> Result<ListenerCapability, SandboxError> {
        let listener = create_dedicated_egress_listener(namespace)
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
        let (descriptor, receipt) = listener.into_parts();
        Ok(ListenerCapability {
            descriptor,
            address: receipt.address(),
            namespace: receipt.namespace_identity(),
        })
    }
}

#[derive(Clone)]
struct PendingInstall {
    prepared: PreparedRouteReceipt,
    request: InstallRequest,
    address: std::net::SocketAddr,
    namespace: NetworkNamespaceIdentity,
    receipt: ShardIngressReceipt,
}

#[derive(Clone)]
struct ActiveRoute {
    pending: PendingInstall,
    active: ActiveInstallResponse,
    next_renewal_sequence: u64,
}

enum LocalRouteState {
    Preparing,
    Prepared(PreparedRouteReceipt),
    Installing(PendingInstall),
    Active(ActiveRoute),
    Terminal,
}

struct LocalRoute {
    reservation: ShardEgressReservation,
    state: LocalRouteState,
    renewal_operation: Arc<Mutex<()>>,
}

#[derive(Clone)]
pub struct EgressRouteAdapter {
    control: Arc<dyn EgressControlPlane>,
    listener_factory: Arc<dyn EgressListenerFactory>,
    daemon_epoch: u64,
    reconcile_timeout: Duration,
    routes: Arc<Mutex<HashMap<LeaseId, LocalRoute>>>,
    install_slots: Arc<Semaphore>,
    revoke_slots: Arc<Semaphore>,
}

impl EgressRouteAdapter {
    #[must_use]
    pub fn new(control: HttpEgressControl) -> Self {
        let daemon_epoch = control.daemon_epoch();
        let reconcile_timeout = control.config.request_timeout;
        Self {
            control: Arc::new(control),
            listener_factory: Arc::new(ExactListenerFactory),
            daemon_epoch,
            reconcile_timeout,
            routes: Arc::new(Mutex::new(HashMap::new())),
            install_slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT_INSTALLS)),
            revoke_slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT_REVOKES)),
        }
    }

    #[cfg(test)]
    fn with_components(
        control: Arc<dyn EgressControlPlane>,
        listener_factory: Arc<dyn EgressListenerFactory>,
        daemon_epoch: u64,
        reconcile_timeout: Duration,
    ) -> Self {
        Self {
            control,
            listener_factory,
            daemon_epoch,
            reconcile_timeout,
            routes: Arc::new(Mutex::new(HashMap::new())),
            install_slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT_INSTALLS)),
            revoke_slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT_REVOKES)),
        }
    }

    #[cfg(test)]
    fn with_components_and_revoke_limit(
        control: Arc<dyn EgressControlPlane>,
        listener_factory: Arc<dyn EgressListenerFactory>,
        daemon_epoch: u64,
        reconcile_timeout: Duration,
        max_in_flight_revoke: usize,
    ) -> Self {
        Self {
            control,
            listener_factory,
            daemon_epoch,
            reconcile_timeout,
            routes: Arc::new(Mutex::new(HashMap::new())),
            install_slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT_INSTALLS)),
            revoke_slots: Arc::new(Semaphore::new(max_in_flight_revoke)),
        }
    }

    fn validate_prepared(
        &self,
        reservation: &ShardEgressReservation,
        prepared: &PreparedRouteReceipt,
    ) -> Result<(), SandboxError> {
        let dedicated = reservation.dedicated_egress().ok_or_else(|| {
            SandboxError::Backend(
                "egress reservation is missing its immutable launch binding".into(),
            )
        })?;
        if prepared.daemon_epoch != self.daemon_epoch
            || prepared.egress_fence != *dedicated.egress_fence()
            || prepared.binding_digest != *dedicated.policy_binding().snapshot_digest()
            || prepared.prepare_revision == 0
        {
            return Err(SandboxError::Backend(
                "egress prepared receipt did not match the exact launch binding".into(),
            ));
        }
        Ok(())
    }

    fn validate_active(
        &self,
        pending: &PendingInstall,
        active: &ActiveInstallResponse,
    ) -> Result<(), SandboxError> {
        if active.transfer_id() != pending.request.transfer_id()
            || active.daemon_epoch() != self.daemon_epoch
            || active.egress_fence() != pending.request.egress_fence()
            || active.proxy_address() != pending.address
            || active.attachment_id() == 0
            || active.activation_revision() == 0
            || active.expires_at_millis() == 0
        {
            return Err(SandboxError::Backend(
                "egress Active receipt did not match the installed listener".into(),
            ));
        }
        Ok(())
    }

    async fn reconcile_active(
        &self,
        pending: &PendingInstall,
    ) -> Result<ActiveInstallResponse, SandboxError> {
        let deadline = Instant::now() + self.reconcile_timeout;
        loop {
            let status = self
                .control
                .status(self.daemon_epoch, pending.request.egress_fence())
                .await
                .map_err(|error| SandboxError::Backend(error.to_string()))?;
            match status {
                Some(status)
                    if status.daemon_epoch == self.daemon_epoch
                        && status.egress_fence == *pending.request.egress_fence()
                        && status.state == RouteStatusState::Active =>
                {
                    let active = status.active.ok_or_else(|| {
                        SandboxError::Backend("Active status omitted its receipt".into())
                    })?;
                    self.validate_active(pending, &active)?;
                    return Ok(active);
                }
                Some(status) if status.state.is_terminal() => {
                    return Err(SandboxError::Backend(
                        "egress install became terminal before Active receipt".into(),
                    ));
                }
                None => {
                    return Err(SandboxError::Backend(
                        "egress install disappeared before Active receipt".into(),
                    ));
                }
                Some(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Some(_) => {
                    return Err(SandboxError::Backend(
                        "egress install status did not become Active before its deadline".into(),
                    ));
                }
            }
        }
    }

    async fn revoke_generation(
        &self,
        reservation: &ShardEgressReservation,
    ) -> Result<(), SandboxError> {
        let fence = reservation
            .egress_fence()
            .ok_or_else(|| SandboxError::Backend("missing exact egress fence".into()))?
            .clone();
        let generation = reservation.generation().clone();
        {
            let mut routes = self.routes.lock().await;
            match routes.get_mut(&generation) {
                Some(route) if route.reservation == *reservation => {
                    route.state = LocalRouteState::Terminal;
                }
                Some(_) => return Err(SandboxError::Backend("egress generation conflict".into())),
                None => {
                    routes.insert(
                        generation.clone(),
                        LocalRoute {
                            reservation: reservation.clone(),
                            state: LocalRouteState::Terminal,
                            renewal_operation: Arc::new(Mutex::new(())),
                        },
                    );
                }
            }
        }
        let control = Arc::clone(&self.control);
        let routes = Arc::clone(&self.routes);
        let daemon_epoch = self.daemon_epoch;
        let expected_reservation = reservation.clone();
        let revoke_permit = Arc::clone(&self.revoke_slots)
            .try_acquire_owned()
            .map_err(|_| {
                SandboxError::Backend(
                    "egress revoke admission is full; terminal generation requires explicit retry"
                        .into(),
                )
            })?;
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let _revoke_permit = revoke_permit;
            let result = control
                .revoke(daemon_epoch, &fence)
                .await
                .and_then(|status| {
                    if status.as_ref().is_none_or(|receipt| {
                        receipt.daemon_epoch == daemon_epoch
                            && receipt.egress_fence == fence
                            && receipt.state.is_terminal()
                    }) {
                        Ok(())
                    } else {
                        Err(EgressControlError::Protocol(
                            "revoke did not reach an exact terminal receipt".into(),
                        ))
                    }
                });
            if result.is_ok()
                && let Some(route) = routes.lock().await.get_mut(&generation)
                && route.reservation == expected_reservation
            {
                route.state = LocalRouteState::Terminal;
            }
            let _ = sender.send(result);
        });
        receiver
            .await
            .map_err(|_| SandboxError::Backend("egress revoke task stopped".into()))?
            .map_err(|error| SandboxError::Backend(error.to_string()))
    }
}

#[async_trait]
impl EgressRouteBackend for EgressRouteAdapter {
    async fn prepare(&self, reservation: &ShardEgressReservation) -> Result<(), SandboxError> {
        let tenant_id = reservation
            .tenant_id()
            .ok_or_else(|| SandboxError::Backend("missing egress tenant binding".into()))?
            .clone();
        let dedicated = reservation
            .dedicated_egress()
            .ok_or_else(|| SandboxError::Backend("missing dedicated egress binding".into()))?
            .clone();
        let generation = reservation.generation().clone();
        {
            let mut routes = self.routes.lock().await;
            match routes.get(&generation) {
                Some(route) if route.reservation != *reservation => {
                    return Err(SandboxError::Backend("egress generation conflict".into()));
                }
                Some(route) if matches!(route.state, LocalRouteState::Terminal) => {
                    return Err(SandboxError::Backend(
                        "egress generation is terminal".into(),
                    ));
                }
                Some(route)
                    if matches!(
                        route.state,
                        LocalRouteState::Prepared(_)
                            | LocalRouteState::Installing(_)
                            | LocalRouteState::Active(_)
                    ) =>
                {
                    return Ok(());
                }
                Some(_) => {}
                None => {
                    routes.insert(
                        generation.clone(),
                        LocalRoute {
                            reservation: reservation.clone(),
                            state: LocalRouteState::Preparing,
                            renewal_operation: Arc::new(Mutex::new(())),
                        },
                    );
                }
            }
        }
        let prepared = self
            .control
            .prepare(PrepareRouteRequest {
                daemon_epoch: self.daemon_epoch,
                tenant_id,
                egress_fence: dedicated.egress_fence().clone(),
                binding_digest: *dedicated.policy_binding().snapshot_digest(),
                profile: dedicated.policy_binding().profile().to_owned(),
                lease_ttl: dedicated.initial_lease_ttl(),
            })
            .await
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
        self.validate_prepared(reservation, &prepared)?;
        let mut routes = self.routes.lock().await;
        let route = routes
            .get_mut(&generation)
            .ok_or_else(|| SandboxError::Backend("egress route state disappeared".into()))?;
        if route.reservation != *reservation || matches!(route.state, LocalRouteState::Terminal) {
            drop(routes);
            let _ = self.revoke_generation(reservation).await;
            return Err(SandboxError::Backend(
                "egress generation was cancelled while prepare completed".into(),
            ));
        }
        route.state = LocalRouteState::Prepared(prepared);
        Ok(())
    }

    async fn attach(
        &self,
        reservation: &ShardEgressReservation,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<ShardIngressReceipt, SandboxError> {
        enum AttachPlan {
            Install(PendingInstall, ListenerCapability),
            Reconcile(PendingInstall),
        }

        let generation = reservation.generation().clone();
        let plan = {
            let mut routes = self.routes.lock().await;
            let route = routes
                .get_mut(&generation)
                .ok_or_else(|| SandboxError::Backend("egress route was not prepared".into()))?;
            if route.reservation != *reservation {
                return Err(SandboxError::Backend("egress generation conflict".into()));
            }
            match &route.state {
                LocalRouteState::Prepared(prepared) => {
                    let listener = self.listener_factory.create(network_namespace)?;
                    if listener.namespace != network_namespace.identity()
                        || !listener.address.ip().is_loopback()
                        || listener.address.port() == 0
                    {
                        return Err(SandboxError::Backend(
                            "dedicated listener did not match the pinned namespace".into(),
                        ));
                    }
                    let request = InstallRequest::new(
                        reservation.generation().clone(),
                        prepared.daemon_epoch,
                        prepared.egress_fence.clone(),
                        prepared.binding_digest,
                        prepared.prepare_revision,
                    )
                    .map_err(|error| SandboxError::Backend(error.to_string()))?;
                    let pending = PendingInstall {
                        prepared: prepared.clone(),
                        request,
                        address: listener.address,
                        namespace: listener.namespace,
                        receipt: ShardIngressReceipt::new(),
                    };
                    route.state = LocalRouteState::Installing(pending.clone());
                    AttachPlan::Install(pending, listener)
                }
                LocalRouteState::Installing(pending) => AttachPlan::Reconcile(pending.clone()),
                LocalRouteState::Active(active)
                    if active.pending.namespace == network_namespace.identity() =>
                {
                    return Ok(active.pending.receipt.clone());
                }
                LocalRouteState::Active(_) => {
                    return Err(SandboxError::Backend("egress namespace changed".into()));
                }
                LocalRouteState::Preparing => {
                    return Err(SandboxError::Backend(
                        "egress prepare is still in progress".into(),
                    ));
                }
                LocalRouteState::Terminal => {
                    return Err(SandboxError::Backend(
                        "egress generation is terminal".into(),
                    ));
                }
            }
        };
        let pending = match plan {
            AttachPlan::Reconcile(pending) => pending,
            AttachPlan::Install(pending, listener) => {
                let install_permit = Arc::clone(&self.install_slots)
                    .try_acquire_owned()
                    .map_err(|_| SandboxError::Backend("egress install admission is full".into()));
                let install_permit = match install_permit {
                    Ok(permit) => permit,
                    Err(error) => {
                        let mut routes = self.routes.lock().await;
                        if let Some(route) = routes.get_mut(&generation)
                            && route.reservation == *reservation
                            && matches!(
                                &route.state,
                                LocalRouteState::Installing(current)
                                    if current.request.transfer_id()
                                        == pending.request.transfer_id()
                            )
                        {
                            route.state = LocalRouteState::Prepared(pending.prepared.clone());
                        }
                        return Err(error);
                    }
                };
                let adapter = self.clone();
                let reservation = reservation.clone();
                let pending_for_task = pending.clone();
                let (sender, receiver) = oneshot::channel();
                tokio::spawn(async move {
                    let _install_permit = install_permit;
                    let owner_result = AssertUnwindSafe(async {
                        let installed = adapter
                            .control
                            .install(pending_for_task.request.clone(), listener.descriptor)
                            .await;
                        let active = match installed {
                            Ok(active) => adapter
                                .validate_active(&pending_for_task, &active)
                                .map(|()| active),
                            Err(_) => adapter.reconcile_active(&pending_for_task).await,
                        };
                        match active {
                            Ok(active) => {
                                let mut routes = adapter.routes.lock().await;
                                let route = routes.get_mut(&generation).ok_or_else(|| {
                                    SandboxError::Backend("egress route state disappeared".into())
                                });
                                match route {
                                    Ok(route)
                                        if route.reservation == reservation
                                            && matches!(
                                                &route.state,
                                                LocalRouteState::Installing(current)
                                                    if current.request.transfer_id()
                                                        == pending_for_task.request.transfer_id()
                                            ) =>
                                    {
                                        route.state = LocalRouteState::Active(ActiveRoute {
                                            pending: pending_for_task.clone(),
                                            active,
                                            next_renewal_sequence: 1,
                                        });
                                        Ok(pending_for_task.receipt.clone())
                                    }
                                    Ok(_) => Err(SandboxError::Backend(
                                        "egress generation changed during install".into(),
                                    )),
                                    Err(error) => Err(error),
                                }
                            }
                            Err(error) => {
                                let revoke = adapter.revoke_generation(&reservation).await;
                                Err(revoke.err().unwrap_or(error))
                            }
                        }
                    })
                    .catch_unwind()
                    .await;
                    let result = match owner_result {
                        Ok(result) => result,
                        Err(_) => {
                            let error = SandboxError::Backend(
                                "egress install owner panicked; generation terminalized".into(),
                            );
                            let revoke = adapter.revoke_generation(&reservation).await;
                            Err(revoke.err().unwrap_or(error))
                        }
                    };
                    let _ = sender.send(result);
                });
                return receiver.await.map_err(|_| {
                    SandboxError::Backend("egress install owner task stopped".into())
                })?;
            }
        };
        let active = self.reconcile_active(&pending).await?;
        let mut routes = self.routes.lock().await;
        let route = routes
            .get_mut(&generation)
            .ok_or_else(|| SandboxError::Backend("egress route state disappeared".into()))?;
        if matches!(route.state, LocalRouteState::Terminal) {
            return Err(SandboxError::Backend(
                "egress generation is terminal".into(),
            ));
        }
        route.state = LocalRouteState::Active(ActiveRoute {
            pending: pending.clone(),
            active,
            next_renewal_sequence: 1,
        });
        Ok(pending.receipt)
    }

    async fn cancel_reservation(
        &self,
        reservation: &ShardEgressReservation,
    ) -> Result<(), SandboxError> {
        self.revoke_generation(reservation).await
    }

    async fn release_reservation(
        &self,
        reservation: &ShardEgressReservation,
    ) -> Result<(), SandboxError> {
        self.revoke_generation(reservation).await
    }

    async fn renew(
        &self,
        lease: &ShardIngressLease,
        lease_ttl: Duration,
    ) -> Result<(), SandboxError> {
        let renewal_operation = {
            let routes = self.routes.lock().await;
            let route = routes
                .get(lease.reservation().generation())
                .ok_or_else(|| SandboxError::Backend("egress lease is unknown".into()))?;
            if route.reservation != *lease.reservation() {
                return Err(SandboxError::Backend(
                    "egress lease generation conflict".into(),
                ));
            }
            Arc::clone(&route.renewal_operation)
        };
        let _renewal_guard = renewal_operation.lock().await;
        let (request, next_renewal_sequence, installed) = {
            let routes = self.routes.lock().await;
            let route = routes
                .get(lease.reservation().generation())
                .ok_or_else(|| SandboxError::Backend("egress lease is unknown".into()))?;
            if route.reservation != *lease.reservation() {
                return Err(SandboxError::Backend(
                    "egress lease generation conflict".into(),
                ));
            }
            let LocalRouteState::Active(active) = &route.state else {
                return Err(SandboxError::Backend("egress lease is not active".into()));
            };
            if active.pending.receipt != *lease.receipt()
                || active.pending.namespace != lease.namespace_identity()
            {
                return Err(SandboxError::Backend(
                    "egress lease receipt mismatch".into(),
                ));
            }
            let next_renewal_sequence = active
                .next_renewal_sequence
                .checked_add(1)
                .ok_or_else(|| SandboxError::Backend("egress renewal sequence exhausted".into()))?;
            let request = RenewRouteLeaseRequest::new(
                active.next_renewal_sequence,
                self.daemon_epoch,
                active.pending.request.egress_fence().clone(),
                active.active.attachment_id(),
                active.active.activation_revision(),
                lease_ttl,
            )
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
            (request, next_renewal_sequence, active.clone())
        };
        let renewed = self
            .control
            .renew(request.clone())
            .await
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
        if renewed.renewal_sequence() != request.renewal_sequence
            || renewed.daemon_epoch() != self.daemon_epoch
            || renewed.egress_fence() != request.egress_fence()
            || renewed.attachment_id() != installed.active.attachment_id()
            || renewed.activation_revision() != installed.active.activation_revision()
            || renewed.expires_at_millis() < installed.active.expires_at_millis()
        {
            return Err(SandboxError::Backend(
                "renewed egress receipt did not match the active route".into(),
            ));
        }
        let renewed_active = ActiveInstallResponse::new(
            installed.active.transfer_id().clone(),
            installed.active.daemon_epoch(),
            installed.active.egress_fence().clone(),
            installed.active.attachment_id(),
            installed.active.proxy_address(),
            renewed.expires_at_millis(),
            installed.active.activation_revision(),
        )
        .map_err(|error| SandboxError::Backend(error.to_string()))?;
        let mut routes = self.routes.lock().await;
        let route = routes
            .get_mut(lease.reservation().generation())
            .ok_or_else(|| SandboxError::Backend("egress lease is unknown".into()))?;
        if route.reservation != *lease.reservation() {
            return Err(SandboxError::Backend(
                "egress lease generation conflict".into(),
            ));
        }
        let LocalRouteState::Active(active) = &mut route.state else {
            return Err(SandboxError::Backend(
                "egress lease was revoked during renewal".into(),
            ));
        };
        if active.pending.receipt != *lease.receipt()
            || active.pending.namespace != lease.namespace_identity()
            || active.active != installed.active
            || active.next_renewal_sequence != request.renewal_sequence
        {
            return Err(SandboxError::Backend(
                "egress lease changed during renewal".into(),
            ));
        }
        active.active = renewed_active;
        active.next_renewal_sequence = next_renewal_sequence;
        Ok(())
    }

    async fn revoke(&self, lease: &ShardIngressLease) -> Result<(), SandboxError> {
        {
            let routes = self.routes.lock().await;
            let route = routes
                .get(lease.reservation().generation())
                .ok_or_else(|| SandboxError::Backend("egress lease is unknown".into()))?;
            if route.reservation != *lease.reservation() {
                return Err(SandboxError::Backend(
                    "egress lease generation conflict".into(),
                ));
            }
            if let LocalRouteState::Active(active) = &route.state
                && (active.pending.receipt != *lease.receipt()
                    || active.pending.namespace != lease.namespace_identity())
            {
                return Err(SandboxError::Backend(
                    "egress lease receipt mismatch".into(),
                ));
            }
        }
        self.revoke_generation(lease.reservation()).await
    }

    async fn release(&self, lease: &ShardIngressLease) -> Result<(), SandboxError> {
        self.revoke_generation(lease.reservation()).await
    }

    async fn is_active(&self, lease: &ShardIngressLease) -> Result<bool, SandboxError> {
        let active = {
            let routes = self.routes.lock().await;
            let Some(route) = routes.get(lease.reservation().generation()) else {
                return Ok(false);
            };
            if route.reservation != *lease.reservation() {
                return Err(SandboxError::Backend(
                    "egress lease generation conflict".into(),
                ));
            }
            match &route.state {
                LocalRouteState::Active(active)
                    if active.pending.receipt == *lease.receipt()
                        && active.pending.namespace == lease.namespace_identity() =>
                {
                    active.clone()
                }
                _ => return Ok(false),
            }
        };
        let status = self
            .control
            .status(self.daemon_epoch, active.pending.request.egress_fence())
            .await
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
        Ok(status.is_some_and(|status| {
            status.daemon_epoch == self.daemon_epoch
                && status.egress_fence == *active.pending.request.egress_fence()
                && status.state == RouteStatusState::Active
                && status.active.as_ref() == Some(&active.active)
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::{Json, Router};
    use browserd_core::{
        EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
        ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
    };
    use browserd_sandbox::{
        ChromiumBinaryDigest, DedicatedEgressSpec, EgressPolicyBinding, LaunchSpec,
        PinnedNetworkNamespace, ShardEgressReservation, ShardIngressLease,
    };
    use tokio::sync::Notify;

    use super::*;

    const DAEMON_EPOCH: u64 = 41;

    fn launch_spec() -> LaunchSpec {
        launch_spec_with_generation(3)
    }

    fn launch_spec_with_generation(generation: u64) -> LaunchSpec {
        let fence = EgressFence::new(
            ShardFence::new(
                OwnerFence::new(
                    WorkerId::new("sandboxd-egress-test-worker")
                        .expect("worker ID should be valid"),
                    WorkerEpoch::new(7).expect("worker epoch should be positive"),
                ),
                ShardId::new(),
                LaunchGeneration::new(generation).expect("launch generation should be positive"),
            ),
            RouteGeneration::new(5).expect("route generation should be positive"),
            SessionId::new(),
            SessionIncarnation::new(2).expect("session incarnation should be positive"),
        );
        let binding = EgressPolicyBinding::new("public-web", [9; 32])
            .expect("egress binding should be valid");
        LaunchSpec::production(
            TenantId::new(),
            DedicatedEgressSpec::new(fence, binding, Duration::from_secs(30))
                .expect("egress spec should be valid"),
            ChromiumBinaryDigest::new([0x3c; 32]),
        )
    }

    fn namespace() -> PinnedNetworkNamespace {
        let descriptor: OwnedFd = File::open("/proc/self/ns/net")
            .expect("current network namespace should open")
            .into();
        PinnedNetworkNamespace::from_owned_fd(descriptor)
            .expect("current network namespace should be pinnable")
    }

    #[derive(Clone)]
    struct RenewalHttpFixture {
        fence: EgressFence,
        received: Arc<StdMutex<Option<(String, serde_json::Value)>>>,
    }

    async fn capture_renewal_request(
        State(fixture): State<RenewalHttpFixture>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let authorization = headers
            .get(reqwest::header::AUTHORIZATION)
            .expect("renewal should include authorization")
            .to_str()
            .expect("authorization should be visible ASCII")
            .to_owned();
        *fixture.received.lock().expect("capture lock should work") = Some((authorization, body));
        Json(serde_json::json!({
            "renewal_sequence": 1,
            "daemon_epoch": DAEMON_EPOCH,
            "egress_fence": fixture.fence,
            "attachment_id": 17,
            "activation_revision": 19,
            "expires_at_millis": 234_567,
        }))
    }

    #[tokio::test]
    async fn http_control_renews_with_worker_auth_and_validates_the_exact_receipt() {
        let route_fence = launch_spec().dedicated_egress().egress_fence().clone();
        let received = Arc::new(StdMutex::new(None));
        let fixture = RenewalHttpFixture {
            fence: route_fence.clone(),
            received: Arc::clone(&received),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("HTTP fixture should bind");
        let address = listener
            .local_addr()
            .expect("fixture address should resolve");
        let app = Router::new()
            .route("/v1/routes/renew", post(capture_renewal_request))
            .with_state(fixture);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let config = EgressClientConfig::new(
            Url::parse(&format!("http://{address}/")).expect("fixture URL should parse"),
            PathBuf::from("/run/browserd/egress-install-test.sock"),
            DAEMON_EPOCH,
            0,
            "w".repeat(32),
            "s".repeat(32),
            Duration::from_secs(2),
            16 * 1024,
        )
        .expect("HTTP control configuration should validate");
        let control = HttpEgressControl::new(config).expect("HTTP control should initialize");
        let request = RenewRouteLeaseRequest::new(
            1,
            DAEMON_EPOCH,
            route_fence.clone(),
            17,
            19,
            Duration::from_secs(10),
        )
        .expect("renewal request should validate");

        let renewed = control
            .renew(request)
            .await
            .expect("renewal response should validate");
        assert_eq!(renewed.renewal_sequence(), 1);
        assert_eq!(renewed.egress_fence(), &route_fence);
        assert_eq!(renewed.expires_at_millis(), 234_567);
        let (authorization, body) = received
            .lock()
            .expect("capture lock should work")
            .clone()
            .expect("fixture should capture one renewal");
        assert_eq!(authorization, format!("Bearer {}", "w".repeat(32)));
        assert_eq!(body["renewal_sequence"], 1);
        assert_eq!(body["lease_ttl_millis"], 10_000);

        server.abort();
        let _ = server.await;
    }

    struct FakeListenerFactory {
        address: std::net::SocketAddr,
        creations: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
        delay: Duration,
    }

    impl EgressListenerFactory for FakeListenerFactory {
        fn create(
            &self,
            namespace: &PinnedNetworkNamespace,
        ) -> Result<ListenerCapability, SandboxError> {
            self.creations.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(SandboxError::Backend(
                    "injected listener creation failure".into(),
                ));
            }
            std::thread::sleep(self.delay);
            let listener = std::net::TcpListener::bind("127.0.0.1:0")
                .map_err(|error| SandboxError::Backend(error.to_string()))?;
            Ok(ListenerCapability {
                descriptor: listener.into(),
                address: self.address,
                namespace: namespace.identity(),
            })
        }
    }

    #[derive(Clone)]
    struct FakeControl {
        address: std::net::SocketAddr,
        prepare_requests: Arc<StdMutex<Vec<PrepareRouteRequest>>>,
        install_requests: Arc<StdMutex<Vec<InstallRequest>>>,
        renew_requests: Arc<StdMutex<Vec<RenewRouteLeaseRequest>>>,
        renew_attempts: Arc<AtomicUsize>,
        renew_entered: Arc<Notify>,
        renew_release: Arc<Notify>,
        block_first_renew: bool,
        active: Arc<StdMutex<Option<ActiveInstallResponse>>>,
        install_fails_after_commit: bool,
        install_panics: bool,
        wrong_address: bool,
        install_entered: Arc<Notify>,
        install_release: Arc<Notify>,
        block_install: bool,
        revoke_entered: Arc<Notify>,
        revoke_release: Arc<Notify>,
        block_revoke: bool,
        listener_creations: Arc<AtomicUsize>,
        listener_fails: Arc<AtomicBool>,
        listener_delay: Duration,
    }

    impl FakeControl {
        fn new(address: std::net::SocketAddr) -> Self {
            Self {
                address,
                prepare_requests: Arc::new(StdMutex::new(Vec::new())),
                install_requests: Arc::new(StdMutex::new(Vec::new())),
                renew_requests: Arc::new(StdMutex::new(Vec::new())),
                renew_attempts: Arc::new(AtomicUsize::new(0)),
                renew_entered: Arc::new(Notify::new()),
                renew_release: Arc::new(Notify::new()),
                block_first_renew: false,
                active: Arc::new(StdMutex::new(None)),
                install_fails_after_commit: false,
                install_panics: false,
                wrong_address: false,
                install_entered: Arc::new(Notify::new()),
                install_release: Arc::new(Notify::new()),
                block_install: false,
                revoke_entered: Arc::new(Notify::new()),
                revoke_release: Arc::new(Notify::new()),
                block_revoke: false,
                listener_creations: Arc::new(AtomicUsize::new(0)),
                listener_fails: Arc::new(AtomicBool::new(false)),
                listener_delay: Duration::ZERO,
            }
        }

        fn active_for(&self, request: &InstallRequest) -> ActiveInstallResponse {
            ActiveInstallResponse::new(
                request.transfer_id().clone(),
                request.daemon_epoch(),
                request.egress_fence().clone(),
                17,
                if self.wrong_address {
                    "127.0.0.1:6553".parse().expect("address should parse")
                } else {
                    self.address
                },
                123_456,
                19,
            )
            .expect("active fixture should validate")
        }
    }

    #[async_trait]
    impl EgressControlPlane for FakeControl {
        async fn current_daemon_epoch(&self) -> Result<u64, EgressControlError> {
            Ok(DAEMON_EPOCH)
        }

        async fn prepare(
            &self,
            request: PrepareRouteRequest,
        ) -> Result<PreparedRouteReceipt, EgressControlError> {
            let receipt = PreparedRouteReceipt {
                daemon_epoch: request.daemon_epoch,
                egress_fence: request.egress_fence.clone(),
                binding_digest: request.binding_digest,
                prepare_revision: 11,
            };
            self.prepare_requests
                .lock()
                .expect("prepare request lock should work")
                .push(request);
            Ok(receipt)
        }

        async fn install(
            &self,
            request: InstallRequest,
            listener: OwnedFd,
        ) -> Result<ActiveInstallResponse, EgressControlError> {
            self.install_entered.notify_one();
            if self.block_install {
                self.install_release.notified().await;
            }
            assert!(!self.install_panics, "injected install owner panic");
            drop(listener);
            let active = self.active_for(&request);
            self.install_requests
                .lock()
                .expect("install request lock should work")
                .push(request);
            *self.active.lock().expect("active lock should work") = Some(active.clone());
            if self.install_fails_after_commit {
                Err(EgressControlError::InstallUncertain)
            } else {
                Ok(active)
            }
        }

        async fn renew(
            &self,
            request: RenewRouteLeaseRequest,
        ) -> Result<RenewedRouteLeaseReceipt, EgressControlError> {
            let attempt = self.renew_attempts.fetch_add(1, Ordering::SeqCst) + 1;
            self.renew_entered.notify_one();
            if self.block_first_renew && attempt == 1 {
                self.renew_release.notified().await;
            }
            let active = self
                .active
                .lock()
                .expect("active lock should work")
                .clone()
                .ok_or_else(|| EgressControlError::Protocol("route is not active".into()))?;
            if active.daemon_epoch() != request.daemon_epoch
                || active.egress_fence() != &request.egress_fence
                || active.attachment_id() != request.attachment_id
                || active.activation_revision() != request.activation_revision
            {
                return Err(EgressControlError::Protocol(
                    "renewal request does not own the active route".into(),
                ));
            }
            let extension = u64::try_from(request.lease_ttl.as_millis())
                .map_err(|_| EgressControlError::Protocol("renewal TTL overflow".into()))?;
            let expires_at_millis = active
                .expires_at_millis()
                .checked_add(extension)
                .ok_or_else(|| EgressControlError::Protocol("renewal expiry overflow".into()))?;
            let renewed_active = ActiveInstallResponse::new(
                active.transfer_id().clone(),
                active.daemon_epoch(),
                active.egress_fence().clone(),
                active.attachment_id(),
                active.proxy_address(),
                expires_at_millis,
                active.activation_revision(),
            )
            .map_err(|error| EgressControlError::Protocol(error.to_string()))?;
            *self.active.lock().expect("active lock should work") = Some(renewed_active);
            self.renew_requests
                .lock()
                .expect("renew request lock should work")
                .push(request.clone());
            Ok(RenewedRouteLeaseReceipt {
                renewal_sequence: request.renewal_sequence,
                daemon_epoch: request.daemon_epoch,
                egress_fence: request.egress_fence,
                attachment_id: request.attachment_id,
                activation_revision: request.activation_revision,
                expires_at_millis,
            })
        }

        async fn status(
            &self,
            daemon_epoch: u64,
            fence: &EgressFence,
        ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
            let active = self.active.lock().expect("active lock should work").clone();
            Ok(Some(RouteStatusReceipt {
                daemon_epoch,
                egress_fence: fence.clone(),
                state: if active.is_some() {
                    RouteStatusState::Active
                } else {
                    RouteStatusState::Prepared
                },
                active,
            }))
        }

        async fn revoke(
            &self,
            daemon_epoch: u64,
            fence: &EgressFence,
        ) -> Result<Option<RouteStatusReceipt>, EgressControlError> {
            self.revoke_entered.notify_one();
            if self.block_revoke {
                self.revoke_release.notified().await;
            }
            *self.active.lock().expect("active lock should work") = None;
            Ok(Some(RouteStatusReceipt {
                daemon_epoch,
                egress_fence: fence.clone(),
                state: RouteStatusState::Released,
                active: None,
            }))
        }
    }

    fn adapter(control: FakeControl) -> EgressRouteAdapter {
        EgressRouteAdapter::with_components(
            Arc::new(control.clone()),
            Arc::new(FakeListenerFactory {
                address: control.address,
                creations: Arc::clone(&control.listener_creations),
                fail: Arc::clone(&control.listener_fails),
                delay: control.listener_delay,
            }),
            DAEMON_EPOCH,
            Duration::from_millis(100),
        )
    }

    #[tokio::test]
    async fn exact_fence_and_active_receipt_are_required_before_route_activation() {
        let address = "127.0.0.1:43117".parse().expect("address should parse");
        let control = FakeControl::new(address);
        let adapter = adapter(control.clone());
        let spec = launch_spec();
        let reservation = ShardEgressReservation::from_launch_spec(&spec);
        adapter
            .prepare(&reservation)
            .await
            .expect("exact route should prepare");
        let namespace = namespace();
        let receipt = adapter
            .attach(&reservation, &namespace)
            .await
            .expect("Active receipt should commit the exact listener");
        let lease =
            ShardIngressLease::from_attachment(reservation.clone(), namespace.identity(), receipt);
        assert!(adapter.is_active(&lease).await.expect("status should work"));

        let prepares = control
            .prepare_requests
            .lock()
            .expect("prepare lock should work");
        assert_eq!(prepares.len(), 1);
        assert_eq!(
            prepares[0].egress_fence,
            *spec.dedicated_egress().egress_fence()
        );
        assert_eq!(prepares[0].tenant_id, *spec.tenant_id());
        assert_eq!(
            prepares[0].binding_digest,
            *spec.dedicated_egress().policy_binding().snapshot_digest()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_active_lease_renewals_are_serialized_with_monotonic_sequences() {
        let address = "127.0.0.1:43126".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.block_first_renew = true;
        let adapter = Arc::new(adapter(control.clone()));
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("route should prepare");
        let namespace = namespace();
        let receipt = adapter
            .attach(&reservation, &namespace)
            .await
            .expect("route should attach");
        let lease = ShardIngressLease::from_attachment(reservation, namespace.identity(), receipt);

        let first = tokio::spawn({
            let adapter = Arc::clone(&adapter);
            let lease = lease.clone();
            async move { adapter.renew(&lease, Duration::from_secs(30)).await }
        });
        control.renew_entered.notified().await;
        let second = tokio::spawn({
            let adapter = Arc::clone(&adapter);
            let lease = lease.clone();
            async move { adapter.renew(&lease, Duration::from_secs(30)).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(control.renew_attempts.load(Ordering::SeqCst), 1);

        control.renew_release.notify_one();
        first
            .await
            .expect("first renewal task should join")
            .expect("first renewal should succeed");
        second
            .await
            .expect("second renewal task should join")
            .expect("second renewal should succeed");
        let sequences: Vec<_> = control
            .renew_requests
            .lock()
            .expect("renew requests should be readable")
            .iter()
            .map(RenewRouteLeaseRequest::renewal_sequence)
            .collect();
        assert_eq!(sequences, [1, 2]);
        assert!(adapter.is_active(&lease).await.expect("status should work"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn revoke_wins_a_blocked_renewal_without_route_resurrection() {
        let address = "127.0.0.1:43127".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.block_first_renew = true;
        let adapter = Arc::new(adapter(control.clone()));
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("route should prepare");
        let namespace = namespace();
        let receipt = adapter
            .attach(&reservation, &namespace)
            .await
            .expect("route should attach");
        let lease = ShardIngressLease::from_attachment(reservation, namespace.identity(), receipt);
        let renew = tokio::spawn({
            let adapter = Arc::clone(&adapter);
            let lease = lease.clone();
            async move { adapter.renew(&lease, Duration::from_secs(30)).await }
        });
        control.renew_entered.notified().await;

        adapter
            .revoke(&lease)
            .await
            .expect("exact revoke should commit while renewal is blocked");
        control.renew_release.notify_one();
        assert!(renew.await.expect("renewal task should join").is_err());
        assert!(!adapter.is_active(&lease).await.expect("status should work"));
        assert!(
            control
                .active
                .lock()
                .expect("active state should be readable")
                .is_none()
        );
    }

    #[tokio::test]
    async fn committed_but_unconfirmed_install_reconciles_exact_active_status() {
        let address = "127.0.0.1:43118".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.install_fails_after_commit = true;
        let adapter = adapter(control);
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("prepare should work");
        assert!(adapter.attach(&reservation, &namespace()).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_exact_attach_has_one_listener_owner_and_one_install_receipt() {
        let address = "127.0.0.1:43121".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.listener_delay = Duration::from_millis(30);
        let adapter = Arc::new(adapter(control.clone()));
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("prepare should work");

        let first = {
            let adapter = Arc::clone(&adapter);
            let reservation = reservation.clone();
            tokio::spawn(async move { adapter.attach(&reservation, &namespace()).await })
        };
        let second = {
            let adapter = Arc::clone(&adapter);
            let reservation = reservation.clone();
            tokio::spawn(async move { adapter.attach(&reservation, &namespace()).await })
        };
        let first_receipt = first
            .await
            .expect("first attach task should not panic")
            .expect("first attach should work");
        let second_receipt = second
            .await
            .expect("second attach task should not panic")
            .expect("second attach should work");

        assert_eq!(first_receipt, second_receipt);
        assert_eq!(control.listener_creations.load(Ordering::SeqCst), 1);
        assert_eq!(
            control
                .install_requests
                .lock()
                .expect("install request lock should work")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn mismatched_active_listener_address_fails_closed() {
        let address = "127.0.0.1:43119".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.wrong_address = true;
        let adapter = adapter(control.clone());
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("prepare should work");
        assert!(adapter.attach(&reservation, &namespace()).await.is_err());
        control.revoke_entered.notified().await;
        assert!(
            control
                .active
                .lock()
                .expect("active lock should work")
                .is_none()
        );
        assert!(adapter.prepare(&reservation).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_install_owner_does_not_strand_installing_generation() {
        let address = "127.0.0.1:43122".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.block_install = true;
        let adapter = Arc::new(adapter(control.clone()));
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("prepare should work");

        let owner = tokio::spawn({
            let adapter = Arc::clone(&adapter);
            let reservation = reservation.clone();
            async move { adapter.attach(&reservation, &namespace()).await }
        });
        control.install_entered.notified().await;
        owner.abort();
        owner.await.expect_err("owner should be cancelled");
        control.install_release.notify_waiters();

        let receipt = tokio::time::timeout(
            Duration::from_secs(1),
            adapter.attach(&reservation, &namespace()),
        )
        .await
        .expect("detached owner should finish")
        .expect("generation should become active");
        assert_eq!(control.listener_creations.load(Ordering::SeqCst), 1);
        assert_eq!(
            control.install_requests.lock().expect("install lock").len(),
            1
        );
        let _ = receipt;
    }

    #[tokio::test]
    async fn panicking_install_owner_terminalizes_and_revokes_exact_generation() {
        let address = "127.0.0.1:43125".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.install_panics = true;
        let adapter = adapter(control.clone());
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("prepare should work");

        assert!(adapter.attach(&reservation, &namespace()).await.is_err());
        tokio::time::timeout(
            Duration::from_millis(100),
            control.revoke_entered.notified(),
        )
        .await
        .expect("a panicking install owner must start exact terminal cleanup");
        assert!(
            adapter.prepare(&reservation).await.is_err(),
            "the uncertain generation must remain a terminal tombstone"
        );
    }

    #[tokio::test]
    async fn listener_failure_before_install_keeps_generation_retryable() {
        let address = "127.0.0.1:43124".parse().expect("address should parse");
        let control = FakeControl::new(address);
        control.listener_fails.store(true, Ordering::SeqCst);
        let adapter = adapter(control.clone());
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("prepare should work");

        assert!(adapter.attach(&reservation, &namespace()).await.is_err());
        control.listener_fails.store(false, Ordering::SeqCst);
        assert!(adapter.attach(&reservation, &namespace()).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saturated_revoke_admission_keeps_terminal_tombstone_for_explicit_retry() {
        let address = "127.0.0.1:43123".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.block_revoke = true;
        let adapter = Arc::new(EgressRouteAdapter::with_components_and_revoke_limit(
            Arc::new(control.clone()),
            Arc::new(FakeListenerFactory {
                address,
                creations: Arc::clone(&control.listener_creations),
                fail: Arc::clone(&control.listener_fails),
                delay: Duration::ZERO,
            }),
            DAEMON_EPOCH,
            Duration::from_millis(100),
            1,
        ));
        let first = ShardEgressReservation::from_launch_spec(&launch_spec());
        let second_spec = launch_spec_with_generation(4);
        let second = ShardEgressReservation::from_launch_spec(&second_spec);
        adapter.prepare(&first).await.expect("first prepare");
        adapter.prepare(&second).await.expect("second prepare");

        let first_revoke = tokio::spawn({
            let adapter = Arc::clone(&adapter);
            let first = first.clone();
            async move { adapter.cancel_reservation(&first).await }
        });
        tokio::time::timeout(Duration::from_secs(1), control.revoke_entered.notified())
            .await
            .expect("first revoke should start");
        let saturated = adapter
            .cancel_reservation(&second)
            .await
            .expect_err("bounded revoke admission must reject overflow");
        assert!(saturated.to_string().contains("retry"));
        assert!(adapter.prepare(&second).await.is_err());

        control.revoke_release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), first_revoke)
            .await
            .expect("first revoke should finish")
            .expect("task should join")
            .expect("revoke");
        control.revoke_release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), adapter.cancel_reservation(&second))
            .await
            .expect("explicit retry should finish")
            .expect("explicit retry should be admitted");
    }

    #[tokio::test]
    async fn cancelled_revoke_future_leaves_a_permanent_generation_tombstone() {
        let address = "127.0.0.1:43120".parse().expect("address should parse");
        let mut control = FakeControl::new(address);
        control.block_revoke = true;
        let adapter = Arc::new(adapter(control.clone()));
        let reservation = ShardEgressReservation::from_launch_spec(&launch_spec());
        adapter
            .prepare(&reservation)
            .await
            .expect("prepare should work");

        let revoke = tokio::spawn({
            let adapter = Arc::clone(&adapter);
            let reservation = reservation.clone();
            async move { adapter.cancel_reservation(&reservation).await }
        });
        control.revoke_entered.notified().await;
        revoke.abort();
        assert!(
            revoke
                .await
                .expect_err("caller should cancel")
                .is_cancelled()
        );
        control.revoke_release.notify_waiters();
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert!(adapter.prepare(&reservation).await.is_err());
    }
}
