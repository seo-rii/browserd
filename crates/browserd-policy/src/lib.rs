#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;

use browserd_core::{IsolationProfile, PageId, PrincipalId, SessionId, TenantId};
use sha2::{Digest, Sha256};
use url::{Host, Url};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyHookResult {
    Allow,
    Deny,
    RequireExternalApproval,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalPolicy {
    pub plan: String,
    pub feature_profile: String,
    pub isolation: IsolationProfile,
    pub network_allowlist: Vec<String>,
    pub ttl_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicySnapshotDigest([u8; 32]);

impl PolicySnapshotDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    policy: NormalPolicy,
    digest: PolicySnapshotDigest,
}

impl PolicySnapshot {
    #[must_use]
    pub fn new(policy: NormalPolicy) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"browserd-policy-snapshot-v1\0");
        for value in [&policy.plan, &policy.feature_profile] {
            hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hasher.update([match policy.isolation {
            IsolationProfile::SharedContext => 0,
            IsolationProfile::TenantDedicatedShard => 1,
            IsolationProfile::DedicatedProcess => 2,
            IsolationProfile::DedicatedWorker => 3,
        }]);
        let mut allowlist = policy.network_allowlist.clone();
        allowlist.sort_unstable();
        allowlist.dedup();
        hasher.update(
            u64::try_from(allowlist.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for domain in allowlist {
            hasher.update(
                u64::try_from(domain.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            hasher.update(domain.as_bytes());
        }
        hasher.update(policy.ttl_seconds.to_be_bytes());
        Self {
            policy,
            digest: PolicySnapshotDigest(hasher.finalize().into()),
        }
    }

    #[must_use]
    pub const fn policy(&self) -> &NormalPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn digest(&self) -> PolicySnapshotDigest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Origin {
    serialized: String,
    host: String,
}

impl Origin {
    pub fn parse(value: &str) -> Result<Self, OriginParseError> {
        let parsed = Url::parse(value).map_err(|_| OriginParseError)?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(OriginParseError);
        }
        let host = parsed
            .host_str()
            .ok_or(OriginParseError)?
            .to_ascii_lowercase();
        Ok(Self {
            serialized: parsed.origin().ascii_serialization(),
            host,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.serialized)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginParseError;

impl fmt::Display for OriginParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("origin must be an absolute HTTP(S) origin")
    }
}

impl std::error::Error for OriginParseError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionArgumentsHash([u8; 32]);

impl ActionArgumentsHash {
    #[must_use]
    pub fn digest(canonical_arguments: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(canonical_arguments.as_ref()).into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialRefsHash([u8; 32]);

impl CredentialRefsHash {
    #[must_use]
    pub fn digest<'a>(credential_refs: impl IntoIterator<Item = &'a str>) -> Self {
        let mut refs = credential_refs.into_iter().collect::<Vec<_>>();
        refs.sort_unstable();
        refs.dedup();
        let mut hasher = Sha256::new();
        hasher.update(b"browserd-credential-refs-v1\0");
        for credential_ref in refs {
            hasher.update(
                u64::try_from(credential_ref.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            hasher.update(credential_ref.as_bytes());
        }
        Self(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionType {
    Click,
    Fill,
    Navigate,
    Evaluate,
    Upload,
    Download,
    Custom(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NodeReference(String);

impl NodeReference {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidNodeReference> {
        let value = value.into();
        if value.is_empty()
            || value.trim() != value
            || value.len() > 1_024
            || value.chars().any(char::is_control)
        {
            return Err(InvalidNodeReference);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidNodeReference;

impl fmt::Display for InvalidNodeReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("node reference must be a non-empty opaque token")
    }
}

impl std::error::Error for InvalidNodeReference {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposalHash([u8; 32]);

impl ProposalHash {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalActionProposal {
    tenant_id: TenantId,
    requester_principal_id: PrincipalId,
    session_id: SessionId,
    session_incarnation: u64,
    page_id: PageId,
    target_incarnation: u64,
    frame_document_epoch: u64,
    current_origin: Origin,
    url_revision: u64,
    action_type: ActionType,
    canonical_arguments_hash: ActionArgumentsHash,
    node_ref: Option<NodeReference>,
    credential_refs_hash: CredentialRefsHash,
    expires_at_unix_ms: u64,
}

impl CanonicalActionProposal {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        requester_principal_id: PrincipalId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
        target_incarnation: u64,
        frame_document_epoch: u64,
        current_origin: Origin,
        url_revision: u64,
        action_type: ActionType,
        canonical_arguments_hash: ActionArgumentsHash,
        node_ref: Option<NodeReference>,
        credential_refs_hash: CredentialRefsHash,
        expires_at_unix_ms: u64,
    ) -> Self {
        Self {
            tenant_id,
            requester_principal_id,
            session_id,
            session_incarnation,
            page_id,
            target_incarnation,
            frame_document_epoch,
            current_origin,
            url_revision,
            action_type,
            canonical_arguments_hash,
            node_ref,
            credential_refs_hash,
            expires_at_unix_ms,
        }
    }

    #[must_use]
    pub fn hash(&self) -> ProposalHash {
        let mut hasher = Sha256::new();
        hasher.update(b"browserd-canonical-action-proposal-v1\0");
        hasher.update(self.tenant_id.as_bytes());
        hasher.update(self.requester_principal_id.as_bytes());
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.session_incarnation.to_be_bytes());
        hasher.update(self.page_id.as_bytes());
        hasher.update(self.target_incarnation.to_be_bytes());
        hasher.update(self.frame_document_epoch.to_be_bytes());
        hasher.update(
            u64::try_from(self.current_origin.as_str().len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(self.current_origin.as_str().as_bytes());
        hasher.update(self.url_revision.to_be_bytes());
        match &self.action_type {
            ActionType::Click => hasher.update([0]),
            ActionType::Fill => hasher.update([1]),
            ActionType::Navigate => hasher.update([2]),
            ActionType::Evaluate => hasher.update([3]),
            ActionType::Upload => hasher.update([4]),
            ActionType::Download => hasher.update([5]),
            ActionType::Custom(name) => {
                hasher.update([6]);
                hasher.update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(name.as_bytes());
            }
        }
        hasher.update(self.canonical_arguments_hash.0);
        match &self.node_ref {
            Some(node_ref) => {
                hasher.update([1]);
                hasher.update(
                    u64::try_from(node_ref.as_str().len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                hasher.update(node_ref.as_str().as_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update(self.credential_refs_hash.0);
        hasher.update(self.expires_at_unix_ms.to_be_bytes());
        ProposalHash(hasher.finalize().into())
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn requester_principal_id(&self) -> &PrincipalId {
        &self.requester_principal_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn session_incarnation(&self) -> u64 {
        self.session_incarnation
    }

    #[must_use]
    pub const fn page_id(&self) -> &PageId {
        &self.page_id
    }

    #[must_use]
    pub const fn target_incarnation(&self) -> u64 {
        self.target_incarnation
    }

    #[must_use]
    pub const fn frame_document_epoch(&self) -> u64 {
        self.frame_document_epoch
    }

    #[must_use]
    pub const fn current_origin(&self) -> &Origin {
        &self.current_origin
    }

    #[must_use]
    pub const fn url_revision(&self) -> u64 {
        self.url_revision
    }

    #[must_use]
    pub const fn node_ref(&self) -> Option<&NodeReference> {
        self.node_ref.as_ref()
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub fn with_session_incarnation(mut self, value: u64) -> Self {
        self.session_incarnation = value;
        self
    }

    #[must_use]
    pub fn with_target_incarnation(mut self, value: u64) -> Self {
        self.target_incarnation = value;
        self
    }

    #[must_use]
    pub fn with_frame_document_epoch(mut self, value: u64) -> Self {
        self.frame_document_epoch = value;
        self
    }

    #[must_use]
    pub fn with_current_origin(mut self, value: Origin) -> Self {
        self.current_origin = value;
        self
    }

    #[must_use]
    pub fn with_url_revision(mut self, value: u64) -> Self {
        self.url_revision = value;
        self
    }

    #[must_use]
    pub fn with_action_type(mut self, value: ActionType) -> Self {
        self.action_type = value;
        self
    }

    #[must_use]
    pub fn with_arguments_hash(mut self, value: ActionArgumentsHash) -> Self {
        self.canonical_arguments_hash = value;
        self
    }

    #[must_use]
    pub fn with_node_ref(mut self, value: Option<NodeReference>) -> Self {
        self.node_ref = value;
        self
    }

    #[must_use]
    pub fn with_credential_refs_hash(mut self, value: CredentialRefsHash) -> Self {
        self.credential_refs_hash = value;
        self
    }

    #[must_use]
    pub fn with_expires_at_unix_ms(mut self, value: u64) -> Self {
        self.expires_at_unix_ms = value;
        self
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionContext {
    pub tenant_id: TenantId,
    pub requester_principal_id: PrincipalId,
    pub session_id: SessionId,
    pub session_incarnation: u64,
    pub page_id: PageId,
    pub target_incarnation: u64,
    pub frame_document_epoch: u64,
    pub current_origin: Origin,
    pub url_revision: u64,
    pub node_ref: Option<NodeReference>,
    pub node_valid: bool,
    pub placement_owned: bool,
    pub resolved_ips: Vec<IpAddr>,
    pub credential_refs: Vec<String>,
    pub feature: String,
    pub chromium_build: String,
    pub effective_isolation: IsolationProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmergencyDenyReason {
    TenantDisabled,
    SessionDisabled,
    DomainDenied,
    IpDenied,
    SecretRevoked,
    FeatureKillSwitch,
    ChromiumBuildKillSwitch,
    ForceDedicatedProcess,
}

#[derive(Default)]
struct EmergencyPolicyState {
    revision: u64,
    disabled_tenants: HashSet<TenantId>,
    disabled_sessions: HashSet<SessionId>,
    denied_domains: HashSet<String>,
    denied_ips: HashSet<IpAddr>,
    revoked_secrets: HashSet<String>,
    killed_features: HashSet<String>,
    killed_chromium_builds: HashSet<String>,
    force_dedicated_tenants: HashSet<TenantId>,
}

#[derive(Default)]
pub struct EmergencyPolicy {
    state: Mutex<EmergencyPolicyState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmergencyPolicyError {
    CoordinationUnavailable,
    RevisionExhausted,
    InvalidDomain,
}

impl fmt::Display for EmergencyPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoordinationUnavailable => formatter.write_str("emergency policy unavailable"),
            Self::RevisionExhausted => formatter.write_str("emergency policy revision exhausted"),
            Self::InvalidDomain => formatter.write_str("emergency denied domain is invalid"),
        }
    }
}

impl std::error::Error for EmergencyPolicyError {}

impl EmergencyPolicy {
    pub fn revision(&self) -> Result<u64, EmergencyPolicyError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?
            .revision)
    }

    pub fn disable_tenant(&self, tenant_id: TenantId) -> Result<u64, EmergencyPolicyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state.disabled_tenants.contains(&tenant_id) {
            return Ok(state.revision);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(EmergencyPolicyError::RevisionExhausted)?;
        state.disabled_tenants.insert(tenant_id);
        Ok(state.revision)
    }

    pub fn disable_session(&self, session_id: SessionId) -> Result<u64, EmergencyPolicyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state.disabled_sessions.contains(&session_id) {
            return Ok(state.revision);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(EmergencyPolicyError::RevisionExhausted)?;
        state.disabled_sessions.insert(session_id);
        Ok(state.revision)
    }

    pub fn deny_domain(&self, domain: impl Into<String>) -> Result<u64, EmergencyPolicyError> {
        let domain = domain.into();
        let domain = match Host::parse(domain.trim_end_matches('.'))
            .map_err(|_| EmergencyPolicyError::InvalidDomain)?
        {
            Host::Domain(domain) => domain,
            Host::Ipv4(_) | Host::Ipv6(_) => return Err(EmergencyPolicyError::InvalidDomain),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state.denied_domains.contains(&domain) {
            return Ok(state.revision);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(EmergencyPolicyError::RevisionExhausted)?;
        state.denied_domains.insert(domain);
        Ok(state.revision)
    }

    pub fn deny_ip(&self, ip: IpAddr) -> Result<u64, EmergencyPolicyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state.denied_ips.contains(&ip) {
            return Ok(state.revision);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(EmergencyPolicyError::RevisionExhausted)?;
        state.denied_ips.insert(ip);
        Ok(state.revision)
    }

    pub fn revoke_secret(
        &self,
        secret_ref: impl Into<String>,
    ) -> Result<u64, EmergencyPolicyError> {
        let secret_ref = secret_ref.into();
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state.revoked_secrets.contains(&secret_ref) {
            return Ok(state.revision);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(EmergencyPolicyError::RevisionExhausted)?;
        state.revoked_secrets.insert(secret_ref);
        Ok(state.revision)
    }

    pub fn deny_feature(&self, feature: impl Into<String>) -> Result<u64, EmergencyPolicyError> {
        let feature = feature.into();
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state.killed_features.contains(&feature) {
            return Ok(state.revision);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(EmergencyPolicyError::RevisionExhausted)?;
        state.killed_features.insert(feature);
        Ok(state.revision)
    }

    pub fn kill_chromium_build(
        &self,
        build: impl Into<String>,
    ) -> Result<u64, EmergencyPolicyError> {
        let build = build.into();
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state.killed_chromium_builds.contains(&build) {
            return Ok(state.revision);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(EmergencyPolicyError::RevisionExhausted)?;
        state.killed_chromium_builds.insert(build);
        Ok(state.revision)
    }

    pub fn force_dedicated_process(
        &self,
        tenant_id: TenantId,
    ) -> Result<u64, EmergencyPolicyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EmergencyPolicyError::CoordinationUnavailable)?;
        if state.force_dedicated_tenants.contains(&tenant_id) {
            return Ok(state.revision);
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or(EmergencyPolicyError::RevisionExhausted)?;
        state.force_dedicated_tenants.insert(tenant_id);
        Ok(state.revision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalState {
    Pending,
    Approved { by: PrincipalId },
    Denied { by: PrincipalId },
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionOutcome {
    Recorded(ApprovalState),
    Existing(ApprovalState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleApprovalReason {
    TokenConsumed,
    Expired,
    RequesterPrincipal,
    SessionIncarnation,
    PlacementOwnership,
    Page,
    TargetIncarnation,
    DocumentEpoch,
    Origin,
    UrlRevision,
    Node,
    CredentialRefs,
    ActionBinding,
    EmergencyDenied(EmergencyDenyReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalError {
    CoordinationUnavailable,
    FourEyesViolation,
    DecisionConflict { existing: ApprovalDecision },
    ApprovalExpired,
    ApprovalDenied,
    ApprovalPending,
    ApprovalStale(StaleApprovalReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalAuthorizationError<E> {
    Approval(ApprovalError),
    Clock(E),
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "approval error: {self:?}")
    }
}

impl std::error::Error for ApprovalError {}

struct ApprovalInner {
    state: ApprovalState,
    token_consumed: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApprovalTokenId(PageId);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalTokenBinding {
    proposal_hash: ProposalHash,
    tenant_id: TenantId,
    requester_principal_id: PrincipalId,
    session_id: SessionId,
    session_incarnation: u64,
    jti: ApprovalTokenId,
    expires_at_unix_ms: u64,
}

impl ApprovalTokenBinding {
    #[must_use]
    pub const fn proposal_hash(&self) -> ProposalHash {
        self.proposal_hash
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn requester_principal_id(&self) -> &PrincipalId {
        &self.requester_principal_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn session_incarnation(&self) -> u64 {
        self.session_incarnation
    }

    #[must_use]
    pub const fn jti(&self) -> &ApprovalTokenId {
        &self.jti
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

pub struct ApprovalRequest {
    proposal: CanonicalActionProposal,
    proposal_hash: ProposalHash,
    token_jti: ApprovalTokenId,
    require_four_eyes: bool,
    inner: Mutex<ApprovalInner>,
}

impl ApprovalRequest {
    #[must_use]
    pub fn new(proposal: CanonicalActionProposal, require_four_eyes: bool) -> Self {
        let proposal_hash = proposal.hash();
        Self {
            proposal,
            proposal_hash,
            token_jti: ApprovalTokenId(PageId::new()),
            require_four_eyes,
            inner: Mutex::new(ApprovalInner {
                state: ApprovalState::Pending,
                token_consumed: false,
            }),
        }
    }

    #[must_use]
    pub const fn proposal(&self) -> &CanonicalActionProposal {
        &self.proposal
    }

    #[must_use]
    pub const fn proposal_hash(&self) -> ProposalHash {
        self.proposal_hash
    }

    #[must_use]
    pub const fn token_jti(&self) -> &ApprovalTokenId {
        &self.token_jti
    }

    #[must_use]
    pub fn token_binding(&self) -> ApprovalTokenBinding {
        ApprovalTokenBinding {
            proposal_hash: self.proposal_hash,
            tenant_id: self.proposal.tenant_id.clone(),
            requester_principal_id: self.proposal.requester_principal_id.clone(),
            session_id: self.proposal.session_id.clone(),
            session_incarnation: self.proposal.session_incarnation,
            jti: self.token_jti.clone(),
            expires_at_unix_ms: self.proposal.expires_at_unix_ms,
        }
    }

    pub fn state(&self) -> Result<ApprovalState, ApprovalError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApprovalError::CoordinationUnavailable)?
            .state
            .clone())
    }

    pub fn decide(
        &self,
        approver: PrincipalId,
        decision: ApprovalDecision,
        now_unix_ms: u64,
    ) -> Result<DecisionOutcome, ApprovalError> {
        if self.require_four_eyes && approver == *self.proposal.requester_principal_id() {
            return Err(ApprovalError::FourEyesViolation);
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ApprovalError::CoordinationUnavailable)?;

        match &inner.state {
            ApprovalState::Approved { .. } => {
                return if decision == ApprovalDecision::Approve {
                    Ok(DecisionOutcome::Existing(inner.state.clone()))
                } else {
                    Err(ApprovalError::DecisionConflict {
                        existing: ApprovalDecision::Approve,
                    })
                };
            }
            ApprovalState::Denied { .. } => {
                return if decision == ApprovalDecision::Deny {
                    Ok(DecisionOutcome::Existing(inner.state.clone()))
                } else {
                    Err(ApprovalError::DecisionConflict {
                        existing: ApprovalDecision::Deny,
                    })
                };
            }
            ApprovalState::Expired => return Err(ApprovalError::ApprovalExpired),
            ApprovalState::Pending => {}
        }
        if now_unix_ms >= self.proposal.expires_at_unix_ms() {
            inner.state = ApprovalState::Expired;
            return Err(ApprovalError::ApprovalExpired);
        }
        inner.state = match decision {
            ApprovalDecision::Approve => ApprovalState::Approved { by: approver },
            ApprovalDecision::Deny => ApprovalState::Denied { by: approver },
        };
        Ok(DecisionOutcome::Recorded(inner.state.clone()))
    }

    /// Atomically revalidates and consumes this approval before invoking `dispatch`.
    ///
    /// Successful token consumption is the dispatch-admission linearization point. Policy changes
    /// that complete after that point do not retroactively cancel the admitted effect. Neither the
    /// emergency-policy lock nor the approval lock is held while `dispatch` runs.
    pub fn authorize_and_dispatch(
        &self,
        emergency: &EmergencyPolicy,
        context: &ExecutionContext,
        now_unix_ms: u64,
        dispatch: impl FnOnce(),
    ) -> Result<(), ApprovalError> {
        match self.authorize_and_dispatch_with_clock(
            emergency,
            context,
            || Ok::<_, std::convert::Infallible>(now_unix_ms),
            dispatch,
        ) {
            Ok(()) => Ok(()),
            Err(ApprovalAuthorizationError::Approval(error)) => Err(error),
            Err(ApprovalAuthorizationError::Clock(never)) => match never {},
        }
    }

    /// Atomically samples trusted time, revalidates, and consumes this approval before dispatch.
    ///
    /// `trusted_now` must be synchronous, non-blocking, and non-reentrant. It runs while the
    /// emergency-policy and approval locks are held so the sampled time belongs to the exact
    /// dispatch-admission linearization point. A clock error leaves the token unconsumed.
    pub fn authorize_and_dispatch_with_clock<E>(
        &self,
        emergency: &EmergencyPolicy,
        context: &ExecutionContext,
        trusted_now: impl FnOnce() -> Result<u64, E>,
        dispatch: impl FnOnce(),
    ) -> Result<(), ApprovalAuthorizationError<E>> {
        {
            let emergency = emergency.state.lock().map_err(|_| {
                ApprovalAuthorizationError::Approval(ApprovalError::CoordinationUnavailable)
            })?;
            let mut inner = self.inner.lock().map_err(|_| {
                ApprovalAuthorizationError::Approval(ApprovalError::CoordinationUnavailable)
            })?;
            let now_unix_ms = trusted_now().map_err(ApprovalAuthorizationError::Clock)?;

            macro_rules! stale {
                ($reason:expr) => {{
                    inner.token_consumed = true;
                    return Err(ApprovalAuthorizationError::Approval(
                        ApprovalError::ApprovalStale($reason),
                    ));
                }};
            }

            match inner.state {
                ApprovalState::Pending => {
                    return Err(ApprovalAuthorizationError::Approval(
                        ApprovalError::ApprovalPending,
                    ));
                }
                ApprovalState::Denied { .. } | ApprovalState::Expired => {
                    return Err(ApprovalAuthorizationError::Approval(
                        ApprovalError::ApprovalDenied,
                    ));
                }
                ApprovalState::Approved { .. } => {}
            }
            if inner.token_consumed {
                stale!(StaleApprovalReason::TokenConsumed);
            }
            if now_unix_ms >= self.proposal.expires_at_unix_ms() {
                stale!(StaleApprovalReason::Expired);
            }
            if context.tenant_id != self.proposal.tenant_id {
                stale!(StaleApprovalReason::ActionBinding);
            }
            if context.requester_principal_id != self.proposal.requester_principal_id {
                stale!(StaleApprovalReason::RequesterPrincipal);
            }
            if context.session_id != self.proposal.session_id
                || context.session_incarnation != self.proposal.session_incarnation
            {
                stale!(StaleApprovalReason::SessionIncarnation);
            }
            if !context.placement_owned {
                stale!(StaleApprovalReason::PlacementOwnership);
            }
            if context.page_id != self.proposal.page_id {
                stale!(StaleApprovalReason::Page);
            }
            if context.target_incarnation != self.proposal.target_incarnation {
                stale!(StaleApprovalReason::TargetIncarnation);
            }
            if context.frame_document_epoch != self.proposal.frame_document_epoch {
                stale!(StaleApprovalReason::DocumentEpoch);
            }
            if context.current_origin != self.proposal.current_origin {
                stale!(StaleApprovalReason::Origin);
            }
            if context.url_revision != self.proposal.url_revision {
                stale!(StaleApprovalReason::UrlRevision);
            }
            if !context.node_valid || context.node_ref != self.proposal.node_ref {
                stale!(StaleApprovalReason::Node);
            }
            if CredentialRefsHash::digest(context.credential_refs.iter().map(String::as_str))
                != self.proposal.credential_refs_hash
            {
                stale!(StaleApprovalReason::CredentialRefs);
            }
            let expected_feature = match &self.proposal.action_type {
                ActionType::Click => "browser:click",
                ActionType::Fill => "browser:fill",
                ActionType::Navigate => "browser:navigate",
                ActionType::Evaluate => "browser:evaluate",
                ActionType::Upload => "browser:upload",
                ActionType::Download => "browser:download",
                ActionType::Custom(feature) => feature,
            };
            if context.feature != expected_feature {
                stale!(StaleApprovalReason::ActionBinding);
            }

            let emergency_reason = if emergency.disabled_tenants.contains(&context.tenant_id) {
                Some(EmergencyDenyReason::TenantDisabled)
            } else if emergency.disabled_sessions.contains(&context.session_id) {
                Some(EmergencyDenyReason::SessionDisabled)
            } else if emergency.denied_domains.iter().any(|domain| {
                context.current_origin.host() == domain
                    || context
                        .current_origin
                        .host()
                        .strip_suffix(domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }) {
                Some(EmergencyDenyReason::DomainDenied)
            } else if context
                .resolved_ips
                .iter()
                .any(|ip| emergency.denied_ips.contains(ip))
            {
                Some(EmergencyDenyReason::IpDenied)
            } else if context
                .credential_refs
                .iter()
                .any(|secret_ref| emergency.revoked_secrets.contains(secret_ref))
            {
                Some(EmergencyDenyReason::SecretRevoked)
            } else if emergency.killed_features.contains(expected_feature) {
                Some(EmergencyDenyReason::FeatureKillSwitch)
            } else if emergency
                .killed_chromium_builds
                .contains(&context.chromium_build)
            {
                Some(EmergencyDenyReason::ChromiumBuildKillSwitch)
            } else if emergency
                .force_dedicated_tenants
                .contains(&context.tenant_id)
                && context.effective_isolation < IsolationProfile::DedicatedProcess
            {
                Some(EmergencyDenyReason::ForceDedicatedProcess)
            } else {
                None
            };
            if let Some(reason) = emergency_reason {
                stale!(StaleApprovalReason::EmergencyDenied(reason));
            }

            inner.token_consumed = true;
        }
        dispatch();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn trusted_time_is_sampled_only_after_policy_admission_locks_are_acquired() {
        let tenant_id = TenantId::new();
        let requester = PrincipalId::new();
        let session_id = SessionId::new();
        let page_id = PageId::new();
        let proposal = CanonicalActionProposal::new(
            tenant_id.clone(),
            requester.clone(),
            session_id.clone(),
            1,
            page_id.clone(),
            2,
            3,
            Origin::parse("https://example.test/").expect("origin should be valid"),
            4,
            ActionType::Click,
            ActionArgumentsHash::digest(b"click"),
            None,
            CredentialRefsHash::digest(std::iter::empty()),
            10_000,
        );
        let context = ExecutionContext {
            tenant_id,
            requester_principal_id: requester,
            session_id,
            session_incarnation: 1,
            page_id,
            target_incarnation: 2,
            frame_document_epoch: 3,
            current_origin: Origin::parse("https://example.test/").expect("origin should be valid"),
            url_revision: 4,
            node_ref: None,
            node_valid: true,
            placement_owned: true,
            resolved_ips: Vec::new(),
            credential_refs: Vec::new(),
            feature: "browser:click".to_owned(),
            chromium_build: "sha256:test".to_owned(),
            effective_isolation: IsolationProfile::SharedContext,
        };
        let request = Arc::new(ApprovalRequest::new(proposal, true));
        request
            .decide(PrincipalId::new(), ApprovalDecision::Approve, 200)
            .expect("approval should be recorded");
        let emergency = Arc::new(EmergencyPolicy::default());
        let clock = Arc::new(AtomicU64::new(200));
        let dispatches = Arc::new(AtomicUsize::new(0));
        let lock_started = Arc::new(Barrier::new(2));
        let release_lock = Arc::new(Barrier::new(2));

        let lock_holder = {
            let emergency = Arc::clone(&emergency);
            let lock_started = Arc::clone(&lock_started);
            let release_lock = Arc::clone(&release_lock);
            thread::spawn(move || {
                let _state = emergency.state.lock().expect("policy lock should work");
                lock_started.wait();
                release_lock.wait();
            })
        };
        lock_started.wait();

        let (clock_sampled_tx, clock_sampled_rx) = mpsc::channel();
        let target = {
            let request = Arc::clone(&request);
            let emergency = Arc::clone(&emergency);
            let clock = Arc::clone(&clock);
            let dispatches = Arc::clone(&dispatches);
            thread::spawn(move || {
                request.authorize_and_dispatch_with_clock(
                    &emergency,
                    &context,
                    || {
                        clock_sampled_tx.send(()).expect("test receiver remains");
                        Ok::<_, ()>(clock.load(Ordering::Acquire))
                    },
                    || {
                        dispatches.fetch_add(1, Ordering::AcqRel);
                    },
                )
            })
        };
        let sampled_before_policy_unlock = clock_sampled_rx
            .recv_timeout(Duration::from_millis(100))
            .is_ok();
        clock.store(10_000, Ordering::Release);
        release_lock.wait();

        lock_holder.join().expect("lock holder should not panic");
        let result = target.join().expect("authorization should not panic");
        assert!(
            !sampled_before_policy_unlock,
            "trusted time must not be sampled before the policy locks are acquired"
        );
        assert_eq!(
            result,
            Err(ApprovalAuthorizationError::Approval(
                ApprovalError::ApprovalStale(StaleApprovalReason::Expired),
            ))
        );
        assert_eq!(dispatches.load(Ordering::Acquire), 0);
    }
}
