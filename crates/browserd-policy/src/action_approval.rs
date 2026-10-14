//! Immutable operator approval policy and typed, credential-free proposal bindings.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use browserd_core::{ActionId, ArtifactId, PrincipalId, TenantId, WorkerId};
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{ActionType, CanonicalActionProposal, CredentialRefsHash, NodeReference, Origin};

pub const MAX_ACTION_APPROVAL_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_ACTION_APPROVAL_GRANTS: usize = 1024;
pub const MAX_TYPED_ACTION_BINDING_BYTES: usize = 256 * 1024;
const LOAD_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalActionKind {
    Navigate,
    Reload,
    GoBack,
    GoForward,
    Click,
    DoubleClick,
    Hover,
    Focus,
    Blur,
    Check,
    Uncheck,
    Fill,
    FillSecret,
    SelectOption,
    SetFiles,
    Evaluate,
    WaitFor,
    HandleDialog,
    Snapshot,
    TypeText,
    PressKey,
    Scroll,
    QueryAll,
    GetText,
    GetHtml,
    GetAttribute,
    GetProperties,
    GetComputedStyle,
    ExtractTable,
    GetUrl,
    GetTitle,
    Screenshot,
    Pdf,
    Scrape,
    Checkpoint,
}

impl ApprovalActionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Navigate => "navigate",
            Self::Reload => "reload",
            Self::GoBack => "go_back",
            Self::GoForward => "go_forward",
            Self::Click => "click",
            Self::DoubleClick => "double_click",
            Self::Hover => "hover",
            Self::Focus => "focus",
            Self::Blur => "blur",
            Self::Check => "check",
            Self::Uncheck => "uncheck",
            Self::Fill => "fill",
            Self::FillSecret => "fill_secret",
            Self::SelectOption => "select_option",
            Self::SetFiles => "set_files",
            Self::Evaluate => "evaluate",
            Self::WaitFor => "wait_for",
            Self::HandleDialog => "handle_dialog",
            Self::Snapshot => "snapshot",
            Self::TypeText => "type_text",
            Self::PressKey => "press_key",
            Self::Scroll => "scroll",
            Self::QueryAll => "query_all",
            Self::GetText => "get_text",
            Self::GetHtml => "get_html",
            Self::GetAttribute => "get_attribute",
            Self::GetProperties => "get_properties",
            Self::GetComputedStyle => "get_computed_style",
            Self::ExtractTable => "extract_table",
            Self::GetUrl => "get_url",
            Self::GetTitle => "get_title",
            Self::Screenshot => "screenshot",
            Self::Pdf => "pdf",
            Self::Scrape => "scrape",
            Self::Checkpoint => "checkpoint",
        }
    }

    #[must_use]
    pub fn legacy_action_type(self) -> ActionType {
        match self {
            Self::Click => ActionType::Click,
            Self::Fill => ActionType::Fill,
            Self::Navigate => ActionType::Navigate,
            Self::Evaluate => ActionType::Evaluate,
            other => ActionType::Custom(format!("browser:{}", other.as_str())),
        }
    }

    /// Sensitive checkpoint export requires manual approval even though capture has no browser
    /// mutation. An approval never replaces the action's separate scope or feature checks.
    #[must_use]
    pub const fn is_safe_observation(self) -> bool {
        matches!(
            self,
            Self::Snapshot
                | Self::QueryAll
                | Self::GetText
                | Self::GetHtml
                | Self::GetAttribute
                | Self::GetProperties
                | Self::GetComputedStyle
                | Self::ExtractTable
                | Self::GetUrl
                | Self::GetTitle
                | Self::Screenshot
                | Self::Pdf
                | Self::Scrape
        )
    }

    const fn requires_node(self) -> bool {
        matches!(
            self,
            Self::Click
                | Self::DoubleClick
                | Self::Hover
                | Self::Focus
                | Self::Blur
                | Self::Check
                | Self::Uncheck
                | Self::Fill
                | Self::SelectOption
                | Self::GetText
                | Self::GetAttribute
                | Self::GetProperties
                | Self::GetComputedStyle
                | Self::ExtractTable
        )
    }
}

/// Non-HTTP scopes are explicit authority categories, never fabricated HTTP origins.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalContextScope {
    HttpOrigin { origin: String },
    OpaqueDocument,
    BrowserContext,
}

impl ApprovalContextScope {
    pub fn validate(&self) -> Result<(), ActionApprovalPolicyError> {
        if let Self::HttpOrigin { origin } = self {
            canonical_origin(origin)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn matches_origin(&self, origin: &Origin) -> bool {
        match self {
            Self::HttpOrigin { origin: expected } => {
                !origin.is_browser_context_scope()
                    && !origin.is_opaque_document_scope()
                    && origin.as_str() == expected
            }
            Self::OpaqueDocument => origin.is_opaque_document_scope(),
            Self::BrowserContext => origin.is_browser_context_scope(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalWorkerFence {
    pub worker_id: WorkerId,
    pub worker_epoch: u64,
    pub placement_version: u64,
    pub session_incarnation: u64,
}

/// The owner hashes its complete, trusted leaf/default-realm/ordered-ancestor guard. Raw CDP
/// routes and execution realm identifiers are kept in the owner's private observation token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalNodeBinding {
    pub node_ref: String,
    pub binding_sha256: [u8; 32],
    /// Untrusted display hint; never used as authority or extracted from an input value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Untrusted aria-label/title display hint; no DOM text or input value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ApprovalNodeBinding {
    fn validate(&self) -> Result<(), ActionApprovalPolicyError> {
        NodeReference::new(&self.node_ref).map_err(|_| ActionApprovalPolicyError::Rejected)?;
        for hint in [self.role.as_deref(), self.name.as_deref()]
            .into_iter()
            .flatten()
        {
            if hint.len() > 256 || hint.chars().any(char::is_control) {
                return Err(ActionApprovalPolicyError::Rejected);
            }
        }
        nonzero(&self.binding_sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalArtifactBinding {
    pub artifact_id: ArtifactId,
    pub object_generation: [u8; 32],
    pub size_bytes: u64,
    pub checksum_sha256: [u8; 32],
    pub effective_filename: String,
    pub publication_sha256: [u8; 32],
    pub scan_evidence_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypedActionPayload {
    Browser {
        action: ApprovalActionKind,
        arguments_sha256: [u8; 32],
        node: Option<ApprovalNodeBinding>,
        navigation_destination: Option<String>,
    },
    FillSecret {
        node: ApprovalNodeBinding,
        secret_ref: String,
        grant_metadata_sha256: [u8; 32],
    },
    SetFiles {
        node: ApprovalNodeBinding,
        files: Vec<ApprovalArtifactBinding>,
    },
    Checkpoint {
        origins: Vec<String>,
        build_identity_sha256: [u8; 32],
    },
}

impl TypedActionPayload {
    #[must_use]
    pub const fn action_kind(&self) -> ApprovalActionKind {
        match self {
            Self::Browser { action, .. } => *action,
            Self::FillSecret { .. } => ApprovalActionKind::FillSecret,
            Self::SetFiles { .. } => ApprovalActionKind::SetFiles,
            Self::Checkpoint { .. } => ApprovalActionKind::Checkpoint,
        }
    }

    #[must_use]
    pub fn legacy_action_type(&self) -> ActionType {
        self.action_kind().legacy_action_type()
    }

    #[must_use]
    pub const fn node(&self) -> Option<&ApprovalNodeBinding> {
        match self {
            Self::Browser { node, .. } => node.as_ref(),
            Self::FillSecret { node, .. } | Self::SetFiles { node, .. } => Some(node),
            Self::Checkpoint { .. } => None,
        }
    }

    #[must_use]
    pub fn navigation_destination(&self) -> Option<&str> {
        match self {
            Self::Browser {
                navigation_destination,
                ..
            } => navigation_destination.as_deref(),
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), ActionApprovalPolicyError> {
        if let Some(node) = self.node() {
            node.validate()?;
        }
        match self {
            Self::Browser {
                action,
                arguments_sha256,
                node,
                navigation_destination,
            } => {
                if matches!(
                    action,
                    ApprovalActionKind::FillSecret
                        | ApprovalActionKind::SetFiles
                        | ApprovalActionKind::Checkpoint
                ) || action.requires_node() && node.is_none()
                    || !action.requires_node()
                        && *action != ApprovalActionKind::GetHtml
                        && node.is_some()
                {
                    return Err(ActionApprovalPolicyError::Rejected);
                }
                nonzero(arguments_sha256)?;
                validate_destination(*action, navigation_destination.as_deref())?;
            }
            Self::FillSecret {
                secret_ref,
                grant_metadata_sha256,
                ..
            } => {
                bounded_token(secret_ref, 1024)?;
                nonzero(grant_metadata_sha256)?;
            }
            Self::SetFiles { files, .. } => {
                if files.is_empty() || files.len() > 128 {
                    return Err(ActionApprovalPolicyError::Rejected);
                }
                let mut ids = BTreeSet::new();
                for file in files {
                    if !ids.insert(&file.artifact_id) || !safe_filename(&file.effective_filename) {
                        return Err(ActionApprovalPolicyError::Rejected);
                    }
                    nonzero(&file.object_generation)?;
                    nonzero(&file.publication_sha256)?;
                    if let Some(scan) = &file.scan_evidence_sha256 {
                        nonzero(scan)?;
                    }
                }
            }
            Self::Checkpoint {
                origins,
                build_identity_sha256,
            } => {
                if origins.len() > 16 {
                    return Err(ActionApprovalPolicyError::Rejected);
                }
                let mut seen = BTreeSet::new();
                for origin in origins {
                    canonical_origin(origin)?;
                    if !seen.insert(origin) {
                        return Err(ActionApprovalPolicyError::Rejected);
                    }
                }
                nonzero(build_identity_sha256)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypedActionProposalBinding {
    pub schema_version: u8,
    pub action_id: ActionId,
    pub sequence: u64,
    pub fence: ApprovalWorkerFence,
    pub policy_digest: [u8; 32],
    pub target_binding_sha256: [u8; 32],
    pub context_scope: ApprovalContextScope,
    pub payload: TypedActionPayload,
}

impl TypedActionProposalBinding {
    pub fn validate(&self) -> Result<(), ActionApprovalPolicyError> {
        if self.schema_version != 2
            || self.sequence == 0
            || self.fence.worker_epoch == 0
            || self.fence.placement_version == 0
            || self.fence.session_incarnation == 0
        {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        nonzero(&self.policy_digest)?;
        nonzero(&self.target_binding_sha256)?;
        self.context_scope.validate()?;
        self.payload.validate()?;
        match (&self.context_scope, &self.payload) {
            (ApprovalContextScope::BrowserContext, TypedActionPayload::Checkpoint { .. }) => {}
            (ApprovalContextScope::BrowserContext, _)
            | (_, TypedActionPayload::Checkpoint { .. }) => {
                return Err(ActionApprovalPolicyError::Rejected);
            }
            (ApprovalContextScope::OpaqueDocument, TypedActionPayload::Browser { .. }) => {}
            (ApprovalContextScope::OpaqueDocument, _) => {
                return Err(ActionApprovalPolicyError::Rejected);
            }
            (ApprovalContextScope::HttpOrigin { .. }, _) => {}
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ActionApprovalPolicyError::Rejected)?;
        if bytes.len() > MAX_TYPED_ACTION_BINDING_BYTES {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        proposal: &CanonicalActionProposal,
    ) -> Result<(), ActionApprovalPolicyError> {
        self.validate()?;
        if self.fence.session_incarnation != proposal.session_incarnation()
            || !self.context_scope.matches_origin(proposal.current_origin())
            || self.payload.action_kind().legacy_action_type() != *proposal.action_type()
            || self.payload.node().map(|node| node.node_ref.as_str())
                != proposal.node_ref().map(NodeReference::as_str)
        {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        let credentials = match &self.payload {
            TypedActionPayload::FillSecret { secret_ref, .. } => {
                CredentialRefsHash::digest([secret_ref.as_str()])
            }
            _ => CredentialRefsHash::digest(std::iter::empty::<&str>()),
        };
        if credentials != proposal.credential_refs_hash() {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        if let TypedActionPayload::Browser {
            arguments_sha256, ..
        } = &self.payload
            && arguments_sha256 != proposal.canonical_arguments_hash().as_bytes()
        {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        Ok(())
    }

    pub(crate) fn hash_into(&self, hasher: &mut Sha256) {
        // Public fields may be mutated by callers, so hashing invalid material remains total;
        // constructors and every policy/dispatch entry point separately reject invalid bindings.
        if let Ok(bytes) = serde_json::to_vec(self) {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionApprovalOutcome {
    Allow,
    Deny,
    Manual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionApprovalDecision {
    pub outcome: ActionApprovalOutcome,
    pub require_four_eyes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionApprovalGrant {
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
    pub action: ApprovalActionKind,
    pub context_scope: ApprovalContextScope,
    pub navigation_destination: Option<String>,
    pub outcome: ActionApprovalOutcome,
    #[serde(default = "default_four_eyes")]
    pub require_four_eyes: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionApprovalPolicyError {
    Rejected,
    Unavailable,
}

impl fmt::Display for ActionApprovalPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected => "action approval policy rejected",
            Self::Unavailable => "action approval policy unavailable",
        })
    }
}
impl std::error::Error for ActionApprovalPolicyError {}

#[derive(Clone, Eq, PartialEq)]
pub struct ActionApprovalPolicy {
    grants: Vec<ActionApprovalGrant>,
    default_require_four_eyes: bool,
    digest: [u8; 32],
}

impl fmt::Debug for ActionApprovalPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActionApprovalPolicy")
            .field("grant_count", &self.grants.len())
            .finish_non_exhaustive()
    }
}

impl Default for ActionApprovalPolicy {
    fn default() -> Self {
        Self::from_valid_grants(Vec::new(), true)
    }
}

impl ActionApprovalPolicy {
    pub fn new(grants: Vec<ActionApprovalGrant>) -> Result<Self, ActionApprovalPolicyError> {
        Self::new_with_four_eyes(grants, true)
    }

    pub fn new_with_four_eyes(
        mut grants: Vec<ActionApprovalGrant>,
        default_require_four_eyes: bool,
    ) -> Result<Self, ActionApprovalPolicyError> {
        if grants.len() > MAX_ACTION_APPROVAL_GRANTS {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        let mut keys = BTreeSet::new();
        for grant in &grants {
            grant.context_scope.validate()?;
            validate_destination(grant.action, grant.navigation_destination.as_deref())?;
            if matches!(grant.context_scope, ApprovalContextScope::BrowserContext)
                != (grant.action == ApprovalActionKind::Checkpoint)
                || matches!(grant.context_scope, ApprovalContextScope::OpaqueDocument)
                    && matches!(
                        grant.action,
                        ApprovalActionKind::FillSecret | ApprovalActionKind::SetFiles
                    )
                || !keys.insert((
                    grant.tenant_id.clone(),
                    grant.principal_id.clone(),
                    grant.action,
                    grant.context_scope.clone(),
                    grant.navigation_destination.clone(),
                    grant.outcome,
                ))
            {
                return Err(ActionApprovalPolicyError::Rejected);
            }
        }
        grants.sort_by(|a, b| {
            (
                &a.tenant_id,
                &a.principal_id,
                a.action,
                &a.context_scope,
                &a.navigation_destination,
                a.outcome,
            )
                .cmp(&(
                    &b.tenant_id,
                    &b.principal_id,
                    b.action,
                    &b.context_scope,
                    &b.navigation_destination,
                    b.outcome,
                ))
        });
        let policy = Self::from_valid_grants(grants, default_require_four_eyes);
        if policy.canonical_bytes().len() > MAX_ACTION_APPROVAL_POLICY_BYTES {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        Ok(policy)
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn evaluate(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        scope: &ApprovalContextScope,
        action: ApprovalActionKind,
        navigation_destination: Option<&str>,
    ) -> Result<ActionApprovalDecision, ActionApprovalPolicyError> {
        scope.validate()?;
        validate_destination(action, navigation_destination)?;
        if matches!(scope, ApprovalContextScope::BrowserContext)
            != (action == ApprovalActionKind::Checkpoint)
            || matches!(scope, ApprovalContextScope::OpaqueDocument)
                && matches!(
                    action,
                    ApprovalActionKind::FillSecret | ApprovalActionKind::SetFiles
                )
        {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        let mut decision: Option<ActionApprovalDecision> = None;
        for grant in &self.grants {
            if &grant.tenant_id != tenant
                || &grant.principal_id != principal
                || grant.action != action
                || &grant.context_scope != scope
                || grant.navigation_destination.as_deref() != navigation_destination
            {
                continue;
            }
            let current = ActionApprovalDecision {
                outcome: grant.outcome,
                require_four_eyes: grant.require_four_eyes,
            };
            decision = Some(match decision {
                None => current,
                Some(previous) => ActionApprovalDecision {
                    outcome: if previous.outcome == ActionApprovalOutcome::Deny
                        || current.outcome == ActionApprovalOutcome::Deny
                    {
                        ActionApprovalOutcome::Deny
                    } else if previous.outcome == ActionApprovalOutcome::Manual
                        || current.outcome == ActionApprovalOutcome::Manual
                    {
                        ActionApprovalOutcome::Manual
                    } else {
                        ActionApprovalOutcome::Allow
                    },
                    require_four_eyes: previous.require_four_eyes || current.require_four_eyes,
                },
            });
        }
        Ok(decision.unwrap_or(ActionApprovalDecision {
            outcome: if action.is_safe_observation() {
                ActionApprovalOutcome::Allow
            } else {
                ActionApprovalOutcome::Manual
            },
            require_four_eyes: self.default_require_four_eyes,
        }))
    }

    pub fn evaluate_proposal(
        &self,
        proposal: &CanonicalActionProposal,
    ) -> Result<ActionApprovalDecision, ActionApprovalPolicyError> {
        let binding = proposal
            .typed_binding()
            .ok_or(ActionApprovalPolicyError::Rejected)?;
        binding.validate_for(proposal)?;
        if binding.policy_digest != self.digest {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        self.evaluate(
            proposal.tenant_id(),
            proposal.requester_principal_id(),
            &binding.context_scope,
            binding.payload.action_kind(),
            binding.payload.navigation_destination(),
        )
    }

    fn from_valid_grants(
        grants: Vec<ActionApprovalGrant>,
        default_require_four_eyes: bool,
    ) -> Self {
        let mut result = Self {
            grants,
            default_require_four_eyes,
            digest: [0; 32],
        };
        let mut hash = Sha256::new();
        hash.update(b"browserd.action-approval-policy.v1\0");
        hash.update(result.canonical_bytes());
        result.digest = hash.finalize().into();
        result
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        // All members have infallible serde representations (UUIDs, strings and integers).
        serde_json::to_vec(&(1u8, self.default_require_four_eyes, &self.grants)).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ActionApprovalPolicyError> {
        if bytes.len() > MAX_ACTION_APPROVAL_POLICY_BYTES {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        let config: ActionApprovalConfig =
            serde_json::from_slice(bytes).map_err(|_| ActionApprovalPolicyError::Rejected)?;
        if config.schema_version != 1 {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        Self::new_with_four_eyes(config.grants.0, config.default_require_four_eyes)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionApprovalConfig {
    schema_version: u8,
    #[serde(default = "default_four_eyes")]
    default_require_four_eyes: bool,
    grants: BoundedGrants,
}
const fn default_four_eyes() -> bool {
    true
}
struct BoundedGrants(Vec<ActionApprovalGrant>);
impl<'de> Deserialize<'de> for BoundedGrants {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct GrantsVisitor;
        impl<'de> Visitor<'de> for GrantsVisitor {
            type Value = BoundedGrants;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded action approval grant array")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut grants = Vec::new();
                while let Some(grant) = sequence.next_element()? {
                    if grants.len() == MAX_ACTION_APPROVAL_GRANTS {
                        return Err(serde::de::Error::custom("too many approval grants"));
                    }
                    grants.push(grant);
                }
                Ok(BoundedGrants(grants))
            }
        }
        deserializer.deserialize_seq(GrantsVisitor)
    }
}

fn nonzero(bytes: &[u8; 32]) -> Result<(), ActionApprovalPolicyError> {
    if bytes.iter().all(|b| *b == 0) {
        Err(ActionApprovalPolicyError::Rejected)
    } else {
        Ok(())
    }
}
fn bounded_token(value: &str, max: usize) -> Result<(), ActionApprovalPolicyError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ActionApprovalPolicyError::Rejected)
    } else {
        Ok(())
    }
}
fn canonical_origin(value: &str) -> Result<(), ActionApprovalPolicyError> {
    if value.len() > 2048
        || !Origin::parse(value)
            .is_ok_and(|origin| origin.as_str() == value && !origin.host().contains('*'))
    {
        return Err(ActionApprovalPolicyError::Rejected);
    }
    Ok(())
}
fn validate_destination(
    action: ApprovalActionKind,
    destination: Option<&str>,
) -> Result<(), ActionApprovalPolicyError> {
    match (action, destination) {
        (ApprovalActionKind::Navigate, Some(value)) => {
            bounded_token(value, 8192)?;
            let url = url::Url::parse(value).map_err(|_| ActionApprovalPolicyError::Rejected)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.as_str() != value
            {
                return Err(ActionApprovalPolicyError::Rejected);
            }
            Ok(())
        }
        (ApprovalActionKind::Navigate, None) | (_, Some(_)) => {
            Err(ActionApprovalPolicyError::Rejected)
        }
        (_, None) => Ok(()),
    }
}
fn safe_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.trim() == value
        && !matches!(value, "." | "..")
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
}

impl ActionApprovalPolicy {
    /// Loads one immutable snapshot through pinned directory/file descriptors. Every path
    /// component rejects symlinks; the immediate parent must be owned by the effective UID with
    /// mode 0700, and the regular, singly linked file must have the same owner and mode 0600.
    pub fn open(path: &Path) -> Result<Self, ActionApprovalPolicyError> {
        if !path.is_absolute() {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        let parent = path.parent().ok_or(ActionApprovalPolicyError::Rejected)?;
        let filename = path
            .file_name()
            .ok_or(ActionApprovalPolicyError::Rejected)?;
        let deadline = Instant::now() + LOAD_BUDGET;
        let owner_uid = nix::unistd::geteuid().as_raw();
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let mut directory = File::from(
            open(Path::new("/"), flags, Mode::empty())
                .map_err(|_| ActionApprovalPolicyError::Unavailable)?,
        );
        for component in parent.components() {
            if Instant::now() >= deadline {
                return Err(ActionApprovalPolicyError::Unavailable);
            }
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    directory = File::from(
                        openat(&directory, Path::new(name), flags, Mode::empty())
                            .map_err(|_| ActionApprovalPolicyError::Rejected)?,
                    );
                }
                _ => return Err(ActionApprovalPolicyError::Rejected),
            }
        }
        let parent_metadata = directory
            .metadata()
            .map_err(|_| ActionApprovalPolicyError::Unavailable)?;
        if !parent_metadata.is_dir()
            || parent_metadata.uid() != owner_uid
            || parent_metadata.mode() & 0o7777 != 0o700
        {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        if Instant::now() >= deadline {
            return Err(ActionApprovalPolicyError::Unavailable);
        }
        let mut file = File::from(
            openat(
                &directory,
                Path::new(filename),
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ActionApprovalPolicyError::Unavailable)?,
        );
        let before = file
            .metadata()
            .map_err(|_| ActionApprovalPolicyError::Unavailable)?;
        let bytes = read_bounded(&mut file, &before, owner_uid, deadline, File::metadata)?;
        let after_parent = directory
            .metadata()
            .map_err(|_| ActionApprovalPolicyError::Unavailable)?;
        if !after_parent.is_dir()
            || after_parent.dev() != parent_metadata.dev()
            || after_parent.ino() != parent_metadata.ino()
            || after_parent.uid() != owner_uid
            || after_parent.mode() & 0o7777 != 0o700
        {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        let result = Self::from_bytes(&bytes);
        if Instant::now() >= deadline {
            return Err(ActionApprovalPolicyError::Unavailable);
        }
        result
    }
}

fn read_bounded<R: Read>(
    reader: &mut R,
    before: &Metadata,
    owner_uid: u32,
    deadline: Instant,
    after_metadata: impl FnOnce(&R) -> std::io::Result<Metadata>,
) -> Result<Zeroizing<Vec<u8>>, ActionApprovalPolicyError> {
    if Instant::now() >= deadline {
        return Err(ActionApprovalPolicyError::Unavailable);
    }
    if !before.is_file()
        || before.uid() != owner_uid
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > MAX_ACTION_APPROVAL_POLICY_BYTES as u64
    {
        return Err(ActionApprovalPolicyError::Rejected);
    }
    // Full preallocation ensures file growth cannot leave an unwiped previous allocation.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_ACTION_APPROVAL_POLICY_BYTES));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        if Instant::now() >= deadline {
            return Err(ActionApprovalPolicyError::Unavailable);
        }
        let count = reader
            .read(chunk.as_mut())
            .map_err(|_| ActionApprovalPolicyError::Unavailable)?;
        if Instant::now() >= deadline {
            return Err(ActionApprovalPolicyError::Unavailable);
        }
        if count == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|length| length > MAX_ACTION_APPROVAL_POLICY_BYTES)
        {
            return Err(ActionApprovalPolicyError::Rejected);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let after = after_metadata(reader).map_err(|_| ActionApprovalPolicyError::Unavailable)?;
    if !after.is_file()
        || after.uid() != owner_uid
        || after.nlink() != 1
        || after.mode() & 0o7777 != 0o600
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(ActionApprovalPolicyError::Rejected);
    }
    if Instant::now() >= deadline {
        return Err(ActionApprovalPolicyError::Unavailable);
    }
    Ok(bytes)
}
