//! Origin-bound secret resolution and the non-serializable credential dispatch lane.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use browserd_core::{ActionId, PageId, PrincipalId, SessionId, TenantId};
use browserd_observability::{AppendOutcome, AuditEvent, AuditEventId};
use browserd_policy::Origin;
use browserd_session::OwnershipFence;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    APPROVED_DISPATCH_AUTHORIZATION_REJECTED, APPROVED_DISPATCH_AUTHORIZING,
    APPROVED_DISPATCH_DRIVER_PENDING, APPROVED_DISPATCH_INSPECTING,
    APPROVED_DISPATCH_RETURNED_UNCERTAIN, APPROVED_DISPATCH_STARTED, APPROVED_DISPATCH_STOPPED,
    ActionExecutionResult, ActionStatus, ChromiumDriver, SandboxClient, SessionExecution,
    SessionExecutor, SessionLifecycle, WorkerActionCommand, WorkerControlPlane, validate_fence,
};

pub const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const MAX_GRANTS: usize = 1024;
const READ_BYTES: usize = 4096;

/// Metadata observed from the current owned main document, never from an API payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretFillTarget {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub page_id: PageId,
    pub fence: OwnershipFence,
    pub node_ref: String,
    pub target_incarnation: u64,
    pub frame_document_epoch: u64,
    pub url_revision: u64,
    pub origin: Origin,
}

impl SecretFillTarget {
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    pub fn page_id(&self) -> &PageId {
        &self.page_id
    }
    pub fn fence(&self) -> &OwnershipFence {
        &self.fence
    }
    pub fn node_ref(&self) -> &str {
        &self.node_ref
    }
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    pub const fn target_incarnation(&self) -> u64 {
        self.target_incarnation
    }
    pub const fn frame_document_epoch(&self) -> u64 {
        self.frame_document_epoch
    }
    pub const fn url_revision(&self) -> u64 {
        self.url_revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretFillError {
    Rejected,
    Unavailable,
    DeadlineBeforeDispatch,
    DispatchRevoked,
    OutcomeUncertain,
}

impl fmt::Display for SecretFillError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "secret request rejected",
            Self::Unavailable => "secret unavailable",
            Self::DeadlineBeforeDispatch => "secret deadline elapsed",
            Self::DispatchRevoked => "secret dispatch revoked",
            Self::OutcomeUncertain => "secret effect outcome uncertain",
        })
    }
}

impl std::error::Error for SecretFillError {}

/// An authorization decision with no secret value or caller-selected filesystem path.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretGrant {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    secret_ref: String,
    origin: Origin,
    provider_id: Uuid,
    entry: usize,
}

impl SecretGrant {
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }
    pub fn secret_ref(&self) -> &str {
        &self.secret_ref
    }
    pub fn origin(&self) -> &Origin {
        &self.origin
    }
    /// Binds the immutable provider grant without serializing or resolving a credential.
    pub(crate) fn metadata_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"browserd-secret-grant-metadata-v1\0");
        hash.update(self.tenant_id.as_bytes());
        hash.update(self.principal_id.as_bytes());
        hash.update(self.provider_id.as_bytes());
        hash.update(u64::try_from(self.entry).unwrap_or(u64::MAX).to_be_bytes());
        for value in [self.secret_ref.as_str(), self.origin.as_str()] {
            hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.finalize().into()
    }
}

impl fmt::Debug for SecretGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretGrant")
            .finish_non_exhaustive()
    }
}

/// Single-owner secret memory. It cannot be cloned, serialized, or printed.
pub struct ResolvedSecret {
    grant: SecretGrant,
    value: Zeroizing<String>,
}

impl ResolvedSecret {
    pub fn grant(&self) -> &SecretGrant {
        &self.grant
    }
    pub(crate) fn value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResolvedSecret([REDACTED])")
    }
}

/// Trusted worker-local provider. Authorization must precede any value read.
pub trait SecretResolver: Send + Sync + 'static {
    fn authorize(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        secret_ref: &str,
        origin: &Origin,
        deadline: Instant,
    ) -> Result<SecretGrant, SecretFillError>;

    fn resolve(
        &self,
        grant: &SecretGrant,
        deadline: Instant,
    ) -> Result<ResolvedSecret, SecretFillError>;
}

/// Metadata is loaded once; values are read only for an authorized running action.
pub struct FileSecretResolver {
    provider_id: Uuid,
    values: File,
    owner_uid: u32,
    entries: Vec<GrantEntry>,
    by_key: BTreeMap<(TenantId, String), usize>,
}

struct GrantEntry {
    tenant_id: TenantId,
    secret_ref: String,
    principals: BTreeSet<PrincipalId>,
    origins: Vec<Origin>,
    value_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema_version: u32,
    grants: Vec<CatalogGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogGrant {
    tenant_id: TenantId,
    secret_ref: String,
    principal_ids: Vec<PrincipalId>,
    allowed_origins: Vec<String>,
    value_file: String,
}

impl FileSecretResolver {
    /// Opens a private catalog and pins its parent directory for every later value read.
    pub fn open(config_file: &Path) -> Result<Self, SecretFillError> {
        let owner_uid = nix::unistd::geteuid().as_raw();
        let parent = config_file.parent().ok_or(SecretFillError::Rejected)?;
        let filename = config_file
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| valid_basename(name))
            .ok_or(SecretFillError::Rejected)?;
        let values = open_private_directory(parent, owner_uid)?;
        let mut config = private_file(&values, filename, owner_uid)?;
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .ok_or(SecretFillError::Unavailable)?;
        let bytes = read_bounded(&mut config, MAX_CATALOG_BYTES, deadline)?;
        let catalog: Catalog =
            serde_json::from_slice(&bytes).map_err(|_| SecretFillError::Rejected)?;
        if catalog.schema_version != 1 || catalog.grants.len() > MAX_GRANTS {
            return Err(SecretFillError::Rejected);
        }
        let mut entries = Vec::with_capacity(catalog.grants.len());
        let mut by_key = BTreeMap::new();
        for entry in catalog.grants {
            if !valid_secret_ref(&entry.secret_ref)
                || entry.principal_ids.is_empty()
                || entry.principal_ids.len() > 128
                || entry.allowed_origins.is_empty()
                || entry.allowed_origins.len() > 32
                || !valid_basename(&entry.value_file)
                || entry.value_file == filename
            {
                return Err(SecretFillError::Rejected);
            }
            let principal_count = entry.principal_ids.len();
            let principals = entry.principal_ids.into_iter().collect::<BTreeSet<_>>();
            if principals.len() != principal_count {
                return Err(SecretFillError::Rejected);
            }
            let mut origins = Vec::with_capacity(entry.allowed_origins.len());
            for value in entry.allowed_origins {
                let origin = canonical_origin(&value)?;
                if origins.contains(&origin) {
                    return Err(SecretFillError::Rejected);
                }
                origins.push(origin);
            }
            let index = entries.len();
            if by_key
                .insert((entry.tenant_id.clone(), entry.secret_ref.clone()), index)
                .is_some()
            {
                return Err(SecretFillError::Rejected);
            }
            entries.push(GrantEntry {
                tenant_id: entry.tenant_id,
                secret_ref: entry.secret_ref,
                principals,
                origins,
                value_file: entry.value_file,
            });
        }
        Ok(Self {
            provider_id: Uuid::new_v4(),
            values,
            owner_uid,
            entries,
            by_key,
        })
    }
}

impl SecretResolver for FileSecretResolver {
    fn authorize(
        &self,
        tenant_id: &TenantId,
        principal_id: &PrincipalId,
        secret_ref: &str,
        origin: &Origin,
        deadline: Instant,
    ) -> Result<SecretGrant, SecretFillError> {
        check_deadline(deadline)?;
        let index = self
            .by_key
            .get(&(tenant_id.clone(), secret_ref.to_owned()))
            .copied()
            .ok_or(SecretFillError::Rejected)?;
        let entry = self
            .entries
            .get(index)
            .ok_or(SecretFillError::Unavailable)?;
        if !entry.principals.contains(principal_id) || !entry.origins.contains(origin) {
            return Err(SecretFillError::Rejected);
        }
        Ok(SecretGrant {
            tenant_id: tenant_id.clone(),
            principal_id: principal_id.clone(),
            secret_ref: secret_ref.to_owned(),
            origin: origin.clone(),
            provider_id: self.provider_id,
            entry: index,
        })
    }

    fn resolve(
        &self,
        grant: &SecretGrant,
        deadline: Instant,
    ) -> Result<ResolvedSecret, SecretFillError> {
        check_deadline(deadline)?;
        if grant.provider_id != self.provider_id {
            return Err(SecretFillError::Rejected);
        }
        let entry = self
            .entries
            .get(grant.entry)
            .ok_or(SecretFillError::Rejected)?;
        if entry.tenant_id != grant.tenant_id
            || entry.secret_ref != grant.secret_ref
            || !entry.principals.contains(&grant.principal_id)
            || !entry.origins.contains(&grant.origin)
        {
            return Err(SecretFillError::Rejected);
        }
        check_private_directory(&self.values, self.owner_uid)?;
        let mut file = private_file(&self.values, &entry.value_file, self.owner_uid)?;
        check_deadline(deadline)?;
        let bytes = read_bounded(&mut file, MAX_SECRET_BYTES, deadline)?;
        // Read bytes and UTF-8 string are both zeroizing. This is the only temporary value copy.
        let value = Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| SecretFillError::Rejected)?
                .to_owned(),
        );
        drop(bytes);
        check_deadline(deadline)?;
        Ok(ResolvedSecret {
            grant: grant.clone(),
            value,
        })
    }
}

fn valid_secret_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_basename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn canonical_origin(value: &str) -> Result<Origin, SecretFillError> {
    let origin = Origin::parse(value).map_err(|_| SecretFillError::Rejected)?;
    // Reject path/query/userinfo/default-port aliases rather than silently widening a grant.
    if origin.as_str() != value {
        return Err(SecretFillError::Rejected);
    }
    Ok(origin)
}

fn check_deadline(deadline: Instant) -> Result<(), SecretFillError> {
    if Instant::now() >= deadline {
        Err(SecretFillError::DeadlineBeforeDispatch)
    } else {
        Ok(())
    }
}

fn open_private_directory(path: &Path, owner_uid: u32) -> Result<File, SecretFillError> {
    if !path.is_absolute() {
        return Err(SecretFillError::Rejected);
    }
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory = File::from(
        open(Path::new("/"), flags, Mode::empty()).map_err(|_| SecretFillError::Unavailable)?,
    );
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(
                    openat(&directory, Path::new(name), flags, Mode::empty())
                        .map_err(|_| SecretFillError::Rejected)?,
                );
            }
            _ => return Err(SecretFillError::Rejected),
        }
    }
    check_private_directory(&directory, owner_uid)?;
    Ok(directory)
}

fn check_private_directory(directory: &File, owner_uid: u32) -> Result<(), SecretFillError> {
    let metadata = directory
        .metadata()
        .map_err(|_| SecretFillError::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != owner_uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(SecretFillError::Rejected);
    }
    Ok(())
}

fn private_file(directory: &File, filename: &str, owner_uid: u32) -> Result<File, SecretFillError> {
    let file = File::from(
        openat(
            directory,
            Path::new(filename),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| SecretFillError::Unavailable)?,
    );
    let metadata = file.metadata().map_err(|_| SecretFillError::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
    {
        return Err(SecretFillError::Rejected);
    }
    Ok(file)
}

fn read_bounded(
    file: &mut File,
    limit: usize,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, SecretFillError> {
    check_deadline(deadline)?;
    let before = file.metadata().map_err(|_| SecretFillError::Unavailable)?;
    if before.len() > limit as u64 {
        return Err(SecretFillError::Rejected);
    }
    // Reserve the full bound: a growing file must never cause a previous credential-bearing
    // allocation to be freed by Vec growth before the final identity/length check rejects it.
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
    let mut chunk = Zeroizing::new([0u8; READ_BYTES]);
    loop {
        check_deadline(deadline)?;
        let count = file
            .read(chunk.as_mut())
            .map_err(|_| SecretFillError::Unavailable)?;
        check_deadline(deadline)?;
        if count == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|size| size > limit)
        {
            return Err(SecretFillError::Rejected);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let after = file.metadata().map_err(|_| SecretFillError::Unavailable)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(SecretFillError::Rejected);
    }
    check_deadline(deadline)?;
    Ok(bytes)
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_secret_fill(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        secret_ref: &str,
        action_id: &ActionId,
        principal_id: &PrincipalId,
        deadline: Instant,
        executor: &Arc<SessionExecutor>,
    ) -> ActionExecutionResult {
        let mut effect_started = false;
        let execution = (|| -> Result<ActionExecutionResult, SecretFillError> {
            check_deadline(deadline)?;
            if !valid_secret_ref(secret_ref)
                || node_ref.is_empty()
                || node_ref.len() > 1024
                || node_ref.trim() != node_ref
                || node_ref.chars().any(char::is_control)
            {
                return Err(SecretFillError::Rejected);
            }
            let resolver = self
                .secret_resolver
                .as_ref()
                .ok_or(SecretFillError::Unavailable)?;
            let (tenant_id, permit) = {
                let session = executor
                    .state
                    .lock()
                    .map_err(|_| SecretFillError::Unavailable)?;
                validate_fence(&session, fence).map_err(|_| SecretFillError::DispatchRevoked)?;
                let snapshot = session.machine.snapshot();
                if session.machine.session_id() != session_id
                    || snapshot.lifecycle != SessionLifecycle::Ready
                    || snapshot.execution != SessionExecution::Running(action_id.clone())
                    || !session.occupies_capacity
                    || !session.pages.contains(page_id)
                    || session.closing_pages.contains(page_id)
                {
                    return Err(SecretFillError::DispatchRevoked);
                }
                let action = session
                    .actions
                    .get(action_id)
                    .ok_or(SecretFillError::DispatchRevoked)?;
                if action.snapshot.status != ActionStatus::Running
                    || action.page_id.as_ref() != Some(page_id)
                    || action.requester_principal_id != *principal_id
                    || action.approval_id.is_some()
                {
                    return Err(SecretFillError::DispatchRevoked);
                }
                match serde_json::from_slice::<WorkerActionCommand>(&action.payload) {
                    Ok(WorkerActionCommand::FillSecret {
                        node_ref: recorded_node,
                        secret_ref: recorded_ref,
                    }) if recorded_node == node_ref && recorded_ref == secret_ref => {}
                    _ => return Err(SecretFillError::Rejected),
                }
                let permit = action
                    .dispatch_permit
                    .clone()
                    .ok_or(SecretFillError::DispatchRevoked)?;
                (session.tenant_id.clone(), permit)
            };
            if executor.approved_dispatch_phase.load(Ordering::Acquire)
                != APPROVED_DISPATCH_INSPECTING
            {
                return Err(SecretFillError::DispatchRevoked);
            }
            let target = self.driver.inspect_secret_fill_target_until(
                &tenant_id, session_id, page_id, fence, node_ref, deadline,
            )?;
            if target.tenant_id != tenant_id
                || target.session_id != *session_id
                || target.page_id != *page_id
                || target.fence != *fence
                || target.node_ref != node_ref
                || target.target_incarnation == 0
                || target.frame_document_epoch == 0
            {
                return Err(SecretFillError::Rejected);
            }
            let grant = resolver.authorize(
                &tenant_id,
                principal_id,
                secret_ref,
                &target.origin,
                deadline,
            )?;
            if grant.tenant_id() != &tenant_id
                || grant.principal_id() != principal_id
                || grant.secret_ref() != secret_ref
                || grant.origin() != &target.origin
            {
                return Err(SecretFillError::Rejected);
            }
            // Check known revocation before obtaining any value. The final callback repeats this
            // admission under the policy lock, since authorization or I/O may have yielded.
            self.emergency_policy
                .authorize_secret_dispatch(
                    &tenant_id,
                    session_id,
                    secret_ref,
                    &target.origin,
                    || (),
                )
                .map_err(|_| SecretFillError::DispatchRevoked)?;
            self.audit_secret_injection_intent(
                &tenant_id,
                session_id,
                action_id,
                principal_id,
                &grant,
            )?;
            let value_deadline = Instant::now()
                .checked_add(std::time::Duration::from_secs(5))
                .ok_or(SecretFillError::Unavailable)?
                .min(deadline);
            let secret = resolver.resolve(&grant, value_deadline)?;
            if secret.grant() != &grant {
                return Err(SecretFillError::Rejected);
            }
            check_deadline(value_deadline)?;
            if executor
                .approved_dispatch_phase
                .compare_exchange(
                    APPROVED_DISPATCH_INSPECTING,
                    APPROVED_DISPATCH_DRIVER_PENDING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Err(SecretFillError::DispatchRevoked);
            }
            self.driver.execute_secret_fill_until(
                &target,
                secret,
                value_deadline,
                &mut |observed| {
                    if executor
                        .approved_dispatch_phase
                        .compare_exchange(
                            APPROVED_DISPATCH_DRIVER_PENDING,
                            APPROVED_DISPATCH_AUTHORIZING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        return Err(SecretFillError::DispatchRevoked);
                    }
                    let admitted = (|| -> Result<(), SecretFillError> {
                        check_deadline(value_deadline)?;
                        if observed != &target {
                            return Err(SecretFillError::DispatchRevoked);
                        }
                        let session = executor
                            .state
                            .lock()
                            .map_err(|_| SecretFillError::Unavailable)?;
                        validate_fence(&session, fence)
                            .map_err(|_| SecretFillError::DispatchRevoked)?;
                        let snapshot = session.machine.snapshot();
                        let now = self
                            .clock
                            .now()
                            .map_err(|_| SecretFillError::Unavailable)?
                            .max(session.machine.last_observed_at());
                        let expired = [
                            snapshot.lease_expires_at,
                            snapshot.session_expires_at,
                            snapshot.idle_expires_at,
                        ]
                        .into_iter()
                        .flatten()
                        .any(|at| now >= at);
                        let action = session
                            .actions
                            .get(action_id)
                            .ok_or(SecretFillError::DispatchRevoked)?;
                        if expired
                            || snapshot.lifecycle != SessionLifecycle::Ready
                            || snapshot.execution != SessionExecution::Running(action_id.clone())
                            || session.tenant_id != tenant_id
                            || !session.occupies_capacity
                            || !session.pages.contains(page_id)
                            || session.closing_pages.contains(page_id)
                            || action.snapshot.status != ActionStatus::Running
                            || action.requester_principal_id != *principal_id
                            || action.page_id.as_ref() != Some(page_id)
                            || action.dispatch_permit.as_ref() != Some(&permit)
                        {
                            return Err(SecretFillError::DispatchRevoked);
                        }
                        self.emergency_policy
                            .authorize_secret_dispatch(
                                &tenant_id,
                                session_id,
                                secret_ref,
                                &target.origin,
                                || {
                                    effect_started = true;
                                    executor
                                        .approved_dispatch_phase
                                        .store(APPROVED_DISPATCH_STARTED, Ordering::Release);
                                },
                            )
                            .map_err(|_| SecretFillError::DispatchRevoked)?;
                        Ok(())
                    })();
                    if admitted.is_err() {
                        executor
                            .approved_dispatch_phase
                            .store(APPROVED_DISPATCH_AUTHORIZATION_REJECTED, Ordering::Release);
                    }
                    admitted
                },
            )
        })();
        // Every exit releases cancel/close waiters, including metadata, value and audit failures.
        let completion = executor.approved_dispatch_wait.lock().ok();
        executor.approved_dispatch_phase.store(
            if effect_started {
                APPROVED_DISPATCH_RETURNED_UNCERTAIN
            } else {
                APPROVED_DISPATCH_STOPPED
            },
            Ordering::Release,
        );
        executor.approved_dispatch_changed.notify_all();
        drop(completion);
        match execution {
            Ok(ActionExecutionResult::Succeeded(_)) if effect_started => {
                // Only a fixed receipt is allowed back through API/WAL. Neither a browser result
                // nor an implementation's diagnostic can reflect the injected credential.
                ActionExecutionResult::Succeeded(b"{\"ok\":true}".to_vec())
            }
            Ok(ActionExecutionResult::OutcomeUnknown) => ActionExecutionResult::OutcomeUnknown,
            _ if effect_started => ActionExecutionResult::OutcomeUnknown,
            Ok(ActionExecutionResult::Succeeded(_)) => ActionExecutionResult::OutcomeUnknown,
            Ok(ActionExecutionResult::FailedKnown(_)) => {
                ActionExecutionResult::FailedKnown("secret_rejected".to_owned())
            }
            Err(SecretFillError::OutcomeUncertain) => ActionExecutionResult::OutcomeUnknown,
            Err(SecretFillError::DeadlineBeforeDispatch) => {
                ActionExecutionResult::FailedKnown("action_timeout".to_owned())
            }
            Err(SecretFillError::Unavailable) => {
                ActionExecutionResult::FailedKnown("secret_unavailable".to_owned())
            }
            Err(SecretFillError::Rejected | SecretFillError::DispatchRevoked) => {
                ActionExecutionResult::FailedKnown("secret_rejected".to_owned())
            }
        }
    }

    pub(crate) fn audit_secret_injection_intent(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        principal_id: &PrincipalId,
        grant: &SecretGrant,
    ) -> Result<(), SecretFillError> {
        let wal = self
            .audit_wal
            .as_ref()
            .ok_or(SecretFillError::Unavailable)?;
        let id = AuditEventId::new(format!("credential-inject:{action_id}"))
            .map_err(|_| SecretFillError::Unavailable)?;
        let payload = serde_json::to_vec(&serde_json::json!({
            "tenant_id": tenant_id, "session_id": session_id, "action_id": action_id,
            "principal_id": principal_id,
            "secret_ref_hash": format!("{:x}", Sha256::digest(grant.secret_ref().as_bytes())),
            "origin_hash": format!("{:x}", Sha256::digest(grant.origin().as_str().as_bytes())),
        }))
        .map_err(|_| SecretFillError::Unavailable)?;
        let event = AuditEvent::new(id, "credential.inject.intent", payload, true);
        match wal
            .append(event)
            .map_err(|_| SecretFillError::Unavailable)?
        {
            AppendOutcome::Durable(_) | AppendOutcome::Existing(_) => Ok(()),
            AppendOutcome::DroppedNonCritical => Err(SecretFillError::Unavailable),
        }
    }
}

#[cfg(test)]
#[path = "secret_fill_tests.rs"]
mod tests;
