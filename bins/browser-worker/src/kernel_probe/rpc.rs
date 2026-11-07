//! Exact real RPCs plus passive bounded CDP observations; no command injection or fake replies.
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use browserd_core::{LaunchGeneration, SessionId, ShardFence, ShardId, WorkerId};
use browserd_sandbox::{
    ChildIdentity, ChromiumCdpPipes, CleanupReason, ContextEgressBinding,
    ContextEgressReleaseReceipt, ContextEgressRequest, CreateShardOutcome, KillShardOutcome,
    LaunchSpec, RpcFailureCode, SandboxRpcClient, SandboxRpcError,
};
use browserd_worker::{SandboxShardRpc, ShardRuntimeError};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::net::UnixStream;

use super::config::{digest, file_digest};
use super::{ProbeError, ProbeResultValue};
use crate::ProductionSandboxControl;

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_TRACE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TRACE_ENTRIES: usize = 8192;
const MAX_TRACE_FAILURE_ROWS: usize = 16;
const MAX_RPC_FAILURES: usize = 32;
const MAX_CLEANUP_OUTCOMES: usize = 32;
const MAX_REMOTE_MESSAGE_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RpcOperation {
    AttachContextEgress,
    RenewContextEgress,
    ReleaseContextEgress,
    CreateShard,
    CancelOrKillShard,
    ClaimCdpPipes,
    RenewOwnerLease,
    KillShard,
    ProbeDaemonEpoch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BackendFailureCategory {
    NativeProfileCatalog,
    NativeProfileBinding,
    PreparedJournalReserve,
    PreparedJournal,
    ProcessSpawn,
    CgroupDirectory,
    CgroupAttachment,
    CgroupKill,
    CgroupEvents,
    InheritedDescriptor,
    ExecutionGate,
    Bootstrap,
    PidResponse,
    PidIdentity,
    Containment,
    NetworkNamespace,
    ProvisionCleanup,
    EgressControlConfiguration,
    EgressControlTimeout,
    EgressControlPeerIdentity,
    EgressControlProtocol,
    EgressControlTransport,
    EgressListenerInstall,
    EgressRouteState,
    NamespaceCapability,
    NamespaceThread,
    NamespaceEnter,
    NamespaceObserve,
    NamespaceIdentity,
    ListenerBind,
    ListenerConfigure,
    ListenerInspect,
    ListenerAddress,
    NativeNamespaceHelper,
    NativeHelperInput,
    NativeHelperOwnerUserNamespace,
    NativeHelperEnterUserNamespace,
    NativeHelperEnterNetworkNamespace,
    NativeHelperLoopback,
    NativeHelperDropPrivileges,
    NativeHelperBindListener,
    NativeHelperReceipt,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct RpcFailure {
    operation: RpcOperation,
    error_variant: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_code: Option<RpcFailureCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_message: Option<&'static str>,
    remote_message_omitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend_category: Option<BackendFailureCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_errno: Option<u16>,
}

// Retain only literal messages produced by the supervisor. A substring match or
// truncating arbitrary text would still disclose credentials/request contents.
fn safe_remote_message(message: &str) -> Option<&'static str> {
    const SAFE: &[&str] = &[
        "launch generation mismatch",
        "supervisor and directory lease TTLs must be nonzero",
        "sandbox cleanup stage timeout must be nonzero",
        "supervisor lease TTL cannot exceed directory lease TTL",
        "dedicated egress policy binding is invalid",
        "dedicated egress lease TTL must be nonzero and at most five minutes",
        "launch identity does not match the dedicated egress fence",
        "launch immutable binding conflicts with the existing shard",
        "launch spec Chromium binary digest does not match the pinned executable",
        "Chromium process profile syntax or resource identity is invalid",
        "launch spec and owner lease do not identify the same worker epoch",
        "owner lease is expired or exceeds the configured supervisor TTL",
        "sandbox supervisor admission is permanently closed",
        "sandbox shard does not exist",
        "a CDP capability claim is already in progress",
        "the CDP capabilities have already been claimed",
        "the supervisor lease has already expired",
        "the renewed supervisor lease exceeds its configured TTL",
        "the dedicated egress lease could not be renewed",
        "owner lease exceeds the supervisor TTL",
    ];
    SAFE.iter().copied().find(|candidate| {
        *candidate == message && candidate.chars().count() <= MAX_REMOTE_MESSAGE_CHARS
    })
}

fn backend_category(message: &str) -> Option<BackendFailureCategory> {
    let message = message.strip_prefix("sandbox backend failed: ")?;
    if let Some((category, _)) = native_helper_diagnostic(message) {
        return Some(category);
    }
    // These are fixed source prefixes, not returned external strings. Preserve
    // the failing phase while dropping filenames, child stderr and request data.
    const PREFIXES: &[(&str, BackendFailureCategory)] = &[
        (
            "native profile catalog is unavailable",
            BackendFailureCategory::NativeProfileCatalog,
        ),
        (
            "native profile required",
            BackendFailureCategory::NativeProfileBinding,
        ),
        (
            "native profile resource binding mismatch",
            BackendFailureCategory::NativeProfileBinding,
        ),
        (
            "native profile requires a private executable directory",
            BackendFailureCategory::NativeProfileBinding,
        ),
        (
            "prepared journal reserve:",
            BackendFailureCategory::PreparedJournalReserve,
        ),
        ("prepared journal ", BackendFailureCategory::PreparedJournal),
        (
            "prepared process spawn: ",
            BackendFailureCategory::ProcessSpawn,
        ),
        (
            "shared routes require durable journal",
            BackendFailureCategory::PreparedJournal,
        ),
        (
            "sandbox cgroup directory:",
            BackendFailureCategory::CgroupDirectory,
        ),
        (
            "sandbox cgroup path has no parent",
            BackendFailureCategory::CgroupDirectory,
        ),
        (
            "sandbox cgroup attachment:",
            BackendFailureCategory::CgroupAttachment,
        ),
        (
            "sandbox cgroup attachment was incomplete",
            BackendFailureCategory::CgroupAttachment,
        ),
        (
            "sandbox child was not attached to its cgroup",
            BackendFailureCategory::CgroupAttachment,
        ),
        (
            "invalid cgroup.procs membership",
            BackendFailureCategory::CgroupAttachment,
        ),
        ("sandbox cgroup kill:", BackendFailureCategory::CgroupKill),
        (
            "sandbox cgroup events:",
            BackendFailureCategory::CgroupEvents,
        ),
        (
            "required inherited descriptor ",
            BackendFailureCategory::InheritedDescriptor,
        ),
        ("execution gate", BackendFailureCategory::ExecutionGate),
        (
            "scratch execution gate",
            BackendFailureCategory::ExecutionGate,
        ),
        ("bootstrap process ", BackendFailureCategory::Bootstrap),
        ("sandbox bootstrap ", BackendFailureCategory::Bootstrap),
        (
            "sandbox child does not have the exact bootstrap parent",
            BackendFailureCategory::Bootstrap,
        ),
        ("sandbox PID ", BackendFailureCategory::PidResponse),
        (
            "failed to read sandbox PID:",
            BackendFailureCategory::PidResponse,
        ),
        (
            "invalid sandbox PID response:",
            BackendFailureCategory::PidResponse,
        ),
        ("child PID ", BackendFailureCategory::PidIdentity),
        ("invalid child PID ", BackendFailureCategory::PidIdentity),
        ("spawned child PID ", BackendFailureCategory::PidIdentity),
        ("prepared child PID ", BackendFailureCategory::PidIdentity),
        ("sandbox child PID ", BackendFailureCategory::PidIdentity),
        ("sandbox containment ", BackendFailureCategory::Containment),
        (
            "sandbox child network namespace ",
            BackendFailureCategory::NetworkNamespace,
        ),
        (
            "provision cleanup incomplete:",
            BackendFailureCategory::ProvisionCleanup,
        ),
        (
            "prepared child cleanup incomplete;",
            BackendFailureCategory::ProvisionCleanup,
        ),
        (
            "egress control configuration is invalid",
            BackendFailureCategory::EgressControlConfiguration,
        ),
        (
            "egress control request timed out",
            BackendFailureCategory::EgressControlTimeout,
        ),
        (
            "egress control peer UID mismatch:",
            BackendFailureCategory::EgressControlPeerIdentity,
        ),
        (
            "egress control protocol failed:",
            BackendFailureCategory::EgressControlProtocol,
        ),
        (
            "egress control request failed:",
            BackendFailureCategory::EgressControlTransport,
        ),
        (
            "egress listener install outcome requires status reconciliation",
            BackendFailureCategory::EgressListenerInstall,
        ),
        (
            "egress install admission is full",
            BackendFailureCategory::EgressListenerInstall,
        ),
        (
            "egress install owner ",
            BackendFailureCategory::EgressListenerInstall,
        ),
        ("egress route ", BackendFailureCategory::EgressRouteState),
        (
            "egress generation ",
            BackendFailureCategory::EgressRouteState,
        ),
        (
            "egress namespace changed",
            BackendFailureCategory::EgressRouteState,
        ),
        (
            "egress Active receipt ",
            BackendFailureCategory::EgressRouteState,
        ),
        (
            "Active status omitted its receipt",
            BackendFailureCategory::EgressRouteState,
        ),
        (
            "missing exact egress fence",
            BackendFailureCategory::EgressRouteState,
        ),
        (
            "missing egress tenant binding",
            BackendFailureCategory::EgressRouteState,
        ),
        (
            "missing dedicated egress binding",
            BackendFailureCategory::EgressRouteState,
        ),
        (
            "failed to clone the network namespace capability:",
            BackendFailureCategory::NamespaceCapability,
        ),
        (
            "failed to start the dedicated network namespace thread:",
            BackendFailureCategory::NamespaceThread,
        ),
        (
            "the dedicated network namespace thread panicked",
            BackendFailureCategory::NamespaceThread,
        ),
        (
            "failed to enter the pinned network namespace:",
            BackendFailureCategory::NamespaceEnter,
        ),
        (
            "failed to observe the current network namespace:",
            BackendFailureCategory::NamespaceObserve,
        ),
        (
            "network namespace identity mismatch:",
            BackendFailureCategory::NamespaceIdentity,
        ),
        (
            "dedicated listener did not match the pinned namespace",
            BackendFailureCategory::NamespaceIdentity,
        ),
        (
            "failed to bind the dedicated egress listener:",
            BackendFailureCategory::ListenerBind,
        ),
        (
            "failed to configure the dedicated egress listener:",
            BackendFailureCategory::ListenerConfigure,
        ),
        (
            "failed to inspect the dedicated egress listener:",
            BackendFailureCategory::ListenerInspect,
        ),
        (
            "the dedicated egress listener has an invalid local address:",
            BackendFailureCategory::ListenerAddress,
        ),
        (
            "native network namespace helper failed:",
            BackendFailureCategory::NativeNamespaceHelper,
        ),
    ];
    PREFIXES
        .iter()
        .find(|(prefix, _)| message.starts_with(*prefix))
        .map(|(_, category)| *category)
}

fn numeric_errno(digits: &str) -> Option<u16> {
    if digits.is_empty() || digits.len() > 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits
        .parse::<u16>()
        .ok()
        .filter(|code| (1..=4095).contains(code))
}

fn native_helper_diagnostic(message: &str) -> Option<(BackendFailureCategory, Option<u16>)> {
    let message = message.strip_prefix("native network namespace helper failed: stage=")?;
    let (stage, errno) = message.split_once(" errno=")?;
    let errno = if errno == "none" {
        None
    } else {
        Some(numeric_errno(errno)?)
    };
    let category = match stage {
        "input" => BackendFailureCategory::NativeHelperInput,
        "owner_user_namespace" => BackendFailureCategory::NativeHelperOwnerUserNamespace,
        "enter_user_namespace" => BackendFailureCategory::NativeHelperEnterUserNamespace,
        "enter_network_namespace" => BackendFailureCategory::NativeHelperEnterNetworkNamespace,
        "loopback" => BackendFailureCategory::NativeHelperLoopback,
        "drop_privileges" => BackendFailureCategory::NativeHelperDropPrivileges,
        "bind_listener" => BackendFailureCategory::NativeHelperBindListener,
        "receipt" => BackendFailureCategory::NativeHelperReceipt,
        _ => return None,
    };
    Some((category, errno))
}

fn safe_errno(message: &str) -> Option<u16> {
    if let Some((_, errno)) = message
        .strip_prefix("sandbox backend failed: ")
        .and_then(native_helper_diagnostic)
    {
        return errno;
    }
    if let Some((_, suffix)) = message.rsplit_once("(os error ") {
        let digits = suffix.strip_suffix(')')?;
        if let Some(code) = numeric_errno(digits) {
            return Some(code);
        }
    }
    // nix's Errno display starts with a fixed symbolic name rather than an OS
    // numeric suffix. Only inspect the error after a recognized source prefix.
    let symbol = message.rsplit_once(": ").map_or(message, |(prefix, _)| {
        prefix.rsplit_once(": ").map_or(prefix, |(_, tail)| tail)
    });
    match symbol {
        "EPERM" => Some(1),
        "ENOENT" => Some(2),
        "ESRCH" => Some(3),
        "EINTR" => Some(4),
        "EIO" => Some(5),
        "EBADF" => Some(9),
        "EAGAIN" => Some(11),
        "ENOMEM" => Some(12),
        "EACCES" => Some(13),
        "EBUSY" => Some(16),
        "EEXIST" => Some(17),
        "ENOTDIR" => Some(20),
        "EISDIR" => Some(21),
        "EINVAL" => Some(22),
        "ENFILE" => Some(23),
        "EMFILE" => Some(24),
        "ENOSPC" => Some(28),
        "EPIPE" => Some(32),
        "ENOSYS" => Some(38),
        "ELOOP" => Some(40),
        "EOVERFLOW" => Some(75),
        "EOPNOTSUPP" => Some(95),
        "ETIMEDOUT" => Some(110),
        "ECANCELED" => Some(125),
        _ => None,
    }
}

impl RpcFailure {
    fn from_error(operation: RpcOperation, error: &SandboxRpcError) -> Self {
        let error_variant = match error {
            SandboxRpcError::InvalidConfig => "InvalidConfig",
            SandboxRpcError::InvalidLease => "InvalidLease",
            SandboxRpcError::FrameTooLarge => "FrameTooLarge",
            SandboxRpcError::TimedOut => "TimedOut",
            SandboxRpcError::ConnectionClosed => "ConnectionClosed",
            SandboxRpcError::Protocol => "Protocol",
            SandboxRpcError::PeerUidMismatch { .. } => "PeerUidMismatch",
            SandboxRpcError::PeerProcessMismatch => "PeerProcessMismatch",
            SandboxRpcError::InvalidCapabilities(_) => "InvalidCapabilities",
            SandboxRpcError::Serialization(_) => "Serialization",
            SandboxRpcError::Io(_) => "Io",
            SandboxRpcError::Remote { .. } => "Remote",
            SandboxRpcError::ShutdownIncomplete { .. } => "ShutdownIncomplete",
        };
        let mut row = Self {
            operation,
            error_variant,
            remote_code: None,
            remote_message: None,
            remote_message_omitted: false,
            backend_category: None,
            os_errno: None,
        };
        match error {
            SandboxRpcError::Remote { code, message } => {
                row.remote_code = Some(*code);
                row.remote_message = safe_remote_message(message);
                row.remote_message_omitted = row.remote_message.is_none();
                if *code == RpcFailureCode::Backend {
                    row.backend_category = backend_category(message);
                    if row.backend_category.is_some() {
                        row.os_errno = safe_errno(message);
                    }
                }
            }
            SandboxRpcError::Io(message) => row.os_errno = safe_errno(message),
            _ => {}
        }
        row
    }
}

#[derive(Default)]
struct RpcFailures {
    rows: Mutex<VecDeque<RpcFailure>>,
}
impl RpcFailures {
    fn record(&self, operation: RpcOperation, error: &SandboxRpcError) {
        if let Ok(mut rows) = self.rows.lock() {
            rows.push_back(RpcFailure::from_error(operation, error));
            while rows.len() > MAX_RPC_FAILURES {
                rows.pop_front();
            }
        }
    }
    fn snapshot(&self) -> ProbeResultValue<Vec<RpcFailure>> {
        self.rows
            .lock()
            .map(|rows| rows.iter().cloned().collect())
            .map_err(|_| ProbeError::failed("RPC failure diagnostic poisoned"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CleanupOperation {
    CancelOrKillShard,
    KillShard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum CleanupOutcomeVariant {
    Terminated {
        route_revoked: bool,
        cgroup_killed: bool,
        namespaces_cleaned: bool,
    },
    CleanupIncomplete {
        route_revoked: bool,
        cgroup_killed: bool,
        namespaces_cleaned: bool,
    },
    AlreadyTerminated,
    CancellationRequested,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct CleanupOutcome {
    operation: CleanupOperation,
    shard: ShardFence,
    #[serde(flatten)]
    result: CleanupOutcomeVariant,
}

impl CleanupOutcome {
    fn from_result(
        operation: CleanupOperation,
        shard: &ShardFence,
        outcome: KillShardOutcome,
    ) -> Self {
        let result = match outcome {
            KillShardOutcome::Terminated(result) => CleanupOutcomeVariant::Terminated {
                route_revoked: result.route_revoked,
                cgroup_killed: result.cgroup_killed,
                namespaces_cleaned: result.namespaces_cleaned,
            },
            KillShardOutcome::CleanupIncomplete(result) => {
                CleanupOutcomeVariant::CleanupIncomplete {
                    route_revoked: result.route_revoked,
                    cgroup_killed: result.cgroup_killed,
                    namespaces_cleaned: result.namespaces_cleaned,
                }
            }
            KillShardOutcome::AlreadyTerminated => CleanupOutcomeVariant::AlreadyTerminated,
            KillShardOutcome::CancellationRequested => CleanupOutcomeVariant::CancellationRequested,
        };
        Self {
            operation,
            shard: shard.clone(),
            result,
        }
    }
}

#[derive(Default)]
struct CleanupOutcomes {
    rows: Mutex<VecDeque<CleanupOutcome>>,
}
impl CleanupOutcomes {
    fn record(&self, operation: CleanupOperation, shard: &ShardFence, outcome: KillShardOutcome) {
        if let Ok(mut rows) = self.rows.lock() {
            rows.push_back(CleanupOutcome::from_result(operation, shard, outcome));
            while rows.len() > MAX_CLEANUP_OUTCOMES {
                rows.pop_front();
            }
        }
    }
    fn snapshot(&self, shard: &ShardFence) -> ProbeResultValue<Vec<CleanupOutcome>> {
        self.rows
            .lock()
            .map(|rows| {
                rows.iter()
                    .filter(|row| row.shard == *shard)
                    .cloned()
                    .collect()
            })
            .map_err(|_| ProbeError::failed("cleanup outcome diagnostic poisoned"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) enum TraceDirection {
    Command,
    Reply,
    Event,
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct TraceEntry {
    pub sequence: u64,
    pub shard: ShardFence,
    pub direction: TraceDirection,
    pub id: Option<u64>,
    pub session_id: Option<String>,
    pub method: Option<String>,
    pub summary: Value,
}
#[derive(Default)]
struct TraceState {
    rows: VecDeque<(TraceEntry, usize)>,
    sequence: u64,
    dropped: u64,
    bytes: usize,
    invalid: bool,
    command_count: u64,
    reply_count: u64,
    event_count: u64,
}
#[derive(Default)]
pub(super) struct Trace {
    state: Mutex<TraceState>,
}
impl Trace {
    pub fn mark(&self) -> u64 {
        self.state.lock().map_or(u64::MAX, |state| state.sequence)
    }
    pub fn failure_summary(&self) -> Value {
        let Ok(state) = self.state.lock() else {
            return json!({"available":false});
        };
        const METHODS: &[&str] = &[
            "Browser.getVersion",
            "Target.setAutoAttach",
            "Target.setDiscoverTargets",
            "Target.getTargets",
            "Target.createBrowserContext",
            "Target.disposeBrowserContext",
            "Target.createTarget",
            "Target.closeTarget",
            "Target.attachToTarget",
            "Target.attachedToTarget",
            "Target.detachedFromTarget",
            "Target.targetCreated",
            "Target.targetDestroyed",
            "Runtime.runIfWaitingForDebugger",
            "Runtime.enable",
            "Page.enable",
            "Page.getFrameTree",
            "Page.setLifecycleEventsEnabled",
            "Network.enable",
            "Fetch.enable",
            "Browser.setDownloadBehavior",
        ];
        let recent: Vec<Value> = state
            .rows
            .iter()
            .skip(state.rows.len().saturating_sub(MAX_TRACE_FAILURE_ROWS))
            .map(|(entry, _)| {
                let direction = match entry.direction {
                    TraceDirection::Command => "command",
                    TraceDirection::Reply => "reply",
                    TraceDirection::Event => "event",
                };
                let mut row = json!({"sequence":entry.sequence,"direction":direction});
                if let Some(method) = entry
                    .method
                    .as_deref()
                    .and_then(|method| METHODS.iter().copied().find(|known| *known == method))
                {
                    row["method"] = json!(method);
                }
                if entry.direction == TraceDirection::Reply {
                    if let Some(success) = entry.summary.get("success").and_then(Value::as_bool) {
                        row["success"] = json!(success);
                    }
                    if let Some(code) = entry.summary.pointer("/error/code").and_then(Value::as_i64)
                    {
                        row["error_code"] = json!(code);
                    }
                }
                row
            })
            .collect();
        json!({"available":true,"sequence":state.sequence,"invalid":state.invalid,
        "dropped":state.dropped,"record_counts":{
            "command":state.command_count,"reply":state.reply_count,"event":state.event_count},
        "recent":recent})
    }
    pub fn since(&self, mark: u64) -> ProbeResultValue<Vec<TraceEntry>> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProbeError::failed("CDP proof trace poisoned"))?;
        if state.invalid || mark < state.dropped || mark > state.sequence {
            return Err(ProbeError::failed(
                "CDP proof trace is incomplete/truncated",
            ));
        }
        Ok(state
            .rows
            .iter()
            .filter(|(row, _)| row.sequence > mark)
            .map(|(row, _)| row.clone())
            .collect())
    }
    #[cfg(test)]
    pub fn snapshot(&self) -> ProbeResultValue<Vec<TraceEntry>> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProbeError::failed("CDP proof trace poisoned"))?;
        if state.invalid {
            return Err(ProbeError::failed("CDP proof trace invalid"));
        }
        Ok(state.rows.iter().map(|(row, _)| row.clone()).collect())
    }
    fn invalid(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.invalid = true;
        }
    }
    fn record(&self, shard: &ShardFence, outgoing: bool, bytes: &[u8]) {
        let Ok(mut summary) = serde_json::from_slice::<Value>(bytes) else {
            self.invalid();
            return;
        };
        if !summary.is_object() {
            self.invalid();
            return;
        }
        let id = summary.get("id").and_then(Value::as_u64);
        let method = summary
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let direction = if outgoing {
            TraceDirection::Command
        } else if id.is_some() {
            TraceDirection::Reply
        } else {
            TraceDirection::Event
        };
        let session_id = summary
            .get("sessionId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if direction == TraceDirection::Reply {
            summary["success"] =
                Value::Bool(summary.get("error").is_none() && summary.get("result").is_some());
        }
        for pointer in ["/result/data", "/params/data"] {
            let Some(data) = summary
                .pointer(pointer)
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let base64_encoded = pointer == "/params/data"
                || summary
                    .pointer("/result/base64Encoded")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            let decoded = if base64_encoded {
                base64::engine::general_purpose::STANDARD.decode(data.as_bytes())
            } else {
                Ok(data.into_bytes())
            };
            let Ok(decoded) = decoded else {
                self.invalid();
                return;
            };
            let parent = if pointer == "/result/data" {
                "result"
            } else {
                "params"
            };
            if let Some(object) = summary.get_mut(parent).and_then(Value::as_object_mut) {
                object.remove("data");
                object.insert("data_bytes".into(), json!(decoded.len()));
                object.insert("data_sha256".into(), json!(digest(&decoded)));
            }
        }
        let Ok(encoded) = serde_json::to_vec(&summary) else {
            self.invalid();
            return;
        };
        if encoded.len() > 256 * 1024 {
            self.invalid();
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.sequence = state.sequence.saturating_add(1);
        match direction {
            TraceDirection::Command => state.command_count = state.command_count.saturating_add(1),
            TraceDirection::Reply => state.reply_count = state.reply_count.saturating_add(1),
            TraceDirection::Event => state.event_count = state.event_count.saturating_add(1),
        }
        let sequence = state.sequence;
        state.bytes = state.bytes.saturating_add(encoded.len());
        state.rows.push_back((
            TraceEntry {
                sequence,
                shard: shard.clone(),
                direction,
                id,
                session_id,
                method,
                summary,
            },
            encoded.len(),
        ));
        while state.rows.len() > MAX_TRACE_ENTRIES || state.bytes > MAX_TRACE_BYTES {
            if let Some((row, size)) = state.rows.pop_front() {
                state.dropped = row.sequence;
                state.bytes = state.bytes.saturating_sub(size);
            } else {
                break;
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct PeerPin {
    pub identity: ChildIdentity,
    pub executable_sha256: String,
}
pub(super) fn process_start(pid: u32) -> ProbeResultValue<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| ProbeError::blocked("pinned peer process unavailable"))?;
    stat.rsplit_once(") ")
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ProbeError::blocked("pinned process start identity unavailable"))
}
pub(super) async fn pin_peer(
    socket: &Path,
    uid: u32,
    executable: &Path,
) -> ProbeResultValue<PeerPin> {
    let stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(socket))
        .await
        .map_err(|_| ProbeError::blocked("approved daemon socket timed out"))?
        .map_err(|_| ProbeError::blocked("approved daemon socket unavailable"))?;
    let peer = stream
        .peer_cred()
        .map_err(|_| ProbeError::blocked("daemon peer credentials unavailable"))?;
    let pid = peer
        .pid()
        .and_then(|p| u32::try_from(p).ok())
        .ok_or_else(|| ProbeError::blocked("daemon peer PID unavailable"))?;
    if peer.uid() != uid {
        return Err(ProbeError::blocked("approved daemon UID mismatch"));
    }
    let start = process_start(pid)?;
    let expected = file_digest(executable)?;
    let actual = file_digest(Path::new(&format!("/proc/{pid}/exe")))?;
    if expected != actual || start != process_start(pid)? {
        return Err(ProbeError::blocked(
            "actual daemon executable/identity differs from approved asset",
        ));
    }
    Ok(PeerPin {
        identity: ChildIdentity::new(pid, start),
        executable_sha256: actual,
    })
}

pub(super) struct RecordingSandboxRpc {
    pub client: SandboxRpcClient,
    pub pin: PeerPin,
    pub trace: Arc<Trace>,
    specs: Mutex<Vec<LaunchSpec>>,
    cleaned: Mutex<BTreeMap<ShardFence, Value>>,
    launch_log: Mutex<Option<(File, Value)>>,
    threads: Mutex<Vec<(ShardFence, JoinHandle<()>)>>,
    failures: RpcFailures,
    cleanup_outcomes: CleanupOutcomes,
    deadline: Instant,
}
impl RecordingSandboxRpc {
    pub fn new(
        client: SandboxRpcClient,
        pin: PeerPin,
        trace: Arc<Trace>,
        deadline: Instant,
    ) -> Self {
        Self {
            client: client.with_expected_server_identity(pin.identity),
            pin,
            trace,
            specs: Mutex::new(Vec::new()),
            cleaned: Mutex::new(BTreeMap::new()),
            launch_log: Mutex::new(None),
            threads: Mutex::new(Vec::new()),
            failures: RpcFailures::default(),
            cleanup_outcomes: CleanupOutcomes::default(),
            deadline,
        }
    }
    pub fn specs(&self) -> ProbeResultValue<Vec<LaunchSpec>> {
        self.specs
            .lock()
            .map(|s| s.clone())
            .map_err(|_| ProbeError::failed("launch proof poisoned"))
    }
    pub fn spec_count(&self) -> ProbeResultValue<usize> {
        self.specs
            .lock()
            .map(|specs| specs.len())
            .map_err(|_| ProbeError::failed("launch proof poisoned"))
    }
    pub fn rpc_failures(&self) -> ProbeResultValue<Vec<RpcFailure>> {
        self.failures.snapshot()
    }
    pub fn cleanup_outcomes(&self, shard: &ShardFence) -> ProbeResultValue<Vec<CleanupOutcome>> {
        self.cleanup_outcomes.snapshot(shard)
    }
    fn map_error(&self, operation: RpcOperation, error: SandboxRpcError) -> ShardRuntimeError {
        self.failures.record(operation, &error);
        ShardRuntimeError::OutcomeUncertain
    }
    pub fn cleanup_proof(&self, shard: &ShardFence) -> ProbeResultValue<Option<Value>> {
        self.cleaned
            .lock()
            .map(|cleaned| cleaned.get(shard).cloned())
            .map_err(|_| ProbeError::failed("cleanup inventory poisoned"))
    }
    pub fn retain_cleanup_proof(&self, shard: &ShardFence, proof: &Value) -> ProbeResultValue<()> {
        self.cleaned
            .lock()
            .map_err(|_| ProbeError::failed("cleanup inventory poisoned"))?
            .insert(shard.clone(), proof.clone());
        Ok(())
    }
    pub fn record_child_launches(&self, specs: &[LaunchSpec]) -> ProbeResultValue<()> {
        let mut recorded = self
            .specs
            .lock()
            .map_err(|_| ProbeError::failed("launch proof poisoned"))?;
        for spec in specs {
            if !recorded.contains(spec) {
                recorded.push(spec.clone());
            }
        }
        Ok(())
    }
    pub fn enable_launch_log(&self, path: &Path, binding: Value) -> ProbeResultValue<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| ProbeError::failed("private child launch inventory unavailable"))?;
        file.sync_all()
            .and_then(|()| {
                File::open(
                    path.parent()
                        .ok_or_else(|| std::io::Error::other("inventory parent absent"))?,
                )
                .and_then(|directory| directory.sync_all())
            })
            .map_err(|_| {
                ProbeError::failed("private child launch inventory durability unavailable")
            })?;
        *self
            .launch_log
            .lock()
            .map_err(|_| ProbeError::failed("launch inventory poisoned"))? = Some((file, binding));
        Ok(())
    }
    pub fn spec_for_session(&self, session: &SessionId) -> ProbeResultValue<LaunchSpec> {
        self.specs()?
            .into_iter()
            .rev()
            .find(|s| s.dedicated_egress().egress_fence().session_id() == session)
            .ok_or_else(|| ProbeError::failed("actual launch does not match owned session"))
    }
    pub fn spec_for_shard(&self, shard: &ShardFence) -> ProbeResultValue<LaunchSpec> {
        self.specs()?
            .into_iter()
            .find(|s| s.dedicated_egress().egress_fence().shard() == shard)
            .ok_or_else(|| {
                ProbeError::failed("actual launch does not match exact shard generation")
            })
    }
    pub fn join_tees(&self, shard: Option<&ShardFence>) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let Ok(mut handles) = self.threads.lock() else {
                return false;
            };
            let mut index = 0;
            while index < handles.len() {
                if shard.is_none_or(|wanted| wanted == &handles[index].0)
                    && handles[index].1.is_finished()
                {
                    if handles.swap_remove(index).1.join().is_err() {
                        return false;
                    }
                } else {
                    index += 1;
                }
            }
            if !handles
                .iter()
                .any(|(fence, _)| shard.is_none_or(|wanted| wanted == fence))
            {
                return true;
            }
            drop(handles);
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn tee(
        &self,
        mut pipes: ChromiumCdpPipes,
        shard: ShardFence,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        let binding = pipes
            .egress_proxy_binding()
            .cloned()
            .ok_or(ShardRuntimeError::Rejected)?;
        let scratch = pipes.take_scratch();
        let (actual_writer, actual_reader) = pipes.into_owned_fds();
        let (command_reader, command_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        let (event_reader, event_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        let mut observed = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
            .map_err(|_| ShardRuntimeError::Rejected)?
            .with_egress_proxy_binding(binding)
            .map_err(|_| ShardRuntimeError::Rejected)?;
        if let Some(scratch) = scratch {
            observed = observed
                .with_scratch(scratch)
                .map_err(|_| ShardRuntimeError::Rejected)?;
        }
        let mut handles = self
            .threads
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        for (reader, writer, outgoing) in [
            (command_reader, actual_writer, true),
            (actual_reader, event_writer, false),
        ] {
            let trace = Arc::clone(&self.trace);
            let fence = shard.clone();
            let deadline = self.deadline;
            let task = std::thread::Builder::new()
                .name("kernel-cdp-observer".into())
                .spawn(move || {
                    forward(
                        File::from(reader),
                        File::from(writer),
                        trace,
                        fence,
                        outgoing,
                        deadline,
                    )
                })
                .map_err(|_| ShardRuntimeError::Unavailable)?;
            handles.push((shard.clone(), task));
        }
        Ok(observed)
    }
}
fn forward(
    mut reader: File,
    mut writer: File,
    trace: Arc<Trace>,
    shard: ShardFence,
    outgoing: bool,
    deadline: Instant,
) {
    let mut frame = Vec::new();
    let mut buffer = [0; 65536];
    for fd in [reader.as_raw_fd(), writer.as_raw_fd()] {
        // Only this observer owns these endpoints. Partial writes remain byte-for-byte identical.
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        if flags < 0
            || unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) }
                < 0
        {
            trace.invalid();
            return;
        }
    }
    loop {
        if Instant::now() >= deadline {
            trace.invalid();
            return;
        }
        if !wait_fd(reader.as_raw_fd(), nix::libc::POLLIN, deadline) {
            trace.invalid();
            return;
        }
        let count = match reader.read(&mut buffer) {
            Ok(0) => {
                if !frame.is_empty() {
                    trace.invalid();
                }
                return;
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(_) => {
                trace.invalid();
                return;
            }
        };
        for byte in &buffer[..count] {
            if *byte == 0 {
                trace.record(&shard, outgoing, &frame);
                frame.clear();
            } else {
                if frame.len() >= MAX_FRAME_BYTES {
                    trace.invalid();
                    return;
                }
                frame.push(*byte);
            }
        }
        let mut written = 0;
        while written < count {
            if !wait_fd(writer.as_raw_fd(), nix::libc::POLLOUT, deadline) {
                trace.invalid();
                return;
            }
            match writer.write(&buffer[written..count]) {
                Ok(0) => {
                    trace.invalid();
                    return;
                }
                Ok(n) => written += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                // Closing an exact disposed owner is expected; retain all already observed frames.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return,
                Err(_) => {
                    trace.invalid();
                    return;
                }
            }
        }
    }
}
fn wait_fd(fd: i32, events: i16, deadline: Instant) -> bool {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let mut descriptor = nix::libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let millis = i32::try_from(remaining.as_millis().min(100))
            .unwrap_or(100)
            .max(1);
        let result = unsafe { nix::libc::poll(&mut descriptor, 1, millis) };
        if result > 0 {
            return descriptor.revents & (events | nix::libc::POLLHUP | nix::libc::POLLERR) != 0;
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
    }
}
#[async_trait]
impl SandboxShardRpc for RecordingSandboxRpc {
    async fn attach_context_egress(
        &self,
        r: &ContextEgressRequest,
    ) -> Result<ContextEgressBinding, ShardRuntimeError> {
        self.client
            .attach_context_egress(r)
            .await
            .map_err(|error| self.map_error(RpcOperation::AttachContextEgress, error))
    }
    async fn renew_context_egress(
        &self,
        b: &ContextEgressBinding,
        t: Duration,
    ) -> Result<(), ShardRuntimeError> {
        self.client
            .renew_context_egress(b, t)
            .await
            .map_err(|error| self.map_error(RpcOperation::RenewContextEgress, error))
    }
    async fn release_context_egress(
        &self,
        r: &ContextEgressRequest,
    ) -> Result<ContextEgressReleaseReceipt, ShardRuntimeError> {
        self.client
            .release_context_egress(r)
            .await
            .map_err(|error| self.map_error(RpcOperation::ReleaseContextEgress, error))
    }
    async fn create_shard(
        &self,
        s: LaunchSpec,
        t: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        {
            let mut log = self
                .launch_log
                .lock()
                .map_err(|_| ShardRuntimeError::Unavailable)?;
            if let Some((file, binding)) = log.as_mut() {
                let mut bytes = serde_json::to_vec(&json!({"binding":binding,"spec":s}))
                    .map_err(|_| ShardRuntimeError::Rejected)?;
                bytes.push(b'\n');
                file.write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| ShardRuntimeError::Unavailable)?;
            }
        }
        self.specs
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .push(s.clone());
        self.client
            .create_shard(s, t)
            .await
            .map_err(|error| self.map_error(RpcOperation::CreateShard, error))
    }
    async fn cancel_or_kill_shard(
        &self,
        s: &LaunchSpec,
        r: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        let result = self.client.cancel_or_kill_shard(s, r).await;
        if let Ok(outcome) = &result {
            self.cleanup_outcomes.record(
                CleanupOperation::CancelOrKillShard,
                s.dedicated_egress().egress_fence().shard(),
                *outcome,
            );
        }
        result.map_err(|error| self.map_error(RpcOperation::CancelOrKillShard, error))
    }
    async fn claim_cdp_pipes(
        &self,
        id: &ShardId,
        w: &WorkerId,
        e: u64,
        g: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        let pipes = self
            .client
            .claim_cdp_pipes(id, w, e, g)
            .await
            .map_err(|error| self.map_error(RpcOperation::ClaimCdpPipes, error))?;
        let fence = self
            .specs
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .iter()
            .find(|s| s.shard_id() == id && s.launch_generation() == g)
            .map(|s| s.dedicated_egress().egress_fence().shard().clone())
            .ok_or(ShardRuntimeError::Rejected)?;
        self.tee(pipes, fence)
    }
    async fn renew_owner_lease(
        &self,
        id: &ShardId,
        e: u64,
        g: LaunchGeneration,
        t: Duration,
    ) -> Result<(), ShardRuntimeError> {
        self.client
            .renew_owner_lease(id, e, g, t)
            .await
            .map_err(|error| self.map_error(RpcOperation::RenewOwnerLease, error))
    }
    async fn kill_shard(
        &self,
        id: &ShardId,
        e: u64,
        g: LaunchGeneration,
        r: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        let result = self.client.kill_shard(id, e, g, r).await;
        if let Ok(outcome) = &result {
            let shard = self.specs.lock().ok().and_then(|specs| {
                specs
                    .iter()
                    .find(|spec| {
                        spec.shard_id() == id
                            && spec.launch_generation() == g
                            && spec
                                .dedicated_egress()
                                .egress_fence()
                                .shard()
                                .owner()
                                .worker_epoch()
                                .get()
                                == e
                    })
                    .map(|spec| spec.dedicated_egress().egress_fence().shard().clone())
            });
            if let Some(shard) = shard {
                self.cleanup_outcomes
                    .record(CleanupOperation::KillShard, &shard, *outcome);
            }
        }
        result.map_err(|error| self.map_error(RpcOperation::KillShard, error))
    }
}
#[async_trait]
impl ProductionSandboxControl for RecordingSandboxRpc {
    async fn probe_daemon_epoch(&self, w: &WorkerId, e: u64) -> Result<u64, ShardRuntimeError> {
        self.client
            .probe_daemon_epoch(w, e)
            .await
            .map_err(|error| self.map_error(RpcOperation::ProbeDaemonEpoch, error))
    }
}

#[cfg(test)]
mod forwarding_tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use browserd_core::{OwnerFence, WorkerEpoch};
    fn shard() -> ShardFence {
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new("kernel-trace-test").expect("worker"),
                WorkerEpoch::new(1).expect("epoch"),
            ),
            ShardId::new(),
            LaunchGeneration::new(1).expect("generation"),
        )
    }

    #[test]
    fn cleanup_outcome_keeps_all_actual_terminal_and_pending_variants_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = shard();
        let complete = browserd_sandbox::CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        };
        for (outcome, expected, has_progress) in [
            (KillShardOutcome::Terminated(complete), "terminated", true),
            (
                KillShardOutcome::CleanupIncomplete(complete),
                "cleanup_incomplete",
                true,
            ),
            (
                KillShardOutcome::AlreadyTerminated,
                "already_terminated",
                false,
            ),
            (
                KillShardOutcome::CancellationRequested,
                "cancellation_requested",
                false,
            ),
        ] {
            let row =
                CleanupOutcome::from_result(CleanupOperation::CancelOrKillShard, &fence, outcome);
            let value = serde_json::to_value(&row)?;
            assert_eq!(value["outcome"], expected);
            assert_eq!(value["operation"], "cancel_or_kill_shard");
            assert_eq!(value["shard"], serde_json::to_value(&fence)?);
            for key in ["route_revoked", "cgroup_killed", "namespaces_cleaned"] {
                assert_eq!(value.get(key).is_some(), has_progress);
            }
        }
        Ok(())
    }

    #[test]
    fn incomplete_cleanup_retains_each_actual_boolean_without_inferring_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = shard();
        for flags in 0..8 {
            let progress = browserd_sandbox::CleanupResult {
                route_revoked: flags & 1 != 0,
                cgroup_killed: flags & 2 != 0,
                namespaces_cleaned: flags & 4 != 0,
            };
            let row = CleanupOutcome::from_result(
                CleanupOperation::KillShard,
                &fence,
                KillShardOutcome::CleanupIncomplete(progress),
            );
            let value = serde_json::to_value(row)?;
            assert_eq!(value["outcome"], "cleanup_incomplete");
            assert_eq!(value["operation"], "kill_shard");
            assert_eq!(value["route_revoked"], progress.route_revoked);
            assert_eq!(value["cgroup_killed"], progress.cgroup_killed);
            assert_eq!(value["namespaces_cleaned"], progress.namespaces_cleaned);
            assert_eq!(value.as_object().ok_or("typed outcome object")?.len(), 6);
        }
        Ok(())
    }

    #[test]
    fn cleanup_outcomes_keep_only_last_32_and_isolate_exact_owner_and_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = shard();
        let second = ShardFence::new(
            first.owner().clone(),
            first.shard_id().clone(),
            LaunchGeneration::new(2).ok_or("generation")?,
        );
        let foreign_owner = ShardFence::new(
            OwnerFence::new(
                WorkerId::new("foreign-cleanup-owner")?,
                WorkerEpoch::new(1).ok_or("epoch")?,
            ),
            first.shard_id().clone(),
            first.launch_generation(),
        );
        let outcomes = CleanupOutcomes::default();
        for index in 0..64 {
            outcomes.record(
                CleanupOperation::CancelOrKillShard,
                if index % 2 == 0 { &first } else { &second },
                if index < 32 {
                    KillShardOutcome::CancellationRequested
                } else {
                    KillShardOutcome::AlreadyTerminated
                },
            );
        }
        let rows = outcomes
            .rows
            .lock()
            .map_err(|_| "cleanup diagnostic lock")?;
        assert_eq!(rows.len(), MAX_CLEANUP_OUTCOMES);
        drop(rows);
        for fence in [&first, &second] {
            let rows = outcomes
                .snapshot(fence)
                .map_err(|error| error.reason().to_owned())?;
            assert_eq!(rows.len(), 16);
            assert!(
                rows.iter().all(|row| row.shard == *fence
                    && row.result == CleanupOutcomeVariant::AlreadyTerminated)
            );
        }
        assert!(
            outcomes
                .snapshot(&foreign_owner)
                .map_err(|error| error.reason().to_owned())?
                .is_empty()
        );
        Ok(())
    }
    #[test]
    fn passive_trace_records_exact_join_and_decoded_bytes_without_payload() {
        let trace = Trace::default();
        let fence = shard();
        trace.record(
            &fence,
            true,
            br#"{"id":7,"sessionId":"owned-flat","method":"IO.read","params":{"handle":"stream"}}"#,
        );
        trace.record(&fence,false,br#"{"id":7,"sessionId":"owned-flat","result":{"data":"aGVsbG8=","base64Encoded":true,"eof":true}}"#);
        let rows = trace.since(0).expect("complete frames");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].shard, rows[1].shard);
        assert_eq!(rows[0].session_id, rows[1].session_id);
        assert_eq!(rows[1].summary.get("success"), Some(&json!(true)));
        assert_eq!(
            rows[1].summary.pointer("/result/data_bytes"),
            Some(&json!(5))
        );
        assert_eq!(
            rows[1].summary.pointer("/result/data_sha256"),
            Some(&json!(digest(b"hello")))
        );
        assert!(rows[1].summary.pointer("/result/data").is_none());
    }
    #[test]
    fn trace_overflow_and_malformed_frames_fail_closed() {
        let trace = Trace::default();
        let fence = shard();
        for _ in 0..=MAX_TRACE_ENTRIES {
            trace.record(
                &fence,
                false,
                br#"{"method":"Target.targetCreated","params":{}}"#,
            );
        }
        assert!(trace.since(0).is_err());
        assert_eq!(
            trace.snapshot().expect("retained window").len(),
            MAX_TRACE_ENTRIES
        );
        let diagnostic = trace.failure_summary();
        assert_eq!(diagnostic["dropped"], 1);
        assert_eq!(diagnostic["record_counts"]["event"], MAX_TRACE_ENTRIES + 1);
        assert_eq!(
            diagnostic["recent"].as_array().map(Vec::len),
            Some(MAX_TRACE_FAILURE_ROWS)
        );
        trace.record(&fence, false, b"truncated-json");
        assert!(trace.snapshot().is_err());
    }
    #[test]
    fn passive_forwarding_partial_frames_is_byte_identical_and_stalled_write_is_bounded() {
        let (input_reader, input_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("input pipe");
        let (output_reader, output_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("output pipe");
        let trace = Arc::new(Trace::default());
        let observed = Arc::clone(&trace);
        let fence = shard();
        let forwarding = std::thread::spawn(move || {
            forward(
                File::from(input_reader),
                File::from(output_writer),
                observed,
                fence,
                true,
                Instant::now() + Duration::from_secs(1),
            )
        });
        let bytes = b"{\"id\":1,\"method\":\"Target.getTargets\"}\0";
        let mut input = File::from(input_writer);
        input.write_all(&bytes[..11]).expect("first fragment");
        input.write_all(&bytes[11..]).expect("second fragment");
        drop(input);
        let mut output = Vec::new();
        File::from(output_reader)
            .read_to_end(&mut output)
            .expect("forwarded EOF");
        forwarding.join().expect("observer joined");
        assert_eq!(output, bytes);
        assert_eq!(trace.since(0).expect("frame").len(), 1);
        let (input_reader, input_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("input");
        let (_output_reader, output_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("stalled output");
        let trace = Arc::new(Trace::default());
        let observed = Arc::clone(&trace);
        let fence = shard();
        let start = Instant::now();
        let forwarding = std::thread::spawn(move || {
            forward(
                File::from(input_reader),
                File::from(output_writer),
                observed,
                fence,
                true,
                Instant::now() + Duration::from_millis(100),
            )
        });
        let producer = std::thread::spawn(move || {
            let _ = File::from(input_writer).write_all(&vec![b'x'; 65536]);
        });
        forwarding.join().expect("deadline closed observer");
        producer.join().expect("producer released");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(trace.snapshot().is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserd_core::{OwnerFence, WorkerEpoch};

    fn shard() -> Result<ShardFence, Box<dyn std::error::Error>> {
        Ok(ShardFence::new(
            OwnerFence::new(
                WorkerId::new("probe-trace-test")?,
                WorkerEpoch::new(1).ok_or("invalid fixture epoch")?,
            ),
            ShardId::new(),
            LaunchGeneration::new(1).ok_or("invalid fixture launch generation")?,
        ))
    }

    #[test]
    fn failure_summary_contains_only_fixed_cdp_metadata_without_external_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let trace = Trace::default();
        let fence = shard()?;
        let secret = "fixture-cdp-credential-session-and-payload";
        for (outgoing, frame) in [
            (
                true,
                json!({"id":1,"method":"Browser.getVersion","sessionId":secret,"params":{"token":secret}}),
            ),
            (
                false,
                json!({"id":1,"sessionId":secret,"result":{"userAgent":secret}}),
            ),
            (
                false,
                json!({"id":2,"error":{"code":-32000,"message":secret,"data":secret}}),
            ),
            (
                false,
                json!({"method":"Target.targetCreated","params":{"url":format!("http://127.0.0.1/{secret}")}}),
            ),
            (
                true,
                json!({"id":3,"method":format!("Browser.{secret}"),"params":{"payload":secret}}),
            ),
        ] {
            trace.record(&fence, outgoing, &serde_json::to_vec(&frame)?);
        }
        let summary = trace.failure_summary();
        assert_eq!(
            summary["record_counts"],
            json!({"command":2,"reply":2,"event":1})
        );
        assert_eq!(summary["sequence"], 5);
        assert_eq!(summary["invalid"], false);
        assert_eq!(summary["recent"][0]["method"], "Browser.getVersion");
        assert_eq!(summary["recent"][1]["success"], true);
        assert_eq!(summary["recent"][2]["success"], false);
        assert_eq!(summary["recent"][2]["error_code"], -32000);
        assert_eq!(summary["recent"][3]["method"], "Target.targetCreated");
        assert!(summary["recent"][4].get("method").is_none());
        let encoded = serde_json::to_string(&summary)?;
        for omitted in [
            secret,
            "127.0.0.1",
            "params",
            "sessionId",
            "payload",
            "userAgent",
            "message",
        ] {
            assert!(!encoded.contains(omitted));
        }
        Ok(())
    }

    #[test]
    fn failure_summary_recent_window_is_bounded_without_resetting_failure_or_counts()
    -> Result<(), Box<dyn std::error::Error>> {
        let trace = Trace::default();
        let empty = trace.failure_summary();
        assert_eq!(
            empty["record_counts"],
            json!({"command":0,"reply":0,"event":0})
        );
        let fence = shard()?;
        for id in 1..=MAX_TRACE_FAILURE_ROWS * 4 {
            trace.record(
                &fence,
                true,
                &serde_json::to_vec(&json!({"id":id,"method":"Browser.getVersion"}))?,
            );
        }
        trace.record(&fence, false, b"invalid-json-fixture");
        let summary = trace.failure_summary();
        let recent = summary["recent"]
            .as_array()
            .ok_or("diagnostic rows absent")?;
        assert_eq!(recent.len(), MAX_TRACE_FAILURE_ROWS);
        assert_eq!(
            recent.first().and_then(|row| row["sequence"].as_u64()),
            Some(49)
        );
        assert_eq!(
            recent.last().and_then(|row| row["sequence"].as_u64()),
            Some(64)
        );
        assert_eq!(summary["record_counts"]["command"], 64);
        assert_eq!(summary["sequence"], 64);
        assert_eq!(summary["invalid"], true);
        assert_eq!(summary["dropped"], 0);
        assert!(trace.since(0).is_err());
        Ok(())
    }

    #[test]
    fn rpc_failures_retain_only_the_last_32_actual_error_summaries()
    -> Result<(), Box<dyn std::error::Error>> {
        let failures = RpcFailures::default();
        for index in 1..=MAX_RPC_FAILURES * 2 {
            failures.record(
                RpcOperation::CreateShard,
                &SandboxRpcError::Remote {
                    code: RpcFailureCode::Backend,
                    message: format!(
                        "sandbox backend failed: sandbox cgroup directory: fixture (os error {index})"
                    ),
                },
            );
        }
        let rows = failures
            .snapshot()
            .map_err(|error| error.reason().to_owned())?;
        assert_eq!(rows.len(), MAX_RPC_FAILURES);
        assert_eq!(rows.first().and_then(|row| row.os_errno), Some(33));
        assert_eq!(rows.last().and_then(|row| row.os_errno), Some(64));
        assert!(
            rows.iter()
                .all(|row| row.operation == RpcOperation::CreateShard)
        );
        assert!(rows.iter().all(|row| row.error_variant == "Remote"));
        assert!(
            rows.iter()
                .all(|row| row.remote_code == Some(RpcFailureCode::Backend))
        );
        assert!(rows.iter().all(|row| row.remote_message.is_none()));
        assert!(rows.iter().all(|row| row.remote_message_omitted));
        Ok(())
    }

    #[test]
    fn rpc_diagnostics_omit_sensitive_external_text_including_known_prefix_details()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "fixture-credential-request-payload-never-retain";
        let external = format!(
            "/private/{secret} {}",
            "x".repeat(MAX_REMOTE_MESSAGE_CHARS * 4)
        );
        let failures = RpcFailures::default();
        for error in [
            SandboxRpcError::Io(format!("{external} (os error 24)")),
            SandboxRpcError::Serialization(external.clone()),
            SandboxRpcError::InvalidCapabilities(external.clone()),
            SandboxRpcError::Remote {
                code: RpcFailureCode::Backend,
                message: external.clone(),
            },
            SandboxRpcError::Remote {
                code: RpcFailureCode::Backend,
                message: format!(
                    "sandbox backend failed: prepared journal reserve: {external} (os error 13)"
                ),
            },
            SandboxRpcError::Remote {
                code: RpcFailureCode::InvalidLease,
                message: format!("owner lease exceeds the supervisor TTL {external}"),
            },
        ] {
            failures.record(RpcOperation::CreateShard, &error);
        }
        let rows = failures
            .snapshot()
            .map_err(|error| error.reason().to_owned())?;
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[0].os_errno, Some(24));
        assert_eq!(
            rows[4].backend_category,
            Some(BackendFailureCategory::PreparedJournalReserve)
        );
        assert_eq!(rows[4].os_errno, Some(13));
        assert!(rows.iter().all(|row| row.remote_message.is_none()));
        let encoded = serde_json::to_string(&rows)?;
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("/private/"));
        assert!(!encoded.contains("request_payload"));
        let literal = RpcFailure::from_error(
            RpcOperation::AttachContextEgress,
            &SandboxRpcError::Remote {
                code: RpcFailureCode::InvalidEgressPolicyBinding,
                message: "dedicated egress policy binding is invalid".into(),
            },
        );
        assert_eq!(
            literal.remote_message,
            Some("dedicated egress policy binding is invalid")
        );
        assert!(!literal.remote_message_omitted);
        assert!(
            literal
                .remote_message
                .is_some_and(|message| message.chars().count() <= MAX_REMOTE_MESSAGE_CHARS)
        );
        Ok(())
    }

    #[test]
    fn backend_phases_and_errno_are_typed_without_retaining_external_messages() {
        for (message, category) in [
            (
                "native profile catalog is unavailable",
                BackendFailureCategory::NativeProfileCatalog,
            ),
            (
                "prepared journal reserve: external",
                BackendFailureCategory::PreparedJournalReserve,
            ),
            (
                "prepared process spawn: EAGAIN: Resource temporarily unavailable",
                BackendFailureCategory::ProcessSpawn,
            ),
            (
                "sandbox cgroup attachment: external",
                BackendFailureCategory::CgroupAttachment,
            ),
            (
                "required inherited descriptor is not open: EBADF: Bad file descriptor",
                BackendFailureCategory::InheritedDescriptor,
            ),
            (
                "execution gate socket: external",
                BackendFailureCategory::ExecutionGate,
            ),
            (
                "bootstrap process pidfd unavailable; child quarantined: external",
                BackendFailureCategory::Bootstrap,
            ),
            (
                "invalid sandbox PID response: external",
                BackendFailureCategory::PidResponse,
            ),
            (
                "sandbox containment changed before activation",
                BackendFailureCategory::Containment,
            ),
        ] {
            let row = RpcFailure::from_error(
                RpcOperation::CreateShard,
                &SandboxRpcError::Remote {
                    code: RpcFailureCode::Backend,
                    message: format!("sandbox backend failed: {message}"),
                },
            );
            assert_eq!(row.backend_category, Some(category));
            assert!(row.remote_message.is_none());
            if category == BackendFailureCategory::InheritedDescriptor {
                assert_eq!(row.os_errno, Some(9));
            } else if category == BackendFailureCategory::ProcessSpawn {
                assert_eq!(row.os_errno, Some(11));
            }
        }
        for malformed in [
            "external (os error 0)",
            "external (os error 4096)",
            "external (os error +13)",
            "external (os error 13) extra",
        ] {
            assert_eq!(safe_errno(malformed), None);
        }
    }

    #[test]
    fn process_spawn_diagnostics_serialize_only_fixed_category_and_numeric_errno()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "fixture-spawn-credential-request-payload";
        for (detail, append_secret, errno) in [
            (
                "Resource temporarily unavailable (os error 11)",
                false,
                Some(11),
            ),
            ("Too many open files (os error 24)", false, Some(24)),
            ("EAGAIN: Resource temporarily unavailable", true, Some(11)),
            ("EMFILE: Too many open files", true, Some(24)),
            ("Resource temporarily unavailable (os error 11)", true, None),
        ] {
            let suffix = if append_secret {
                format!(" credential={secret}")
            } else {
                String::new()
            };
            let message =
                format!("sandbox backend failed: prepared process spawn: {detail}{suffix}");
            let row = RpcFailure::from_error(
                RpcOperation::CreateShard,
                &SandboxRpcError::Remote {
                    code: RpcFailureCode::Backend,
                    message,
                },
            );
            let mut expected = serde_json::json!({
                "operation": "create_shard",
                "error_variant": "Remote",
                "remote_code": "backend",
                "remote_message_omitted": true,
                "backend_category": "process_spawn",
            });
            if let Some(errno) = errno {
                expected["os_errno"] = serde_json::json!(errno);
            }
            let encoded = serde_json::to_value(&row)?;
            assert_eq!(encoded, expected);
            assert!(!encoded.to_string().contains(secret));
        }
        for message in [
            format!("sandbox backend failed: {secret} (os error 11)"),
            format!("prepared process spawn: {secret} (os error 24)"),
            format!("sandbox backend failed: {secret} prepared process spawn: (os error 11)"),
            format!("sandbox backend failed: prepared process spawn:{secret} (os error 24)"),
        ] {
            let row = RpcFailure::from_error(
                RpcOperation::CreateShard,
                &SandboxRpcError::Remote {
                    code: RpcFailureCode::Backend,
                    message,
                },
            );
            assert_eq!(
                serde_json::to_value(row)?,
                serde_json::json!({
                    "operation": "create_shard",
                    "error_variant": "Remote",
                    "remote_code": "backend",
                    "remote_message_omitted": true,
                })
            );
        }
        Ok(())
    }

    #[test]
    fn ingress_failure_categories_preserve_only_phase_and_numeric_errno()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "fixture-ingress-token-and-request-content";
        let address = "http://127.0.0.1:18083/private-fixture";
        for (prefix, category) in [
            (
                "egress control configuration is invalid",
                BackendFailureCategory::EgressControlConfiguration,
            ),
            (
                "egress control request timed out",
                BackendFailureCategory::EgressControlTimeout,
            ),
            (
                "egress control peer UID mismatch:",
                BackendFailureCategory::EgressControlPeerIdentity,
            ),
            (
                "egress control protocol failed:",
                BackendFailureCategory::EgressControlProtocol,
            ),
            (
                "egress control request failed:",
                BackendFailureCategory::EgressControlTransport,
            ),
            (
                "egress listener install outcome requires status reconciliation",
                BackendFailureCategory::EgressListenerInstall,
            ),
            (
                "egress route was not prepared",
                BackendFailureCategory::EgressRouteState,
            ),
            (
                "failed to clone the network namespace capability:",
                BackendFailureCategory::NamespaceCapability,
            ),
            (
                "failed to start the dedicated network namespace thread:",
                BackendFailureCategory::NamespaceThread,
            ),
            (
                "failed to enter the pinned network namespace:",
                BackendFailureCategory::NamespaceEnter,
            ),
            (
                "failed to observe the current network namespace:",
                BackendFailureCategory::NamespaceObserve,
            ),
            (
                "network namespace identity mismatch:",
                BackendFailureCategory::NamespaceIdentity,
            ),
            (
                "failed to bind the dedicated egress listener:",
                BackendFailureCategory::ListenerBind,
            ),
            (
                "failed to configure the dedicated egress listener:",
                BackendFailureCategory::ListenerConfigure,
            ),
            (
                "failed to inspect the dedicated egress listener:",
                BackendFailureCategory::ListenerInspect,
            ),
            (
                "the dedicated egress listener has an invalid local address:",
                BackendFailureCategory::ListenerAddress,
            ),
            (
                "native network namespace helper failed:",
                BackendFailureCategory::NativeNamespaceHelper,
            ),
        ] {
            let row = RpcFailure::from_error(
                RpcOperation::CreateShard,
                &SandboxRpcError::Remote {
                    code: RpcFailureCode::Backend,
                    message: format!(
                        "sandbox backend failed: {prefix} {secret} {address} (os error 13)"
                    ),
                },
            );
            assert_eq!(row.backend_category, Some(category));
            assert_eq!(row.os_errno, Some(13));
            assert!(row.remote_message.is_none());
            assert!(row.remote_message_omitted);
            let encoded = serde_json::to_string(&row)?;
            assert!(!encoded.contains(secret));
            assert!(!encoded.contains(address));
            assert!(!encoded.contains("127.0.0.1"));
        }
        let unrecognized = RpcFailure::from_error(
            RpcOperation::CreateShard,
            &SandboxRpcError::Remote {
                code: RpcFailureCode::Backend,
                message: format!("sandbox backend failed: {secret} (os error 13)"),
            },
        );
        assert!(unrecognized.backend_category.is_none());
        assert!(unrecognized.os_errno.is_none());
        Ok(())
    }

    #[test]
    fn native_net_user_namespace_helper_diagnostics_require_known_typed_stages() {
        for (stage, category) in [
            ("input", BackendFailureCategory::NativeHelperInput),
            (
                "owner_user_namespace",
                BackendFailureCategory::NativeHelperOwnerUserNamespace,
            ),
            (
                "enter_user_namespace",
                BackendFailureCategory::NativeHelperEnterUserNamespace,
            ),
            (
                "enter_network_namespace",
                BackendFailureCategory::NativeHelperEnterNetworkNamespace,
            ),
            ("loopback", BackendFailureCategory::NativeHelperLoopback),
            (
                "drop_privileges",
                BackendFailureCategory::NativeHelperDropPrivileges,
            ),
            (
                "bind_listener",
                BackendFailureCategory::NativeHelperBindListener,
            ),
            ("receipt", BackendFailureCategory::NativeHelperReceipt),
        ] {
            for (errno, expected) in [("1", Some(1)), ("none", None)] {
                let row = RpcFailure::from_error(
                    RpcOperation::CreateShard,
                    &SandboxRpcError::Remote {
                        code: RpcFailureCode::Backend,
                        message: format!(
                            "sandbox backend failed: native network namespace helper failed: stage={stage} errno={errno}"
                        ),
                    },
                );
                assert_eq!(row.backend_category, Some(category));
                assert_eq!(row.os_errno, expected);
                assert!(row.remote_message.is_none());
            }
        }
        for details in [
            "stage=unrecognized-secret-stage errno=13",
            "stage=enter_user_namespace errno=13 token=fixture-secret",
            "stage=enter_user_namespace errno=0",
            "stage=enter_user_namespace errno=4096",
            "stage=enter_user_namespace errno=+13",
        ] {
            let row = RpcFailure::from_error(
                RpcOperation::CreateShard,
                &SandboxRpcError::Remote {
                    code: RpcFailureCode::Backend,
                    message: format!(
                        "sandbox backend failed: native network namespace helper failed: {details}"
                    ),
                },
            );
            assert_eq!(
                row.backend_category,
                Some(BackendFailureCategory::NativeNamespaceHelper)
            );
            assert!(row.os_errno.is_none());
            assert!(row.remote_message.is_none());
        }
    }

    #[test]
    fn truncated_trace_never_supplies_complete_protocol_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let trace = Trace::default();
        let fence = shard()?;
        let mark = trace.mark();
        for id in 0..=MAX_TRACE_ENTRIES {
            trace.record(
                &fence,
                true,
                &serde_json::to_vec(&json!({"id":id,"method":"Target.getTargets","params":{}}))?,
            );
        }
        assert!(trace.since(mark).is_err());
        assert!(trace.since(trace.mark()).is_ok());
        Ok(())
    }

    #[test]
    fn streamed_data_keeps_digest_and_length_without_retaining_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let trace = Trace::default();
        trace.record(
            &shard()?,
            false,
            br#"{"id":5,"result":{"data":"Y2FuYXJ5","base64Encoded":true,"eof":true}}"#,
        );
        let rows = trace.since(0).map_err(|error| error.reason().to_owned())?;
        assert_eq!(rows.len(), 1);
        assert!(rows[0].summary.pointer("/result/data").is_none());
        assert_eq!(
            rows[0].summary.pointer("/result/data_bytes"),
            Some(&json!(6))
        );
        assert_eq!(
            rows[0].summary.pointer("/result/data_sha256"),
            Some(&json!(digest(b"canary")))
        );
        Ok(())
    }

    #[test]
    fn idle_forwarder_exits_at_deadline_instead_of_holding_pipe_forever()
    -> Result<(), Box<dyn std::error::Error>> {
        let (reader, _input) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let (_output, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let trace = Arc::new(Trace::default());
        let started = Instant::now();
        forward(
            File::from(reader),
            File::from(writer),
            Arc::clone(&trace),
            shard()?,
            true,
            started + Duration::from_millis(20),
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(trace.since(0).is_err());
        Ok(())
    }
}
