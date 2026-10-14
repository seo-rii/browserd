use super::super::config::EngineRequest;
use super::super::rpc::{pin_peer, process_start};
use super::{Harness, ProbeError, ProbeResultValue, config, private_subdirectory, verify_cleanup};
use crate::{LifecycleBounds, ProductionWorkerRuntime};
use browserd_core::{SessionId, ShardFence};
use browserd_sandbox::{ChildIdentity, LaunchSpec};
use browserd_worker::{
    CreateSessionCommand, SystemWorkerClock, WorkerClock, WorkerRpcClient, WorkerRpcConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    request: EngineRequest,
    nonce: String,
    ready: PathBuf,
    state: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    schema_version: u32,
    binding: super::super::RunBinding,
    nonce: String,
    identity: ChildIdentity,
    worker_ready: bool,
    session: SessionId,
    shard: ShardFence,
    specs: Vec<LaunchSpec>,
    socket: PathBuf,
}
pub(crate) fn child_main(path: &Path) -> Result<(), String> {
    child(path).map_err(|error| error.reason().to_owned())
}
fn child(path: &Path) -> ProbeResultValue<()> {
    let bootstrap: Bootstrap =
        serde_json::from_slice(&config::read_bounded(path, 1024 * 1024, false)?)
            .map_err(|_| ProbeError::blocked("invalid private worker-child bootstrap"))?;
    config::validate_request(&bootstrap.request)?;
    let approved = config::load_approved(&bootstrap.request)?;
    let expected = approved
        .deployment
        .worker
        .state_root
        .join(&bootstrap.request.binding.run_id)
        .join("worker-child");
    if bootstrap.state != expected
        || bootstrap.ready.parent() != Some(bootstrap.request.log_dir.as_path())
        || uuid::Uuid::parse_str(&bootstrap.nonce).is_err()
    {
        return Err(ProbeError::blocked("worker-child authority scope mismatch"));
    }
    config::private_directory(&bootstrap.state)?;
    let mut h = super::open_harness_scoped(&bootstrap.request, approved, Some(&bootstrap.state))?;
    h.rpc.enable_launch_log(
        &bootstrap
            .request
            .log_dir
            .join("worker-child-launches.jsonl"),
        serde_json::to_value(&bootstrap.request.binding)
            .map_err(|_| ProbeError::failed("child inventory binding encoding failed"))?,
    )?;
    let result = (|| {
        let state = bootstrap.state.join("control");
        private_subdirectory(&state)?;
        let socket = state.join("w.sock");
        let (worker, peer) = super::super::control::open_worker(&h, &state)?;
        if !worker.is_ready() {
            return Err(ProbeError::blocked(
                "actual child Worker dependencies/runtime safety not ready",
            ));
        }
        let mut options = h.default_options()?;
        options.feature_profile = "standard".into();
        let encoded = serde_json::to_vec(&options)
            .map_err(|_| ProbeError::failed("worker session options invalid"))?;
        let hash: [u8; 32] = hex::decode(config::digest(&encoded))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| ProbeError::failed("worker canonical create digest invalid"))?;
        let created = worker
            .create_session_with_options(
                &peer,
                CreateSessionCommand {
                    tenant_id: browserd_core::TenantId::new(),
                    idempotency_key: bootstrap.nonce.clone(),
                    canonical_request_hash: hash,
                    placement_version: 1,
                    session_incarnation: 1,
                },
                &options,
                SystemWorkerClock
                    .now()
                    .map_err(|_| ProbeError::failed("worker trusted clock unavailable"))?,
            )
            .map_err(|_| ProbeError::failed("actual child Worker session creation failed"))?;
        let spec = h.rpc.spec_for_session(&created.session_id)?;
        let rpc_config = WorkerRpcConfig::new(
            socket.clone(),
            4 * 1024 * 1024,
            128,
            Duration::from_secs(5),
            Some(nix::unistd::Uid::effective().as_raw()),
        )
        .map_err(|_| ProbeError::failed("worker child RPC configuration invalid"))?;
        let bounds = LifecycleBounds::new(
            Duration::from_secs(3),
            Duration::from_secs(1),
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .map_err(|_| ProbeError::failed("worker lifecycle bounds invalid"))?;
        let runtime =
            ProductionWorkerRuntime::new(worker, peer, rpc_config, bounds).map_err(|_| {
                ProbeError::failed("actual production Worker runtime qualification failed")
            })?;
        let identity = ChildIdentity::new(std::process::id(), process_start(std::process::id())?);
        config::write_private(
            &bootstrap.ready,
            &json!({"schema_version":1,"binding":bootstrap.request.binding,"nonce":bootstrap.nonce,"identity":identity,"worker_ready":true,
            "session":created.session_id,"shard":spec.dedicated_egress().egress_fence().shard(),"specs":h.rpc.specs()?,"socket":socket}),
        )?;
        h.runtime
            .block_on(runtime.serve(CancellationToken::new()))
            .map_err(|_| ProbeError::failed("worker child runtime stopped before owned signal"))
    })();
    // The expected SIGKILL cannot execute this branch; an ordinary error still owns all launches.
    let cleanup = super::finish_harness(&mut h);
    if !cleanup {
        return Err(ProbeError::failed(
            "worker child error path cleanup incomplete",
        ));
    }
    result
}
struct OwnedChild {
    child: Child,
    pidfd: OwnedFd,
    identity: ChildIdentity,
    signalled: bool,
}
struct ChildInventory<'a> {
    h: &'a Harness,
}
impl Drop for ChildInventory<'_> {
    fn drop(&mut self) {
        let path = self.h.request.log_dir.join("worker-child-launches.jsonl");
        if let Ok(bytes) = config::read_bounded(&path, 1024 * 1024, false) {
            let binding = serde_json::to_value(&self.h.binding).ok();
            for line in bytes
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .take(8)
            {
                if let Ok(value) = serde_json::from_slice::<Value>(line) {
                    if value.get("binding") != binding.as_ref() {
                        continue;
                    }
                    if let Some(spec) = value
                        .get("spec")
                        .cloned()
                        .and_then(|v| serde_json::from_value::<LaunchSpec>(v).ok())
                        && self
                            .h
                            .config
                            .worker_id()
                            .is_ok_and(|worker| spec.worker_id() == &worker)
                        && spec.worker_epoch() == self.h.config.sandbox.worker_epoch
                    {
                        let _ = self.h.rpc.record_child_launches(&[spec]);
                    }
                }
            }
        }
    }
}
impl OwnedChild {
    fn spawn(input: &Path, log: &Path) -> ProbeResultValue<Self> {
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(log)
            .map_err(|_| ProbeError::failed("private worker child log unavailable"))?;
        let child = Command::new(
            std::env::current_exe()
                .map_err(|_| ProbeError::failed("approved probe executable unavailable"))?,
        )
        .arg("--internal-worker")
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().map_err(|_| {
            ProbeError::failed("worker log clone unavailable")
        })?))
        .stderr(Stdio::from(log))
        .spawn()
        .map_err(|_| ProbeError::blocked("actual Worker child could not start"))?;
        let pid = child.id();
        let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProbeError::blocked(
                "pidfd unavailable for exact owned Worker child",
            ));
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let start = match process_start(pid) {
            Ok(start) => start,
            Err(error) => {
                let _ = unsafe {
                    nix::libc::syscall(
                        nix::libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        nix::libc::SIGKILL,
                        std::ptr::null::<nix::libc::siginfo_t>(),
                        0,
                    )
                };
                let mut child = child;
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(Self {
            child,
            pidfd,
            identity: ChildIdentity::new(pid, start),
            signalled: false,
        })
    }
    fn sigkill(&mut self) -> ProbeResultValue<()> {
        if ChildIdentity::new(self.child.id(), process_start(self.child.id())?) != self.identity {
            return Err(ProbeError::failed(
                "owned Worker PID/start identity changed",
            ));
        }
        if unsafe {
            nix::libc::syscall(
                nix::libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                nix::libc::SIGKILL,
                std::ptr::null::<nix::libc::siginfo_t>(),
                0,
            )
        } < 0
        {
            return Err(ProbeError::failed(
                "exact owned Worker pidfd SIGKILL failed",
            ));
        }
        self.signalled = true;
        let exit = self
            .child
            .wait()
            .map_err(|_| ProbeError::failed("owned Worker child reap failed"))?;
        use std::os::unix::process::ExitStatusExt;
        if exit.signal() != Some(nix::libc::SIGKILL) {
            return Err(ProbeError::failed(
                "owned Worker did not terminate by requested SIGKILL",
            ));
        }
        Ok(())
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.signalled {
            let _ = unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    nix::libc::SIGKILL,
                    std::ptr::null::<nix::libc::siginfo_t>(),
                    0,
                )
            };
            let _ = self.child.wait();
        }
    }
}
pub(super) fn worker_sigkill_cleanup(h: &Harness) -> ProbeResultValue<Value> {
    let state = h
        .config
        .worker
        .state_root
        .join(&h.binding.run_id)
        .join("worker-child");
    private_subdirectory(&state)?;
    let input = h.request.log_dir.join("worker-child-input.json");
    let ready_path = h.request.log_dir.join("worker-child-ready.json");
    let nonce = uuid::Uuid::new_v4().to_string();
    config::write_private(
        &input,
        &json!({"request":h.request,"nonce":nonce,"ready":ready_path,"state":state}),
    )?;
    let _inventory = ChildInventory { h };
    let mut child = OwnedChild::spawn(&input, &h.request.log_dir.join("worker-child.log"))?;
    let until = (Instant::now() + Duration::from_secs(120)).min(h.deadline);
    let ready = loop {
        if let Ok(bytes) = config::read_bounded(&ready_path, 1024 * 1024, false)
            && let Ok(ready) = serde_json::from_slice::<Ready>(&bytes)
        {
            break ready;
        }
        if child
            .child
            .try_wait()
            .map_err(|_| ProbeError::failed("Worker child status unavailable"))?
            .is_some()
        {
            return Err(ProbeError::failed(
                "actual Worker child failed before ready receipt",
            ));
        }
        if Instant::now() >= until {
            return Err(ProbeError::failed(
                "actual Worker child ready deadline elapsed",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if ready.schema_version != 1
        || ready.binding != h.binding
        || ready.nonce != nonce
        || ready.identity != child.identity
        || !ready.worker_ready
        || ready.specs.len() > 8
        || ready.socket != state.join("control/w.sock")
        || ready.shard.owner().worker_id() != &h.config.worker_id()?
    {
        return Err(ProbeError::failed(
            "actual Worker child ready proof binding mismatch",
        ));
    }
    for spec in &ready.specs {
        if spec.worker_id() != &h.config.worker_id()?
            || spec.worker_epoch() != h.config.sandbox.worker_epoch
        {
            return Err(ProbeError::failed("Worker child recorded a foreign launch"));
        }
    }
    let exact = ready
        .specs
        .iter()
        .find(|spec| {
            spec.dedicated_egress().egress_fence().shard() == &ready.shard
                && spec.dedicated_egress().egress_fence().session_id() == &ready.session
        })
        .ok_or_else(|| ProbeError::failed("Worker child actual session/launch binding absent"))?;
    h.rpc.record_child_launches(&ready.specs)?;
    let client = WorkerRpcClient::new(
        &ready.socket,
        4 * 1024 * 1024,
        Duration::from_secs(2),
        Some(nix::unistd::Uid::effective().as_raw()),
    )
    .map_err(|_| ProbeError::failed("Worker child probe client invalid"))?;
    let probe = loop {
        if let Ok(pin) = h.runtime.block_on(pin_peer(
            &ready.socket,
            nix::unistd::Uid::effective().as_raw(),
            &std::env::current_exe()
                .map_err(|_| ProbeError::failed("probe executable unavailable"))?,
        )) {
            if pin.identity != child.identity {
                return Err(ProbeError::failed(
                    "child Worker RPC peer differs from owned process",
                ));
            }
            if let Ok(probe) = h
                .runtime
                .block_on(client.probe(h.config.sandbox.worker_epoch))
            {
                break probe;
            }
        }
        if Instant::now() >= until {
            return Err(ProbeError::failed(
                "actual Worker RPC ready probe deadline elapsed",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if probe.worker_id != h.config.worker_id()? || !probe.ready {
        return Err(ProbeError::failed(
            "actual Worker RPC ready identity mismatch",
        ));
    }
    let before = super::process::browser_process(h, &ready.shard)?.identity;
    child.sigkill()?;
    let until = (Instant::now() + Duration::from_secs(90)).min(h.deadline);
    // No supervisor kill/cancel call is allowed on the pass path: independent lease cleanup wins.
    let cleanup = loop {
        if let Ok(cleanup) = verify_cleanup(h, &ready.shard) {
            break cleanup;
        }
        if Instant::now() >= until {
            return Err(ProbeError::failed(
                "independent supervisor lease cleanup did not positively complete after Worker SIGKILL",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if process_start(before.pid())
        .is_ok_and(|start| ChildIdentity::new(before.pid(), start) == before)
    {
        return Err(ProbeError::failed(
            "original browser process survived lease cleanup",
        ));
    }
    Ok(
        json!({"worker_identity":ready.identity,"rpc_ready_observed":true,"worker_sigkill_via_pidfd":true,"browser_identity":before,"session":ready.session,
        "launch_generation":exact.launch_generation(),"cleanup_via_independent_lease":true,"cleanup":cleanup}),
    )
}
