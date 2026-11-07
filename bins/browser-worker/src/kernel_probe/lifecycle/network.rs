use super::super::config::EngineRequest;
use super::super::rpc::{TraceDirection, process_start};
use super::{Harness, ProbeError, ProbeResultValue, config, process, with_session};
use browser_sandboxd::{EgressControlPlane, RouteStatusState};
use browserd_core::ShardFence;
use browserd_egress::{IpDenyReason, IpPolicy};
use browserd_sandbox::{
    ChildIdentity, FilePreparedShardJournal, PreparedShardJournalLimits, PreparedShardRecoveryRoots,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    request: EngineRequest,
    shard: ShardFence,
    identity: ChildIdentity,
    nonce: String,
    mode: String,
    ready: PathBuf,
    output: PathBuf,
    stop: PathBuf,
    public_address: SocketAddr,
    #[serde(default)]
    canary: Option<String>,
}
pub(crate) fn helper_main(path: &Path) -> Result<(), String> {
    helper(path).map_err(|error| error.reason().to_owned())
}
fn helper(path: &Path) -> ProbeResultValue<()> {
    let input: Input = serde_json::from_slice(&config::read_bounded(path, 1024 * 1024, false)?)
        .map_err(|_| ProbeError::blocked("invalid private namespace-helper input"))?;
    let approved = config::load_approved(&input.request)?;
    let deployment = approved.deployment;
    if !["loopback", "direct", "isolation"].contains(&input.mode.as_str())
        || uuid::Uuid::parse_str(&input.nonce).is_err()
        || [&input.ready, &input.output, &input.stop]
            .into_iter()
            .any(|path| path.parent() != Some(input.request.log_dir.as_path()))
        || input.shard.owner().worker_id() != &deployment.worker_id()?
        || input.shard.owner().worker_epoch().get() != deployment.sandbox.worker_epoch
        || (input.mode == "isolation") != input.canary.is_some()
        || input
            .canary
            .as_deref()
            .is_some_and(|value| uuid::Uuid::parse_str(value).is_err())
    {
        return Err(ProbeError::blocked(
            "namespace helper authority binding mismatch",
        ));
    }
    if input.mode != "isolation"
        && !public_addresses(&deployment.fixtures.origin)?.contains(&input.public_address)
    {
        return Err(ProbeError::blocked(
            "namespace helper public target differs from approved origin",
        ));
    }
    let journal = FilePreparedShardJournal::inspect_existing_record(
        &deployment.sandbox.journal_directory,
        PreparedShardJournalLimits::default(),
        PreparedShardRecoveryRoots::new(
            deployment.sandbox.cgroup_root.clone(),
            deployment.sandbox.runtime_root.clone(),
        )
        .map_err(|_| ProbeError::blocked("namespace recovery roots invalid"))?,
        &input.shard,
    )
    .map_err(|_| ProbeError::blocked("namespace helper exact live launch unavailable"))?;
    if !process::cgroup_pids(journal.locators().cgroup_path())?.contains(&input.identity.pid())
        || ChildIdentity::new(input.identity.pid(), process_start(input.identity.pid())?)
            != input.identity
        || config::file_digest(Path::new(&format!("/proc/{}/exe", input.identity.pid())))?
            != config::file_digest(&deployment.assets.chromium_host_executable)?
    {
        return Err(ProbeError::blocked(
            "namespace helper PID is not the exact approved launched Chromium",
        ));
    }
    let user = File::open(format!("/proc/{}/ns/user", input.identity.pid()))
        .map_err(|_| ProbeError::blocked("actual Chromium user namespace unavailable"))?;
    let net = File::open(format!("/proc/{}/ns/net", input.identity.pid()))
        .map_err(|_| ProbeError::blocked("actual Chromium network namespace unavailable"))?;
    let user_identity = namespace_identity(&user, nix::libc::CLONE_NEWUSER)?;
    let net_identity = namespace_identity(&net, nix::libc::CLONE_NEWNET)?;
    let net_inode = net_identity.1;
    if ChildIdentity::new(input.identity.pid(), process_start(input.identity.pid())?)
        != input.identity
    {
        return Err(ProbeError::blocked(
            "namespace PID/start changed before entry",
        ));
    }
    if input.mode == "isolation" {
        return isolation_helper(&input, user, net);
    }
    let owner = namespace_owner(&user, &net, None)?;
    enter_browser_namespaces(&owner, &net, None, &user, setns_namespace)?;
    drop_namespace_privileges()?;
    require_unprivileged_helper(
        &File::open("/proc")
            .map_err(|_| ProbeError::failed("helper privilege observation unavailable"))?,
    )?;
    for (name, expected, kind) in [
        ("user", user_identity, nix::libc::CLONE_NEWUSER),
        ("net", net_identity, nix::libc::CLONE_NEWNET),
    ] {
        let observed = File::open(format!("/proc/self/ns/{name}"))
            .map_err(|_| ProbeError::failed("entered namespace identity unavailable"))?;
        if namespace_identity(&observed, kind)? != expected {
            return Err(ProbeError::failed(
                "helper did not enter the exact pinned Chromium namespaces",
            ));
        }
    }
    // No browser disabling flags, fake routes, or replacement resolver are installed.
    if input.mode == "direct" {
        let targets = [
            deployment.fixtures.host_direct_address,
            deployment.fixtures.private_direct_address,
            input.public_address,
        ];
        let mut results = Vec::new();
        for target in targets {
            match TcpStream::connect_timeout(&target,Duration::from_secs(3)){
                Ok(_)=>results.push(json!({"address":target,"connected":true})),
                Err(error)=>results.push(json!({"address":target,"connected":false,"error_kind":format!("{:?}",error.kind())})),
            }
        }
        return config::write_private(
            &input.output,
            &json!({"schema_version":1,"binding":input.request.binding,"nonce":input.nonce,"process_identity":input.identity,
            "network_namespace":net_inode,"raw_tcp_results":results}),
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|_| ProbeError::blocked("owned namespace loopback canary unavailable"))?;
    listener
        .set_nonblocking(true)
        .map_err(|_| ProbeError::failed("loopback canary nonblocking mode unavailable"))?;
    let address = listener
        .local_addr()
        .map_err(|_| ProbeError::failed("loopback canary address unavailable"))?;
    // A positive connect within the same namespace proves the canary is live before browser use.
    let control = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|_| ProbeError::failed("loopback canary positive control failed"))?;
    let (positive, _) = listener
        .accept()
        .map_err(|_| ProbeError::failed("loopback canary positive accept failed"))?;
    drop(control);
    drop(positive);
    config::write_private(
        &input.ready,
        &json!({"schema_version":1,"binding":input.request.binding,"nonce":input.nonce,"process_identity":input.identity,
        "network_namespace":net_inode,"address":address,"positive_control":true}),
    )?;
    let until = Instant::now() + Duration::from_secs(40);
    let mut browser_connections = 0;
    while Instant::now() < until && !input.stop.exists() {
        match listener.accept() {
            Ok((mut socket, _)) => {
                browser_connections += 1;
                let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = socket.set_write_timeout(Some(Duration::from_secs(1)));
                let mut buffer = [0; 2048];
                let _ = socket.read(&mut buffer);
                let body = format!("unexpected-browser-bypass-{}", input.nonce);
                let _=socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type:text/html\r\nContent-Length:{}\r\nConnection:close\r\n\r\n{body}",body.len()).as_bytes());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => return Err(ProbeError::failed("namespace canary listener failed")),
        }
    }
    config::write_private(
        &input.output,
        &json!({"schema_version":1,"binding":input.request.binding,"nonce":input.nonce,"process_identity":input.identity,
        "network_namespace":net_inode,"positive_control":true,"browser_direct_connections":browser_connections}),
    )
}
fn public_addresses(origin: &str) -> ProbeResultValue<Vec<SocketAddr>> {
    let url = url::Url::parse(origin).map_err(|_| ProbeError::blocked("fixture origin invalid"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| ProbeError::blocked("fixture origin port absent"))?;
    let addresses = match url
        .host()
        .ok_or_else(|| ProbeError::blocked("fixture origin host absent"))?
    {
        url::Host::Ipv4(address) => vec![SocketAddr::new(address.into(), port)],
        url::Host::Ipv6(address) => vec![SocketAddr::new(address.into(), port)],
        url::Host::Domain(host) => (host, port)
            .to_socket_addrs()
            .map_err(|_| ProbeError::blocked("approved fixture public DNS unavailable"))?
            .take(17)
            .collect::<Vec<_>>(),
    };
    if addresses.is_empty()
        || addresses.len() > 16
        || addresses
            .iter()
            .any(|address| IpPolicy::public_web_default().check(address.ip()).is_err())
    {
        return Err(ProbeError::blocked(
            "approved fixture needs bounded nonloopback public DNS addresses",
        ));
    }
    Ok(addresses)
}
struct OwnedHelper {
    child: Child,
    output: PathBuf,
    stop: PathBuf,
    nonce: String,
    identity: ChildIdentity,
    network_namespace: u64,
}
impl Drop for OwnedHelper {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
fn spawn(h: &Harness, session: &super::OwnedSession, mode: &str) -> ProbeResultValue<OwnedHelper> {
    spawn_with_canary(h, session, mode, None)
}
fn spawn_with_canary(
    h: &Harness,
    session: &super::OwnedSession,
    mode: &str,
    canary: Option<&str>,
) -> ProbeResultValue<OwnedHelper> {
    let process = process::browser_process(h, &session.shard)?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let name = format!("namespace-{mode}-{nonce}");
    let input_path = h.request.log_dir.join(format!("{name}-input.json"));
    let output = h.request.log_dir.join(format!("{name}-output.json"));
    let ready = h.request.log_dir.join(format!("{name}-ready.json"));
    let stop = h.request.log_dir.join(format!("{name}-stop.json"));
    let public_address = if mode == "isolation" {
        h.config.fixtures.bind_address
    } else {
        public_addresses(&h.config.fixtures.origin)?[0]
    };
    config::write_private(
        &input_path,
        &json!({"request":h.request,"shard":session.shard,"identity":process.identity,"nonce":nonce,"mode":mode,"ready":ready,"output":output,"stop":stop,"public_address":public_address,"canary":canary}),
    )?;
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(h.request.log_dir.join(format!("{name}.log")))
        .map_err(|_| ProbeError::failed("private namespace helper log unavailable"))?;
    let child = Command::new(
        std::env::current_exe()
            .map_err(|_| ProbeError::failed("approved helper executable unavailable"))?,
    )
    .arg("--internal-namespace")
    .arg(input_path)
    .stdin(Stdio::null())
    .stdout(Stdio::from(log.try_clone().map_err(|_| {
        ProbeError::failed("namespace log clone unavailable")
    })?))
    .stderr(Stdio::from(log))
    .spawn()
    .map_err(|_| ProbeError::blocked("owned namespace validation helper could not start"))?;
    Ok(OwnedHelper {
        child,
        output,
        stop,
        nonce,
        identity: process.identity,
        network_namespace: process.net_namespace,
    })
}
fn output(h: &Harness, helper: &mut OwnedHelper, path: &Path) -> ProbeResultValue<Value> {
    let until = (Instant::now() + Duration::from_secs(20)).min(h.deadline);
    loop {
        if let Ok(bytes) = config::read_bounded(path, 1024 * 1024, false)
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
        {
            if value.get("binding")
                != Some(
                    &serde_json::to_value(&h.binding)
                        .map_err(|_| ProbeError::failed("binding encoding failed"))?,
                )
                || value.get("nonce").and_then(Value::as_str) != Some(helper.nonce.as_str())
                || value.get("schema_version") != Some(&json!(1))
                || value.get("process_identity")
                    != Some(
                        &serde_json::to_value(helper.identity)
                            .map_err(|_| ProbeError::failed("process identity encoding failed"))?,
                    )
                || value.get("network_namespace").and_then(Value::as_u64)
                    != Some(helper.network_namespace)
            {
                return Err(ProbeError::failed(
                    "actual namespace helper evidence binding mismatch",
                ));
            }
            return Ok(value);
        }
        if helper
            .child
            .try_wait()
            .map_err(|_| ProbeError::failed("namespace helper status unavailable"))?
            .is_some()
        {
            return Err(ProbeError::blocked(
                "actual namespace helper could not complete; see private helper log",
            ));
        }
        if Instant::now() >= until {
            return Err(ProbeError::blocked(
                "actual namespace helper deadline elapsed",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn completed_output(h: &Harness, helper: &mut OwnedHelper) -> ProbeResultValue<Value> {
    let path = helper.output.clone();
    let value = output(h, helper, &path)?;
    let until = (Instant::now() + Duration::from_secs(5)).min(h.deadline);
    loop {
        if let Some(status) = helper
            .child
            .try_wait()
            .map_err(|_| ProbeError::failed("owned namespace helper exit unavailable"))?
        {
            if !status.success() {
                return Err(ProbeError::failed(
                    "owned namespace helper did not exit successfully",
                ));
            }
            return Ok(value);
        }
        if Instant::now() >= until {
            return Err(ProbeError::failed(
                "owned namespace helper did not close and reap after its evidence",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub(super) fn direct_egress_denial(h: &Harness) -> ProbeResultValue<Value> {
    let mark = h.trace.mark();
    with_session(h, |session| {
        if IpPolicy::public_web_default().check(h.config.fixtures.host_direct_address.ip())
            != Err(IpDenyReason::Loopback)
            || !matches!(
                IpPolicy::public_web_default().check(h.config.fixtures.private_direct_address.ip()),
                Err(IpDenyReason::Private | IpDenyReason::UniqueLocal)
            )
        {
            return Err(ProbeError::blocked(
                "approved direct controls must include live host loopback and private IP endpoints",
            ));
        }
        let public = public_addresses(&h.config.fixtures.origin)?[0];
        for target in [
            h.config.fixtures.host_direct_address,
            h.config.fixtures.private_direct_address,
            public,
        ] {
            TcpStream::connect_timeout(&target, Duration::from_secs(3)).map_err(|_| {
                ProbeError::blocked(
                    "approved direct canary lacks a live host-side positive control",
                )
            })?;
        }
        session.action(
            json!({"type":"navigate","url":h.fixture_url("direct_egress")?,"wait_until":"load"}),
            h.deadline,
        )?;
        if !h.fixture.saw("direct_egress") {
            return Err(ProbeError::failed(
                "public fixture was not reached through actual browser egress",
            ));
        }
        let mut helper = spawn(h, session, "direct")?;
        let proxy = actual_proxy_route(h, session, mark)?;
        let value = completed_output(h, &mut helper)?;
        let results = value
            .get("raw_tcp_results")
            .and_then(Value::as_array)
            .ok_or_else(|| ProbeError::failed("actual raw TCP evidence absent"))?;
        if results.len() != 3
            || results
                .iter()
                .zip([
                    h.config.fixtures.host_direct_address,
                    h.config.fixtures.private_direct_address,
                    public,
                ])
                .any(|(result, expected)| result.get("address") != Some(&json!(expected)))
            || results
                .iter()
                .any(|result| result.get("connected") != Some(&Value::Bool(false)))
        {
            return Err(ProbeError::failed(
                "direct raw TCP reached an approved live canary outside egress",
            ));
        }
        for target in [
            h.config.fixtures.host_direct_address,
            h.config.fixtures.private_direct_address,
            public,
        ] {
            TcpStream::connect_timeout(&target, Duration::from_secs(3)).map_err(|_| {
                ProbeError::blocked("approved direct canary positive control disappeared during namespace validation")
            })?;
        }
        let mut denied_browser_targets = Vec::new();
        for target in [
            h.config.fixtures.host_direct_address,
            h.config.fixtures.private_direct_address,
        ] {
            let url = format!(
                "http://{target}/browserd-kernel-denial-{}",
                uuid::Uuid::new_v4()
            );
            let rejection_mark = h.trace.mark();
            let action = session.action(
                json!({"type":"navigate","url":url,"wait_until":"load"}),
                (Instant::now() + Duration::from_secs(15)).min(h.deadline),
            );
            let rows = h.trace.since(rejection_mark)?;
            if action.is_ok() || !navigation_denied(&rows, &session.shard, &url) {
                return Err(ProbeError::failed(
                    "actual browser proxy did not positively reject the approved live loopback/private control",
                ));
            }
            TcpStream::connect_timeout(&target, Duration::from_secs(3))
                .map_err(|_| ProbeError::blocked("browser denial control became unavailable"))?;
            denied_browser_targets.push(target);
        }
        Ok(
            json!({"shard":session.shard,"host_positive_controls":3,"proxied_fixture_success":true,"namespace_raw_tcp":results,
                "exact_proxy":proxy,"browser_loopback_private_denials":denied_browser_targets}),
        )
    })
}
pub(super) fn proxy_loopback(h: &Harness) -> ProbeResultValue<Value> {
    let mark = h.trace.mark();
    with_session(h, |session| {
        session.action(
            json!({"type":"navigate","url":h.fixture_url("proxy_loopback")?,"wait_until":"load"}),
            h.deadline,
        )?;
        if !h.fixture.saw("proxy_loopback") {
            return Err(ProbeError::failed(
                "actual public proxy fixture positive control absent",
            ));
        }
        let mut helper = spawn(h, session, "loopback")?;
        let proxy = actual_proxy_route(h, session, mark)?;
        let ready_path = h
            .request
            .log_dir
            .join(format!("namespace-loopback-{}-ready.json", helper.nonce));
        let ready = output(h, &mut helper, &ready_path)?;
        let address: SocketAddr = serde_json::from_value(
            ready
                .get("address")
                .cloned()
                .ok_or_else(|| ProbeError::failed("actual canary address absent"))?,
        )
        .map_err(|_| ProbeError::failed("actual canary address invalid"))?;
        if !address.ip().is_loopback() || ready.get("positive_control") != Some(&Value::Bool(true))
        {
            return Err(ProbeError::failed(
                "namespace loopback positive control invalid",
            ));
        }
        let url = format!("http://{address}/{}", helper.nonce);
        let navigation = session.action(
            json!({"type":"navigate","url":url,"wait_until":"load"}),
            (Instant::now() + Duration::from_secs(15)).min(h.deadline),
        );
        config::write_private(&helper.stop, &json!({"nonce":helper.nonce}))?;
        let result = completed_output(h, &mut helper)?;
        let rows = h.trace.since(mark)?;
        if navigation.is_ok()
            || !navigation_denied(&rows, &session.shard, &url)
            || result.get("browser_direct_connections") != Some(&json!(0))
        {
            return Err(ProbeError::failed(
                "actual browser bypassed loopback proxy or lacks witnessed exact proxy denial",
            ));
        }
        Ok(
            json!({"shard":session.shard,"proxy_bypass_list":"<-loopback>","public_proxy_positive_control":true,"namespace_loopback_positive_control":true,
            "actual_navigation_rejected":true,"browser_direct_connections":0,"network_namespace":ready.get("network_namespace"),"exact_proxy":proxy}),
        )
    })
}

fn navigation_denied(
    rows: &[super::super::rpc::TraceEntry],
    shard: &ShardFence,
    url: &str,
) -> bool {
    rows.iter()
        .filter(|row| {
            row.shard == *shard
                && row.direction == TraceDirection::Command
                && row.id.is_some()
                && row.method.as_deref() == Some("Page.navigate")
                && row.summary.pointer("/params/url").and_then(Value::as_str) == Some(url)
        })
        .any(|command| {
            rows.iter().any(|reply| {
                reply.direction == TraceDirection::Reply
                    && reply.shard == command.shard
                    && reply.session_id == command.session_id
                    && reply.id == command.id
                    && reply.sequence > command.sequence
                    && reply.summary.get("success") == Some(&Value::Bool(true))
                    && reply.summary.get("error").is_none()
                    && reply
                        .summary
                        .pointer("/result/errorText")
                        .and_then(Value::as_str)
                        .is_some_and(|error| error.starts_with("net::ERR_"))
            })
        })
}

fn actual_proxy_route(
    h: &Harness,
    session: &super::OwnedSession,
    mark: u64,
) -> ProbeResultValue<Value> {
    let spec = h.rpc.spec_for_session(&session.session)?;
    let fence = spec.dedicated_egress().egress_fence();
    let status = h
        .runtime
        .block_on(h.egress.status(h.config.egress.daemon_epoch, fence))
        .map_err(|_| ProbeError::failed("authenticated actual egress route status unavailable"))?
        .ok_or_else(|| ProbeError::failed("actual egress route has no positive status receipt"))?;
    let active = status
        .active()
        .ok_or_else(|| ProbeError::failed("actual egress route has no positive Active receipt"))?;
    let proxy = active.proxy_address();
    if status.state() != RouteStatusState::Active
        || status.daemon_epoch() != h.config.egress.daemon_epoch
        || status.egress_fence() != fence
        || active.egress_fence() != fence
        || active.daemon_epoch() != h.config.egress.daemon_epoch
        || !matches!(proxy, SocketAddr::V4(address) if *address.ip() == std::net::Ipv4Addr::LOCALHOST && address.port() != 0)
        || active.attachment_id() == 0
        || active.activation_revision() == 0
    {
        return Err(ProbeError::failed(
            "actual positive egress receipt does not match the exact owned launch",
        ));
    }
    let rows = h.trace.since(mark)?;
    let proxy_uri = format!("http://{proxy}");
    let configured = rows
        .iter()
        .filter(|row| {
            row.shard == session.shard
                && row.direction == TraceDirection::Command
                && row.id.is_some()
                && row.method.as_deref() == Some("Target.createBrowserContext")
                && row
                    .summary
                    .pointer("/params/proxyBypassList")
                    .and_then(Value::as_str)
                    == Some("<-loopback>")
                && row
                    .summary
                    .pointer("/params/proxyServer")
                    .and_then(Value::as_str)
                    == Some(proxy_uri.as_str())
        })
        .any(|command| {
            rows.iter().any(|reply| {
                reply.direction == TraceDirection::Reply
                    && reply.shard == command.shard
                    && reply.session_id == command.session_id
                    && reply.id == command.id
                    && reply.sequence > command.sequence
                    && reply.summary.get("success") == Some(&Value::Bool(true))
                    && reply.summary.get("error").is_none()
                    && reply
                        .summary
                        .pointer("/result/browserContextId")
                        .and_then(Value::as_str)
                        .is_some_and(|id| !id.is_empty())
            })
        });
    if !configured {
        return Err(ProbeError::failed(
            "real successful context creation did not use the exact authenticated loopback proxy",
        ));
    }
    Ok(
        json!({"egress_fence":fence,"daemon_epoch":status.daemon_epoch(),"proxy_address":proxy,
        "attachment_id":active.attachment_id(),"activation_revision":active.activation_revision(),"state":"active"}),
    )
}

// Namespace entry grants capabilities in the target user namespace. The canary
// performs ordinary unprivileged operations after entry; it never changes routes
// or mounts, and namespace entry itself does not inherit Chromium's seccomp.
fn namespace_identity(namespace: &File, kind: i32) -> ProbeResultValue<(u64, u64)> {
    // SAFETY: this ioctl only queries the namespace held by this owned descriptor.
    if unsafe { nix::libc::ioctl(namespace.as_raw_fd(), nix::libc::NS_GET_NSTYPE) } != kind {
        return Err(ProbeError::blocked(
            "pinned namespace descriptor has the wrong type",
        ));
    }
    let metadata = namespace
        .metadata()
        .map_err(|_| ProbeError::blocked("pinned namespace identity unavailable"))?;
    Ok((metadata.dev(), metadata.ino()))
}
fn derived_namespace_owner(namespace: &File, kind: i32) -> ProbeResultValue<File> {
    let _ = namespace_identity(namespace, kind)?;
    // SAFETY: the ioctl returns one newly owned descriptor for this pinned namespace's owner.
    let raw = unsafe { nix::libc::ioctl(namespace.as_raw_fd(), nix::libc::NS_GET_USERNS) };
    if raw < 0 {
        return Err(ProbeError::blocked(
            "pinned namespace owning USER unavailable",
        ));
    }
    // SAFETY: NS_GET_USERNS transferred a fresh descriptor exactly once.
    let owner = File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let _ = namespace_identity(&owner, nix::libc::CLONE_NEWUSER)?;
    Ok(owner)
}
fn require_unprivileged_helper(proc: &File) -> ProbeResultValue<()> {
    let mut status = String::new();
    open_at(proc, c"self/status")?
        .take(65537)
        .read_to_string(&mut status)
        .map_err(|_| ProbeError::failed("helper privilege proof unavailable"))?;
    if status.len() > 65536
        || [
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
            "NoNewPrivs",
            "Threads",
        ]
        .into_iter()
        .any(|expected| {
            !status.lines().any(|line| {
                line.split_once(':').is_some_and(|(key, value)| {
                    key == expected
                        && value.trim()
                            == if matches!(expected, "NoNewPrivs" | "Threads") {
                                "1"
                            } else {
                                "0000000000000000"
                            }
                })
            })
        })
    {
        return Err(ProbeError::failed(
            "namespace helper must be single-threaded with all capabilities cleared and no_new_privs",
        ));
    }
    Ok(())
}
fn validate_namespace_owner(
    current_user: (u64, u64),
    owner: (u64, u64),
    mount_owner: Option<(u64, u64)>,
    owner_uid: u32,
    original_uid: u32,
) -> ProbeResultValue<()> {
    if owner == current_user {
        return Err(ProbeError::blocked(
            "namespace helper cannot acquire its host USER namespace",
        ));
    }
    if original_uid == 0 || owner_uid != original_uid {
        return Err(ProbeError::blocked(
            "pinned namespace USER owner differs from the helper UID",
        ));
    }
    if mount_owner.is_some_and(|mount_owner| mount_owner != owner) {
        return Err(ProbeError::blocked(
            "pinned NET and MNT namespaces have different USER owners",
        ));
    }
    Ok(())
}
fn namespace_owner(user: &File, net: &File, mount: Option<&File>) -> ProbeResultValue<File> {
    let proc = File::open("/proc")
        .map_err(|_| ProbeError::blocked("helper initial namespace observation unavailable"))?;
    require_unprivileged_helper(&proc)?;
    // SAFETY: these getters do not change credentials or capabilities.
    let uid = unsafe { nix::libc::getuid() };
    if uid == 0 || uid != unsafe { nix::libc::geteuid() } {
        return Err(ProbeError::blocked(
            "namespace helper requires its original unprivileged UID",
        ));
    }
    let current_user =
        namespace_identity(&open_at(&proc, c"self/ns/user")?, nix::libc::CLONE_NEWUSER)?;
    let current_net =
        namespace_identity(&open_at(&proc, c"self/ns/net")?, nix::libc::CLONE_NEWNET)?;
    if namespace_identity(user, nix::libc::CLONE_NEWUSER)? == current_user
        || namespace_identity(net, nix::libc::CLONE_NEWNET)? == current_net
    {
        return Err(ProbeError::blocked(
            "namespace helper cannot enter its host USER or NET namespace",
        ));
    }
    let owner = derived_namespace_owner(net, nix::libc::CLONE_NEWNET)?;
    let owner_identity = namespace_identity(&owner, nix::libc::CLONE_NEWUSER)?;
    // Reject the host USER before OWNER_UID, which is not defined for the initial USER namespace.
    if owner_identity == current_user {
        return Err(ProbeError::blocked(
            "namespace helper cannot acquire its host USER namespace",
        ));
    }
    let mut owner_uid: nix::libc::uid_t = 0;
    // SAFETY: owner is a validated USER namespace; the ioctl writes one uid_t.
    if unsafe {
        nix::libc::ioctl(
            owner.as_raw_fd(),
            nix::libc::NS_GET_OWNER_UID,
            &raw mut owner_uid,
        )
    } < 0
    {
        return Err(ProbeError::blocked(
            "pinned namespace USER owner UID unavailable",
        ));
    }
    let mut mount_owner_identity = None;
    if let Some(mount) = mount {
        let current_mount =
            namespace_identity(&open_at(&proc, c"self/ns/mnt")?, nix::libc::CLONE_NEWNS)?;
        if namespace_identity(mount, nix::libc::CLONE_NEWNS)? == current_mount {
            return Err(ProbeError::blocked(
                "namespace helper cannot enter its host MNT namespace",
            ));
        }
        let mount_owner = derived_namespace_owner(mount, nix::libc::CLONE_NEWNS)?;
        mount_owner_identity = Some(namespace_identity(&mount_owner, nix::libc::CLONE_NEWUSER)?);
    }
    validate_namespace_owner(
        current_user,
        owner_identity,
        mount_owner_identity,
        owner_uid,
        uid,
    )?;
    Ok(owner)
}
fn setns_namespace(namespace: &File, kind: i32) -> ProbeResultValue<()> {
    // SAFETY: only this single-threaded private helper enters the admitted, pinned namespace.
    if unsafe { nix::libc::setns(namespace.as_raw_fd(), kind) } != 0 {
        return Err(ProbeError::blocked(
            "kernel forbids the pinned namespace entry sequence",
        ));
    }
    Ok(())
}
fn enter_browser_namespaces(
    owner: &File,
    net: &File,
    mount: Option<&File>,
    user: &File,
    mut enter: impl FnMut(&File, i32) -> ProbeResultValue<()>,
) -> ProbeResultValue<()> {
    // Chromium's native USER namespace can be a child of the USER owning bwrap's NET/MNT.
    // Enter ancestor-owned namespaces before descending into Chromium's exact USER namespace.
    enter(owner, nix::libc::CLONE_NEWUSER)?;
    enter(net, nix::libc::CLONE_NEWNET)?;
    if let Some(mount) = mount {
        enter(mount, nix::libc::CLONE_NEWNS)?;
    }
    enter(user, nix::libc::CLONE_NEWUSER)
}
fn drop_namespace_privileges() -> ProbeResultValue<()> {
    for capability in 0..64 {
        if unsafe { nix::libc::prctl(nix::libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EINVAL) {
                break;
            }
            return Err(ProbeError::blocked(
                "namespace helper cannot drop its capability bounding set",
            ));
        }
    }
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_capset,
            &header as *const CapHeader,
            data.as_ptr(),
        )
    } != 0
        || unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(ProbeError::blocked(
            "namespace helper cannot clear capabilities and require no_new_privs",
        ));
    }
    Ok(())
}

fn open_at(directory: &File, relative: &std::ffi::CStr) -> ProbeResultValue<File> {
    let fd = unsafe {
        nix::libc::openat(
            directory.as_raw_fd(),
            relative.as_ptr(),
            nix::libc::O_RDONLY | nix::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ProbeError::blocked(
            "pinned namespace observation cannot open",
        ));
    }
    // SAFETY: openat returned a new descriptor; this File is its sole owner.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn canary_bytes(canary: &str) -> Vec<u8> {
    format!("browserd-owned-private-canary:{canary}\n").into_bytes()
}

fn isolation_helper(input: &Input, user: File, net: File) -> ProbeResultValue<()> {
    let canary = input
        .canary
        .as_deref()
        .ok_or_else(|| ProbeError::failed("isolation canary absent"))?;
    let pid = input.identity.pid();
    let mount = File::open(format!("/proc/{pid}/ns/mnt"))
        .map_err(|_| ProbeError::blocked("actual Chromium mount namespace unavailable"))?;
    let root = File::open(format!("/proc/{pid}/root"))
        .map_err(|_| ProbeError::blocked("actual Chromium root capability unavailable"))?;
    let proc = File::open("/proc")
        .map_err(|_| ProbeError::blocked("host proc observation capability unavailable"))?;
    let net_identity = namespace_identity(&net, nix::libc::CLONE_NEWNET)?;
    let mount_identity = namespace_identity(&mount, nix::libc::CLONE_NEWNS)?;
    let user_identity = namespace_identity(&user, nix::libc::CLONE_NEWUSER)?;
    let (net_inode, mount_inode, user_inode) = (net_identity.1, mount_identity.1, user_identity.1);
    let owner = namespace_owner(&user, &net, Some(&mount))?;
    let root_metadata = root
        .metadata()
        .map_err(|_| ProbeError::blocked("pinned root identity unavailable"))?;
    // Host evidence descriptors are opened before chroot. They cannot become
    // capabilities exported to the browser or be reached through its /proc.
    config::private_directory(
        input
            .output
            .parent()
            .ok_or_else(|| ProbeError::failed("private output parent absent"))?,
    )?;
    let mut evidence = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&input.output)
        .map_err(|_| ProbeError::failed("fresh private isolation output unavailable"))?;
    let output_directory = File::open(input.request.log_dir.clone())
        .map_err(|_| ProbeError::failed("private evidence directory unavailable"))?;
    if ChildIdentity::new(pid, process_start(pid)?) != input.identity {
        return Err(ProbeError::blocked(
            "actual Chromium changed before pinned root entry",
        ));
    }
    enter_browser_namespaces(&owner, &net, Some(&mount), &user, setns_namespace)?;
    for (name, expected, kind) in [
        (c"self/ns/user", user_identity, nix::libc::CLONE_NEWUSER),
        (c"self/ns/net", net_identity, nix::libc::CLONE_NEWNET),
        (c"self/ns/mnt", mount_identity, nix::libc::CLONE_NEWNS),
    ] {
        if namespace_identity(&open_at(&proc, name)?, kind)? != expected {
            return Err(ProbeError::failed(
                "helper entered a different namespace from its pinned process",
            ));
        }
    }
    if unsafe { nix::libc::fchdir(root.as_raw_fd()) } != 0
        || unsafe { nix::libc::chroot(c".".as_ptr()) } != 0
        || unsafe { nix::libc::chdir(c"/".as_ptr()) } != 0
    {
        return Err(ProbeError::blocked(
            "helper cannot enter the pinned actual Chromium root",
        ));
    }
    let observed_root =
        fs::metadata("/").map_err(|_| ProbeError::failed("entered root unavailable"))?;
    if observed_root.dev() != root_metadata.dev() || observed_root.ino() != root_metadata.ino() {
        return Err(ProbeError::failed(
            "helper root differs from its pinned Chromium root",
        ));
    }
    drop_namespace_privileges()?;
    require_unprivileged_helper(&proc)?;
    // The directory name is a validated random UUID; no caller-selected path is accepted.
    let directory = PathBuf::from(format!("/tmp/browserd-kernel-isolation-{canary}"));
    let expected = canary_bytes(canary);
    let (file_read, file_matches, file_errno) = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(directory.join("marker"))
    {
        Ok(mut file) => {
            let metadata = file
                .metadata()
                .map_err(|_| ProbeError::failed("private file canary metadata unavailable"))?;
            if !metadata.is_file() || metadata.len() > 512 {
                return Err(ProbeError::failed(
                    "accessible private canary is not a bounded regular file",
                ));
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take(513)
                .read_to_end(&mut bytes)
                .map_err(|_| ProbeError::failed("private canary read failed"))?;
            (true, bytes == expected, None)
        }
        Err(error) => (false, false, error.raw_os_error()),
    };
    let (socket_connected, socket_matches, socket_errno) =
        match UnixStream::connect(directory.join("socket")) {
            Ok(socket) => {
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|_| ProbeError::failed("private socket read ceiling unavailable"))?;
                let mut bytes = Vec::new();
                socket
                    .take(513)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ProbeError::failed("private socket canary read failed"))?;
                (true, bytes == expected, None)
            }
            Err(error) => (false, false, error.raw_os_error()),
        };
    let value = json!({"schema_version":1,"binding":input.request.binding,"nonce":input.nonce,"process_identity":input.identity,
        "network_namespace":net_inode,"mount_namespace":mount_inode,"user_namespace":user_inode,"root_device":observed_root.dev(),"root_inode":observed_root.ino(),
        "effective_capabilities":"0","no_new_privs":1,"file_read":file_read,"file_matches":file_matches,"file_errno":file_errno,
        "socket_connected":socket_connected,"socket_matches":socket_matches,"socket_errno":socket_errno});
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| ProbeError::failed("isolation evidence serialization failed"))?;
    evidence
        .write_all(&bytes)
        .and_then(|()| evidence.write_all(b"\n"))
        .and_then(|()| evidence.sync_all())
        .and_then(|()| output_directory.sync_all())
        .map_err(|_| ProbeError::failed("private isolation evidence durability failed"))
}

struct PrivateCanary {
    // This capability keeps the path tied to A's actual private tmpfs even if its PID exits.
    _tmp: File,
    directory: PathBuf,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<bool>>,
    complete: bool,
}
impl PrivateCanary {
    fn open(h: &Harness, session: &super::OwnedSession, nonce: &str) -> ProbeResultValue<Self> {
        let browser = process::browser_process(h, &session.shard)?;
        let tmp = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(format!("/proc/{}/root/tmp", browser.identity.pid()))
            .map_err(|_| {
                ProbeError::blocked("owned browser private tmpfs is inaccessible for canary setup")
            })?;
        if ChildIdentity::new(
            browser.identity.pid(),
            process_start(browser.identity.pid())?,
        ) != browser.identity
        {
            return Err(ProbeError::failed(
                "actual browser changed during private canary pin",
            ));
        }
        let directory = PathBuf::from(format!(
            "/proc/self/fd/{}/browserd-kernel-isolation-{nonce}",
            tmp.as_raw_fd()
        ));
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| {
                ProbeError::blocked("fresh actual private canary directory cannot be created")
            })?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut canary = Self {
            _tmp: tmp,
            directory,
            shutdown,
            thread: None,
            complete: false,
        };
        let bytes = canary_bytes(nonce);
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(canary.directory.join("marker"))
            .map_err(|_| ProbeError::failed("owned private file canary setup failed"))?;
        marker
            .write_all(&bytes)
            .and_then(|()| marker.sync_all())
            .map_err(|_| ProbeError::failed("owned private canary durability failed"))?;
        let listener = UnixListener::bind(canary.directory.join("socket"))
            .map_err(|_| ProbeError::failed("owned private socket canary setup failed"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ProbeError::failed("private socket nonblocking ceiling unavailable"))?;
        let stop = Arc::clone(&canary.shutdown);
        canary.thread = Some(
            std::thread::Builder::new()
                .name("kernel-private-socket".into())
                .spawn(move || {
                    let mut connections = 0;
                    while !stop.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((mut socket, _)) => {
                                connections += 1;
                                if connections > 16
                                    || socket
                                        .set_write_timeout(Some(Duration::from_secs(2)))
                                        .is_err()
                                    || socket.write_all(&bytes).is_err()
                                {
                                    return false;
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5))
                            }
                            Err(_) => return false,
                        }
                    }
                    true
                })
                .map_err(|_| ProbeError::failed("owned private socket worker unavailable"))?,
        );
        Ok(canary)
    }
    fn finish(&mut self) -> bool {
        if self.complete {
            return true;
        }
        self.shutdown.store(true, Ordering::Release);
        let mut complete = self
            .thread
            .take()
            .is_none_or(|thread| thread.join().is_ok_and(|result| result));
        for name in ["marker", "socket"] {
            complete &= match fs::remove_file(self.directory.join(name)) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
        }
        complete &= fs::remove_dir(&self.directory).is_ok();
        self.complete = complete;
        complete
    }
}
impl Drop for PrivateCanary {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.finish();
        }
    }
}

fn isolation_proof(
    value: &Value,
    browser: &process::ProcessProof,
    positive: bool,
) -> ProbeResultValue<()> {
    for (field, name) in [
        ("mount_namespace", "mnt"),
        ("user_namespace", "user"),
        ("network_namespace", "net"),
    ] {
        if value.get(field).and_then(Value::as_u64) != browser.namespaces.get(name).copied() {
            return Err(ProbeError::failed(
                "private canary evidence uses a different actual browser namespace",
            ));
        }
    }
    if value.get("effective_capabilities").and_then(Value::as_str) != Some("0")
        || value.get("no_new_privs") != Some(&json!(1))
    {
        return Err(ProbeError::failed(
            "private canary proof is not unprivileged",
        ));
    }
    if positive {
        if [
            "file_read",
            "file_matches",
            "socket_connected",
            "socket_matches",
        ]
        .into_iter()
        .any(|field| value.get(field) != Some(&Value::Bool(true)))
        {
            return Err(ProbeError::failed(
                "same-shard private file/socket canaries lack positive controls",
            ));
        }
    } else if value.get("file_read") != Some(&Value::Bool(false))
        || value.get("socket_connected") != Some(&Value::Bool(false))
        || ["file_errno", "socket_errno"].into_iter().any(|field| {
            !value
                .get(field)
                .and_then(Value::as_i64)
                .is_some_and(|errno| {
                    errno == i64::from(nix::libc::ENOENT) || errno == i64::from(nix::libc::EACCES)
                })
        })
    {
        return Err(ProbeError::failed(
            "sibling shard could access the private file/socket canary or denial was inconclusive",
        ));
    }
    Ok(())
}

pub(super) fn cross_shard_private_isolation(
    h: &Harness,
    a: &super::OwnedSession,
    b: &super::OwnedSession,
) -> ProbeResultValue<Value> {
    h.check_deadline()?;
    let a_process = process::browser_process(h, &a.shard)?;
    let b_process = process::browser_process(h, &b.shard)?;
    if a.shard == b.shard
        || a_process.identity == b_process.identity
        || a_process.namespaces.get("mnt") == b_process.namespaces.get("mnt")
    {
        return Err(ProbeError::failed(
            "file/socket isolation requires distinct actual owned mount namespaces",
        ));
    }
    let nonce = uuid::Uuid::new_v4().to_string();
    let mut canary = PrivateCanary::open(h, a, &nonce)?;
    let observed = (|| {
        let mut first = spawn_with_canary(h, a, "isolation", Some(&nonce))?;
        let positive = completed_output(h, &mut first)?;
        isolation_proof(&positive, &a_process, true)?;
        let mut second = spawn_with_canary(h, b, "isolation", Some(&nonce))?;
        let negative = completed_output(h, &mut second)?;
        isolation_proof(&negative, &b_process, false)?;
        // Recheck A after B's attempts so an absent/dead canary cannot prove isolation.
        let mut control = spawn_with_canary(h, a, "isolation", Some(&nonce))?;
        let after = completed_output(h, &mut control)?;
        isolation_proof(&after, &a_process, true)?;
        for identity in [a_process.identity, b_process.identity] {
            if ChildIdentity::new(identity.pid(), process_start(identity.pid())?) != identity {
                return Err(ProbeError::failed(
                    "owned browser exited or changed during private isolation proof",
                ));
            }
        }
        Ok(
            json!({"shard_a":a.shard,"shard_b":b.shard,"same_shard_file_and_socket_positive":true,
            "sibling_file_and_socket_denied":true,"positive_control_after_denial":true,
            "namespace_a":positive,"namespace_b":negative}),
        )
    })();
    if !canary.finish() {
        return Err(ProbeError::failed(
            "owned private isolation canary cleanup incomplete",
        ));
    }
    observed
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::super::super::rpc::TraceEntry;
    use super::*;
    use browserd_core::{LaunchGeneration, OwnerFence, ShardId, WorkerEpoch, WorkerId};
    use std::collections::BTreeMap;

    fn shard() -> ShardFence {
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new("kernel-network-test").expect("worker"),
                WorkerEpoch::new(3).expect("epoch"),
            ),
            ShardId::new(),
            LaunchGeneration::new(4).expect("generation"),
        )
    }
    fn browser() -> process::ProcessProof {
        process::ProcessProof {
            identity: ChildIdentity::new(10, 20),
            net_namespace: 31,
            namespaces: BTreeMap::from([
                ("mnt".into(), 30),
                ("net".into(), 31),
                ("user".into(), 32),
            ]),
            status: BTreeMap::new(),
            argv: Vec::new(),
        }
    }
    fn isolated(positive: bool) -> Value {
        json!({"mount_namespace":30,"network_namespace":31,"user_namespace":32,
            "effective_capabilities":"0","no_new_privs":1,"file_read":positive,"file_matches":positive,
            "socket_connected":positive,"socket_matches":positive,"file_errno":nix::libc::ENOENT,"socket_errno":nix::libc::ENOENT})
    }
    #[test]
    fn private_canary_requires_both_same_shard_positive_controls() {
        let browser = browser();
        assert!(isolation_proof(&isolated(true), &browser, true).is_ok());
        for field in [
            "file_read",
            "file_matches",
            "socket_connected",
            "socket_matches",
        ] {
            let mut value = isolated(true);
            value[field] = json!(false);
            assert!(isolation_proof(&value, &browser, true).is_err());
        }
    }
    #[test]
    fn sibling_isolation_rejects_leaks_wrong_namespaces_and_inconclusive_errors() {
        let browser = browser();
        assert!(isolation_proof(&isolated(false), &browser, false).is_ok());
        for field in ["file_read", "socket_connected"] {
            let mut value = isolated(false);
            value[field] = json!(true);
            assert!(isolation_proof(&value, &browser, false).is_err());
        }
        for field in ["mount_namespace", "network_namespace", "user_namespace"] {
            let mut value = isolated(false);
            value[field] = json!(999);
            assert!(isolation_proof(&value, &browser, false).is_err());
        }
        for errno in [
            nix::libc::ECONNREFUSED,
            nix::libc::ETIMEDOUT,
            nix::libc::EMFILE,
        ] {
            let mut value = isolated(false);
            value["socket_errno"] = json!(errno);
            assert!(isolation_proof(&value, &browser, false).is_err());
        }
        let mut value = isolated(false);
        value["effective_capabilities"] = json!("1");
        assert!(isolation_proof(&value, &browser, false).is_err());
    }
    #[test]
    fn browser_network_denial_requires_exact_successful_command_reply_pair() {
        let shard = shard();
        let url = "http://127.0.0.1:10000/owned";
        let command = TraceEntry {
            sequence: 1,
            shard: shard.clone(),
            direction: TraceDirection::Command,
            id: Some(9),
            session_id: Some("owned".into()),
            method: Some("Page.navigate".into()),
            summary: json!({"params":{"url":url}}),
        };
        let reply = TraceEntry {
            sequence: 2,
            shard: shard.clone(),
            direction: TraceDirection::Reply,
            id: Some(9),
            session_id: Some("owned".into()),
            method: None,
            summary: json!({"success":true,"result":{"errorText":"net::ERR_PROXY_CONNECTION_FAILED"}}),
        };
        assert!(navigation_denied(
            &[command.clone(), reply.clone()],
            &shard,
            url
        ));
        let mut other = reply.clone();
        other.session_id = Some("foreign".into());
        assert!(!navigation_denied(&[command.clone(), other], &shard, url));
        let mut early = reply.clone();
        early.sequence = 0;
        assert!(!navigation_denied(&[command.clone(), early], &shard, url));
        let mut unsuccessful = reply.clone();
        unsuccessful.summary["success"] = json!(false);
        assert!(!navigation_denied(
            &[command.clone(), unsuccessful],
            &shard,
            url
        ));
        let mut protocol_error = reply;
        protocol_error.summary["error"] = json!({"code":-1});
        assert!(!navigation_denied(&[command, protocol_error], &shard, url));
    }
    #[test]
    fn public_fixture_rejects_private_reserved_and_mapped_loopback_ips() {
        for origin in [
            "http://10.0.0.1",
            "http://198.51.100.1",
            "http://127.0.0.1",
            "http://[::ffff:127.0.0.1]",
        ] {
            assert!(public_addresses(origin).is_err());
        }
        assert_eq!(
            public_addresses("http://93.184.216.34:31338").expect("literal public fixture"),
            vec![
                "93.184.216.34:31338"
                    .parse::<SocketAddr>()
                    .expect("address")
            ]
        );
    }
    #[test]
    fn namespace_entry_uses_owner_before_network_mount_and_browser_user() {
        let owner = tempfile::tempfile().expect("owner descriptor");
        let net = tempfile::tempfile().expect("network descriptor");
        let mount = tempfile::tempfile().expect("mount descriptor");
        let user = tempfile::tempfile().expect("browser user descriptor");
        for isolation in [false, true] {
            let mut observed = Vec::new();
            assert!(
                enter_browser_namespaces(
                    &owner,
                    &net,
                    isolation.then_some(&mount),
                    &user,
                    |descriptor, kind| {
                        observed.push((descriptor.as_raw_fd(), kind));
                        Ok(())
                    },
                )
                .is_ok()
            );
            let mut expected = vec![
                (owner.as_raw_fd(), nix::libc::CLONE_NEWUSER),
                (net.as_raw_fd(), nix::libc::CLONE_NEWNET),
            ];
            if isolation {
                expected.push((mount.as_raw_fd(), nix::libc::CLONE_NEWNS));
            }
            expected.push((user.as_raw_fd(), nix::libc::CLONE_NEWUSER));
            assert_eq!(observed, expected);
        }
    }
    #[test]
    fn namespace_entry_failure_prevents_descendant_entry() {
        let owner = tempfile::tempfile().expect("owner descriptor");
        let net = tempfile::tempfile().expect("network descriptor");
        let mount = tempfile::tempfile().expect("mount descriptor");
        let user = tempfile::tempfile().expect("browser user descriptor");
        for failed in [owner.as_raw_fd(), net.as_raw_fd(), mount.as_raw_fd()] {
            let mut observed = Vec::new();
            assert!(
                enter_browser_namespaces(&owner, &net, Some(&mount), &user, |descriptor, _| {
                    observed.push(descriptor.as_raw_fd());
                    if descriptor.as_raw_fd() == failed {
                        Err(ProbeError::blocked("test kernel denial"))
                    } else {
                        Ok(())
                    }
                },)
                .is_err()
            );
            assert_eq!(observed.last().copied(), Some(failed));
            assert!(!observed.contains(&user.as_raw_fd()));
        }
    }
    #[test]
    fn namespace_owner_rejects_host_foreign_owner_and_wrong_uid() {
        let host = (1, 10);
        let owner = (1, 20);
        assert!(validate_namespace_owner(host, owner, None, 1003, 1003).is_ok());
        assert!(validate_namespace_owner(host, owner, Some(owner), 1003, 1003).is_ok());
        assert!(validate_namespace_owner(host, host, None, 1003, 1003).is_err());
        assert!(validate_namespace_owner(host, owner, Some((1, 21)), 1003, 1003).is_err());
        assert!(validate_namespace_owner(host, owner, Some((2, 20)), 1003, 1003).is_err());
        assert!(validate_namespace_owner(host, owner, None, 1004, 1003).is_err());
        assert!(validate_namespace_owner(host, owner, None, 0, 0).is_err());
    }
    #[test]
    fn namespace_owner_ioctl_rejects_regular_and_wrong_type_descriptors_without_entry() {
        let before = ["user", "net", "mnt"].map(|name| {
            let metadata = fs::metadata(format!("/proc/self/ns/{name}")).expect("parent namespace");
            (metadata.dev(), metadata.ino())
        });
        let user = File::open("/proc/self/ns/user").expect("actual USER namespace descriptor");
        let net = File::open("/proc/self/ns/net").expect("actual NET namespace descriptor");
        let regular = tempfile::tempfile().expect("ordinary file descriptor");
        assert!(namespace_identity(&user, nix::libc::CLONE_NEWUSER).is_ok());
        assert!(namespace_identity(&net, nix::libc::CLONE_NEWNET).is_ok());
        assert!(derived_namespace_owner(&user, nix::libc::CLONE_NEWNET).is_err());
        assert!(derived_namespace_owner(&net, nix::libc::CLONE_NEWNS).is_err());
        assert!(derived_namespace_owner(&regular, nix::libc::CLONE_NEWNET).is_err());
        let after = ["user", "net", "mnt"].map(|name| {
            let metadata =
                fs::metadata(format!("/proc/self/ns/{name}")).expect("unchanged parent namespace");
            (metadata.dev(), metadata.ino())
        });
        assert_eq!(before, after);
    }
}
