#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs::File;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use browserd_core::{
    EgressFence, LaunchGeneration, LeaseId, OwnerFence, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, ChromiumCdpPipes, DedicatedEgressProxyBinding, DedicatedEgressSpec,
    EgressPolicyBinding, LaunchSpec, PinnedNetworkNamespace, SandboxRpcClient, SandboxRpcError,
    ShardEgressReservation, ShardIngressLease, ShardIngressReceipt,
};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use nix::fcntl::OFlag;
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use nix::sys::stat::fstat;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::UnixListener;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

fn spec() -> LaunchSpec {
    let fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new("scratch-worker").unwrap(),
                WorkerEpoch::new(7).unwrap(),
            ),
            ShardId::new(),
            LaunchGeneration::new(1).unwrap(),
        ),
        RouteGeneration::new(1).unwrap(),
        SessionId::new(),
        SessionIncarnation::new(1).unwrap(),
    );
    LaunchSpec::production(
        TenantId::new(),
        DedicatedEgressSpec::new(
            fence,
            EgressPolicyBinding::new("scratch-test", [1; 32]).unwrap(),
            Duration::from_secs(1),
        )
        .unwrap(),
        ChromiumBinaryDigest::new([2; 32]),
    )
}

fn binding(spec: &LaunchSpec) -> DedicatedEgressProxyBinding {
    let namespace = PinnedNetworkNamespace::from_owned_fd(
        File::open("/proc/thread-self/ns/net").unwrap().into(),
    )
    .unwrap();
    DedicatedEgressProxyBinding::from_lease(&ShardIngressLease::from_attachment(
        ShardEgressReservation::from_launch_spec(spec),
        namespace.identity(),
        ShardIngressReceipt::with_proxy_address("127.0.0.1:20124".parse().unwrap()).unwrap(),
    ))
    .unwrap()
}

fn metadata(binding: &DedicatedEgressProxyBinding, identity: (u64, u64)) -> Value {
    json!({"version":1,"sandbox_path":"/profile/browserd-files","max_bytes":33554432,
        "owner_uid":nix::unistd::geteuid().as_raw(),"device":identity.0,"inode":identity.1,"binding":binding})
}

async fn offer(
    spec: &LaunchSpec,
    bound: &DedicatedEgressProxyBinding,
    scratch: Value,
    directory: Option<OwnedFd>,
    expect_success: bool,
) -> Result<ChromiumCdpPipes, SandboxRpcError> {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("scratch.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let transfer_id = LeaseId::new();
    let response = json!({"status":"success","value":{"result":"cdp_pipes_ready","value":{
        "transfer_id":transfer_id,"egress_proxy_binding":bound,"scratch":scratch}}});
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        framed.next().await.unwrap().unwrap();
        framed
            .send(Bytes::from(serde_json::to_vec(&response).unwrap()))
            .await
            .unwrap();
        let mut stream = framed.into_inner();
        let mut ready = [0u8; 17];
        if directory.is_none() {
            assert_eq!(
                stream.read(&mut ready).await.unwrap(),
                0,
                "invalid metadata must not reach descriptor READY"
            );
            return;
        }
        stream.read_exact(&mut ready).await.unwrap();
        assert_eq!(ready[0], 0x51);
        assert_eq!(&ready[1..], transfer_id.as_bytes());
        let (_command_reader, command_writer) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let (event_reader, _event_writer) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let directory = directory.unwrap();
        let descriptors = [
            command_writer.as_raw_fd(),
            event_reader.as_raw_fd(),
            directory.as_raw_fd(),
        ];
        stream
            .async_io(Interest::WRITABLE, || {
                sendmsg::<()>(
                    stream.as_raw_fd(),
                    &[IoSlice::new(&[0x52])],
                    &[ControlMessage::ScmRights(&descriptors)],
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                    None,
                )
                .map_err(std::io::Error::from)
            })
            .await
            .unwrap();
        if !expect_success {
            let mut ack = [0u8; 17];
            assert_eq!(
                stream.read(&mut ack).await.unwrap(),
                0,
                "a swapped directory must not receive descriptor ACCEPTED"
            );
            return;
        }
        let challenge = LeaseId::new();
        stream.write_all(challenge.as_bytes()).await.unwrap();
        let mut ack = [0u8; 17];
        stream.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack[0], 0x53);
        assert_eq!(&ack[1..], challenge.as_bytes());
        ack[0] = 0x54;
        stream.write_all(&ack).await.unwrap();
        stream.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack[0], 0x55);
        ack[0] = 0x56;
        stream.write_all(&ack).await.unwrap();
    });
    let client = SandboxRpcClient::new(
        socket,
        16 * 1024,
        Duration::from_secs(2),
        nix::unistd::geteuid().as_raw(),
        1,
    )
    .unwrap();
    let result = client
        .claim_cdp_pipes(
            spec.shard_id(),
            spec.worker_id(),
            spec.worker_epoch(),
            spec.launch_generation(),
        )
        .await;
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    result
}

#[tokio::test]
async fn scratch_metadata_with_a_different_session_is_rejected_before_ready() {
    let spec = spec();
    let expected = binding(&spec);
    let other = binding(&self::spec());
    assert!(
        offer(&spec, &expected, metadata(&other, (1, 1)), None, false)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn scratch_metadata_with_a_different_path_or_ceiling_is_rejected_before_ready() {
    let spec = spec();
    let expected = binding(&spec);
    for (name, value) in [
        ("sandbox_path", json!("/tmp")),
        ("max_bytes", json!(67108864)),
        ("inode", json!(0)),
    ] {
        let mut wrong = metadata(&expected, (1, 1));
        wrong[name] = value;
        assert!(offer(&spec, &expected, wrong, None, false).await.is_err());
    }
}

#[test]
#[ignore = "requires isolated Linux user/mount namespaces for an actual bounded tmpfs capability"]
fn three_fd_rpc_preserves_exact_directory_and_rejects_swapped_inode() {
    if std::env::var_os("BROWSERD_SCRATCH_RPC_HELPER").is_none() {
        let output = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--fork"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "three_fd_rpc_preserves_exact_directory_and_rejects_swapped_inode",
                "--nocapture",
            ])
            .env("BROWSERD_SCRATCH_RPC_HELPER", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "scratch RPC namespace proof failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use nix::mount::{MsFlags, mount, umount};
    let mountpoint = tempfile::tempdir().unwrap();
    mount(
        Some("tmpfs"),
        mountpoint.path(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=33554432,mode=0700"),
    )
    .unwrap();
    let original = File::open(mountpoint.path()).unwrap();
    let stat = fstat(&original).unwrap();
    let identity = (stat.st_dev, stat.st_ino);
    let other = mountpoint.path().join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let spec = spec();
            let binding = binding(&spec);
            let mut pipes = offer(
                &spec,
                &binding,
                metadata(&binding, identity),
                Some(original.try_clone().unwrap().into()),
                true,
            )
            .await
            .unwrap();
            let scratch = pipes
                .take_scratch()
                .expect("third capability must be attached");
            assert!(scratch.metadata().matches_launch(&spec));
            let received = fstat(scratch.directory()).unwrap();
            assert_eq!((received.st_dev, received.st_ino), identity);
            assert!(
                offer(
                    &spec,
                    &binding,
                    metadata(&binding, identity),
                    Some(File::open(&other).unwrap().into()),
                    false
                )
                .await
                .is_err()
            );
        });
    drop(original);
    umount(mountpoint.path()).unwrap();
}
