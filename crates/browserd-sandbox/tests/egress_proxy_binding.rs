#![allow(clippy::expect_used)]

use std::fs::File;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::time::Duration;

use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, ChromiumCdpPipes, DedicatedEgressProxyBinding, DedicatedEgressSpec,
    EgressPolicyBinding, LaunchSpec, PinnedNetworkNamespace, ShardEgressFence,
    ShardEgressReservation, ShardIngressLease, ShardIngressReceipt,
};
use serde_json::{Value, json};

fn launch_spec() -> LaunchSpec {
    let fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new("proxy-binding-worker").expect("valid worker ID"),
                WorkerEpoch::new(7).expect("nonzero worker epoch"),
            ),
            ShardId::new(),
            LaunchGeneration::new(11).expect("nonzero launch generation"),
        ),
        RouteGeneration::new(13).expect("nonzero route generation"),
        SessionId::new(),
        SessionIncarnation::new(17).expect("nonzero session incarnation"),
    );
    LaunchSpec::production(
        TenantId::new(),
        DedicatedEgressSpec::new(
            fence,
            EgressPolicyBinding::new("public-web", [0x42; 32]).expect("valid policy binding"),
            Duration::from_secs(30),
        )
        .expect("valid dedicated egress spec"),
        ChromiumBinaryDigest::new([0x24; 32]),
    )
}

fn lease(spec: &LaunchSpec, receipt: ShardIngressReceipt) -> ShardIngressLease {
    let descriptor: OwnedFd = File::open("/proc/self/ns/net")
        .expect("current network namespace opens")
        .into();
    let namespace = PinnedNetworkNamespace::from_owned_fd(descriptor)
        .expect("current network namespace can be pinned");
    ShardIngressLease::from_attachment(
        ShardEgressReservation::from_launch_spec(spec),
        namespace.identity(),
        receipt,
    )
}

fn binding(spec: &LaunchSpec) -> DedicatedEgressProxyBinding {
    let receipt = ShardIngressReceipt::with_proxy_address(address())
        .expect("fixed IPv4 loopback listener is valid");
    DedicatedEgressProxyBinding::from_lease(&lease(spec, receipt))
        .expect("complete exact ingress lease creates a binding")
}

fn address() -> SocketAddr {
    "127.0.0.1:43117"
        .parse()
        .expect("valid fixed loopback address")
}

fn raw_pipes() -> ChromiumCdpPipes {
    let (command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe opens");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe opens");
    drop(command_reader);
    drop(event_writer);
    ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
        .expect("owned CDP directions are valid")
}

#[test]
fn ingress_receipt_accepts_only_the_fixed_nonzero_ipv4_loopback_endpoint() {
    let receipt = ShardIngressReceipt::with_proxy_address(address())
        .expect("the internally selected listener endpoint is valid");
    assert_eq!(receipt.proxy_address(), Some(address()));
    assert_eq!(ShardIngressReceipt::new().proxy_address(), None);
    assert_eq!(ShardIngressReceipt::default().proxy_address(), None);
    for invalid in [
        "127.0.0.1:0",
        "127.0.0.2:43117",
        "0.0.0.0:43117",
        "192.0.2.1:43117",
        "[::1]:43117",
    ] {
        assert!(
            ShardIngressReceipt::with_proxy_address(invalid.parse().expect("valid socket syntax"))
                .is_err(),
            "caller-selected endpoint {invalid} must fail closed"
        );
    }
}

#[test]
fn proxy_binding_round_trip_preserves_every_exact_lease_identity() {
    let spec = launch_spec();
    let ingress = lease(
        &spec,
        ShardIngressReceipt::with_proxy_address(address()).expect("valid listener address"),
    );
    let binding = DedicatedEgressProxyBinding::from_lease(&ingress).expect("valid lease binding");
    assert_eq!(binding.proxy_address(), address());
    assert_eq!(
        binding.egress_fence(),
        spec.dedicated_egress().egress_fence()
    );
    assert_eq!(binding.tenant_id(), spec.tenant_id());
    assert_eq!(
        binding.policy_binding(),
        spec.dedicated_egress().policy_binding()
    );
    assert_eq!(binding.namespace_identity(), ingress.namespace_identity());
    assert_eq!(
        binding.reservation_generation(),
        ingress.reservation().generation()
    );
    assert_eq!(
        binding.attachment_generation(),
        ingress.receipt().attachment_generation()
    );
    assert!(binding.matches_launch(&spec));
    let decoded: DedicatedEgressProxyBinding =
        serde_json::from_slice(&serde_json::to_vec(&binding).expect("serialize binding"))
            .expect("deserialize exact binding");
    assert_eq!(decoded, binding);
    assert!(decoded.matches_launch(&spec));
}

#[test]
fn legacy_or_unbound_receipts_cannot_become_production_proxy_bindings() {
    let spec = launch_spec();
    assert!(
        DedicatedEgressProxyBinding::from_lease(&lease(&spec, ShardIngressReceipt::new())).is_err()
    );
    let bound_lease = lease(
        &spec,
        ShardIngressReceipt::with_proxy_address(address()).expect("valid listener address"),
    );
    let unbound = ShardIngressLease::from_attachment(
        ShardEgressReservation::new(ShardEgressFence::new(
            spec.shard_id().clone(),
            spec.worker_epoch(),
        )),
        bound_lease.namespace_identity(),
        bound_lease.receipt().clone(),
    );
    assert!(DedicatedEgressProxyBinding::from_lease(&unbound).is_err());
}

#[test]
fn matching_the_port_does_not_authorize_another_tenant_route_or_policy() {
    let spec = launch_spec();
    let endpoint = binding(&spec);
    let mut altered = serde_json::to_value(&spec).expect("serialize launch spec");
    altered["tenant_id"] = serde_json::to_value(TenantId::new()).expect("serialize tenant ID");
    let other_tenant: LaunchSpec = serde_json::from_value(altered).expect("different valid tenant");
    assert!(!endpoint.matches_launch(&other_tenant));

    let other_route = launch_spec();
    assert_eq!(
        binding(&other_route).proxy_address(),
        endpoint.proxy_address()
    );
    assert!(!endpoint.matches_launch(&other_route));

    let mut altered = serde_json::to_value(&spec).expect("serialize launch spec");
    altered["dedicated_egress"]["policy_binding"]["snapshot_digest"] =
        serde_json::to_value([0x43_u8; 32]).expect("serialize different policy digest");
    let other_policy: LaunchSpec = serde_json::from_value(altered).expect("different valid policy");
    assert!(!endpoint.matches_launch(&other_policy));
}

#[test]
fn every_egress_fence_component_is_required_even_when_the_endpoint_is_unchanged() {
    let spec = launch_spec();
    let original = serde_json::to_value(binding(&spec)).expect("serialize binding");
    for (path, replacement) in [
        (
            "/egress_fence/shard/owner/worker_id",
            json!("another-worker"),
        ),
        ("/egress_fence/shard/owner/worker_epoch", json!(8)),
        ("/egress_fence/shard/shard_id", json!(ShardId::new())),
        ("/egress_fence/shard/launch_generation", json!(12)),
        ("/egress_fence/route_generation", json!(14)),
        ("/egress_fence/session_id", json!(SessionId::new())),
        ("/egress_fence/session_incarnation", json!(18)),
    ] {
        let mut altered = original.clone();
        *altered.pointer_mut(path).expect("fence component exists") = replacement;
        let other: DedicatedEgressProxyBinding = serde_json::from_value(altered)
            .expect("different nonzero fence is syntactically valid");
        assert_eq!(other.proxy_address(), address());
        assert!(
            !other.matches_launch(&spec),
            "changed {path} must reject this launch"
        );
    }
}

#[test]
fn binding_deserialization_rejects_missing_unknown_and_invalid_contract_fields() {
    let original = serde_json::to_value(binding(&launch_spec())).expect("serialize binding");
    let mut altered = original.clone();
    altered["untrusted_proxy_bypass"] = json!("*");
    assert!(serde_json::from_value::<DedicatedEgressProxyBinding>(altered).is_err());

    for field in [
        "tenant_id",
        "egress_fence",
        "policy_binding",
        "namespace_identity",
        "reservation_generation",
        "attachment_generation",
        "proxy_address",
    ] {
        let mut altered = original.clone();
        altered
            .as_object_mut()
            .expect("binding is an object")
            .remove(field);
        assert!(
            serde_json::from_value::<DedicatedEgressProxyBinding>(altered).is_err(),
            "missing {field} must not acquire an implicit legacy default"
        );
    }
    for field in ["reservation_generation", "attachment_generation"] {
        let mut altered = original.clone();
        altered[field] = json!("00000000-0000-0000-0000-000000000000");
        assert!(serde_json::from_value::<DedicatedEgressProxyBinding>(altered).is_err());
    }
    for field in ["device", "inode"] {
        let mut altered = original.clone();
        altered["namespace_identity"][field] = json!(0);
        assert!(serde_json::from_value::<DedicatedEgressProxyBinding>(altered).is_err());
    }
    let mut altered = original.clone();
    altered["namespace_identity"]["unknown_namespace_field"] = json!(1);
    assert!(serde_json::from_value::<DedicatedEgressProxyBinding>(altered).is_err());
    for invalid_policy in [
        json!({"profile":"", "snapshot_digest": [1, 2]}),
        json!({"profile":"public-web", "snapshot_digest": vec![0_u8; 32]}),
        json!({"profile":"Public-Web", "snapshot_digest": vec![1_u8; 32]}),
    ] {
        let mut altered = original.clone();
        altered["policy_binding"] = invalid_policy;
        assert!(serde_json::from_value::<DedicatedEgressProxyBinding>(altered).is_err());
    }
    for invalid in [
        "127.0.0.1:0",
        "127.0.0.2:43117",
        "192.0.2.1:43117",
        "[::1]:43117",
    ] {
        let mut altered = original.clone();
        altered["proxy_address"] = Value::String(invalid.to_owned());
        assert!(serde_json::from_value::<DedicatedEgressProxyBinding>(altered).is_err());
    }
}

#[test]
fn raw_cdp_pipe_ownership_is_unchanged_and_binding_cannot_be_replaced() {
    let endpoint = binding(&launch_spec());
    let pipes = raw_pipes();
    assert!(pipes.egress_proxy_binding().is_none());
    let pipes = pipes
        .with_egress_proxy_binding(endpoint.clone())
        .expect("first binding attaches");
    assert_eq!(pipes.egress_proxy_binding(), Some(&endpoint));
    assert!(
        pipes
            .with_egress_proxy_binding(binding(&launch_spec()))
            .is_err()
    );

    let pipes = raw_pipes()
        .with_egress_proxy_binding(endpoint)
        .expect("first binding attaches");
    let (writer, reader) = pipes.into_owned_fds();
    let reconstructed = ChromiumCdpPipes::from_owned_fds(writer, reader)
        .expect("raw descriptors still reconstruct without changing ownership");
    assert!(reconstructed.egress_proxy_binding().is_none());
}
