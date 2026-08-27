#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, WorkerEpoch, WorkerId,
};

use crate::{
    AttachmentError, AttachmentExpiry, AttachmentRegistry, AttachmentState, AttachmentStatus,
    BindingDigest, DaemonEpoch, InstallReceipt,
};

fn fence(seed: u64) -> EgressFence {
    full_fence(
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new(format!("worker-{seed}")).expect("valid worker ID"),
                WorkerEpoch::new(seed).expect("non-zero worker epoch"),
            ),
            ShardId::new(),
            LaunchGeneration::new(seed).expect("non-zero launch generation"),
        ),
        seed,
    )
}

fn full_fence(shard: ShardFence, seed: u64) -> EgressFence {
    EgressFence::new(
        shard,
        RouteGeneration::new(seed).expect("non-zero route generation"),
        SessionId::new(),
        SessionIncarnation::new(seed).expect("non-zero session incarnation"),
    )
}

#[test]
fn one_dedicated_shard_fence_cannot_prepare_a_second_egress_fence() {
    let epoch = DaemonEpoch::new(5).expect("non-zero daemon epoch");
    let shard = ShardFence::new(
        OwnerFence::new(
            WorkerId::new("single-route-worker").expect("valid worker ID"),
            WorkerEpoch::new(5).expect("non-zero worker epoch"),
        ),
        ShardId::new(),
        LaunchGeneration::new(5).expect("non-zero launch generation"),
    );
    let first_fence = full_fence(shard.clone(), 51);
    let second_fence = full_fence(shard, 52);
    let mut registry = AttachmentRegistry::new(epoch);
    let prepared = registry
        .prepare(epoch, first_fence, digest(51))
        .expect("first route prepares");

    assert_eq!(
        registry.prepare(epoch, second_fence.clone(), digest(52)),
        Err(AttachmentError::ShardAttachmentConflict)
    );

    let install = registry
        .begin_install(&prepared, address(30_051), AttachmentExpiry::new(51_000))
        .expect("first route install starts");
    assert!(matches!(install, InstallReceipt::Installing(_)));
    let InstallReceipt::Installing(installing) = install else {
        return;
    };
    registry
        .complete_install(&installing)
        .expect("first route activates");
    assert_eq!(
        registry.prepare(epoch, second_fence, digest(52)),
        Err(AttachmentError::ShardAttachmentConflict),
        "activation does not free the shard for a second route"
    );
}

#[test]
fn install_rejects_invalid_proxy_metadata_without_leaving_prepared() {
    let epoch = DaemonEpoch::new(6).expect("non-zero daemon epoch");
    let route_fence = fence(61);
    let mut registry = AttachmentRegistry::new(epoch);
    let prepared = registry
        .prepare(epoch, route_fence.clone(), digest(61))
        .expect("route prepares");

    for invalid_address in [
        address(0),
        "0.0.0.0:31061".parse().expect("valid address"),
        "192.0.2.1:31061".parse().expect("valid address"),
    ] {
        assert_eq!(
            registry.begin_install(&prepared, invalid_address, AttachmentExpiry::new(61_000),),
            Err(AttachmentError::InvalidProxyAddress(invalid_address))
        );
    }
    assert_eq!(
        registry.begin_install(&prepared, address(31_061), AttachmentExpiry::new(0)),
        Err(AttachmentError::InvalidExpiry)
    );
    assert_eq!(
        registry.state(epoch, &route_fence),
        Ok(AttachmentState::Prepared),
        "invalid metadata cannot publish Installing"
    );
}

fn digest(byte: u8) -> BindingDigest {
    BindingDigest::new([byte; 32])
}

fn address(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[test]
fn prepare_is_keyed_by_the_full_fence_and_is_exactly_idempotent() {
    let epoch = DaemonEpoch::new(7).expect("non-zero daemon epoch");
    let route_fence = fence(1);
    let mut registry = AttachmentRegistry::new(epoch);

    assert_eq!(
        registry.status(epoch, &route_fence),
        Ok(AttachmentStatus::Absent)
    );

    let first = registry
        .prepare(epoch, route_fence.clone(), digest(1))
        .expect("first preparation succeeds");
    let retry = registry
        .prepare(epoch, route_fence.clone(), digest(1))
        .expect("exact preparation retry succeeds");

    assert_eq!(first, retry);
    assert_eq!(first.fence(), &route_fence);
    assert_eq!(first.binding_digest(), digest(1));
    assert_eq!(first.daemon_epoch(), epoch);
    assert_eq!(
        registry.status(epoch, &route_fence),
        Ok(AttachmentStatus::Prepared(first.clone()))
    );
    assert_eq!(
        registry.prepare(epoch, route_fence, digest(2)),
        Err(AttachmentError::BindingConflict)
    );
}

#[test]
fn install_retry_requires_exact_listener_metadata_and_preserves_receipts() {
    let epoch = DaemonEpoch::new(11).expect("non-zero daemon epoch");
    let route_fence = fence(2);
    let mut registry = AttachmentRegistry::new(epoch);
    let prepared = registry
        .prepare(epoch, route_fence.clone(), digest(2))
        .expect("preparation succeeds");
    let first_expiry = AttachmentExpiry::new(10_000);

    let install = registry
        .begin_install(&prepared, address(30_001), first_expiry)
        .expect("install starts");
    assert!(matches!(install, InstallReceipt::Installing(_)));
    let InstallReceipt::Installing(installing) = install else {
        return;
    };
    let retry = registry
        .begin_install(&prepared, address(30_001), first_expiry)
        .expect("exact install retry succeeds");

    assert_eq!(retry, InstallReceipt::Installing(installing.clone()));
    assert_eq!(
        registry.begin_install(&prepared, address(30_999), first_expiry),
        Err(AttachmentError::InstallConflict)
    );
    assert_eq!(
        registry.begin_install(&prepared, address(30_001), AttachmentExpiry::new(99_999),),
        Err(AttachmentError::InstallConflict)
    );
    assert_eq!(installing.proxy_address(), address(30_001));
    assert_eq!(installing.expires_at(), first_expiry);
    assert_eq!(
        registry.status(epoch, &route_fence),
        Ok(AttachmentStatus::Installing(installing.clone()))
    );

    let active = registry
        .complete_install(&installing)
        .expect("install completes");
    assert_eq!(active.proxy_address(), address(30_001));
    assert_eq!(active.expires_at(), first_expiry);
    assert_eq!(active.prepared(), &prepared);
    assert_eq!(
        registry
            .begin_install(&prepared, address(30_001), first_expiry)
            .expect("exact active install retry succeeds"),
        InstallReceipt::Active(active.clone())
    );
    assert_eq!(
        registry.begin_install(&prepared, address(31_000), AttachmentExpiry::new(100_000),),
        Err(AttachmentError::InstallConflict)
    );
    assert_eq!(
        registry.status(epoch, &route_fence),
        Ok(AttachmentStatus::Active(active))
    );
}

#[test]
fn active_revoke_drain_release_is_monotonic_and_guarded() {
    let epoch = DaemonEpoch::new(13).expect("non-zero daemon epoch");
    let route_fence = fence(3);
    let mut registry = AttachmentRegistry::new(epoch);
    let prepared = registry
        .prepare(epoch, route_fence.clone(), digest(3))
        .expect("preparation succeeds");
    let install = registry
        .begin_install(&prepared, address(31_001), AttachmentExpiry::new(20_000))
        .expect("install starts");
    assert!(matches!(install, InstallReceipt::Installing(_)));
    let InstallReceipt::Installing(installing) = install else {
        return;
    };
    let active = registry
        .complete_install(&installing)
        .expect("install completes");
    let guard = registry
        .begin_accepted(&active)
        .expect("active attachment accepts a guard");

    registry.begin_revoke(&active).expect("revocation starts");
    assert_eq!(
        registry.state(epoch, &route_fence),
        Ok(AttachmentState::Revoking)
    );
    assert_eq!(
        registry.release(&active),
        Err(AttachmentError::ListenerCloseNotAcknowledged)
    );

    registry
        .acknowledge_listener_closed(&active)
        .expect("listener close is acknowledged");
    assert_eq!(
        registry.state(epoch, &route_fence),
        Ok(AttachmentState::Revoked)
    );
    assert_eq!(
        registry.release(&active),
        Err(AttachmentError::AcceptedGuardsRemain { count: 1 })
    );

    registry
        .finish_accepted(guard)
        .expect("accepted guard drains");
    assert_eq!(registry.release(&active), Err(AttachmentError::NotDrained));
    registry
        .mark_drained(&active)
        .expect("zero guards allow drain completion");
    assert_eq!(
        registry.state(epoch, &route_fence),
        Ok(AttachmentState::Drained)
    );
    let released = registry.release(&active).expect("drained route releases");
    assert_eq!(released.fence(), &route_fence);
    assert_eq!(released.daemon_epoch(), epoch);
    assert_eq!(
        registry.status(epoch, &route_fence),
        Ok(AttachmentStatus::Released(released.clone()))
    );
    assert_eq!(
        registry.release(&active),
        Ok(released),
        "release retry returns the original tombstone"
    );
    assert_eq!(
        registry.prepare(epoch, route_fence, digest(3)),
        Err(AttachmentError::Terminal(AttachmentState::Released)),
        "a released generation cannot be resurrected"
    );
}

#[test]
fn cancel_wins_a_late_install_completion_and_requires_close_ack() {
    let epoch = DaemonEpoch::new(17).expect("non-zero daemon epoch");
    let route_fence = fence(4);
    let mut registry = AttachmentRegistry::new(epoch);
    let prepared = registry
        .prepare(epoch, route_fence.clone(), digest(4))
        .expect("preparation succeeds");
    let install = registry
        .begin_install(&prepared, address(31_002), AttachmentExpiry::new(30_000))
        .expect("install starts");
    assert!(matches!(install, InstallReceipt::Installing(_)));
    let InstallReceipt::Installing(installing) = install else {
        return;
    };

    let cancelled = registry.cancel(&prepared).expect("cancellation wins");
    assert_eq!(
        registry.complete_install(&installing),
        Err(AttachmentError::Terminal(AttachmentState::Cancelled))
    );
    assert_eq!(
        registry.release_cancelled(&cancelled),
        Err(AttachmentError::ListenerCloseNotAcknowledged)
    );
    registry
        .acknowledge_cancelled_listener_closed(&installing)
        .expect("cancelled listener close is acknowledged");
    let released = registry
        .release_cancelled(&cancelled)
        .expect("cancelled reservation releases");
    assert_eq!(released.fence(), &route_fence);
    assert_eq!(
        registry.complete_install(&installing),
        Err(AttachmentError::Terminal(AttachmentState::Released))
    );
}

#[test]
fn prepared_cancel_needs_no_listener_ack_and_retries_return_original_tombstones() {
    let epoch = DaemonEpoch::new(18).expect("non-zero daemon epoch");
    let route_fence = fence(41);
    let mut registry = AttachmentRegistry::new(epoch);
    let prepared = registry
        .prepare(epoch, route_fence.clone(), digest(41))
        .expect("preparation succeeds");

    let cancelled = registry
        .cancel(&prepared)
        .expect("prepared reservation cancels");
    assert_eq!(
        registry.cancel(&prepared),
        Ok(cancelled.clone()),
        "cancel retry returns the original cancellation tombstone"
    );
    assert_eq!(
        registry.status(epoch, &route_fence),
        Ok(AttachmentStatus::Cancelled(cancelled.clone()))
    );

    let released = registry
        .release_cancelled(&cancelled)
        .expect("no listener existed, so release needs no close acknowledgement");
    assert_eq!(
        registry.release_cancelled(&cancelled),
        Ok(released.clone()),
        "release retry returns the original release tombstone"
    );
    assert_eq!(
        registry.cancel(&prepared),
        Ok(cancelled),
        "cancel reconciliation retains its original tombstone after release"
    );
}

#[test]
fn revoke_wins_a_late_install_completion() {
    let epoch = DaemonEpoch::new(19).expect("non-zero daemon epoch");
    let route_fence = fence(5);
    let mut registry = AttachmentRegistry::new(epoch);
    let prepared = registry
        .prepare(epoch, route_fence.clone(), digest(5))
        .expect("preparation succeeds");
    let install = registry
        .begin_install(&prepared, address(31_003), AttachmentExpiry::new(40_000))
        .expect("install starts");
    assert!(matches!(install, InstallReceipt::Installing(_)));
    let InstallReceipt::Installing(installing) = install else {
        return;
    };

    let reserved_active = registry
        .begin_revoke_installing(&installing)
        .expect("revocation wins");
    assert_eq!(
        registry.complete_install(&installing),
        Err(AttachmentError::Terminal(AttachmentState::Revoking))
    );
    registry
        .acknowledge_listener_closed(&reserved_active)
        .expect("listener close is acknowledged");
    registry
        .mark_drained(&reserved_active)
        .expect("no guards remain");
    registry
        .release(&reserved_active)
        .expect("revoked install releases");
    assert_eq!(
        registry.state(epoch, &route_fence),
        Ok(AttachmentState::Released)
    );
}

#[test]
fn daemon_epoch_mismatch_fails_closed_even_when_the_fence_is_absent() {
    let old_epoch = DaemonEpoch::new(23).expect("non-zero daemon epoch");
    let new_epoch = DaemonEpoch::new(29).expect("non-zero daemon epoch");
    let route_fence = fence(6);
    let mut old_registry = AttachmentRegistry::new(old_epoch);
    let prepared = old_registry
        .prepare(old_epoch, route_fence.clone(), digest(6))
        .expect("old daemon prepares");
    let mut new_registry = AttachmentRegistry::new(new_epoch);

    assert_eq!(
        new_registry.status(old_epoch, &route_fence),
        Err(AttachmentError::DaemonEpochMismatch {
            expected: new_epoch,
            actual: old_epoch,
        })
    );
    assert_eq!(
        new_registry.prepare(old_epoch, route_fence.clone(), digest(6)),
        Err(AttachmentError::DaemonEpochMismatch {
            expected: new_epoch,
            actual: old_epoch,
        })
    );
    assert_eq!(
        new_registry.begin_install(&prepared, address(31_004), AttachmentExpiry::new(50_000),),
        Err(AttachmentError::DaemonEpochMismatch {
            expected: new_epoch,
            actual: old_epoch,
        })
    );
}

#[test]
fn equal_proxy_addresses_do_not_alias_different_full_fences() {
    let epoch = DaemonEpoch::new(31).expect("non-zero daemon epoch");
    let first_fence = fence(7);
    let second_fence = fence(8);
    let shared_address = address(31_005);
    let mut registry = AttachmentRegistry::new(epoch);

    let first_prepared = registry
        .prepare(epoch, first_fence.clone(), digest(7))
        .expect("first preparation succeeds");
    let second_prepared = registry
        .prepare(epoch, second_fence.clone(), digest(8))
        .expect("second preparation succeeds");
    let first_install = registry
        .begin_install(
            &first_prepared,
            shared_address,
            AttachmentExpiry::new(60_000),
        )
        .expect("first install starts");
    assert!(matches!(first_install, InstallReceipt::Installing(_)));
    let InstallReceipt::Installing(first_installing) = first_install else {
        return;
    };
    let second_install = registry
        .begin_install(
            &second_prepared,
            shared_address,
            AttachmentExpiry::new(60_000),
        )
        .expect("second install starts");
    assert!(matches!(second_install, InstallReceipt::Installing(_)));
    let InstallReceipt::Installing(second_installing) = second_install else {
        return;
    };
    let first_active = registry
        .complete_install(&first_installing)
        .expect("first install completes");
    let second_active = registry
        .complete_install(&second_installing)
        .expect("second install completes");

    assert_eq!(first_active.proxy_address(), shared_address);
    assert_eq!(second_active.proxy_address(), shared_address);
    assert_ne!(first_active.attachment_id(), second_active.attachment_id());
    assert_eq!(first_active.fence(), &first_fence);
    assert_eq!(second_active.fence(), &second_fence);

    registry
        .begin_revoke(&first_active)
        .expect("first attachment revokes independently");
    assert_eq!(
        registry.state(epoch, &first_fence),
        Ok(AttachmentState::Revoking)
    );
    assert_eq!(
        registry.state(epoch, &second_fence),
        Ok(AttachmentState::Active)
    );
}
