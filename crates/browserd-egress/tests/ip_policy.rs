use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use browserd_egress::{IpDenyReason, IpPolicy};

#[test]
fn public_web_policy_rejects_forbidden_ipv4_ranges() {
    let policy = IpPolicy::public_web_default();
    let cases = [
        (Ipv4Addr::UNSPECIFIED, IpDenyReason::Unspecified),
        (Ipv4Addr::LOCALHOST, IpDenyReason::Loopback),
        (Ipv4Addr::new(10, 1, 2, 3), IpDenyReason::Private),
        (Ipv4Addr::new(172, 16, 0, 1), IpDenyReason::Private),
        (Ipv4Addr::new(192, 168, 0, 1), IpDenyReason::Private),
        (Ipv4Addr::new(100, 64, 0, 1), IpDenyReason::CarrierGradeNat),
        (
            Ipv4Addr::new(169, 254, 169, 254),
            IpDenyReason::CloudMetadata,
        ),
        (Ipv4Addr::new(169, 254, 1, 1), IpDenyReason::LinkLocal),
        (
            Ipv4Addr::new(224, 0, 0, 1),
            IpDenyReason::MulticastOrReserved,
        ),
        (
            Ipv4Addr::new(240, 0, 0, 1),
            IpDenyReason::MulticastOrReserved,
        ),
        (
            Ipv4Addr::new(192, 0, 2, 1),
            IpDenyReason::MulticastOrReserved,
        ),
    ];

    for (address, reason) in cases {
        assert_eq!(policy.check(IpAddr::V4(address)), Err(reason));
    }

    assert_eq!(
        policy.check(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        Ok(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
    );
}

#[test]
fn public_web_policy_rejects_forbidden_ipv6_ranges() {
    let policy = IpPolicy::public_web_default();
    let cases = [
        (Ipv6Addr::UNSPECIFIED, IpDenyReason::Unspecified),
        (Ipv6Addr::LOCALHOST, IpDenyReason::Loopback),
        (
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
            IpDenyReason::UniqueLocal,
        ),
        (
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            IpDenyReason::LinkLocal,
        ),
        (
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            IpDenyReason::MulticastOrReserved,
        ),
        (
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            IpDenyReason::MulticastOrReserved,
        ),
    ];

    for (address, reason) in cases {
        assert_eq!(policy.check(IpAddr::V6(address)), Err(reason));
    }

    let public = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    assert_eq!(policy.check(IpAddr::V6(public)), Ok(IpAddr::V6(public)));
}

#[test]
fn ipv4_mapped_ipv6_is_canonicalized_before_classification() {
    let policy = IpPolicy::public_web_default();

    let mapped_loopback = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
    let mapped_metadata = Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped();
    let mapped_cgnat = Ipv4Addr::new(100, 64, 0, 1).to_ipv6_mapped();
    let public_v4 = Ipv4Addr::new(93, 184, 216, 34);

    assert_eq!(
        policy.check(IpAddr::V6(mapped_loopback)),
        Err(IpDenyReason::Loopback),
    );
    assert_eq!(
        policy.check(IpAddr::V6(mapped_metadata)),
        Err(IpDenyReason::CloudMetadata),
    );
    assert_eq!(
        policy.check(IpAddr::V6(mapped_cgnat)),
        Err(IpDenyReason::CarrierGradeNat),
    );
    assert_eq!(
        policy.check(IpAddr::V6(public_v4.to_ipv6_mapped())),
        Ok(IpAddr::V4(public_v4)),
    );
}
