use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The low-cardinality reason an address was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpDenyReason {
    Unspecified,
    Loopback,
    Private,
    CarrierGradeNat,
    CloudMetadata,
    LinkLocal,
    UniqueLocal,
    MulticastOrReserved,
}

/// The strong public-web IP policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct IpPolicy;

impl IpPolicy {
    #[must_use]
    pub const fn public_web_default() -> Self {
        Self
    }

    /// Checks an address and returns its canonical form. IPv4-mapped IPv6 is
    /// returned as IPv4 so later code cannot accidentally classify it twice.
    pub fn check(self, address: IpAddr) -> Result<IpAddr, IpDenyReason> {
        let check_ipv4 = |address: Ipv4Addr| {
            let octets = address.octets();
            if octets[0] == 0 {
                return Err(IpDenyReason::Unspecified);
            }
            if octets[0] == 127 {
                return Err(IpDenyReason::Loopback);
            }
            if octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
            {
                return Err(IpDenyReason::Private);
            }
            if address == Ipv4Addr::new(169, 254, 169, 254)
                || address == Ipv4Addr::new(100, 100, 100, 200)
            {
                return Err(IpDenyReason::CloudMetadata);
            }
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return Err(IpDenyReason::CarrierGradeNat);
            }
            if octets[0] == 169 && octets[1] == 254 {
                return Err(IpDenyReason::LinkLocal);
            }
            if octets[0] >= 224
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
                return Err(IpDenyReason::MulticastOrReserved);
            }
            Ok(address)
        };
        match address {
            IpAddr::V4(address) => check_ipv4(address).map(IpAddr::V4),
            IpAddr::V6(address) => {
                if let Some(mapped) = address.to_ipv4_mapped() {
                    check_ipv4(mapped).map(IpAddr::V4)
                } else {
                    if address.is_unspecified() {
                        return Err(IpDenyReason::Unspecified);
                    }
                    if address.is_loopback() {
                        return Err(IpDenyReason::Loopback);
                    }
                    let segments = address.segments();
                    if address == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
                        return Err(IpDenyReason::CloudMetadata);
                    }
                    let octets = address.octets();
                    let embedded = if octets[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
                    {
                        Some(Ipv4Addr::new(
                            octets[12], octets[13], octets[14], octets[15],
                        ))
                    } else if octets[0] == 0x20 && octets[1] == 0x02 {
                        Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]))
                    } else {
                        None
                    };
                    if let Some(embedded) = embedded {
                        check_ipv4(embedded)?;
                    }
                    if segments[0] & 0xfe00 == 0xfc00 {
                        return Err(IpDenyReason::UniqueLocal);
                    }
                    if segments[0] & 0xffc0 == 0xfe80 {
                        return Err(IpDenyReason::LinkLocal);
                    }
                    if segments[0] & 0xff00 == 0xff00
                        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1)
                        || (segments[0] == 0x2001 && segments[1] == 0)
                        || (segments[0] & 0xffc0 == 0xfec0)
                        || (segments[0] == 0x2001 && segments[1] == 0x0002)
                        || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010)
                        || segments[0] == 0
                    {
                        return Err(IpDenyReason::MulticastOrReserved);
                    }
                    Ok(IpAddr::V6(address))
                }
            }
        }
    }
}
