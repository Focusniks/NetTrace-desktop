use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// 48-bit IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Individual/Group bit: set for multicast (and broadcast).
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn parse(s: &str) -> Option<MacAddr> {
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return None;
        }
        let mut out = [0u8; 6];
        for (dst, part) in out.iter_mut().zip(parts) {
            if part.is_empty() || part.len() > 2 {
                return None;
            }
            *dst = u8::from_str_radix(part, 16).ok()?;
        }
        Some(MacAddr(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// Endpoint address at any layer. Ordered so tables can sort by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Address {
    #[default]
    None,
    Mac(MacAddr),
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Address {
    pub fn is_none(&self) -> bool {
        matches!(self, Address::None)
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Address::V4(_) | Address::V6(_))
    }

    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Address::V4(b) => Some(Ipv4Addr::from(*b)),
            _ => None,
        }
    }

    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Address::V6(b) => Some(Ipv6Addr::from(*b)),
            _ => None,
        }
    }

    pub fn mac(&self) -> Option<MacAddr> {
        match self {
            Address::Mac(m) => Some(*m),
            _ => None,
        }
    }

    /// Classifies a destination as broadcast / multicast / unicast.
    pub fn cast(&self) -> CastType {
        match self {
            Address::None => CastType::Unknown,
            Address::Mac(m) if m.is_broadcast() => CastType::Broadcast,
            Address::Mac(m) if m.is_multicast() => CastType::Multicast,
            Address::Mac(_) => CastType::Unicast,
            Address::V4(b) => {
                let ip = Ipv4Addr::from(*b);
                if ip.is_broadcast() || b[3] == 255 {
                    CastType::Broadcast
                } else if ip.is_multicast() {
                    CastType::Multicast
                } else {
                    CastType::Unicast
                }
            }
            Address::V6(b) => {
                if b[0] == 0xff {
                    CastType::Multicast
                } else {
                    CastType::Unicast
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastType {
    Unknown,
    Unicast,
    Multicast,
    Broadcast,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::None => Ok(()),
            Address::Mac(m) => m.fmt(f),
            Address::V4(b) => Ipv4Addr::from(*b).fmt(f),
            Address::V6(b) => Ipv6Addr::from(*b).fmt(f),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_display_and_parse_roundtrip() {
        let m = MacAddr([0x48, 0x8f, 0x5a, 0xdb, 0x11, 0x22]);
        assert_eq!(m.to_string(), "48:8f:5a:db:11:22");
        assert_eq!(MacAddr::parse("48:8f:5a:db:11:22"), Some(m));
        assert_eq!(MacAddr::parse("48-8F-5A-DB-11-22"), Some(m));
        assert_eq!(MacAddr::parse("48:8f:5a:db:11"), None);
        assert_eq!(MacAddr::parse("48:8f:5a:db:11:2222"), None);
        assert_eq!(MacAddr::parse("zz:8f:5a:db:11:22"), None);
    }

    #[test]
    fn cast_type_classification() {
        assert_eq!(Address::Mac(MacAddr::BROADCAST).cast(), CastType::Broadcast);
        assert_eq!(Address::Mac(MacAddr([0x01, 0, 0x5e, 0, 0, 1])).cast(), CastType::Multicast);
        assert_eq!(Address::V4([224, 0, 0, 251]).cast(), CastType::Multicast);
        assert_eq!(Address::V4([10, 0, 0, 1]).cast(), CastType::Unicast);
        assert_eq!(Address::V4([255, 255, 255, 255]).cast(), CastType::Broadcast);
        let mut v6 = [0u8; 16];
        v6[0] = 0xff;
        assert_eq!(Address::V6(v6).cast(), CastType::Multicast);
    }

    #[test]
    fn address_display() {
        assert_eq!(Address::V4([10, 10, 1, 15]).to_string(), "10.10.1.15");
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert_eq!(Address::V6(v6).to_string(), "::1");
        assert_eq!(Address::None.to_string(), "");
    }
}
