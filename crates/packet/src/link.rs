/// Link-layer header types (subset of the tcpdump.org LINKTYPE_* registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    /// BSD loopback: 4-byte address family in host byte order.
    Null,
    Ethernet,
    /// Raw IPv4 or IPv6, version taken from the first nibble.
    Raw,
    Ipv4,
    Ipv6,
    /// OpenBSD loopback: 4-byte address family in network byte order.
    Loop,
    LinuxSll,
    LinuxSll2,
    Other(u32),
}

impl LinkType {
    pub fn from_raw(value: u32) -> LinkType {
        match value {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            101 | 12 | 14 => LinkType::Raw,
            108 => LinkType::Loop,
            113 => LinkType::LinuxSll,
            228 => LinkType::Ipv4,
            229 => LinkType::Ipv6,
            276 => LinkType::LinuxSll2,
            other => LinkType::Other(other),
        }
    }

    pub fn to_raw(self) -> u32 {
        match self {
            LinkType::Null => 0,
            LinkType::Ethernet => 1,
            LinkType::Raw => 101,
            LinkType::Loop => 108,
            LinkType::LinuxSll => 113,
            LinkType::Ipv4 => 228,
            LinkType::Ipv6 => 229,
            LinkType::LinuxSll2 => 276,
            LinkType::Other(v) => v,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            LinkType::Null => "BSD loopback",
            LinkType::Ethernet => "Ethernet",
            LinkType::Raw => "Raw IP",
            LinkType::Ipv4 => "Raw IPv4",
            LinkType::Ipv6 => "Raw IPv6",
            LinkType::Loop => "OpenBSD loopback",
            LinkType::LinuxSll => "Linux cooked capture v1",
            LinkType::LinuxSll2 => "Linux cooked capture v2",
            LinkType::Other(_) => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_roundtrip() {
        for raw in [0u32, 1, 101, 108, 113, 228, 229, 276, 9999] {
            assert_eq!(LinkType::from_raw(raw).to_raw(), raw);
        }
        assert_eq!(LinkType::from_raw(12), LinkType::Raw);
    }
}
