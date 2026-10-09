use serde::Serialize;

/// Protocols known to the dissector set. The numeric value is a bit index
/// in [`ProtocolSet`], so at most 32 variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum ProtocolId {
    Frame = 0,
    Eth = 1,
    Vlan = 2,
    Arp = 3,
    Ipv4 = 4,
    Ipv6 = 5,
    Icmp = 6,
    Icmpv6 = 7,
    Tcp = 8,
    Udp = 9,
    Dns = 10,
    Dhcp = 11,
    Http = 12,
    Tls = 13,
    Ntp = 14,
    Sll = 15,
    Loopback = 16,
    Data = 17,
    Malformed = 18,
}

impl ProtocolId {
    pub const ALL: [ProtocolId; 19] = [
        ProtocolId::Frame,
        ProtocolId::Eth,
        ProtocolId::Vlan,
        ProtocolId::Arp,
        ProtocolId::Ipv4,
        ProtocolId::Ipv6,
        ProtocolId::Icmp,
        ProtocolId::Icmpv6,
        ProtocolId::Tcp,
        ProtocolId::Udp,
        ProtocolId::Dns,
        ProtocolId::Dhcp,
        ProtocolId::Http,
        ProtocolId::Tls,
        ProtocolId::Ntp,
        ProtocolId::Sll,
        ProtocolId::Loopback,
        ProtocolId::Data,
        ProtocolId::Malformed,
    ];

    pub fn from_u8(v: u8) -> Option<ProtocolId> {
        Self::ALL.get(usize::from(v)).copied()
    }

    pub fn bit(self) -> u32 {
        1u32 << (self as u8)
    }

    /// Short name for the Protocol column.
    pub fn short_name(self) -> &'static str {
        match self {
            ProtocolId::Frame => "Frame",
            ProtocolId::Eth => "Ethernet",
            ProtocolId::Vlan => "802.1Q",
            ProtocolId::Arp => "ARP",
            ProtocolId::Ipv4 => "IPv4",
            ProtocolId::Ipv6 => "IPv6",
            ProtocolId::Icmp => "ICMP",
            ProtocolId::Icmpv6 => "ICMPv6",
            ProtocolId::Tcp => "TCP",
            ProtocolId::Udp => "UDP",
            ProtocolId::Dns => "DNS",
            ProtocolId::Dhcp => "DHCP",
            ProtocolId::Http => "HTTP",
            ProtocolId::Tls => "TLS",
            ProtocolId::Ntp => "NTP",
            ProtocolId::Sll => "SLL",
            ProtocolId::Loopback => "Loopback",
            ProtocolId::Data => "Data",
            ProtocolId::Malformed => "Malformed",
        }
    }

    /// Display filter keyword.
    pub fn filter_name(self) -> &'static str {
        match self {
            ProtocolId::Frame => "frame",
            ProtocolId::Eth => "eth",
            ProtocolId::Vlan => "vlan",
            ProtocolId::Arp => "arp",
            ProtocolId::Ipv4 => "ip",
            ProtocolId::Ipv6 => "ipv6",
            ProtocolId::Icmp => "icmp",
            ProtocolId::Icmpv6 => "icmpv6",
            ProtocolId::Tcp => "tcp",
            ProtocolId::Udp => "udp",
            ProtocolId::Dns => "dns",
            ProtocolId::Dhcp => "dhcp",
            ProtocolId::Http => "http",
            ProtocolId::Tls => "tls",
            ProtocolId::Ntp => "ntp",
            ProtocolId::Sll => "sll",
            ProtocolId::Loopback => "null",
            ProtocolId::Data => "data",
            ProtocolId::Malformed => "_ws.malformed",
        }
    }

    /// Full name used as the protocol tree heading.
    pub fn long_name(self) -> &'static str {
        match self {
            ProtocolId::Frame => "Frame",
            ProtocolId::Eth => "Ethernet II",
            ProtocolId::Vlan => "802.1Q Virtual LAN",
            ProtocolId::Arp => "Address Resolution Protocol",
            ProtocolId::Ipv4 => "Internet Protocol Version 4",
            ProtocolId::Ipv6 => "Internet Protocol Version 6",
            ProtocolId::Icmp => "Internet Control Message Protocol",
            ProtocolId::Icmpv6 => "Internet Control Message Protocol v6",
            ProtocolId::Tcp => "Transmission Control Protocol",
            ProtocolId::Udp => "User Datagram Protocol",
            ProtocolId::Dns => "Domain Name System",
            ProtocolId::Dhcp => "Dynamic Host Configuration Protocol",
            ProtocolId::Http => "Hypertext Transfer Protocol",
            ProtocolId::Tls => "Transport Layer Security",
            ProtocolId::Ntp => "Network Time Protocol",
            ProtocolId::Sll => "Linux cooked capture",
            ProtocolId::Loopback => "Null/Loopback",
            ProtocolId::Data => "Data",
            ProtocolId::Malformed => "Malformed Packet",
        }
    }
}

/// Bitmask of [`ProtocolId`]s present in a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ProtocolSet(pub u32);

impl ProtocolSet {
    pub fn insert(&mut self, p: ProtocolId) {
        self.0 |= p.bit();
    }

    pub fn contains(self, p: ProtocolId) -> bool {
        self.0 & p.bit() != 0
    }

    pub fn union(self, other: ProtocolSet) -> ProtocolSet {
        ProtocolSet(self.0 | other.0)
    }

    pub fn iter(self) -> impl Iterator<Item = ProtocolId> {
        ProtocolId::ALL.into_iter().filter(move |p| self.contains(*p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_dense_and_roundtrip() {
        for (i, p) in ProtocolId::ALL.iter().enumerate() {
            assert_eq!(*p as usize, i);
            assert_eq!(ProtocolId::from_u8(i as u8), Some(*p));
        }
        assert_eq!(ProtocolId::from_u8(200), None);
    }

    #[test]
    fn set_operations() {
        let mut s = ProtocolSet::default();
        s.insert(ProtocolId::Tcp);
        s.insert(ProtocolId::Tls);
        assert!(s.contains(ProtocolId::Tcp));
        assert!(!s.contains(ProtocolId::Udp));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![ProtocolId::Tcp, ProtocolId::Tls]);
    }
}
