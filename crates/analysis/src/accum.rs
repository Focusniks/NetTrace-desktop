//! Aggregates updated incrementally while the capture is indexed.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use hashbrown::{DefaultHashBuilder, HashTable};
use nettrace_model::{
    AddressKind, ConversationKind, ConversationRow, HostRow, ProtocolId, ProtocolNode, ProtocolSet, TimelineKind,
};
use nettrace_packet::Address;
use nettrace_storage::{AddressTable, NONE};

/// Facts about one packet needed by the aggregates.
#[derive(Debug, Clone)]
pub struct PacketFacts<'a> {
    pub index: u32,
    pub ts_ns: i64,
    pub frame_len: u32,
    pub l2_src: Address,
    pub l2_dst: Address,
    pub net_src: Address,
    pub net_dst: Address,
    /// Interned ids (`AddressTable`) of the four addresses above, or `NONE`.
    pub l2_src_id: u32,
    pub l2_dst_id: u32,
    pub net_src_id: u32,
    pub net_dst_id: u32,
    pub protocols: ProtocolSet,
    pub path: &'a [u8],
    pub malformed: bool,
    pub event: Option<(TimelineKind, &'a str, Option<&'a str>)>,
    pub flow: Option<u32>,
}

/// Traffic of one host. Addresses are `AddressTable` ids (56 bytes per host).
#[derive(Debug, Clone, Copy)]
pub struct HostStats {
    pub addr: u32,
    /// MAC seen as the link-layer source of this IP host, or `NONE`.
    pub mac: u32,
    pub tx_packets: u32,
    pub rx_packets: u32,
    pub protocols: ProtocolSet,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub first_ns: i64,
    pub last_ns: i64,
}

/// Traffic between two addresses; `a` is the lower address (`Address` order).
#[derive(Debug, Clone, Copy)]
pub struct ConvStats {
    pub a: u32,
    pub b: u32,
    pub a_to_b_packets: u32,
    pub b_to_a_packets: u32,
    pub a_to_b_bytes: u64,
    pub b_to_a_bytes: u64,
    pub first_ns: i64,
    pub last_ns: i64,
}

/// Hosts by address id: a dense slot per interned address (4 bytes) plus one
/// compact entry per address that actually sent or received.
#[derive(Debug, Default)]
pub struct HostTable {
    slot: Vec<u32>,
    entries: Vec<HostStats>,
}

impl HostTable {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[HostStats] {
        &self.entries
    }

    fn touch(&mut self, addr: u32, ts: i64) -> &mut HostStats {
        let i = addr as usize;
        if self.slot.len() <= i {
            self.slot.resize(i + 1, NONE);
        }
        if self.slot[i] == NONE {
            self.slot[i] = self.entries.len() as u32;
            self.entries.push(HostStats {
                addr,
                mac: NONE,
                tx_packets: 0,
                rx_packets: 0,
                protocols: ProtocolSet::default(),
                tx_bytes: 0,
                rx_bytes: 0,
                first_ns: ts,
                last_ns: ts,
            });
        }
        let h = &mut self.entries[self.slot[i] as usize];
        h.first_ns = h.first_ns.min(ts);
        h.last_ns = h.last_ns.max(ts);
        h
    }

    fn shrink_to_fit(&mut self) {
        self.slot.shrink_to_fit();
        self.entries.shrink_to_fit();
    }
}

/// Conversations keyed by their two address ids (4 bytes of index per entry).
#[derive(Debug, Default)]
pub struct ConvTable {
    entries: Vec<ConvStats>,
    index: HashTable<u32>,
    hasher: DefaultHashBuilder,
}

impl ConvTable {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[ConvStats] {
        &self.entries
    }

    fn key(c: &ConvStats) -> (u32, u32) {
        (c.a, c.b)
    }

    fn record(&mut self, src: (Address, u32), dst: (Address, u32), ts: i64, len: u64) {
        let forward = src.0 <= dst.0;
        let key = if forward { (src.1, dst.1) } else { (dst.1, src.1) };
        let hash = self.hasher.hash_one(key);
        let entries = &self.entries;
        let i = match self.index.find(hash, |&i| Self::key(&entries[i as usize]) == key) {
            Some(&i) => i as usize,
            None => {
                let i = self.entries.len();
                self.entries.push(ConvStats {
                    a: key.0,
                    b: key.1,
                    a_to_b_packets: 0,
                    b_to_a_packets: 0,
                    a_to_b_bytes: 0,
                    b_to_a_bytes: 0,
                    first_ns: ts,
                    last_ns: ts,
                });
                let (entries, hasher) = (&self.entries, &self.hasher);
                self.index.insert_unique(hash, i as u32, |&j| hasher.hash_one(Self::key(&entries[j as usize])));
                i
            }
        };
        let c = &mut self.entries[i];
        c.last_ns = c.last_ns.max(ts);
        c.first_ns = c.first_ns.min(ts);
        if forward {
            c.a_to_b_packets += 1;
            c.a_to_b_bytes += len;
        } else {
            c.b_to_a_packets += 1;
            c.b_to_a_bytes += len;
        }
    }

    fn shrink_to_fit(&mut self) {
        self.entries.shrink_to_fit();
        let (entries, hasher) = (&self.entries, &self.hasher);
        self.index.shrink_to_fit(|&j| hasher.hash_one(Self::key(&entries[j as usize])));
    }
}

/// Application event (DNS, TLS, HTTP) recorded during indexing.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: TimelineKind,
    pub packet: u32,
    pub ts_ns: i64,
    pub label: String,
    pub flow: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsActivity {
    pub queries: u32,
    /// Hashes of the distinct names asked (only their number is reported).
    pub names: HashSet<u64>,
}

/// Cap that keeps memory proportional for adversarial captures.
pub const MAX_EVENTS: usize = 5_000_000;
/// Distinct DNS names remembered per host (only their number is shown).
const MAX_DISTINCT_NAMES: usize = 10_000;
const MAX_LABEL: usize = 200;

#[derive(Debug, Default)]
pub struct Accumulators {
    pub hosts: HostTable,
    pub ip_convs: ConvTable,
    pub eth_convs: ConvTable,
    names_hasher: DefaultHashBuilder,
    hierarchy: HashMap<([u8; 12], u8), (u64, u64)>,
    pub events: Vec<Event>,
    pub dns_by_host: HashMap<Address, DnsActivity>,
    pub malformed: u64,
    pub packets: u64,
    pub bytes: u64,
    /// Set when a cap was hit and some statistics are incomplete.
    pub limit_reached: bool,
}

impl Accumulators {
    pub fn record(&mut self, p: &PacketFacts) {
        let len = u64::from(p.frame_len);
        self.packets += 1;
        self.bytes += len;
        if p.malformed {
            self.malformed += 1;
        }
        let ip = p.net_src.is_ip();
        let (src, src_id, dst_id) =
            if ip { (p.net_src, p.net_src_id, p.net_dst_id) } else { (p.l2_src, p.l2_src_id, p.l2_dst_id) };
        if src_id != NONE {
            let h = self.hosts.touch(src_id, p.ts_ns);
            h.tx_packets += 1;
            h.tx_bytes += len;
            h.protocols = h.protocols.union(p.protocols);
            if ip && h.mac == NONE && matches!(p.l2_src, Address::Mac(_)) {
                h.mac = p.l2_src_id;
            }
        }
        if dst_id != NONE {
            let h = self.hosts.touch(dst_id, p.ts_ns);
            h.rx_packets += 1;
            h.rx_bytes += len;
            h.protocols = h.protocols.union(p.protocols);
        }
        if ip && p.net_dst.is_ip() {
            self.ip_convs.record((p.net_src, p.net_src_id), (p.net_dst, p.net_dst_id), p.ts_ns, len);
        }
        if let (Address::Mac(_), Address::Mac(_)) = (p.l2_src, p.l2_dst) {
            self.eth_convs.record((p.l2_src, p.l2_src_id), (p.l2_dst, p.l2_dst_id), p.ts_ns, len);
        }
        let mut key = [0u8; 12];
        let n = p.path.len().min(12);
        key[..n].copy_from_slice(&p.path[..n]);
        let e = self.hierarchy.entry((key, n as u8)).or_default();
        e.0 += 1;
        e.1 += len;
        if let Some((kind, label, name)) = p.event {
            if self.events.len() < MAX_EVENTS {
                let label: String = label.chars().take(MAX_LABEL).collect();
                self.events.push(Event { kind, packet: p.index, ts_ns: p.ts_ns, label, flow: p.flow });
            } else {
                self.limit_reached = true;
            }
            if kind == TimelineKind::DnsQuery && !src.is_none() {
                let d = self.dns_by_host.entry(src).or_default();
                d.queries += 1;
                if let Some(name) = name {
                    if d.names.len() < MAX_DISTINCT_NAMES {
                        d.names.insert(self.names_hasher.hash_one(name));
                    }
                }
            }
        }
    }

    /// Protocol hierarchy tree (each packet counted at every level of its stack).
    pub fn protocol_hierarchy(&self) -> Vec<ProtocolNode> {
        #[derive(Default)]
        struct Tmp {
            packets: u64,
            bytes: u64,
            children: Vec<(u8, Tmp)>,
        }
        fn child(node: &mut Tmp, id: u8) -> &mut Tmp {
            let pos = match node.children.iter().position(|(c, _)| *c == id) {
                Some(p) => p,
                None => {
                    node.children.push((id, Tmp::default()));
                    node.children.len() - 1
                }
            };
            &mut node.children[pos].1
        }
        let mut root = Tmp::default();
        for ((key, len), (packets, bytes)) in &self.hierarchy {
            let mut node = &mut root;
            for id in &key[..usize::from(*len)] {
                node = child(node, *id);
                node.packets += packets;
                node.bytes += bytes;
            }
        }
        fn convert(children: Vec<(u8, Tmp)>) -> Vec<ProtocolNode> {
            let mut out: Vec<ProtocolNode> = children
                .into_iter()
                .filter_map(|(id, t)| {
                    let p = ProtocolId::from_u8(id)?;
                    Some(ProtocolNode {
                        name: p.long_name().to_owned(),
                        filter: p.filter_name().to_owned(),
                        packets: t.packets,
                        bytes: t.bytes,
                        children: convert(t.children),
                    })
                })
                .collect();
            out.sort_by(|a, b| b.packets.cmp(&a.packets).then_with(|| a.name.cmp(&b.name)));
            out
        }
        convert(root.children)
    }

    /// Drops spare capacity once the capture is fully indexed.
    pub fn shrink_to_fit(&mut self) {
        self.hosts.shrink_to_fit();
        self.ip_convs.shrink_to_fit();
        self.eth_convs.shrink_to_fit();
        self.events.shrink_to_fit();
    }

    /// Ethernet or IP conversations (TCP/UDP ones are the flows).
    pub fn conversations(&self, kind: ConversationKind) -> &ConvTable {
        match kind {
            ConversationKind::Eth => &self.eth_convs,
            _ => &self.ip_convs,
        }
    }
}

/// UI row of one host (built only for the rows actually requested).
pub fn host_row(h: &HostStats, addrs: &AddressTable, base_ns: i64) -> HostRow {
    let addr = addrs.get(h.addr);
    let (kind, filter) = match addr {
        Address::V4(_) => (AddressKind::Ipv4, format!("ip.addr == {addr}")),
        Address::V6(_) => (AddressKind::Ipv6, format!("ipv6.addr == {addr}")),
        _ => (AddressKind::Mac, format!("eth.addr == {addr}")),
    };
    HostRow {
        address: addr.to_string(),
        kind,
        mac: (h.mac != NONE).then(|| addrs.get(h.mac).to_string()),
        packets: u64::from(h.tx_packets) + u64::from(h.rx_packets),
        bytes: h.tx_bytes + h.rx_bytes,
        tx_packets: u64::from(h.tx_packets),
        tx_bytes: h.tx_bytes,
        rx_packets: u64::from(h.rx_packets),
        rx_bytes: h.rx_bytes,
        protocols: protocol_names(h.protocols),
        first_seen: h.first_ns.saturating_sub(base_ns) as f64 / 1e9,
        last_seen: h.last_ns.saturating_sub(base_ns) as f64 / 1e9,
        filter,
    }
}

/// UI row of one Ethernet or IP conversation.
pub fn conversation_row(kind: ConversationKind, c: &ConvStats, addrs: &AddressTable, base_ns: i64) -> ConversationRow {
    let (a, b) = (addrs.get(c.a), addrs.get(c.b));
    let filter = match (kind, a) {
        (ConversationKind::Eth, _) => format!("eth.addr == {a} && eth.addr == {b}"),
        (_, Address::V6(_)) => format!("ipv6.addr == {a} && ipv6.addr == {b}"),
        _ => format!("ip.addr == {a} && ip.addr == {b}"),
    };
    ConversationRow {
        kind,
        a: a.to_string(),
        a_port: None,
        b: b.to_string(),
        b_port: None,
        packets: u64::from(c.a_to_b_packets) + u64::from(c.b_to_a_packets),
        bytes: c.a_to_b_bytes + c.b_to_a_bytes,
        a_to_b_packets: u64::from(c.a_to_b_packets),
        a_to_b_bytes: c.a_to_b_bytes,
        b_to_a_packets: u64::from(c.b_to_a_packets),
        b_to_a_bytes: c.b_to_a_bytes,
        start: c.first_ns.saturating_sub(base_ns) as f64 / 1e9,
        duration: c.last_ns.saturating_sub(c.first_ns) as f64 / 1e9,
        state: None,
        stream: None,
        filter,
    }
}

/// Names of the "interesting" protocols in a set (link/frame layers omitted).
pub fn protocol_names(set: ProtocolSet) -> Vec<String> {
    set.iter()
        .filter(|p| !matches!(p, ProtocolId::Frame | ProtocolId::Eth | ProtocolId::Data | ProtocolId::Sll | ProtocolId::Loopback))
        .map(|p| p.short_name().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use nettrace_packet::MacAddr;

    fn facts(addrs: &mut AddressTable, src: [u8; 4], dst: [u8; 4], path: &'static [u8], len: u32) -> PacketFacts<'static> {
        let mut protocols = ProtocolSet::default();
        for p in path {
            protocols.insert(ProtocolId::from_u8(*p).unwrap());
        }
        let (l2_src, l2_dst) = (Address::Mac(MacAddr([0, 0, 0, 0, 0, 1])), Address::Mac(MacAddr([0, 0, 0, 0, 0, 2])));
        let (net_src, net_dst) = (Address::V4(src), Address::V4(dst));
        PacketFacts {
            index: 0,
            ts_ns: 1_000,
            frame_len: len,
            l2_src,
            l2_dst,
            net_src,
            net_dst,
            l2_src_id: addrs.intern(l2_src),
            l2_dst_id: addrs.intern(l2_dst),
            net_src_id: addrs.intern(net_src),
            net_dst_id: addrs.intern(net_dst),
            protocols,
            path,
            malformed: false,
            event: None,
            flow: None,
        }
    }

    const TCP_PATH: &[u8] = &[0, 1, 4, 8];
    const DNS_PATH: &[u8] = &[0, 1, 4, 9, 10];

    #[test]
    fn hosts_and_conversations() {
        let mut acc = Accumulators::default();
        let mut a = AddressTable::default();
        acc.record(&facts(&mut a, [10, 0, 0, 1], [10, 0, 0, 2], TCP_PATH, 100));
        acc.record(&facts(&mut a, [10, 0, 0, 2], [10, 0, 0, 1], TCP_PATH, 60));
        acc.record(&facts(&mut a, [10, 0, 0, 1], [10, 0, 0, 3], DNS_PATH, 80));
        let hosts: Vec<_> = acc.hosts.entries().iter().map(|h| host_row(h, &a, 0)).collect();
        assert_eq!(hosts.len(), 3);
        let h1 = hosts.iter().find(|h| h.address == "10.0.0.1").unwrap();
        assert_eq!((h1.tx_packets, h1.tx_bytes, h1.rx_packets, h1.rx_bytes), (2, 180, 1, 60));
        assert_eq!(h1.mac.as_deref(), Some("00:00:00:00:00:01"));
        assert_eq!(h1.filter, "ip.addr == 10.0.0.1");
        assert!(h1.protocols.contains(&"DNS".to_owned()));
        let convs: Vec<_> =
            acc.ip_convs.entries().iter().map(|c| conversation_row(ConversationKind::Ip, c, &a, 0)).collect();
        assert_eq!(convs.len(), 2);
        // Oriented by address order whatever the direction of the first packet.
        let c = convs.iter().find(|c| c.b == "10.0.0.2").unwrap();
        assert_eq!((c.a.as_str(), c.a_to_b_packets, c.b_to_a_packets, c.bytes), ("10.0.0.1", 1, 1, 160));
        assert_eq!(acc.eth_convs.len(), 1);
    }

    #[test]
    fn hierarchy_counts_every_level() {
        let mut acc = Accumulators::default();
        let mut a = AddressTable::default();
        acc.record(&facts(&mut a, [1, 1, 1, 1], [2, 2, 2, 2], TCP_PATH, 100));
        acc.record(&facts(&mut a, [1, 1, 1, 1], [2, 2, 2, 2], DNS_PATH, 50));
        let tree = acc.protocol_hierarchy();
        assert_eq!(tree.len(), 1);
        let frame = &tree[0];
        assert_eq!((frame.packets, frame.bytes), (2, 150));
        let ip = &frame.children[0].children[0];
        assert_eq!(ip.filter, "ip");
        assert_eq!(ip.packets, 2);
        assert_eq!(ip.children.len(), 2);
        let udp = ip.children.iter().find(|c| c.filter == "udp").unwrap();
        assert_eq!(udp.children[0].filter, "dns");
    }

    #[test]
    fn dns_activity_per_host() {
        let mut acc = Accumulators::default();
        let mut a = AddressTable::default();
        for name in ["a.example", "b.example", "a.example"] {
            let mut f = facts(&mut a, [10, 0, 0, 9], [10, 0, 0, 53], DNS_PATH, 70);
            f.event = Some((TimelineKind::DnsQuery, "A x", Some(name)));
            acc.record(&f);
        }
        let d = &acc.dns_by_host[&Address::V4([10, 0, 0, 9])];
        assert_eq!((d.queries, d.names.len()), (3, 2));
        assert_eq!(acc.events.len(), 3);
    }
}
