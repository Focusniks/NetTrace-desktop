//! Aggregates updated incrementally while the capture is indexed.

use std::collections::{HashMap, HashSet};

use nettrace_model::{
    AddressKind, ConversationKind, ConversationRow, HostRow, ProtocolId, ProtocolNode, ProtocolSet, TimelineKind,
};
use nettrace_packet::{Address, MacAddr};

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
    pub protocols: ProtocolSet,
    pub path: &'a [u8],
    pub malformed: bool,
    pub event: Option<(TimelineKind, &'a str, Option<&'a str>)>,
    pub flow: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct HostStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub protocols: ProtocolSet,
    pub first_ns: i64,
    pub last_ns: i64,
    pub mac: Option<MacAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct ConvStats {
    pub a_to_b_packets: u64,
    pub a_to_b_bytes: u64,
    pub b_to_a_packets: u64,
    pub b_to_a_bytes: u64,
    pub first_ns: i64,
    pub last_ns: i64,
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
    pub names: HashSet<String>,
}

const MAX_DISTINCT_NAMES: usize = 10_000;
/// Caps that keep memory proportional for adversarial captures.
pub const MAX_EVENTS: usize = 5_000_000;
pub const MAX_HOSTS: usize = 2_000_000;
pub const MAX_CONVERSATIONS: usize = 4_000_000;
const MAX_LABEL: usize = 200;

#[derive(Debug, Default)]
pub struct Accumulators {
    pub hosts: HashMap<Address, HostStats>,
    pub ip_convs: HashMap<(Address, Address), ConvStats>,
    pub eth_convs: HashMap<(Address, Address), ConvStats>,
    hierarchy: HashMap<([u8; 12], u8), (u64, u64)>,
    pub events: Vec<Event>,
    pub dns_by_host: HashMap<Address, DnsActivity>,
    pub malformed: u64,
    pub packets: u64,
    pub bytes: u64,
    /// Set when a cap was hit and some statistics are incomplete.
    pub limit_reached: bool,
}

fn touch_host<'a>(
    hosts: &'a mut HashMap<Address, HostStats>,
    addr: Address,
    ts: i64,
    limit: &mut bool,
) -> Option<&'a mut HostStats> {
    if hosts.len() >= MAX_HOSTS && !hosts.contains_key(&addr) {
        *limit = true;
        return None;
    }
    let h = hosts.entry(addr).or_insert_with(|| HostStats { first_ns: ts, last_ns: ts, ..HostStats::default() });
    h.first_ns = h.first_ns.min(ts);
    h.last_ns = h.last_ns.max(ts);
    Some(h)
}

fn conv(map: &mut HashMap<(Address, Address), ConvStats>, src: Address, dst: Address, ts: i64, len: u64, limit: &mut bool) {
    let forward = src <= dst;
    let key = if forward { (src, dst) } else { (dst, src) };
    if map.len() >= MAX_CONVERSATIONS && !map.contains_key(&key) {
        *limit = true;
        return;
    }
    let c = map.entry(key).or_insert_with(|| ConvStats { first_ns: ts, last_ns: ts, ..ConvStats::default() });
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

impl Accumulators {
    pub fn record(&mut self, p: &PacketFacts) {
        let len = u64::from(p.frame_len);
        self.packets += 1;
        self.bytes += len;
        if p.malformed {
            self.malformed += 1;
        }
        let (src, dst) = if p.net_src.is_ip() { (p.net_src, p.net_dst) } else { (p.l2_src, p.l2_dst) };
        let limit = &mut self.limit_reached;
        if !src.is_none() {
            if let Some(h) = touch_host(&mut self.hosts, src, p.ts_ns, limit) {
                h.tx_packets += 1;
                h.tx_bytes += len;
                h.protocols = h.protocols.union(p.protocols);
                if src.is_ip() {
                    if let Address::Mac(m) = p.l2_src {
                        h.mac.get_or_insert(m);
                    }
                }
            }
        }
        if !dst.is_none() {
            if let Some(h) = touch_host(&mut self.hosts, dst, p.ts_ns, limit) {
                h.rx_packets += 1;
                h.rx_bytes += len;
                h.protocols = h.protocols.union(p.protocols);
            }
        }
        if p.net_src.is_ip() && p.net_dst.is_ip() {
            conv(&mut self.ip_convs, p.net_src, p.net_dst, p.ts_ns, len, limit);
        }
        if let (Address::Mac(_), Address::Mac(_)) = (p.l2_src, p.l2_dst) {
            conv(&mut self.eth_convs, p.l2_src, p.l2_dst, p.ts_ns, len, limit);
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
                        d.names.insert(name.to_owned());
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

    pub fn host_rows(&self, base_ns: i64) -> Vec<HostRow> {
        let mut rows: Vec<HostRow> = self
            .hosts
            .iter()
            .map(|(addr, h)| {
                let (kind, filter) = match addr {
                    Address::V4(_) => (AddressKind::Ipv4, format!("ip.addr == {addr}")),
                    Address::V6(_) => (AddressKind::Ipv6, format!("ipv6.addr == {addr}")),
                    _ => (AddressKind::Mac, format!("eth.addr == {addr}")),
                };
                HostRow {
                    address: addr.to_string(),
                    kind,
                    mac: h.mac.map(|m| m.to_string()),
                    packets: h.tx_packets + h.rx_packets,
                    bytes: h.tx_bytes + h.rx_bytes,
                    tx_packets: h.tx_packets,
                    tx_bytes: h.tx_bytes,
                    rx_packets: h.rx_packets,
                    rx_bytes: h.rx_bytes,
                    protocols: protocol_names(h.protocols),
                    first_seen: h.first_ns.saturating_sub(base_ns) as f64 / 1e9,
                    last_seen: h.last_ns.saturating_sub(base_ns) as f64 / 1e9,
                    filter,
                }
            })
            .collect();
        rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.address.cmp(&b.address)));
        rows
    }

    pub fn conversation_rows(&self, kind: ConversationKind, base_ns: i64) -> Vec<ConversationRow> {
        let map = match kind {
            ConversationKind::Eth => &self.eth_convs,
            ConversationKind::Ip => &self.ip_convs,
            _ => return Vec::new(),
        };
        let mut rows: Vec<ConversationRow> = map
            .iter()
            .map(|((a, b), c)| {
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
                    packets: c.a_to_b_packets + c.b_to_a_packets,
                    bytes: c.a_to_b_bytes + c.b_to_a_bytes,
                    a_to_b_packets: c.a_to_b_packets,
                    a_to_b_bytes: c.a_to_b_bytes,
                    b_to_a_packets: c.b_to_a_packets,
                    b_to_a_bytes: c.b_to_a_bytes,
                    start: c.first_ns.saturating_sub(base_ns) as f64 / 1e9,
                    duration: c.last_ns.saturating_sub(c.first_ns) as f64 / 1e9,
                    state: None,
                    stream: None,
                    filter,
                }
            })
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.bytes));
        rows
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

    fn facts(src: [u8; 4], dst: [u8; 4], path: &'static [u8], len: u32) -> PacketFacts<'static> {
        let mut protocols = ProtocolSet::default();
        for p in path {
            protocols.insert(ProtocolId::from_u8(*p).unwrap());
        }
        PacketFacts {
            index: 0,
            ts_ns: 1_000,
            frame_len: len,
            l2_src: Address::Mac(MacAddr([0, 0, 0, 0, 0, 1])),
            l2_dst: Address::Mac(MacAddr([0, 0, 0, 0, 0, 2])),
            net_src: Address::V4(src),
            net_dst: Address::V4(dst),
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
        acc.record(&facts([10, 0, 0, 1], [10, 0, 0, 2], TCP_PATH, 100));
        acc.record(&facts([10, 0, 0, 2], [10, 0, 0, 1], TCP_PATH, 60));
        acc.record(&facts([10, 0, 0, 1], [10, 0, 0, 3], DNS_PATH, 80));
        let hosts = acc.host_rows(0);
        let h1 = hosts.iter().find(|h| h.address == "10.0.0.1").unwrap();
        assert_eq!((h1.tx_packets, h1.tx_bytes, h1.rx_packets, h1.rx_bytes), (2, 180, 1, 60));
        assert_eq!(h1.mac.as_deref(), Some("00:00:00:00:00:01"));
        assert_eq!(h1.filter, "ip.addr == 10.0.0.1");
        assert!(h1.protocols.contains(&"DNS".to_owned()));
        let convs = acc.conversation_rows(ConversationKind::Ip, 0);
        assert_eq!(convs.len(), 2);
        let c = convs.iter().find(|c| c.b == "10.0.0.2").unwrap();
        assert_eq!((c.a_to_b_packets, c.b_to_a_packets, c.bytes), (1, 1, 160));
        assert_eq!(acc.conversation_rows(ConversationKind::Eth, 0).len(), 1);
    }

    #[test]
    fn hierarchy_counts_every_level() {
        let mut acc = Accumulators::default();
        acc.record(&facts([1, 1, 1, 1], [2, 2, 2, 2], TCP_PATH, 100));
        acc.record(&facts([1, 1, 1, 1], [2, 2, 2, 2], DNS_PATH, 50));
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
        for name in ["a.example", "b.example", "a.example"] {
            let mut f = facts([10, 0, 0, 9], [10, 0, 0, 53], DNS_PATH, 70);
            f.event = Some((TimelineKind::DnsQuery, "A x", Some(name)));
            acc.record(&f);
        }
        let d = &acc.dns_by_host[&Address::V4([10, 0, 0, 9])];
        assert_eq!((d.queries, d.names.len()), (3, 2));
        assert_eq!(acc.events.len(), 3);
    }
}
