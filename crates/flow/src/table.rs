use std::collections::HashMap;

use nettrace_model::{
    tcp_analysis as ta, Endpoint, FlowSummary, Handshake, ProtocolId, TcpFlowStats, Transport,
};
use nettrace_packet::Address;

use crate::tcp::TcpFlow;
use crate::{flags as fl, Dir};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub window: u16,
    pub payload_len: u32,
    /// Window scale option (SYN only).
    pub wscale: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    Tcp(TcpSegment),
    Udp { payload_len: u32 },
}

/// The subset of a dissected packet the flow engine needs.
#[derive(Debug, Clone, Copy)]
pub struct FlowPacket {
    /// 0-based packet index in the capture.
    pub index: u32,
    pub ts_ns: i64,
    pub frame_len: u32,
    pub src: Address,
    pub dst: Address,
    pub sport: u16,
    pub dport: u16,
    pub kind: FlowKind,
    /// Highest protocol above the transport layer, if any.
    pub app: Option<ProtocolId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowAssignment {
    /// Index into [`FlowTable::flows`].
    pub flow: u32,
    pub dir: Dir,
    pub analysis: u16,
}

#[derive(Debug, Clone, Default)]
pub struct DirStats {
    pub packets: u64,
    pub bytes: u64,
    pub payload: u64,
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub transport: Transport,
    /// `tcp.stream` / `udp.stream` number.
    pub stream_id: u32,
    pub client: (Address, u16),
    pub server: (Address, u16),
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    /// Packet indices (0-based) in capture order.
    pub packets: Vec<u32>,
    pub c2s: DirStats,
    pub s2c: DirStats,
    pub app: Option<ProtocolId>,
    pub tcp: Option<Box<TcpFlow>>,
}

impl Flow {
    pub fn direction_of(&self, src: Address, sport: u16) -> Dir {
        if (src, sport) == self.client { Dir::ClientToServer } else { Dir::ServerToClient }
    }

    pub fn first_packet(&self) -> u32 {
        self.packets.first().copied().unwrap_or(0)
    }

    pub fn last_packet(&self) -> u32 {
        self.packets.last().copied().unwrap_or(0)
    }

    pub fn duration_ns(&self) -> i64 {
        self.last_ts_ns.saturating_sub(self.first_ts_ns)
    }

    pub fn total_bytes(&self) -> u64 {
        self.c2s.bytes + self.s2c.bytes
    }

    /// Display filter selecting the flow.
    pub fn filter(&self) -> String {
        match self.transport {
            Transport::Tcp => format!("tcp.stream == {}", self.stream_id),
            Transport::Udp => format!("udp.stream == {}", self.stream_id),
        }
    }

    /// UI model; times are relative to `base_ns` (first packet of the capture).
    pub fn summary(&self, base_ns: i64) -> FlowSummary {
        let ms = |ns: i64| ns as f64 / 1e6;
        let secs = (self.duration_ns() as f64 / 1e9).max(0.0);
        let throughput = |bytes: u64| if secs > 0.0 { bytes as f64 / secs } else { 0.0 };
        let tcp = self.tcp.as_deref().map(|t| TcpFlowStats {
            state: t.state(),
            handshake: Handshake {
                syn: t.syn.map(|p| p + 1),
                syn_ack: t.syn_ack.map(|p| p + 1),
                ack: t.handshake_ack.map(|p| p + 1),
            },
            irtt_ms: t.irtt_ns.map(ms),
            rtt_min_ms: t.rtt_min_ns.map(ms),
            rtt_avg_ms: t.rtt_avg_ns().map(ms),
            rtt_max_ms: t.rtt_max_ns.map(ms),
            rtt_samples: t.rtt_samples.len() as u32,
            retransmissions: t.retransmissions,
            fast_retransmissions: t.fast_retransmissions,
            duplicate_acks: t.duplicate_acks,
            out_of_order: t.out_of_order,
            zero_window: t.zero_window,
            keep_alive: t.keep_alive,
            lost_segments: t.lost_segments,
            resets: t.resets,
            fin_client: t.fin[0].map(|p| p + 1),
            fin_server: t.fin[1].map(|p| p + 1),
            throughput_c2s: throughput(self.c2s.payload),
            throughput_s2c: throughput(self.s2c.payload),
        });
        FlowSummary {
            kind: self.transport,
            id: self.stream_id,
            client: Endpoint { addr: self.client.0.to_string(), port: self.client.1 },
            server: Endpoint { addr: self.server.0.to_string(), port: self.server.1 },
            protocol: self
                .app
                .map(|p| p.short_name().to_owned())
                .unwrap_or_else(|| match self.transport {
                    Transport::Tcp => "TCP".to_owned(),
                    Transport::Udp => "UDP".to_owned(),
                }),
            packets: self.packets.len() as u64,
            bytes: self.total_bytes(),
            c2s_packets: self.c2s.packets,
            c2s_bytes: self.c2s.bytes,
            c2s_payload: self.c2s.payload,
            s2c_packets: self.s2c.packets,
            s2c_bytes: self.s2c.bytes,
            s2c_payload: self.s2c.payload,
            first_packet: self.first_packet() + 1,
            last_packet: self.last_packet() + 1,
            start: self.first_ts_ns.saturating_sub(base_ns) as f64 / 1e9,
            duration: secs,
            tcp,
        }
    }
}

type Endpoint2 = (Address, u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    a: Endpoint2,
    b: Endpoint2,
    transport: Transport,
}

impl FlowKey {
    fn new(transport: Transport, x: Endpoint2, y: Endpoint2) -> Self {
        if x <= y { FlowKey { a: x, b: y, transport } } else { FlowKey { a: y, b: x, transport } }
    }
}

fn is_well_known(port: u16) -> bool {
    port < 1024
}

/// All flows of a capture.
#[derive(Debug, Default)]
pub struct FlowTable {
    flows: Vec<Flow>,
    by_key: HashMap<FlowKey, u32>,
    tcp_streams: Vec<u32>,
    udp_streams: Vec<u32>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn flows(&self) -> &[Flow] {
        &self.flows
    }

    pub fn flow(&self, index: u32) -> Option<&Flow> {
        self.flows.get(index as usize)
    }

    pub fn stream(&self, transport: Transport, id: u32) -> Option<(u32, &Flow)> {
        let list = match transport {
            Transport::Tcp => &self.tcp_streams,
            Transport::Udp => &self.udp_streams,
        };
        let idx = *list.get(id as usize)?;
        Some((idx, &self.flows[idx as usize]))
    }

    pub fn tcp_count(&self) -> u32 {
        self.tcp_streams.len() as u32
    }

    pub fn udp_count(&self) -> u32 {
        self.udp_streams.len() as u32
    }

    fn create(&mut self, key: FlowKey, p: &FlowPacket) -> u32 {
        let src = (p.src, p.sport);
        let dst = (p.dst, p.dport);
        let (transport, client_is_src) = match p.kind {
            FlowKind::Tcp(seg) => {
                let syn = seg.flags & fl::SYN != 0;
                let ack = seg.flags & fl::ACK != 0;
                let c = if syn {
                    !ack
                } else if is_well_known(p.sport) != is_well_known(p.dport) {
                    is_well_known(p.dport)
                } else {
                    true
                };
                (Transport::Tcp, c)
            }
            FlowKind::Udp { .. } => {
                let c = if is_well_known(p.sport) != is_well_known(p.dport) { is_well_known(p.dport) } else { true };
                (Transport::Udp, c)
            }
        };
        let (client, server) = if client_is_src { (src, dst) } else { (dst, src) };
        let index = self.flows.len() as u32;
        let streams = match transport {
            Transport::Tcp => &mut self.tcp_streams,
            Transport::Udp => &mut self.udp_streams,
        };
        let stream_id = streams.len() as u32;
        streams.push(index);
        self.flows.push(Flow {
            transport,
            stream_id,
            client,
            server,
            first_ts_ns: p.ts_ns,
            last_ts_ns: p.ts_ns,
            packets: Vec::new(),
            c2s: DirStats::default(),
            s2c: DirStats::default(),
            app: None,
            tcp: (transport == Transport::Tcp).then(Box::default),
        });
        self.by_key.insert(key, index);
        index
    }

    /// Assigns a TCP/UDP packet to its flow (creating it if needed) and runs
    /// TCP analysis. Packets must be fed in capture order.
    pub fn process(&mut self, p: &FlowPacket) -> FlowAssignment {
        let transport = match p.kind {
            FlowKind::Tcp(_) => Transport::Tcp,
            FlowKind::Udp { .. } => Transport::Udp,
        };
        let key = FlowKey::new(transport, (p.src, p.sport), (p.dst, p.dport));
        let mut extra = 0u16;
        let index = match self.by_key.get(&key).copied() {
            None => self.create(key, p),
            Some(existing) => {
                if self.is_port_reuse(existing, p) {
                    extra |= ta::PORT_REUSE;
                    self.create(key, p)
                } else {
                    existing
                }
            }
        };
        let flow = &mut self.flows[index as usize];
        let dir = flow.direction_of(p.src, p.sport);
        flow.packets.push(p.index);
        flow.last_ts_ns = flow.last_ts_ns.max(p.ts_ns);
        let payload = match p.kind {
            FlowKind::Tcp(seg) => seg.payload_len,
            FlowKind::Udp { payload_len } => payload_len,
        };
        let stats = match dir {
            Dir::ClientToServer => &mut flow.c2s,
            Dir::ServerToClient => &mut flow.s2c,
        };
        stats.packets += 1;
        stats.bytes += u64::from(p.frame_len);
        stats.payload += u64::from(payload);
        if let Some(app) = p.app {
            flow.app.get_or_insert(app);
        }
        let mut analysis = extra;
        if let (FlowKind::Tcp(seg), Some(tcp)) = (p.kind, flow.tcp.as_deref_mut()) {
            let a = tcp.analyse(p.index, p.ts_ns, dir, &seg);
            analysis |= a.flags;
        }
        FlowAssignment { flow: index, dir, analysis }
    }

    /// Like [`FlowTable::process`], but when `allow_new` is false packets of
    /// unknown flows are not tracked (returns `None`).
    pub fn process_capped(&mut self, allow_new: bool, p: &FlowPacket) -> Option<FlowAssignment> {
        if !allow_new {
            let transport = match p.kind {
                FlowKind::Tcp(_) => Transport::Tcp,
                FlowKind::Udp { .. } => Transport::Udp,
            };
            let key = FlowKey::new(transport, (p.src, p.sport), (p.dst, p.dport));
            match self.by_key.get(&key) {
                Some(&idx) if !self.is_port_reuse(idx, p) => {}
                _ => return None,
            }
        }
        Some(self.process(p))
    }

    fn is_port_reuse(&self, existing: u32, p: &FlowPacket) -> bool {
        let FlowKind::Tcp(seg) = p.kind else { return false };
        if seg.flags & fl::SYN == 0 || seg.flags & fl::ACK != 0 {
            return false;
        }
        let flow = &self.flows[existing as usize];
        let Some(tcp) = flow.tcp.as_deref() else { return false };
        let dir = flow.direction_of(p.src, p.sport);
        let same_isn = tcp.syn.is_some() && tcp.dirs[dir.index()].base_seq == Some(seg.seq);
        // A SYN that is not a retransmission of the flow's own SYN starts a new stream.
        !flow.packets.is_empty() && !same_isn
    }
}
