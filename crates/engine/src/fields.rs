//! Binds the display filter to packets.
//!
//! Field ids are positions in `protocol::fields::ALL`. Fields that can be
//! answered from [`PacketMeta`] ("fast" fields) never touch the file; all
//! others trigger one lazy `Values`-mode dissection per packet.

use std::sync::OnceLock;

use nettrace_model::{tcp_analysis as ta, FieldInfo, FieldKind, FieldValue, ProtocolId, Transport};
use nettrace_packet::Address;
use nettrace_protocol::{dissect, fields, DissectOptions};
use nettrace_query::{FieldRegistry, FieldSource, FieldSpec, Filter, QueryError};
use nettrace_storage::{CaptureFile, PacketMeta};

use crate::frame::frame_context;
use crate::session::Shared;

#[derive(Debug, Clone, Copy)]
enum Fast {
    Protocol(ProtocolId),
    FrameNumber,
    FrameLen,
    FrameCapLen,
    TimeRelative,
    Interface,
    EthSrc,
    EthDst,
    IpSrc,
    IpDst,
    Ipv6Src,
    Ipv6Dst,
    SrcPort(Transport),
    DstPort(Transport),
    Stream(Transport),
    TcpFlags,
    TcpFlag(u16),
    Analysis(u16),
    AnalysisAny,
}

pub struct Registry {
    fast: Vec<Option<Fast>>,
    /// Protocol that must be present for a deep field to exist (skips dissection).
    owner: Vec<Option<ProtocolId>>,
}

fn owner_of(abbrev: &str) -> Option<ProtocolId> {
    let prefix = abbrev.split('.').next().unwrap_or(abbrev);
    match prefix {
        "x509sat" | "x509af" | "x509ce" => Some(ProtocolId::Tls),
        "frame" | "_ws" => None,
        p => fields::protocol_by_abbrev(p),
    }
}

fn fast_for(abbrev: &str) -> Option<Fast> {
    if let Some(p) = fields::protocol_by_abbrev(abbrev) {
        return Some(Fast::Protocol(p));
    }
    Some(match abbrev {
        "frame.number" => Fast::FrameNumber,
        "frame.len" => Fast::FrameLen,
        "frame.cap_len" => Fast::FrameCapLen,
        "frame.time_relative" => Fast::TimeRelative,
        "frame.interface_id" => Fast::Interface,
        "eth.src" => Fast::EthSrc,
        "eth.dst" => Fast::EthDst,
        "ip.src" => Fast::IpSrc,
        "ip.dst" => Fast::IpDst,
        "ipv6.src" => Fast::Ipv6Src,
        "ipv6.dst" => Fast::Ipv6Dst,
        "tcp.srcport" => Fast::SrcPort(Transport::Tcp),
        "tcp.dstport" => Fast::DstPort(Transport::Tcp),
        "udp.srcport" => Fast::SrcPort(Transport::Udp),
        "udp.dstport" => Fast::DstPort(Transport::Udp),
        "tcp.stream" => Fast::Stream(Transport::Tcp),
        "udp.stream" => Fast::Stream(Transport::Udp),
        "tcp.flags" => Fast::TcpFlags,
        "tcp.flags.fin" => Fast::TcpFlag(0x001),
        "tcp.flags.syn" => Fast::TcpFlag(0x002),
        "tcp.flags.reset" => Fast::TcpFlag(0x004),
        "tcp.flags.push" => Fast::TcpFlag(0x008),
        "tcp.flags.ack" => Fast::TcpFlag(0x010),
        "tcp.flags.urg" => Fast::TcpFlag(0x020),
        "tcp.flags.ece" => Fast::TcpFlag(0x040),
        "tcp.flags.cwr" => Fast::TcpFlag(0x080),
        "tcp.flags.ae" => Fast::TcpFlag(0x100),
        "tcp.analysis.flags" => Fast::AnalysisAny,
        "tcp.analysis.retransmission" => Fast::Analysis(ta::RETRANSMISSION),
        "tcp.analysis.fast_retransmission" => Fast::Analysis(ta::FAST_RETRANSMISSION),
        "tcp.analysis.out_of_order" => Fast::Analysis(ta::OUT_OF_ORDER),
        "tcp.analysis.duplicate_ack" => Fast::Analysis(ta::DUPLICATE_ACK),
        "tcp.analysis.zero_window" => Fast::Analysis(ta::ZERO_WINDOW),
        "tcp.analysis.keep_alive" => Fast::Analysis(ta::KEEP_ALIVE),
        "tcp.analysis.lost_segment" => Fast::Analysis(ta::LOST_SEGMENT),
        "tcp.analysis.window_update" => Fast::Analysis(ta::WINDOW_UPDATE),
        "tcp.analysis.reused_ports" => Fast::Analysis(ta::PORT_REUSE),
        "tcp.analysis.ack_lost_segment" => Fast::Analysis(ta::ACKED_UNSEEN),
        _ => return None,
    })
}

pub fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(|| Registry {
        fast: fields::ALL.iter().map(|f| fast_for(f.abbrev)).collect(),
        owner: fields::ALL.iter().map(|f| owner_of(f.abbrev)).collect(),
    })
}

fn id_of(field: &'static fields::Field) -> Option<u32> {
    fields::ALL.iter().position(|f| std::ptr::eq(*f, field)).map(|i| i as u32)
}

impl FieldRegistry for Registry {
    fn resolve(&self, name: &str) -> Option<FieldSpec> {
        if let Some((kind, members)) = fields::alias(name) {
            return Some(FieldSpec { kind, ids: members.iter().filter_map(|f| id_of(f)).collect() });
        }
        let id = fields::ALL.iter().position(|f| f.abbrev == name)?;
        Some(FieldSpec { kind: fields::ALL[id].kind, ids: vec![id as u32] })
    }
}

impl Registry {
    pub fn compile(&self, text: &str) -> Result<Filter, QueryError> {
        Filter::compile(text, self)
    }

    pub fn field_infos(&self) -> Vec<FieldInfo> {
        let mut out: Vec<FieldInfo> = fields::ALL
            .iter()
            .enumerate()
            .filter(|(_, f)| f.kind != FieldKind::None || f.abbrev.starts_with("tcp.analysis."))
            .map(|(i, f)| FieldInfo {
                abbrev: f.abbrev.to_owned(),
                name: f.name.to_owned(),
                kind: f.kind,
                indexed: self.fast[i].is_some(),
            })
            .collect();
        for (abbrev, name, kind, members) in fields::ALIASES {
            out.push(FieldInfo {
                abbrev: (*abbrev).to_owned(),
                name: (*name).to_owned(),
                kind: *kind,
                indexed: members.iter().all(|m| fast_for(m.abbrev).is_some()),
            });
        }
        out.sort_by(|a, b| a.abbrev.cmp(&b.abbrev));
        out
    }
}

/// Field values of one indexed packet; deep fields are dissected lazily.
pub struct PacketFields<'a> {
    shared: &'a Shared,
    file: &'a CaptureFile,
    index: u32,
    meta: &'a PacketMeta,
    deep: Option<Vec<(&'static fields::Field, FieldValue)>>,
    /// Already-loaded packet bytes, if the caller has them.
    data: Option<&'a [u8]>,
    /// Set when the packet bytes could not be read; results are then unreliable.
    read_error: Option<std::io::Error>,
}

impl<'a> PacketFields<'a> {
    pub fn new(shared: &'a Shared, file: &'a CaptureFile, index: u32, meta: &'a PacketMeta) -> Self {
        PacketFields { shared, file, index, meta, deep: None, data: None, read_error: None }
    }

    pub fn with_data(mut self, data: &'a [u8]) -> Self {
        self.data = Some(data);
        self
    }

    fn deep(&mut self) -> &[(&'static fields::Field, FieldValue)] {
        if self.deep.is_none() {
            let owned;
            let bytes = match self.data {
                Some(d) => d,
                None => {
                    owned = match self.file.read(self.meta) {
                        Ok(b) => b,
                        Err(e) => {
                            self.read_error = Some(e);
                            Vec::new()
                        }
                    };
                    &owned[..]
                }
            };
            let fctx = frame_context(self.shared, self.index);
            self.deep = Some(dissect(bytes, &fctx, DissectOptions::VALUES).values);
        }
        self.deep.as_deref().unwrap_or(&[])
    }

    /// I/O error hit while loading the packet for deep fields, if any.
    pub fn take_read_error(&mut self) -> Option<std::io::Error> {
        self.read_error.take()
    }

    fn addr(&self, id: u32) -> Address {
        self.shared.index.addrs.get(id)
    }
}

fn push_addr(out: &mut Vec<FieldValue>, addr: Address, want: FieldKind) {
    match (addr, want) {
        (Address::V4(b), FieldKind::Ipv4) => out.push(FieldValue::Ipv4(b)),
        (Address::V6(b), FieldKind::Ipv6) => out.push(FieldValue::Ipv6(b)),
        (Address::Mac(m), FieldKind::Mac) => out.push(FieldValue::Mac(m.0)),
        _ => {}
    }
}

impl FieldSource for PacketFields<'_> {
    fn values(&mut self, id: u32, out: &mut Vec<FieldValue>) {
        let reg = registry();
        let m = self.meta;
        let transport = |t: Transport| {
            let p = if t == Transport::Tcp { ProtocolId::Tcp } else { ProtocolId::Udp };
            m.protocols & p.bit() != 0
        };
        match reg.fast.get(id as usize).copied().flatten() {
            Some(Fast::Protocol(p)) => {
                if m.protocols & p.bit() != 0 {
                    out.push(FieldValue::None);
                }
            }
            Some(Fast::FrameNumber) => out.push(FieldValue::U64(u64::from(self.index) + 1)),
            Some(Fast::FrameLen) => out.push(FieldValue::U64(u64::from(m.origlen))),
            Some(Fast::FrameCapLen) => out.push(FieldValue::U64(u64::from(m.caplen))),
            Some(Fast::Interface) => out.push(FieldValue::U64(u64::from(m.interface))),
            Some(Fast::TimeRelative) => {
                let base = self.shared.index.first_ts().unwrap_or(m.ts_ns);
                out.push(FieldValue::F64(m.ts_ns.saturating_sub(base) as f64 / 1e9));
            }
            Some(Fast::EthSrc) => push_addr(out, self.addr(m.l2_src), FieldKind::Mac),
            Some(Fast::EthDst) => push_addr(out, self.addr(m.l2_dst), FieldKind::Mac),
            Some(Fast::IpSrc) => push_addr(out, self.addr(m.src), FieldKind::Ipv4),
            Some(Fast::IpDst) => push_addr(out, self.addr(m.dst), FieldKind::Ipv4),
            Some(Fast::Ipv6Src) => push_addr(out, self.addr(m.src), FieldKind::Ipv6),
            Some(Fast::Ipv6Dst) => push_addr(out, self.addr(m.dst), FieldKind::Ipv6),
            Some(Fast::SrcPort(t)) => {
                if transport(t) {
                    out.push(FieldValue::U64(u64::from(m.sport)));
                }
            }
            Some(Fast::DstPort(t)) => {
                if transport(t) {
                    out.push(FieldValue::U64(u64::from(m.dport)));
                }
            }
            Some(Fast::Stream(t)) => {
                if let Some(f) = m.flow().and_then(|f| self.shared.flows.flow(f)) {
                    if f.transport == t {
                        out.push(FieldValue::U64(u64::from(f.stream_id)));
                    }
                }
            }
            Some(Fast::TcpFlags) => {
                if transport(Transport::Tcp) {
                    out.push(FieldValue::U64(u64::from(m.tcp_flags)));
                }
            }
            Some(Fast::TcpFlag(bit)) => {
                if transport(Transport::Tcp) {
                    out.push(FieldValue::Bool(m.tcp_flags & bit != 0));
                }
            }
            Some(Fast::Analysis(bit)) => {
                if m.analysis & bit != 0 {
                    out.push(FieldValue::None);
                }
            }
            Some(Fast::AnalysisAny) => {
                if m.analysis & !ta::WINDOW_UPDATE != 0 {
                    out.push(FieldValue::None);
                }
            }
            None => {
                let Some(field) = fields::ALL.get(id as usize).copied() else { return };
                if let Some(p) = reg.owner.get(id as usize).copied().flatten() {
                    if m.protocols & p.bit() == 0 {
                        return;
                    }
                }
                for (f, v) in self.deep() {
                    if std::ptr::eq(*f, field) {
                        out.push(v.clone());
                    }
                }
            }
        }
    }
}
