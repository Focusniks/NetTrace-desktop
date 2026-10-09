//! Dissector registry and the per-frame dispatch loop.
//!
//! Dissectors never call each other directly: each returns a [`Handoff`]
//! describing the next layer and the registry picks the next dissector.
//! New protocols are added by registering them here — the UI and the filter
//! engine work with the generic tree and need no changes.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

use nettrace_model::{FieldValue, ProtocolId, Severity, Transport};
use nettrace_packet::{Cursor, LinkType};

use crate::context::{Ctx, DissectOptions, FrameContext, Malformed, Summary};
use crate::fields::{self, Field};
use crate::tree::{Node, Tree};
use crate::{app, link, net, transport};

/// Byte range of one layer inside the frame.
#[derive(Debug, Clone, Copy)]
pub struct Layer<'a> {
    pub frame: &'a [u8],
    pub start: usize,
    pub end: usize,
}

impl<'a> Layer<'a> {
    pub fn new(frame: &'a [u8], start: usize, end: usize) -> Self {
        let end = end.min(frame.len());
        Layer { frame, start: start.min(end), end }
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.frame.get(self.start..self.end).unwrap_or(&[])
    }

    pub fn cursor(&self) -> Cursor<'a> {
        Cursor::with_base(self.bytes(), self.start)
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// What follows the current layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handoff {
    Done,
    Ethertype { ethertype: u16, start: usize, end: usize },
    IpProto { proto: u8, start: usize, end: usize },
    Payload { transport: Transport, src_port: u16, dst_port: u16, start: usize, end: usize },
    /// Undissected bytes.
    Data { start: usize, end: usize },
}

/// Link, network and transport layer dissector.
pub trait Dissector: Send + Sync {
    fn protocol(&self) -> ProtocolId;
    fn dissect(&self, ctx: &mut Ctx, layer: Layer) -> Result<Handoff, Malformed>;
}

/// Application protocol carried over TCP/UDP.
pub trait AppDissector: Send + Sync {
    fn protocol(&self) -> ProtocolId;
    fn tcp_ports(&self) -> &'static [u16] {
        &[]
    }
    fn udp_ports(&self) -> &'static [u16] {
        &[]
    }
    /// Cheap check used when the port matches.
    fn accepts(&self, payload: &[u8], transport: Transport) -> bool;
    /// Stricter content check for traffic on non-registered ports.
    fn heuristic(&self, _payload: &[u8], _transport: Transport) -> bool {
        false
    }
    fn dissect(&self, ctx: &mut Ctx, layer: Layer, transport: Transport) -> Result<(), Malformed>;
}

pub struct Registry {
    link: HashMap<LinkType, &'static dyn Dissector>,
    ethertype: HashMap<u16, &'static dyn Dissector>,
    ip_proto: HashMap<u8, &'static dyn Dissector>,
    tcp_ports: HashMap<u16, Vec<&'static dyn AppDissector>>,
    udp_ports: HashMap<u16, Vec<&'static dyn AppDissector>>,
    apps: Vec<&'static dyn AppDissector>,
}

impl Registry {
    pub fn empty() -> Self {
        Registry {
            link: HashMap::new(),
            ethertype: HashMap::new(),
            ip_proto: HashMap::new(),
            tcp_ports: HashMap::new(),
            udp_ports: HashMap::new(),
            apps: Vec::new(),
        }
    }

    pub fn with_builtins() -> Self {
        let mut r = Registry::empty();
        r.register_link(LinkType::Ethernet, &link::ethernet::ETHERNET);
        r.register_link(LinkType::LinuxSll, &link::sll::SLL);
        r.register_link(LinkType::LinuxSll2, &link::sll::SLL2);
        r.register_link(LinkType::Null, &link::null::NULL);
        r.register_link(LinkType::Loop, &link::null::LOOP);
        r.register_link(LinkType::Ipv4, &net::ipv4::IPV4);
        r.register_link(LinkType::Ipv6, &net::ipv6::IPV6);

        for t in [0x8100, 0x88a8, 0x9100] {
            r.register_ethertype(t, &link::vlan::VLAN);
        }
        r.register_ethertype(0x0806, &link::arp::ARP);
        r.register_ethertype(0x0800, &net::ipv4::IPV4);
        r.register_ethertype(0x86dd, &net::ipv6::IPV6);

        r.register_ip_proto(1, &net::icmp::ICMP);
        r.register_ip_proto(58, &net::icmpv6::ICMPV6);
        r.register_ip_proto(6, &transport::tcp::TCP);
        r.register_ip_proto(17, &transport::udp::UDP);

        r.register_app(&app::dns::DNS);
        r.register_app(&app::dhcp::DHCP);
        r.register_app(&app::ntp::NTP);
        r.register_app(&app::tls::TLS);
        r.register_app(&app::http::HTTP);
        r
    }

    pub fn register_link(&mut self, link: LinkType, d: &'static dyn Dissector) {
        self.link.insert(link, d);
    }

    pub fn register_ethertype(&mut self, ethertype: u16, d: &'static dyn Dissector) {
        self.ethertype.insert(ethertype, d);
    }

    pub fn register_ip_proto(&mut self, proto: u8, d: &'static dyn Dissector) {
        self.ip_proto.insert(proto, d);
    }

    pub fn register_app(&mut self, d: &'static dyn AppDissector) {
        for p in d.tcp_ports() {
            self.tcp_ports.entry(*p).or_default().push(d);
        }
        for p in d.udp_ports() {
            self.udp_ports.entry(*p).or_default().push(d);
        }
        self.apps.push(d);
    }

    fn app_for(&self, payload: &[u8], transport: Transport, src: u16, dst: u16) -> Option<&'static dyn AppDissector> {
        let table = match transport {
            Transport::Tcp => &self.tcp_ports,
            Transport::Udp => &self.udp_ports,
        };
        // Try the lower (usually well-known) port first.
        let (lo, hi) = if src <= dst { (src, dst) } else { (dst, src) };
        for port in [lo, hi] {
            if let Some(list) = table.get(&port) {
                if let Some(d) = list.iter().find(|d| d.accepts(payload, transport)) {
                    return Some(*d);
                }
            }
        }
        self.apps.iter().copied().find(|d| d.heuristic(payload, transport))
    }
}

/// Process-wide registry with all built-in dissectors.
pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::with_builtins)
}

/// Result of dissecting one frame.
#[derive(Debug)]
pub struct Dissection {
    pub summary: Summary,
    pub info: String,
    /// Protocol tree (Full mode only).
    pub nodes: Vec<Node>,
    /// Flat typed values (Values mode only).
    pub values: Vec<(&'static Field, FieldValue)>,
}

const MAX_LAYERS: usize = 24;

/// Dissects a frame with the built-in registry. Never panics: a panic inside a
/// dissector is caught and reported as a malformed packet.
pub fn dissect(frame: &[u8], fctx: &FrameContext, opts: DissectOptions) -> Dissection {
    dissect_with(registry(), frame, fctx, opts)
}

pub fn dissect_with(reg: &Registry, frame: &[u8], fctx: &FrameContext, opts: DissectOptions) -> Dissection {
    match catch_unwind(AssertUnwindSafe(|| run(reg, frame, fctx, opts))) {
        Ok(d) => d,
        Err(_) => {
            let mut ctx = Ctx::new(fctx, opts);
            ctx.push_protocol(ProtocolId::Frame);
            ctx.push_protocol(ProtocolId::Malformed);
            ctx.summary.malformed = true;
            ctx.tree.expert(&fields::MALFORMED, Severity::Error, || {
                "[Malformed Packet: dissector failure]".to_owned()
            });
            ctx.info.set(ProtocolId::Malformed, || "[Malformed Packet]".to_owned());
            finish(ctx, frame)
        }
    }
}

enum Step<'a> {
    Layer(&'static dyn Dissector, Layer<'a>),
    App(&'static dyn AppDissector, Layer<'a>, Transport),
    Data(Layer<'a>),
    Done,
}

fn run(reg: &Registry, frame: &[u8], fctx: &FrameContext, opts: DissectOptions) -> Dissection {
    let mut ctx = Ctx::new(fctx, opts);
    ctx.push_protocol(ProtocolId::Frame);
    let whole = Layer::new(frame, 0, frame.len());
    let mut step = match fctx.link_type {
        // Raw IP has no link header: dispatch on the IP version nibble.
        Some(LinkType::Raw) => {
            let ethertype = if frame.first().map(|b| b >> 4) == Some(6) { 0x86dd } else { 0x0800 };
            resolve(reg, frame, Handoff::Ethertype { ethertype, start: 0, end: frame.len() })
        }
        Some(l) => match reg.link.get(&l) {
            Some(d) => Step::Layer(*d, whole),
            None => Step::Data(whole),
        },
        None => Step::Data(whole),
    };
    for _ in 0..MAX_LAYERS {
        let depth = ctx.tree.depth();
        let app = matches!(step, Step::App(..));
        let result = match step {
            Step::Done => break,
            Step::Layer(d, layer) => {
                ctx.push_protocol(d.protocol());
                d.dissect(&mut ctx, layer)
            }
            Step::App(d, layer, transport) => {
                ctx.push_protocol(d.protocol());
                d.dissect(&mut ctx, layer, transport).map(|_| Handoff::Done)
            }
            Step::Data(layer) => {
                data(&mut ctx, layer);
                Ok(Handoff::Done)
            }
        };
        ctx.tree.close_to(depth);
        step = match result {
            Ok(h) => resolve(reg, frame, h),
            // Running out of bytes is expected when the payload is knowingly cut;
            // invalid values are still malformed.
            Err(mal) if app && ctx.incomplete && mal.truncated => {
                unreassembled(&mut ctx, mal);
                Step::Done
            }
            Err(mal) => {
                malformed(&mut ctx, mal);
                Step::Done
            }
        };
    }
    finish(ctx, frame)
}

fn resolve<'a>(reg: &Registry, frame: &'a [u8], h: Handoff) -> Step<'a> {
    match h {
        Handoff::Done => Step::Done,
        Handoff::Data { start, end } => {
            let layer = Layer::new(frame, start, end);
            if layer.is_empty() { Step::Done } else { Step::Data(layer) }
        }
        Handoff::Ethertype { ethertype, start, end } => {
            let layer = Layer::new(frame, start, end);
            match reg.ethertype.get(&ethertype) {
                Some(d) => Step::Layer(*d, layer),
                None if layer.is_empty() => Step::Done,
                None => Step::Data(layer),
            }
        }
        Handoff::IpProto { proto, start, end } => {
            let layer = Layer::new(frame, start, end);
            match reg.ip_proto.get(&proto) {
                Some(d) => Step::Layer(*d, layer),
                None if layer.is_empty() => Step::Done,
                None => Step::Data(layer),
            }
        }
        Handoff::Payload { transport, src_port, dst_port, start, end } => {
            let layer = Layer::new(frame, start, end);
            if layer.is_empty() {
                return Step::Done;
            }
            match reg.app_for(layer.bytes(), transport, src_port, dst_port) {
                Some(d) => Step::App(d, layer, transport),
                None => Step::Data(layer),
            }
        }
    }
}

fn data(ctx: &mut Ctx, layer: Layer) {
    ctx.push_protocol(ProtocolId::Data);
    let bytes = layer.bytes();
    let n = bytes.len();
    ctx.tree.open(&fields::DATA, layer.start, n);
    ctx.tree.heading(|| format!("Data ({})", crate::format::plural_bytes(n)));
    ctx.tree.bytes(&fields::DATA_DATA, layer.start, bytes);
    ctx.tree.generated(&fields::DATA_LEN, FieldValue::U64(n as u64), || n.to_string());
    ctx.tree.close();
}

fn malformed(ctx: &mut Ctx, mal: Malformed) {
    ctx.summary.malformed = true;
    ctx.push_protocol(ProtocolId::Malformed);
    let name = mal.protocol.short_name();
    ctx.tree.expert(&fields::MALFORMED, Severity::Error, || {
        format!("[Malformed Packet: {name}] (offset {})", mal.offset)
    });
    if ctx.info.enabled() {
        let text = if ctx.info.as_str().is_empty() {
            format!("[Malformed Packet: {name}]")
        } else {
            format!("{} [Malformed Packet]", ctx.info.as_str())
        };
        ctx.info.set(ProtocolId::Malformed, || text);
    }
}

/// An application message cut short by the capture itself (snaplen, IP
/// fragmentation without reassembly): a note, not a malformed packet.
fn unreassembled(ctx: &mut Ctx, mal: Malformed) {
    let name = mal.protocol.short_name();
    ctx.tree.expert(&fields::EXPERT, Severity::Warning, || {
        format!("[{name} message is incomplete in this packet (offset {}): not reassembled]", mal.offset)
    });
    if ctx.info.enabled() {
        let text = match ctx.info.as_str() {
            "" => format!("[Unreassembled {name}]"),
            info => format!("{info} [Unreassembled]"),
        };
        ctx.info.set(mal.protocol, || text);
    }
}

fn finish(ctx: Ctx, frame: &[u8]) -> Dissection {
    let Ctx { frame: fctx, summary, tree, info, .. } = ctx;
    let mode = tree.mode();
    let (mut nodes, mut values) = tree.finish();
    if mode != crate::tree::TreeMode::Off {
        let mut ft = Tree::new(mode);
        link::frame::frame_tree(&mut ft, fctx, &summary, frame.len());
        let (fnodes, fvalues) = ft.finish();
        nodes.splice(0..0, fnodes);
        values.splice(0..0, fvalues);
    }
    Dissection { summary, info: info.into_string(), nodes, values }
}
