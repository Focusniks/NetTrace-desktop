use nettrace_model::{ProtocolId, ProtocolSet, TimelineKind, Transport};
use nettrace_packet::{Address, LinkType, Timestamp, Truncated};

use crate::tree::{Tree, TreeMode};

/// What the caller needs from a dissection pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DissectOptions {
    pub tree: TreeMode,
    /// Build the Info column text.
    pub info: bool,
    /// Report application events (DNS query, TLS SNI, HTTP request …).
    pub events: bool,
}

impl DissectOptions {
    /// Indexing pass: summary + events, no strings for the tree.
    pub const INDEX: DissectOptions = DissectOptions { tree: TreeMode::Off, info: false, events: true };
    /// Packet list row.
    pub const ROW: DissectOptions = DissectOptions { tree: TreeMode::Off, info: true, events: false };
    /// Deep display filter.
    pub const VALUES: DissectOptions = DissectOptions { tree: TreeMode::Values, info: false, events: false };
    /// Packet details pane.
    pub const FULL: DissectOptions = DissectOptions { tree: TreeMode::Full, info: true, events: false };
}

/// Facts about the frame supplied by the caller (capture + analysis layers).
#[derive(Debug, Clone, Default)]
pub struct FrameContext {
    pub number: u32,
    pub ts: Timestamp,
    pub time_rel_ns: i64,
    pub time_delta_ns: i64,
    pub caplen: u32,
    pub origlen: u32,
    pub interface: u16,
    pub link_type: Option<LinkType>,
    /// TCP analysis results, when the packet is already indexed.
    pub tcp: Option<TcpAnnotations>,
    pub udp_stream: Option<u32>,
}

/// Results of TCP stream analysis for one segment.
#[derive(Debug, Clone, Default)]
pub struct TcpAnnotations {
    pub stream: u32,
    /// Raw sequence number that maps to relative 0 for this direction.
    pub seq_base: Option<u32>,
    /// Raw sequence number of the opposite direction (for relative ACK).
    pub ack_base: Option<u32>,
    pub analysis: u16,
    pub ack_rtt_ns: Option<i64>,
    /// Frame number of the segment acknowledged by this packet.
    pub acked_frame: Option<u32>,
    /// Window scale shift for this direction, if negotiated.
    pub window_shift: Option<u8>,
    pub time_since_first_ns: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpInfo {
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub window: u16,
    pub header_len: u8,
    pub payload_len: u32,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_perm: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportInfo {
    Tcp(TcpInfo),
    Udp { payload_len: u32 },
}

impl TransportInfo {
    pub fn kind(&self) -> Transport {
        match self {
            TransportInfo::Tcp(_) => Transport::Tcp,
            TransportInfo::Udp { .. } => Transport::Udp,
        }
    }
}

/// Application-level event reported during indexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEvent {
    pub kind: TimelineKind,
    pub label: String,
    /// Querying host for DNS (used by indicators).
    pub name: Option<String>,
}

pub const MAX_PATH: usize = 12;

/// Compact facts extracted by every dissection pass (the "fast path").
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub protocols: ProtocolSet,
    /// Highest protocol layer (Protocol column).
    pub top: Option<ProtocolId>,
    /// Protocol stack in order (for the protocol hierarchy).
    pub path: [u8; MAX_PATH],
    pub path_len: u8,
    pub l2_src: Address,
    pub l2_dst: Address,
    pub net_src: Address,
    pub net_dst: Address,
    pub src_port: u16,
    pub dst_port: u16,
    /// IPv4 TTL / IPv6 hop limit of the outer header.
    pub hop_limit: Option<u8>,
    /// Absolute frame offset where the IP payload ends on the wire, from the
    /// IP length field. May exceed the captured length (snaplen truncation).
    pub ip_end: Option<usize>,
    pub transport: Option<TransportInfo>,
    pub malformed: bool,
    pub event: Option<AppEvent>,
}

impl Summary {
    pub fn path(&self) -> impl Iterator<Item = ProtocolId> + '_ {
        self.path[..usize::from(self.path_len)].iter().filter_map(|b| ProtocolId::from_u8(*b))
    }

    /// Source column: network address, falling back to the link-layer address.
    pub fn src(&self) -> Address {
        if self.net_src.is_none() { self.l2_src } else { self.net_src }
    }

    pub fn dst(&self) -> Address {
        if self.net_dst.is_none() { self.l2_dst } else { self.net_dst }
    }
}

/// Info column builder with layering: higher layers replace
/// lower-layer text, multiple messages of one layer are appended.
#[derive(Debug, Default)]
pub struct Info {
    enabled: bool,
    text: String,
    owner: Option<ProtocolId>,
}

impl Info {
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Replaces the info text on behalf of `owner`.
    pub fn set(&mut self, owner: ProtocolId, text: impl FnOnce() -> String) {
        if self.enabled {
            self.text = text();
            self.owner = Some(owner);
        }
    }

    /// Appends with ", " if `owner` already wrote text, otherwise replaces.
    pub fn append(&mut self, owner: ProtocolId, text: impl FnOnce() -> String) {
        if !self.enabled {
            return;
        }
        if self.owner == Some(owner) && !self.text.is_empty() {
            self.text.push_str(", ");
            self.text.push_str(&text());
        } else {
            self.text = text();
            self.owner = Some(owner);
        }
    }

    pub fn prefix(&mut self, p: &str) {
        if self.enabled {
            self.text.insert_str(0, p);
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn into_string(self) -> String {
        self.text
    }
}

/// State threaded through all dissectors for one frame.
pub struct Ctx<'f> {
    pub opts: DissectOptions,
    pub frame: &'f FrameContext,
    pub summary: Summary,
    pub tree: Tree,
    pub info: Info,
    /// The payload is knowingly incomplete (snaplen cut, first IP fragment):
    /// an application layer running out of bytes is not malformed.
    pub incomplete: bool,
}

impl<'f> Ctx<'f> {
    pub fn new(frame: &'f FrameContext, opts: DissectOptions) -> Self {
        Ctx {
            opts,
            frame,
            summary: Summary::default(),
            tree: Tree::new(opts.tree),
            info: Info { enabled: opts.info, ..Info::default() },
            incomplete: frame.caplen < frame.origlen,
        }
    }

    /// Records that `p` is present; non-data protocols become the top layer.
    pub fn push_protocol(&mut self, p: ProtocolId) {
        self.summary.protocols.insert(p);
        if !matches!(p, ProtocolId::Data | ProtocolId::Malformed) {
            self.summary.top = Some(p);
        }
        let len = usize::from(self.summary.path_len);
        if len < MAX_PATH {
            self.summary.path[len] = p as u8;
            self.summary.path_len += 1;
        }
    }

    pub fn event(&mut self, kind: TimelineKind, label: impl FnOnce() -> String) {
        if self.opts.events && self.summary.event.is_none() {
            self.summary.event = Some(AppEvent { kind, label: label(), name: None });
        }
    }
}

/// A layer could not be parsed. The driver records it as `[Malformed]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed {
    pub protocol: ProtocolId,
    pub offset: usize,
    /// The layer ran out of bytes (as opposed to holding invalid values).
    pub truncated: bool,
}

impl Malformed {
    pub fn at(protocol: ProtocolId, offset: usize) -> Self {
        Malformed { protocol, offset, truncated: false }
    }
}

/// Lets dissectors use `?` on cursor reads: `c.be_u16().map_err(m(ProtocolId::Tcp))?`.
pub fn m(protocol: ProtocolId) -> impl Fn(Truncated) -> Malformed {
    move |t| Malformed { protocol, offset: t.offset, truncated: true }
}
