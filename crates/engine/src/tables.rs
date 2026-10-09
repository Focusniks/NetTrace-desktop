//! Statistics tables (hosts, conversations) served page by page: the backend
//! filters and sorts row ids and builds UI rows only for the requested slice,
//! so millions of hosts or connections never cross the IPC boundary at once.

use std::cmp::Ordering;
use std::fmt::Write;

use nettrace_analysis::{conversation_row, host_row};
use nettrace_flow::Flow;
use nettrace_model::{ConversationKind, ConversationPage, ConversationRow, HostPage, StreamRef, Transport};
use rayon::slice::ParallelSliceMut;
use serde::Deserialize;

use crate::session::Shared;

/// Rows per request; the UI asks for the visible pages only.
pub const MAX_TABLE_ROWS: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostSort {
    Address,
    Mac,
    Packets,
    Bytes,
    Tx,
    Rx,
    First,
    Last,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostQuery {
    pub sort: HostSort,
    #[serde(default)]
    pub desc: bool,
    pub offset: u32,
    pub limit: u32,
    /// Substring of the address or MAC.
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConversationSort {
    A,
    B,
    Packets,
    Bytes,
    Ab,
    Ba,
    Start,
    Duration,
    State,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationQuery {
    pub kind: ConversationKind,
    pub sort: ConversationSort,
    #[serde(default)]
    pub desc: bool,
    pub offset: u32,
    pub limit: u32,
    /// Substring of either endpoint ("addr" or "addr:port").
    #[serde(default)]
    pub search: Option<String>,
}

/// Normalized search needle (None when empty).
pub(crate) fn needle(search: Option<&str>) -> Option<String> {
    let s = search?.trim();
    (!s.is_empty()).then(|| s.to_lowercase())
}

/// Ids `0..n` that pass `keep`, sorted by `cmp` (ties by id, so pages are stable).
pub(crate) fn sorted_ids(n: usize, mut keep: impl FnMut(u32) -> bool, cmp: impl Fn(u32, u32) -> Ordering + Sync, desc: bool) -> Vec<u32> {
    let mut ids: Vec<u32> = (0..n as u32).filter(|&i| keep(i)).collect();
    ids.par_sort_unstable_by(|&a, &b| {
        let o = cmp(a, b).then(a.cmp(&b));
        if desc { o.reverse() } else { o }
    });
    ids
}

/// Reusable lowercase text buffer for substring search over many entries.
pub(crate) struct Matcher {
    needle: Option<String>,
    buf: String,
}

impl Matcher {
    pub fn new(search: Option<&str>) -> Self {
        Matcher { needle: needle(search), buf: String::new() }
    }

    pub fn key(&self) -> &str {
        self.needle.as_deref().unwrap_or("")
    }

    /// True when there is no needle or the text written by `write` contains it.
    pub fn matches(&mut self, write: impl FnOnce(&mut String)) -> bool {
        let Some(n) = &self.needle else { return true };
        self.buf.clear();
        write(&mut self.buf);
        self.buf.make_ascii_lowercase();
        self.buf.contains(n.as_str())
    }
}

fn page<T>(order: &[u32], offset: u32, limit: u32, row: impl Fn(u32) -> T) -> Vec<T> {
    order.iter().skip(offset as usize).take(limit.min(MAX_TABLE_ROWS) as usize).map(|&i| row(i)).collect()
}

pub(crate) fn hosts_key(q: &HostQuery) -> String {
    format!("hosts|{:?}|{}|{}", q.sort, q.desc, Matcher::new(q.search.as_deref()).key())
}

pub(crate) fn host_order(sh: &Shared, q: &HostQuery) -> Vec<u32> {
    let hosts = sh.acc.hosts.entries();
    let addrs = &sh.index.addrs;
    let mut m = Matcher::new(q.search.as_deref());
    let keep = |i: u32| {
        let h = &hosts[i as usize];
        m.matches(|b| {
            let _ = write!(b, "{} ", addrs.get(h.addr));
            if h.mac != nettrace_storage::NONE {
                let _ = write!(b, "{}", addrs.get(h.mac));
            }
        })
    };
    let cmp = |a: u32, b: u32| {
        let (x, y) = (&hosts[a as usize], &hosts[b as usize]);
        match q.sort {
            HostSort::Address => addrs.get(x.addr).cmp(&addrs.get(y.addr)),
            HostSort::Mac => addrs.get(x.mac).cmp(&addrs.get(y.mac)),
            HostSort::Packets => (u64::from(x.tx_packets) + u64::from(x.rx_packets)).cmp(&(u64::from(y.tx_packets) + u64::from(y.rx_packets))),
            HostSort::Bytes => (x.tx_bytes + x.rx_bytes).cmp(&(y.tx_bytes + y.rx_bytes)),
            HostSort::Tx => x.tx_bytes.cmp(&y.tx_bytes),
            HostSort::Rx => x.rx_bytes.cmp(&y.rx_bytes),
            HostSort::First => x.first_ns.cmp(&y.first_ns),
            HostSort::Last => x.last_ns.cmp(&y.last_ns),
        }
    };
    sorted_ids(hosts.len(), keep, cmp, q.desc)
}

pub(crate) fn host_page(sh: &Shared, order: &[u32], q: &HostQuery) -> HostPage {
    let base = sh.index.first_ts().unwrap_or(0);
    let hosts = sh.acc.hosts.entries();
    HostPage {
        total: order.len() as u32,
        offset: q.offset,
        rows: page(order, q.offset, q.limit, |i| host_row(&hosts[i as usize], &sh.index.addrs, base)),
    }
}

fn transport(kind: ConversationKind) -> Option<Transport> {
    match kind {
        ConversationKind::Tcp => Some(Transport::Tcp),
        ConversationKind::Udp => Some(Transport::Udp),
        _ => None,
    }
}

pub(crate) fn conversations_key(q: &ConversationQuery) -> String {
    format!("conv|{:?}|{:?}|{}|{}", q.kind, q.sort, q.desc, Matcher::new(q.search.as_deref()).key())
}

pub(crate) fn conversation_order(sh: &Shared, q: &ConversationQuery) -> Vec<u32> {
    let mut m = Matcher::new(q.search.as_deref());
    match transport(q.kind) {
        Some(t) => {
            let flows = sh.flows.flows();
            let keep = |i: u32| {
                let f = &flows[i as usize];
                f.transport == t
                    && m.matches(|b| {
                        let _ = write!(b, "{}:{} {}:{}", f.client.0, f.client.1, f.server.0, f.server.1);
                    })
            };
            let cmp = |a: u32, b: u32| flow_cmp(&flows[a as usize], &flows[b as usize], q.sort);
            sorted_ids(flows.len(), keep, cmp, q.desc)
        }
        None => {
            let convs = sh.acc.conversations(q.kind).entries();
            let addrs = &sh.index.addrs;
            let keep = |i: u32| {
                let c = &convs[i as usize];
                m.matches(|b| {
                    let _ = write!(b, "{} {}", addrs.get(c.a), addrs.get(c.b));
                })
            };
            let cmp = |a: u32, b: u32| {
                let (x, y) = (&convs[a as usize], &convs[b as usize]);
                match q.sort {
                    ConversationSort::A => addrs.get(x.a).cmp(&addrs.get(y.a)),
                    ConversationSort::B => addrs.get(x.b).cmp(&addrs.get(y.b)),
                    ConversationSort::Packets => (u64::from(x.a_to_b_packets) + u64::from(x.b_to_a_packets))
                        .cmp(&(u64::from(y.a_to_b_packets) + u64::from(y.b_to_a_packets))),
                    ConversationSort::Bytes => (x.a_to_b_bytes + x.b_to_a_bytes).cmp(&(y.a_to_b_bytes + y.b_to_a_bytes)),
                    ConversationSort::Ab => x.a_to_b_bytes.cmp(&y.a_to_b_bytes),
                    ConversationSort::Ba => x.b_to_a_bytes.cmp(&y.b_to_a_bytes),
                    ConversationSort::Start => x.first_ns.cmp(&y.first_ns),
                    ConversationSort::Duration => x.last_ns.saturating_sub(x.first_ns).cmp(&y.last_ns.saturating_sub(y.first_ns)),
                    ConversationSort::State => Ordering::Equal,
                }
            };
            sorted_ids(convs.len(), keep, cmp, q.desc)
        }
    }
}

fn flow_cmp(x: &Flow, y: &Flow, sort: ConversationSort) -> Ordering {
    let state = |f: &Flow| f.tcp.as_deref().map(|t| tcp_state_code(t.state()));
    match sort {
        ConversationSort::A => x.client.cmp(&y.client),
        ConversationSort::B => x.server.cmp(&y.server),
        ConversationSort::Packets => x.packet_count().cmp(&y.packet_count()),
        ConversationSort::Bytes => x.total_bytes().cmp(&y.total_bytes()),
        ConversationSort::Ab => x.c2s.bytes.cmp(&y.c2s.bytes),
        ConversationSort::Ba => x.s2c.bytes.cmp(&y.s2c.bytes),
        ConversationSort::Start => x.first_ts_ns.cmp(&y.first_ts_ns),
        ConversationSort::Duration => x.duration_ns().cmp(&y.duration_ns()),
        ConversationSort::State => state(x).cmp(&state(y)),
    }
}

pub(crate) fn conversation_page(sh: &Shared, order: &[u32], q: &ConversationQuery) -> ConversationPage {
    let base = sh.index.first_ts().unwrap_or(0);
    let rows = match transport(q.kind) {
        Some(_) => page(order, q.offset, q.limit, |i| flow_row(q.kind, &sh.flows.flows()[i as usize], base)),
        None => {
            let convs = sh.acc.conversations(q.kind).entries();
            page(order, q.offset, q.limit, |i| conversation_row(q.kind, &convs[i as usize], &sh.index.addrs, base))
        }
    };
    ConversationPage { total: order.len() as u32, offset: q.offset, rows }
}

fn flow_row(kind: ConversationKind, f: &Flow, base: i64) -> ConversationRow {
    ConversationRow {
        kind,
        a: f.client.0.to_string(),
        a_port: Some(f.client.1),
        b: f.server.0.to_string(),
        b_port: Some(f.server.1),
        packets: u64::from(f.packet_count()),
        bytes: f.total_bytes(),
        a_to_b_packets: u64::from(f.c2s.packets),
        a_to_b_bytes: f.c2s.bytes,
        b_to_a_packets: u64::from(f.s2c.packets),
        b_to_a_bytes: f.s2c.bytes,
        start: f.first_ts_ns.saturating_sub(base) as f64 / 1e9,
        duration: f.duration_ns() as f64 / 1e9,
        state: f.tcp.as_deref().map(|t| tcp_state_code(t.state()).to_owned()),
        stream: Some(StreamRef { kind: f.transport, id: f.stream_id }),
        filter: f.filter(),
    }
}

/// `TcpState` as its serde string (snake_case).
pub(crate) fn tcp_state_code(state: nettrace_model::TcpState) -> &'static str {
    use nettrace_model::TcpState::*;
    match state {
        SynSent => "syn_sent",
        SynReceived => "syn_received",
        Established => "established",
        Closing => "closing",
        Closed => "closed",
        Reset => "reset",
        Refused => "refused",
        Midstream => "midstream",
    }
}
