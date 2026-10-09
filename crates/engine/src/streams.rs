//! Stream (flow) listing, details and the sequence (ladder) diagram.

use std::fmt::Write;

use nettrace_flow::Flow;
use nettrace_model::{Direction, FlowPage, ProtocolId, SequenceEntry, SequencePage, Transport};
use nettrace_protocol::{dissect, tcp_flags_string, DissectOptions};
use nettrace_storage::CaptureFile;
use serde::Deserialize;

use crate::error::Result;
use crate::frame::frame_context;
use crate::view::read_error;
use crate::session::Shared;
use crate::tables::{sorted_ids, Matcher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FlowSort {
    Id,
    Packets,
    Bytes,
    Start,
    Duration,
    Retransmissions,
    Rtt,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowQuery {
    pub kind: Option<Transport>,
    pub sort: FlowSort,
    #[serde(default)]
    pub desc: bool,
    pub offset: u32,
    pub limit: u32,
    /// Substring matched against "addr:port" of both endpoints and the protocol.
    #[serde(default)]
    pub search: Option<String>,
}

fn sort_key(f: &Flow, sort: FlowSort) -> (i128, u32) {
    let k: i128 = match sort {
        FlowSort::Id => i128::from(f.stream_id),
        FlowSort::Packets => i128::from(f.packet_count()),
        FlowSort::Bytes => i128::from(f.total_bytes()),
        FlowSort::Start => i128::from(f.first_ts_ns),
        FlowSort::Duration => i128::from(f.duration_ns()),
        FlowSort::Retransmissions => f.tcp.as_deref().map_or(0, |t| i128::from(t.retransmissions)),
        FlowSort::Rtt => f.tcp.as_deref().and_then(|t| t.rtt_avg_ns()).map_or(-1, i128::from),
    };
    (k, f.stream_id)
}

pub(crate) fn flows_key(q: &FlowQuery) -> String {
    format!("flows|{:?}|{:?}|{}|{}", q.kind, q.sort, q.desc, Matcher::new(q.search.as_deref()).key())
}

/// Flow indices matching `q`, sorted.
pub(crate) fn flow_order(sh: &Shared, q: &FlowQuery) -> Vec<u32> {
    let flows = sh.flows.flows();
    let mut m = Matcher::new(q.search.as_deref());
    let keep = |i: u32| {
        let f = &flows[i as usize];
        q.kind.is_none_or(|k| f.transport == k)
            && m.matches(|b| {
                let app = f.app.map(|p| p.short_name()).unwrap_or("");
                let _ = write!(b, "{}:{} {}:{} {app}", f.client.0, f.client.1, f.server.0, f.server.1);
            })
    };
    let cmp = |a: u32, b: u32| {
        let (x, y) = (&flows[a as usize], &flows[b as usize]);
        // Stream ids are numbered per transport, so only the id order groups by it;
        // any other key ranks TCP and UDP flows together.
        match q.sort {
            FlowSort::Id => (x.transport, sort_key(x, q.sort)).cmp(&(y.transport, sort_key(y, q.sort))),
            _ => sort_key(x, q.sort).cmp(&sort_key(y, q.sort)).then(x.transport.cmp(&y.transport)),
        }
    };
    sorted_ids(flows.len(), keep, cmp, q.desc)
}

pub(crate) fn flow_page(sh: &Shared, order: &[u32], q: &FlowQuery) -> FlowPage {
    let base = sh.index.first_ts().unwrap_or(0);
    let flows = sh.flows.flows();
    let page = order.iter().skip(q.offset as usize).take(q.limit.min(5000) as usize);
    FlowPage { total: order.len() as u32, offset: q.offset, flows: page.map(|&i| flows[i as usize].summary(base)).collect() }
}

/// One page of the ladder diagram. `from` is a known (offset, packet) of the
/// flow's chain at or before `offset` (the first packet otherwise); the result
/// also tells where the page ended, for the next one.
pub fn sequence(
    sh: &Shared,
    file: &CaptureFile,
    flow: &Flow,
    offset: u32,
    limit: u32,
    from: (u32, u32),
) -> Result<(SequencePage, Option<(u32, u32)>)> {
    let total = flow.packet_count();
    let mut entries = Vec::new();
    let mut buf = Vec::new();
    let tcp = flow.tcp.as_deref();
    let mut last = None;
    let packets = sh.index.flow_packets(from.1).skip(offset.saturating_sub(from.0) as usize);
    for (n, index) in packets.take(limit.min(5000) as usize).enumerate() {
        last = Some((offset + n as u32, index));
        let Some(m) = sh.index.get(index) else { continue };
        file.read_into(m.offset, m.caplen, &mut buf).map_err(|e| read_error(index, &e))?;
        let fctx = frame_context(sh, index);
        let d = dissect(&buf, &fctx, DissectOptions::ROW);
        let direction = if m.reverse() { Direction::S2c } else { Direction::C2s };
        let top = ProtocolId::from_u8(m.top);
        let app = top.is_some_and(|p| !matches!(p, ProtocolId::Tcp | ProtocolId::Udp));
        let (seq, ack, len, window, flags) = match (flow.transport, &d.summary.transport) {
            (Transport::Tcp, Some(nettrace_protocol::TransportInfo::Tcp(t))) => {
                let (d_i, r_i) = if m.reverse() { (1, 0) } else { (0, 1) };
                let rel = |raw: u32, dir: usize| tcp.and_then(|t| t.dirs[dir].base_seq).map_or(raw, |b| raw.wrapping_sub(b));
                let has_ack = t.flags & 0x010 != 0;
                (Some(rel(t.seq, d_i)), has_ack.then(|| rel(t.ack, r_i)), t.payload_len, Some(u32::from(t.window)), Some(tcp_flags_string(t.flags)))
            }
            (_, Some(nettrace_protocol::TransportInfo::Udp { payload_len })) => (None, None, *payload_len, None, None),
            _ => (None, None, 0, None, None),
        };
        let label = if app {
            d.info.clone()
        } else if let Some(fl) = &flags {
            if len > 0 { format!("{fl} · Len={len}") } else { fl.clone() }
        } else {
            format!("Len={len}")
        };
        entries.push(SequenceEntry {
            number: index + 1,
            time_rel: m.ts_ns.saturating_sub(sh.index.first_ts().unwrap_or(m.ts_ns)) as f64 / 1e9,
            time_stream: m.ts_ns.saturating_sub(flow.first_ts_ns) as f64 / 1e9,
            direction,
            label,
            tcp_flags: flags,
            seq,
            ack,
            len,
            window,
            analysis: m.analysis,
        });
    }
    Ok((SequencePage { total, offset, entries }, last))
}
