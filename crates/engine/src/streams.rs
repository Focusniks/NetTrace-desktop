//! Stream (flow) listing, details and the sequence (ladder) diagram.

use nettrace_flow::Flow;
use nettrace_model::{Direction, FlowPage, ProtocolId, SequenceEntry, SequencePage, Transport};
use nettrace_protocol::{dissect, tcp_flags_string, DissectOptions};
use nettrace_storage::CaptureFile;
use serde::Deserialize;

use crate::error::Result;
use crate::frame::frame_context;
use crate::view::read_error;
use crate::session::Shared;

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
        FlowSort::Packets => f.packets.len() as i128,
        FlowSort::Bytes => i128::from(f.total_bytes()),
        FlowSort::Start => i128::from(f.first_ts_ns),
        FlowSort::Duration => i128::from(f.duration_ns()),
        FlowSort::Retransmissions => f.tcp.as_deref().map_or(0, |t| i128::from(t.retransmissions)),
        FlowSort::Rtt => f.tcp.as_deref().and_then(|t| t.rtt_avg_ns()).map_or(-1, i128::from),
    };
    (k, f.stream_id)
}

pub fn list_flows(sh: &Shared, q: &FlowQuery) -> FlowPage {
    let base = sh.index.first_ts().unwrap_or(0);
    let needle = q.search.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_lowercase);
    let mut list: Vec<&Flow> = sh
        .flows
        .flows()
        .iter()
        .filter(|f| q.kind.is_none_or(|k| f.transport == k))
        .filter(|f| match &needle {
            None => true,
            Some(n) => {
                let text = format!(
                    "{}:{} {}:{} {}",
                    f.client.0,
                    f.client.1,
                    f.server.0,
                    f.server.1,
                    f.app.map(|p| p.short_name()).unwrap_or("")
                )
                .to_lowercase();
                text.contains(n.as_str())
            }
        })
        .collect();
    list.sort_by(|a, b| {
        let ord = (a.transport, sort_key(a, q.sort)).cmp(&(b.transport, sort_key(b, q.sort)));
        let ord = if q.kind.is_some() { sort_key(a, q.sort).cmp(&sort_key(b, q.sort)) } else { ord };
        if q.desc { ord.reverse() } else { ord }
    });
    let total = list.len() as u32;
    let limit = q.limit.min(5000) as usize;
    let flows = list.iter().skip(q.offset as usize).take(limit).map(|f| f.summary(base)).collect();
    FlowPage { total, offset: q.offset, flows }
}

pub fn sequence(sh: &Shared, file: &CaptureFile, flow: &Flow, offset: u32, limit: u32) -> Result<SequencePage> {
    let total = flow.packets.len() as u32;
    let mut entries = Vec::new();
    let mut buf = Vec::new();
    let tcp = flow.tcp.as_deref();
    for &index in flow.packets.iter().skip(offset as usize).take(limit.min(5000) as usize) {
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
    Ok(SequencePage { total, offset, entries })
}
