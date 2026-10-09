//! Builds the per-frame context (timing + TCP analysis results) passed to dissectors.

use nettrace_flow::Dir;
use nettrace_model::{StreamRef, Transport};
use nettrace_packet::Timestamp;
use nettrace_protocol::{FrameContext, TcpAnnotations};

use crate::session::Shared;

pub fn frame_context(shared: &Shared, index: u32) -> FrameContext {
    let Some(m) = shared.index.get(index) else { return FrameContext::default() };
    let base = shared.index.first_ts().unwrap_or(m.ts_ns);
    let prev = index.checked_sub(1).and_then(|i| shared.index.get(i)).map_or(m.ts_ns, |p| p.ts_ns);
    let mut fctx = FrameContext {
        number: index + 1,
        ts: Timestamp::from_nanos(m.ts_ns),
        time_rel_ns: m.ts_ns.saturating_sub(base),
        time_delta_ns: m.ts_ns.saturating_sub(prev),
        caplen: m.caplen,
        origlen: m.origlen,
        interface: m.interface,
        link_type: Some(shared.index.link_type(m.interface)),
        tcp: None,
        udp_stream: None,
    };
    if let Some(flow) = m.flow().and_then(|f| shared.flows.flow(f)) {
        match (flow.transport, flow.tcp.as_deref()) {
            (Transport::Tcp, Some(tcp)) => {
                let dir = if m.reverse() { Dir::ServerToClient } else { Dir::ClientToServer };
                let rtt = tcp.rtt_for(index);
                fctx.tcp = Some(TcpAnnotations {
                    stream: flow.stream_id,
                    seq_base: tcp.dirs[dir.index()].base_seq,
                    ack_base: tcp.dirs[dir.reverse().index()].base_seq,
                    analysis: m.analysis,
                    ack_rtt_ns: rtt.map(|r| r.rtt_ns),
                    acked_frame: rtt.map(|r| r.acked + 1),
                    window_shift: tcp.window_shift(dir),
                    time_since_first_ns: m.ts_ns.saturating_sub(flow.first_ts_ns),
                });
            }
            (Transport::Udp, _) => fctx.udp_stream = Some(flow.stream_id),
            _ => {}
        }
    }
    fctx
}

pub fn stream_ref(shared: &Shared, index: u32) -> Option<StreamRef> {
    let m = shared.index.get(index)?;
    let flow = shared.flows.flow(m.flow()?)?;
    Some(StreamRef { kind: flow.transport, id: flow.stream_id })
}
