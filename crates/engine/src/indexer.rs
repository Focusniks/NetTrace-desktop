//! Background indexing: one sequential pass over the file.
//!
//! Dissection (the expensive part) runs without any lock; parsed summaries are
//! applied to the shared index in batches under a short write lock, so the UI
//! can read partial results while indexing continues.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nettrace_analysis::PacketFacts;
use nettrace_capture::{CaptureError, PacketSource, RecordMeta};
use nettrace_flow::{Dir, FlowKind, FlowPacket, TcpSegment};
use nettrace_model::{IndexProgress, IndexState, ProtocolId};
use nettrace_protocol::{dissect, DissectOptions, FrameContext, Summary, TransportInfo};
use nettrace_storage::{status, PacketMeta, NONE};

use crate::session::{Session, Shared};

pub type ProgressFn = Arc<dyn Fn(IndexProgress) + Send + Sync>;

const BATCH: usize = 4096;
const FLUSH_EVERY: Duration = Duration::from_millis(50);
const PROGRESS_EVERY: Duration = Duration::from_millis(100);
const MAX_PACKETS: u32 = u32::MAX - 1;
/// New flows beyond this are not tracked (packets stay in the list without a stream).
const MAX_FLOWS: usize = 8_000_000;

struct Pending {
    rec: RecordMeta,
    summary: Summary,
}

fn is_app(p: ProtocolId) -> bool {
    matches!(p, ProtocolId::Dns | ProtocolId::Dhcp | ProtocolId::Http | ProtocolId::Tls | ProtocolId::Ntp)
}

pub(crate) fn apply(sh: &mut Shared, rec: &RecordMeta, s: &Summary) {
    let index = sh.index.len();
    let src = sh.index.addrs.intern(s.src());
    let dst = sh.index.addrs.intern(s.dst());
    let l2_src = sh.index.addrs.intern(s.l2_src);
    let l2_dst = sh.index.addrs.intern(s.l2_dst);
    let ts_ns = rec.ts.nanos();
    let mut flow = NONE;
    let mut analysis = 0;
    let mut tcp_flags = 0;
    let mut st = if s.malformed { status::MALFORMED } else { 0 };
    let flow_room = sh.flows.flows().len() < MAX_FLOWS;
    if let (Some(t), true) = (s.transport, s.net_src.is_ip()) {
        let kind = match t {
            TransportInfo::Tcp(tcp) => {
                tcp_flags = tcp.flags;
                FlowKind::Tcp(TcpSegment {
                    seq: tcp.seq,
                    ack: tcp.ack,
                    flags: tcp.flags,
                    window: tcp.window,
                    payload_len: tcp.payload_len,
                    wscale: tcp.wscale,
                })
            }
            TransportInfo::Udp { payload_len } => FlowKind::Udp { payload_len },
        };
        let assigned = sh.flows.process_capped(flow_room, &FlowPacket {
            index,
            ts_ns,
            frame_len: rec.origlen,
            src: s.net_src,
            dst: s.net_dst,
            sport: s.src_port,
            dport: s.dst_port,
            kind,
            app: s.top.filter(|p| is_app(*p)),
        });
        match assigned {
            Some(a) => {
                flow = a.flow;
                analysis = a.analysis;
                if a.dir == Dir::ServerToClient {
                    st |= status::REVERSE;
                }
            }
            None => sh.acc.limit_reached = true,
        }
    }
    sh.index.push(PacketMeta {
        offset: rec.offset,
        ts_ns,
        caplen: rec.caplen,
        origlen: rec.origlen,
        protocols: s.protocols.0,
        src,
        dst,
        l2_src,
        l2_dst,
        flow,
        sport: s.src_port,
        dport: s.dst_port,
        analysis,
        tcp_flags,
        interface: rec.interface,
        top: s.top.unwrap_or(ProtocolId::Frame) as u8,
        status: st,
    });
    sh.acc.record(&PacketFacts {
        index,
        ts_ns,
        frame_len: rec.origlen,
        l2_src: s.l2_src,
        l2_dst: s.l2_dst,
        net_src: s.net_src,
        net_dst: s.net_dst,
        protocols: s.protocols,
        path: &s.path[..usize::from(s.path_len)],
        malformed: s.malformed,
        event: s.event.as_ref().map(|e| (e.kind, e.label.as_str(), e.name.as_deref())),
        flow: (flow != NONE).then_some(flow),
    });
}

fn snapshot(session: &Session, state: IndexState, bytes_read: u64, warning: Option<String>, error: Option<String>) -> IndexProgress {
    let sh = session.data.read();
    let live = session.live.as_ref();
    IndexProgress {
        capture_id: session.id,
        state,
        packets: sh.index.len(),
        tcp_streams: sh.flows.tcp_count(),
        udp_streams: sh.flows.udp_count(),
        bytes_read,
        // A live file has no final size; report what was read so far.
        total_bytes: if live.is_some() { bytes_read } else { session.file.size() },
        elapsed_ms: session.started.elapsed().as_millis() as u64,
        warning,
        error: error.or_else(|| live.and_then(|l| l.error.lock().clone())),
        capture: live.map(|l| l.stats.lock().clone()),
    }
}

pub(crate) fn run<S: PacketSource>(session: Arc<Session>, mut reader: S, on_progress: ProgressFn) {
    let live = session.live.is_some();
    let mut buf = Vec::with_capacity(2048);
    let mut pending: Vec<Pending> = Vec::with_capacity(BATCH);
    let mut last_flush = Instant::now();
    let mut last_progress = Instant::now();
    let mut count: u32 = 0;
    let mut link_types_seen = 0usize;

    let flush = |pending: &mut Vec<Pending>, reader: &S, link_types_seen: &mut usize| {
        let mut sh = session.data.write();
        let ifaces = reader.interfaces();
        if ifaces.len() != *link_types_seen {
            sh.index.link_types = ifaces.iter().map(|i| i.link_type).collect();
            sh.interfaces = ifaces
                .iter()
                .map(|i| nettrace_model::InterfaceInfo {
                    link_type: i.link_type.name().to_owned(),
                    name: i.name.clone(),
                    snaplen: i.snaplen,
                })
                .collect();
            *link_types_seen = ifaces.len();
        }
        sh.index.reserve(pending.len());
        for p in pending.drain(..) {
            apply(&mut sh, &p.rec, &p.summary);
        }
    };

    let (state, warning, error) = loop {
        if session.cancel.load(Ordering::Relaxed) {
            break (IndexState::Cancelled, None, None);
        }
        if count >= MAX_PACKETS {
            break (IndexState::Done, Some("too_many_packets".to_owned()), None);
        }
        match reader.next_record(&mut buf) {
            Ok(Some(rec)) => {
                let link = reader.interfaces().get(usize::from(rec.interface)).map(|i| i.link_type);
                let fctx = FrameContext {
                    number: count + 1,
                    ts: rec.ts,
                    caplen: rec.caplen,
                    origlen: rec.origlen,
                    interface: rec.interface,
                    link_type: link,
                    ..FrameContext::default()
                };
                let summary = dissect(&buf, &fctx, DissectOptions::INDEX).summary;
                pending.push(Pending { rec, summary });
                count += 1;
                // Live: every packet becomes visible immediately (the source may go quiet).
                if live || pending.len() >= BATCH || last_flush.elapsed() >= FLUSH_EVERY {
                    flush(&mut pending, &reader, &mut link_types_seen);
                    last_flush = Instant::now();
                }
            }
            Ok(None) => break (IndexState::Done, None, None),
            Err(CaptureError::Truncated { .. }) => break (IndexState::Done, Some("truncated".to_owned()), None),
            Err(e) => break (IndexState::Failed, None, Some(format!("{}: {e}", e.code()))),
        }
        if last_progress.elapsed() >= PROGRESS_EVERY {
            if !pending.is_empty() {
                flush(&mut pending, &reader, &mut link_types_seen);
                last_flush = Instant::now();
            }
            let p = snapshot(&session, IndexState::Indexing, reader.bytes_consumed(), None, None);
            session.set_progress(p.clone());
            on_progress(p);
            last_progress = Instant::now();
        }
    };
    flush(&mut pending, &reader, &mut link_types_seen);
    let warning = warning.or_else(|| session.data.read().acc.limit_reached.then(|| "limit_reached".to_owned()));
    // A capture that stopped because of a driver/disk error is reported as failed.
    let state = match &session.live {
        Some(l) if state == IndexState::Done && l.error.lock().is_some() => IndexState::Failed,
        _ => state,
    };
    let p = snapshot(&session, state, reader.bytes_consumed(), warning, error);
    session.set_progress(p.clone());
    on_progress(p);
}
