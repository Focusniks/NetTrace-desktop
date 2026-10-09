//! Time series and distributions computed on demand from the packet index.

use nettrace_flow::FlowTable;
use nettrace_model::{IoGraph, LengthBucket, PacketLengths, StreamRef, Timeline, TimelineEvent, TimelineKind, Transport};
use nettrace_storage::PacketMeta;

use crate::accum::Event;

pub const MAX_BUCKETS: usize = 20_000;

/// Packets/bytes per interval over `[base_ns, end_ns]`.
/// The interval is widened if it would produce more than [`MAX_BUCKETS`].
pub fn io_graph(
    metas: &[PacketMeta],
    selection: impl Iterator<Item = u32>,
    base_ns: i64,
    end_ns: i64,
    interval_ns: i64,
) -> IoGraph {
    let span = end_ns.saturating_sub(base_ns).max(0);
    let mut interval = interval_ns.max(1_000);
    if span / interval >= MAX_BUCKETS as i64 {
        interval = span / (MAX_BUCKETS as i64 - 1) + 1;
    }
    let n = (span / interval) as usize + 1;
    let mut packets = vec![0u64; n];
    let mut bytes = vec![0u64; n];
    let mut matched = 0;
    for i in selection {
        let Some(m) = metas.get(i as usize) else { continue };
        let b = (m.ts_ns.saturating_sub(base_ns).max(0) / interval) as usize;
        if b < n {
            packets[b] += 1;
            bytes[b] += u64::from(m.origlen);
            matched += 1;
        }
    }
    IoGraph { interval: interval as f64 / 1e9, start: 0.0, packets, bytes, matched_packets: matched }
}

const LENGTH_BOUNDS: [(u32, Option<u32>); 10] = [
    (0, Some(19)),
    (20, Some(39)),
    (40, Some(79)),
    (80, Some(159)),
    (160, Some(319)),
    (320, Some(639)),
    (640, Some(1279)),
    (1280, Some(2559)),
    (2560, Some(5119)),
    (5120, None),
];

/// Packet length distribution in power-of-two buckets (20–39, 40–79, …).
pub fn packet_lengths(metas: &[PacketMeta], selection: impl Iterator<Item = u32>) -> PacketLengths {
    #[derive(Default, Clone, Copy)]
    struct Acc {
        count: u64,
        sum: u64,
        min: Option<u32>,
        max: Option<u32>,
    }
    let mut buckets = [Acc::default(); 10];
    let mut total = Acc::default();
    for i in selection {
        let Some(m) = metas.get(i as usize) else { continue };
        let len = m.origlen;
        let b = LENGTH_BOUNDS.iter().position(|(_, hi)| hi.is_none_or(|h| len <= h)).unwrap_or(9);
        for a in [&mut buckets[b], &mut total] {
            a.count += 1;
            a.sum += u64::from(len);
            a.min = Some(a.min.map_or(len, |x| x.min(len)));
            a.max = Some(a.max.map_or(len, |x| x.max(len)));
        }
    }
    let avg = |a: &Acc| (a.count > 0).then(|| a.sum as f64 / a.count as f64);
    PacketLengths {
        buckets: LENGTH_BOUNDS
            .iter()
            .zip(buckets.iter())
            .map(|((lo, hi), a)| LengthBucket { min: *lo, max: *hi, count: a.count, min_seen: a.min, max_seen: a.max, avg: avg(a) })
            .collect(),
        total: total.count,
        min: total.min,
        max: total.max,
        avg: avg(&total),
    }
}

/// Activity lanes for the timeline over `[start_ns, end_ns]` (absolute ns).
#[allow(clippy::too_many_arguments)]
pub fn timeline(
    metas: &[PacketMeta],
    flows: &FlowTable,
    events: &[Event],
    base_ns: i64,
    start_ns: i64,
    end_ns: i64,
    buckets: usize,
    max_events: usize,
) -> Timeline {
    let buckets = buckets.clamp(1, MAX_BUCKETS);
    let span = end_ns.saturating_sub(start_ns).max(1);
    let width = (span as f64 / buckets as f64).max(1.0);
    let slot = |ts: i64| -> Option<usize> {
        if ts < start_ns || ts > end_ns {
            return None;
        }
        Some(((ts.saturating_sub(start_ns) as f64 / width) as usize).min(buckets - 1))
    };
    let mut t = Timeline {
        start: start_ns.saturating_sub(base_ns) as f64 / 1e9,
        end: end_ns.saturating_sub(base_ns) as f64 / 1e9,
        bucket: width / 1e9,
        packets: vec![0; buckets],
        bytes: vec![0; buckets],
        tcp_open: vec![0; buckets],
        tcp_active: vec![0; buckets],
        dns: vec![0; buckets],
        tls: vec![0; buckets],
        http: vec![0; buckets],
        events: Vec::new(),
        events_truncated: false,
    };
    for m in metas {
        if let Some(b) = slot(m.ts_ns) {
            t.packets[b] += 1;
            t.bytes[b] += u64::from(m.origlen);
        }
    }
    let rel = |ts: i64| ts.saturating_sub(base_ns) as f64 / 1e9;
    let mut list: Vec<(i64, TimelineEvent)> = Vec::new();
    let mut active = vec![0i64; buckets + 1];
    for f in flows.flows() {
        if f.transport != Transport::Tcp {
            continue;
        }
        let stream = Some(StreamRef { kind: Transport::Tcp, id: f.stream_id });
        if f.last_ts_ns >= start_ns && f.first_ts_ns <= end_ns {
            let a = slot(f.first_ts_ns.max(start_ns)).unwrap_or(0);
            let b = slot(f.last_ts_ns.min(end_ns)).unwrap_or(buckets - 1);
            active[a] += 1;
            active[b + 1] -= 1;
        }
        let endpoints = format!("{}:{} → {}:{}", f.client.0, f.client.1, f.server.0, f.server.1);
        if let Some(b) = slot(f.first_ts_ns) {
            t.tcp_open[b] += 1;
            list.push((f.first_ts_ns, TimelineEvent {
                kind: TimelineKind::TcpOpen,
                number: f.first_packet() + 1,
                time_rel: rel(f.first_ts_ns),
                label: endpoints.clone(),
                stream,
            }));
        }
        if let Some(tcp) = f.tcp.as_deref() {
            let closing = tcp.first_rst.map(|p| (p, TimelineKind::TcpReset)).or_else(|| {
                match (tcp.fin[0], tcp.fin[1]) {
                    (Some(a), Some(b)) => Some((a.max(b), TimelineKind::TcpClose)),
                    _ => None,
                }
            });
            if let Some((packet, kind)) = closing {
                if let Some(m) = metas.get(packet as usize) {
                    if slot(m.ts_ns).is_some() {
                        list.push((m.ts_ns, TimelineEvent { kind, number: packet + 1, time_rel: rel(m.ts_ns), label: endpoints, stream }));
                    }
                }
            }
        }
    }
    let mut running = 0i64;
    for (i, v) in t.tcp_active.iter_mut().enumerate() {
        running += active[i];
        *v = running.max(0) as u32;
    }
    for e in events {
        let Some(b) = slot(e.ts_ns) else { continue };
        match e.kind {
            TimelineKind::DnsQuery | TimelineKind::DnsResponse => t.dns[b] += 1,
            TimelineKind::TlsClientHello | TimelineKind::TlsServerHello => t.tls[b] += 1,
            TimelineKind::HttpRequest | TimelineKind::HttpResponse => t.http[b] += 1,
            _ => {}
        }
        let stream = e.flow.and_then(|f| flows.flow(f)).map(|f| StreamRef { kind: f.transport, id: f.stream_id });
        list.push((e.ts_ns, TimelineEvent { kind: e.kind, number: e.packet + 1, time_rel: rel(e.ts_ns), label: e.label.clone(), stream }));
    }
    list.sort_by_key(|(ts, e)| (*ts, e.number));
    if list.len() > max_events {
        t.events_truncated = true;
        list.truncate(max_events);
    }
    t.events = list.into_iter().map(|(_, e)| e).collect();
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use nettrace_storage::NONE;

    fn meta(ts_ns: i64, len: u32) -> PacketMeta {
        PacketMeta {
            offset: 0,
            ts_ns,
            caplen: len,
            origlen: len,
            protocols: 0,
            src: NONE,
            dst: NONE,
            l2_src: NONE,
            l2_dst: NONE,
            flow: NONE,
            sport: 0,
            dport: 0,
            analysis: 0,
            tcp_flags: 0,
            interface: 0,
            top: 0,
            status: 0,
        }
    }

    #[test]
    fn io_graph_buckets() {
        let metas = vec![meta(0, 100), meta(500_000_000, 50), meta(1_200_000_000, 10)];
        let g = io_graph(&metas, 0..3, 0, 1_200_000_000, 1_000_000_000);
        assert_eq!(g.packets, vec![2, 1]);
        assert_eq!(g.bytes, vec![150, 10]);
        assert_eq!(g.matched_packets, 3);
        let g = io_graph(&metas, [1u32].into_iter(), 0, 1_200_000_000, 1_000_000_000);
        assert_eq!(g.packets, vec![1, 0]);
        // Tiny interval over a long span is widened.
        let g = io_graph(&metas, 0..3, 0, 1_000_000_000_000, 1_000);
        assert!(g.packets.len() <= MAX_BUCKETS);
    }

    #[test]
    fn length_distribution() {
        let metas = vec![meta(0, 60), meta(0, 60), meta(0, 1514), meta(0, 9000)];
        let l = packet_lengths(&metas, 0..4);
        assert_eq!(l.total, 4);
        assert_eq!(l.buckets[2].count, 2);
        assert_eq!(l.buckets[7].count, 1);
        assert_eq!(l.buckets[9].count, 1);
        assert_eq!((l.min, l.max), (Some(60), Some(9000)));
    }

    #[test]
    fn timeline_packets_and_events() {
        let metas = vec![meta(0, 100), meta(5, 100), meta(10, 100)];
        let events = vec![Event { kind: TimelineKind::DnsQuery, packet: 1, ts_ns: 5, label: "A x".into(), flow: None }];
        let t = timeline(&metas, &FlowTable::new(), &events, 0, 0, 10, 2, 100);
        assert_eq!(t.packets, vec![1, 2]);
        assert_eq!(t.dns, vec![0, 1]);
        assert_eq!(t.events.len(), 1);
        assert_eq!(t.events[0].number, 2);
        let t = timeline(&metas, &FlowTable::new(), &events, 0, 0, 10, 2, 0);
        assert!(t.events_truncated && t.events.is_empty());
    }
}
