//! Technical indicators: objective observations with counts and a filter to
//! the underlying packets. They state facts ("31 retransmissions"), never
//! conclusions ("attack").

use std::collections::HashMap;

use nettrace_flow::{Flow, FlowTable};
use nettrace_model::{Indicator, IndicatorKind, ProtocolId, Severity, TcpState, Transport};
use nettrace_packet::Address;
use nettrace_storage::{AddressTable, NONE};

use crate::accum::Accumulators;

#[derive(Debug, Clone)]
pub struct IndicatorConfig {
    pub retrans_min_count: u32,
    pub retrans_min_percent: f64,
    pub failed_min_attempts: u32,
    pub many_connections: u32,
    pub many_ports: u32,
    pub many_dns_queries: u32,
    pub large_flow_bytes: u64,
    /// Cap on per-flow indicators of one kind, so huge captures stay readable.
    pub max_per_kind: usize,
}

impl Default for IndicatorConfig {
    fn default() -> Self {
        IndicatorConfig {
            retrans_min_count: 10,
            retrans_min_percent: 2.0,
            failed_min_attempts: 3,
            many_connections: 100,
            many_ports: 50,
            many_dns_queries: 200,
            large_flow_bytes: 50 * 1024 * 1024,
            max_per_kind: 200,
        }
    }
}

/// `ip.addr == x` / `ipv6.addr == x` / `eth.addr == x` depending on the address family.
pub fn addr_filter(addr: &Address, dir: &str) -> String {
    let proto = match addr {
        Address::V4(_) => "ip",
        Address::V6(_) => "ipv6",
        _ => "eth",
    };
    format!("{proto}.{dir} == {addr}")
}

fn standard_port(protocol: ProtocolId, port: u16) -> bool {
    match protocol {
        ProtocolId::Http => matches!(port, 80 | 3128 | 8000 | 8008 | 8080 | 8888),
        ProtocolId::Tls => matches!(port, 443 | 465 | 563 | 636 | 853 | 989 | 990 | 992 | 993 | 995 | 5061 | 8443),
        _ => true,
    }
}

/// A connection attempt (SYN) with interned endpoint ids: 16 bytes per flow,
/// grouped by sorting instead of per-client hash sets.
#[derive(Clone, Copy)]
struct Attempt {
    client: u32,
    server: u32,
    port: u16,
    refused: bool,
    failed: bool,
    first: u32,
}

fn endpoints(f: &Flow) -> String {
    format!("{}:{} → {}:{}", f.client.0, f.client.1, f.server.0, f.server.1)
}

pub fn indicators(flows: &FlowTable, acc: &Accumulators, addrs: &AddressTable, cfg: &IndicatorConfig) -> Vec<Indicator> {
    let mut out = Vec::new();
    let mut retrans = Vec::new();
    let mut zero = Vec::new();
    let mut large = Vec::new();
    let mut reset_streams = 0u32;
    let mut reset_packets = 0u64;
    let mut reset_first: Option<u32> = None;
    let mut attempts: Vec<Attempt> = Vec::new();
    let mut odd_ports: HashMap<(ProtocolId, u16), (u32, u32)> = HashMap::new();
    let id = |a: &Address| addrs.id_of(a).unwrap_or(NONE);

    for f in flows.flows() {
        if let Some(t) = f.tcp.as_deref() {
            let segments = u64::from(f.packet_count());
            let percent = if segments > 0 { f64::from(t.retransmissions) * 100.0 / segments as f64 } else { 0.0 };
            if t.retransmissions >= cfg.retrans_min_count && percent >= cfg.retrans_min_percent {
                retrans.push(Indicator {
                    severity: Severity::Warning,
                    kind: IndicatorKind::TcpRetransmissionRate {
                        stream: f.stream_id,
                        endpoints: endpoints(f),
                        retransmissions: t.retransmissions,
                        segments,
                        percent: (percent * 10.0).round() / 10.0,
                    },
                    filter: format!("{} && tcp.analysis.retransmission", f.filter()),
                    first_packet: Some(f.first_packet() + 1),
                });
            }
            if t.zero_window > 0 {
                zero.push(Indicator {
                    severity: Severity::Note,
                    kind: IndicatorKind::TcpZeroWindow { stream: f.stream_id, endpoints: endpoints(f), count: t.zero_window },
                    filter: format!("{} && tcp.analysis.zero_window", f.filter()),
                    first_packet: Some(f.first_packet() + 1),
                });
            }
            if t.resets > 0 {
                reset_streams += 1;
                reset_packets += u64::from(t.resets);
                if let Some(p) = t.first_rst() {
                    reset_first = Some(reset_first.map_or(p, |x| x.min(p)));
                }
            }
            let state = t.state();
            let failed = matches!(state, TcpState::Refused | TcpState::SynSent);
            if t.syn().is_some() || failed {
                attempts.push(Attempt {
                    client: id(&f.client.0),
                    server: id(&f.server.0),
                    port: f.server.1,
                    refused: state == TcpState::Refused,
                    failed,
                    first: f.first_packet(),
                });
            }
        }
        if let Some(app) = f.app {
            if f.transport == Transport::Tcp && !standard_port(app, f.server.1) {
                let e = odd_ports.entry((app, f.server.1)).or_insert((0, f.first_packet()));
                e.0 += 1;
            }
        }
        if f.c2s.bytes >= cfg.large_flow_bytes || f.s2c.bytes >= cfg.large_flow_bytes {
            large.push(Indicator {
                severity: Severity::Note,
                kind: IndicatorKind::LargeFlow {
                    stream: f.stream_id,
                    kind: if f.transport == Transport::Tcp { "tcp".into() } else { "udp".into() },
                    client: format!("{}:{}", f.client.0, f.client.1),
                    server: format!("{}:{}", f.server.0, f.server.1),
                    client_bytes: f.c2s.bytes,
                    server_bytes: f.s2c.bytes,
                },
                filter: f.filter(),
                first_packet: Some(f.first_packet() + 1),
            });
        }
    }

    if acc.malformed > 0 {
        out.push(Indicator {
            severity: Severity::Warning,
            kind: IndicatorKind::MalformedPackets { count: acc.malformed },
            filter: "_ws.malformed".into(),
            first_packet: None,
        });
    }
    retrans.sort_by(|a, b| match (&a.kind, &b.kind) {
        (IndicatorKind::TcpRetransmissionRate { retransmissions: x, .. }, IndicatorKind::TcpRetransmissionRate { retransmissions: y, .. }) => y.cmp(x),
        _ => std::cmp::Ordering::Equal,
    });
    out.extend(retrans.into_iter().take(cfg.max_per_kind));

    // Failed attempts per (client, server, port).
    attempts.sort_unstable_by_key(|a| (a.client, a.server, a.port, a.first));
    let mut failed = Vec::new();
    for g in attempts.chunk_by(|x, y| (x.client, x.server, x.port) == (y.client, y.server, y.port)) {
        let tries = g.iter().filter(|a| a.failed).count() as u32;
        if tries >= cfg.failed_min_attempts {
            let refused = g.iter().filter(|a| a.failed && a.refused).count() as u32;
            let first = g.iter().filter(|a| a.failed).map(|a| a.first).min().unwrap_or(0);
            failed.push(((addrs.get(g[0].client), addrs.get(g[0].server), g[0].port), (tries, refused, first)));
        }
    }
    failed.sort_by_key(|f| std::cmp::Reverse(f.1 .0));
    for ((client, server, port), (attempts, refused, first)) in failed.into_iter().take(cfg.max_per_kind) {
        out.push(Indicator {
            severity: Severity::Warning,
            kind: IndicatorKind::RepeatedFailedConnections {
                client: client.to_string(),
                server: server.to_string(),
                port,
                attempts,
                refused,
            },
            filter: format!(
                "{} && {} && tcp.dstport == {port} && tcp.flags.syn == 1",
                addr_filter(&client, "src"),
                addr_filter(&server, "dst")
            ),
            first_packet: Some(first + 1),
        });
    }

    if reset_streams > 0 {
        out.push(Indicator {
            severity: Severity::Note,
            kind: IndicatorKind::TcpResets { streams: reset_streams, packets: reset_packets },
            filter: "tcp.flags.reset == 1".into(),
            first_packet: reset_first.map(|p| p + 1),
        });
    }
    out.extend(zero.into_iter().take(cfg.max_per_kind));

    // Connections (SYN), distinct peers and ports per client: groups of the
    // sorted attempts (already ordered by client, server).
    attempts.retain(|a| a.client != NONE);
    let mut busy = Vec::new();
    for g in attempts.chunk_by_mut(|x, y| x.client == y.client) {
        let connections = g.len() as u32;
        let peers = g.chunk_by(|x, y| x.server == y.server).count() as u32;
        let first = g.iter().map(|a| a.first).min().unwrap_or(0);
        g.sort_unstable_by_key(|a| a.port);
        let ports = g.chunk_by(|x, y| x.port == y.port).count() as u32;
        if connections >= cfg.many_connections || ports >= cfg.many_ports {
            busy.push((addrs.get(g[0].client), (connections, peers, ports, first)));
        }
    }
    busy.sort_by_key(|b| std::cmp::Reverse(b.1 .0));
    for (host, (connections, peers, ports, first)) in busy.into_iter().take(cfg.max_per_kind) {
        out.push(Indicator {
            severity: Severity::Note,
            kind: IndicatorKind::ManyConnections {
                host: host.to_string(),
                connections,
                distinct_peers: peers,
                distinct_ports: ports,
            },
            filter: format!("{} && tcp.flags.syn == 1 && tcp.flags.ack == 0", addr_filter(&host, "src")),
            first_packet: Some(first + 1),
        });
    }

    let mut dns: Vec<_> = acc.dns_by_host.iter().filter(|(_, d)| d.queries >= cfg.many_dns_queries).collect();
    dns.sort_by_key(|d| std::cmp::Reverse(d.1.queries));
    for (host, d) in dns.into_iter().take(cfg.max_per_kind) {
        out.push(Indicator {
            severity: Severity::Note,
            kind: IndicatorKind::ManyDnsQueries { host: host.to_string(), queries: d.queries, distinct_names: d.names.len() as u32 },
            filter: format!("dns && dns.flags.response == 0 && {}", addr_filter(host, "src")),
            first_packet: None,
        });
    }

    large.sort_by(|a, b| match (&a.kind, &b.kind) {
        (IndicatorKind::LargeFlow { client_bytes: x, server_bytes: xs, .. }, IndicatorKind::LargeFlow { client_bytes: y, server_bytes: ys, .. }) => {
            (y + ys).cmp(&(x + xs))
        }
        _ => std::cmp::Ordering::Equal,
    });
    out.extend(large.into_iter().take(cfg.max_per_kind));

    let mut odd: Vec<_> = odd_ports.into_iter().collect();
    odd.sort_by_key(|((p, port), _)| (*p as u8, *port));
    for ((protocol, port), (streams, first)) in odd {
        out.push(Indicator {
            severity: Severity::Note,
            kind: IndicatorKind::NonStandardPort { protocol: protocol.short_name().into(), port, streams },
            filter: format!("{} && tcp.port == {port}", protocol.filter_name()),
            first_packet: Some(first + 1),
        });
    }
    out
}
