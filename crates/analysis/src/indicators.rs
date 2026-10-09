//! Technical indicators: objective observations with counts and a filter to
//! the underlying packets. They state facts ("31 retransmissions"), never
//! conclusions ("attack").

use std::collections::{HashMap, HashSet};

use nettrace_flow::FlowTable;
use nettrace_model::{Indicator, IndicatorKind, ProtocolId, Severity, TcpState, Transport};
use nettrace_packet::Address;

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

pub fn indicators(flows: &FlowTable, acc: &Accumulators, cfg: &IndicatorConfig) -> Vec<Indicator> {
    let mut out = Vec::new();
    let mut retrans = Vec::new();
    let mut zero = Vec::new();
    let mut large = Vec::new();
    let mut reset_streams = 0u32;
    let mut reset_packets = 0u64;
    let mut reset_first: Option<u32> = None;
    let mut failed: HashMap<(Address, Address, u16), (u32, u32, u32)> = HashMap::new();
    let mut per_client: HashMap<Address, (u32, HashSet<Address>, HashSet<u16>, u32)> = HashMap::new();
    let mut odd_ports: HashMap<(ProtocolId, u16), (u32, u32)> = HashMap::new();

    for f in flows.flows() {
        let endpoints = format!("{}:{} → {}:{}", f.client.0, f.client.1, f.server.0, f.server.1);
        let filter = f.filter();
        if let Some(t) = f.tcp.as_deref() {
            let segments = f.packets.len() as u64;
            let percent = if segments > 0 { f64::from(t.retransmissions) * 100.0 / segments as f64 } else { 0.0 };
            if t.retransmissions >= cfg.retrans_min_count && percent >= cfg.retrans_min_percent {
                retrans.push(Indicator {
                    severity: Severity::Warning,
                    kind: IndicatorKind::TcpRetransmissionRate {
                        stream: f.stream_id,
                        endpoints: endpoints.clone(),
                        retransmissions: t.retransmissions,
                        segments,
                        percent: (percent * 10.0).round() / 10.0,
                    },
                    filter: format!("{filter} && tcp.analysis.retransmission"),
                    first_packet: Some(f.first_packet() + 1),
                });
            }
            if t.zero_window > 0 {
                zero.push(Indicator {
                    severity: Severity::Note,
                    kind: IndicatorKind::TcpZeroWindow { stream: f.stream_id, endpoints: endpoints.clone(), count: t.zero_window },
                    filter: format!("{filter} && tcp.analysis.zero_window"),
                    first_packet: Some(f.first_packet() + 1),
                });
            }
            if t.resets > 0 {
                reset_streams += 1;
                reset_packets += u64::from(t.resets);
                if let Some(p) = t.first_rst {
                    reset_first = Some(reset_first.map_or(p, |x| x.min(p)));
                }
            }
            let state = t.state();
            if matches!(state, TcpState::Refused | TcpState::SynSent) {
                let e = failed.entry((f.client.0, f.server.0, f.server.1)).or_insert((0, 0, f.first_packet()));
                e.0 += 1;
                e.1 += u32::from(state == TcpState::Refused);
                e.2 = e.2.min(f.first_packet());
            }
            if t.syn.is_some() {
                let e = per_client.entry(f.client.0).or_insert_with(|| (0, HashSet::new(), HashSet::new(), f.first_packet()));
                e.0 += 1;
                e.1.insert(f.server.0);
                e.2.insert(f.server.1);
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
                filter,
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

    let mut failed: Vec<_> = failed.into_iter().filter(|(_, v)| v.0 >= cfg.failed_min_attempts).collect();
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

    let mut busy: Vec<_> = per_client
        .into_iter()
        .filter(|(_, v)| v.0 >= cfg.many_connections || v.2.len() as u32 >= cfg.many_ports)
        .collect();
    busy.sort_by_key(|b| std::cmp::Reverse(b.1 .0));
    for (host, (connections, peers, ports, first)) in busy.into_iter().take(cfg.max_per_kind) {
        out.push(Indicator {
            severity: Severity::Note,
            kind: IndicatorKind::ManyConnections {
                host: host.to_string(),
                connections,
                distinct_peers: peers.len() as u32,
                distinct_ports: ports.len() as u32,
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
