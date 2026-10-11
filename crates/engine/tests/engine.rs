use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nettrace_engine::{
    ConversationQuery, ConversationSort, Engine, FlowQuery, FlowSort, HostQuery, HostSort, IoGraphRequest, SearchQuery, SearchRequest,
    SortKey, SortSpec, TimelineRequest,
};
use nettrace_model::{ConversationKind, IndexState, IndicatorKind, StreamRef, TimelineKind, Transport};
use nettrace_testkit::scenarios;

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn fixture(name: &str, bytes: Vec<u8>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    Fixture { _dir: dir, path }
}

fn open(path: &Path) -> Engine {
    let engine = Engine::new();
    engine.open(path, Arc::new(|_| {})).unwrap();
    let p = engine.session().unwrap().wait_indexed(Duration::from_secs(60));
    assert_eq!(p.state, IndexState::Done, "{p:?}");
    engine
}

fn count(engine: &Engine, filter: &str) -> u32 {
    engine.apply_view(Some(filter), None).unwrap_or_else(|e| panic!("{filter}: {e}")).total
}

fn demo() -> (Fixture, Engine) {
    let f = fixture("demo.pcapng", scenarios::demo().to_pcapng());
    let e = open(&f.path);
    (f, e)
}

#[test]
fn indexes_demo_capture() {
    let (_f, e) = demo();
    let frames = scenarios::demo().frames.len() as u32;
    let s = e.summary().unwrap();
    assert_eq!(s.packets, frames);
    assert_eq!(s.tcp_streams, 9);
    assert_eq!(s.malformed, 2);
    assert_eq!(s.info.format, "PCAPNG");
    assert!(s.duration > 0.0);
    let p = e.progress().unwrap();
    assert_eq!(p.packets, frames);
    assert_eq!(p.bytes_read, p.total_bytes);
}

#[test]
fn packet_rows() {
    let (_f, e) = demo();
    let rows = e.rows(0, 0, 3).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].number, 1);
    assert_eq!(rows[0].protocol, "ARP");
    assert_eq!(rows[0].info, "Who has 10.10.0.1? Tell 10.10.1.15");
    assert_eq!(rows[0].cast, "broadcast");
    assert_eq!(rows[0].time_rel, 0.0);
    assert_eq!(rows[2].protocol, "DHCP");
    assert!(rows[1].time_delta > 0.0);
    // Past the end → empty, not an error.
    assert!(e.rows(0, 10_000, 10).unwrap().is_empty());
}

#[test]
fn display_filters() {
    let (_f, e) = demo();
    assert!(count(&e, "ip.addr == 10.10.1.15") > 50);
    assert_eq!(count(&e, "ip.addr == 10.10.1.15"), count(&e, "ip.src == 10.10.1.15") + count(&e, "ip.dst == 10.10.1.15"));
    assert_eq!(count(&e, "udp.port == 53"), 5);
    assert_eq!(count(&e, "dns"), 5);
    assert_eq!(count(&e, "frame.number == 7"), 1);
    assert_eq!(count(&e, "arp"), 2);
    assert_eq!(count(&e, "dhcp"), 4);
    assert_eq!(count(&e, "ntp"), 2);
    assert_eq!(count(&e, "vlan"), 1);
    assert_eq!(count(&e, "icmpv6"), 3);
    assert_eq!(count(&e, "_ws.malformed"), 2);
    assert_eq!(count(&e, "tcp.stream == 0"), 3 + 2 + 1 + 6 + 1 + 3);
    assert!(count(&e, "tcp.port == 443 && !tls") > 0);
    assert_eq!(count(&e, "tcp.analysis.retransmission"), 5);
    assert_eq!(count(&e, "tcp.flags.syn == 1 && tcp.flags.ack == 0"), 9);
    // Deep fields (require reading packet bytes).
    assert_eq!(count(&e, r#"dns.qry.name contains "api""#), 2);
    assert_eq!(count(&e, r#"http.host == "api.example.com""#), 1);
    assert_eq!(count(&e, r#"tls.handshake.extensions_server_name == "odd-port.example.com""#), 1);
    assert_eq!(count(&e, "x509sat.subject.cn == legacy.example.com"), 1);
    assert_eq!(count(&e, "ip.ttl == 64 && udp"), count(&e, "ip && udp"));
    assert_eq!(count(&e, "frame.time_relative >= 0"), e.summary().unwrap().packets);
}

#[test]
fn filter_errors_are_structured() {
    let (_f, e) = demo();
    let err = e.apply_view(Some("ip.addr == 10.10.1"), None).unwrap_err();
    assert_eq!(err.code, "filter");
    let fe = err.filter.unwrap();
    assert_eq!((fe.code.as_str(), fe.start, fe.end), ("invalid_value", 11, 18));
    let json = serde_json::to_value(e.validate_filter("foo.bar").unwrap_err()).unwrap();
    assert_eq!(json["code"], "unknown_field");
    assert!(e.validate_filter("tcp.port in {80 443}").is_ok());
}

#[test]
fn sorting_and_find_row() {
    let (_f, e) = demo();
    let v = e.apply_view(None, Some(SortSpec { key: SortKey::Length, desc: true })).unwrap();
    let rows = e.rows(v.view_id, 0, 5).unwrap();
    assert!(rows.windows(2).all(|w| w[0].length >= w[1].length));
    let total = v.total;
    let last = e.rows(v.view_id, total - 1, 1).unwrap();
    assert!(last[0].length <= rows[0].length);
    let row = e.find_row(v.view_id, rows[2].number).unwrap();
    assert_eq!(row, Some(2));

    let dns = e.apply_view(Some("dns"), None).unwrap();
    let first_dns = e.rows(dns.view_id, 0, 1).unwrap()[0].number;
    assert_eq!(e.find_row(dns.view_id, first_dns).unwrap(), Some(0));
    assert_eq!(e.find_row(dns.view_id, 1).unwrap(), None);
    assert_eq!(e.find_row(0, 5).unwrap(), Some(4));
}

#[test]
fn packet_details_have_tree_bytes_and_stream() {
    let (_f, e) = demo();
    let v = e.apply_view(Some(r#"tls.handshake.extensions_server_name == "api.example.com""#), None).unwrap();
    let number = e.rows(v.view_id, 0, 1).unwrap()[0].number;
    let d = e.packet_detail(number).unwrap();
    assert_eq!(d.number, number);
    assert!(!d.bytes.is_empty());
    // Protocol headings plus the "TCP payload (N bytes)" text line before TLS.
    let names: Vec<&str> = d.tree.iter().map(|n| n.field.as_str()).collect();
    assert_eq!(names, vec!["frame", "eth", "ip", "tcp", "", "tls"]);
    assert!(d.tree[4].name.starts_with("TCP payload"));
    let tcp = &d.tree[3];
    let stream = tcp.children.iter().find(|c| c.field == "tcp.stream").unwrap();
    assert!(stream.generated);
    let seq = tcp.children.iter().find(|c| c.field == "tcp.seq").unwrap();
    assert!(seq.display.starts_with("1 "), "relative seq: {}", seq.display);
    assert_eq!(d.stream, Some(StreamRef { kind: Transport::Tcp, id: 0 }));
    // Field byte ranges are inside the packet.
    let ip_src = d.tree[2].children.iter().find(|c| c.field == "ip.src").unwrap();
    assert_eq!(&d.bytes[ip_src.start as usize..(ip_src.start + ip_src.len) as usize], &[10, 10, 1, 15]);
    assert!(e.packet_detail(0).is_err());
    assert!(e.packet_detail(1_000_000).is_err());
}

#[test]
fn streams_and_sequence() {
    let (_f, e) = demo();
    let page = e
        .flows(&FlowQuery { kind: Some(Transport::Tcp), sort: FlowSort::Id, desc: false, offset: 0, limit: 100, search: None })
        .unwrap();
    assert_eq!(page.total, 9);
    let tls = &page.flows[0];
    assert_eq!((tls.client.port, tls.server.port, tls.protocol.as_str()), (52144, 443, "TLS"));
    let t = tls.tcp.as_ref().unwrap();
    assert_eq!(t.handshake.syn, Some(tls.first_packet));
    assert!((t.irtt_ms.unwrap() - 38.0).abs() < 0.01);
    assert!(t.rtt_avg_ms.is_some());

    let lossy = e
        .flows(&FlowQuery { kind: Some(Transport::Tcp), sort: FlowSort::Retransmissions, desc: true, offset: 0, limit: 1, search: None })
        .unwrap();
    assert_eq!(lossy.flows[0].client.port, 52190);
    assert_eq!(lossy.flows[0].tcp.as_ref().unwrap().retransmissions, 5);

    let found = e
        .flows(&FlowQuery { kind: None, sort: FlowSort::Bytes, desc: true, offset: 0, limit: 50, search: Some(":4444".into()) })
        .unwrap();
    assert_eq!(found.total, 1);

    // "All" ranks TCP and UDP flows together by the chosen key.
    let all = e.flows(&FlowQuery { kind: None, sort: FlowSort::Bytes, desc: true, offset: 0, limit: 100, search: None }).unwrap();
    assert!(all.flows.windows(2).all(|w| w[0].bytes >= w[1].bytes));
    assert!(all.flows.iter().any(|f| f.kind == Transport::Udp) && all.flows.iter().any(|f| f.kind == Transport::Tcp));

    let seq = e.sequence(StreamRef { kind: Transport::Tcp, id: 0 }, 0, 100).unwrap();
    assert_eq!(seq.total as usize, seq.entries.len());
    // Paging (forward, then jumping back) gives the same packets as one page.
    let numbers = |off, lim| e.sequence(StreamRef { kind: Transport::Tcp, id: 0 }, off, lim).unwrap().entries.into_iter().map(|x| x.number);
    let paged: Vec<u32> = (0..seq.total).step_by(5).flat_map(|o| numbers(o, 5)).collect();
    assert_eq!(paged, seq.entries.iter().map(|x| x.number).collect::<Vec<_>>());
    assert_eq!(numbers(2, 3).collect::<Vec<_>>(), seq.entries[2..5].iter().map(|x| x.number).collect::<Vec<_>>());
    assert_eq!(seq.entries[0].label, "SYN");
    assert_eq!(seq.entries[1].label, "SYN, ACK");
    assert_eq!(seq.entries[1].direction, nettrace_model::Direction::S2c);
    assert_eq!(seq.entries[0].seq, Some(0));
    assert!(seq.entries[3].label.starts_with("Client Hello"));
    assert_eq!(seq.entries[3].seq, Some(1));
    assert!(seq.entries.iter().any(|x| x.label.contains("Server Hello")));
    assert!(e.flow(StreamRef { kind: Transport::Udp, id: 999 }).is_err());
}

#[test]
fn statistics() {
    let (_f, e) = demo();
    let hq = |search: Option<&str>| HostQuery { sort: HostSort::Bytes, desc: true, offset: 0, limit: 1000, search: search.map(Into::into) };
    let hosts = e.hosts_page(&hq(None)).unwrap();
    assert_eq!(hosts.total as usize, hosts.rows.len());
    assert!(hosts.rows.windows(2).all(|w| w[0].bytes >= w[1].bytes));
    let found = e.hosts_page(&hq(Some("10.10.1.15"))).unwrap();
    assert_eq!(found.total, 1);
    let client = &found.rows[0];
    assert!(client.tx_packets > 0 && client.rx_packets > 0);
    assert_eq!(client.mac.as_deref(), Some("00:1f:1a:2b:3c:01"));
    assert!(client.protocols.iter().any(|p| p == "TLS"));

    let conv = |kind, offset, limit| {
        e.conversations_page(&ConversationQuery { kind, sort: ConversationSort::Bytes, desc: true, offset, limit, search: None }).unwrap()
    };
    let tcp = conv(ConversationKind::Tcp, 0, 1000);
    assert_eq!((tcp.total, tcp.rows.len()), (9, 9));
    assert!(tcp.rows.iter().any(|c| c.state.as_deref() == Some("refused")));
    // Pages concatenate to the full order.
    let paged: Vec<_> = (0..9).step_by(4).flat_map(|o| conv(ConversationKind::Tcp, o, 4).rows).map(|r| r.filter).collect();
    assert_eq!(paged, tcp.rows.iter().map(|r| r.filter.clone()).collect::<Vec<_>>());
    assert!(conv(ConversationKind::Tcp, 50, 10).rows.is_empty());
    assert!(conv(ConversationKind::Ip, 0, 10).total > 0);
    assert!(conv(ConversationKind::Eth, 0, 10).total > 0);
    assert_eq!(conv(ConversationKind::Udp, 0, 10).total, e.summary().unwrap().udp_streams);
    // End = start + duration, and sorting by it works.
    for kind in [ConversationKind::Eth, ConversationKind::Ip, ConversationKind::Tcp, ConversationKind::Udp] {
        for r in conv(kind, 0, 1000).rows {
            assert!((r.end - (r.start + r.duration)).abs() < 1e-6, "{kind:?}: {} != {} + {}", r.end, r.start, r.duration);
        }
        let q = ConversationQuery { kind, sort: ConversationSort::End, desc: true, offset: 0, limit: 1000, search: None };
        let rows = e.conversations_page(&q).unwrap().rows;
        assert!(rows.windows(2).all(|w| w[0].end >= w[1].end));
    }

    let h = e.protocol_hierarchy().unwrap();
    assert_eq!(h[0].filter, "frame");
    assert_eq!(h[0].packets, u64::from(e.summary().unwrap().packets));

    let io = e.io_graph(&IoGraphRequest { interval: 0.1, filter: None }).unwrap();
    assert_eq!(io.packets.iter().sum::<u64>(), u64::from(e.summary().unwrap().packets));
    let io_dns = e.io_graph(&IoGraphRequest { interval: 0.1, filter: Some("dns".into()) }).unwrap();
    assert_eq!(io_dns.matched_packets, 5);

    let lengths = e.packet_lengths(None).unwrap();
    assert_eq!(lengths.total, u64::from(e.summary().unwrap().packets));

    let tl = e.timeline(&TimelineRequest { start: None, end: None, buckets: 50, max_events: 1000 }).unwrap();
    assert_eq!(tl.packets.iter().sum::<u32>(), e.summary().unwrap().packets);
    assert!(tl.events.iter().any(|ev| ev.kind == TimelineKind::DnsQuery && ev.label == "A api.example.com"));
    assert!(tl.events.iter().any(|ev| ev.kind == TimelineKind::TcpOpen));
    assert!(tl.events.iter().any(|ev| ev.kind == TimelineKind::TlsClientHello && ev.label == "api.example.com"));
    assert!(tl.events.iter().any(|ev| ev.kind == TimelineKind::HttpRequest));
    assert!(tl.tcp_active.iter().any(|n| *n > 0));
}

#[test]
fn many_connections_counts_peers_and_ports() {
    use nettrace_testkit::build::{self, tcpf, TcpSegment};
    let mut cap = nettrace_testkit::Capture::ethernet();
    let syn = |client: [u8; 4], server: [u8; 4], sport: u16, dport: u16| {
        let seg = TcpSegment { sport, dport, seq: 1, ack: 0, flags: tcpf::SYN, window: 1024, options: vec![], payload: vec![] };
        build::ethernet(build::MAC_B, build::MAC_A, build::ETH_IPV4, &build::ipv4(client, server, 6, 1, 64, &build::tcp(&seg)))
    };
    for i in 0..120u16 {
        cap.push_after_us(10, syn([10, 9, 9, 9], [172, 16, 0, 1 + (i % 3) as u8], 40_000 + i, 1000 + i % 60));
    }
    cap.push_after_us(10, syn([10, 9, 9, 8], [172, 16, 0, 1], 40_000, 80));
    let f = fixture("scan.pcap", cap.to_pcap());
    let e = open(&f.path);
    let busy: Vec<_> = e
        .indicators()
        .unwrap()
        .into_iter()
        .filter_map(|i| match i.kind {
            IndicatorKind::ManyConnections { host, connections, distinct_peers, distinct_ports } => {
                Some((host, connections, distinct_peers, distinct_ports, i.first_packet))
            }
            _ => None,
        })
        .collect();
    assert_eq!(busy, [("10.9.9.9".to_owned(), 120, 3, 60, Some(1))]);
}

#[test]
fn technical_indicators_report_facts() {
    let (_f, e) = demo();
    let ind = e.indicators().unwrap();
    let has = |pred: &dyn Fn(&IndicatorKind) -> bool| ind.iter().any(|i| pred(&i.kind));
    assert!(has(&|k| matches!(k, IndicatorKind::MalformedPackets { count: 2 })));
    assert!(has(&|k| matches!(k, IndicatorKind::RepeatedFailedConnections { port: 445, attempts: 4, refused: 4, .. })));
    assert!(has(&|k| matches!(k, IndicatorKind::NonStandardPort { port: 4444, .. })));
    assert!(has(&|k| matches!(k, IndicatorKind::TcpResets { .. })));
    // Every indicator's filter is valid and selects at least one packet.
    for i in &ind {
        assert!(count(&e, &i.filter) > 0, "indicator filter selects nothing: {}", i.filter);
    }
}

/// The detail tree node at a search hit's path.
fn node_at<'a>(tree: &'a [nettrace_model::PacketField], path: &[u32]) -> &'a nettrace_model::PacketField {
    let (first, rest) = path.split_first().expect("non-empty path");
    let node = &tree[*first as usize];
    if rest.is_empty() { node } else { node_at(&node.children, rest) }
}

#[test]
fn search_hits_point_at_the_matching_field_and_bytes() {
    let (_f, e) = demo();
    let find = |query| e.search(&SearchRequest { view_id: 0, from_row: None, backwards: false, query }).unwrap().unwrap();

    // Bytes: the exact range, found in the packet bytes.
    let hit = find(SearchQuery::Hex { text: "16 03 01".into() });
    let loc = hit.location.clone().expect("location");
    let bytes = e.packet_detail(hit.number).unwrap().bytes;
    assert_eq!(&bytes[loc.start as usize..(loc.start + loc.len) as usize], &[0x16, 0x03, 0x01]);

    // Decoded text: the DNS name field.
    let hit = find(SearchQuery::Text { text: "API.EXAMPLE.COM".into(), case_sensitive: false });
    let path = hit.location.unwrap().path.expect("path to a field");
    let tree = e.packet_detail(hit.number).unwrap().tree;
    assert_eq!(node_at(&tree, &path).field, "dns.qry.name");

    // Filters: the field that satisfies the condition, or the protocol.
    for (filter, fields) in [("tcp.port == 443", &["tcp.srcport", "tcp.dstport"][..]), ("dns", &["dns"][..]), ("ip.addr == 10.10.0.53", &["ip.src", "ip.dst"][..])] {
        let hit = find(SearchQuery::Filter { text: filter.into() });
        let loc = hit.location.unwrap_or_else(|| panic!("{filter}: no location"));
        let tree = e.packet_detail(hit.number).unwrap().tree;
        let node = node_at(&tree, &loc.path.unwrap());
        assert!(fields.contains(&node.field.as_str()), "{filter}: {}", node.field);
        assert_eq!((loc.start, loc.len), (node.start, node.len));
    }
    // Only negations: the packet is found, but no field can be pointed at.
    assert!(find(SearchQuery::Filter { text: "!tcp".into() }).location.is_none());
}

#[test]
fn search_text_hex_and_filter() {
    let (_f, e) = demo();
    // DNS names are label-encoded on the wire; the text search also checks decoded values.
    let hit = e
        .search(&SearchRequest {
            view_id: 0,
            from_row: None,
            backwards: false,
            query: SearchQuery::Text { text: "API.EXAMPLE.COM".into(), case_sensitive: false },
        })
        .unwrap()
        .unwrap();
    let dns_first = e.rows(e.apply_view(Some("dns"), None).unwrap().view_id, 0, 1).unwrap()[0].number;
    assert_eq!(hit.number, dns_first);
    assert!(!hit.wrapped);

    let next = e
        .search(&SearchRequest {
            view_id: 0,
            from_row: Some(hit.row),
            backwards: false,
            query: SearchQuery::Text { text: "api.example.com".into(), case_sensitive: true },
        })
        .unwrap()
        .unwrap();
    assert!(next.number > hit.number);

    let hex = e
        .search(&SearchRequest { view_id: 0, from_row: None, backwards: false, query: SearchQuery::Hex { text: "16 03 01".into() } })
        .unwrap()
        .unwrap();
    assert!(e.rows(0, hex.row, 1).unwrap()[0].protocol == "TLS");

    let back = e
        .search(&SearchRequest { view_id: 0, from_row: None, backwards: true, query: SearchQuery::Filter { text: "arp".into() } })
        .unwrap()
        .unwrap();
    assert_eq!(back.number, 2);

    let wrapped = e
        .search(&SearchRequest { view_id: 0, from_row: Some(5), backwards: false, query: SearchQuery::Filter { text: "arp".into() } })
        .unwrap()
        .unwrap();
    assert!(wrapped.wrapped);

    let none = e
        .search(&SearchRequest { view_id: 0, from_row: None, backwards: false, query: SearchQuery::Text { text: "zzz-not-there".into(), case_sensitive: false } })
        .unwrap();
    assert!(none.is_none());
    assert!(e.search(&SearchRequest { view_id: 0, from_row: None, backwards: false, query: SearchQuery::Hex { text: "xyz".into() } }).is_err());
}

#[test]
fn coloring_rules() {
    let (_f, e) = demo();
    let errors = e.set_coloring_rules(&["tcp.flags.reset == 1".into(), "bad ==".into(), "arp".into(), "dns".into()]);
    assert!(errors[0].is_none() && errors[1].is_some() && errors[2].is_none());
    let rows = e.rows(0, 0, 1).unwrap();
    assert_eq!(rows[0].color_rule, Some(2));
}

#[test]
fn export_filtered_view() {
    let (f, e) = demo();
    let v = e.apply_view(Some("dns || arp"), None).unwrap();
    let out = f.path.with_file_name("subset.pcap");
    assert_eq!(e.export(v.view_id, &out).unwrap(), 7);
    let e2 = open(&out);
    assert_eq!(e2.summary().unwrap().packets, 7);
    assert_eq!(count(&e2, "dns"), 5);
    assert!(e.export(0, &f.path).is_err());
}

#[test]
fn truncated_and_invalid_files() {
    let mut bytes = scenarios::tcp_basic().to_pcap();
    bytes.truncate(bytes.len() - 10);
    let f = fixture("cut.pcap", bytes);
    let e = Engine::new();
    e.open(&f.path, Arc::new(|_| {})).unwrap();
    let p = e.session().unwrap().wait_indexed(Duration::from_secs(10));
    assert_eq!(p.state, IndexState::Done);
    assert_eq!(p.warning.as_deref(), Some("truncated"));
    assert_eq!(p.packets, 8);

    let junk = fixture("junk.pcap", b"definitely not a capture".to_vec());
    let err = Engine::new().open(&junk.path, Arc::new(|_| {})).unwrap_err();
    assert_eq!(err.code, "unknown_format");
    assert_eq!(Engine::new().open(Path::new("/does/not/exist.pcap"), Arc::new(|_| {})).unwrap_err().code, "io");
    assert_eq!(Engine::new().rows(0, 0, 1).unwrap_err().code, "no_capture");
}

#[test]
fn ui_can_read_while_indexing() {
    let f = fixture("large.pcap", scenarios::large(4000).to_pcap());
    let e = Engine::new();
    let updates = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let u = updates.clone();
    e.open(&f.path, Arc::new(move |_| {
        u.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }))
    .unwrap();
    let mut reads = 0;
    let deadline = Instant::now() + Duration::from_secs(60);
    while e.session().unwrap().is_indexing() && Instant::now() < deadline {
        let n = e.view_len(0).unwrap();
        if n > 10 {
            let rows = e.rows(0, n - 10, 10).unwrap();
            assert_eq!(rows.len(), 10);
            let _ = e.flows(&FlowQuery { kind: None, sort: FlowSort::Id, desc: false, offset: 0, limit: 10, search: None }).unwrap();
            reads += 1;
        }
    }
    let p = e.session().unwrap().wait_indexed(Duration::from_secs(60));
    assert_eq!(p.state, IndexState::Done);
    assert_eq!(p.packets as usize, scenarios::large(4000).frames.len());
    assert!(updates.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    let _ = reads;
    assert_eq!(count(&e, "tcp.flags.syn == 1 && tcp.flags.ack == 0"), 4000);
}

#[test]
fn reopening_cancels_previous_capture() {
    let a = fixture("a.pcap", scenarios::large(2000).to_pcap());
    let b = fixture("b.pcap", scenarios::tcp_basic().to_pcap());
    let e = Engine::new();
    e.open(&a.path, Arc::new(|_| {})).unwrap();
    let first = e.session().unwrap();
    e.open(&b.path, Arc::new(|_| {})).unwrap();
    let p = first.wait_indexed(Duration::from_secs(30));
    assert!(matches!(p.state, IndexState::Cancelled | IndexState::Done));
    let s = e.session().unwrap();
    s.wait_indexed(Duration::from_secs(10));
    assert_eq!(e.summary().unwrap().packets, 9);
}

/// Performance smoke test: `cargo test -p nettrace-engine --release -- --ignored --nocapture`
#[test]
#[ignore]
fn perf_large_capture() {
    let conns: u32 = std::env::var("NETTRACE_PERF_CONNS").ok().and_then(|v| v.parse().ok()).unwrap_or(40_000);
    let f = fixture("perf.pcap", scenarios::large(conns).to_pcap());
    let size = std::fs::metadata(&f.path).unwrap().len();
    let t = Instant::now();
    let e = open(&f.path);
    let s = e.summary().unwrap();
    println!("indexed {} packets ({} MB, {} tcp streams) in {:?}", s.packets, size / 1_000_000, s.tcp_streams, t.elapsed());
    for filter in ["ip.addr == 10.1.0.5", "tcp.port == 443", "tcp.analysis.flags", r#"dns.qry.name contains "host7""#] {
        let t = Instant::now();
        let v = e.apply_view(Some(filter), None).unwrap();
        println!("filter {filter:<32} → {:>8} rows in {:?}", v.total, t.elapsed());
    }
    let t = Instant::now();
    e.rows(0, s.packets / 2, 100).unwrap();
    println!("100 rows in {:?}", t.elapsed());
}

#[test]
fn live_capture_records_and_indexes_in_real_time() {
    use nettrace_live::ReplaySource;
    use nettrace_packet::LinkType;

    let frames = scenarios::demo().frames;
    let n = frames.len() as u32;
    let source = ReplaySource::new(LinkType::Ethernet, frames, Duration::from_millis(3));
    let e = Engine::new();
    let updates = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let u = updates.clone();
    let info = e
        .start_capture_with(Box::new(source), "test0", Arc::new(move |_| {
            u.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }))
        .unwrap();
    assert!(info.live);
    let temp = PathBuf::from(&info.path);
    assert!(temp.exists());

    // Packets appear while the capture is running.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen_partial = false;
    while Instant::now() < deadline {
        let len = e.view_len(0).unwrap();
        if len > 0 && len < n {
            seen_partial = true;
            let rows = e.rows(0, 0, 5).unwrap();
            assert_eq!(rows[0].protocol, "ARP");
        }
        if len == n {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(seen_partial, "packets must be visible before the capture ends");
    assert_eq!(e.view_len(0).unwrap(), n);
    assert!(e.session().unwrap().capturing());
    // Filters work on live data.
    assert_eq!(count(&e, "dns"), 5);
    // Saving is refused while recording.
    assert_eq!(e.export(0, &temp.with_file_name("x.pcap")).unwrap_err().code, "export_capturing");

    e.stop_capture().unwrap();
    let p = e.session().unwrap().wait_indexed(Duration::from_secs(20));
    assert_eq!(p.state, IndexState::Done, "{p:?}");
    assert_eq!(p.packets, n);
    let stats = p.capture.unwrap();
    assert_eq!((stats.captured, stats.running, stats.interface.as_str()), (u64::from(n), false, "test0"));
    assert!(!e.session().unwrap().capturing());
    assert!(updates.load(std::sync::atomic::Ordering::SeqCst) >= 1);

    // The recorded capture can be saved and reopened like a file.
    let out = tempfile::tempdir().unwrap();
    let saved = out.path().join("live.pcap");
    assert_eq!(e.export(0, &saved).unwrap(), n);
    let e2 = open(&saved);
    assert_eq!(e2.summary().unwrap().packets, n);
    assert!(e.stop_capture().is_ok());

    // Closing removes the temporary file.
    e.close();
    drop(e);
    let gone = Instant::now() + Duration::from_secs(5);
    while temp.exists() && Instant::now() < gone {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!temp.exists(), "temporary capture file must be deleted");
}

#[test]
fn shutdown_removes_the_live_capture_file() {
    use nettrace_live::ReplaySource;
    use nettrace_packet::LinkType;

    let e = Engine::new();
    let info = e
        .start_capture_with(Box::new(ReplaySource::new(LinkType::Ethernet, Vec::new(), Duration::ZERO)), "idle0", Arc::new(|_| {}))
        .unwrap();
    let temp = PathBuf::from(&info.path);
    assert!(temp.exists());
    e.shutdown(Duration::from_secs(5));
    assert!(!temp.exists(), "temporary capture file must be deleted on shutdown");
}

#[test]
fn stopping_a_quiet_capture_finishes_indexing() {
    use nettrace_live::ReplaySource;
    use nettrace_packet::LinkType;

    let e = Engine::new();
    e.start_capture_with(Box::new(ReplaySource::new(LinkType::Ethernet, Vec::new(), Duration::ZERO)), "idle0", Arc::new(|_| {}))
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(e.session().unwrap().is_indexing());
    e.stop_capture().unwrap();
    let p = e.session().unwrap().wait_indexed(Duration::from_secs(10));
    assert_eq!((p.state, p.packets), (IndexState::Done, 0));
    // A file capture is not live.
    let f = fixture("b.pcap", scenarios::tcp_basic().to_pcap());
    let e2 = open(&f.path);
    assert_eq!(e2.stop_capture().unwrap_err().code, "not_live");
}

#[test]
fn a_crashing_capture_driver_ends_the_session() {
    use nettrace_live::{DriverStats, LiveError, LivePacket, LiveSource};
    use nettrace_packet::LinkType;

    struct Crashing;
    impl LiveSource for Crashing {
        fn link_type(&self) -> LinkType {
            LinkType::Ethernet
        }
        fn next_packet(&mut self, _: &mut Vec<u8>, _: Duration) -> Result<Option<LivePacket>, LiveError> {
            panic!("driver crashed");
        }
        fn stats(&mut self) -> Option<DriverStats> {
            None
        }
    }

    let e = Engine::new();
    e.start_capture_with(Box::new(Crashing), "crash0", Arc::new(|_| {})).unwrap();
    let p = e.session().unwrap().wait_indexed(Duration::from_secs(10));
    assert_ne!(p.state, IndexState::Indexing, "indexing must not wait forever for a dead recorder");
    assert!(!e.session().unwrap().capturing());
}

mod follow {
    use super::*;
    use base64::Engine as _;
    use nettrace_engine::FollowRequest;
    use nettrace_model::{Direction, FollowChunkKind, FollowDirection, FollowPage};
    use nettrace_testkit::build;
    use nettrace_testkit::scenarios::{CLIENT, SERVER};
    use nettrace_testkit::{Capture, TcpConv};

    fn page(e: &Engine, kind: Transport, id: u32, direction: FollowDirection, offset: u64, limit: u32) -> FollowPage {
        e.follow_stream(&FollowRequest { stream: StreamRef { kind, id }, direction, offset, limit }).unwrap()
    }

    /// All data bytes of a stream with their directions, read page by page.
    fn data(e: &Engine, kind: Transport, id: u32, direction: FollowDirection, limit: u32) -> (Vec<u8>, Vec<Direction>, usize) {
        let (mut bytes, mut dirs, mut gaps, mut offset) = (Vec::new(), Vec::new(), 0, 0);
        for _ in 0..10_000 {
            let p = page(e, kind, id, direction, offset, limit);
            for c in &p.chunks {
                match c.kind {
                    FollowChunkKind::Data => {
                        bytes.extend(base64::engine::general_purpose::STANDARD.decode(c.data.as_ref().unwrap()).unwrap());
                        if dirs.last() != Some(&c.direction) {
                            dirs.push(c.direction);
                        }
                    }
                    _ => gaps += 1,
                }
            }
            if p.done {
                return (bytes, dirs, gaps);
            }
            // A finished capture never waits; an empty page just continues.
            assert!(!p.waiting);
            assert!(p.next_offset >= offset);
            offset = p.next_offset;
        }
        panic!("the stream never finished");
    }

    #[test]
    fn follows_a_conversation_in_order() {
        let f = fixture("basic.pcap", scenarios::tcp_basic().to_pcap());
        let e = open(&f.path);
        let request = build::http_request("GET", "example.test", "/index.html");
        let response = build::http_response(200, "OK", "<html>hello</html>");
        let (bytes, dirs, gaps) = data(&e, Transport::Tcp, 0, FollowDirection::Both, 1 << 20);
        assert_eq!(bytes, [request.clone(), response.clone()].concat());
        assert_eq!((dirs, gaps), (vec![Direction::C2s, Direction::S2c], 0));
        assert_eq!(data(&e, Transport::Tcp, 0, FollowDirection::C2s, 1 << 20).0, request);
        assert_eq!(data(&e, Transport::Tcp, 0, FollowDirection::S2c, 1 << 20).0, response);
    }

    #[test]
    fn retransmissions_and_reordering_are_resolved() {
        let f = fixture("problems.pcap", scenarios::tcp_problems().to_pcap());
        let e = open(&f.path);
        let (c2s, _, gaps) = data(&e, Transport::Tcp, 0, FollowDirection::C2s, 1 << 20);
        assert_eq!(c2s, [[1u8; 100], [2; 100], [3; 100], [4; 100]].concat());
        assert_eq!(gaps, 0);
        assert_eq!(data(&e, Transport::Tcp, 0, FollowDirection::S2c, 1 << 20).0, vec![9u8; 200]);
        // Small pages give exactly the same bytes as one big page.
        let whole = data(&e, Transport::Tcp, 0, FollowDirection::Both, 1 << 20).0;
        assert_eq!(data(&e, Transport::Tcp, 0, FollowDirection::Both, 37).0, whole);
        let p = page(&e, Transport::Tcp, 0, FollowDirection::Both, 250, 10);
        let got = base64::engine::general_purpose::STANDARD.decode(p.chunks[0].data.as_ref().unwrap()).unwrap();
        assert_eq!((p.chunks[0].offset, got.as_slice()), (250, &whole[250..260]));
    }

    #[test]
    fn lost_segments_become_gaps() {
        let mut cap = Capture::ethernet();
        let mut c = TcpConv::new(CLIENT, 50_100, SERVER, 80);
        c.handshake(&mut cap, 100);
        c.send(&mut cap, true, &[1u8; 100], 100);
        c.cseq = c.cseq.wrapping_add(50); // 50 bytes never captured
        c.send(&mut cap, true, &[2u8; 100], 100);
        let f = fixture("lost.pcap", cap.to_pcap());
        let e = open(&f.path);
        let p = page(&e, Transport::Tcp, 0, FollowDirection::Both, 0, 1 << 20);
        let kinds: Vec<_> = p.chunks.iter().map(|c| (c.kind, c.len, c.stream_offset)).collect();
        assert_eq!(kinds, [(FollowChunkKind::Data, 100, 0), (FollowChunkKind::Gap, 50, 100), (FollowChunkKind::Data, 100, 150)]);
    }

    #[test]
    fn holes_are_reported_once_across_pages() {
        let mut cap = Capture::ethernet();
        let mut c = TcpConv::new(CLIENT, 50_101, SERVER, 80);
        c.handshake(&mut cap, 100);
        c.send(&mut cap, true, &[1u8; 100], 100);
        c.cseq = c.cseq.wrapping_add(50);
        c.send(&mut cap, true, &[2u8; 100], 100);
        let f = fixture("lost_pages.pcap", cap.to_pcap());
        let e = open(&f.path);
        // Pages ending right before the gap (10, 100), around it (7) or past it.
        for limit in [10, 7, 100, 1 << 20] {
            let (bytes, _, gaps) = data(&e, Transport::Tcp, 0, FollowDirection::Both, limit);
            assert_eq!((bytes.len(), gaps), (200, 1), "limit {limit}");
        }
    }

    #[test]
    fn long_stretches_without_payload_do_not_stall() {
        // The client sends a few bytes, then only the server talks: following
        // the client side walks well past one request's step budget.
        let mut cap = Capture::ethernet();
        let mut c = TcpConv::new(CLIENT, 50_102, SERVER, 80);
        c.handshake(&mut cap, 100);
        c.send(&mut cap, true, b"hi", 100);
        for _ in 0..120_000 {
            c.send(&mut cap, false, b"x", 1);
        }
        c.send(&mut cap, true, b"bye", 100);
        let f = fixture("long.pcap", cap.to_pcap());
        let e = open(&f.path);
        assert_eq!(data(&e, Transport::Tcp, 0, FollowDirection::C2s, 1 << 20).0, b"hibye");
    }

    #[test]
    fn tiny_segments_are_joined_into_few_chunks() {
        let mut cap = Capture::ethernet();
        let mut c = TcpConv::new(CLIENT, 50_104, SERVER, 22);
        c.handshake(&mut cap, 100);
        for _ in 0..3000 {
            c.send(&mut cap, true, b"k", 10);
        }
        let f = fixture("keys.pcap", cap.to_pcap());
        let e = open(&f.path);
        let p = page(&e, Transport::Tcp, 0, FollowDirection::Both, 0, 1 << 20);
        let lens: Vec<u32> = p.chunks.iter().map(|c| c.len).collect();
        assert!(lens.len() <= 3 && lens.iter().sum::<u32>() == 3000, "{lens:?}");
        assert_eq!(data(&e, Transport::Tcp, 0, FollowDirection::Both, 100).0, vec![b'k'; 3000]);
    }

    #[test]
    fn data_on_a_syn_starts_the_stream() {
        // TCP Fast Open: the SYN carries the first bytes.
        let mut cap = Capture::ethernet();
        let mut c = TcpConv::new(CLIENT, 50_103, SERVER, 80);
        let syn = c.segment(true, 0x02, c.cseq, 0, b"GET", vec![]);
        cap.push_after_us(1, syn);
        c.cseq = c.cseq.wrapping_add(4);
        c.send(&mut cap, true, b" /", 100);
        let f = fixture("tfo.pcap", cap.to_pcap());
        let e = open(&f.path);
        let (bytes, _, gaps) = data(&e, Transport::Tcp, 0, FollowDirection::C2s, 1 << 20);
        assert_eq!((bytes.as_slice(), gaps), (&b"GET /"[..], 0));
    }

    #[test]
    fn udp_datagrams_and_export() {
        let (f, e) = demo();
        let _ = f;
        let (dns, dirs, _) = data(&e, Transport::Udp, 0, FollowDirection::Both, 1 << 20);
        assert!(!dns.is_empty() && dirs[0] == Direction::C2s);

        let basic = fixture("basic.pcap", scenarios::tcp_basic().to_pcap());
        let e = open(&basic.path);
        let out = basic.path.with_file_name("stream.bin");
        let n = e.export_stream(StreamRef { kind: Transport::Tcp, id: 0 }, FollowDirection::Both, &out).unwrap();
        let saved = std::fs::read(&out).unwrap();
        let whole = data(&e, Transport::Tcp, 0, FollowDirection::Both, 1 << 20).0;
        assert_eq!((n.bytes as usize, n.missing, saved), (whole.len(), 0, whole));
        assert_eq!(e.export_stream(StreamRef { kind: Transport::Tcp, id: 0 }, FollowDirection::Both, &basic.path).unwrap_err().code, "export_same_file");
        let leftovers = std::fs::read_dir(out.parent().unwrap()).unwrap().filter(|x| x.as_ref().unwrap().file_name().to_string_lossy().ends_with(".part")).count();
        assert_eq!(leftovers, 0);
    }
}

#[test]
#[ignore]
fn bench_follow_large_stream() {
    use nettrace_engine::FollowRequest;
    use nettrace_model::FollowDirection;
    use nettrace_testkit::scenarios::{CLIENT, SERVER};
    use nettrace_testkit::{Capture, TcpConv};
    let mut cap = Capture::ethernet();
    let mut c = TcpConv::new(CLIENT, 50_200, SERVER, 80);
    c.handshake(&mut cap, 100);
    let seg = vec![7u8; 1400];
    for i in 0..50_000 {
        c.send(&mut cap, false, &seg, 10);
        if i % 2 == 0 {
            c.ack(&mut cap, true, 10);
        }
    }
    let f = fixture("bench.pcap", cap.to_pcap());
    let e = open(&f.path);
    let t = std::time::Instant::now();
    let (mut offset, mut pages) = (0u64, 0);
    loop {
        let p = e.follow_stream(&FollowRequest { stream: StreamRef { kind: Transport::Tcp, id: 0 }, direction: FollowDirection::Both, offset, limit: 256 * 1024 }).unwrap();
        pages += 1;
        if p.done { break; }
        offset = p.next_offset;
    }
    eprintln!("follow: {} MB in {pages} pages, {:?}", offset >> 20, t.elapsed());
    let t = std::time::Instant::now();
    let p = e.follow_stream(&FollowRequest { stream: StreamRef { kind: Transport::Tcp, id: 0 }, direction: FollowDirection::Both, offset: 50_000_000, limit: 256 * 1024 }).unwrap();
    eprintln!("random page: {} chunks, {:?}", p.chunks.len(), t.elapsed());
    let out = f.path.with_file_name("bench.bin");
    let t = std::time::Instant::now();
    let r = e.export_stream(StreamRef { kind: Transport::Tcp, id: 0 }, FollowDirection::Both, &out).unwrap();
    eprintln!("export: {} MB, {:?}", r.bytes >> 20, t.elapsed());
}
