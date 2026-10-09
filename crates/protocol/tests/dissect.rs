use nettrace_model::{FieldValue, ProtocolId, TimelineKind};
use nettrace_packet::{Address, LinkType, MacAddr, Timestamp};
use nettrace_protocol::{dissect, DissectOptions, Dissection, FrameContext, Node, TransportInfo};
use nettrace_testkit::build::{self, tcpf, TcpSegment};
use nettrace_testkit::scenarios::{self, CLIENT, SERVER};
use nettrace_testkit::{udp_frame, Capture, TcpConv};

fn ctx(link: LinkType, len: usize) -> FrameContext {
    FrameContext {
        number: 1,
        ts: Timestamp::from_parts(1_700_000_000, 0),
        caplen: len as u32,
        origlen: len as u32,
        link_type: Some(link),
        ..FrameContext::default()
    }
}

fn full(frame: &[u8]) -> Dissection {
    dissect(frame, &ctx(LinkType::Ethernet, frame.len()), DissectOptions::FULL)
}

fn find<'a>(nodes: &'a [Node], abbrev: &str) -> Option<&'a Node> {
    for n in nodes {
        if n.field.map(|f| f.abbrev) == Some(abbrev) {
            return Some(n);
        }
        if let Some(found) = find(&n.children, abbrev) {
            return Some(found);
        }
    }
    None
}

fn values(d: &Dissection, abbrev: &str) -> Vec<FieldValue> {
    d.values.iter().filter(|(f, _)| f.abbrev == abbrev).map(|(_, v)| v.clone()).collect()
}

fn tcp_frame(flags: u8, payload: &[u8], dport: u16) -> Vec<u8> {
    let seg = TcpSegment { sport: 52144, dport, seq: 1000, ack: 2000, flags, window: 502, options: vec![], payload: payload.to_vec() };
    let ip = build::ipv4(CLIENT.ip, SERVER.ip, 6, 7, 64, &build::tcp(&seg));
    build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV4, &ip)
}

#[test]
fn ethernet_ipv4_tcp_syn() {
    let seg = TcpSegment {
        sport: 52144,
        dport: 443,
        seq: 12345,
        ack: 0,
        flags: tcpf::SYN,
        window: 64240,
        options: build::syn_options(1460, 7),
        payload: vec![],
    };
    let ip = build::ipv4(CLIENT.ip, SERVER.ip, 6, 7, 64, &build::tcp(&seg));
    let frame = build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV4, &ip);
    let d = full(&frame);
    let s = &d.summary;
    assert!(!s.malformed);
    assert_eq!(s.top, Some(ProtocolId::Tcp));
    assert_eq!(s.path().collect::<Vec<_>>(), vec![ProtocolId::Frame, ProtocolId::Eth, ProtocolId::Ipv4, ProtocolId::Tcp]);
    assert_eq!(s.l2_src, Address::Mac(MacAddr(CLIENT.mac)));
    assert_eq!(s.net_src, Address::V4(CLIENT.ip));
    assert_eq!(s.net_dst, Address::V4(SERVER.ip));
    assert_eq!((s.src_port, s.dst_port), (52144, 443));
    let Some(TransportInfo::Tcp(t)) = s.transport else { panic!("tcp expected") };
    assert_eq!((t.seq, t.flags, t.mss, t.wscale, t.sack_perm), (12345, 0x002, Some(1460), Some(7), true));
    assert_eq!(d.info, "52144 → 443 [SYN] Seq=12345 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128");

    // Byte ranges point at the right bytes.
    let src = find(&d.nodes, "ip.src").unwrap();
    assert_eq!((src.start, src.len), (26, 4));
    assert_eq!(&frame[src.start..src.start + src.len], &CLIENT.ip);
    let port = find(&d.nodes, "tcp.dstport").unwrap();
    assert_eq!(&frame[port.start..port.start + 2], &443u16.to_be_bytes());
    assert_eq!(find(&d.nodes, "ip.checksum.status").unwrap().display, "Good");
    assert!(find(&d.nodes, "frame.number").is_some());
    assert_eq!(d.nodes[0].field.unwrap().abbrev, "frame");
}

#[test]
fn modes_produce_expected_outputs() {
    let frame = tcp_frame(tcpf::ACK | tcpf::PSH, b"hello", 9999);
    let fctx = ctx(LinkType::Ethernet, frame.len());
    let index = dissect(&frame, &fctx, DissectOptions::INDEX);
    assert!(index.nodes.is_empty() && index.values.is_empty() && index.info.is_empty());
    assert_eq!(index.summary.top, Some(ProtocolId::Tcp));
    assert!(index.summary.protocols.contains(ProtocolId::Data));

    let vals = dissect(&frame, &fctx, DissectOptions::VALUES);
    assert!(vals.nodes.is_empty());
    assert_eq!(values(&vals, "ip.ttl"), vec![FieldValue::U64(64)]);
    assert_eq!(values(&vals, "tcp.payload"), vec![FieldValue::Bytes(b"hello".to_vec())]);
    assert_eq!(values(&vals, "frame.len"), vec![FieldValue::U64(frame.len() as u64)]);

    let row = dissect(&frame, &fctx, DissectOptions::ROW);
    assert!(row.info.starts_with("52144 → 9999 [PSH, ACK]"));
}

#[test]
fn vlan_dns_query_event() {
    let q = build::ipv4(CLIENT.ip, SERVER.ip, 17, 1, 64, &build::udp(5000, 53, &build::dns_query(0x7777, "vlan.example.org", 28)));
    let frame = build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_VLAN, &build::vlan_tag(100, 3, build::ETH_IPV4, &q));
    let fctx = ctx(LinkType::Ethernet, frame.len());
    let d = dissect(&frame, &fctx, DissectOptions { events: true, ..DissectOptions::FULL });
    assert!(d.summary.protocols.contains(ProtocolId::Vlan));
    assert_eq!(d.summary.top, Some(ProtocolId::Dns));
    assert_eq!(find(&d.nodes, "vlan.id").unwrap().value, FieldValue::U64(100));
    assert_eq!(find(&d.nodes, "vlan.priority").unwrap().value, FieldValue::U64(3));
    assert_eq!(find(&d.nodes, "dns.qry.name").unwrap().display, "vlan.example.org");
    assert_eq!(d.info, "Standard query 0x7777 AAAA vlan.example.org");
    let ev = d.summary.event.unwrap();
    assert_eq!(ev.kind, TimelineKind::DnsQuery);
    assert_eq!(ev.label, "AAAA vlan.example.org");
}

#[test]
fn dns_response_with_cname_and_compression() {
    let frame = udp_frame(SERVER, 53, CLIENT, 5000, &build::dns_response_a(0x1a2b, "api.example.com", Some("edge.example.net"), [93, 184, 216, 34]));
    let d = dissect(&frame, &ctx(LinkType::Ethernet, frame.len()), DissectOptions { events: true, ..DissectOptions::FULL });
    assert_eq!(
        d.info,
        "Standard query response 0x1a2b A api.example.com CNAME edge.example.net A 93.184.216.34"
    );
    assert_eq!(find(&d.nodes, "dns.a").unwrap().value, FieldValue::Ipv4([93, 184, 216, 34]));
    assert_eq!(find(&d.nodes, "dns.cname").unwrap().display, "edge.example.net");
    assert_eq!(d.summary.event.unwrap().label, "api.example.com → 93.184.216.34");

    let nx = udp_frame(SERVER, 53, CLIENT, 5000, &build::dns_response_nxdomain(5, "nothing.invalid"));
    let d = full(&nx);
    assert_eq!(d.info, "Standard query response 0x0005 No such name A nothing.invalid");
}

#[test]
fn http_request_and_response() {
    let frame = tcp_frame(tcpf::PSH | tcpf::ACK, &build::http_request("GET", "example.test", "/index.html"), 80);
    let d = full(&frame);
    assert_eq!(d.summary.top, Some(ProtocolId::Http));
    assert_eq!(d.info, "GET /index.html HTTP/1.1");
    assert_eq!(find(&d.nodes, "http.host").unwrap().value, FieldValue::Str("example.test".into()));
    assert_eq!(find(&d.nodes, "http.request.method").unwrap().display, "GET");

    let resp = tcp_frame(tcpf::PSH | tcpf::ACK, &build::http_response(404, "Not Found", "nope"), 80);
    let d = full(&resp);
    assert_eq!(d.info, "HTTP/1.1 404 Not Found  (text/html)");
    assert_eq!(find(&d.nodes, "http.response.code").unwrap().value, FieldValue::U64(404));
    assert_eq!(find(&d.nodes, "http.content_length").unwrap().value, FieldValue::U64(4));

    // Non-standard port → heuristic still finds HTTP.
    let odd = tcp_frame(tcpf::PSH | tcpf::ACK, &build::http_request("POST", "h", "/x"), 7070);
    assert_eq!(full(&odd).summary.top, Some(ProtocolId::Http));

    // Port 80 with arbitrary bytes → continuation, not data.
    let cont = tcp_frame(tcpf::PSH | tcpf::ACK, b"\x00\x01binary", 80);
    assert_eq!(full(&cont).info, "Continuation");
}

#[test]
fn tls_hellos_and_certificate() {
    let ch = tcp_frame(tcpf::PSH | tcpf::ACK, &build::tls_client_hello("api.example.com"), 443);
    let d = dissect(&ch, &ctx(LinkType::Ethernet, ch.len()), DissectOptions { events: true, ..DissectOptions::FULL });
    assert_eq!(d.summary.top, Some(ProtocolId::Tls));
    assert_eq!(d.info, "Client Hello (SNI=api.example.com)");
    assert_eq!(find(&d.nodes, "tls.handshake.extensions_server_name").unwrap().display, "api.example.com");
    assert_eq!(find(&d.nodes, "tls.handshake.extensions_alpn_str").unwrap().display, "h2");
    let ev = d.summary.event.unwrap();
    assert_eq!((ev.kind, ev.label.as_str()), (TimelineKind::TlsClientHello, "api.example.com"));

    let odd = tcp_frame(tcpf::PSH | tcpf::ACK, &build::tls_client_hello("odd.example"), 4444);
    assert_eq!(full(&odd).summary.top, Some(ProtocolId::Tls));

    let sh = tcp_frame(tcpf::PSH | tcpf::ACK, &build::tls_server_hello_tls13(), 443);
    let d = full(&sh);
    assert_eq!(d.info, "Server Hello, Change Cipher Spec, Application Data");
    assert_eq!(find(&d.nodes, "tls.handshake.extensions.supported_version").unwrap().value, FieldValue::U64(0x0304));

    let cert = tcp_frame(tcpf::PSH | tcpf::ACK, &build::tls12_server_flight("legacy.example.com"), 443);
    let d = full(&cert);
    assert_eq!(d.info, "Server Hello, Certificate, Server Hello Done");
    assert_eq!(find(&d.nodes, "x509sat.subject.cn").unwrap().display, "legacy.example.com");
    assert_eq!(find(&d.nodes, "x509sat.issuer.cn").unwrap().display, "NetTrace Test CA");

    // Random bytes on 443 must not be mistaken for records.
    let junk = tcp_frame(tcpf::PSH | tcpf::ACK, &[0x99; 40], 443);
    assert_eq!(full(&junk).info, "Continuation Data");
}

#[test]
fn dhcp_ntp_arp_icmp() {
    let bcast = nettrace_testkit::Host::new(build::MAC_BCAST, [255; 4]);
    let zero = nettrace_testkit::Host::new(CLIENT.mac, [0; 4]);
    let f = udp_frame(zero, 68, bcast, 67, &build::dhcp(1, 0x3903_f326, CLIENT.mac, [0; 4], Some("ws-77")));
    let d = full(&f);
    assert_eq!(d.summary.top, Some(ProtocolId::Dhcp));
    assert_eq!(d.info, "DHCP Discover - Transaction ID 0x3903f326 (ws-77)");
    assert_eq!(find(&d.nodes, "dhcp.option.hostname").unwrap().display, "ws-77");

    let f = udp_frame(CLIENT, 123, SERVER, 123, &build::ntp_client(1_700_000_000));
    let d = full(&f);
    assert_eq!(d.info, "NTP Version 4, client");
    assert_eq!(find(&d.nodes, "ntp.xmt").unwrap().display, "2023-11-14 22:13:20.250000000 UTC");

    let a = build::arp(1, CLIENT.mac, CLIENT.ip, [0; 6], SERVER.ip);
    let f = build::ethernet(build::MAC_BCAST, CLIENT.mac, build::ETH_ARP, &a);
    let d = full(&f);
    assert_eq!(d.info, "Who has 10.10.4.21? Tell 10.10.1.15");
    assert_eq!(d.summary.top, Some(ProtocolId::Arp));
    assert!(d.summary.net_src.is_none());
    assert_eq!(d.summary.src(), Address::Mac(MacAddr(CLIENT.mac)));

    let ping = build::ipv4(CLIENT.ip, SERVER.ip, 1, 9, 64, &build::icmp_echo(true, 1, 1, b"abc"));
    let d = full(&build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV4, &ping));
    assert_eq!(d.info, "Echo (ping) request  id=0x0001, seq=1/256, ttl=64");
    assert!(find(&d.nodes, "icmp.checksum").unwrap().display.ends_with("[correct]"));

    let probe = build::ipv4(CLIENT.ip, SERVER.ip, 17, 1, 64, &build::udp(40000, 33434, b"p"));
    let un = build::ipv4(SERVER.ip, CLIENT.ip, 1, 2, 64, &build::icmp_port_unreachable(&probe));
    let d = full(&build::ethernet(CLIENT.mac, SERVER.mac, build::ETH_IPV4, &un));
    assert_eq!(d.info, "Destination unreachable (Port unreachable)");
    // The embedded header must not overwrite the outer addresses.
    assert_eq!(d.summary.net_src, Address::V4(SERVER.ip));
}

#[test]
fn ipv6_and_icmpv6() {
    let a: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let b: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let ns = build::ipv6(a, b, 58, 255, &build::icmpv6_neighbor_solicitation(b, CLIENT.mac));
    let d = full(&build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV6, &ns));
    assert_eq!(d.summary.top, Some(ProtocolId::Icmpv6));
    assert_eq!(d.summary.net_src, Address::V6(a));
    assert_eq!(d.info, "Neighbor Solicitation for fe80::2 from 00:1f:1a:2b:3c:01");

    let udp6 = build::ipv6(a, b, 17, 64, &build::udp(5353, 5353, &build::dns_query(0, "printer.local", 12)));
    let d = full(&build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV6, &udp6));
    assert_eq!(d.summary.top, Some(ProtocolId::Dns));
}

#[test]
fn raw_ip_and_sll_link_types() {
    let ip = build::ipv4(CLIENT.ip, SERVER.ip, 17, 1, 64, &build::udp(1, 53, &build::dns_query(1, "a.b", 1)));
    let d = dissect(&ip, &ctx(LinkType::Raw, ip.len()), DissectOptions::FULL);
    assert_eq!(d.summary.top, Some(ProtocolId::Dns));
    assert!(!d.summary.protocols.contains(ProtocolId::Eth));

    let mut sll = vec![0, 4, 0, 1, 0, 6];
    sll.extend_from_slice(&CLIENT.mac);
    sll.extend_from_slice(&[0, 0, 0x08, 0x00]);
    sll.extend_from_slice(&ip);
    let d = dissect(&sll, &ctx(LinkType::LinuxSll, sll.len()), DissectOptions::FULL);
    assert_eq!(d.summary.top, Some(ProtocolId::Dns));
    assert_eq!(d.summary.l2_src, Address::Mac(MacAddr(CLIENT.mac)));
}

#[test]
fn malformed_packets_are_marked_not_fatal() {
    let mut bad_tcp = build::ipv4(CLIENT.ip, SERVER.ip, 6, 1, 64, &[0x01, 0xbb, 0x00]);
    bad_tcp.truncate(23);
    let f = build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV4, &bad_tcp);
    let d = full(&f);
    assert!(d.summary.malformed);
    assert!(d.summary.protocols.contains(ProtocolId::Malformed));
    assert!(find(&d.nodes, "_ws.malformed").is_some());

    let mut bad_ip = build::ipv4(CLIENT.ip, SERVER.ip, 17, 1, 64, &build::udp(1, 2, b"x"));
    bad_ip[0] = 0x43;
    let d = full(&build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV4, &bad_ip));
    assert!(d.summary.malformed);
    assert!(d.info.contains("Malformed"));

    // TCP data offset smaller than 5 words.
    let mut f = tcp_frame(tcpf::ACK, b"x", 80);
    f[14 + 20 + 12] = 0x20;
    assert!(full(&f).summary.malformed);

    // Truncated frame (snaplen) still yields lower layers.
    let f = tcp_frame(tcpf::ACK, b"payload", 80);
    let d = full(&f[..20]);
    assert!(d.summary.malformed);
    assert!(d.summary.protocols.contains(ProtocolId::Eth));
}

#[test]
fn all_byte_ranges_are_inside_the_frame() {
    fn check(nodes: &[Node], len: usize) {
        for n in nodes {
            assert!(n.start + n.len <= len, "{:?} {}+{} > {len}", n.field.map(|f| f.abbrev), n.start, n.len);
            check(&n.children, len);
        }
    }
    let cap: Capture = scenarios::demo();
    for (i, (_, frame)) in cap.frames.iter().enumerate() {
        let mut fctx = ctx(LinkType::Ethernet, frame.len());
        fctx.number = i as u32 + 1;
        let d = dissect(frame, &fctx, DissectOptions::FULL);
        check(&d.nodes, frame.len());
        assert!(!d.info.is_empty(), "frame {} has empty info", i + 1);
    }
}

/// Deterministic xorshift PRNG so the fuzz test is reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

static FUZZ_PANICS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[test]
fn fuzz_random_and_mutated_frames_never_panic() {
    // `dissect` converts panics into malformed markers; count them through the
    // panic hook so a dissector bug still fails this test.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().name().is_some_and(|n| n.contains("fuzz")) {
            FUZZ_PANICS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            eprintln!("dissector panic: {info}");
        } else {
            default_hook(info);
        }
    }));
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let links = [LinkType::Ethernet, LinkType::Raw, LinkType::LinuxSll, LinkType::LinuxSll2, LinkType::Null, LinkType::Loop];
    let modes = [DissectOptions::INDEX, DissectOptions::VALUES, DissectOptions::FULL];
    let mut seeds: Vec<Vec<u8>> = scenarios::demo().frames.into_iter().map(|(_, f)| f).collect();
    seeds.extend(scenarios::tcp_problems().frames.into_iter().map(|(_, f)| f));
    let mut c = TcpConv::new(CLIENT, 1, SERVER, 53);
    seeds.push(c.segment(true, tcpf::ACK, 1, 1, &[0, 30, 1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c], vec![]));

    for iter in 0..40_000u32 {
        let mut frame = if iter % 4 == 0 {
            let len = (rng.next() % 200) as usize;
            (0..len).map(|_| rng.next() as u8).collect::<Vec<u8>>()
        } else {
            let mut f = seeds[(rng.next() as usize) % seeds.len()].clone();
            for _ in 0..1 + rng.next() % 6 {
                if f.is_empty() {
                    break;
                }
                let at = (rng.next() as usize) % f.len();
                f[at] = rng.next() as u8;
            }
            if rng.next().is_multiple_of(3) {
                let cut = (rng.next() as usize) % (f.len() + 1);
                f.truncate(cut);
            }
            f
        };
        if iter % 97 == 0 {
            frame.clear();
        }
        let link = if iter % 4 == 0 { links[(rng.next() as usize) % links.len()] } else { LinkType::Ethernet };
        let mode = modes[(iter as usize) % modes.len()];
        let d = dissect(&frame, &ctx(link, frame.len()), mode);
        let _ = d.summary.src();
    }
    assert_eq!(FUZZ_PANICS.load(std::sync::atomic::Ordering::SeqCst), 0, "dissectors panicked");
}

#[test]
fn snaplen_truncated_tcp_keeps_wire_length() {
    let frame = tcp_frame(tcpf::PSH | tcpf::ACK, &[0x42; 1000], 9000);
    // Keep only Ethernet + IPv4 + TCP header + 10 payload bytes (like `tcpdump -s 64`).
    let cut = &frame[..14 + 20 + 20 + 10];
    let mut fctx = ctx(LinkType::Ethernet, cut.len());
    fctx.origlen = frame.len() as u32;
    let d = dissect(cut, &fctx, DissectOptions::FULL);
    let Some(TransportInfo::Tcp(t)) = d.summary.transport else { panic!("tcp expected") };
    assert_eq!(t.payload_len, 1000);
    assert!(d.info.ends_with("Len=1000"), "{}", d.info);
    assert!(!d.summary.malformed);

    // Options cut by snaplen: still a TCP segment with transport info.
    let seg = TcpSegment { sport: 1, dport: 2, seq: 5, ack: 0, flags: tcpf::SYN, window: 100, options: build::syn_options(1460, 7), payload: vec![] };
    let ip = build::ipv4(CLIENT.ip, SERVER.ip, 6, 1, 64, &build::tcp(&seg));
    let full = build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV4, &ip);
    let cut = &full[..14 + 20 + 22];
    let d = dissect(cut, &ctx(LinkType::Ethernet, cut.len()), DissectOptions::FULL);
    assert!(matches!(d.summary.transport, Some(TransportInfo::Tcp(_))));
}
