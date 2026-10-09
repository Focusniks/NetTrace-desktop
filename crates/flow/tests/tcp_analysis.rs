use nettrace_flow::{FlowAssignment, FlowKind, FlowPacket, FlowTable, TcpSegment};
use nettrace_model::{tcp_analysis as ta, TcpState, Transport};
use nettrace_packet::LinkType;
use nettrace_protocol::{dissect, DissectOptions, FrameContext, TransportInfo};
use nettrace_testkit::build::{self, tcpf};
use nettrace_testkit::scenarios::{self, CLIENT, OTHER, SERVER};
use nettrace_testkit::{udp_frame, Capture, TcpConv};

/// Runs a capture through dissection + flow tracking like the engine does.
fn run(cap: &Capture) -> (FlowTable, Vec<Option<FlowAssignment>>) {
    let mut table = FlowTable::new();
    let mut out = Vec::new();
    for (i, (ts, frame)) in cap.frames.iter().enumerate() {
        let fctx = FrameContext { link_type: Some(LinkType::Ethernet), ..FrameContext::default() };
        let s = dissect(frame, &fctx, DissectOptions::INDEX).summary;
        let kind = match s.transport {
            Some(TransportInfo::Tcp(t)) => FlowKind::Tcp(TcpSegment {
                seq: t.seq,
                ack: t.ack,
                flags: t.flags,
                window: t.window,
                payload_len: t.payload_len,
                wscale: t.wscale,
            }),
            Some(TransportInfo::Udp { payload_len }) => FlowKind::Udp { payload_len },
            None => {
                out.push(None);
                continue;
            }
        };
        let p = FlowPacket {
            index: i as u32,
            ts_ns: ts.nanos(),
            frame_len: frame.len() as u32,
            src: s.net_src,
            dst: s.net_dst,
            sport: s.src_port,
            dport: s.dst_port,
            kind,
            app: s.top.filter(|p| !matches!(p, nettrace_model::ProtocolId::Tcp | nettrace_model::ProtocolId::Udp)),
        };
        out.push(Some(table.process(&p)));
    }
    (table, out)
}

fn flags(a: &[Option<FlowAssignment>], packet_no: usize) -> u16 {
    a[packet_no - 1].map(|x| x.analysis).unwrap_or(0)
}

#[test]
fn handshake_data_and_fin() {
    let (table, a) = run(&scenarios::tcp_basic());
    assert_eq!(table.tcp_count(), 1);
    let (_, flow) = table.stream(Transport::Tcp, 0).unwrap();
    let tcp = flow.tcp.as_deref().unwrap();
    assert_eq!(flow.client, (nettrace_packet::Address::V4(CLIENT.ip), 52144));
    assert_eq!(flow.server.1, 80);
    assert_eq!((tcp.syn, tcp.syn_ack, tcp.handshake_ack), (Some(0), Some(1), Some(2)));
    assert_eq!(tcp.irtt_ns, Some(38_000_000));
    assert_eq!(tcp.fin, [Some(6), Some(7)]);
    assert_eq!(tcp.state(), TcpState::Closed);
    assert_eq!(tcp.retransmissions + tcp.duplicate_acks + tcp.out_of_order, 0);
    for p in 1..=9 {
        assert_eq!(flags(&a, p), 0, "packet {p} should have no analysis flags");
    }
    assert_eq!(flow.packets, (0..9).collect::<Vec<u32>>());
    assert_eq!(flow.app, Some(nettrace_model::ProtocolId::Http));
    // Relative sequence numbering: SYN = 0, first data = 1.
    assert_eq!(tcp.dirs[0].base_seq.map(|b| b.wrapping_add(1)), Some(TcpConv::new(CLIENT, 52144, SERVER, 80).cseq.wrapping_add(1)));
    // RTT: response (pkt 5) acks request (pkt 4) after 20 ms.
    let rtt = tcp.rtt_for(4).unwrap();
    assert_eq!((rtt.acked, rtt.rtt_ns), (3, 20_000_000));
    assert!(tcp.rtt_min_ns.is_some() && tcp.rtt_avg_ns().is_some());
    let summary = flow.summary(scenarios::tcp_basic().frames[0].0.nanos());
    assert_eq!(summary.c2s_packets + summary.s2c_packets, 9);
    assert_eq!(summary.tcp.unwrap().handshake.syn, Some(1));
}

#[test]
fn retransmission_ooo_dup_ack_fast_retrans_zero_window_rst() {
    let (table, a) = run(&scenarios::tcp_problems());
    // 1-3 handshake, 4 data#1, 5 data#2, 6 retrans of #2
    assert_eq!(flags(&a, 4), 0);
    assert_eq!(flags(&a, 5), 0);
    assert_eq!(flags(&a, 6) & ta::RETRANSMISSION, ta::RETRANSMISSION);
    // 7 server ACK, 8 data after a gap, 9 gap filler shortly after (out-of-order)
    assert_eq!(flags(&a, 8) & ta::LOST_SEGMENT, ta::LOST_SEGMENT);
    assert_eq!(flags(&a, 9) & ta::OUT_OF_ORDER, ta::OUT_OF_ORDER);
    assert_eq!(flags(&a, 9) & ta::RETRANSMISSION, 0);
    // 10 server data, 11-13 duplicate ACKs, 14 fast retransmission
    for p in 11..=13 {
        assert_eq!(flags(&a, p) & ta::DUPLICATE_ACK, ta::DUPLICATE_ACK, "packet {p}");
    }
    assert_eq!(flags(&a, 14) & (ta::RETRANSMISSION | ta::FAST_RETRANSMISSION), ta::RETRANSMISSION | ta::FAST_RETRANSMISSION);
    // 15 zero window, 16 reset
    assert_eq!(flags(&a, 15) & ta::ZERO_WINDOW, ta::ZERO_WINDOW);
    let (_, flow) = table.stream(Transport::Tcp, 0).unwrap();
    let tcp = flow.tcp.as_deref().unwrap();
    assert_eq!(tcp.retransmissions, 2);
    assert_eq!(tcp.fast_retransmissions, 1);
    assert_eq!(tcp.duplicate_acks, 3);
    assert_eq!(tcp.out_of_order, 1);
    assert_eq!(tcp.zero_window, 1);
    assert_eq!(tcp.resets, 1);
    assert_eq!(tcp.state(), TcpState::Reset);
}

#[test]
fn retransmitted_segments_are_excluded_from_rtt() {
    let (table, _) = run(&scenarios::tcp_problems());
    let (_, flow) = table.stream(Transport::Tcp, 0).unwrap();
    let tcp = flow.tcp.as_deref().unwrap();
    // Packet 7 (index 6) acknowledges data#2 which was retransmitted: Karn's rule.
    assert!(tcp.rtt_for(6).is_none());
}

#[test]
fn syn_answered_by_rst_is_refused() {
    let mut cap = Capture::ethernet();
    let mut c = TcpConv::new(OTHER, 41000, SERVER, 445);
    let syn = c.segment(true, tcpf::SYN, c.cseq, 0, &[], vec![]);
    cap.push_after_us(10, syn);
    let rst = c.segment(false, tcpf::RST | tcpf::ACK, 0, c.cseq.wrapping_add(1), &[], vec![]);
    cap.push_after_us(10, rst);
    let (table, _) = run(&cap);
    let (_, flow) = table.stream(Transport::Tcp, 0).unwrap();
    assert_eq!(flow.tcp.as_deref().unwrap().state(), TcpState::Refused);
}

#[test]
fn syn_retransmission_and_port_reuse() {
    let mut cap = Capture::ethernet();
    let mut c = TcpConv::new(CLIENT, 40000, SERVER, 80);
    let syn = c.segment(true, tcpf::SYN, c.cseq, 0, &[], vec![]);
    cap.push_after_us(10, syn.clone());
    cap.push_after_us(1_000_000, syn);
    c.handshake(&mut cap, 100);
    // handshake() sends a SYN with the same ISN again → still the same stream.
    c.close(&mut cap, true, 100);
    // New connection on the same ports with a new ISN.
    let mut c2 = TcpConv::new(CLIENT, 40000, SERVER, 80);
    c2.cseq = 0x5555_0000;
    c2.handshake(&mut cap, 100);
    let (table, a) = run(&cap);
    assert_eq!(flags(&a, 2) & ta::RETRANSMISSION, ta::RETRANSMISSION);
    assert_eq!(table.tcp_count(), 2);
    let reuse_at = cap.frames.len() - 2; // SYN of the second connection (1-based)
    assert_eq!(flags(&a, reuse_at) & ta::PORT_REUSE, ta::PORT_REUSE);
    assert_eq!(a[reuse_at - 1].unwrap().flow, table.stream(Transport::Tcp, 1).unwrap().0);
}

#[test]
fn midstream_capture_numbers_from_one() {
    let mut cap = Capture::ethernet();
    let mut c = TcpConv::new(CLIENT, 50001, SERVER, 443);
    c.send(&mut cap, true, &[1; 10], 10);
    c.send(&mut cap, false, &[2; 10], 10);
    let (table, a) = run(&cap);
    let (_, flow) = table.stream(Transport::Tcp, 0).unwrap();
    let tcp = flow.tcp.as_deref().unwrap();
    assert_eq!(tcp.state(), TcpState::Midstream);
    let base = tcp.dirs[0].base_seq.unwrap();
    assert_eq!(TcpConv::new(CLIENT, 50001, SERVER, 443).cseq.wrapping_sub(base), 1);
    assert_eq!(flags(&a, 1), 0);
    assert_eq!(flow.client.1, 50001);
}

#[test]
fn keep_alive_is_not_a_retransmission() {
    let mut cap = Capture::ethernet();
    let mut c = TcpConv::new(CLIENT, 50002, SERVER, 22);
    c.handshake(&mut cap, 100);
    c.send(&mut cap, true, b"data", 100);
    c.ack(&mut cap, false, 100);
    let ka_seq = c.cseq.wrapping_sub(1);
    let ka = c.segment(true, tcpf::ACK, ka_seq, c.sseq, &[0], vec![]);
    cap.push_after_us(60_000_000, ka);
    let (table, a) = run(&cap);
    let last = cap.frames.len();
    assert_eq!(flags(&a, last), ta::KEEP_ALIVE);
    assert_eq!(table.stream(Transport::Tcp, 0).unwrap().1.tcp.as_deref().unwrap().retransmissions, 0);
}

#[test]
fn window_scaling_requires_both_sides() {
    let (table, _) = run(&scenarios::tcp_basic());
    let tcp = table.stream(Transport::Tcp, 0).unwrap().1.tcp.as_deref().unwrap();
    assert_eq!(tcp.window_shift(nettrace_flow::Dir::ClientToServer), Some(7));
    assert_eq!(tcp.window_shift(nettrace_flow::Dir::ServerToClient), Some(8));
}

#[test]
fn udp_flows_and_direction() {
    let mut cap = Capture::ethernet();
    cap.push_after_us(10, udp_frame(CLIENT, 53001, SERVER, 53, &build::dns_query(1, "a.example", 1)));
    cap.push_after_us(10, udp_frame(SERVER, 53, CLIENT, 53001, &build::dns_response_a(1, "a.example", None, [1, 2, 3, 4])));
    cap.push_after_us(10, udp_frame(CLIENT, 53002, SERVER, 53, &build::dns_query(2, "b.example", 1)));
    let (table, a) = run(&cap);
    assert_eq!(table.udp_count(), 2);
    let (_, f0) = table.stream(Transport::Udp, 0).unwrap();
    assert_eq!(f0.packets.len(), 2);
    assert_eq!(f0.server.1, 53);
    assert_eq!(f0.c2s.packets, 1);
    assert_eq!(f0.s2c.packets, 1);
    assert_eq!(a[1].unwrap().dir, nettrace_flow::Dir::ServerToClient);
    assert!(f0.tcp.is_none());
}

#[test]
fn demo_capture_streams() {
    let (table, _) = run(&scenarios::demo());
    // TLS1.3, TLS1.2, HTTP, odd-port TLS, 4 refused, lossy stream
    assert_eq!(table.tcp_count(), 9);
    let refused = table
        .flows()
        .iter()
        .filter(|f| f.tcp.as_deref().is_some_and(|t| t.state() == TcpState::Refused))
        .count();
    assert_eq!(refused, 4);
    let lossy = table.flows().iter().find(|f| f.client.1 == 52190).unwrap();
    let t = lossy.tcp.as_deref().unwrap();
    assert_eq!(t.retransmissions, 5);
    assert_eq!(t.fast_retransmissions, 5);
    assert!(t.duplicate_acks >= 10);
}
