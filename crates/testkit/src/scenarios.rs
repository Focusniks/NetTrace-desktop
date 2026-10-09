//! Canned captures. Packet numbers referenced in tests are documented inline.

use nettrace_packet::LinkType;

use crate::build::{self, tcpf};
use crate::{udp_frame, Capture, Host, TcpConv};

pub const CLIENT: Host = Host::new(build::MAC_A, [10, 10, 1, 15]);
pub const SERVER: Host = Host::new(build::MAC_B, [10, 10, 4, 21]);
pub const RESOLVER: Host = Host::new([0x00, 0x50, 0x56, 0xaa, 0xbb, 0x01], [10, 10, 0, 53]);
pub const GATEWAY: Host = Host::new([0x00, 0x50, 0x56, 0xaa, 0xbb, 0x02], [10, 10, 0, 1]);
pub const OTHER: Host = Host::new([0x00, 0x1f, 0x1a, 0x2b, 0x3c, 0x09], [10, 10, 1, 77]);

/// 1-3 handshake, 4 request, 5 response, 6 ACK, 7-9 FIN/FIN/ACK.
pub fn tcp_basic() -> Capture {
    let mut cap = Capture::ethernet();
    let mut c = TcpConv::new(CLIENT, 52144, SERVER, 80);
    c.handshake(&mut cap, 19_000);
    c.send(&mut cap, true, &build::http_request("GET", "example.test", "/index.html"), 500);
    c.send(&mut cap, false, &build::http_response(200, "OK", "<html>hello</html>"), 20_000);
    c.ack(&mut cap, true, 300);
    c.close(&mut cap, true, 1000);
    cap
}

/// TCP problems in one stream (1-based packet numbers):
/// 1-3 handshake; 4 data#1; 5 data#2; 6 retransmission of #2; 7 server ACK;
/// 8 data after a 100-byte gap (previous segment not captured); 9 gap filler
/// 50 µs later (out-of-order); 10 server data; 11-13 duplicate ACKs;
/// 14 fast retransmission; 15 zero-window ACK; 16 RST from the server.
pub fn tcp_problems() -> Capture {
    let mut cap = Capture::ethernet();
    let mut c = TcpConv::new(CLIENT, 50000, SERVER, 443);
    c.handshake(&mut cap, 10_000);
    let s1 = c.send(&mut cap, true, &[1u8; 100], 100);
    let _ = s1;
    let s2 = c.send(&mut cap, true, &[2u8; 100], 100);
    c.send_at(&mut cap, true, s2, &[2u8; 100], 200_000);
    c.ack(&mut cap, false, 10_000);
    // Skip 100 bytes: send seq +300 first, then fill the gap (+200).
    let gap_seq = c.cseq;
    c.cseq = c.cseq.wrapping_add(100);
    c.send(&mut cap, true, &[4u8; 100], 100);
    c.send_at(&mut cap, true, gap_seq, &[3u8; 100], 50);
    // Server sends data; client keeps acking an old value → duplicate ACKs.
    let srv = c.send(&mut cap, false, &[9u8; 200], 100);
    let client_ack = srv; // acknowledges nothing new
    for _ in 0..3 {
        c.ack_at(&mut cap, true, client_ack, 100);
    }
    c.send_at(&mut cap, false, srv, &[9u8; 200], 100);
    c.set_window(0);
    c.ack(&mut cap, true, 100);
    c.rst(&mut cap, false, 100);
    cap
}

/// Rich capture covering every MVP dissector plus indicator triggers.
pub fn demo() -> Capture {
    let mut cap = Capture::ethernet();

    // ARP who-has / reply
    let arp_req = build::arp(1, CLIENT.mac, CLIENT.ip, [0; 6], GATEWAY.ip);
    cap.push_after_us(10, build::ethernet(build::MAC_BCAST, CLIENT.mac, build::ETH_ARP, &arp_req));
    let arp_rep = build::arp(2, GATEWAY.mac, GATEWAY.ip, CLIENT.mac, CLIENT.ip);
    cap.push_after_us(150, build::ethernet(CLIENT.mac, GATEWAY.mac, build::ETH_ARP, &arp_rep));

    // DHCP DORA
    let bcast = Host::new(build::MAC_BCAST, [255, 255, 255, 255]);
    let zero = Host::new(OTHER.mac, [0, 0, 0, 0]);
    let xid = 0x3903_f326;
    cap.push_after_us(1000, udp_frame(zero, 68, bcast, 67, &build::dhcp(1, xid, OTHER.mac, [0; 4], Some("ws-77"))));
    cap.push_after_us(800, udp_frame(GATEWAY, 67, bcast, 68, &build::dhcp(2, xid, OTHER.mac, OTHER.ip, None)));
    cap.push_after_us(800, udp_frame(zero, 68, bcast, 67, &build::dhcp(3, xid, OTHER.mac, [0; 4], Some("ws-77"))));
    cap.push_after_us(800, udp_frame(GATEWAY, 67, bcast, 68, &build::dhcp(5, xid, OTHER.mac, OTHER.ip, None)));

    // DNS
    cap.push_after_us(2000, udp_frame(CLIENT, 53001, RESOLVER, 53, &build::dns_query(0x1a2b, "api.example.com", 1)));
    cap.push_after_us(
        12_000,
        udp_frame(RESOLVER, 53, CLIENT, 53001, &build::dns_response_a(0x1a2b, "api.example.com", Some("edge.example.net"), SERVER.ip)),
    );
    cap.push_after_us(500, udp_frame(CLIENT, 53002, RESOLVER, 53, &build::dns_query(0x1a2c, "nothing.invalid", 1)));
    cap.push_after_us(9000, udp_frame(RESOLVER, 53, CLIENT, 53002, &build::dns_response_nxdomain(0x1a2c, "nothing.invalid")));

    // TLS 1.3 to api.example.com
    let mut tls = TcpConv::new(CLIENT, 52144, SERVER, 443);
    tls.handshake(&mut cap, 19_000);
    tls.send(&mut cap, true, &build::tls_client_hello("api.example.com"), 200);
    tls.send(&mut cap, false, &build::tls_server_hello_tls13(), 19_000);
    tls.send(&mut cap, true, &build::tls_application_data(120), 300);
    for _ in 0..6 {
        tls.send(&mut cap, false, &build::tls_application_data(1200), 400);
    }
    tls.ack(&mut cap, true, 200);
    tls.close(&mut cap, true, 5000);

    // TLS 1.2 with certificate
    let mut tls12 = TcpConv::new(CLIENT, 52150, SERVER, 8443);
    tls12.handshake(&mut cap, 15_000);
    tls12.send(&mut cap, true, &build::tls_client_hello("legacy.example.com"), 200);
    tls12.send(&mut cap, false, &build::tls12_server_flight("legacy.example.com"), 15_000);
    tls12.ack(&mut cap, true, 300);
    tls12.close(&mut cap, false, 3000);

    // HTTP
    let mut http = TcpConv::new(CLIENT, 52160, SERVER, 80);
    http.handshake(&mut cap, 18_000);
    http.send(&mut cap, true, &build::http_request("GET", "api.example.com", "/v1/status"), 300);
    http.send(&mut cap, false, &build::http_response(200, "OK", "{\"ok\":true}"), 25_000);
    http.ack(&mut cap, true, 200);
    http.close(&mut cap, true, 2000);

    // TLS on a non-standard port (heuristic detection)
    let mut odd = TcpConv::new(CLIENT, 52170, SERVER, 4444);
    odd.handshake(&mut cap, 12_000);
    odd.send(&mut cap, true, &build::tls_client_hello("odd-port.example.com"), 200);
    odd.close(&mut cap, true, 2000);

    // ICMP echo + port unreachable
    let echo = build::ipv4(CLIENT.ip, GATEWAY.ip, 1, 0x2000, 64, &build::icmp_echo(true, 1, 1, b"ping-data-0123456789"));
    cap.push_after_us(1000, build::ethernet(GATEWAY.mac, CLIENT.mac, build::ETH_IPV4, &echo));
    let reply = build::ipv4(GATEWAY.ip, CLIENT.ip, 1, 0x2001, 64, &build::icmp_echo(false, 1, 1, b"ping-data-0123456789"));
    cap.push_after_us(700, build::ethernet(CLIENT.mac, GATEWAY.mac, build::ETH_IPV4, &reply));
    let probe = build::ipv4(CLIENT.ip, GATEWAY.ip, 17, 0x2002, 64, &build::udp(40000, 33434, b"probe"));
    let unreach = build::ipv4(GATEWAY.ip, CLIENT.ip, 1, 0x2003, 64, &build::icmp_port_unreachable(&probe));
    cap.push_after_us(500, build::ethernet(GATEWAY.mac, CLIENT.mac, build::ETH_IPV4, &probe));
    cap.push_after_us(400, build::ethernet(CLIENT.mac, GATEWAY.mac, build::ETH_IPV4, &unreach));

    // IPv6: neighbor solicitation + echo
    let v6a: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1f, 0x1a, 0xff, 0xfe, 0x2b, 0x3c, 0x01];
    let v6b: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x4a, 0x8f, 0x5a, 0xff, 0xfe, 0xdb, 0x11, 0x22];
    let ns = build::ipv6(v6a, v6b, 58, 255, &build::icmpv6_neighbor_solicitation(v6b, CLIENT.mac));
    cap.push_after_us(1000, build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV6, &ns));
    let e6 = build::ipv6(v6a, v6b, 58, 64, &build::icmpv6_echo(true, 7, 1));
    cap.push_after_us(300, build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV6, &e6));
    let r6 = build::ipv6(v6b, v6a, 58, 64, &build::icmpv6_echo(false, 7, 1));
    cap.push_after_us(300, build::ethernet(CLIENT.mac, SERVER.mac, build::ETH_IPV6, &r6));

    // NTP
    cap.push_after_us(2000, udp_frame(CLIENT, 123, GATEWAY, 123, &build::ntp_client(1_700_000_000)));
    cap.push_after_us(1500, udp_frame(GATEWAY, 123, CLIENT, 123, &build::ntp_server(1_700_000_000)));

    // VLAN-tagged DNS query
    let q = build::ipv4(OTHER.ip, RESOLVER.ip, 17, 0x3000, 64, &build::udp(53100, 53, &build::dns_query(0x7777, "vlan.example.org", 28)));
    let tagged = build::vlan_tag(100, 3, build::ETH_IPV4, &q);
    cap.push_after_us(800, build::ethernet(RESOLVER.mac, OTHER.mac, build::ETH_VLAN, &tagged));

    // Repeated failed connections: SYN → RST/ACK
    for i in 0..4u16 {
        let mut f = TcpConv::new(OTHER, 41000 + i, SERVER, 445);
        let syn = f.segment(true, tcpf::SYN, f.cseq, 0, &[], build::syn_options(1460, 2));
        cap.push_after_us(3000, syn);
        let rst = f.segment(false, tcpf::RST | tcpf::ACK, 0, f.cseq.wrapping_add(1), &[], vec![]);
        cap.push_after_us(400, rst);
    }

    // Malformed: truncated TCP header and a bogus IPv4 header length
    let mut bad_tcp = build::ipv4(CLIENT.ip, SERVER.ip, 6, 0x4000, 64, &[0x01, 0xbb, 0x00]);
    bad_tcp.truncate(23);
    cap.push_after_us(500, build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV4, &bad_tcp));
    let mut bad_ip = build::ipv4(CLIENT.ip, SERVER.ip, 17, 0x4001, 64, &build::udp(1, 2, b"x"));
    bad_ip[0] = 0x43;
    cap.push_after_us(500, build::ethernet(SERVER.mac, CLIENT.mac, build::ETH_IPV4, &bad_ip));

    // A TCP stream with retransmissions/dup ACKs (reuses the problem scenario's shape)
    let mut lossy = TcpConv::new(CLIENT, 52190, SERVER, 443);
    lossy.handshake(&mut cap, 40_000);
    for i in 0..20u8 {
        let seq = lossy.send(&mut cap, false, &[i; 1000], 200);
        if i % 4 == 0 {
            lossy.ack_at(&mut cap, true, seq, 50);
            lossy.ack_at(&mut cap, true, seq, 50);
            lossy.ack_at(&mut cap, true, seq, 50);
            lossy.send_at(&mut cap, false, seq, &[i; 1000], 300);
        }
        lossy.ack(&mut cap, true, 40_000);
    }
    lossy.close(&mut cap, false, 1000);
    cap
}

/// Synthetic large capture (`connections` TCP sessions plus DNS) for
/// performance testing. Roughly 14 packets per connection.
pub fn large(connections: u32) -> Capture {
    let mut cap = Capture::new(LinkType::Ethernet);
    for i in 0..connections {
        let client = Host::new(build::MAC_A, [10, 1, (i >> 8) as u8, (i & 0xff) as u8]);
        let server = Host::new(build::MAC_B, [172, 16, (i % 7) as u8, 10 + (i % 50) as u8]);
        let port = 20_000 + (i % 40_000) as u16;
        let name = format!("host{}.example.com", i % 997);
        cap.push_after_us(50, udp_frame(client, port, RESOLVER, 53, &build::dns_query(i as u16, &name, 1)));
        cap.push_after_us(900, udp_frame(RESOLVER, 53, client, port, &build::dns_response_a(i as u16, &name, None, server.ip)));
        let dport = if i % 3 == 0 { 80 } else { 443 };
        let mut c = TcpConv::new(client, port, server, dport);
        c.handshake(&mut cap, 900);
        if dport == 443 {
            c.send(&mut cap, true, &build::tls_client_hello(&name), 50);
            c.send(&mut cap, false, &build::tls_server_hello_tls13(), 900);
        } else {
            c.send(&mut cap, true, &build::http_request("GET", &name, "/"), 50);
            c.send(&mut cap, false, &build::http_response(200, "OK", "ok"), 900);
        }
        for _ in 0..3 {
            c.send(&mut cap, false, &[0x42; 900], 30);
        }
        c.ack(&mut cap, true, 100);
        c.close(&mut cap, true, 200);
    }
    cap
}
